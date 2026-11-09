# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 32

## Executive Summary

The records are largely production-like from a detection ingestion and correlation perspective: native identifiers, timestamps, process lifecycles, and network companion records withstand direct checks. I found a limited native Security-event schema concern, but no demonstrated impossible ordering or identity contradiction sufficient to establish synthetic origin. The score reflects mostly realistic telemetry with an explainable export/enrichment artifact, rather than confidence that the source is real.

## Evidence For Synthetic

- [schema_or_format] Security Event 4658 version 0 contains an additional `ProcessName` EventData element. For example, `/private/tmp/log-study-20261105-r22/data/FILE-SRV-01.meridianhcs.local/windows_event_security.xml:9104`, record 272169 at `2026-11-02T14:15:16.6062557Z`, includes `ProcessId=0x4` and `ProcessName=System`. The native 4658 payload has the subject fields, ObjectServer, HandleId, and ProcessId; ProcessName is characteristic of adjacent object-access schemas rather than this event's native template. All 38 observed 4658 records have this additional element. This is a verified field-presence observation and a schema concern based on native-event expectations; collector enrichment could explain it, so it is not treated as a hard contradiction or decisive origin proof.

## Evidence For Real

- Visible Windows process lifecycles are coherent. Across ten Sysmon files, 864 Event 1 process creations and 741 Event 5 terminations have no checked same-GUID dependent event before its visible creation or after its visible termination, and no visible parent creation after the child's creation. Processes that start outside the slice were treated neutrally.
- Security logon/logoff identities align in the checks performed. For example, `/private/tmp/log-study-20261105-r22/data/DC-02.meridianhcs.local/windows_event_security.xml:4466` creates `WS-MCHEN-01$` Type 3 session `0xcb676af` at `13:10:34.7411311Z`; the matching 4634 at line 5094 closes it at `13:10:59.4737923Z` with the same SID and LogonType.
- Network accounting is internally defensible. All 21,412 Zeek connections pass elementary payload/IP-byte/packet lower-bound checks; the checked DNS, HTTP, TLS, SMB, and file companions have matching connection tuples and fit inside their visible connection intervals. This is evidence of correctness, not a claim that complete matching proves real origin.
- Browser metadata survives a useful cross-source check: `/private/tmp/log-study-20261105-r22/data/WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml:783` describes Edge `120.0.2210.144`; its connection at line 866 matches `/private/tmp/log-study-20261105-r22/data/zeek-core/http.json:50`, whose User-Agent advertises `Edg/120.0.0.0` and Chrome 120. The reduced User-Agent version is compatible with the executable version.
- macOS records maintain distinctions that often fail in fabricated telemetry. `/private/tmp/log-study-20261105-r22/data/MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1-3` separates fork and successive exec observations and advances PID version while preserving PID. The Unified Log policy message at `/private/tmp/log-study-20261105-r22/data/MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:2` says policy “would not allow” a process; I did not misinterpret that wording as a demonstrated denied execution.

## Detailed Analysis

All paths below are relative to `/private/tmp/log-study-20261105-r22/data/`. I examined only this supplied directory. I parsed all twenty Windows XML documents and all 72,059 JSON/NDJSON records; syntax parsing succeeded. The XML inventory contains 18,707 Security events and 11,542 Sysmon events. It also includes Linux RFC5424-style syslog, normalized eCAR, multiple Zeek sensors, firewall/proxy/web data, and two Mac endpoint exports. No conclusions rely on copied-file timestamps, domain ownership, missing selected Sysmon types, or the ease of narrating suspicious activity.

### Native event and ingestion checks

The following sample checks cover distinct event types and include both successful and anomalous findings. Line numbers refer to the opening Event element, or the complete JSON row.

| Record location | Concrete check | Result |
|---|---|---|
| `DC-02.meridianhcs.local/windows_event_security.xml:4466` | 4624 v2; Type 3 Kerberos; SID and hexadecimal LUID; IPv4-mapped IPv6 source | Consistent field shapes and remote-logon semantics. |
| `DC-02.meridianhcs.local/windows_event_security.xml:5094` | 4634; same `0xcb676af`, SID and Type 3 | Consistent closure, about 24.73 seconds later. |
| `DC-01.meridianhcs.local/windows_event_security.xml:167` | 4776; `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, machine account, workstation and `Status=0x0` | Plausible NTLM validation shape. |
| `DC-01.meridianhcs.local/windows_event_security.xml:962` | 4769; `ServiceName=DC-01$`, service SID, `TicketEncryptionType=0x12`, `Status=0x0` | Plausible service-ticket record. |
| `DC-01.meridianhcs.local/windows_event_security.xml:2387` | 4768; `ServiceName=krbtgt`, krbtgt SID ending 502, `PreAuthType=2` | Plausible password-based TGT request. Absence of a new TGT before every TGS was not scored. |
| `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:8969` | 5145; `ShareName=\\*\Shared`, `ShareLocalPath=\??\D:\Shared`, relative file path | Correctly distinguishes share and local filesystem namespaces. |
| `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:9014` | 4656 v1; handle `0xf80e2434`, `AccessMask=0x120089` | Plausible handle request for the same file. |
| `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:9063` | 4663 v1; same handle, `AccessMask=0x1` | Requested access and exercised read access are not incorrectly forced to be identical. |
| `FILE-SRV-01.meridianhcs.local/windows_event_security.xml:9104` | 4658 v0; same handle, later timestamp | Lifecycle is correct; additive ProcessName is the schema concern described above. |
| `DC-01.meridianhcs.local/windows_event_security.xml:177469` | 4697; `PSEXESVC`, `%SystemRoot%\PSEXESVC.exe`, service type `0x10`, start type `3` | Coherent service-install field values. |
| `DC-01.meridianhcs.local/windows_event_security.xml:187508` | 4720; new account SID ending 1688, `OldUacValue=0x0`, `NewUacValue=0x15` | Structured account-creation data rather than a free-text imitation. |
| `DC-01.meridianhcs.local/windows_event_security.xml:192488` | 4698; TaskContent nested XML | TaskContent parses successfully as XML; it contains real line breaks and normal single path separators. |
| `DC-01.meridianhcs.local/windows_event_security.xml:268289` | 1102; Eventlog provider, UserData/LogFileCleared, EventRecordID 1 | Correctly uses a distinct provider/payload and reset record numbering. |
| `DC-02.meridianhcs.local/windows_event_sysmon.xml:311` | Sysmon 1 v5; decimal PID 7304, parent PID 5128, GUIDs, hashes, System integrity | Plausible native process schema; Security 4688 independently represents these PIDs in hexadecimal. |
| `DC-02.meridianhcs.local/windows_event_sysmon.xml:504` | Sysmon 10; SourceProcessGUID/TargetProcessGUID, access `0x1000`, call trace | Case-specific GUID field names and process-access structure are plausible. |
| `DC-02.meridianhcs.local/windows_event_sysmon.xml:619` | Sysmon 22; QueryStatus 0, semicolon-terminated QueryResults | Suitable shape for common DNS-event detection parsers. |
| `DC-02.meridianhcs.local/windows_event_sysmon.xml:3059` | Sysmon 13; SetValue, HKLM path, `DWORD (0x00000000)` | Plausible source-native registry-value representation. |
| `zeek-core/conn.json:1` and `zeek-core/dhcp.json:1` | Same DHCP UID, UDP 68→67, REQUEST/ACK, lease time and duration | Companion and connection semantics agree. |
| `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson:1-3` | Version 11; fork then exec; PID 42198; PID versions 10→11→12 | Actor/target distinction is maintained; no same-identity image contradiction found. |
| `MAC-MROSS-01.meridianhcs.local/macos_unified_log.ndjson:3` | sshd-session image, timestamp offset, accepted-key message and backtrace image UUID | Internally consistent Unified Log-shaped record; not confused with a normalized FLOW row. |

The Windows provider/channel/keyword split is generally sensible: Security auditing successes use level 0 and success keywords, failure 4625 records use failure keywords, while Sysmon uses its Operational channel and informational level. The 1102 event has the different Eventlog provider and UserData namespace. These details would materially affect SIEM routing and are handled convincingly in the samples.

I did not validate every native template against an external release-specific manifest, and I do not claim that unfamiliar macOS version 11 extension fields are defects. The single 4658 concern would normally be resolved by checking whether the exporter deliberately adds enrichment to EventData.

### Lifecycle and identity checks

For Sysmon I keyed process observations by host and ProcessGuid, including the differing GUID key capitalization used by process-access events. Where initiators were visible, I checked dependencies against creation and termination timestamps and checked visible parent creation order. The checks found no violations. They are not proof of complete process-state validity: a GUID absent from visible creates can refer to a pre-window process, and I did not flag it.

For Security events I checked 4624/4634 ordering by host and TargetLogonId, and whether 4688, 4648 or 4672 used a subject LUID after a visible 4634. No violations appeared in these checks. Built-in session identifiers such as `0x3e7` were not required to have an initiating logon inside the slice.

The file-access chain at `FILE-SRV-01` is particularly useful: 5145 at `14:15:16.3216964Z`, 4656 at `.3284122Z`, 4663 at `.4118480Z`, and 4658 at `.6062557Z` preserve the user/session/handle relationship and reasonable ordering. The extra close-event field does not invalidate those relationships.

### Network, normalized telemetry, and timing

I checked each Zeek sensor independently to avoid treating a legitimate multi-sensor observation as duplicate corruption. Every DNS/HTTP/SSL/SMB companion UID checked resolves within its own sensor, and the four-tuple matches. Companion timestamps are not earlier than connection start by more than one millisecond and do not exceed a connection's reported close by more than ten milliseconds. File seen-byte counts do not exceed the respective connection direction's payload count in the tested file records. These elementary tests passed; they do not establish all transport details as packet-capture accurate.

Zeek connection-state coverage has a plausible tail: established TCP/UDP traffic coexists with S0, resets, rejections and partial TCP states. eCAR uses normalized object/action records and millisecond timestamps, whereas XML provides submicrosecond event publication time, Sysmon UtcTime is millisecond text, Zeek uses fractional epoch seconds, and syslog uses UTC RFC3339 timestamps. I found no reason to impose identical timestamp precision across these exports.

Linux SSH examples also separate acceptance from PAM/session opening. In `DB-PROD-01.meridianhcs.local/syslog.log:8-11`, source `10.10.1.35:59353` connects at `13:08:29.587455Z`, key authentication succeeds at `13:08:31.088422Z`, PAM opens at `.205701Z`, and logind registers the session at `.845124Z`. Fixed wording from PAM, CRON or daemons is expected; repetition of those messages alone was not scored as synthetic texture.

### macOS interpretation

The two endpoint-security exports contain 291 records, restricted here to fork, exec and exit observations. Their limited family coverage is neutral. I checked repeated top-level process identities keyed by PID and PID version: none changed executable image under the same identity. The first Mac launch sequence uses launchd, xpcproxy and Terminal as separate lifecycle observations, with exec targets replacing images while PID version advances.

Only five Unified Log rows are supplied across the two Macs. That small count is not itself an authenticity defect without a contradictory collection declaration. I did not infer that a policy warning established enforcement, that every exec needed a Unified Log companion, or that native ES notifications should contain normalized EDR network fields.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | Windows Security 4658 v0 XML | 38 of 38 visible 4658 records contain an additional ProcessName element | Limited evidence that the records were reconstructed or enriched. It affects strict native-template fidelity but has a plausible collector explanation. |

No hard contradiction, demonstrated contract gap, or adequately grounded dataset-wide distribution defect was established in this review. Successful correlation checks were not counted as synthetic indicators.

## Realism Score by Category

- **Field format accuracy:** 8 — XML/JSON parsing and most inspected native field shapes are convincing; 4658 has an additive field concern.
- **Temporal patterns:** 9 — Visible process, session, file-access and protocol ordering passes the checks performed; bounded-window omissions were treated neutrally.
- **Cross-source correlation:** 9 — Connection UID/tuple/interval, browser version and selected Windows identity relationships are sound.
- **Behavioral realism:** 8 — Plausible authentication, maintenance and mixed transport outcomes; this review does not establish all workload distributions as production-derived.
- **Environmental consistency:** 9 — Windows, Linux and Mac source semantics are generally distinguished and host/software evidence is compatible in inspected examples.

## Recommendations

- If this were synthetic, match the exact native 4658 version 0 payload by omitting ProcessName from EventData. If it is intentional collector enrichment, label and document that transformation and keep native fields distinguishable from enrichment so strict SIEM schema consumers do not mistake it for an OS-emitted field.
- Preserve the demonstrated identity and timing relationships when changing field templates: in particular the shared handle across 4656/4663/4658, GUID lifecycle ordering, and network companion intervals. The visible evidence does not justify adding arbitrary source families, retries, or missingness merely to make the data appear less clean.

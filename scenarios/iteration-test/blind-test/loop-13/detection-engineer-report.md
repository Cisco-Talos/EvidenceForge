# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 65

## Executive Summary

The data is largely usable by a real detection stack, with plausible Windows event schemas, valid JSON, coherent endpoint identities, and strong network correlation. I judge it likely synthetic because the same Windows event-version mismatch recurs throughout the visible file-share audit records, and independent command bursts on both Macs preserve exact microsecond fractions across irregular whole-second intervals. These are bounded findings; I did not find widespread impossible process ordering or network-tuple contradictions.

## Evidence For Synthetic

- [schema_or_format] All **105 Security Event 5140 records** declare **Version 0** while including **AccessMask and AccessList**, the access fields associated with the version 1 event shape. Examples are `DC-01.meridianhcs.local/windows_event_security.xml`, record **28248217**, `2026-11-02T14:06:57.1114616Z`; `DC-02.../windows_event_security.xml`, record **25377540**, `13:04:44.0918417Z`; and `FILE-SRV-01.../windows_event_security.xml`, record **271774**, `13:00:05.3202711Z`. This is a repeated header/payload mismatch, relevant to parsers that select an event template using provider, ID, and version. It is stronger than simply preferring a newer Windows event version.
- [distribution_texture] `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines **56, 59, 62**, records shell forks at **14:37:50.487145000Z**, **14:38:28.487145000Z**, and **14:38:57.487145000Z**. The children subsequently execute `bash ...connector-check.sh --check-network`, `cat /etc/resolv.conf`, and `cat /etc/hosts`. Distinct operations spaced 38 and 29 seconds apart preserve precisely the same microsecond fraction. `MAC-MROSS-02.../macos_endpoint_security.ndjson`, lines **89, 92, 95**, repeats the pattern at **15:30:55.965208000Z**, **15:31:17.965208000Z**, and **15:31:58.965208000Z**, followed by `dscl`, `find`, and `du` executions. The repeated fine-time anchor in two separate bursts suggests timestamp construction from an anchor plus integer-second offsets. Automation or timestamp rewriting could explain it, so this is texture evidence, not impossible ordering.

## Evidence For Real

- **Parsing and source typing are sound.** All **76,568 JSON/NDJSON records** parsed, and all **28,690 Windows XML events** parsed. Windows Security and Sysmon retain distinct providers, channels, levels, and source timestamp representations.
- **Visible process lifecycles are coherent in the checks performed.** Across the Sysmon files, references to visible process GUIDs did not precede their visible creates or follow their visible termination by more than the 200 ms tolerance used. The analogous eCAR actor-reference checks also found no violations. GUID-to-PID references to visible Sysmon creates were consistent.
- **Authentication pairing works.** **373** visible 4634 records had a preceding visible 4624 for the same host and LogonID, with matching user and LogonType. For example, on DC-01, machine account `WS-AJOHNSON-01$`, LogonID `0x538875d`, Type 3, logs on at **13:10:11.9705308Z** and logs off at **13:10:15.7197729Z**.
- **Network records exhibit realistic state diversity.** The three Zeek sensors contain successful, unanswered, rejected, reset, partial, and midstream connections. There were no cases of positive byte counts without packets or IP-byte counts below payload-byte counts in the checks performed.
- **macOS is represented with native distinctions.** ES records distinguish fork, exec, and exit, preserve PID across exec while changing PID version, and transition into user audit identities. Unified Log uses its own writer/subsystem/message fields rather than pretending to be endpoint FLOW telemetry.
- **Linux authentication includes distinct phases.** On DB-PROD-01, SSH PID `1369962` reports connection from `10.10.1.41:56332` at **13:26:13.677283Z**, public-key acceptance at **13:26:19.866241Z**, PAM session open at **13:26:19.924343Z**, and a logind session at **13:26:20.417851Z**.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory, using record contents rather than filesystem timestamps or external provenance. It contains **116 files**, approximately **80.6 MB**, across Windows Security/Sysmon, normalized eCAR, Linux syslog and shell history, macOS ES and Unified Log, Zeek, proxy/web access, ASA, and IDS alert sources.

I parsed every supplied XML and JSON/NDJSON record, inspected representative source fields, and ran bounded structural and relationship checks over the full parsed sources. Windows totals are **17,375 Security** and **11,315 Sysmon** records. Zeek connection totals are **12,080 core**, **9,839 DMZ**, and **489 database** records. Native ES totals are **147** and **175** records on the two Macs.

I treated timestamps as source event/observation times with possible collection latency. I did not assume that eCAR PROCESS/CREATE and native ES exec are interchangeable: eCAR explicitly distinguishes `operation: fork` and execution identities in the Mac records. I did not count absent pre-window initiators, missing selected Sysmon types, sanitized names, or the completeness of matching as synthetic indicators.

### Twenty representative record checks

All times below are UTC on **2026-11-02**. Host abbreviations refer to directories ending in `.meridianhcs.local`; Windows Security/Sysmon refer to their corresponding XML files.

| # | Source / record | Time | Fields examined and result |
|---|---|---|---|
| 1 | DC-01 Security 4624 | 13:10:11.9705308 | Version 2; Type 3; Kerberos; `WS-AJOHNSON-01$`; `TargetLogonId=0x538875d`; mapped IPv4 source `::ffff:10.10.1.35`; plausible machine network logon. |
| 2 | DC-01 Security 4634 | 13:10:15.7197729 | Same account, Type 3, and LogonID as #1; correct within-window termination relationship. |
| 3 | DC-01 Security 4688 | 13:02:10.7031679 | Version 2; `NewProcessId=0xe80`, parent `ProcessId=0x91c`, services.exe parent, svchost.exe child; mandatory label and target-subject fields present. |
| 4 | DC-01 Security 4768 | 13:02:07.3826088 | `omar.haddad`, krbtgt service SID ending 502, encryption `0x12`, preauth 2, mapped IPv4 client and decimal port; coherent ticket request shape. |
| 5 | DC-01 Security 4769 | 13:01:24.2826094 | `MAIL-EDGE-01$`, service `DC-01$`, ticket options `0x40810000`, encryption `0x12`, success status `0x0`; plausible service-ticket record. |
| 6 | DC-01 Security 4771 | 13:33:55.8134194 | `lina.nguyen`, status `0x18`, preauth 2, failure keyword `0x8010000000000000`; failure-specific fields and keyword agree. |
| 7 | DC-01 Security 5156 | 13:00:00.8064024 | Decimal PID 2420, dns.exe device path, inbound `%%14592`, receive/accept layer `%%14610`, UDP protocol 17 and destination port 53; mutually consistent. |
| 8 | FILE-SRV-01 Security 5140, record 271774 | 13:00:05.3202711 | Share ClinicalExports; `AccessMask=0x1`, `AccessList=%%4416`, but version 0; principal schema finding. |
| 9 | FILE-SRV-01 Security 4656 | 13:00:05.9844267 | Version 1; handle `0xec6f2c02`, System PID `0x4`, access mask `0x12019f`, user marcus.chen; plausible SMB-server object access. |
| 10 | FILE-SRV-01 Security 4663 | 13:00:06.1459007 | Same handle, identity, and archive-final.bak path as #9; access `0x2`/`%%4417`; occurs after handle request. |
| 11 | DC-01 Sysmon 1 | 13:02:10.5386850 | PID 3712 equals #3's `0xe80`; parent PID 2332 equals `0x91c`; svchost.exe/service parent agree; UtcTime millisecond precision distinct from XML SystemTime. |
| 12 | DC-02 Sysmon 10 | 13:00:30.0553583 | Version 3; `SourceProcessGUID`/`TargetProcessGUID`, services.exe PID 5088, svchost.exe PID 5132, access `0x0400`, module-offset call trace and source/target users; plausible access event shape. |
| 13 | DC-01 Security 1102 | 18:42:23.2681586 | Microsoft-Windows-Eventlog provider, Level 4, Task 104, UserData/LogFileCleared in its own namespace, SYSTEM actor and record ID 1; correctly differs from ordinary audit EventData. |
| 14 | zeek-core conn.json, line 1 | 13:00:00.617179 | UID `Cz3NMJPqehAd3ATCiW2`, UDP DNS tuple `10.10.2.30:36162 -> 10.10.2.10:53`, one packet each direction, payload 52/57 and IP bytes 80/85; header accounting is plausible. |
| 15 | zeek-core dns.json, line 1 | 13:00:00.617179 | Same UID/tuple as #14; query DC-02, A/NOERROR, boolean flags, TTL list and `rtt=0.009835`; RTT equals the associated short transaction duration. |
| 16 | zeek-core ssl.json, line 1 | 13:00:28.700077 | TLSv12, valid-looking cipher enumeration, `established=true`, `resumed=false`, LOG-MON-01 SNI, certificate FUID list; appropriate TLS fields. |
| 17 | zeek-core x509.json, line 1 | 13:00:28.723202 | ID `FbuozjPXMp7g6NrDLJ` links #16's certificate; RSA 2048, exponent 65537, DNS SANs, validity interval and SHA-1-sized fingerprint; coherent certificate metadata. |
| 18 | MAC-MROSS-01 ES fork, line 1 | 13:07:32.811343000 | Event type 11, notification action, launchd actor PID 1, child PID 25527/PID-version 12; child initially inherits launchd executable identity. |
| 19 | MAC-MROSS-01 ES exec, line 2 | 13:07:32.820534000 | Event type 9; actor PID 25527/version 12, target same PID/version 13, xpcproxy executable, args/cwd/fds present; exec differs correctly from fork. |
| 20 | DB-PROD-01 syslog SSH acceptance | 13:26:19.866241 | RFC5424 envelope; sshd PID 1369962, publickey, user maya.ross, source port 56332 and ED25519 SHA256 fingerprint; follows visible connection and precedes PAM open. |

### Windows schema and correlation implications

The 5140 defect is systematic across the DCs and file server, rather than a single damaged event. A field-name-based XML ingestion pipeline will probably retain the access fields, so I would not call the file unparseable. A manifest/version-aware parser can instead choose the wrong positional template or reject the extra fields. An export or transformation layer could also have rewritten version metadata; this alternative lowers verdict certainty but does not make the exported source-native combination correct.

The wider Windows sample is comparatively strong. SID structures are plausible. Apparent SID/name variations for `svc_dirsync` reduce to a SAM name versus a group-membership distinguished name, not conflicting identities. Shared executable hashes across different users' Zoom/OneDrive installation paths are also consistent with identical software and were not treated as collisions.

The 373 matched logoff/logon pairs had no tested account or type disagreements, and no matched logoff preceded every visible logon for its identifier. The seven remaining logoffs need not have visible logons in a time slice, and were not penalized. Built-in service-session reuse also requires care before treating repeated low LogonIDs as collisions.

### Network detection behavior

For protocol rows carrying a UID, I compared sensor-local connection tuples and timestamps against conn.json. There were no tuple disagreements, no protocol events earlier than connection start by more than 100 ms, and no protocol events later than connection end by more than 100 ms for matched records. Established TLS was not paired with S0 or REJ transport states.

One `zeek-core/smb_mapping.json` record, line **88**, UID `CPpgHD9SZo76AEy8y4`, lacks a corresponding visible core conn row. Its timestamp is **1793640924.86979** and its tuple is `10.10.1.22:36233 -> 10.10.2.20:445`. This is a join limitation, not scored evidence of fabrication: a slice, selective export, or source-local loss can remove an initiating record without creating an impossible visible relationship.

Core connection states include SF **9,654**, S0 **1,631**, OTH **454**, RSTO **151**, RSTR **102**, REJ **41**, plus S1/S2/S3. Their presence provides realistic unsuccessful and partial traffic for rule testing. I did not interpret strong UID integrity elsewhere as evidence against authenticity.

### macOS semantics and timestamp texture

The ES exports declare message `version=11` and `schema_version=1`. I assessed their observed relationships without asserting an undocumented version-specific field defect. Both per-event sequence counters and global sequence counters advance consistently; complete counters can reflect collection scope and were not scored as a synthetic clue.

User shells have `auid=501`, user UID/GID values, and audit sessions distinct from launchd's unset audit user. The observed exec transitions preserve process start time and change executable/PID-version identity. Native ES notification result fields were not interpreted as a security-policy denial or authorization decision. Thin Unified Log coverage was likewise not penalized.

The precise repeated fork fractions are a narrower concern. These are different commands at irregular intervals, with separately varied fork-to-exec delays, while the fork anchors preserve all six meaningful fractional digits. A recorder capable of microsecond timestamps would normally expose scheduler variation between invocations; two three-event bursts showing this shape make integer-offset construction a plausible explanation. I do not claim that script scheduling or normalization could never produce it.

### Limits and verdict calibration

There is no raw EVTX, packet payload, binary content, or collection configuration with which to establish provenance. Good parsing and successful correlation demonstrate utility, not authenticity, while the source-native version mismatch could originate in an export tool rather than a generator. I therefore choose the rubric's **61–80 likely-synthetic band**, at **65**, rather than claiming dataset-wide hard contradictions or near certainty.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | Windows Security 5140 | All 105 visible events; DC-01, DC-02, FILE-SRV-01 | Largest contribution: repeated version-0 header with version-1 access-field shape can affect manifest-aware ingestion. |
| distribution_texture | Native macOS ES fork/exec telemetry | Two three-command bursts, one on each Mac | Moderate contribution: exact microsecond fork fractions survive irregular integer-second spacing; automation/normalization remains an alternative. |

## Realism Score by Category

- **Field format accuracy:** 8 — Broadly valid and source-aware, with a systematic 5140 version/payload mismatch.
- **Temporal patterns:** 8 — Visible lifecycle ordering is sound; repeated microsecond command anchors are suspicious.
- **Cross-source correlation:** 9 — Windows process/session joins and matched Zeek tuple/time relationships hold in the checks performed.
- **Behavioral realism:** 8 — Operational traffic, failures, service activity, and interactive processes are plausible; command-start timestamp texture reduces confidence.
- **Environmental consistency:** 9 — Windows, Linux, macOS, proxy, and network representations largely respect platform and source distinctions.

## Recommendations

- If this were synthetic, emit Security 5140 using the native version corresponding to its payload: preserve the version 1 declaration when including AccessMask/AccessList, and validate provider/ID/version/field combinations together.
- If this were synthetic, give separate command invocations realistic scheduling variation at the precision claimed by native ES timestamps. Preserve observed fork-to-exec ordering and shared identities while avoiding exact fractional-second reuse across irregularly spaced invocations.
- If this were synthetic, retain the existing coherent process, authentication, packet-accounting, and UID relationships when correcting those defects; the analysis does not justify adding arbitrary missing sources or breaking legitimate matching.

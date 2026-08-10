# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 73
**Synthetic-Confidence Score:** 29

## Executive Summary

The data is highly credible as a filtered, normalized enterprise telemetry collection: the Windows event schemas, provider metadata, source-specific timestamps, identifiers, and cross-source lifecycle relationships are consistently usable by a SIEM without becoming mechanically identical. I found a few minor normalization and collection-shape artifacts, but no impossible visible ordering, invalid Event ID payload, broken Zeek tuple/UID relationship, or generator identity leak; on balance, this looks more like production-derived telemetry than a synthetic rendering.

## Evidence For Synthetic

- [schema_or_format] eCAR records carry redundant aliases for the same actor or target value. For example, `DC-01.meridianhcs.local/ecar.json` at `2024-03-18 12:00:13.825Z` has top-level `pid: 2420` plus `src_pid: "2420"` and `source_pid: "2420"`, while the remote-thread record at `2024-03-18 12:14:13.660Z` carries both `tgt_tid` and `target_tid` with value `12496`. This is parseable, but it looks more like a deliberately denormalized interchange model than a raw product feed.
- [distribution_texture] All 8,295 Windows Filtering Platform 5156 records use the same `\device\harddiskvolume1\...` device-volume convention, even though the endpoint fleet visibly spans Windows builds `10.0.17763.1`, `10.0.19041.1`, `10.0.20348.1`, and `10.0.22621.1`. Standardized imaging can explain it, but the dataset-wide uniformity is mildly templated.
- [weak_signal] Security 4688 and Sysmon Event 1 records are extremely tightly coupled: 968 process creations could be paired by host, PID, image, and command line, normally within roughly -21 to +17 ms (with only a few larger sub-130-ms outliers). That is technically plausible because both providers observe the same creation callback, but the consistently narrow timing envelope across nine hosts is cleaner than many heterogeneous production collection pipelines.

## Evidence For Real

- Windows XML is source-native rather than merely look-alike. Security 4624 uses Version 2 and the expected 27-field payload; 4688 uses Version 2 with `TokenElevationType`, target fields, `ParentProcessName`, and `MandatoryLabel`; 5156 uses Version 1 with WFP layer/filter fields. Sysmon Event IDs 1, 3, 5, 7, 8, 10, 11, 13, and 22 likewise have internally appropriate versions and field sets.
- `DC-01.meridianhcs.local/windows_event_security.xml` handles the audit-log clear at `2024-03-18T17:41:49.0211714Z` correctly: Event 1102 uses provider `Microsoft-Windows-Eventlog`, Level 4, Task 104, a `UserData/LogFileCleared` payload, and `EventRecordID` resets to 1 after `wevtutil cl Security`. This is a particularly good source-native detail.
- Authentication values are coherent. The DC's 4624 at `12:00:38.9076838Z` is a Type 3 Kerberos logon from `::ffff:10.10.1.31` with `KeyLength=0`; the failed Type 4 logon at `12:00:39.0050005Z` uses status `0xc000006d`, substatus `0xc0000072`, and failure reason `%%2307`; NTLM Type 3 successes use `LmPackageName=NTLM V2` and `KeyLength=128`.
- Visible session lifecycles are sane. Across 1,086 Security 4624 and 776 Security 4634 events, I found no case where a visible 4634 preceded the visible 4624 for the same host and Logon ID. Reused Logon IDs on unlocks are tied to Type 7 events rather than fabricated new interactive identities.
- Process telemetry has realistic small collection gaps. Of 972 Security 4688 events and 969 Sysmon Event 1 events, 968 paired cleanly by PID, image, command line, and near timestamp. The few isolated missing companions include `dllhost.exe` on DC-01 at `16:49:29.528447Z`, `dllhost.exe` on FILE-SRV-01 at `13:59:12.340222Z`, `userinit.exe` on WS-EBROOKS-01 at `13:51:04.454974Z`, and `taskhostw.exe` on WS-MCHEN-01 at `17:12:15.822189Z`; this looks like ordinary source-local loss/filtering rather than a broken generation contract.
- Sysmon process identity is stable. For every visible ProcessGuid referenced by Event 3/5/7/10/11/13, PID and image agreed with its visible Event 1, and I found no dependent event more than 500 ms before its visible creation or after its visible Event 5 termination. Parent ProcessGuids likewise did not resolve to a later visible parent creation.
- Cross-source Windows detections are operationally useful. DC-01's PSEXESVC activity has Security 4697 at `16:00:27.3741079Z`, Sysmon 11 file creation, Security/Sysmon process creation for `C:\Windows\PSEXESVC.exe`, and matching eCAR SERVICE/FILE/PROCESS records without contradictory actors or PIDs.
- Zeek JSON behaves like a coherent parsed feed. Every DNS (2,971 total), HTTP (2,215), SSL (1,792), and SMTP (67) UID was present in the corresponding sensor's `conn.json`, with no four-tuple mismatch. DNS rows share the connection open timestamp, TLS rows follow it by plausible handshake delays, and X.509 file hashes agree with certificate fingerprints.
- The broader feeds preserve their source formats: RFC 5424-like syslog has structured priority/version/timestamp/host/app/procid fields; Snort uses fast-alert timestamp/SID/classification/priority/tuple syntax; ASA messages use distinct build/teardown message IDs and second precision; web and proxy access records retain their own native timestamp and byte conventions.

## Detailed Analysis

### Corpus and ingestability

The visible interval is approximately `2024-03-18 12:00:00Z` through `17:59:57Z`. I parsed 14,154 Windows Security events, 4,273 Sysmon events, and 25,954 newline-delimited eCAR records, then sampled and correlated records from the Zeek core and DMZ feeds, firewall, IDS, proxy, web, and Linux syslog sources. The XML documents are namespace-correct and the JSON logs parse as discrete records with stable primitive types.

The Security distribution is credible for a selected-event export: 8,295 Event 5156, 1,223 Event 4769, 1,086 Event 4624, 972 Event 4688, 776 Event 4634, 704 Event 4689, 542 Event 4768, 348 Event 4672, and smaller numbers of 4776, 4648, 4625, 4800/4801, 4697, account-management, task-creation, and log-clear records. EventRecordIDs are unique and generally advance with gaps, as expected when only selected IDs are exported. The reset after Event 1102 is semantically correct rather than an ordering defect.

### Windows Security and Sysmon schema fidelity

Representative 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4697, 4698, 4720, 4724, 4726, 4728, 4738, 4768, 4769, 4771, 4776, 4800, 4801, 5156, and 1102 records have fields appropriate to their Event IDs. System metadata is also credible: Security success events use `0x8020000000000000`, failures use `0x8010000000000000`, Sysmon operational records use Level 4 and `0x8000000000000000`, and task/version values are consistent within each Event ID.

The DC account-creation sequence is especially usable. Security 4688 records show `net user svc_mhsync ... /add /domain` at `16:14:49.2802147Z`; 4720 follows at `16:14:50.8930974Z`; 4724 and 4738 capture password/account changes; and 4728 adds the same SID `S-1-5-21-1537687973-2974994828-3875246326-5122` to Domain Admins at `16:14:53.3201434Z`. The account is later removed by 4726 at `17:50:16.7935586Z`. SID-to-name checks found no SID assigned to multiple principals and no ordinary principal assigned multiple SIDs.

Sysmon fields are similarly credible. The DC's Event 1 for `WmiPrvSE.exe` at `12:05:05.101Z` includes a correctly shaped ProcessGuid, decimal ProcessId, four hash algorithms, LogonId, integrity level, and parent metadata; it matches Security 4688 at `12:05:05.0918500Z`. Event 10 ProcessAccess records have source/target GUIDs and PIDs that resolve consistently, Event 8 includes target-thread semantics, and Events 11/13/22 use appropriate file, registry, and DNS fields.

### Timestamp and lifecycle checks

Timestamp precision varies naturally by source: Windows SystemTime uses 100-ns-shaped precision, Sysmon's embedded `UtcTime` uses milliseconds, eCAR uses integer epoch milliseconds, Zeek uses floating-point epoch seconds, Snort uses microseconds without a year, ASA uses whole seconds, and access logs use Apache-style seconds with offsets. I did not see a source timestamp rendered in an alien format.

For all visible Sysmon process identities, dependent network/module/registry/file/process-access records did not appear materially before a matching visible creation or after a visible termination. Security 4689 and Sysmon Event 5 terminations also use the same process identity established at creation. The collection-window caveat accounts for processes and sessions whose start is not visible; I did not score those as defects.

### Zeek and normalized eCAR checks

Zeek field shapes are plausible across conn, dns, http, ssl, smtp, files, x509, ocsp, pe, and DHCP logs. Connection records distinguish rows with absent duration from completed rows, preserve service omission when not identified, and use protocol-appropriate histories and packet accounting. Protocol siblings keep the same UID and tuple; HTTP transaction timestamps can advance within a connection, while DNS rows share the UDP request timestamp and an RTT.

eCAR uses consistent top-level `timestamp_ms`, UUID-like `id`/`objectID`/`actorID`, host, object, action, PID/principal, and typed properties. Visible PROCESS CREATE/TERMINATE and USER_SESSION LOGIN/LOGOUT pairs preserve object identity. The main concern is the abundance of duplicate aliases (`src_pid` and `source_pid`, `src_tid` and `source_tid`, `tgt_tid` and `target_tid`) rather than a broken relationship. A strict downstream mapping should choose one canonical field to avoid ambiguous detections.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| schema_or_format | eCAR | Repeated across process, flow, and thread records | Redundant canonical/source aliases look deliberately normalized and could cause ambiguous field mapping, but values agree. |
| distribution_texture | Windows Security 5156 | Dataset-wide across Windows hosts | Uniform `harddiskvolume1` device paths are mildly templated despite multiple OS builds; standardized imaging remains a plausible explanation. |
| weak_signal | Security 4688 / Sysmon 1 | 968 paired creations across nine hosts | The narrow provider-to-provider timing band is cleaner than many production pipelines, but it is technically consistent with local provider timestamps and contains realistic outliers/gaps. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Sysmon, Zeek, firewall, IDS, syslog, and access-log fields are strongly source-native; eCAR alias duplication is the main blemish.
- **Temporal patterns:** 9 — Precision is source-specific and visible lifecycle ordering is causal, with realistic small offsets and collection gaps.
- **Cross-source correlation:** 9 — Process, session, network, UID, tuple, and certificate relationships resolve without concrete contradictions.
- **Behavioral realism:** 8 — Detection-relevant activity has credible process, account, service, task, and network artifacts mixed into substantial baseline traffic.
- **Environmental consistency:** 8 — Host roles, OS-specific paths, principals, and service placement are coherent; uniform WFP device-volume naming is a minor concern.

## Recommendations

- If this were synthetic, define one canonical eCAR property per semantic value and remove or explicitly document alias pairs such as `src_pid`/`source_pid` and `tgt_tid`/`target_tid`; validate that SIEM mappings cannot silently choose different copies.
- If this were synthetic, vary device-volume ordinals according to host image/partition layouts rather than emitting `\device\harddiskvolume1` on every Windows system, while preserving the native lowercase WFP application-path convention.
- If this were synthetic, retain the small observed Security/Sysmon collection gaps and provider-timing outliers. They materially improve collection realism; tests should ensure gaps are source-local and never orphan a required same-source lifecycle in an impossible way.

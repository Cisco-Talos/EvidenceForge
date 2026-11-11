# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 20

## Executive Summary

The bounded sample would support ordinary SIEM ingestion and correlation: Windows XML, Zeek JSON, Linux syslog, normalized eCAR, and the sampled macOS exports have usable source-specific structures. Two exact correlations agree on identities and event meaning, and this review found no demonstrated contradiction or defensible synthetic indicator. These records look production-like, but a deliberately high-fidelity collection could produce the same observations, so provenance remains inconclusive.

## Evidence For Synthetic

- No important synthetic indicator was established in this bounded review. In particular, independent source timestamps differing by tens or hundreds of milliseconds, zero-valued service-session GUIDs, and a logoff or termination without an in-window initiator do not establish defects.
- A possible Windows path-escaping issue was explicitly checked and rejected: decoded XML values contain ordinary single backslash separators. Display/serialization escaping is not a source-native field defect and contributes nothing to the score.

## Evidence For Real

- Windows Security events use event-specific structures rather than one interchangeable payload: sampled 4688 version 2 uses hexadecimal process IDs and a mandatory-label SID; 4624 version 2 contains the linked-logon/elevated-token fields; 4771 contains preauthentication status and certificate placeholders. Security success/failure keyword values differ appropriately in the sampled successful 4769 and failed 4771 records.
- The exact `WS-MCHEN-01` process pivot preserves PID `7208`, parent PID `5904`, `taskhostw.exe`, SYSTEM identity, and logon ID `0x3e7` across Security 4688, Sysmon 1, and eCAR PROCESS/CREATE. Source timestamps differ without reversing the visible process lifetime.
- DNS UID `CjDiL5ET9N7H5kjqFl` agrees between Zeek conn and dns records on the complete tuple, timestamp, UDP protocol, and response interval. Endpoint WFP, Sysmon DNS, and eCAR FLOW records independently agree on the host/process and destination.
- Linux sudo PID `2933509` has a command record, a subsequent PAM open, and a later PAM close; auth facility/severity and RFC5424-style headers are internally plausible.
- The sampled macOS ES fork/exec/exit data distinguishes the actor from exec target and retains PID version, executable metadata, audit identities, signing fields, and process start time. The Unified Log sample is recognizably a separate export shape, rather than normalized network/EDR telemetry.

## Detailed Analysis

### Scope and sampling

Only the assigned data directory and briefing were read. This was a bounded inspection of **20 representative records**, with supporting aggregates from the selected Windows files and one macOS ES file. It was not an exhaustive schema, lifecycle, or authenticity audit. No commands or links embedded in records were executed.

Paths below are relative to the assigned `data/` directory. `MCHEN` means `WS-MCHEN-01.meridianhcs.local/`; `DC01` means `DC-01.meridianhcs.local/`; `MAC01` means `MAC-MROSS-01.meridianhcs.local/`; `APP01` means `APP-INT-01.meridianhcs.local/`. Times are UTC on 2026-11-02.

| # | File / exact selector | Representative facts checked |
|---|---|---|
| 1 | MCHEN/windows_event_security.xml, record 948718 | 5156 v1 at 13:00:02.6464717; PID 5916, UDP 17, outbound `%%14593`, `10.10.1.31:57649 → 10.10.2.11:53`; native device application path. |
| 2 | MCHEN/windows_event_sysmon.xml, record 525176 | 22 v5; event UtcTime 13:00:02.677; process GUID `{7b2a0e3f-abdb-6adc-d802-0000dcad9316}`, PID 5916, query `_ldap._tcp.meridianhcs.local`, status 0; SRV-like result text. |
| 3 | MCHEN/ecar.json, id fd296eb2-1914-4882-bdc9-b07448be2e89 | FLOW/CONNECT at timestamp_ms 1793624402643; PID 5916, LOCAL SERVICE, same DNS tuple as #1. |
| 4 | zeek-core/conn.json, line 5 | UID CjDiL5ET9N7H5kjqFl; UDP/dns; duration 0.004598, state SF, history Dd, one packet each direction; 46/167 payload bytes and 74/195 IP bytes. |
| 5 | zeek-core/dns.json, line 4 | Same UID/tuple/ts; transaction 21588, qtype 33/SRV, NOERROR, rtt 0.004598; two answers and two TTLs. |
| 6 | MCHEN/windows_event_security.xml, record 948874 | 4624 v2 at 13:49:28.7946156; NETWORK SERVICE SID S-1-5-20, service logon type 5, logon ID 0x3e4, Advapi/Negotiate, no remote IP. |
| 7 | MCHEN/windows_event_security.xml, record 948733 | 4634 v0 at 13:04:58.3109708; omar.haddad, domain SID, logon ID 0x6bba35d, type 3. Initiator may predate the visible window. |
| 8 | MCHEN/windows_event_security.xml, record 948728 | 4688 v2 at 13:02:42.6189107; new PID 0x1c28, creator PID 0x1710, taskhostw.exe, SYSTEM/0x3e7, mandatory label S-1-16-16384. |
| 9 | MCHEN/windows_event_sysmon.xml, record 525184 | 1 v5; UtcTime 13:02:42.477; PID 7208, parent 5904, taskhostw.exe; System integrity, matching logon ID, hashes of appropriate hexadecimal lengths. |
| 10 | DC01/windows_event_security.xml, record 28245294 | 4769 v0 at 13:00:50.3849034; DC-02$ requests DC-01$, success 0x0, encryption 0x17, IPv4-mapped address ::ffff:10.10.2.11, decimal port 59131. |
| 11 | DC01/windows_event_security.xml, record 28251113 | 4771 v0 at 15:03:08.1963848; jennifer.walsh, krbtgt, status 0x12, PreAuthType 2, mapped IP ::ffff:10.10.4.10; failure keywords 0x8010000000000000. |
| 12 | MAC01/macos_endpoint_security.ndjson, global_seq_num 0 | Fork notification, event_type 11, version 11, at 13:00:06.950823000; launchd PID 1 creates child PID 41136/pidversion 12. |
| 13 | Same file, global_seq_num 1 | Exec notification, event_type 9, at 13:00:06.953308000; actor launchd PID 41136/pidversion 12, target xpcproxy same PID/pidversion 13; separate args/env/fds/cwd. |
| 14 | Same file, global_seq_num 3 | Exit notification, event_type 15, at 13:00:29.844683000; PID 41136/pidversion 14, Chrome image, user 501, exit stat 0. Intervening exec can change image/pidversion; no contradiction is alleged. |
| 15 | MAC01/macos_unified_log.ndjson, first record | 13:03:16.611945+0000; loginwindow PID 40562, UID 0, com.apple.loginwindow.logging/Standard; sender/process image identities and boot UUID supplied. |
| 16 | APP01/syslog.log, line 16 | 13:12:30.570840Z, sudo PID 2933509, aisha.johnson, TTY pts/2, PWD /var/log, root command /usr/bin/lsblk. |
| 17 | Same file, line 17 | 13:12:30.723194Z, same sudo PID; PAM session opened for root by UID 2528. |
| 18 | Same file, line 18 | 13:12:34.117710Z, same sudo PID; PAM session closed for root. |
| 19 | MCHEN/ecar.json, id 637f28a2-ef92-4612-a339-f94bb62bcd24 | PROCESS/CREATE at timestamp_ms 1793624562585; PID 7208, parent 5904, SYSTEM; objectID 9469aeb0-f350-4f4c-8c1c-9ffb5b224b62. |
| 20 | MCHEN/ecar.json, id 0f1bdce0-0ce8-4ddd-86e6-31d60b909918 | PROCESS/TERMINATE at timestamp_ms 1793624568870; same PID and objectID as #19, SYSTEM identity and logon ID 0x3e7. |


### Exact cross-source pivot 1: process creation and lifetime

The join key is host `WS-MCHEN-01`, PID `7208` (`0x1c28`), image `C:\Windows\System32\taskhostw.exe`, parent PID `5904` (`0x1710`), and the approximately 13:02:42 creation time. This is an exact identity/time/image join, not a hostname-only match.

- Sysmon 1 record 525184: UtcTime 13:02:42.477 and publication TimeCreated 13:02:42.4797906. The process GUID is `{7b2a0e3f-89f2-6ae8-5c02-0000d8538e2e}`; parent is svchost.exe, logon ID 0x3e7.
- eCAR CREATE: 13:02:42.585, pid 7208, ppid 5904, SYSTEM, logon_id 0x3e7. ObjectID 9469aeb0-f350-4f4c-8c1c-9ffb5b224b62 persists into the TERMINATE observation at 13:02:48.870.
- Security 4688 record 948728: 13:02:42.6189107; new/parent process IDs, paths, SYSTEM subject and System integrity agree.

Different timestamps on independent source records do not prove that a process existed before its actual creation. The source-native Sysmon occurrence time is earliest here, and termination is later than all three creation observations. I did not perform a third cross-source pivot into the termination records or a full parent-process audit.

### Exact cross-source pivot 2: DNS transport and query

The key is UDP `10.10.1.31:57649 → 10.10.2.11:53`, with endpoint process PID 5916 and Zeek UID `CjDiL5ET9N7H5kjqFl`.

- Endpoint eCAR FLOW occurs at 13:00:02.643; WFP 5156 at 13:00:02.6464717; Sysmon 22 gives UtcTime 13:00:02.677 and the `_ldap._tcp.meridianhcs.local` query.
- Zeek conn and dns both use ts 1793624403.208604 (13:00:03.208604), the exact same UID and tuple. DNS rtt equals the 0.004598-second connection duration.
- UDP accounting is consistent: 46 + 28 = 74 and 167 + 28 = 195 bytes for one IPv4/UDP packet each way. Successful query response and SF/Dd are coherent.

The roughly 0.53–0.57-second endpoint/sensor offset is compatible with independent clocks or source timing. A single pivot cannot establish clock calibration, and I do not label the offset impossible ordering. Complete matching itself contributes no synthetic evidence.

### Aggregate checks and detection usability

The selected MCHEN Security file contains 654 events: 396 WFP 5156, 114 process creates, 81 process exits, 23 logons, 13 logoffs, and other audit families. Its first/last records are 13:00:02.6464717–18:56:53.7403452. The selected Sysmon file contains 465 events, including 113 process creates, 81 terminates, 89 DNS events, and 89 network events, over 13:00:02.6805452–18:57:30.2746420. Different create counts do not establish a required missing companion under the selected collection scope.

All 114 Security 4688 image values and 113 Sysmon 1 image values in this host file use normal decoded path separators; all 113 Sysmon 1 User values use normal account separators. Sysmon 1 publication-minus-UtcTime ranges from 0.399 to 11.452 ms across 113 records, which does not show an identical fixed offset.

DC01 has 1,042 sampled-file TGS records with encryption types distributed as 727 AES256 (0x12), 160 AES128 (0x11), and 155 RC4 (0x17). This prevents mistaking the first RC4 sample for a dataset-wide exclusive protocol choice. It does not prove organizational crypto policy or authenticity.

MAC01 ES contains 141 records: 52 exec, 45 fork, and 44 exit. This family distribution is an observed collection characteristic, not evidence that other ES types should have been collected. The version-11 notification shape was inspected without asserting unverified native schema errors. I did not interpret the notification result field as a user authorization verdict or use the separate policy-message wording to claim denied execution.

### Limits and alternative explanations

The records can support detectors keyed on event IDs, principals, process ancestry, tuple/UID matching, and command text. Parser acceptance here means XML/JSON decoding and representative field inspection, not certification against every vendor manifest or the entire data population. No claim is made about unobserved event families, full clock models, long-tail frequency, whole-environment event volume, macOS release-specific implementation details, or absence of pre-window/post-window lifecycle evidence.

Production-like formatting and coherent joins are also compatible with well-made synthetic data. This is why the verdict is Inconclusive despite a low synthetic-confidence score; the score describes observed texture, while verdict confidence describes confidence in the limited provenance conclusion.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| None established | Windows, Zeek, Linux, macOS, eCAR | Bounded representative samples and two exact pivots | No demonstrated defect warrants an upward synthetic adjustment. |

No hard_contradiction, contract_gap, distribution_texture, schema_or_format, environment_or_collection_plausibility, or independent weak_signal finding met the evidence standard in this scope.

## Realism Score by Category

- **Field format accuracy:** 9 — Representative event-specific XML/JSON/syslog fields and decoded value formats are credible; no full native-manifest certification was performed.
- **Temporal patterns:** 9 — Sampled occurrence/publication timing and visible sudo/process lifetimes are plausible; independent clocks remain uncalibrated.
- **Cross-source correlation:** 9 — Both exact pivots preserve their identities and semantics; completeness is not treated as an authenticity indicator.
- **Behavioral realism:** 8 — Service authentication, scheduled process activity, sudo execution and macOS process transitions are plausible in the sampled records; broad behavior was outside scope.
- **Environmental consistency:** 8 — Platform-appropriate paths and source families agree in the sample; organization-wide roles and collection policy were not supplied.

## Recommendations

No corrective realism change is justified by a demonstrated defect in this bounded review. If this were synthetic, retain the observed event-specific schemas, exact process/tuple identities, and distinct source timestamps. Further realism recommendations would require a concrete defect from additional authorized sampling; adding uncollected event types, inventing retries, or weakening correct joins would not be evidence-based improvements.

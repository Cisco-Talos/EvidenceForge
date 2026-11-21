# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 28

## Executive Summary

The supplied telemetry is mostly production-like from a detection engineering perspective: parsers accept the records, native Windows fields preserve important event-specific distinctions, and the visible process, authentication, and transport identities hold together. I found one isolated unmatched Zeek SMB UID, but no demonstrated impossible lifecycle or source-native contradiction in the checks performed. The verdict is a modest lean toward real data, not a claim that a sufficiently careful synthetic producer could not produce this dataset.

## Evidence For Synthetic

- [weak_signal] `zeek-core/smb_mapping.json`, line 105, at epoch `1793640924.869945` contains UID `ClGQ20XvLARdhEcASSd`, tuple `10.10.1.22:54664 -> 10.10.2.20:445`, share `\\FILE-SRV-01\ClinicalExports`. That UID does not appear in any supplied `conn.json`. It is the single unmatched reference among 14,614 inspected DNS/HTTP/TLS/SMTP/SMB rows across the three sensors. This is a minor correlation defect for a SIEM join, but connection persistence across the collection boundary or source filtering could explain it; the records do not prove a generator error. It carries little weight in the score.

## Evidence For Real

- Windows Security preserves hexadecimal process IDs while Sysmon uses decimal IDs for the same process. On DC-02, Sysmon Event 1 record `1368549` at `13:02:15.5211172Z` identifies `dllhost.exe`, PID `6912`; Security 4688 record `25377497` at `13:02:15.6826729Z` has `NewProcessId=0x1b00`, the same command line and parent PID `0x13fc`/`5116`.
- Authentication and file-share lifecycles use meaningful identifiers. DC-02 Security 4624, 5140 and 4634 records `25377539`–`25377541`, at `13:04:44.0168723Z`, `13:04:44.0918417Z` and `13:04:48.2650255Z`, preserve `0xcb5c02d`, user `diego.ramirez`, and a Type 3 network logon in the correct order.
- Source-native details are not flattened into one generic schema. Security 1102 on DC-01 at `18:42:21.4815386Z` uses the Eventlog provider, `UserData/LogFileCleared`, and record ID `1`; ordinary auditing events use the Security-Auditing provider and named EventData.
- The same SSH tuple has sensor-specific observations rather than identical timestamps and packet visibility: `10.10.1.31:60321 -> 10.10.4.10:22` starts at epoch `1793627025.687933` in zeek-core and `1793627025.745454` in zeek-db. Core reports `missed_bytes=485` and 120 response packets; DB reports zero missed bytes and 121 response packets. The endpoint then records connection, successful public-key authentication and PAM session opening in causal order.
- macOS records distinguish a fork from an exec image transition. On MAC-MROSS-02, PID `88252` is forked from launchd at `13:12:07.845472000Z` with pidversion `12`, then execs xpcproxy at `13:12:07.861432000Z` with target pidversion `13`. eCAR likewise distinguishes PROCESS CREATE from MODIFY rather than inventing a new process for each exec.
- Routine scheduler repetition has an operational explanation. MAIL-EDGE-01, WS-LNGUYEN-01 and WS-OHADDAD-01 each show 36 `debian-sa1 1 1` executions, approximately ten minutes apart with host-specific phase and subsecond variation. This is consistent with sysstat scheduling and is not counted as a synthetic indicator.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. I parsed all 29,377 Windows XML events and all 38,189 eCAR JSON records, inspected native macOS records, and checked 23,502 Zeek connection records. I checked 14,614 protocol records against their own sensor's connection table for UID existence, tuple agreement, and timestamp placement inside the visible connection interval, allowing 10 ms before start and 100 ms after close for observational precision. I checked packet accounting for each connection direction: no negative/impossible relationship between payload bytes, IP bytes and minimum IP header overhead was found.

For Sysmon, I indexed visible process creates and terminations by ProcessGuid and checked dependent observations and child creation against those lifetimes, allowing 10 ms for timestamp differences. There were no flagged before-create, after-termination, future-parent or dead-parent relationships. For eCAR, analogous checks by process objectID/actorID found no relationship more than one second outside a visible process lifetime. These are bounded consistency checks, not proof of complete or authentic collection. Pre-window parents, unmatched termination events and post-window survivors were not counted as defects.

### Native Windows sample review

The following is a representative field-level sample. Times are UTC on 2026-11-02. Unless otherwise stated, rows are from DC-02's corresponding Windows XML file.

| Source / Event | Time; record ID | Fields inspected and result |
|---|---|---|
| Sysmon 22 v5 | 13:00:48.6988327; 1368530 | `QueryName=_kerberos._tcp.meridianhcs.local`, success status, SRV-shaped answer strings, ProcessId 4 / Image System; credible DNS event shape. |
| Sysmon 3 v5 | 13:00:48.9165637; 1368531 | Decimal PID 5136, UDP, boolean Initiated/IPv6 values and port 53; source and destination host IP are the DC itself, compatible with local DNS service use. |
| Sysmon 5 v3 | 13:01:14.2072687; 1368538 | ProcessGuid, decimal PID 5904, spoolsv image and SYSTEM user; recognizable termination shape. |
| Security 4689 v0 | 13:01:14.3161928; 25377475 | `ProcessId=0x1710` equals 5904, exit Status 0x0 and SYSTEM LUID; agrees with the prior Sysmon termination. |
| Security 4769 v0 | 13:01:20.9893872; 25377478 | `DC-01$` requests `DC-02$`, service SID, ticket flags, AES type 0x11, mapped IPv4 client address; credible Kerberos service-ticket fields. |
| Sysmon 10 v3 | 13:01:26.0357991; 1368542 | SourceProcessGUID/TargetProcessGUID, source thread ID, GrantedAccess 0x1010, module-offset CallTrace and source/target users; preserves process-access semantics. |
| Sysmon 1 v5 | 13:02:15.5211172; 1368549 | dllhost image metadata, hashes, decimal PID and parent identity, SYSTEM integrity and LUID 0x3e7; internally consistent. |
| Security 4688 v2 | 13:02:15.6826729; 25377497 | Hex PID, TokenElevationType `%%1936`, ParentProcessName and MandatoryLabel `S-1-16-16384`; matches the process above without confusing creator and target fields. |
| Security 4624 v2 | 13:04:44.0168723; 25377539 | Type 3, NTLM/NtLmSsp, NTLM V2, key length 128, remote IP/port and named workstation; meaningful authentication mechanism. |
| Security 5140 v0 | 13:04:44.0918417; 25377540 | Share audit SubjectLogonId matches that Type 3 login. |
| Security 4634 v0 | 13:04:48.2650255; 25377541 | Same user/LUID and Type 3; follows the share audit. |
| Security 4672 v0 | 13:08:16.8672064; 25377636 | NETWORK SERVICE SID S-1-5-20 and LUID 0x3e4, with service-appropriate privileges; not assigned a human user's SID. |
| Security 4768 v0 | 13:11:25.3188394; 25377725 | MAC-MROSS-02$ requests krbtgt; service SID ends in 502, AES 0x12 and PreAuthType 2; coherent machine-account domain activity. |
| Security 4776 v0 | 13:13:10.4730897; 25377790 | `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0`, TargetUserName, Workstation and Status; distinct NTLM validation shape. |
| Sysmon 13 v2 | 13:50:13.3638555; 1369219 | SetValue under Defender Real-Time Protection, DWORD 0, MsMpEng actor; plausible configuration observation. |
| Sysmon 7 v3 | 14:00:11.4573357; 1369346 | Explorer loads FileSyncShell64.dll with signature status Valid and image metadata; module loading is not confused with process creation. |
| Sysmon 8 v2 | 14:43:26.0110443; 1369922 | SearchIndexer -> SearchProtocolHost, distinct process GUIDs, NewThreadId, StartAddress/Module/Function; appropriate remote-thread fields. |
| Security 4771 v0 | 16:00:33.4657650; 25382043 | Failure audit keywords `0x8010000000000000`, Status 0x18 and PreAuthType 2; failure differs correctly from success events. |
| Security 4625 v0, DC-01 | 16:25:08.6145037; 28254476 | General failure 0xc000006d and disabled-account substatus 0xc0000072 for svc_mgmt, Type 3 NTLM; useful failure specificity. |
| Security 4656/4663/4658, FILE-SRV-01 | 13:00:05.9844267 / 13:00:06.1459007 / 13:00:09.7044242; 271776–271778 | Same handle 0xec6f2c02 and LUID 0xf62b74b; requested mask 0x12019f precedes actual write access 0x2 and handle close. The distinction between requested and exercised rights is preserved. |

All parsed events use structurally valid XML. Relevant successes use Level 0 and success audit keywords; inspected failures use failure audit keywords. Inspected Sysmon events use the Operational channel, information level and their event-specific task numbers. SID/GUID syntax and source-native PID representations in this sample are credible. I did not assert a defect merely because a selected event version is older than another version that can exist on newer Windows builds.

The 927 visible Sysmon process creations also have ProcessGuid timestamp portions consistent with the event's creation second. That removes one common process-identity contradiction, although the property is reproducible by a careful producer.

### Zeek, Linux authentication and eCAR

Only the single SMB mapping noted above failed the UID existence test. All existing UID joins in the inspected protocol families agreed on the four-tuple and fit the connection interval. Schema examples preserve numeric ports, boolean DNS flags, DNS answer/TTL arrays, SMB names and paths, TLS certificate FUID arrays, and files.log connection UID arrays.

The SSH example is particularly useful for causal review. The zeek-db connection is UID `CfwhU800KbIHzPntDI`, duration `1035.838309`, state SF. DB-PROD-01 syslog records connection from port 60321 at `13:43:49.252679Z`, public-key acceptance at `13:43:55.566288Z`, and PAM session opened at `13:43:55.688693Z`; eCAR USER_SESSION LOGIN follows at epoch-ms `1793627035822` (`13:43:55.822Z`). Transport thus precedes successful authentication and the endpoint session, while the source timestamps remain distinct.

The syslog files use parseable RFC5424-style envelopes with PRI, version, UTC timestamp, hostname, application, PID, message ID and structured-data placeholders. Sudo records distinguish the requesting user from a root session, e.g. DB-PROD-01 at `13:03:30.917428Z`, `pam_unix(sudo:session): session opened for user root(uid=0) by maya.ross(uid=2176)`. Linux million-range PIDs are permissible on hosts configured for large PID spaces and are not a defect by themselves.

### macOS interpretation

The native ES files contain 315 records: 100 fork, 117 exec and 98 exit notifications, with declared message version 11. Event types 11, 9 and 15 align with fork, exec and exit event bodies. I checked actor versus target shape, audit-token fields, PID version transitions, executable paths and stable image metadata; no observed use-after-exit emerged. The launchd -> xpcproxy -> application pattern, distinct terminal shell sessions, real/effective/audit UID fields, signing identity and per-image cdhash values support usable detection semantics.

The five Unified Log rows are a separate source with logEvent/messageType, timestamp offset, boot UUID, writer/sender paths, subsystem/category and eventMessage fields. For example MAC-MROSS-02 records loginwindow at `13:04:18.924354+0000` and sshd-session authentication activity separately. I did not impose native ES event semantics on eCAR FLOW rows or count sparse Unified Log coverage as a defect. I also did not treat notification result fields as authorization decisions or infer that a launch plist observation proves execution.

### Limits and weighting

The strongest finding is absence of demonstrated contradictions in the tests performed, not a provenance signature. Complete cross-source matching is not used as negative authenticity evidence. Domain spelling, file copy timestamps, a narratable intrusion sequence, selected Sysmon coverage, and missing out-of-window lifecycle boundaries have no weight in the score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Zeek SMB mapping / connection join | One UID, `ClGQ20XvLARdhEcASSd`; 1 of 14,614 inspected protocol rows | Slight upward pressure only. A SIEM correlation is unavailable, but a collection boundary or filtering can explain it; no impossible native relationship is demonstrated. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse cleanly; detailed native Windows event distinctions and inspected ES shapes are credible.
- **Temporal patterns:** 9 — Visible process lifetimes, SSH authentication order and transport intervals agree; scheduler periodicity has a valid operational explanation.
- **Cross-source correlation:** 9 — Strong process/session/tuple agreement with an isolated unmatched SMB mapping UID.
- **Behavioral realism:** 8 — Service-specific traffic, sudo actor changes, machine-account authentication and scheduled sysstat activity are plausible within the visible collection.
- **Environmental consistency:** 9 — Windows, Linux and native macOS evidence use distinct platform semantics; no demonstrated incompatible host/software placement was found.

## Recommendations

- If this were synthetic, preserve the owning Zeek connection for SMB mapping UID `ClGQ20XvLARdhEcASSd` when the collection policy calls for it. If the owning connection intentionally falls outside the slice or is filtered, retain that collection explanation rather than adding a fabricated connection solely to make a join complete.
- No further corrective recommendation is justified by the checks performed. Continue validating event-version-specific fields and lifecycle identities when extending coverage; the supplied sample does not establish another concrete defect requiring repair.

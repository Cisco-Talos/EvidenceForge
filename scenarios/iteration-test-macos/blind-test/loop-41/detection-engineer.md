# Detection Engineer — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 87
**Synthetic-Confidence Score:** 63

## Executive Summary

The records are unusually strong on parseability, source-specific fields, process identity and network correlation; I did not establish an impossible lifecycle or broad native-schema failure. However, the native macOS process notifications contain repeated microsecond-identical timing anchors across unrelated commands and exact repeated process lifetimes across both hosts. Those reproducible timing distributions make synthetic generation more likely than production collection, while the otherwise coherent evidence keeps the score near the lower end of the likely-synthetic band.

## Evidence For Synthetic

- [distribution_texture] **Repeated six-digit fractional fork timestamps:** In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 32, 35 and 38 report separate zsh forks at `13:48:35.351324000Z`, `13:49:05.351324000Z` and `13:49:55.351324000Z`. Their exec children run `pwd`, `ls -la /Users/maya.ross/Documents` and `du -sh /Users/maya.ross/Documents` on lines 33, 36 and 39. Lines 53, 56 and 59 similarly reuse `.173001000` for `df`, `ps` and `find` forks spaced 37 and 52 seconds apart. This is repeated subsecond identity in distinct kernel-level operations, not merely a shared timestamp on different views of one event.
- [distribution_texture] **The same timing texture occurs on the second Mac:** `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` lines 155, 158 and 161 have fork times `18:24:27.675443000Z`, `18:25:32.675443000Z` and `18:26:32.675443000Z` for `find`, `ps` and `pwd` executions. Across the two ES files, 38 of 108 fork records belong to 15 repeated fractional-timestamp groups: 18/50 on the first host and 20/58 on the second. Some groups are browser startup sequences, which are related activity, but the repeated fractions also span the independent shell commands above. Integer-second scheduling can explain rough cadence; retaining exactly the same microsecond across so many actual forks is a stronger artifact.
- [distribution_texture] **Six inventory process lifetimes are exactly 2.000000 seconds from fork to exit:** On MAC-MROSS-01, ES line pairs 28/31, 70/73 and 133/136; on MAC-MROSS-02, pairs 31/34, 95/98 and 138/141. Each is a launchd → xpcproxy → `/usr/bin/sw_vers` chain. For example, MAC-MROSS-01 line 28 forks at `13:31:25.866513000Z`, line 30 executes sw_vers at `13:31:25.873119000Z`, and line 31 exits at `13:31:27.866513000Z`. Startup latency varies, but termination always lands on the original fork fraction exactly two seconds later. A shared inventory task is plausible; six identical microsecond-exact total lifetimes are a tell of a fixed duration assigned to the activity.

## Evidence For Real

- All 20 Windows XML files parsed successfully. Representative records preserve provider GUIDs, channel, version, task, level, keyword and source-specific payload distinctions rather than treating every event as one generic schema.
- Across all ten Windows hosts, the Sysmon lifecycle check found no referenced process GUID used before its visible creation or after its visible termination, allowing a 10 ms comparison tolerance. Referenced PID/image pairs agreed with visible Event 1 identities. Pre-window processes were left unjudged.
- All 12,335 checked Zeek DNS/HTTP/TLS/SMTP/SMB protocol rows referenced a connection in their own sensor directory, with matching endpoint tuples. Their timestamps fell within their connection intervals, allowing 1 ms before open and 200 ms after close for the comparison. No individual HTTP response body exceeded its connection's responder byte count. This is credible correlation, not an authenticity defect.
- MAC-MROSS-01 ES lines 1–10 distinguish fork, successive exec images, PID versions and exit: launchd → xpcproxy → Terminal, followed by a login/zsh chain and an `id` command. Within each `(pid, pidversion)` identity, executable path and process start time are stable, and there are no visible uses before birth or after exit in either Mac's ES file.
- `DC-01.meridianhcs.local/windows_event_security.xml` line 268424 uses the Eventlog provider and a `UserData/LogFileCleared` payload for Event 1102, with RecordID reset to 1. That is a meaningful native exception handled correctly rather than rendering log clearing as a generic Security-Auditing EventData record.
- The network data includes meaningful differences between TLS 1.2 certificate visibility and TLS 1.3 handshakes, failed connection states, DNS query types, NAT-aware ASA fields and CONNECT tunnel accounting. For example, `zeek-core/ssl.json` line 1 is TLSv13 without an invented visible certificate chain, while `zeek-dmz/ssl.json` line 1 is TLSv12 and references certificate FUIds.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed every Windows XML file, inspected actual payloads from more than 20 distinct Windows event types, checked all visible Sysmon GUID lifecycles, parsed the Zeek JSON families and checked their connection references, and inspected both macOS ES streams and their Unified Log companions. Source absence, deliberate Sysmon event selection, sanitized domains, file modification times and completeness of an intrusion narrative were not used as authenticity evidence.

The checks are bounded by the visible collection window. A missing process creation before the window, an open session at the end, and a type 7 unlock for an already-existing logon ID are neutral. Similarly, independent clocks and collection delays prevent treating small timestamp differences between sources as contradictions.

### Windows schema and event semantics

The following samples illustrate the source-specific verification. Line numbers identify the opening Event element; all times below are UTC on 2026-11-02. The file is `DC-01.meridianhcs.local/windows_event_security.xml` unless stated otherwise.

| Type / line | Time / RecordID | Fields checked and observation |
|---|---|---|
| 4624 / 3 | 13:00:22.7331903 / 28245268 | Version 2, logon type 5, SYSTEM SID `S-1-5-18`, `0x3e7`, Advapi/Negotiate, no remote IP; coherent service logon. |
| 4672 / 58 | 13:00:22.7458394 / 28245269 | Same SYSTEM identity/logon ID and multiline privilege tokens; follows the service logon. |
| 5156 / 101 | 13:00:57.9077322 / 28245287 | Decimal ProcessID 2420, native device application path, protocol 17, inbound DNS tuple and WFP layer fields. |
| 4768 / 388 | 13:01:40.7220046 / 28245315 | Machine account `LT-MRIVERA-02$`, krbtgt service SID ending 502, AES type `0x12`, IPv4-mapped client address, preauth type 2. |
| 4769 / 430 | 13:01:40.7252215 / 28245316 | Same client IP/port, target service account `DC-01$`, separate TGS payload and success status. |
| 4688 / 469 | 13:01:42.9596624 / 28245318 | Version 2, hexadecimal new PID `0xe1c` (=3612), WmiPrvSE image, parent PID `0x924`, token/mandatory-label and target-subject fields. Matching Sysmon Event 1 identifies PID 3612 and parent PID 2340. |
| 4634 / 4359 | 13:08:32.2463201 / 28245580 | Target account, target LogonID and type 3 are correctly distinct from subject fields. |
| 4776 / 4433 | 13:08:51.3917027 / 28245591 | NTLM credential-validation package, workstation and status fields; no invented Kerberos ticket fields. |
| 5140 / 51391 | 14:09:06.2457795 / 28248413 | SYSVOL share name, NT-style local path, remote IP/port and subject logon identity. |
| 4771 / 74453 | 14:40:57.6799278 / 28249859 | Failure keyword `0x8010000000000000`, krbtgt, failure status `0x12`, mapped client IP and preauth fields. |
| 4697 / 182203 | 16:59:44.8958060 / 28256342 | PSEXESVC service installation, `%SystemRoot%\PSEXESVC.exe`, type `0x10`, demand start 3 and LocalSystem account. |
| 4720 / 192319 | 17:14:52.0809664 / 28256994 | Domain SID, SAM name, old/new UAC values and account-property fields; source-native account creation shape. |
| 4698 / 197734 | 17:19:55.0522831 / 28257261 | Embedded task XML parses as content and supplies trigger, principal, settings and executable action. |
| 1102 / 268424 | 18:42:26.0007020 / 1 | Eventlog provider, Level 4, Task 104, proper UserData exception and record-number reset. |

I also examined 4625, 4648, 4656, 4658, 4663, 4724, 4728, 4738, 4779, 4800/4801 and Sysmon 1/3/5/7/8/10/11/13/22 payloads. No demonstrated schema defect from those samples contributes to the score. In particular, Sysmon Event 10's uppercase `SourceProcessGUID`/`TargetProcessGUID` field spelling was not confused with the different capitalization used by other event types.

### Zeek and SIEM correlation

The three conn files contain 22,030 rows: core 12,279, DMZ 9,287 and DB 464. Protocol reference checks covered 3,993 DNS, 4,825 HTTP, 3,106 TLS, 67 SMTP, 218 SMB-file and 126 SMB-mapping records. These total **12,335** protocol rows.

As a concrete example, `zeek-core/dns.json` line 1 and `conn.json` line 2 share UID `CYTxdaWg8hQSZFUhNr`, UDP tuple `10.10.1.21:34462 → 10.10.2.10:53`, and timestamp `1793624457.725877`. The DNS row's SRV query, answer array and TTL array have appropriate shapes. `zeek-core/smb_files.json` lines 1–2 share UID `CGGIhzcd1Hc4Y0cAlD` and use separate FILE_OPEN/FILE_READ actions; the read's FUID matches `files.json` line 1 and its byte count is 5,359,834.

I also grouped X.509 rows by fingerprint and by certificate serial across all sensors; I found no conflicting certificate metadata within either grouping. These checks support utility in a SIEM. Perfect matching is not itself evidence of synthetic origin.

### macOS source semantics and timing

I treated ES notifications, normalized eCAR and Unified Log as separate exports. ES records declare message version 11 and carry action/result unions, audit tokens, event-specific fork/exec/exit payloads and signing/file metadata. I have not asserted a native schema defect based on unfamiliar version-specific additions.

The kernel policy line in MAC-MROSS-01's Unified Log line 2 says policy **would not allow** MeetingAssist; that message alone does not establish a denied execution. The SSH success message in line 3 is authored by `/usr/libexec/sshd-session` rather than being misread as a network sensor row. Neither is counted as a synthetic indicator.

The scored concern is the timing distribution inside the native ES stream itself. The repeated fractions survive even where actual exec timestamps have independent small delays. Likewise, inventory exits are anchored exactly to fork+2 seconds, despite different launchd/xpcproxy/exec startup intervals. These are compatible with an event scheduler assigning activity anchors and durations; they are poorly explained by ordinary kernel observation timing. They do not demonstrate an impossible individual event, so I classify them as distribution texture rather than hard contradictions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS ES fork timing | 38 of 108 forks across both hosts participate in 15 repeated fractional groups | Strongest indicator; independent command forks recur at exactly the same microsecond fraction. |
| distribution_texture | Native macOS ES inventory lifecycles | Six complete sw_vers activities, three per host | Supporting timing fingerprint: all fork-to-exit intervals equal exactly 2.000000 seconds despite varied startup latency. |

These are related temporal findings, not two unrelated hard defects. No score increase is assigned for source completeness, thin Unified Log coverage, absence of other Sysmon event types, sanitized naming or narrative structure.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed XML/JSON and sampled native event payloads are strong; no substantiated broad schema defect.
- **Temporal patterns:** 5 — Repeated microsecond anchors and exact inventory lifetimes materially weaken authenticity.
- **Cross-source correlation:** 9 — Zeek references and visible Windows process identities are coherent under bounded checks.
- **Behavioral realism:** 8 — Plausible mixed endpoint/network activity with differentiated process trees and authentication mechanisms.
- **Environmental consistency:** 9 — Windows/Linux/macOS distinctions and routed network sources are broadly coherent; missing optional telemetry was not penalized.

## Recommendations

- If this were synthetic, retain the underlying causal ordering but assign each actual fork its own plausible observed timestamp. Avoid copying the entire fractional timestamp into separate command launches tens of seconds apart.
- If this were synthetic, model inventory completion from execution/runtime rather than terminating every launchd activity exactly two seconds after fork. Let startup latency and runtime contribute to the final observed exit time.
- Preserve the existing source-specific schemas, visible identity consistency and Zeek reference integrity while changing the timing texture. Adding unrelated sources or deliberately breaking correlations would not address the observed issue.

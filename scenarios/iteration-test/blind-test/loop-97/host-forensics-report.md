# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 32

## Executive Summary

The bounded endpoint sample is mostly production-like: Windows process identities agree across three sources, Linux SSH authentication agrees with normalized session telemetry, and macOS records distinguish fork and successive exec images. Repetitive macOS version-query activity is a weak texture signal, but I found no demonstrated impossible identity, ordering, or field value in the inspected records; this sample cannot reliably establish origin.

## Evidence For Synthetic

- [weak_signal] Both Macs repeatedly execute `/usr/bin/sw_vers` during the approximately six-hour slice: 5 of 52 ES exec notifications on MAC-MROSS-01 and 6 of 64 on MAC-MROSS-02. On the same named user's two machines, version queries account for 11 of 116 exec notifications. This could reflect a reused command pool, but administrative scripts or an intentionally filtered collection could explain it. It only slightly raises the score.
- [weak_signal] Shared mundane process vocabulary dominates the two Mac exec aggregates: `sw_vers`, `id`, `ls`, `uname`, `df`, `ps`, `find`, and `du` appear on both hosts. This overlaps the preceding observation and is not counted as a separate strong defect. Different actual command arguments and workload selection have not been comprehensively tested.

## Evidence For Real

- WS-AJOHNSON-01 Sysmon Event 1 record 30326, Security Event 4688 record 129968, and eCAR PROCESS/CREATE agree on PID 5180 (`0x143c`), parent 4356 (`0x1104`), `taskhostw.exe /Run`, SYSTEM, and the `svchost.exe` parent. Their source timestamps differ modestly rather than presenting an impossible lifecycle.
- APP-INT-01 records a successful password authentication for `lina.nguyen` from `10.10.1.21:38780` at 13:34:47.103568Z, a PAM session opening at 13:34:47.243309Z under the same sshd PID 2937762, and a matching eCAR SSH login at 13:34:48.126Z.
- MAC-MROSS-01 shows PID 41136 forked from launchd, execing xpcproxy, then execing Google Chrome, retaining its process start time while changing image and pidversion. The fork and first exec inherit root identity; the final Chrome target uses UID/AUID 501 and a user environment. This has substantially more lifecycle detail than a flattened process list.
- Three selected Windows hosts have stable hashes for repeated occurrences of the same image path within each host, and every inspected aggregate hash has the expected hexadecimal digest length. The hosts' process and source-family distributions differ substantially.
- The first Windows process termination in the slice is not treated as an orphan: its creation could precede collection. Linux syslog includes rsyslog queue backlog noise, and a sampled history entry is the ordinary command `timedatectl`.

## Detailed Analysis

### Scope and method

I read only the supplied briefing and files inside the assigned `data` directory. I inspected 19 representative logical records: two Windows termination observations and their eCAR counterpart; a Windows creation and its Security/eCAR joins; one Linux daemon-health record, one SSH authentication, one PAM session opening, one eCAR login and one history command; two Mac fork records, two Mac initial exec records, one subsequent Chrome exec, one Mac normalized fork observation, one Unified Log entry; and two Windows session-manager creations. The history timestamp and command are counted as one logical history record.

I additionally computed bounded aggregates for the two Mac ES exports and Unified Log exports and three Windows Sysmon files (WS-AJOHNSON-01, DC-01, FILE-SRV-01). Aggregation extracted event counts, executable distributions and hash consistency; it was not a full lifecycle or exhaustive cross-source audit. All dates below are November 2, 2026 UTC. File references are relative to `data`; host directories carry the suffix `.meridianhcs.local`.

### Exact cross-source pivot 1: Windows process creation

In `WS-AJOHNSON-01.../windows_event_sysmon.xml`, EventRecordID 30326 has SystemTime `13:10:01.7957426Z`, UtcTime `13:10:01.794`, ProcessGuid `{fd907e59-8ba9-6ae8-5f00-00102d8b8bdb}`, PID 5180, parent PID 4356, image `C:\Windows\System32\taskhostw.exe`, command `taskhostw.exe /Run`, SYSTEM, LogonId `0x3e7`, and TerminalSessionId 0.

Security record 129968 in the same host's `windows_event_security.xml` is Event 4688 at `13:10:02.1751666Z`, NewProcessId `0x143c` = 5180, creator ProcessId `0x1104` = 4356, matching image/command, SYSTEM SID `S-1-5-18`, LogonId `0x3e7`, and mandatory label `S-1-16-16384`. eCAR PROCESS/CREATE at timestamp_ms 1793625002033 (`13:10:02.033Z`), objectID `c1768f0c-97ca-49d9-8ee4-a5716307f697`, agrees on PID, PPID, command, principal, and parent image. I do not assume that Sysmon ProcessGuid and normalized eCAR objectID must be identical.

The three observations span about 379 ms and preserve compatible process ownership. No exact-identity creation/termination inversion was demonstrated. The earlier Sysmon Event 5 at `13:00:22.0699245Z`, Security 4689 at `13:00:22.3504973Z`, and eCAR TERMINATE at `13:00:22.137Z` also agree on SSH client PID 5116 (`0x13fc`), image and Aisha's identity. The unseen creation may be before the window.

### Exact cross-source pivot 2: Linux SSH session

`APP-INT-01.../syslog.log` has:

- `13:34:47.103568Z`, sshd PID 2937762: `Accepted password for lina.nguyen from 10.10.1.21 port 38780 ssh2`.
- `13:34:47.243309Z`, the same sshd PID: `pam_unix(sshd:session): session opened for user lina.nguyen(uid=5302) by (uid=0)`.

`APP-INT-01.../ecar.json` at `13:34:48.126Z` is USER_SESSION/LOGIN, principal `lina.nguyen`, source `10.10.1.21:38780`, outcome success, session_type ssh, logon_id `0x1518bcf1`, session_id `337`, objectID `3451c175-9da0-45cb-ba13-aefd36fb3f7b`. Username, exact tuple and close timestamp provide the join. The later normalized observation is compatible with collection delay; it does not establish a delayed underlying authentication. I did not inspect the close of this exact session and assign no missing-close penalty.

Other sampled Linux evidence is rsyslog queue backlog at `13:00:32.218756Z` (2028 pending messages, two workers) and Lina's timestamped `timedatectl` history entry. These are plausible, but too few to establish overall Linux workload quality.

### macOS lifetime and identity interpretation

In `MAC-MROSS-01.../macos_endpoint_security.ndjson`, the sampled launchd fork is at `13:00:06.950823000Z`, event_type 11, message version 11. The child PID 41136 has pidversion 12, parent PID 1, root identity, and launchd's inherited image. At `13:00:06.953308000Z`, event_type 9 records the same PID execing xpcproxy with target pidversion 13. At `13:00:06.958279000Z`, the target becomes Google Chrome with pidversion 14, UID/AUID 501, ASID 100001 and user environment for `maya.ross`. Its start_time remains the original fork time. The intermediate process credentials and target credentials are distinct fields and are not incorrectly interpreted as two simultaneous contradictory identities.

The normalized fork at `13:00:08.307Z` has PID 41136, PPID 1, principal root, operation fork, inherited launchd image, objectID `85243acd-6fc1-4805-aaa7-5f44bd360f9e`. Its later timestamp is compatible with normalized observation delay. I did not inspect all subsequent normalized exec observations and make no claim of exhaustive image-to-image alignment.

MAC-MROSS-02's corresponding sampled fork at `13:09:33.569707000Z` uses a different PID (18757), device and inode, then xpcproxy exec at `13:09:33.571733000Z`. Across the two exports, ES contains 141 and 175 records respectively: 52/64 exec, 45/54 fork, and 44/57 exit notifications. Unequal counts are not defects because inherited processes, exec-only transitions and window boundaries can explain them.

The sampled Unified Log row is loginwindow's `-[Login1 launchWorkspace] | enter` at `13:03:16.611945+0000`, not an Endpoint Security process-creation event. The Unified Log files contain only 3 and 2 rows respectively. That may be a filtered export; coverage thinness alone is excluded from the score. I verified no OS release-dependent native schema violation and make no such allegation.

### Aggregate texture and Windows environment

The selected Sysmon files span approximately `13:00–19:00Z`. WS-AJOHNSON-01 has 118 Event 1, 99 Event 5 and 161 Event 3 records; DC-01 has 153, 152 and 3975 respectively; FILE-SRV-01 has 96, 97 and 98. This supports varied host roles, not a uniform per-host event quota. Other event-type absences are not used as evidence.

The same-image hash consistency aggregates cover 117 SHA1/MD5/SHA256-bearing creations on WS-AJOHNSON-01, 152 on DC-01 and 96 on FILE-SRV-01. IMPHASH counts are 114, 150 and 96. None has an incorrect expected digest width; no image path within a selected host has multiple values for the same hash algorithm. This does not prove the digests correspond to actual vendor binaries, which was not tested.

DC-01 record 3289739 (`13:54:26.8458273Z`, PID 4032, session 6) and FILE-SRV-01 record 1644471 (`14:21:53.2234468Z`, PID 5336, session 7) show SYSTEM smss.exe with an smss.exe parent. Per-session manager creation is compatible with Windows session lifecycles; it is not treated as a new machine boot or a contradiction simply because collection begins earlier. Missing version metadata in these entries is not independently diagnostic.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | macOS ES exec notifications | `sw_vers`: 5/52 execs on MAC-MROSS-01, 6/64 on MAC-MROSS-02 | Mild repeated-command texture; admin tooling and filtering remain viable explanations |
| weak_signal | macOS ES executable distribution | Shared utility names across the same user's two hosts | Corroborates the same weak texture observation; not scored independently |

No hard_contradiction, demonstrated contract_gap, or verified schema_or_format defect was established in this bounded sample.

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled native and normalized fields are internally plausible; hash widths are valid. Native release-specific correctness was not comprehensively verified.
- **Temporal patterns:** 9 — Sampled forks, execs, authentication and delayed observations are compatible; broad timing distributions were not audited.
- **Cross-source correlation:** 9 — Two exact substantive joins and a Mac fork observation agree on identities and source semantics.
- **Behavioral realism:** 7 — Plausible platform-specific behavior, with repeated macOS version queries providing a modest texture concern.
- **Environmental consistency:** 8 — Windows host distributions differ with apparent roles; limited Linux and filtered Mac evidence constrain confidence.

## Recommendations

- If this were synthetic, review whether the repeated `sw_vers` executions on both Macs are driven by a credible visible administrative workflow. Derive repeated discovery commands from particular scripts, troubleshooting sessions or application probes instead of repeating a general-purpose pool without that context.
- Retain the observed distinctions between process lifetime and exec image, source observation times and underlying activity, and exact parent/session identities. Those details make the sampled evidence coherent.
- No recommendation to add absent source families or out-of-window lifecycle endpoints is warranted from this bounded review.

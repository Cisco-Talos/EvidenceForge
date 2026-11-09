# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 75
**Synthetic-Confidence Score:** 52

## Executive Summary

The operational evidence is substantially realistic: suspicious activity can be followed across host processes, authentication, network transport, proxying, and file movement without a demonstrated impossible lifecycle. My synthetic verdict rests chiefly on a reproducible filesystem-metadata pattern across the two Mac hosts, with a smaller contribution from the narrow way shared-document access is represented; these are distribution artifacts rather than proof that the observed intrusion could not work.

## Evidence For Synthetic

- [distribution_texture] Executable inode values are strictly ordered by full pathname on both Macs, across unrelated application, operating-system, and user-library binaries. All 26 distinct executable paths observed on MAC-MROSS-01 and all 31 on MAC-MROSS-02 have increasing `executable.stat.st_ino` when sorted alphabetically. For example, MAC-MROSS-01's `macos_endpoint_security.ndjson` lines 33, 36, 48, and 51 expose `/bin/pwd` = 2992497, `/bin/ls` = 2992495, `/bin/df` = 2992493, and `/bin/ps` = 2992496. On MAC-MROSS-02, corresponding values are 2509813, 2509811, 2509809, and 2509812. Across the 23 shared executable paths, 20 inode pairs differ by exactly 482684 and the other three by 482685. This resembles allocation from a pathname catalog much more than independent installation and update histories. It is the highest-weight indicator, although image provisioning or metadata sanitization could provide an alternative explanation.
- [distribution_texture] Shared-document access on MAC-MROSS-02 has a narrow command-to-artifact mapping: all ten visible `/Volumes/` FILE/READ observations are associated with eight `/bin/cat` processes and two `/bin/ls` processes. The sole corresponding write uses `/usr/bin/tee`. Examples include `ecar.json` lines 318/320 (`cat ...service-review.xlsx`), 447/451 (`cat ...project-plan.docx`), 454/458 (`cat ...onboarding.docx`), and 580/584 (`tee ...draft.docx`). These commands are possible, but repeatedly representing Office/PDF work as raw terminal byte reads while Word is also running gives this slice a limited behavioral vocabulary. This is a modest distribution indicator, not an impossible action or a requirement for additional collection.

## Evidence For Real

- Transport-before-authentication ordering held in the remote-session checks. Across the 75 successful SSH or Windows Type 10 login observations in eCAR, I found no matching endpoint FLOW more than one second after the login, using source address, source port, destination service, and the relevant time neighborhood. This does not establish every protocol detail, but it avoids a common impossible pivot.
- The database-to-application SCP pivot has plausible endpoint and network companions. DB-PROD-01 `ecar.json` lines 600 and 602 show the SCP process and source-file read; APP-INT-01 lines 938–942 contain the inbound transport, SSH session, and receiver file creation. `zeek-core/conn.json` line 11017 and `zeek-db/conn.json` line 433 describe the same 10.10.4.10:56155 → 10.10.2.30:22 transfer with roughly 25.28 seconds of transport and asymmetric byte counts consistent with an upload.
- Windows network-only credentials retain the local identity rather than changing every process into the outbound identity. WS-AJOHNSON-01 `ecar.json` line 1133 records a Type 9 session with local principal `aisha.johnson`, outbound principal `marcus.chen`, and cloned session `0x2702395`; line 1134 gives the new `cmd.exe` the new LogonID `0x27cb381` while preserving the local principal.
- Normal background and ambiguous activity are present in meaningful volume: 19,411 Security events, 12,058 Sysmon events, 4,291 Linux syslog lines, 22,509 sensor-local Zeek connection records, and 3,551 proxy records. The connection mix includes incomplete/reset/rejected sessions, not only successful exchanges. Domain controllers dominate Windows authentication/network volume, while the web and proxy hosts dominate their respective service evidence.
- The suspicious web activity has technically usable pivots rather than only narrative labels. WEB-EXT-01 `web_access.log` line 449 shows a POST to `/ehr/admin/upload.php` at 14:19:51 UTC; `ecar.json` line 984 shows a `www-data` shell at 14:19:52.737; `zeek-dmz/conn.json` line 2011 shows the subsequent 10.10.3.10 → 45.33.32.30:8443 TCP session. This supports investigation, although the access row alone does not prove the exact exploit mechanism.

## Detailed Analysis

### Scope, provenance, and method

I read only the supplied neutral threat-hunter instructions and files under `/private/tmp/log-study-0kwedkcm/data`. Parsing used system `python3` from `/private/tmp`; I did not access project code, scenario files, prior assessments, other reviewers, TODO files, or worklogs. No external sources were consulted. Generic inherited operating instructions were not treated as evidence of data origin.

The supplied slice spans approximately 2026-11-02 13:00–19:00 UTC. It contains 23 endpoint host directories: ten with Windows Security/Sysmon XML, eleven with Linux syslog, and two with Mac Endpoint Security/Unified Log exports. eCAR is present for all 23. Additional sources include three Zeek sensor directories, two Snort directories, perimeter ASA logs, a forward proxy, and web access logs. The apparent address structure places clients in 10.10.1.0/24, much of the server environment in 10.10.2.0/24, DMZ systems in 10.10.3.0/24, and the production database in 10.10.4.0/24.

I counted source records, parsed the Windows XML, inspected suspicious process commands and file operations, and checked actor/process lifetime relationships in eCAR. The automated actor check compared visible PROCESS/CREATE and PROCESS/TERMINATE timestamps against events referring to that process identity, with a one-second tolerance. It found no referenced actor demonstrably used more than one second before its visible creation or after its visible termination. This is a bounded check; it does not validate every PID field or every native source timestamp.

### Hunting pivots and operational coherence

The web foothold is visible through a suspicious upload, a `www-data` shell with a base64-decoded reverse-shell command, and an outbound transport. The connection begins at epoch 1793629195.836582 and lasts 27.203172 seconds; the shell remains visible until 14:20:37.107 (`WEB-EXT-01/ecar.json` line 990). The network interval fits within the observed shell lifetime. I do not infer that a later root SSH login was necessarily produced by this shell: the logs independently show that root session, and do not expose every credential-acquisition step.

The root session from 10.10.1.22:54014 is particularly well supported. WEB-EXT-01 `syslog.log` lines 505, 508, 509, and 510 show connection, accepted public key, PAM session opening, and logind session creation at 14:39:29–32. eCAR lines 1136–1140 show the matching daemon, login, and shell. `zeek-dmz/conn.json` line 2431 records the TCP connection starting at 14:39:23.975, before authentication, with an approximately 1827.8-second duration. The following `nmap` commands have endpoint process lifetimes and network scan activity, so scanning is investigable without inventing a second transport.

The later database operation also works as a hunting sequence. DB-PROD-01 receives an SSH login from APP-INT-01, runs `mysqldump --single-transaction ehr patients insurance_claims`, creates `/tmp/rpt_0318.sql`, compresses it, and invokes SCP. The root bash history contains the shell redirection for the dump, while the process command line omits the redirection and the file event records its effect. That distinction is appropriate for shell-owned redirection rather than an authenticity defect.

The SCP transfer reaches APP-INT-01 under a separate SSH session. APP-INT-01 `syslog.log` lines 216–221 show connection at 18:16:18.246883, accepted public key at 18:16:20.527498, session opening, then closing at 18:16:38.780641. The receiver file creation is at 18:16:38.865 in eCAR line 942. The roughly 84-millisecond cross-source inversion is small enough to be source observation/clock behavior and is not scored as an impossible causal relationship.

On Windows, WS-AJOHNSON-01 has a successful RDP login from 10.10.1.99:44098 at 16:20:54.791 (`ecar.json` line 662). `zeek-core/conn.json` line 7269 gives the successful RDP transport an earlier start, epoch 1793636449.183295, and duration 2882.950856 seconds. The later credential-access process at 16:45:05 (`ecar.json` lines 833–846) has process-open and remote-thread observations before its termination. I treat the command arguments as evidence of intended credential access; they do not by themselves prove credentials were recovered.

DC-01 has a PSEXESVC file/service/process sequence around 17:00 (`ecar.json` lines 3567–3578), subsequent account/persistence changes, and a PowerShell/`wevtutil` sequence around 18:42. Security XML includes a 1102 event at 18:42:29.4754242. I found no reason to score the number or arrangement of these suspicious stages: their compactness and investigative readability are neutral under this study's rules.

### Mac interpretation and metadata pattern

I distinguished native Endpoint Security process observations from eCAR normalized observations and Unified Log messages. The ES rows contain `version:11`, fork/exec/exit payloads, audit tokens, executable metadata, and process start times. I did not declare those schemas invalid based on unfamiliar fields. I also did not treat the Unified Log message `ASP: Security policy would not allow process...MeetingAssist` as proof of successful execution or as proof that a child executed: the policy message alone establishes neither.

The inode pattern is independent of those schema questions. Deduplicating `process.executable`, `event.exec.target.executable`, and `event.fork.child.executable` by pathname produces a perfectly increasing inode sequence by alphabetical pathname on each host. It spans Chrome helpers, user-installed terminal components, shell tools, and system daemons. For the 23 paths common to both hosts, almost all values differ by a constant, with the Chrome trio shifted by just one additional inode. Shared binary content and matching code hashes can naturally result from a common image; the additional pathname-rank/near-constant-inode arithmetic is the part that raises concern. A deliberately sanitized inode map could explain it, so I do not label it a hard contradiction.

The terminal file-access mix is weaker. MAC-MROSS-02 exposes ten `/Volumes/` FILE/READ operations; none in that set is attributed to a document-viewing application, although Word execution is visible at eCAR lines 295–298. A terminal-focused activity subset could explain this. I assign modest weight because the specific observed actions repeatedly use `cat` for binary document formats and `tee` for a `.docx` write, not because another log source or event family is missing.

### Signal-to-noise and limits

I found no demonstrable source-volume contradiction. The dataset is a six-hour slice with selected event types, and a busy DC, proxy, web edge, database, and mixed client fleet can plausibly produce the observed distribution. Sensor-local connection counts include duplicate observations of traffic traversing multiple sensors and are not unique enterprise connection counts.

I did not score absent Sysmon event types, thin Mac Unified Log coverage, missing out-of-window process initiators/closures, sanitized domains, filesystem modification times, complete cross-source alignment, or the attack's narratability. The inode and document-operation patterns make synthetic origin more likely to me, but the large amount of coherent operational evidence keeps the synthetic-confidence score in the mixed range rather than the hard-contradiction range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on synthetic-confidence score |
|---|---|---|---|
| distribution_texture | Mac Endpoint Security executable stat metadata | 26 executable paths on one host, 31 on the other; 23 shared paths | Highest impact: perfect pathname/inode ordering and nearly constant cross-host offsets suggest catalog-derived metadata. Image preparation or sanitization remains an alternative. |
| distribution_texture | Mac eCAR process/file activity | Ten shared-volume reads and one write on MAC-MROSS-02 | Modest impact: repeated `cat`/`ls`/`tee` representation of document activity has a narrow behavioral texture. Possible for terminal work, so not decisive alone. |

## Realism Score by Category

- **Field format accuracy:** 8 — Native exports parse and carry detailed source-specific fields; filesystem metadata has a conspicuous allocation pattern.
- **Temporal patterns:** 8 — Checked remote transport/authentication and process lifetimes are coherent; no decisive visible ordering contradiction found.
- **Cross-source correlation:** 9 — Web, RDP, SSH, SCP, Windows session, and proxy pivots are usable and generally agree.
- **Behavioral realism:** 7 — Suspicious commands and effects are credible, but shared-document activity has a narrow terminal-command vocabulary.
- **Environmental consistency:** 8 — Source volumes broadly fit the apparent roles and mixed fleet; the cross-host executable inode pattern weakens independent host-history plausibility.

## Recommendations

- If this were synthetic, assign persistent filesystem object identities from a per-volume installation/history model rather than a globally sorted pathname catalog. Preserve identity for each file across repeated observations, but avoid making unrelated executable inode order a direct function of alphabetical path or translating nearly every shared file by the same host offset.
- If this were synthetic, diversify the concrete shared-document behaviors represented on MAC-MROSS-02. Retain terminal activity where intended, and tie reads/writes of Office and PDF files to the actual selected applications or explicitly modeled terminal workflows. The goal is to address the observed `cat`/`ls`/`tee` concentration, not to require extra source coverage.
- Preserve the currently coherent transport/session/process ownership and source-specific timing; these checked relationships contribute substantially to realism.

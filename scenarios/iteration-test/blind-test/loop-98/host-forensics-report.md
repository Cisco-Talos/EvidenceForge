# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 20

## Executive Summary

The bounded endpoint sample is strongly production-like, with credible platform-specific process semantics and no demonstrated source-native contradiction. Two exact process pivots preserve identity, executable, ancestry, credentials, and execution ordering; the sample cannot establish provenance, so the classification remains inconclusive despite a low synthetic-confidence score.

## Evidence For Synthetic

- No score-bearing synthetic indicator was demonstrated in the 17 representative records examined. The absence of a defect in this bounded sample does not establish that all records are authentic.
- No conclusions are drawn from missing Sysmon event types, source completeness, attack progression, sanitized names, or out-of-window process/session endpoints.

## Evidence For Real

- On `WS-AJOHNSON-01.meridianhcs.local`, Sysmon Event 1 at `2026-11-02T13:10:01.7957426Z` identifies SYSTEM `taskhostw.exe`, PID 5180, parent `svchost.exe` PID 4356. Security 4688 at `13:10:02.1751666Z` independently represents those identifiers in hexadecimal (`0x143c`, `0x1104`) with matching command, parent image, subject logon `0x3e7`, and system integrity.
- The later Windows process pivot joins Sysmon Event 1 record 31779, PID 6984, at `18:53:48.5512644Z` to eCAR PROCESS/CREATE at epoch milliseconds `1793645628706` (`18:53:48.706Z`). Both describe `SearchProtocolHost.exe` under `SearchIndexer.exe` PID 4636, SYSTEM, logon `0x3e7`, with the same detailed pipe command line.
- On `MAC-MROSS-01.meridianhcs.local`, Endpoint Security distinguishes a forked launchd image, subsequent xpcproxy exec, and subsequent Chrome exec within PID 41136 instead of inventing three independent process lifetimes. eCAR similarly preserves the same object across CREATE and MODIFY/exec.
- Linux SSH evidence includes a transport opening followed by successful public-key authentication and PAM session opening for the same sshd PID and remote tuple, with realistic nonzero timing separation.

## Detailed Analysis

### Examination scope and record budget

Read only the supplied data directory and the assigned briefing. This was a bounded review of **17 distinct representative records**, plus aggregate calculations over the named files. No exhaustive audit, repository inspection, external reports, or modifications to source data were performed.

The visible samples span early `13:00`, middle `14:39`/`16:37`, and late `18:53`/`18:54` activity on November 2, 2026. The examined workstation Linux syslog spans `13:01:19.806888Z`–`18:58:44.735066Z`. These are observed sample/file bounds, not an assertion about the complete dataset's capture boundaries.

The record inventory is:

1. Windows Sysmon Event 5, `WS-AJOHNSON-01`, `13:00:22.0699245Z`, SSH PID 5116, user `MERIDIANHCS\\aisha.johnson`.
2. Mac ES launchd fork, `13:00:06.950823Z`, child PID 41136.
3. Mac Unified Log loginwindow message, `13:03:16.611945+0000`, process 40562, `-[Login1 launchWorkspace] | enter`.
4. Linux workstation dhclient message, `WS-LNGUYEN-01`, `13:01:19.806888Z`, DHCPREQUEST for `10.10.1.21`.
5. Windows Sysmon Event 1, `13:10:01.7957426Z`, taskhostw PID 5180.
6. Matching Windows Security 4688, `13:10:02.1751666Z`, PID `0x143c`.
7. Mac ES xpcproxy exec, `13:00:06.953308Z`, PID 41136.
8. Mac eCAR launchd PROCESS/CREATE, epoch milliseconds `1793624408307`, PID 41136.
9. Windows Sysmon Event 1, `18:53:48.5512644Z`, SearchProtocolHost PID 6984.
10. Matching Windows eCAR PROCESS/CREATE, epoch milliseconds `1793645628706`, PID 6984.
11. Mac eCAR xpcproxy PROCESS/MODIFY/exec, epoch milliseconds `1793624408308`, PID 41136.
12. Mac ES Chrome exec, `13:00:06.958279Z`, PID 41136.
13. Mac ES find exec, `14:39:20.748540Z`, PID 54311.
14. Mac ES Terminal exit, `18:54:59.789184Z`, PID 42205.
15. Linux APP-INT SSH acceptance, `16:37:34.883351Z`, sshd PID 2972725.
16. Matching APP-INT SSH connection, `16:37:27.469810Z`, same PID.
17. Matching APP-INT PAM session open, `16:37:35.061676Z`, same PID.

Host directories use the `.meridianhcs.local` suffix. Windows records are in `windows_event_sysmon.xml` and `windows_event_security.xml`; Mac native records are in `macos_endpoint_security.ndjson` and `macos_unified_log.ndjson`; normalized records are in `ecar.json`; Linux records are in `syslog.log`.

### Windows process evidence and later-window exact pivot

The early taskhostw pair agrees on process identity, SYSTEM ownership, parent service host, and command `taskhostw.exe /Run`. The approximately 379 ms separation between source observations does not establish an execution-order contradiction. Sysmon's own `UtcTime` and envelope timestamp differ by roughly 2 ms, which is compatible with distinct event and recording times.

The later exact pivot is keyed by host, PID 6984, close time, image, parent PID 4636, full command, and logon ID, rather than PID alone. Sysmon uses ProcessGuid `{fd907e59-dc3c-6ae8-f600-0010dc5ec561}`; eCAR uses its own object UUID `4fef75ba-2030-4229-a01c-8e1e56f05480`. Different source identity namespaces are expected and are not a mismatch. eCAR's approximately 155 ms later observation preserves the process occurrence. The parent-child SearchIndexer/SearchProtocolHost relationship is plausible.

Aggregate context: this host's Sysmon file contains 593 records: 118 Event 1, 99 Event 5, 161 Event 3, 124 Event 22, 42 Event 10, 25 Event 13, 17 Event 7, four Event 11, and three Event 8. The create/terminate count difference is not a lifecycle defect without exact process and window analysis. For the 117 adjacent Event 1 PID differences, +4 occurs 13 times and +8 ten times, with numerous positive and negative deltas; this is not evidence of a single fixed PID increment.

The initial SSH termination may close a process that started before the visible window. Its absent sampled creation is not scored.

### macOS execution semantics and exact pivot

The native ES records declare message `version:11`. PID 41136 is forked from launchd with a launchd executable snapshot, then changes image to `/usr/libexec/xpcproxy`, then `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`. PID versions progress 12→13→14 while the process start time remains `13:00:06.950823Z`. Current and target executable snapshots therefore differ for a legitimate exec reason.

The exact ES/eCAR pivot uses PID 41136, xpcproxy path and arguments, predecessor launchd image, and pidversion transition 12→13. eCAR object `85243acd-6fc1-4805-aaa7-5f44bd360f9e` remains stable across CREATE and MODIFY, with execution IDs ending `exec:0` and `exec:1`. Its source observations at `13:00:08.307Z` and `13:00:08.308Z` preserve fork-before-exec order despite arriving later than ES.

The next native exec's target is user 501, audit user 501, audit session 100001, Chrome signing ID `com.google.Chrome`, and team `EQHXZ8M8AV`. I do not misclassify the preceding root xpcproxy snapshot as a root-running Chrome browser. Credential/session transitions warrant platform-aware interpretation, and the bounded selection does not demonstrate an impossible transition.

The middle ES exec shows `/bin/zsh` becoming `/usr/bin/find` under parent PID 42207, responsible PID 42205, audit/session 100002, and tty `/dev/ttys000`. It runs a Documents PDF search from `/Users/maya.ross`, a plausible interactive shell activity. The later Terminal exit belongs to PID 42205, whose native start time is `13:08:05.775646Z`; no impossible visible lifetime relationship was demonstrated. The loginwindow Unified Log message is treated as a log message, not proof that every process shares that particular GUI session.

Aggregate context: this Mac ES file has 141 records: 45 fork, 52 exec, and 44 exit. Multiple exec images per process explain why exec counts can exceed fork counts. Neither the surplus nor the single unmatched aggregate fork count establishes a missing in-window termination.

### Linux session evidence

`APP-INT-01/syslog.log` has 248 records and nine `Accepted` messages. The selected middle acceptance is line 155: public-key ECDSA authentication of `marcus.chen` from `10.10.1.31:63418`, sshd PID 2972725, at `16:37:34.883351Z`. Line 153 opens the same tuple toward `10.10.2.30:22` at `16:37:27.469810Z`; line 156 opens PAM session user `marcus.chen(uid=4119)` at `16:37:35.061676Z`. Transport precedes acceptance by about 7.414 seconds and PAM follows acceptance by about 178 ms. These source-native phases and identifiers are coherent.

`WS-LNGUYEN-01` has 268 syslog records and no `Accepted` messages. That absence is not scored: a Linux endpoint need not act as an SSH server during this slice. Its sampled DHCP renewal is plausible workstation background activity.

### Limits

This review does not verify every hash, native field against every OS build, session endpoint, process tree, Mac launch-item/policy transition, or Linux shell-history command. The native ES schema is distinguished from normalized eCAR and Unified Log; no unverified native-field suspicion is promoted into a format defect. The two exact cross-source pivots demonstrate local consistency only. Collection completeness and useful joins are neither authenticity proof nor synthetic indicators.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| None demonstrated | Windows, macOS, Linux, normalized eCAR | 17 representative records; named-file aggregate context | No concrete synthetic defect found; score 20 reflects the production-like examined evidence, while provenance remains inconclusive. |

## Realism Score by Category

- **Field format accuracy:** 9 — Sampled XML, ES, Unified Log, syslog, and normalized fields are credible; this is not complete native-schema certification.
- **Temporal patterns:** 9 — Sampled transport/auth/session and fork/exec sequences preserve meaningful timing; no impossible visible ordering found.
- **Cross-source correlation:** 9 — Two exact process pivots preserve shared facts while allowing distinct source identities and observation delays.
- **Behavioral realism:** 9 — Service-host tasks, indexing children, user Chrome and Terminal activity, and SSH administration are credible in the observed contexts.
- **Environmental consistency:** 8 — Sampled Windows, Linux, and Mac ownership/paths fit their platforms, with host-role breadth only lightly sampled.

## Recommendations

- No specific corrective recommendation is supported by this bounded evidence. If this were synthetic, retain the observed fork-versus-exec distinctions, platform-specific ownership, source-local identifiers, and transport-before-auth timing. A broader review could test additional lifetimes and source families, but their unexamined status is not a finding against authenticity.

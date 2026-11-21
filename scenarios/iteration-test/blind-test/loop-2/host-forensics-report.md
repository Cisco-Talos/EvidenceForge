# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 77
**Synthetic-Confidence Score:** 63

## Executive Summary

The endpoint data is substantially realistic: Windows process identities and hashes remain coherent, Linux authentication includes credible session sequencing, and macOS evidence distinguishes fork, exec, credentials, and terminal/session state. I nevertheless lean synthetic because the macOS local-terminal activity combines repeated process-group inheritance with overlapping apparently foreground commands from the same shell, and the normalized eCAR process timeline repeatedly compresses native fork/exec intervals. These are bounded behavioral and timing concerns, rather than demonstrated impossible native schemas or dataset-wide lifecycle failures.

## Evidence For Synthetic

- [contract_gap] The local macOS terminal process-group and command histories do not convincingly support the concurrency shown. On `MAC-MROSS-01`, `macos_endpoint_security.ndjson` line 109 records PID 66778 executing `/usr/bin/ssh maya.ross@DB-PROD-01.meridianhcs.local` at `16:27:40.693524Z`, under shell PPID 42156, process group 42155, POSIX session 42155, audit session 100002, and `/dev/ttys000`. The same shell launches `/usr/bin/id`, PID 67424, at `16:34:32.048370Z` (line 114), before SSH exits at `17:00:44.761399Z` (line 116). Both commands appear without backgrounding in the zsh history, and both remain in process group 42155. A suspended or background job could explain overlap in principle, but ordinary interactive job control would normally separate these jobs into their own process groups; that separation is absent in the actual exec snapshots.
- [environment_or_collection_plausibility] That process-group behavior repeats on the other Mac and across the local terminal workload. On `MAC-MROSS-02`, PID 45509 executes `ssh -tt maya.ross@MAC-MROSS-01.meridianhcs.local` at `16:01:51.843341Z` (ES line 103), while the same shell PPID 19001 launches PID 46192 executing SSH to `WEB-EXT-01` at `16:09:07.153351Z` (line 108). The first SSH exits only at `16:18:00.427669Z`; both exec targets retain process group/session 19000 and `/dev/ttys001`. More broadly, 31 exec records whose source image is zsh on Mac 02, and 24 on Mac 01, have a terminal but do not make the exec target its own process-group leader. This is possible with unusual shell/job-control configuration, so it is a repeated plausibility concern rather than an impossible field value.
- [distribution_texture] The macOS eCAR fork-to-first-exec timing is markedly compressed relative to the native ES evidence. Among 94 eCAR process identities with visible CREATE and first `operation=exec` MODIFY, 93 have intervals of only 1–5 ms; 59 are exactly 1 ms, and the remaining outlier is 67 ms. Native ES visible fork-to-first-exec intervals span 1.218–102.535 ms on Mac 01 and 2.211–141.558 ms on Mac 02, with no duplicated microsecond interval within either host. For example, Mac 02 PID 18998 forks at `13:12:07.845472Z` and execs xpcproxy at `13:12:07.861432Z` in ES lines 1–2 (15.960 ms), but appears at `13:12:08.170Z` and `13:12:08.171Z` in eCAR lines 5 and 7 (1 ms). Collection or normalization timestamps could explain individual differences; the repeated compression across both hosts is the scored concern.

## Evidence For Real

- All 954 visible Sysmon Event 1 records across the ten Windows hosts have a corresponding Security 4688 record with matching numeric PID, image path, and command line. This is affirmative correlation evidence, not a synthetic indicator based on completeness.
- Within each Windows host, repeated Sysmon process-creation records for the same image and declared file version retain the same hash set. Visible same-ProcessGuid records do not change PID or image; checked same-GUID records do not precede their visible creation or follow their visible termination by their native UtcTime.
- The eCAR identity checks across all 23 endpoints found no visible child CREATE preceding a visible parent CREATE, no process termination before its same-object CREATE, and no checked non-FLOW actor activity more than one second after its visible termination. No FLOW observation tied to a visible terminated process was more than two seconds late.
- Windows behavior varies by host and apparent role. The domain controllers favor WMI, task-host, COM-surrogate, and service activity; administrative workstations show PowerShell, SSH, MMC, and RDP clients. Desktop workstations show browser, indexing, updater, and user-application activity rather than one identical command sequence.
- Windows logon types are differentiated. DC-02 has 136 Type 3, 111 Type 5, four Type 10, and one Type 2 logons. WS-MCHEN-01 includes service/network logons, one local interactive logon, three unlocks, and a Type 9 logon. Reserved service LUIDs and repeated unlock LUIDs were excluded from naive “process before logon” allegations.
- Linux authentication has meaningful internal ordering. `DB-PROD-01/syslog.log` lines 185–187 show root password acceptance at `18:15:05.214877Z`, PAM session opening at `18:15:05.360136Z`, and systemd-logind session 500 creation at `18:15:06.073953Z`. Sudo records distinguish allowed command invocation, session opening/closing, and denied commands.
- macOS process identity is considerably richer than a flat list of fabricated command launches. Fork children inherit executable identity, exec changes image and pidversion without requiring a new PID, and audit session IDs are distinct from POSIX session/process-group IDs. Across the examined ES records, the same device/inode executable identity did not acquire conflicting path, cdhash, size, or mode, and the same PID/pidversion did not acquire conflicting executable path or start time.
- Native macOS SSH evidence distinguishes a non-PTY session from an explicitly requested PTY. Mac 02's inbound shell has no tty, whereas Mac 01's later session reached using `ssh -tt` has `/dev/ttys001`; this is plausible, source-visible differentiation.
- The Mac 01 Unified Log policy message at `15:42:09.009673Z` says security policy would not allow PID 62500, MeetingAssist. I found no corresponding MeetingAssist exec target in the supplied ES records, so I do not allege denied execution followed by successful execution.

## Detailed Analysis

### Scope and method

I examined only the assigned data directory and briefing. The host sources comprise 23 eCAR files, Security and Sysmon XML for ten Windows hosts, syslog for eleven Linux hosts, native-looking Endpoint Security JSON for two Macs, their Unified Log exports, and supplied shell histories. The visible endpoint time span is approximately `2026-11-02 13:00–19:00 UTC`. Automated checks parsed the supplied JSON/XML and compared visible process identities, timestamps, hashes, and session references; I also inspected individual records and shell commands.

The verdict does not use filesystem modification times, public resolution of domains, missing selected Sysmon event types, log-source completeness, or how neatly suspicious activity forms a narrative. I did not require a visible boot, logon, or termination outside the slice. There is no demonstrated generator identity leak in the records examined.

### Windows process and authentication evidence

The 954 Sysmon process creations are accompanied by 784 Sysmon terminations. That difference is compatible with running processes and the time window; I did not score it as incomplete lifecycle evidence. The other observed Sysmon counts are 7,677 network connections, 1,191 DNS queries, 672 process-access events, 150 registry-value events, 133 image loads, 19 file creates, and eight remote-thread events. These counts describe the supplied selection, not an expectation that every Sysmon event family be collected.

On DC-02, for example, a COM-surrogate process at `13:01:35.776` has PID 6780, image `C:\Windows\System32\dllhost.exe`, version `10.0.20348.1`, a COM `/Processid:{...}` argument, SYSTEM identity, LUID `0x3e7`, and an svchost parent running `-k DcomLaunch`. WS-MCHEN-01's Zscaler tray process at `13:04:43.966` instead has a user-owned explorer parent, medium integrity, user LUID `0x6b432f6`, and a quoted installed application path. These are appropriate distinctions in parentage and security context.

The cross-provider PID/image/command check matched every visible Sysmon creation to a 4688 record. I also checked same-GUID image/PID consistency and native UtcTime ordering against visible creation/termination. Those checks found no contradiction. Different provider publication times were not themselves treated as impossible ordering.

Authentication mixtures differ between servers and workstations. Service-account logons using the well-known SYSTEM/LOCAL SERVICE/NETWORK SERVICE LUIDs recur; treating the last such 4624 as a unique initiating logon would create false positives. Similarly, unlock records reuse a logon session. After accounting for these cases, I found no ordinary process/privilege record preceding the earliest visible relevant non-unlock user logon in the comparison performed.

### Linux process, shell, and service evidence

The Linux files show SSH, sudo/PAM, cron, package maintenance, journald/rsyslog, service-related activity, and role-specific commands. For example, WEB-EXT-01's first sudo records distinguish an allowed invocation for lina.nguyen from a nearby “command not allowed” event for maya.ross, then show the allowed sudo session opening and closing. DB-PROD-01's history includes database-client and diagnostic commands; WEB-EXT-01 includes web-server configuration and certificate commands.

Recurring `/bin/sh` and `debian-sa1` executions occur 36 times each on many Linux hosts. I did not call this synthetic merely because the count is fixed: a six-hour window containing a ten-minute sysstat cron job can naturally yield 36 occurrences, and the syslog entries explicitly show that scheduled command. Shell builtins and pipelines were not indiscriminately treated as separate executable images in the sampled eCAR commands.

The role evidence is varied enough that I do not infer an unrealistic Linux environment from common diagnostic vocabulary, or from software that could coexist. No Linux-native hard contradiction established the verdict.

### macOS process identities and session ownership

Mac 01 has 144 ES messages: 46 fork, 53 exec, and 45 exit. Mac 02 has 173: 55 fork, 64 exec, and 54 exit. Successive execs are therefore expected within a single process lifetime. The launchd → xpcproxy → application and terminal/login/shell paths are represented through successive images and fork relationships, rather than each image transition automatically becoming a new process.

Mac 02 PID 18998, for instance, starts as a launchd fork, execs xpcproxy, then becomes iTerm2. Its audit credentials and group/session information differ between these stages. I did not mistake a root-to-user credential transition for two competing processes, or confuse `asid` 100003 with POSIX session 19000. The Mac 01 remote PTY shell PID 64378 uses process group and POSIX session 64378, while child `/usr/bin/id` PID 64580 is already its own process-group leader at exec. This last example is a useful internal contrast with the local-terminal patterns.

The local-terminal concern is concrete but not absolute. Mac 01's shell PID 42156 keeps its children in process group 42155; Mac 02's shell PID 19001 keeps them in 19000. Repeated local commands, including long-running SSH clients, inherit those groups in the native exec target snapshots. During visible SSH lifetimes, the same parent shell launches further history-listed commands with no `&` in the supplied history. Conventional foreground zsh behavior would block the shell pending completion, and conventional background/suspend handling with job control would usually give jobs separate process groups. A deliberately unusual shell configuration, omitted signal/job-control observations, or manipulated history could reconcile the records, so this is scored as a contract/plausibility gap, not proof of kernel impossibility.

### macOS source timing

Native ES time and normalized eCAR timestamp_ms are visibly different time domains or observation policies. This is not inherently an error. The measurable concern is the shape: among the 94 matched eCAR fork/first-exec pairs, the delays are 59 × 1 ms, 17 × 2 ms, 11 × 3 ms, 5 × 4 ms, 1 × 5 ms, and 1 × 67 ms. The ES equivalents have substantially broader sub-millisecond-resolution elapsed intervals.

The example PID 18998 has a 15.960 ms native fork/exec gap but a 1 ms normalized gap. Mac 01 PID 42154 similarly has a native gap of 9.191 ms (`13:07:32.811343Z` to `13:07:32.820534Z`), compared with 2 ms in eCAR beginning at `13:07:33.990Z`. This resembles a timestamping rule that allocates very small increments within a materialized process sequence. A documented eCAR ingestion-time convention could reduce its significance, and it does not make the native ES order impossible. I assign it moderate weight alongside the job-control issue.

### Balance of evidence

Most of the endpoint evidence survived checks that commonly expose synthetic datasets. The verdict therefore remains a moderate lean, concentrated in macOS process/job ownership and normalized timing, rather than a confident assertion of pervasive fabrication. The 63 synthetic-confidence score reflects multiple concrete but explainable artifacts; the 77 verdict confidence expresses my confidence in that overall lean, not certainty about every causal interpretation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | macOS ES, eCAR, zsh history | Both Macs; overlapping same-parent SSH/local commands in the same local terminal group | Highest weight: command concurrency is not convincingly supported by the visible shell/job ownership. Alternative job-control explanations remain possible. |
| `environment_or_collection_plausibility` | macOS ES process snapshots | Repeated tty-backed zsh exec targets retain inherited groups; explicit remote PTY jobs show a different pattern | Moderate supporting weight; this is the same behavioral family as the overlap concern and is not counted as an independent hard contradiction. |
| `distribution_texture` | macOS eCAR compared with ES | 93/94 visible eCAR fork-to-first-exec gaps are 1–5 ms | Moderate weight for a repeated timing transformation across two hosts; ingestion-time semantics are an important alternative explanation. |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed source fields, native identity distinctions, GUIDs, paths, and stable executable identities are convincing; no demonstrated native schema contradiction.
- **Temporal patterns:** 7 — Visible lifecycles are ordered, but macOS eCAR fork/exec intervals have a concentrated timing texture.
- **Cross-source correlation:** 9 — Windows process PID/image/command matches and identity consistency are strong; macOS timestamp interpretation limits precision.
- **Behavioral realism:** 6 — Varied host activity is credible, but same-shell overlapping jobs and repeated inherited terminal process groups need explanation.
- **Environmental consistency:** 8 — Host roles and platform evidence generally agree; local macOS job-control behavior is the main unresolved environmental concern.

## Recommendations

- If this were synthetic, model local terminal foreground/background/suspended job state together with process groups, terminal ownership, and shell readiness. The visible Mac 01 SSH/id overlap and Mac 02 overlapping SSH clients should follow the intended job-control behavior; if jobs run in the background, preserve that intent in the corresponding history and native process-group snapshots.
- If this were synthetic, preserve meaningful native fork/exec elapsed intervals in normalized occurrence timestamps. If eCAR intentionally uses ingestion timestamps, make that collection policy explicit and use a plausible arrival/batching model that explains the observed 1–5 ms concentration.
- If this were synthetic, retain the existing Windows cross-provider process identity/hash consistency and macOS distinctions among fork, exec, audit session, POSIX session, process group, credentials, and PTY state. These are strengths; adding unrelated source families or filling the collection-window boundaries would not address the findings above.

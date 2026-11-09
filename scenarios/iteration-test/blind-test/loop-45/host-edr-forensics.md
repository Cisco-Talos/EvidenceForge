# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 62
**Synthetic-Confidence Score:** 29

## Executive Summary

The endpoint evidence is mostly production-like: process identities survive lifecycle transitions, Linux authentication has meaningful intermediate stages, and macOS fork/exec evidence distinguishes successive images from separate process lifetimes. I found mild repetition in command vocabulary, but no demonstrated impossible same-identity ordering or source-native contradiction strong enough to support a synthetic verdict; the Real verdict is consequently tentative.

## Evidence For Synthetic

- [weak_signal] The background Windows COM-surrogate vocabulary is narrow across different apparent host roles. All 105 visible Sysmon Event 1 `dllhost.exe` creations use one of only three `/Processid` values: `{3EB3C877-1F16-487C-9050-104DBCD66683}`, `{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}`, or `{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}`. For example, DC-01 Sysmon record 3289068 (`windows_event_sysmon.xml`, line 5449) uses the first value at 13:11:25.589; the same three-value vocabulary appears on both DCs, the file/mail servers, and workstations. This is compatible with common Windows components and a standardized image, so it carries little weight by itself.
- [weak_signal] Lina's early shell activity repeats a short developer routine across a workstation and an application server: `git status --short`, `git diff --stat`, `npm test`, and `docker compose ps` occur in that order in `WS-LNGUYEN-01.../bash_history/lina.nguyen.bash_history` lines 2–10 and `APP-INT-01.../bash_history/lina.nguyen.bash_history` lines 2–8. The workstation sequence includes an intervening SSH command and the timings differ. This could reflect a small command pool, but it could equally be the same developer repeating a normal deployment check; I do not treat the sequence's narratability as evidence.

## Evidence For Real

- Process lifetime checks across all 23 EDR host files found no child `PROCESS/CREATE` after the visible termination of its identified `actorID` parent, and no process termination before its matching visible creation. Missing pre-window parents and processes still alive at the end were excluded from this check.
- Windows processes carry credible source-specific representations: WS-PPATEL Sysmon record 739645 records TiWorker PID 6076, parent PID 5064, a servicing-stack path, system integrity, and multiple hash types. Its EDR `PROCESS/CREATE` is line 2, with the same PID, parent PID, image, and command. The timestamps differ by about 125 ms rather than being mechanically identical.
- Of 895 Windows Sysmon Event 1 records, 888 had a same-host EDR creation with the same PID within five seconds. All 888 matched image and command-line fields. The seven unmatched creations are compatible with selective collection and were not scored as missing evidence.
- No within-host Sysmon Event 1 image path had conflicting `Hashes` strings among its visible repeated executions. This supports internal executable identity consistency, though it does not independently authenticate those hashes.
- APP-INT SSH PID 2932124 has a connection at 13:05:31.327255, accepted public-key authentication at 13:05:37.469097, a PAM session opening at 13:05:37.559586, and a logind session at 13:05:38.042836 (`syslog.log`, lines 18–21). These are distinct, sensibly ordered stages.
- The Macs contain native-style fork, exec, and exit observations with stable process start times and changing exec identities. MAC-MROSS-01 ES lines 66–78 show launchd's fork, xpcproxy, sshd-keygen-wrapper, sshd, sshd-session, and post-authentication child creation; Unified Log line 3 places successful authentication between the pre-authentication setup and the post-authentication fork.
- The denied MeetingAssist policy message on MAC-MROSS-01 (`macos_unified_log.ndjson`, line 2, 15:42:11.450696) is not accompanied by an ES exec target or EDR process image claiming MeetingAssist successfully ran. The visible data does not turn that policy message into successful child execution.

## Detailed Analysis

### Input provenance and scope

I examined the supplied `host-prompt.md` and files exclusively beneath `/private/tmp/log-study-rm6iexyd/data`. I did not access repository code, project memory files, scenario files, previous assessments, other reviewers' reports, or parent-directory inventories. Public Microsoft and Apple documentation was consulted for field interpretation; it supplied no information about the origin of this dataset.

I enumerated the available source files, parsed all 35,807 EDR records across 23 hosts, parsed all ten hosts' Security and Sysmon XML exports, and inspected selected native Linux/macOS rows and shell histories. The visible endpoint interval is approximately 2026-11-02 13:00–19:00 UTC. This is a bounded authenticity assessment of that slice, not a claim of exhaustive forensic reconstruction or complete source coverage.

### Windows process and session evidence

The EDR inventory contains 2,043 process creations and 1,904 terminations across platforms. Differences between these totals are not inherently suspicious in a time slice. My lifecycle check linked identities rather than comparing bare PIDs across time or demanding a closure for every start.

On Windows, the Sysmon-to-EDR comparison used host plus PID and a five-second tolerance. The 888 matches had EDR times 6–913 ms later than Sysmon's `UtcTime` (median 172 ms). Such variation is compatible with separate observation pipelines. A matching source record is useful evidence of consistency, but the high matching rate itself was not treated as proof of either authenticity or synthetic generation.

The Windows population includes interactive, network, service, unlock, remote-interactive, and new-credentials logons. For example, WS-PPATEL's 15 successful 4624 records comprise nine Type 5, two Type 7, two Type 3, one Type 2, and one Type 9; its file also includes lock/unlock records. DC-01 instead has 155 Type 3, 148 Type 5, and two Type 10 successes. These are different host-role mixes, rather than a uniform workstation session template imposed on every machine. I did not penalize unclosed service sessions using well-known service logon IDs.

Some cross-principal parent/child trees deserve careful interpretation, particularly a NETWORK SERVICE `svchost.exe` parent for a SYSTEM TiWorker child (WS-PPATEL Sysmon 739645). A parent's principal alone does not establish the creating thread's effective token or rule out brokered creation. Microsoft distinguishes the requesting subject and target subject in [Event 4688's field documentation](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688); I did not convert this unfamiliar tree into a hard contradiction without evidence establishing an impossible token transition.

The strongest residual reservation is distributional rather than causal: the repeated three-value dllhost command pool. The host-by-host counts vary—for instance DC-01 has 9/8/8 occurrences of the three commands and DC-02 has 13/6/11—so this is not a fixed per-host count. Standardized Windows images and shared workloads remain a substantial alternative explanation.

### Linux host evidence and user activity

Linux sources exhibit SSH/PAM/logind stages, sudo command/open/close triplets, cron-driven sysstat activity, anacron execution, DHCP renewal, resolver changes, and host-role differences. APP-INT's sudo PID 2931451 at 13:00:45.894600 requests `/usr/sbin/ss -s`, opens PAM at 13:00:46.017833, and closes at 13:00:47.414379 (`syslog.log`, lines 7–9); EDR lines 8–9 show sudo and its root-owned child. This is meaningful process/credential agreement.

WS-LNGUYEN's DHCP sequence includes REQUEST, ACK, and a renewal interval at 13:01:19–20, followed by the next REQUEST/ACK near 13:32:46 (`syslog.log`, lines 2–4 and 32–34). That is consistent with the first reported renewal interval of 1,885 seconds, allowing ordinary jitter and observation delay.

Developer commands differ from Aisha's host-inspection commands. For example, APP-INT Lina history lines 2–16 contain git/npm/docker checks, whereas Aisha's corresponding history lines 2–14 contains log inspection, IP configuration, disk usage, and journal queries. Repetition of the same developer's routine across machines is a weak reservation, not evidence of impossible behavior. Shell builtins and pipes also require care: absence of an EDR process for a shell builtin is neutral.

### macOS identity, policy, and timing

Both ES exports declare message version 11 and contain fork/exec/exit observations (MAC-MROSS-01: 40/47/39; MAC-MROSS-02: 49/60/48). The two machines have different boot identities and process populations. Within the inspected ES structures, the same PID/start-time lifetime persists through successive exec images; `pidversion` is not misread as an immutable lifetime identifier.

MAC-MROSS-01 PID 64329 is forked at 16:01:37.636390 (ES line 66), becomes sshd-session at 16:01:37.759074 (line 71), emits the accepted-publickey Unified Log message at 16:01:38.551396 (Unified line 3), and forks the post-authentication child at 16:01:38.643735 (ES line 78). The native timestamps and Mach values agree on this ordering. The normalized EDR observations arrive later; comparing their arrival-like times against native timestamps without accounting for that difference would produce a false inversion. Apple's [ES event-time documentation](https://developer.apple.com/documentation/endpointsecurity/es_message_t/time?language=objc) identifies `time` as the occurrence time and distinguishes the Mach representation.

MAC-MROSS-01 and MAC-MROSS-02 each show creation and later deletion of an inventory LaunchDaemon plist (EDR lines 40/513 and 43/448, respectively). Deleting that file does not itself prove a loaded job stopped, and I did not require a process exit exactly at deletion. Similarly, the MeetingAssist policy log is not enough to demand a successful exec notification or downstream effects. No contradiction was established in these visible transitions.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Windows Sysmon process commands | 105 dllhost creations across ten Windows hosts use three command variants | Small upward adjustment; common COM classes and standardized images can explain this |
| weak_signal | Linux histories / EDR process commands | Same developer repeats four core checks on workstation and application server | Small upward adjustment; routine user behavior is an equally plausible explanation |
| No demonstrated hard contradiction | Endpoint lifecycle and native-source ordering | Broad EDR checks and sampled native Windows/Linux/macOS chains | Prevents a high synthetic-confidence score; does not prove production origin |

## Realism Score by Category

- **Field format accuracy:** 9 — Native XML/NDJSON fields and process identities are internally credible; no demonstrated schema defect.
- **Temporal patterns:** 9 — Visible lifecycles and sampled authentication stages are compatible; collection boundaries and source delays explain apparent gaps.
- **Cross-source correlation:** 9 — Matched process fields and Linux/macOS authentication chains agree without requiring identical timestamps.
- **Behavioral realism:** 8 — Role-specific tools and user routines are credible, with mild command-vocabulary repetition.
- **Environmental consistency:** 8 — Different platforms and host roles have distinct evidence; the repeated background COM vocabulary remains a minor reservation.

## Recommendations

- If this were synthetic, assess the visible dllhost command mix against host-role-specific production samples before expanding it. The observed three-value pool is the concrete issue; merely adding random GUIDs would reduce accuracy.
- If this were synthetic, verify that repeated developer routines are intentional same-user habits and vary naturally with the task. Preserve legitimate repetition rather than forcing variation solely to make the logs look messy.
- Preserve the demonstrated native macOS process ordering and distinguish native occurrence time from normalized observation time in downstream analysis. No additional source family, blanket increase in volume, or mandatory out-of-window closure is justified by this review.

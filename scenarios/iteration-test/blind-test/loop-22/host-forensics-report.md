# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 61
**Synthetic-Confidence Score:** 28

## Executive Summary

The endpoint evidence is mostly production-like: visible process identities, parent relationships, authentication sequences and Unix exec transitions survive detailed consistency checks across the supplied sources. A small cluster of nearly identical 15-minute Windows process lifetimes is a weak synthetic indicator, but I did not establish a hard contradiction; the verdict is a modest lean toward real telemetry, not a claim that a sophisticated simulation has been excluded.

## Evidence For Synthetic

- [weak_signal] Four of 754 matched Sysmon process-create/process-terminate lifetimes fall within 0.14 seconds above exactly 900 seconds, across two domain controllers and two executable names. In `DC-01.meridianhcs.local/windows_event_sysmon.xml`, taskhostw PID 4300 starts at `2026-11-02T14:34:02.4720955Z` and its embedded `UtcTime` lifetime is 900.131 seconds. In the corresponding DC-02 file, conhost PID 7688 starts at `14:03:13.0725665Z` and lasts 900.140 seconds; taskhostw PIDs 8396 and 8784 start at `16:26:25.5149534Z` and `17:51:35.0393079Z` and last 900.048 and 900.109 seconds. This resembles a shared lifetime cap plus source delay, but timeout policies and scheduled work are credible alternatives. It receives little weight and is not treated as an impossible lifecycle.

## Evidence For Real

- Windows process creation agrees in concrete identities and ownership. On WS-MCHEN-01, Security record 948751, Event 4688 at `13:12:18.2953440Z`, describes Firefox PID `0x1c28` (7208), parent `0x1a7c` (6780), user `marcus.chen`, and logon `0x6c29844`. Sysmon record 525194, Event 1 at `13:12:18.2214335Z`, carries those same values, an explorer parent, medium integrity and the matching command. Its eCAR PROCESS/CREATE observation occurs at `13:12:18.387Z`. The modest source offsets are credible.
- User sessions include organic workstation locking. WS-AJOHNSON-01 Security records 130287/130291 show lock/unlock at `14:53:33.1030611Z` / `14:55:40.5110925Z`; subsequent pairs span `17:25:08.5233118Z`–`17:53:38.9629346Z` and `18:20:13.0473015Z`–`18:34:37.6436821Z`. All retain user `aisha.johnson`, logon `0x25e4b26`, session 2.
- Linux SSH evidence preserves recognizable transport/authentication/session distinctions. APP-INT-01 syslog lines 83–86 identify connection, public-key acceptance, PAM opening and logind session 187 for the same user/source tuple; lines 98–99 close and remove that session later.
- macOS native records represent fork and successive exec images separately, preserving PID while changing `pidversion`. On MAC-MROSS-01, PID 25527 executes launchd → xpcproxy → Terminal; PID 25528 executes login, and PID 25529 executes the user's zsh. MAC-MROSS-02 has a distinct iTerm/iTermServer/login/shell chain. These are substantially more convincing than treating an executable change as a new unrelated process.
- Exhaustive bounded identity checks found no eCAR actor activity before its visible creation or after its visible termination, and no Sysmon own-process, parent-process or source/target-process timing inversion against visible Event 1/5 lifetimes. This is evidence of consistency, not proof of provenance.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the analyst briefing. The endpoint inventory contains 23 eCAR files with 38,411 records, 10 Security XML files with 17,894 events, 10 Sysmon XML files with 11,689 events, 11 Linux syslog files with 4,304 lines, and two macOS Endpoint Security exports totaling 320 records. The two Unified Log files contain five records. I also read selected bash and zsh histories. The principal visible window is approximately `2026-11-02 13:00–19:00 UTC`.

I parsed the XML namespaces and JSON records, counted event families, joined process identities within each host, compared native creation/termination timing, checked parent and access-target timing, inspected session identities, and read concrete authentication and command sequences. Paths in this report are relative to the supplied data directory. Absence of unselected event types, out-of-window initiators and source coverage alone did not affect the score.

### Windows process trees and hashes

Process relationships are plausible for the visible applications and roles. The domain controllers show svchost-hosted COM/WMI/task activity; workstation records include explorer-launched user applications, search host workers and service-manager-launched maintenance programs. For example, DC-02's first visible Event 1 at `13:04:02.1664283Z` identifies dllhost PID 6908, parent svchost PID 5116, command `dllhost.exe /Processid:{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}`, SYSTEM user and system integrity. The parent command is specifically `svchost.exe -k DcomLaunch`.

The Firefox example in Evidence For Real also agrees at the command level: `"C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url http://WEB-EXT-01/`. Its Sysmon ProcessGuid is `{7b2a0e3f-8c32-6ae8-3502-0010f0fef533}` and SHA256 is `CDF043E5616C1A4BD79E1A7755E780CC261A8A4190AA98866191F0A746F2C444`. Repeated Event 1 observations of the same image within each host did not show changing hash sets in my scan. Some paths with unknown FileVersion (`-`) have different hashes on different hosts; that is compatible with software differences and was not scored as an inconsistency.

For each Sysmon file I checked visible process GUIDs against Event 1 creation and Event 5 termination. I additionally checked ParentProcessGuid and the source/target process GUID variants used by access-related events. No checked dependency preceded its visible creation or followed its visible termination. These checks do not assert that all pre-window parents or all unobserved terminations must be present.

### Windows sessions and duration texture

The visible logon mix varies by role. DC-02 has 147 type-5, 145 type-3 and one type-10 Event 4624; FILE-SRV-01 has 45 type-5, 59 type-3 and four type-10. WS-AJOHNSON-01 additionally has interactive, unlock and NewCredentials logons. I found no TargetLogonId that referred to different successful target usernames on the same host.

Matched short network sessions and longer remote-interactive sessions coexist. On DC-02, 140 uniquely matched type-3 sessions range from approximately 1.642 to 30.143 seconds, while its matched type-10 session lasts 2,509.019 seconds. FILE-SRV-01's four matched type-10 sessions range from 956.139 to 5,328.396 seconds. These differences are directionally reasonable. They do not require every service session to terminate inside the collection window.

The 900-second process cluster is the principal reservation. It is small: four lifetimes among 754 matched native Sysmon pairs, rather than a dataset-wide fixed duration. Other lifetimes are varied, including sub-minute workers and much longer processes. I therefore treat this as a possible shared timeout boundary, not a strong generator fingerprint. The values were measured from the embedded Sysmon `UtcTime` fields, rather than assuming that raw file order measures lifetime.

### Linux SSH, privilege changes and history

APP-INT-01 provides a useful complete in-window example. In `syslog.log`, sshd PID 3394691 logs:

- Line 83, `13:59:51.858219Z`: connection from `10.10.1.35:54705` to `10.10.2.30:22`.
- Line 84, `13:59:52.662496Z`: RSA public-key acceptance for `aisha.johnson`.
- Line 85, `13:59:52.807326Z`: PAM session opens for UID 2528.
- Line 86, `13:59:53.390124Z`: logind announces session 187.
- Line 98, `14:21:48.262233Z`: PAM closes the session.
- Line 99, `14:21:48.940789Z`: logind removes session 187.

The corresponding eCAR session uses source tuple `10.10.1.35:54705`, logon `0x151bdd5c`, session ID 187, and login/logout observations at `13:59:54.275Z` / `14:22:06.897Z`. The closing EDR observation arrives later than syslog; it remains ordered and does not establish activity outside the process/session lifecycle by itself.

The command histories differ by user and host. WS-LNGUYEN-01 includes git, Docker, make, npm, Python and SSH work, while APP-INT-01's aisha history includes journalctl, getent and storage checks. Sudo records distinguish the invoking user from root command execution, and eCAR often represents the sudo process and root child separately. Background sysstat occurs 36 times on numerous hosts over the six-hour window; this is compatible with the explicitly visible ten-minute cron job and is not an authenticity defect.

Some commands query package-like names as systemd units, such as APP-INT-01's `systemctl restart cifs-utils` at `13:18:35.248247Z`. The supplied record establishes that a user attempted the command; it does not establish successful service activation. I did not convert that administrative oddity into a hard contradiction.

### macOS native semantics and normalization

The native files declare Endpoint Security message version 11 and contain fork, exec and exit observations. MAC-MROSS-01 has 47 fork, 54 exec and 46 exit records; MAC-MROSS-02 has 55 fork, 64 exec and 54 exit records. Extra execs relative to forks are expected when a process changes images more than once.

On MAC-MROSS-01, native lines 1–7 show PID 25527 forked at `13:07:32.811343Z`, exec into xpcproxy at `13:07:32.820534Z`, then Terminal at `13:07:32.835499Z`. Its child PID 25528 execs `/usr/bin/login`; PID 25529 then execs `/bin/zsh`. The audit principal binds to UID 501 while privileged login execution retains root effective UID at the appropriate stage. I did not confuse audit session IDs with eCAR logon IDs or POSIX session/group IDs.

The SSH path also differentiates daemon and helper roles. Native lines 87–101 show PID 44180 progressing through xpcproxy, sshd-keygen-wrapper, sshd and sshd-session, with sshd-auth and session children, followed by a UID-501 shell. Successful authentication is not inferred merely from the presence of an ES notification: the Unified Log and normalized session evidence provide the authentication context.

An automated image comparison initially highlighted eCAR child PID 44183 because its parent state appeared one physical line later. Inspection resolved this: eCAR lines 305 and 306 both have timestamp `16:02:09.756Z`; the native exec into sshd-session is at `16:02:06.184365Z`, before the native child fork at `16:02:06.201477Z`. Equal-millisecond serialization order is insufficient to allege impossible causality. This observation did not affect the score.

Across the native Mac snapshots I found no same `(pid, pidversion)` assigned multiple executable paths, and no changing signing identity or cdhash for the same executable device/inode identity. Sampled mach-time differences convert consistently at 24,000,000 ticks per second. Sparse Unified Log coverage and the absence of other ES event types are collection facts, not defects.

The eCAR inventory plist CREATE/DELETE records are separate from process execution. The evidence does not justify equating plist removal with unloading a job, or assuming that writing the plist alone proves activation. No such unsupported lifecycle claim contributes to this assessment.

### Overall weight and limits

The positive evidence is not that the logs match “too perfectly”; it is that concrete native fields and meaningful temporal relationships are plausible under the stated collection assumptions. The small duration-boundary pattern leaves some suspicion, but does not outweigh the observed consistency. A well-engineered synthetic source could reproduce these properties, which limits verdict confidence despite the relatively low synthetic-appearance score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| weak_signal | Windows Sysmon process lifecycle | Four of 754 matched lifetimes, DC-01/DC-02; taskhostw and conhost | Slight upward adjustment for a possible shared 900-second lifetime boundary; scheduled timeouts remain a credible explanation. |

No demonstrated hard contradiction, source-native schema violation or material lifecycle contract gap was established in the endpoint checks described above.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native records and normalized identities are internally credible; no demonstrated schema defect.
- **Temporal patterns:** 8 — Varied native lifetimes and sensible lifecycle ordering, with a small suspicious 900-second cluster.
- **Cross-source correlation:** 9 — Concrete PID, user, parent and session comparisons agree with plausible observation offsets.
- **Behavioral realism:** 8 — Distinct administrative/developer activity and credible workstation/background processes; the short slice limits longitudinal judgment.
- **Environmental consistency:** 9 — Windows, Linux and macOS evidence is generally platform-appropriate without requiring uncollected sources.

## Recommendations

- If this were synthetic, inspect the four near-900-second Windows process lifetimes for a shared default or cap. Preserve a common boundary when an actual scheduler, idle timeout or policy explains it; otherwise use lifetimes appropriate to each executable and activity.
- If this were synthetic, retain the existing distinctions between fork, exec, privilege changes, authentication, session opening and termination. The native Mac sequence and the Linux SSH example are effective, concrete models of those distinctions.
- If this were synthetic, preserve source-specific timing while keeping causal execution-state references intelligible at the exported timestamp precision. The equal-millisecond Mac eCAR parent/child example is explainable, but higher precision would make that explanation easier to verify.

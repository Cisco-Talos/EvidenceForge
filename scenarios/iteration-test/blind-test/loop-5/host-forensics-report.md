# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint evidence is unusually convincing in its process identity, session ownership, binary consistency, and platform-specific execution semantics. I nevertheless assess it as synthetic because two independent native-source timing patterns look like prescribed execution offsets: eleven RDP session bootstrap pairs cluster within one millisecond of exactly half a second, and two macOS command groups have repeated microsecond-exact fork fractions with matching monotonic-clock intervals. These are timing-distribution findings, not impossible causality findings; the absence of a demonstrated hard contradiction keeps the synthetic-confidence score in the “likely synthetic” range.

## Evidence For Synthetic

- [distribution_texture] All eleven visible RDP-associated `smss.exe` → `winlogon.exe` process-create pairs across DC-01, DC-02, FILE-SRV-01, MAIL-FIN-01, and WS-AJOHNSON-01 have a Sysmon `UtcTime` separation of either 0.500 seconds (eight pairs) or 0.499 seconds (three pairs). Examples include DC-01 `13:55:21.813` → `13:55:22.313`, FILE-SRV-01 `14:12:16.113` → `14:12:16.613`, and DC-02 `14:45:36.240` → `14:45:36.740`, all on 2026-11-02. This near-degenerate delay across distinct hosts and sessions resembles a fixed lifecycle offset. Other visible interactive bootstrap pairs span 0.363–1.225 seconds, so the whole source is not simply quantized into half-second intervals.
- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 58, 61, and 64 report forks at `14:37:50.487145000Z`, `14:38:28.487145000Z`, and `14:38:57.487145000Z`. Their children are PIDs 54077, 54176, and 54254; subsequent exec records show `bash connector-check.sh --check-network`, `cat /etc/resolv.conf`, and `cat /etc/hosts`. The identical six-digit fractional second survives 38- and 29-second intervals, and the `mach_time` differences are exactly 912,000,000 and 696,000,000 ticks. These are native fork occurrence timestamps rather than coarse shell-history timestamps.
- [distribution_texture] The same timing construction recurs independently on MAC-MROSS-02: native ES lines 86, 89, and 92 record forks at `15:30:55.965208000Z`, `15:31:17.965208000Z`, and `15:31:58.965208000Z`. The children execute `dscl . -read /Users/maya.ross UserShell NFSHomeDirectory`, `find /Users/maya.ross/Documents -maxdepth 2 -type f -name '*.json'`, and `du -sh /Users/maya.ross/Documents`. The corresponding `mach_time` differences are exactly 528,000,000 and 984,000,000 ticks. Two separate groups with preserved microsecond fractions are more suggestive of assigned command offsets than ordinary dispatch and scheduler timing. Scripted activity or a timestamp transformation is a possible alternative explanation, so this is not labeled an impossibility.

## Evidence For Real

- Every one of the 955 Windows Sysmon Event 1 records has a Security 4688 counterpart on the same host with the same numeric process ID within a one-second matching window. All 955 matched image paths agree. This supports a shared underlying process history; completeness itself is not used as a synthetic indicator.
- Across 11,624 Sysmon records, the visible per-`ProcessGuid` checks found no dependent record preceding its visible creation, no record following its visible termination, and no child creation preceding a visible parent creation. Repeated creations of the same image on a host retain the same hash set.
- Windows sources contain differentiated account/session semantics: Type 9 network-credential cloning, Type 10 remote-interactive sessions, Type 7 unlocks, local-interactive sessions, network logons, service logons, and failures. The records are not all generic successful Type 3 logons.
- MAC-MROSS-01 models Terminal startup as launchd/fork → xpcproxy/exec → Terminal/exec → login/fork/exec → zsh, while MAC-MROSS-02 has an iTerm2/iTermServer/ShellLauncher chain. Native audit-token `(pid, pidversion)` identities retain consistent executable paths and process start times across subsequent observations.
- Linux SSH and sudo activity includes plausible distinct connection, authentication, PAM session, logind, command, and close observations. For example, DB-PROD-01 receives a connection from `10.10.1.21:56040` at `13:07:31.506676Z`, accepts lina.nguyen's password at `13:07:39.625701Z`, opens the PAM session at `13:07:39.719419Z`, then logs session 342 at `13:07:40.399678Z`.
- Background activity is role-sensitive: FILE-LNX-01 has smbd and smbd_audit evidence; the mail hosts have Postfix/Dovecot traffic; workstations show GNOME, printing, desktop indexing, package management, and network-management activity. Periodic sysstat collection has an ordinary cron explanation.

## Detailed Analysis

### Examination scope and method

I examined only the supplied data directory and this analyst's instruction file. The endpoint inventory comprises 23 host eCAR files with 37,537 records, ten Windows Security exports containing 17,832 events, ten Sysmon exports containing 11,624 events, eleven Linux syslog files, shell histories, and two macOS Endpoint Security exports containing 330 records in total. The endpoint timestamps span approximately 13:00–19:00 UTC on 2026-11-02.

I parsed the XML and JSON endpoint records, inspected actual process/session/file entries, compared Windows process creation identities and image paths, checked visible Sysmon process and parent ordering, checked eCAR process actor lifetimes with a one-second tolerance, and examined macOS fork/exec/exit chains and audit identities. This was an endpoint-focused review rather than an exhaustive audit of the network sensors. A process/session whose initiation precedes the collection window was not treated as defective.

### Windows process trees and shared identity

The Windows process trees generally make sense. On WS-MCHEN-01, Sysmon records show services.exe spawning `svchost.exe -k netsvcs -p -s Winmgmt` at `13:01:29.420`, explorer.exe spawning PowerShell at `13:28:48.987`, and that PowerShell spawning OpenSSH `ssh.exe marcus.chen@PROXY-01.meridianhcs.local` at `13:28:52.928`. Background WMI, COM surrogate, search, console, update, endpoint protection, and service activity have plausible parent families.

The same host's `runas.exe /netonly /user:marcus.chen-admin ...` starts at `14:13:45.467`, followed at `14:13:49.114` by cmd.exe with a distinct `LogonId` of `0x6cc5e46`; the initiating process belongs to `0x6c29844`. The normalized session record distinguishes the local principal marcus.chen from outbound principal marcus.chen-admin and records `cloned_from_logon_id`. That is materially better ownership than assigning the outbound account as the local process owner.

All 955 visible Sysmon process creations matched a Security 4688 PID/image counterpart. Hash sets were stable for the same image path within each host's visible creations. These checks do not establish the provenance of the telemetry, but they rule out several common synthetic failures.

### Windows sessions and the repeated RDP timing

Type 10 sessions have their own session bootstrap processes rather than reusing arbitrary workstation processes. The problem is the distribution of one internal timing step:

| Host | smss.exe UtcTime | winlogon.exe UtcTime | Delay, seconds |
|---|---|---|---:|
| DC-01 | 13:55:21.813 | 13:55:22.313 | 0.500 |
| DC-01 | 14:52:32.041 | 14:52:32.541 | 0.500 |
| DC-01 | 17:54:44.115 | 17:54:44.615 | 0.500 |
| DC-01 | 18:10:14.005 | 18:10:14.504 | 0.499 |
| DC-02 | 14:45:36.240 | 14:45:36.740 | 0.500 |
| FILE-SRV-01 | 14:12:16.113 | 14:12:16.613 | 0.500 |
| FILE-SRV-01 | 14:59:41.617 | 14:59:42.117 | 0.500 |
| MAIL-FIN-01 | 13:50:26.658 | 13:50:27.157 | 0.499 |
| MAIL-FIN-01 | 14:11:42.449 | 14:11:42.949 | 0.500 |
| MAIL-FIN-01 | 14:45:21.884 | 14:45:22.384 | 0.500 |
| WS-AJOHNSON-01 | 16:01:21.332 | 16:01:21.831 | 0.499 |

Times are 2026-11-02 UTC and come from the respective host's `windows_event_sysmon.xml`, matching each winlogon process to its visible smss parent by `ParentProcessGuid`. The narrow interval is not a causality violation: smss still precedes its child. It is a repeated timing shape across five hosts. In comparison, visible non-RDP bootstrap examples include WS-EBROOKS-01 at 1.173 seconds and WS-SMARTINEZ-01 at 0.363 and 0.420 seconds.

I did not score absent pre-window logons, missing selected Sysmon event types, or the existence of complete correlated RDP evidence. The suspicious property is the repeated numerical delay.

### Linux authentication, command execution, and background noise

APP-INT-01's syslog at `13:12:39.464117Z` records aisha.johnson invoking `/usr/bin/iostat -xz 1 3` through sudo, opens the sudo PAM session at `13:12:39.560586Z`, and closes it at `13:12:43.727135Z`. The command duration is compatible with a short sampled performance query. APP-INT-01's SSH records at `13:20:15.970390Z` through `13:20:22.432576Z` separately represent connection, successful public-key authentication, PAM open, and logind session creation.

Across the eCAR files, the actor-lifetime scan did not find an actor operation more than one second before its visible process creation or after its visible termination. This check used the recorded UUID identities rather than treating PID alone as globally unique.

Ten Debian-style hosts each contain 36 sysstat cron invocations over the six-hour slice. That equality is not evidence of synthetic scheduling: the records explicitly identify a periodic cron job. For example, LOG-MON-01 records `(sysstat) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)` at `13:06:00.320772Z`. A regular configured task should be regular. Anacron has its own start, delayed job start, termination, and exit messages. DB-PROD-01 has a different background profile dominated by irqbalance and multipathd rather than simply copying the Debian desktop services.

Some repeated syslog wording merits caution as weak texture, but repeated messages from the same daemon or a centrally configured fleet are ordinary. I did not add those impressions to the score without a stronger demonstrated contradiction or distribution defect.

### macOS native execution and timing

The native macOS records declare message version 11 and distinguish fork, exec, and exit. MAC-MROSS-01 PID 42154 is initially a forked launchd image at `13:07:32.811343000Z`, becomes xpcproxy at `13:07:32.820534000Z`, and becomes Terminal at `13:07:32.835499000Z`; its process start time remains tied to the fork. Subsequent records distinguish elevated login from the user shell. MAC-MROSS-02 uses an iTerm-specific chain instead. I found no executable/start-time disagreement for repeated `(pid, pidversion)` observations on either host.

The SSH chain on MAC-MROSS-01 around `16:02:07Z` includes xpcproxy, sshd-keygen-wrapper, sshd, sshd-session, sshd-auth, and a later user zsh. The root service identity retains an unauthenticated audit user until the user-side transition; this is not treated as a Linux PAM or Windows logon schema. Unified Log's accepted-publickey message at `16:02:08.783262+0000` refers to the same source tuple `10.10.1.42:58545` represented by the normalized SSH session evidence.

The suspicious pattern is narrower: two command groups preserve exactly the same microsecond fraction for multiple forks spaced whole seconds apart. On MAC-MROSS-01 the monotonic timestamps are 25,024,091,691,480; 25,025,003,691,480; and 25,025,699,691,480. MAC-MROSS-02 independently repeats the pattern with 56,204,543,164,992; 56,205,071,164,992; and 56,206,055,164,992. Other fork/exec events have varied microsecond fractions, and the execs immediately after these forks have their own varied small delays. This selective exactness makes ordinary source-wide timestamp rounding a less satisfactory explanation.

I did not infer successful execution from the Unified Log policy message `ASP: Security policy would not allow process: 62500, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist` at `15:42:09.009673+0000`. The visible ES stream does not show a successful exec of that process. Likewise, normalized plist creation/deletion observations were treated as file operations, not proof of registration, activation, or job termination.

### Weighting and alternative explanations

The assessment rests on two timing mechanisms observed across different native families, not on a polished intrusion narrative or comprehensive collection. The RDP delay could reflect a repeatable implementation timeout; the macOS groups could reflect automation plus a source transformation that preserves intended schedule timestamps. Neither alternative is impossible. However, their combination is more consistent with rendered timing plans than untouched endpoint occurrence times.

No verified hard contradiction, native schema impossibility, or visible process-identity break was found in the checks described here. That is why the score is 66 rather than in the 81–100 band.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process creation | Eleven RDP bootstrap pairs on five hosts; eight delays of 0.500 s and three of 0.499 s | Strongest repeated cross-host timing indicator; consistent with a prescribed internal offset |
| distribution_texture | macOS Endpoint Security fork notifications | Three forks on MAC-MROSS-01 and three on MAC-MROSS-02, in two separate command groups | Microsecond-exact fractions and exact monotonic whole-second intervals suggest assigned scheduling anchors; strengthens the synthetic assessment |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON are parseable, Windows fields are coherent, and the examined macOS audit identities remain consistent; no native schema impossibility was established.
- **Temporal patterns:** 5 — Most ordering and durations are plausible, but repeated half-second RDP offsets and microsecond-exact macOS command groups are conspicuous.
- **Cross-source correlation:** 9 — All 955 Sysmon process creations have matching Security PID/image evidence; examined normalized endpoint ownership is coherent.
- **Behavioral realism:** 8 — User tools, administrative session semantics, role-specific services, and desktop activity are varied and generally plausible.
- **Environmental consistency:** 9 — Windows, Linux, and macOS have differentiated evidence and appropriate service/process families within the visible collection scope.

## Recommendations

- If this were synthetic, vary the smss-to-winlogon interval according to the session bootstrap and host execution conditions while preserving causal ordering. Validate its distribution across all RDP sessions, rather than validating each pair only in isolation.
- If this were synthetic, distinguish intended command schedule times from observed native fork times. Apply execution/scheduler latency before producing both wall-clock and monotonic occurrence timestamps so separate command starts do not retain identical microsecond fractions across whole-second offsets.
- If this were synthetic, add distribution checks for repeated fractional-second groups and near-constant lifecycle delays across hosts. Preserve the existing process identity, hash stability, session ownership, and platform-specific fork/exec distinctions while changing timing behavior.

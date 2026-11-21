# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 74
**Synthetic-Confidence Score:** 62

## Executive Summary

The endpoint evidence is substantially convincing: Windows process identities and binary hashes remain consistent, normalized process lifetimes are coherent, and the Macs preserve the distinction between fork, exec, session identity, and process termination. A repeatable, message-dependent timestamp precision artifact across ten Linux hosts nevertheless favors synthetic origin; this is a distribution finding, not a demonstrated impossible process or session lifecycle.

## Evidence For Synthetic

- [distribution_texture] Every Linux syslog message containing `Anacron 2.3 started` has a six-digit fractional timestamp whose last three digits are zero: **10/10 startup messages**, compared with **0/40 subsequent anacron messages** and **5/4,080 other syslog messages**. These are native-looking RFC5424 rows, not the deliberately millisecond-resolution normalized eCAR timestamps. Examples: `APP-INT-01.../syslog.log:28`, `2026-11-02T13:24:09.013000Z`; `FILE-LNX-01.../syslog.log:85`, `13:23:36.032000Z`; `WS-OHADDAD-01.../syslog.log:5`, `13:06:28.204000Z`. The precision changes with the message's position in a lifecycle across otherwise separate hosts.
- [weak_signal] The same ten anacron lifecycles each comprise exactly five messages—startup, announced delay, job start, job termination, normal exit—and every startup falls between `13:03:39.080000Z` and `13:27:55.113000Z` in an approximately six-hour slice. Shared fleet scheduling can explain clustered daily maintenance and is not independently a defect. Its relevance is limited to supporting the specific timestamp fingerprint above; it is not a separate major contribution to the score.

## Evidence For Real

- All **935** Sysmon Event 1 records for which Security 4688 supplied the same host/PID had identical executable image and command line in that matching pair. There were 936 Sysmon process-create records in total; source counts differ slightly rather than forcing every source into identical coverage. No per-host executable path had changing Sysmon `Hashes` values in the visible Event 1 population.
- A scan of all 23 host `ecar.json` files found no actor references more than 100 ms before that actor's visible PROCESS/CREATE or more than 100 ms after its visible PROCESS/TERMINATE, when the relevant process UUID existed in those records. This is a useful bounded lifecycle check, not a claim that every possible endpoint correlation was proven.
- Windows logs include interactive, service, network, remote interactive, unlock, and new-credentials logons, plus workstation lock/unlock and RDP reconnect/disconnect activity. For example, WS-MCHEN has type 2, 3, 5, 7, and 9 logons; its visible records include three each of 4800 and 4801. The mix is richer than an exclusively attack-centered event stream.
- macOS Endpoint Security rows distinguish inherited process images at fork from exec targets using the same PID with a changed `pidversion`. On MAC-MROSS-02, PID 19001 successively executes `ShellLauncher` and `/bin/zsh`; the records retain iTerm as the responsible process rather than falsely making it the immediate parent of every descendant.
- Linux SSH, sudo/PAM, logind, cron, Samba, mail, and desktop service records vary by host role. FILE-LNX-01 has an actual Samba authentication/open/read/close/disconnect sequence, whereas the Linux workstations include NetworkManager, GNOME, printing, thermal, and package-management messages.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the assigned briefing. Host evidence covers approximately `2026-11-02 13:00–19:00 UTC`, across 23 normalized endpoint files, ten Windows Security/Sysmon host pairs, eleven Linux syslog files, and two macOS Endpoint Security/Unified Log pairs. Windows XML parsing covered **17,484 Security events** and **11,489 Sysmon events**. I also inspected bash/zsh histories and actual records from each endpoint source family.

Checks included per-host process UUID lifetime relationships in normalized telemetry, Sysmon create-event PID alignment with Security 4688, within-host image/hash stability, Windows logon-type populations, native macOS identity consistency, and Linux message/timestamp distributions. I did not use filesystem modification times, domain resolvability, scenario narrative shape, source completeness, or absent pre-window processes as authenticity evidence. Missing selected Sysmon event families were not penalized.

### Windows process and session evidence

The dominant parent/child pairs are plausible service and desktop patterns: `svchost.exe → taskhostw.exe` (127 visible Sysmon creates), `svchost.exe → dllhost.exe` (126), `svchost.exe → WmiPrvSE.exe` (118), and the `smss → winlogon → userinit → explorer` family. These counts describe the supplied Event 1 population; they are not themselves proof of real or synthetic origin. All visible Event 1 process IDs were divisible by four, and there were no duplicate per-host ProcessGUIDs among those creation records.

A concrete example is WS-MCHEN at `13:11:53.5131628Z`: Sysmon Event 1 reports PID **7260**, image `C:\Windows\System32\taskhostw.exe`, parent PID **5904** / `svchost.exe -k LocalSystem`, SYSTEM identity, system integrity, session 0, and LogonId `0x3e7`. At `13:43:26.4325543Z`, PID **7440** is `mstsc.exe /v:DC-02`, owned by `MERIDIANHCS\marcus.chen`, parent `explorer.exe` PID **6604**, with a user logon ID and terminal session 1. These contexts sensibly separate background execution from interactive remote administration.

The matching Security/Sysmon image and command-line checks yielded **935 agreeing pairs**. The unmatched Sysmon create is not, by itself, a collection defect. Likewise, paths having different hashes across different machines can reflect different software builds; the relevant stronger check found no hash changes for the same image path within one host's observed creates.

DC-01's Security records include 302 successful logons: 155 type 3, 144 type 5, and three type 10. WS-EBROOKS includes a type 2 interactive logon, type 3 network activity, type 5 service activity, and two type 7 unlocks. These are credible kinds of events for the apparent hosts. I did not demand every session close within this six-hour window or treat service sessions surviving the window as erroneous.

### Linux SSH, administrative commands, and background services

FILE-LNX-01 provides a source-native sequence at `13:01:46.403064Z`: Samba authentication for `marcus.chen` from `10.10.2.11` succeeds using Kerberos. A worker PID **2665015** connects to `Shared` at `13:01:46.438237Z`, then records open/read/close operations against `/srv/samba/Shared/Team/2024/vendor-review-v2.docx` at `13:01:47.070052Z`, `.177486Z`, and `.294481Z`, before closing the service connection at `13:01:48.052898Z`. The worker, share, principal, and path remain coherent.

Near the end of the same file, SSH PID **2735008** logs a connection from `10.10.1.31:50548` at `18:57:19.301362Z`, accepts `marcus.chen`'s password at `18:57:26.535344Z`, opens PAM at `.691165Z`, then creates logind session 477 at `18:57:27.451013Z`. An absent close before collection ends would not be an authenticity issue. At the beginning of the file, an already existing SSH session closes at `13:00:59.171682Z`; this is compatible with collection starting mid-session.

The histories are not simply converted into bogus executable names for shell builtins. Across normalized process creates I found no executable image named `cd`, `history`, `ulimit`, `export`, `source`, or related tested builtins. Compound commands generally use shell images. Role-specific examples include Omar's PostgreSQL inspection commands, Lina's build/system inspection work, and operations users' service/log inspection commands. Such activity can occur in either real or well-authored synthetic logs, but the visible mechanics are credible.

The strongest negative evidence is specifically the **anacron startup timestamp distribution**. APP-INT-01's same PID **2935583** logs startup at `13:24:09.013000Z`, its delay announcement at `13:24:10.738813Z`, job start at `13:35:10.442457Z`, job termination at `13:37:23.985691Z`, and normal exit at `13:37:26.739810Z`. FILE-LNX-01's PID **2674812** similarly begins at `13:23:36.032000Z`, then logs at `13:23:37.655070Z`, `13:28:36.899785Z`, `13:30:45.720152Z`, and `13:30:46.080992Z`.

The ten startup rows all have exact millisecond alignment; none of the forty follow-on rows does. Only five of 4,080 non-anacron syslog rows share that alignment, approximately the incidental frequency expected from unrestricted microsecond timestamps. Scheduling explains daily maintenance and common cron intervals, but does not naturally explain a precision change tied to the startup message from the same process. A special collector or upstream timestamp transformation remains possible because collection internals were not supplied. This uncertainty prevents an extremely high synthetic score or a hard-contradiction classification.

The 36 sysstat cron rows on each of ten hosts are not separately penalized: a common ten-minute fleet schedule is a normal production possibility. Nor are ordinary repeated daemon messages alone proof of templating.

### macOS process and policy semantics

The 326 native Endpoint Security rows comprise fork, exec, and exit notifications. MAC-MROSS-01 has 48 forks, 55 execs, and 47 exits; MAC-MROSS-02 has 56 forks, 65 execs, and 55 exits. Multiple execs per lifetime are expected and explain why exec counts exceed forks.

On MAC-MROSS-02, launchd forks PID **18998** at `13:12:07.845472000Z`; it becomes xpcproxy at `.861432000Z` and iTerm2 at `.873566000Z`. The visible chain then includes iTermServer, `/usr/bin/login`, and a ShellLauncher-to-zsh transition. PID **19001** retains its process start time across exec while its `pidversion` changes from 20 to 21 at `13:12:07.954212000Z`. Immediate parent PID **19000** and responsible iTerm PID **18998** are different concepts and are represented separately.

I checked repeated native process identities by host/PID/pidversion for changing executable path, inode, or size and found none. I also found no reused device/inode pair associated with conflicting paths in the examined native rows. These checks support stable observed identity without assuming every executable path universally denotes one immutable file.

The inbound SSH sequence on MAC-MROSS-01 starts with launchd/xpcproxy, `sshd-keygen-wrapper`, sshd, and sshd-session transitions around `16:02:05.895451–16:02:06.011611Z`. Its Unified Log row at `16:02:06.270473+0000` reports accepted publickey authentication from `10.10.1.42:53362`. The user shell exec follows at `16:02:06.440808000Z`, under a user audit session distinct from the GUI session. The row vocabulary is native macOS-style evidence; Linux PAM/systemd rows are not required here.

MAC-MROSS-01's Unified Log also contains the kernel/AppleSystemPolicy message at `15:42:09.009673+0000`, `Security policy would not allow process: 62500, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no successful native exec or normalized execution of that named application. I do not infer successful child effects from that policy message, and I do not confuse a notification's action-result structure with a separate authorization verdict. No launch-item registration/write/activation contradiction was established in the visible Mac records.

### Interpretation and limits

The score is driven by a strong, repeatable timestamp distribution artifact, with only minor supporting weight from the corresponding maintenance-start cluster. It is not driven by suspicious behavior being easy to reconstruct, apparently complete collection, or an assumed absence of ordinary platform artifacts. The data could reflect a real environment passed through a specialized transformation, but the message-specific precision boundary makes synthetic construction the more likely explanation at moderate confidence. I established no hard contradiction in the visible process lifetimes reviewed.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Linux RFC5424 syslog timestamps | 10/10 anacron startup messages exact to milliseconds; 0/40 same-process follow-on messages; 5/4,080 other rows | Primary finding: repeatable lifecycle-position-dependent precision supports likely synthetic origin despite coherent event content. |
| weak_signal | Linux anacron maintenance activity | Ten hosts, one five-row run each, all starting within the first 28 minutes | Small supporting weight only; shared scheduling is a viable real-world explanation. Not counted as an independent hard defect. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML and macOS process/exec identities are credible; no demonstrated native field contradiction was established.
- **Temporal patterns:** 7 — Lifecycles are ordered plausibly, but the ten-host anacron startup precision fingerprint is a material authenticity tell.
- **Cross-source correlation:** 9 — The 935 matching Windows create pairs agree on image/command, and sampled SSH/native process sequences remain coherent.
- **Behavioral realism:** 8 — User tools, service activity, shell treatment, and session types fit the visible platforms and roles.
- **Environmental consistency:** 8 — Mixed Windows, Linux, and Mac host behavior is credible; the fleet maintenance startup cluster adds limited uncertainty.

## Recommendations

- If this were synthetic, correct the source-timestamp path responsible for the anacron startup precision boundary. A startup message and its subsequent messages should use the same source clock/precision treatment, unless an explicit collection transformation explains the difference.
- If this were synthetic, tie the observed fleet maintenance starts to actual per-host scheduling or uptime intent. Preserve shared schedules when appropriate, but avoid independently assigning one lifecycle to the beginning of every collection slice without an environmental reason.
- Retain the observed strengths: consistent per-host binary hashes, coherent source identities, distinct fork/exec/process lifetimes, and platform-appropriate session evidence. No extra source family or out-of-window lifecycle record is required to address the findings above.

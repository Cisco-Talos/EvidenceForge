# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 38

## Executive Summary

The endpoint evidence is mostly production-like, with coherent process identities, credible Windows user/service separation, and well-ordered Linux and macOS session evidence. I found some repeated background-activity texture and questionable desktop-software placement on apparent Linux servers, but no demonstrated impossible lifecycle or source-native contradiction strong enough to establish synthetic origin. The score reflects mostly realistic telemetry with explainable artifacts; the verdict confidence expresses confidence that a categorical authenticity decision is not justified by these endpoint observations.

## Evidence For Synthetic

- [environment_or_collection_plausibility] Desktop integration activity is repeatedly present on apparent infrastructure servers. `WEB-EXT-01.meridianhcs.local/syslog.log` contains eight messages naming `snapd-desktop-integration`, including `2026-11-02T14:04:49.880781Z` (`taskrunner.go:271: change 5235 task 1 done`), `14:42:40.386025Z` (`gracefully waiting for hook ...configure`), and `15:02:45.214421Z` (`refresh candidates checked`). Corresponding counts are nine on `LOG-MON-01` and eight on `FILE-LNX-01`; the latter also runs visible `smbd` file-service activity. A shared desktop-derived server image could explain this. The concern is recurring software placement across roles, not missing telemetry or an assertion that these services cannot coexist.
- [distribution_texture] Windows process creation counts have an unusual tie across several otherwise different workstations: the Sysmon files on `WS-EBROOKS-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01` each contain exactly 76 Event 1 records; `WS-MCHEN-01` has 107 and `WS-DRAMIREZ-01` has 46. The tied workstations contain different users and applications. This is a weak count artifact, without a known production reference distribution, and receives little weight by itself.
- [weak_signal] Repeated Linux service-management vocabulary sometimes targets package/client labels rather than recognizable daemon names. `APP-INT-01` records `systemctl restart cifs-utils` in both `bash_history/marcus.chen.bash_history` and its eCAR process creation (`timestamp_ms=1793634937302`, PID `3413498`); `systemctl status smb-client --no-pager` appears for `aisha.johnson` (`1793644376661`, PID `3433491`). Other nearby history commands similarly use `smbclient` as a systemd unit. These may be ordinary operator errors or locally defined units. There is no visible successful service transition proving an impossible command effect, so this does not establish a hard contradiction.

## Evidence For Real

- Windows process-create evidence agrees on substantive facts across independently shaped sources. Across all ten Windows hosts, 927 Sysmon Event 1 records had a matching Security 4688 PID, and all 927 agreed on executable path, command line, and parent executable. For example, `WS-MCHEN-01` records PID `7192` / `0x1c18`, `svchost.exe -k netsvcs -p -s BITS`, parent `services.exe` PID `5872` / `0x16f0`, at Sysmon SystemTime `13:01:29.4219996Z` and Security SystemTime `13:01:29.5058694Z`.
- Windows has real session distinctions rather than one generic user login shape. `WS-MCHEN-01` includes service logons, remote/network activity, and a paired workstation lock/unlock at `16:06:05.0024308Z` and `16:14:35.5830594Z`, session `5`, LogonID `0x6c0a30d`. Its intervening 4624 at `16:14:35.2569827Z` is Type 7, correctly interpretable as an unlock of an existing session rather than a newly created session that would invalidate earlier processes.
- Linux SSH evidence has plausible stages and durations. On `APP-INT-01`, SSH PID `3412000` sees a connection from `10.10.1.31:63228` at `15:41:52.956981Z`, public-key acceptance at `15:41:59.289680Z`, PAM session opening at `15:41:59.454093Z`, and logind session `260` at `15:42:00.026118Z`. Session close and removal occur at `16:15:00.913230Z` and `16:15:01.446048Z`.
- Linux logs include non-attack operational detail: sudo command/PAM sequences, resolver degradation and recovery, rsyslog queues, Samba open/read/close activity, scheduled sysstat work, and delayed anacron jobs. On `APP-INT-01`, anacron announces a five-minute delay at `13:24:10.994973Z`, starts `cron.daily` at `13:29:11.927842Z`, and finishes at `13:30:20.344658Z`.
- macOS evidence preserves fork and exec as different operations. `MAC-MROSS-01` PID `25527` progresses from launchd's fork at `13:07:32.811343000Z`, through exec of `xpcproxy` at `13:07:32.820534000Z`, to Terminal at `13:07:32.835499000Z`. It is one PID with successive executable images, not three unrelated process creations. Native ES and normalized eCAR preserve these distinctions.
- Binary identities are stable within the inspected evidence. No Windows executable/module path in an individual host's Sysmon Event 1/7 records had conflicting hash strings. No macOS executable device/inode pair in the ES process/fork/exec records had conflicting executable size or cdhash.

## Detailed Analysis

### Scope and method

I examined only supplied log files under the data directory. Endpoint coverage comprises 23 eCAR host files containing 37,414 records, ten Windows Security files containing 17,780 events, ten Sysmon files containing 11,606 events, eleven Linux syslog files, shell histories, and two macOS ES/Unified Log pairs. The macOS ES files contain 144 and 163 notifications respectively. The visible Windows interval is approximately `2026-11-02 13:00–19:00 UTC`.

I parsed the Windows XML and endpoint JSON, summarized event families, inspected actual records, and checked process creation/termination relationships and actor identities. I did not infer the complete audit policy, require uncollected Sysmon event types, or treat state entering or leaving the time slice as defective. Native macOS numeric fields were not judged against an assumed operating-system release; no external schema reference was consulted, so the macOS conclusions concern visible internal relationships rather than exhaustive schema certification.

### Windows process ownership and source agreement

The process trees have recognizable separation between service and user execution. On `WS-MCHEN-01`, visible parent/child pairs include explorer to PowerShell, PowerShell to OpenSSH, services to service executables, SearchIndexer to SearchProtocolHost, and svchost to taskhostw/dllhost. System processes use system/service security contexts, while interactive tools carry user LogonIDs. The server files contain service and infrastructure activity, including DFS replication, WMI, and file-service observations.

The 927 process matches were matched by the numeric PID within the same host; the observed creation PIDs did not have overlapping visible generations that would make this comparison ambiguous. Counts of matched Sysmon creates by host are: DC-01 152, DC-02 118, FILE-SRV-01 107, MAIL-FIN-01 75, WS-AJOHNSON-01 94, WS-DRAMIREZ-01 46, WS-EBROOKS-01 76, WS-MCHEN-01 107, WS-PPATEL-01 76, and WS-SMARTINEZ-01 76. No path/command/parent disagreement was found in those matches. I did not penalize the small differences in total counts between sources because selective observation is permitted and those differences did not identify a contradictory record.

For GUIDs with visible creation/termination records, no Sysmon dependent event was more than one second before creation or more than one second after termination, and no visible child creation was more than one second after its parent's visible termination. This tolerance avoids treating ordinary subsecond event observation differences as impossible causality. Comparable checks on eCAR actor UUIDs found no actor use beyond those bounds. These are targeted checks, not proof that every conceivable process relationship is valid.

The fixed-count tie of 76 process creates merits only a small texture penalty. Common background commands themselves are plausible: `WS-SMARTINEZ-01` has nine `taskhostw.exe` and five `DropboxUpdate.exe /svc` launches, while `WS-EBROOKS-01` has seven `GoogleUpdater.exe -Embedding` launches. Such repetition is expected in managed endpoints; only the repeated aggregate totals are mildly suspicious.

### Windows sessions

I explicitly distinguished successful fresh logons from Type 7 unlocks and the reserved system/service LogonIDs. Earlier processes using `WS-AJOHNSON-01` LogonID `0x254febf`, `WS-DRAMIREZ-01` `0x970e485`, and `WS-MCHEN-01` `0x6c0a30d` do not violate causality merely because their visible Type 7 events occur later. The initiating interactive sessions could precede collection.

The observed network, service, privileged, lock, unlock, and remote-interactive event mix is credible for the host set. Repeated service logons under reserved service identities are not evidence that each later 4624 created a new identity that invalidates earlier system activity. I did not find a nonreserved user process visibly starting after a matched final 4634 in the checked Security records.

### Linux processes, sessions, and operational texture

The SSH example above agrees with normalized endpoint evidence: eCAR session LOGIN has `timestamp_ms=1793634120287`, principal `marcus.chen`, tuple `10.10.1.31:63228`, LogonID `0x1528a133`, and session `260`. Its shell create at `1793634121911` is PID `3412019`, parent PID `3412000`, image `/bin/bash`, command `-bash`; session LOGOUT is `1793636101920` under the same session object identity.

Samba evidence on `FILE-LNX-01` provides a credible local lifecycle. At `13:15:00.142570Z`, `smbd` PID `2774038` connects to share `Shared` as `marcus.chen` UID/GID `4119`; subsequent audit lines open, read, and close `/srv/samba/Shared/Archive/vendor-review-approved.docx`, followed by service disconnect at `13:15:03.737407Z`.

The histories include normal troubleshooting and development commands, typographical mistakes, and role-relevant tools. For example, `WS-LNGUYEN-01` includes git, pytest, Docker Compose, editors, and resolver checks. I do not count absent child processes for shell builtins or a failed typo as collection defects. The questionable service-unit vocabulary remains only a weak indication of reusable command templates.

Linux infrastructure hosts repeatedly showing desktop-integration hooks is the more meaningful environmental concern. The visible roles do not prove that desktop software is absent, and common workstation-derived images remain a credible explanation. More host-role evidence would be required to elevate this to a contradiction.

### macOS native and normalized observations

The native ES notifications include process start times, audit tokens, pidversion, original/current parent information, signing metadata, executable stat identity, exec arguments, and process exit observations. I kept process lifetime and successive exec images separate, and did not equate audit session identifiers with eCAR LogonIDs.

The two Macs differ in terminal lineage: the first visibly uses Terminal, while the second has iTerm/iTermServer/login/zsh processes. Chrome helpers have separate PIDs and executable paths. There are corresponding SSH-related process trees and Unified Log authentication messages rather than Linux PAM/systemd lines imposed on the Mac hosts.

`MAC-MROSS-01` Unified Log at `15:42:09.009673+0000` says policy would not allow PID `42008`, `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no eCAR process record containing that application name and therefore do not infer that a denied application successfully executed. Conversely, the small Unified Log extract does not justify demanding every launchd, policy, or loginwindow message. The six combined Unified Log rows are treated as a selected export, not a claim to complete native logging.

### Alternative explanations and decision weight

The strongest positive findings are relationship-level coherence and source-native behavioral distinctions. They cannot prove production origin because a capable synthetic system could intentionally preserve them. The negative findings are low-specificity observations: shared images can explain desktop components, random counts can tie, and real administrators can address nonexistent service names.

There is no demonstrated hard contradiction in this review. I therefore keep the score within the mostly realistic band and leave the classification inconclusive rather than converting weak clues into a high-confidence synthetic verdict. Confidence is limited by the short window, unknown collection filters, and absence of a production reference distribution.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| environment_or_collection_plausibility | Linux syslog | Repeated desktop-integration activity on WEB-EXT-01, LOG-MON-01, FILE-LNX-01 | Modest concern about software placement across infrastructure roles; shared desktop-derived images remain possible. |
| distribution_texture | Windows Sysmon Event 1 | Three workstation files with exactly 76 creates each | Small texture concern; no established null distribution and no impossible event count. |
| weak_signal | Linux shell history and eCAR | APP-INT-01 commands addressing cifs-utils/smb-client/smbclient as units | Minimal weight; operator mistakes or custom units can explain the observations. |

## Realism Score by Category

- **Field format accuracy:** 8 — XML/JSON parses and substantive native fields are coherent; macOS schema fidelity was not exhaustively certified against a declared OS release.
- **Temporal patterns:** 8 — Credible session stages, scheduled delays, and no demonstrated impossible visible process lifetime; the window limits longer-term inference.
- **Cross-source correlation:** 9 — The 927 inspected Windows process matches agree on path, command, and parent, and Linux session identities remain coherent.
- **Behavioral realism:** 8 — Plausible user/service trees, development/admin commands, lock/unlock activity, and operational noise; mild repeated-count and command-vocabulary texture.
- **Environmental consistency:** 7 — Mixed-platform roles are largely credible, with recurring desktop-integration activity on apparent Linux infrastructure hosts remaining questionable.

## Recommendations

- If this were synthetic, condition recurring snapd desktop-integration activity on actual package/image membership and host role. The repeated desktop hooks on the visible web, monitoring, and Samba servers are the specific placement concern; desktop software on servers should not be categorically forbidden.
- If this were synthetic, compare workstation process-count distributions over additional independent windows. The three exactly-76 totals merit testing for a repeated count budget, but this one window does not justify changing valid records simply to avoid an accidental tie.
- If this were synthetic, distinguish package names, client utilities, and systemd unit names in routine administration commands. Keep plausible failed commands, but give recurring `cifs-utils`/`smbclient`/`smb-client` unit operations a concrete local configuration or visible outcome when representing them as successful management work.

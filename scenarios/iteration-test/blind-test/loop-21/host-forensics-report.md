# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 72

## Executive Summary

The endpoint evidence is substantially more convincing in identity, lifecycle, and cross-source consistency than in a few details of timing and Windows service placement. My strongest synthetic indicator is three groups of distinct macOS shell forks whose native event times preserve precisely the same microsecond fraction over irregular integer-second intervals, corroborated by their Mach timestamps; repeated atypical Windows service/tool representations provide additional support. I found no demonstrated impossible process lifecycle in the checks described below, so the score reflects strong distribution artifacts and repeated environmental anomalies rather than wholesale source corruption.

## Evidence For Synthetic

- [distribution_texture] In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41, and 44 describe different shell forks at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z`, and `13:50:02.198588000Z` on 2026-11-02. These create different PIDs for curl, bash, ls, and id, but all preserve the identical six-digit fraction. A second group on this host, lines 53/56/59, repeats `.487145000` at `14:37:50`, `14:38:28`, and `14:38:57`. On MAC-MROSS-02, lines 85/88/91 repeat `.965208000` at `15:30:55`, `15:31:17`, and `15:31:58`. The repeated fractions affect 10 of 62 visible zsh-originated fork notifications across the two Macs. Mach timestamps preserve the same exact integer-second intervals, making simple display rounding an inadequate explanation.
- [environment_or_collection_plausibility] All 12 visible Sysmon process creations for `MpCmdRun.exe`, spanning all 10 Windows hosts, place the image at `C:\Windows\System32\MpCmdRun.exe`, with `services.exe` as parent and the version-resource fields rendered `-`. Examples include DC-01 at `13:29:26.200`, EventRecordID `3289265`; DC-02 at `14:51:19.618`, record `1370131`; FILE-SRV-01 at `14:56:01.437`, record `1644597`; and WS-MCHEN-01 at `15:06:39.591`, record `525362`. Defender's normal installed command-line tool resides under its Defender installation/platform directories. A copied executable or a custom wrapper could explain an isolated instance, but this same placement and parentage across every Windows endpoint resembles a shared simplified process catalog.
- [environment_or_collection_plausibility] Four CryptSvc launches use `svchost.exe -k netsvcs -p -s CryptSvc` under `NT AUTHORITY\SYSTEM`, including WS-DRAMIREZ-01 at `13:20:58.138`, WS-SMARTINEZ-01 at `14:25:34.174`, WS-EBROOKS-01 at `13:49:10.013`, and DC-01 at `15:19:55.792` in their Sysmon files. Cryptographic Services ordinarily uses the NetworkService group/account. The same unusual group/account combination across client and server hosts reinforces the catalog concern, although the logs do not include service configuration, so I do not label this an impossible configuration.

## Evidence For Real

- Process identity and lifecycle relationships are internally coherent in broad automated checks. Across all Windows Sysmon files, I found no same-ProcessGuid dependent event visibly preceding its process creation or following its termination; visible parent creation/image relationships also passed the checks performed.
- Of 949 Sysmon Event 1 records, 948 have a Security 4688 counterpart with matching host, PID, and image. Small source differences are present. This is useful positive consistency evidence; complete matching itself is not a synthetic indicator.
- Hash values remain stable for repeated executions of the same image on the same host. All 4,276 algorithm/value pairs examined in Sysmon `Hashes` fields had the expected hexadecimal lengths for SHA1, SHA256, MD5, or IMPHASH.
- Windows identities are differentiated sensibly: visible domain account SIDs remain consistent across hosts; server system binaries report server-family builds (`10.0.20348.1` on the DCs and `10.0.17763.1` on FILE-SRV-01), while WS-DRAMIREZ-01 reports `10.0.19041.1` system binaries and separate application versions.
- Linux SSH records contain transport, authentication, PAM session, logind, shell, and close evidence with meaningful spacing rather than one timestamp for the whole session. Denied sudo commands examined did not also acquire matching successful command-child evidence.
- The macOS sources distinguish fork from successive exec images, including Terminal versus iTerm2 launch paths, per-exec pidversion changes, controlling terminals, audit-session identifiers, and distinct executable identities. The policy message on MAC-MROSS-01 does not visibly turn into a successful execution of the rejected application.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. The endpoint population includes 10 Windows hosts with Security/Sysmon XML, Linux endpoints and servers with syslog/eCAR and selected shell histories, and two Macs with version-11 Endpoint Security messages, Unified Log exports, normalized eCAR, and zsh history. The visible endpoint interval is approximately 2026-11-02 13:00–19:00 UTC.

I parsed the Windows XML and endpoint JSON, inspected actual process/session records, compared visible process creation, dependency, and termination relationships, checked repeated-image hashes, and reviewed Linux and macOS native examples. No repository, scenario, ground-truth, or evaluation material was consulted. Network-source coverage and missing optional audit families were not used as penalties. Records whose initiators or closers could lie outside the interval were not treated as defective merely for that reason.

### Windows process and session evidence

A useful concrete cross-source example is Chrome PID `6532` on WS-DRAMIREZ-01. Sysmon record `319984` gives `UtcTime=2026-11-02 13:11:19.281`, ProcessGuid `{5af96291-8bf7-6ae8-8600-00109f53bae5}`, parent PID `6496` / `explorer.exe`, user `MERIDIANHCS\diego.ramirez`, and LogonId `0x96cfaea`. Its Security 4688 record at `13:11:19.6579493Z` reports `NewProcessId=0x1984` and parent `0x1960`, the same image, command line, user, and logon ID. The eCAR CREATE at `13:11:19.326Z` reports the same decimal PID/PPID and command; its later TERMINATE retains the same object identity. The subsecond source offsets are plausible and do not invert the process relationship.

The population has expected differences in foreground tools: administrator workstations show SSH, PowerShell, MMC, and RDP clients; WS-DRAMIREZ-01 shows browsers, Zoom, Webex, Citrix, and a smaller amount of command-line activity. Background records include SearchIndexer children, COM hosts, task hosts, WMI providers, update-related processes, and service-host launches. Existing system-process references can legitimately precede this slice of telemetry.

Security 4624 records include 417 type-5, 394 type-3, 13 type-10, seven type-7, six type-2, and two type-9 logons. Thus unlock and noninteractive session semantics are represented. For 401 same-ID logon/logoff pairs visible in the interval, I found no negative duration: 387 type-3 pairs ranged from about 1.19 seconds to 9,644 seconds; 13 type-10 pairs ranged from about 956 to 10,419 seconds; one type-9 pair lasted about 15 seconds. Long network sessions and unmatched edges were not presumed wrong.

The repeated Defender path and CryptSvc account/group observations remain materially less convincing than these correlations. They are environmental defaults applied too broadly, not a proven claim that those processes could never execute with customized service configuration. They therefore carry less weight than the native macOS timing artifact.

### Linux authentication and command execution

DB-PROD-01 provides a coherent SSH example. In `syslog.log`, lines 12–15 show connection arrival at `13:08:57.484358Z` from `10.10.1.21:49410`, accepted password at `13:09:02.848109Z`, PAM session open at `13:09:02.915188Z`, and logind session `337` at `13:09:03.360344Z`. eCAR records the privileged sshd PID `1367366` and a user shell PID `1367385` at `13:09:03.950Z`, with `lina.nguyen`, session `337`, and LogonId `0x115fadb3`. Syslog closes this PAM session at `14:01:19.340799Z` and removes session 337 at `14:01:20.420361Z`. The shell exits earlier than its sshd owner; that gap alone is not impossible because an SSH connection can outlive a shell/channel.

Visible commands are role-aware enough to be plausible: database inspection includes mysql, psql, process listings, disk usage, query diagnostics, and mysqldump; web-server maintenance includes nginx logs and package/service inspection. Sudo commands appear as a user-owned sudo process and a root-owned child rather than simply assigning root to the original shell. WEB-EXT-01's denied tail command at `13:01:36.096882Z` and PROXY-01's denied private-key-directory listing at `13:27:50.528552Z` did not have matching successful child processes in the examined eCAR records.

Cron sysstat invocations, DHCP renewal sequences, anacron start/delay/run/exit sequences, journald, log forwarding, desktop services, and mail/file-server messages provide non-attack context. Regular cron timing is expected and is not scored as a synthetic tell. The large web-host kernel firewall population also retained increasing kernel uptime in the check performed. The presence or absence of other Linux sources was not itself scored.

### macOS process semantics and timestamp texture

On MAC-MROSS-01, the native records show launchd forking PID `25527`, then that PID execing xpcproxy and Terminal. Terminal forks login PID `25528`, which creates shell PID `25529`; zsh then creates distinct command children. MAC-MROSS-02 instead includes iTerm2, its iTermServer helper, login/ShellLauncher, and zsh. I treated a forked child's inherited image and a later executable replacement as different stages of one process lifetime, not as contradictory duplicate creations.

Audit UID `501`, root effective UID during login, audit-session identifiers such as `100002`/`100003`, and POSIX process-session identifiers are separate fields. Their numerical differences were not scored. A non-PTY remote shell on MAC-MROSS-02 need not have the terminal device shown by MAC-MROSS-01's `ssh -tt` session.

The strongest concern is the native fork timing described above. For example, MAC-MROSS-01's four successive fork Mach values are `24953308766112`, `24953956766112`, `24954796766112`, and `24955252766112`; their differences preserve precisely 27, 35, and 19 seconds at the apparent 24-million-tick-per-second scale. The corresponding exec events add distinct millisecond-scale offsets, making the exact fork phases especially conspicuous. A script can schedule commands, and exports can transform timestamps, but repeated exact phases across separate command bursts on both hosts are much more consistent with event planning than ordinary native scheduling. This is a distribution finding, not an assertion of impossible OS behavior.

MAC-MROSS-01's Unified Log at `15:42:09.009673+0000` says `ASP: Security policy would not allow process: 42008, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I did not infer a successful launch from a policy notification: no matching successful native exec for PID 42008 was visible in the inspected ES export. Sparse Unified Log output was not penalized because the collection can be filtered.

### Weighting and limits

The verdict rests chiefly on a measurable precision pattern, with repeated Windows service/tool placement as independent supporting evidence. Strong lifecycle/correlation performance lowers the score; there is no justified 90-plus claim of widespread impossible telemetry. A documented timestamp-reconstruction procedure and custom Windows service configuration could explain part of the result, which is why verdict confidence is 86 rather than certainty.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | macOS Endpoint Security native fork notifications | Three repeated fractional-time groups; 10 of 62 zsh-originated forks across two hosts | Highest weight: exact microsecond phase retention and matching Mach intervals across independent command starts |
| environment_or_collection_plausibility | Windows Sysmon process creation, corroborating eCAR/Security | 12 MpCmdRun launches on all 10 Windows hosts | Moderate weight: universal System32 placement, direct services.exe parentage, and absent version resources suggest a simplified shared tool representation |
| environment_or_collection_plausibility | Windows Sysmon service-host launches | Four CryptSvc launches on four hosts | Supporting weight: repeated atypical netsvcs/SYSTEM combination; custom configuration remains possible |

## Realism Score by Category

- **Field format accuracy:** 8 — XML/JSON structures, PID encodings, hash lengths, and platform-specific process fields are largely credible.
- **Temporal patterns:** 6 — Lifecycles are ordered sensibly, but exact native fork phases recur across three command groups.
- **Cross-source correlation:** 9 — Process identities, users, images, session IDs, and source offsets agree well in the checks performed.
- **Behavioral realism:** 8 — Role-specific applications, administrative commands, denials, unlocks, and background activity are represented plausibly.
- **Environmental consistency:** 6 — Platform/build differentiation is good, while repeated Windows service/tool placement is difficult to reconcile with ordinary defaults.

## Recommendations

- If this were synthetic, generate each macOS fork's native time from an execution/scheduling model with actual subsecond variation. Preserve the coherent relationship between wall time and Mach time; avoid merely adding cosmetic noise to one representation.
- If this were synthetic, represent Defender's installed executable identity and normal launch mechanism for the modeled host. The visible System32 copy should be an explicitly modeled exceptional deployment rather than a universal background default.
- If this were synthetic, select service group and account together for the host/version, particularly CryptSvc. Keep any deliberate custom service configuration coherent across command lines and process ownership.
- Preserve the existing process identity, cross-source PID/logon correlation, native fork/exec separation, denied-command behavior, and slice-of-time lifecycle handling. These are strengths, and adding arbitrary unmatched records would not improve them.

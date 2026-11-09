# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 67

## Executive Summary

The endpoint evidence is generally coherent, with stable process identities, plausible Windows session types, Linux SSH sequencing, and unusually detailed macOS fork/exec lifetimes. My principal concern is application lifecycle behavior: repeated ordinary Chrome window launches become concurrent, long-lived browser-root processes, most clearly on MAC-MROSS-01 and also on Windows endpoints. This repeated application-state inconsistency, with a weaker pattern of artificial-looking document-access commands, favors synthetic data without establishing an unequivocal native-schema contradiction.

## Evidence For Synthetic

- [contract_gap] On `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, seven distinct Chrome browser-root processes run under UID/audit UID 501 and ASID 100001. Their exec records are lines 19, 73, 108, 115, 134, 149, and 158; their eventual exits are lines 199, 197, 196, 195, 194, 193, and 192, respectively. The later invocations use `--new-window` with a URL, have the same executable and `HOME=/Users/maya.ross`, and show no distinct user-data-directory argument or environment override. Each remains alive until approximately 18:54:59, rather than behaving as a short-lived request to an existing browser. Several also spawn fresh helper subtrees. The logs therefore depict seven overlapping browser instances for ordinary window-opening activity. A hidden profile arrangement could qualify the interpretation, so this is scored as an application lifecycle gap, not an impossible kernel event.
- [contract_gap] The same concern appears in Windows Sysmon. `WS-DRAMIREZ-01.meridianhcs.local/windows_event_sysmon.xml` records browser roots PID 6548 at 13:16:48.408 and PID 6544 at 13:33:25.672, with the first explicitly surviving to 14:17:35.589 (`UtcTime` lines 446, 1480, and 3063). Both are the same Chrome executable and `MERIDIANHCS\diego.ramirez`; their arguments open mail URLs without distinguishing user-data directories. The first process's visible termination after the second creation establishes overlap independently of the second process's eventual exit.
- [distribution_texture] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` repeatedly represents access to PDF, DOCX, and XLSX documents as terminal `/bin/cat` executions: lines 32, 105, 115, 118, 146, 152, 158, and 161. All eight complete successfully and last 11.98–23.34 seconds. Examples include `cat .../service-review.xlsx` at 16:05:46.523742 and `cat .../onboarding.docx` at 17:12:27.405663. This is possible, especially with terminal output or unusual file sizes, but the repeated choice of a raw byte-dumping tool and similar dwell times across distinct office-document formats gives document access a templated behavioral texture. It is a secondary indicator with limited weight.

## Evidence For Real

- Windows background activity has recognizable process ownership: on WS-MCHEN-01, Sysmon records `dllhost.exe /Processid:{73E709EA-5D93-4B2E-BBB0-99B7938DA9E4}` under the DcomLaunch `svchost.exe`, PID 6808, at 13:05:29.166, followed by termination at 13:05:49.310. Security 4688/4689 agree on PID `0x1a98`, executable, and SYSTEM context.
- Across all ten supplied Windows Sysmon exports, the 942 Event 1 process creations preserve a single hash set per same-host `(Image, FileVersion)` pair. I found no same-ProcessGuid Sysmon activity occurring before its visible creation or after its visible termination in the checked ProcessGuid/SourceProcessGUID relationships.
- The macOS records distinguish a process lifetime from changing executable images. MAC-MROSS-01 lines 1–7 show launchd fork, xpcproxy exec, Terminal exec, a login child, and a zsh child; PID versions change across exec while the relevant process start times remain stable. MAC-MROSS-02 lines 1–10 use a different, iTerm-specific server/login/ShellLauncher sequence.
- Linux SSH evidence has believable connection/authentication/session phases. `APP-INT-01.../syslog.log` lines 71–73 show connection from `10.10.1.42:55789` at 14:19:33.653286, accepted public key at 14:19:42.573597, then PAM session open at 14:19:42.751659. Line 90 closes that session at 15:00:42.325034; matching eCAR USER_SESSION records identify the same source tuple and session.
- Windows collection includes network, service, interactive, remote-interactive, NewCredentials, and unlock logons where appropriate. WS-MCHEN-01 has Types 2, 3, 5, 7, and 9; WS-AJOHNSON-01 also has Type 10. Visible lock/unlock records and varied process durations provide useful everyday endpoint texture.

## Detailed Analysis

### Scope, provenance, and method

I read the supplied neutral briefing and examined files only under `/private/tmp/log-study-sucvw85x/data`, using system Python with an explicit neutral working directory. I did not inspect project code, scenario material, project memory files, or prior assessments. I additionally consulted official upstream Chromium source for browser-instance semantics; inherited generic operating context was not used as authenticity evidence.

The eCAR slice contains 36,352 records from 13:00:00.299 through 18:59:53.650 UTC on 2026-11-02. I parsed all ten Windows Security/Sysmon pairs and all endpoint eCAR files for counts and selected identity/lifecycle checks, and inspected both macOS Endpoint Security exports plus Linux syslog/history examples. This is an endpoint-focused assessment, not a comprehensive network-protocol audit.

I treated pre-window processes, post-window survivors, source selection, and differing source timestamps as neutral unless they produced an explicit inconsistency. In particular, SYSTEM's well-known logon ID `0x3e7` and Type 7 unlocks cannot be interpreted as fresh unique session births for simple before-logon tests.

### Browser process state is the highest-impact finding

The macOS case is stronger than a simple excess count. MAC-MROSS-01 explicitly observes both creation and termination of each browser root:

| PID | Chrome exec line | Exec time UTC | Exit line | Exit time UTC |
|---|---:|---|---:|---|
| 42887 | 19 | 13:14:17.567601 | 199 | 18:54:59.855585 |
| 62371 | 73 | 15:40:47.095499 | 197 | 18:54:59.541462 |
| 68389 | 108 | 16:44:48.537020 | 196 | 18:54:59.325110 |
| 68443 | 115 | 16:45:27.191599 | 195 | 18:54:59.157626 |
| 73015 | 134 | 17:30:10.044401 | 194 | 18:54:59.037820 |
| 76081 | 149 | 17:58:35.119211 | 193 | 18:54:58.833171 |
| 76099 | 158 | 17:58:46.029634 | 192 | 18:54:58.724968 |

All are the browser executable itself, not helper processes with renderer/GPU/utility arguments. For example, lines 108 and 115 launch the same application as maya.ross only 38.65 seconds apart, with `--new-window` for wiki and Jira URLs. The original browser remains alive. Additional helpers are attached to these new roots, including lines 110–112 and 117–121.

Chromium's [ProcessSingleton contract](https://chromium.googlesource.com/chromium/src/%2B/master/chrome/browser/process_singleton.h) scopes the browser instance to its user-data directory, and its [startup handling](https://chromium.googlesource.com/chromium/src/%2B/refs/heads/main/chrome/app/chrome_main_delegate.cc) exits a new invocation after notifying an existing instance. My inference is that these records repeatedly turn a window-opening action into an independent persistent browser instance. The repeated Windows examples strengthen this interpretation. The telemetry does not explicitly expose resolved browser profile directories, which prevents treating it as an unconditional hard contradiction.

### Native process and session coherence

The basic lifecycle model is substantially better than the application behavior above. Across eCAR files, checks of visible process object identity found no PROCESS MODIFY/OPEN-like activity after that object's recorded termination or before its recorded creation; checked non-process actor references also respected visible process bounds. I found no overlapping eCAR CREATE lifetimes reusing one PID without an intervening matching termination.

Windows Sysmon preserves source/target process GUIDs for access events and consistent binary hash sets within the visible image/version groups. These checks establish useful internal consistency; they do not prove hashes are hashes of actual production binaries, because no executable bytes are supplied.

Linux SSH records are not just isolated successful-logon messages. APP-INT-01's example above keeps connection, accepted-key, PAM open, and eventual close under sshd PID 2944229. eCAR lines 146 and 203 preserve source `10.10.1.42:55789` and USER_SESSION object `6db19844-c174-4000-9b4a-df1b0b56b70b`. Their timestamp differences from syslog are small enough to be plausible independent source observation rather than a semantic contradiction.

### macOS interpretation and limits

The two Mac exports have 200 and 174 Endpoint Security notifications respectively. Both use message version 11 and typed numeric fork/exec/exit observations. Their executable stat identities and cdhashes remain consistent for the same path within each supplied host. I did not equate an exec image change with a second process lifetime or confuse POSIX session ID with audit session ID.

MAC-MROSS-01 Unified Log line 2, at 15:41:55.909819, says `ASP: Security policy would not allow process: 62474, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I found no corresponding successful MeetingAssist exec in the supplied ES sequence, so I did not infer successful child execution or command effects from that policy message. Thin Unified Log coverage alone was not penalized.

The repeated document `cat` executions on MAC-MROSS-02 are a behavioral distribution concern, not an invalid syscall or an impossible filesystem access. Successful raw reads of Office documents can happen. Their score contribution is deliberately smaller than the browser-instance finding.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| contract_gap | macOS Endpoint Security | Seven overlapping same-user Chrome roots on MAC-MROSS-01, all visibly terminated later | Main reason for a likely-synthetic score; ordinary new-window commands appear to create persistent independent browser instances |
| contract_gap | Windows Sysmon | Explicit overlapping Chrome lifetimes on WS-DRAMIREZ-01 | Repetition across platforms makes an isolated application quirk less convincing; not counted as a separate impossible-ordering defect |
| distribution_texture | macOS Endpoint Security | Eight successful 11.98–23.34-second `cat` reads of PDF/DOCX/XLSX on MAC-MROSS-02 | Limited secondary weight for repetitive document-access behavior |

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native exports and normalized records are coherent; no demonstrated native-schema error was established.
- **Temporal patterns:** 8 — Varied timings and coherent visible lifetimes; several routine document-read durations have repetitive texture.
- **Cross-source correlation:** 9 — Checked Windows process and Linux SSH examples agree in identity and semantics, allowing plausible source latency.
- **Behavioral realism:** 5 — Persistent duplicate browser roots and repeated raw Office-document reads weaken otherwise recognizable endpoint activity.
- **Environmental consistency:** 8 — Platform-specific session/process structures and role-appropriate service activity are credible; browser instance state is the material exception.

## Recommendations

- If this were synthetic, retain browser state per host, user, and resolved user-data directory. Route additional URLs/windows to the existing browser; represent any temporary invocation as short lived. Only create a second persistent browser root when a distinct profile directory or other concrete isolation mechanism supports it.
- If this were synthetic, vary document-access behavior by the actual tool used. Preserve `/bin/cat` for intentional raw reads, but use application-owned document access when the activity is an Office/PDF viewing workflow, and base process duration on the visible operation rather than applying similar dwell times to every document format.
- Preserve the existing distinctions among fork, exec, process lifetime, audit session, authentication, and policy observation. The visible checks do not justify adding arbitrary sources or filling every pre-window/post-window lifecycle gap.

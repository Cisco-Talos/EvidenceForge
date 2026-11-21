# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 80
**Synthetic-Confidence Score:** 64

## Executive Summary

The endpoint telemetry is substantially production-like: process identities, hashes, parentage, and most session lifecycles withstand direct checks across Windows, Linux, and macOS. The strongest contrary evidence is a repeated Windows lock/unlock timing defect on two workstations: submillisecond lock intervals appear several minutes after independently represented unlock authentication for the same session. This supports a likely-synthetic verdict, but the absence of broader demonstrated contradictions limits the score and confidence.

## Evidence For Synthetic

- [contract_gap] In `WS-AJOHNSON-01.meridianhcs.local/windows_event_security.xml`, record **130239**, Event **4800**, locks session **2**, LUID **0x2584fde**, at **2026-11-02T14:24:58.0206366Z**. Record **130240**, Event **4801**, unlocks that same session at **14:24:58.0209546Z**: only **318 microseconds** later. Its visible Type **7** unlock authentication, Event 4624 record **130199**, is instead at **14:15:51.0240344Z**. The eCAR `USER_SESSION/LOGIN` with `logon_type=7`, the same LUID and session 2, is likewise at **14:15:50.989Z**. The very short lock interval and the roughly nine-minute separation from the represented authentication jointly suggest a timestamp/lifecycle construction problem.
- [contract_gap] The same pattern recurs in `WS-MCHEN-01.meridianhcs.local/windows_event_security.xml`: Event **4800** record **949724**, session **5**, LUID **0x6d0365e**, occurs at **17:43:19.5680623Z**; Event **4801** record **949725** occurs at **17:43:19.5690180Z**, **955.7 microseconds** later. Type 7 Event 4624 record **949697** is at **17:38:34.7475392Z**, and the corresponding eCAR login is at **17:38:34.733Z**. Both examples fall well inside the collection window and repeat across different users and hosts. I treat them as one recurring defect family, not two independent classes of failure.
- [weak_signal] `MAC-MROSS-02.meridianhcs.local/macos_endpoint_security.ndjson` repeatedly shows `/bin/cat` invoked directly against binary office documents: `project-plan.pdf` at **13:37:11.223221Z**, `service-review.xlsx` at **16:05:48.670374Z**, `project-plan.docx` at **17:10:43.520711Z**, `onboarding.docx` at **17:12:27.399937Z**, `draft-draft.pdf` at **18:37:47.001397Z**, and further DOCX documents at **18:42:07.534517Z** and **18:44:51.350352Z**. This repeated command-to-file-type pairing looks more like generic file-access behavior than ordinary document consumption. It is executable and could reflect inspection or adversarial activity, so it receives little weight and is not a hard contradiction.

## Evidence For Real

- Process identities are internally stable. Across the ten Windows Sysmon exports, I found no `ProcessGuid` associated with conflicting PID/image pairs. Repeated process creations at the same host/image path retained the same hash set; I found no within-host executable-path hash variation in the observed Event 1 records.
- Visible Windows process dependencies were coherent in the checks performed. Sysmon parent creations did not occur after their children, and no checked dependent event occurred more than one second after its same-GUID termination. Security 5156 records likewise did not identify a checked PID more than one second before its visible creation or after its visible termination.
- Windows activity contains meaningful session variation rather than a single logon shape. For example, WS-AJOHNSON has interactive, network, service, unlock, remote-interactive, and new-credentials logons; WS-MCHEN retains a session LUID across multiple Type 7 unlocks. Several lock intervals are sensible: approximately **420 seconds** on WS-AJOHNSON and **804** and **840 seconds** on WS-MCHEN.
- The Outlook launch on WS-AJOHNSON at **13:10:12** agrees across Security 4688 and Sysmon 1: PID **5380 / 0x1504**, explorer parent PID **5188 / 0x1444**, user `aisha.johnson`, and LUID **0x2584fde**. Subsequent source-local module and DNS observations retain that process identity.
- Linux SSH sequencing is credible. On DB-PROD, the connection from **10.10.1.41:63409** is logged at **13:14:10.227094Z**, public-key acceptance at **13:14:16.045098Z**, PAM session opening at **13:14:16.198815Z**, and logind session **255** creation at **13:14:16.780034Z**.
- macOS evidence distinguishes fork from exec and preserves process lifetime across successive executable images. MAC-MROSS-01 PID **42154** progresses from inherited launchd image to xpcproxy to Terminal, with pidversion changes, instead of inventing three unrelated process lifetimes. eCAR represents the same sequence as CREATE followed by MODIFY operations.
- Linux source texture differs by host role: Postfix/Dovecot activity on mail systems, Samba audit activity on FILE-LNX, desktop/network-management activity on Linux workstations, and database/storage-related messages on DB-PROD. Regular ten-minute sysstat jobs have an operational explanation and are not authenticity defects.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory and the assigned briefing. The review parsed **19,405 Security events**, **12,197 Sysmon events**, and **39,336 eCAR records** across the available endpoint files, then examined representative native records and shell histories. Both macOS Endpoint Security streams were parsed in full: **144** records on MAC-MROSS-01 and **175** on MAC-MROSS-02. Linux syslogs and histories were reviewed for source shape, activity vocabulary, and representative SSH/session sequences.

The visible period is approximately six hours on November 2, 2026. I did not penalize processes or sessions whose initiation or termination could lie outside that period. Missing selected Sysmon event families, export filesystem timestamps, sanitized domain names, and the completeness of matching telemetry did not influence the synthetic score. I used no outside source documentation; consequently, unfamiliar macOS schema details were not elevated into native-format findings.

### Windows process and identity integrity

The process checks were keyed to GUID where available rather than simply to executable name. A parent missing from the visible creation records was treated as potentially pre-existing. For Security-only PID checks, I compared visible creation and termination records with the network-authorization observations, using a one-second tolerance to avoid classifying small provider timing differences as causality violations.

For the WS-AJOHNSON Outlook example, Sysmon record **30335** has `UtcTime=2026-11-02 13:10:12.683`, `ProcessGuid={fd907e59-8bb4-6ae8-ca00-0010a8566e55}`, PID **5380**, and parent explorer PID **5188**. Security record **129983** reports the corresponding creation at **13:10:12.7798468Z**. The second visible Outlook instance at **16:01:27.728** has a new PID/GUID and a different owning session, while retaining the original instance's SHA256 **0F09C44EDF1F18371575BC93FD79AD83646AE879E03C7F93495F33238AE11968**. These are convincing identity relationships; they do not independently establish real provenance.

Windows process timing also has a long tail: the checked system processes include lifetimes of seconds, minutes, and hours. The observed service/WMI/task-host vocabulary is repetitive, but repetition alone is expected for these processes and was not scored as a separate defect.

### Windows lock and unlock timing

The two submillisecond pairs are the main score driver. They are source-native `TimeCreated/SystemTime` values, not file modification times or differences between collectors. Each pair has consecutive Security record IDs and explicitly matches both LUID and terminal session ID. Their timing is sharply different from the other visible lock intervals.

For WS-AJOHNSON, the earlier Type 7 authentication and eCAR unlock representation agree within approximately **35 milliseconds**, whereas the 4800/4801 pair appears about **547 seconds** later. On WS-MCHEN, authentication and eCAR agree within approximately **15 milliseconds**, whereas the pair appears about **285 seconds** later. This is a repeated mismatch between the represented authentication moment and lock-state lifecycle, beyond simply having comprehensive coverage.

A programmatically cancelled lock or unusual logging behavior could theoretically produce a very short pair. The supplied records do not prove that every Type 7 event must be paired one-to-one with a particular 4801, and I do not call either example a mathematically impossible event sequence. The combination of two nearly collapsed pairs, their multi-minute displacement, and normal-duration pairs elsewhere is nevertheless a substantive authenticity concern. I classify it as a contract gap rather than a hard contradiction.

### Linux sessions, histories, and background activity

The DB-PROD SSH example uses one daemon PID **1044792** for the connection, authentication, and PAM opening messages. The separate long-lived logind PID is consistent with its role. A second session for `marcus.chen` from **10.10.1.31:62497** repeats the appropriate ordering at **13:29:29–13:29:36**, using a different child daemon PID and session number.

Histories include commands relevant to the visible roles, command pipelines, background jobs, and occasional mistypes such as `sss`, `pd`, and `kl`. These details support believable command texture but are easy to reproduce and were given modest positive weight. I did not interpret successful command invocation as proof that a command's intended state change succeeded.

### macOS process semantics and collection limits

The two native streams expose notification records with declared message `version=11`, audit tokens, executable file identities, and fork/exec/exit payloads. MAC-MROSS-01 contains **46 forks, 53 execs, and 45 exits**; MAC-MROSS-02 contains **55 forks, 66 execs, and 54 exits**. More execs than forks is expected when a process changes executable image multiple times. I found no conflicting executable identities for the same observed PID/pidversion pair, nor conflicting path/size/mode tuples for the same observed device/inode combination in these streams.

The Terminal chain on MAC-MROSS-01 and the distinct iTerm/login/ShellLauncher chain on MAC-MROSS-02 show attention to platform-specific behavior. The remote SSH records use macOS daemon paths and audit/session concepts; I did not demand Linux PAM or systemd evidence on these hosts.

MAC-MROSS-01's Unified Log includes **15:42:09.009673Z**, kernel message `ASP: Security policy would not allow process: 62500, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I did not find a successful native execution of that named application in the supplied Endpoint Security stream. Therefore this policy message does not establish a denied-execution/child-effects contradiction. Similarly, plist creation/removal records alone were not treated as proof of activation or unload.

The repeated raw reads of PDF/DOCX/XLSX documents on MAC-MROSS-02 are the main macOS behavioral reservation. They are possible operations, and the absence of those commands from a particular shell-history export is not proof of inconsistency. Their weight is much lower than the Windows timing defect.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Windows Security, corroborating eCAR authentication times | Two workstations; two lock/unlock pairs with 318 µs and 955.7 µs intervals, minutes after represented unlock authentication | Primary reason for crossing into likely synthetic; one repeated defect family, not an impossible-ordering claim |
| `weak_signal` | macOS Endpoint Security and eCAR file/process observations | MAC-MROSS-02; seven explicit raw reads of binary office-document paths | Small upward adjustment for repeated command/file-type mismatch; plausible alternative explanations remain |

No demonstrated generator identity leak, impossible PID/GUID ownership, or decisive native-schema contradiction was found. The strong identity and lifecycle consistency keeps the score well below the 81–100 band.

## Realism Score by Category

- **Field format accuracy:** 9 — Parsed native and normalized records have credible field shapes; no demonstrated native-schema defect.
- **Temporal patterns:** 6 — Most process timing is coherent, but the two collapsed lock/unlock pairs materially weaken session timing realism.
- **Cross-source correlation:** 8 — Process/session identities align well; authentication timing and lock-state timing diverge in the identified cases.
- **Behavioral realism:** 8 — Role-specific tools and background activity are credible; repeated raw office-document reads are an unusual, limited pattern.
- **Environmental consistency:** 9 — Platform-specific process chains and host-role source texture are generally convincing.

## Recommendations

- If this were synthetic, preserve the actual lock interval and authentication-to-unlock relationship when producing Security 4800, 4801, 4624 Type 7, and normalized session observations. Specifically address the WS-AJOHNSON and WS-MCHEN pairs cited above, while retaining realistic variation in the normal intervals already present.
- If this were synthetic, tie document-access commands to the intended activity. Repeatedly using `/bin/cat` on DOCX/XLSX/PDF files should reflect an explicit inspection, content-processing, or adversarial purpose; ordinary document consumption should have appropriate application/process behavior. Do not invent unsuccessful outcomes for the existing successful process observations solely to add noise.
- Preserve the existing process GUID/hash consistency, visible parent/child ordering, fork-versus-exec distinction, platform-specific SSH behavior, and justified slice-of-time boundaries. Additional coverage or arbitrary errors are not needed to correct the demonstrated issues.

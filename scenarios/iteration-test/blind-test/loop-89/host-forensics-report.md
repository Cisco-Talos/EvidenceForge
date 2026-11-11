# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 34

## Executive Summary

The endpoint collection is mostly production-like: Windows process identities agree across Security, Sysmon and eCAR, and representative Linux/macOS remote sessions preserve credible transport, authentication, shell and close relationships. A small amount of repetitive diagnostic activity and unusual shell-based access to binary documents raises a mild behavioral concern, but I did not establish a hard contradiction or a required cross-source companion gap; the records alone do not justify confidently assigning real or synthetic provenance.

## Evidence For Synthetic

- [weak_signal] On `MAC-MROSS-02.meridianhcs.local`, seven of the 64 visible Endpoint Security exec notifications execute `/bin/cat` against `.xlsx`, `.docx` or `.pdf` paths on `/Volumes`. Examples are PID 45873 at `2026-11-02T16:05:43.050283Z` reading `service-review.xlsx`, PID 52106 at `17:10:43.522337Z` reading `project-plan.docx`, and PID 65765 at `18:56:44.867290Z` reading `onboarding-approved.xlsx`. The repeated choice of a terminal byte-stream utility for office-document access is unusual user behavior and resembles a simplified file-access model. It remains possible for real scripts or a user to do this; it is not an impossible process tree or proof that the files have the contents implied by their extensions.
- [weak_signal] The two Macs' visible interactive histories concentrate on a small diagnostic vocabulary. `MAC-MROSS-01/.../zsh_history/maya.ross.zsh_history` has 24 entries, of which four invoke SSH and 20 use commands such as `id`, `sw_vers`, `uname`, `pwd`, `ls`, `du`, `df`, `ps`, `find`, `ifconfig` and `dscl`; `MAC-MROSS-02` has 19 entries, of which two invoke SSH and 17 use that diagnostic vocabulary. This repeated texture is a minor concern, discounted substantially because both histories belong to the same user, include separate local/remote activity, and need not represent all application use. Neither history completeness nor a compact narrative contributes to the score.

## Evidence For Real

- Across ten Windows hosts, 912 of 913 Sysmon Event 1 rows join to Security 4688 on host, numeric PID and executable path. Every joined pair agrees on numeric parent PID and command line. The single unjoined row is a `DC-02` taskhostw creation, and is not sufficient to allege a collection defect.
- Exact Sysmon ProcessGUID joins preserve image and PID across the visible event families; visible parent ProcessGUIDs agree with child records' parent PID/image. Per-host Event 1 records do not assign competing hash strings to the same executable path.
- `WS-MCHEN-01` PID 7208 is consistently `taskhostw.exe`, parent PID 5904 (`svchost.exe`), in Sysmon, Security and eCAR, with small source-dependent timestamp differences rather than a forced identical timestamp.
- Linux `APP-INT-01` SSH session 431 joins source `10.10.1.41:49804`, sshd PID 2968957, user `maya.ross`, shell PID 2968984 and eCAR LogonID `0x152b7b2c`. Connection evidence precedes accepted authentication and the shell, and visible session close evidence agrees in timing with the source client's exit.
- macOS distinguishes fork from exec. On `MAC-MROSS-01`, PID 41136 retains its lifetime while changing executable from launchd to xpcproxy to Chrome, with advancing pidversion values; it is not falsely represented as three independent process creations.
- The macOS remote session from `10.10.1.42:60818` to `10.10.1.41:22` has a matching Zeek transport, Unified Log public-key authentication, native sshd/session/shell evidence and normalized eCAR session identity. Windows PAM/systemd expectations were not applied to these Macs.
- Background activity differs by platform and host role: Linux workstation records contain desktop and printing components, `MAIL-CLIN-01` has Postfix/Dovecot messages, and `DB-PROD-01` has multipath activity. Windows hosts expose service, network, interactive, remote-interactive, new-credentials and unlock logon types according to the host.

## Detailed Analysis

### Scope and method

I inspected only the supplied data directory and the assigned briefing. I parsed all 39,270 eCAR rows across 23 endpoints, including 2,630 PROCESS/CREATE rows; all 19,224 Windows Security events and 12,086 Sysmon events across ten Windows endpoints; and both Macs' 310 Endpoint Security notifications. I also read representative Linux syslog/history records, both Mac histories and Unified Log exports, and exact Zeek connections needed for endpoint joins. XML parsed successfully, as did the JSON/NDJSON used in these checks.

The collection is approximately `2026-11-02 13:00–19:00 UTC`. I did not treat a logout or termination near the beginning without a visible initiation as defective, nor require a closing record for a process that could remain alive after the end. This is a bounded collection, not a complete disk image or an assurance that every provider/event type was subscribed.

The eCAR lifetime check looked for use of an exact actor object identity more than two seconds after that object's visible PROCESS/TERMINATE, allowing small observation-time differences. None was found. This is a bounded consistency result, not proof that every dependency or event family is complete.

### Windows process and source identity

The per-host Sysmon 1 to Security 4688 join counts were: DC-01 144/144; DC-02 118/119; FILE-SRV-01 96/96; MAIL-FIN-01 85/85; WS-AJOHNSON-01 109/109; WS-DRAMIREZ-01 60/60; WS-EBROOKS-01 54/54; WS-MCHEN-01 94/94; WS-PPATEL-01 76/76; WS-SMARTINEZ-01 76/76. These joins compare actual source fields, including hexadecimal Security PID decoding. I found zero parent-PID or command-line disagreements in the 912 joined pairs.

For a concrete three-source example, `WS-MCHEN-01/windows_event_sysmon.xml` records Event 1 with `UtcTime=2026-11-02 13:02:42.477`, ProcessGUID `{7b2a0e3f-89f2-6ae8-5c02-0000d8538e2e}`, PID 7208, image `C:\Windows\System32\taskhostw.exe`, parent PID 5904 and parent command `svchost.exe -k LocalSystem`. Security 4688 at `13:02:42.6189107Z` has `NewProcessId=0x1c28` (7208), `ProcessId=0x1710` (5904), the same command and paths, SYSTEM subject and `SubjectLogonId=0x3e7`. eCAR CREATE at `13:02:42.585Z` has the same PID, PPID, image, command and system logon ID under object `9469aeb0-f350-4f4c-8c1c-9ffb5b224b62`; that object terminates at `13:02:48.870Z`.

The unmatched DC-02 row is PID 9064, `taskhostw.exe`, `UtcTime=18:52:54.290`, ProcessGUID `{d55311aa-dc06-6ae8-7302-0000ce77bac3}`. An isolated source-only row is compatible with collection differences, so I did not score it as a missing-companion defect. Similarly, I did not use absent Sysmon event types as evidence.

Visible process trees include svchost children for taskhostw/dllhost/WmiPrvSE, services.exe children, and user explorer/cmd/PowerShell/SSH relationships. The presence of recurring Windows service trees and consistent hashes supports mechanical coherence; it does not independently authenticate provenance.

### Sessions and Linux evidence

Windows logon distributions differ meaningfully by role. DC-01 has 282 visible 4624 records: 120 type 5, 159 type 3 and three type 10. WS-MCHEN-01 has 14: seven type 5, one type 2, three type 9, two type 7 and one type 3. These include unlock and new-credentials behavior instead of reducing every login to an interactive workstation session. Long-running service sessions and pre-window user sessions make simple login/logout count equality inappropriate.

On APP-INT-01, eCAR inbound TCP/22 FLOW for `10.10.1.41:49804 → 10.10.2.30:22` occurs at `16:04:59.019Z`; sshd process 2968957 is observed at `16:04:59.321Z`. Syslog reports the same tuple at `16:05:01.293706Z`, accepted password at `16:05:09.103529Z`, PAM open at `16:05:09.160897Z` for `maya.ross(uid=2176)`, and logind session 431 at `16:05:09.604496Z`. eCAR session LOGIN at `16:05:10.102Z` uses LogonID `0x152b7b2c`; its shell PID 2968984 is created at `16:05:12.180Z`, parent 2968957.

At close, syslog PAM closes at `17:01:15.797028Z`, logind removes session 431 at `17:01:16.825730Z`, eCAR logs out the exact session object at `17:01:18.478Z`, and sshd terminates at `17:01:20.947Z`. On MAC-MROSS-01, the corresponding SSH client PID 64629 exits in Endpoint Security at `17:01:15.983196Z`. These are compatible observations with source timing differences.

The repeated sysstat schedule is not scored as synthetic uniformity: APP-INT-01, WS-LNGUYEN-01, WS-OHADDAD-01 and other Linux hosts each show the recognizable cron command `command -v debian-sa1 > /dev/null && debian-sa1 1 1`. Thirty-six executions across six hours are compatible with an intentionally periodic ten-minute task, and associated shell/child process evidence exists.

### macOS process, audit and collection semantics

Both native Endpoint Security exports declare message `version=11` and `schema_version=1`. I treated these separately from Unified Log and eCAR. On MAC-MROSS-01, native rows 1–4 show fork at `13:00:06.950823Z`, exec of PID 41136 to xpcproxy at `13:00:06.953308Z`, exec to Chrome at `13:00:06.958279Z`, and exit at `13:00:29.844683Z`. pidversion advances 12→13→14 while start_time stays attached to the same process lifetime. eCAR represents this as one CREATE and subsequent MODIFY operations. UID/audit-session changes and a responsible process are separate fields; I did not confuse an audit session number with an eCAR logon ID.

For remote access to MAC-MROSS-01, Zeek core UID `CJ8g4a0Jhtlp08PBgV` records `10.10.1.42:60818 → 10.10.1.41:22`, start epoch `1793635287.497884` (`16:01:27.497884Z`), duration `992.087432` seconds, `service=ssh` and `conn_state=SF`. Native ES then records launch/exec activity for sshd-session PID 64322, and Unified Log at `16:01:33.543134+0000` reports accepted public key for maya.ross from the exact source tuple. The shell becomes PID 64327 `/bin/zsh` at `16:01:33.708041Z`. eCAR binds that activity to SSH logon `0x894616f`. The transport close is around `16:17:59.585316Z`, compatible with native shell exit `16:17:59.738651Z` and parent close evidence shortly afterward. Tiny cross-source differences are not impossible ordering.

MAC-MROSS-01 Unified Log also contains an AppleSystemPolicy message at `15:41:38.735570+0000`: `Security policy would not allow process: 62451, /Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist`. I did not find an accompanying successful native exec for PID 62451 and therefore did not infer a successful denied application's effects or manufacture a policy contradiction.

The inventory plist CREATE/DELETE rows in eCAR establish file operations, not automatic launchd registration, job unload or execution. A native inventory process after plist creation is consistent with deployment, but file deletion alone would not prove an active job stopped. Native files retain coherent device/inode/path/size combinations in the examined records; no competing paths for an identical device/inode or future process start timestamps were found.

### Weight of behavioral concerns

The seven binary-document `cat` launches are the clearest remaining oddity, but they affect one user on one Mac and could arise from automation. The diagnostic command pools are also shared by the same user and are therefore much weaker than unrelated actors repeating identical tool sequences. These concerns raise the score above an unqualified production-like 0–20, while the extensive identity and timing consistency keeps it within the rubric's 21–40 range. The result is uncertainty about provenance, not a demonstrated contradiction disguised as a confidence estimate.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| weak_signal | macOS ES and normalized eCAR file/process activity | MAC-MROSS-02: 7/64 visible exec notifications use cat for binary document paths | Unusual repeated access mechanism; possible simplified file-access behavior, but compatible with real automation. Mild weight only. |
| weak_signal | zsh histories, corroborated by native exec samples | Two Macs, one user: 20/24 and 17/19 history entries use a small diagnostic vocabulary | Repetitive texture, heavily discounted for shared user and bounded source scope. |
| No established hard contradiction or contract gap | Windows Security/Sysmon/eCAR; sampled Linux/macOS SSH chains | All Windows XML and eCAR identity scans; representative exact-tuple remote joins | No score increase from missing families, complete joins, narrative cleanliness or out-of-window lifecycle boundaries. |

## Realism Score by Category

- **Field format accuracy:** 9 — XML/JSON parse and visible native/normalized identity fields remain coherent; unverified platform details were not treated as errors.
- **Temporal patterns:** 8 — Source offsets and session lifecycles are plausible; scheduled cron periodicity has an operational explanation.
- **Cross-source correlation:** 9 — 912 matched Windows process pairs agree on tested fields, and exact-tuple SSH joins are coherent.
- **Behavioral realism:** 7 — Role-specific activity is credible, with mild concerns about repetitive Mac diagnostics and binary-document cat launches.
- **Environmental consistency:** 9 — Windows, Linux and macOS evidence respects platform distinctions and visible host/service roles.

## Recommendations

- If this were synthetic, improve the binary-document access behavior on MAC-MROSS-02: use the actual application or automation mechanism responsible for each read, preserving its parent process, command and file evidence. Retain cat when a byte-stream inspection or real script explains it.
- If this were synthetic, broaden the interactive Mac command vocabulary only where the modeled user's work requires it, while preserving coherent local/remote session ownership. Do not add arbitrary missing sources or noise simply to conceal repeated commands.
- Preserve the demonstrated PID/GUID/hash consistency, distinct fork/exec semantics, source-dependent observation timing and exact remote-session tuples. No repair is warranted merely because a lifecycle begins before or ends after this collection window.

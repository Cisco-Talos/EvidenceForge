# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 66

## Executive Summary

The endpoint evidence is substantially coherent: process identity, visible termination boundaries, Windows process-creation companions, and the macOS fork/exec distinction generally hold up. My synthetic verdict rests on repeated, measurable timing and metadata patterns, especially destination-specific PowerShell-to-SSH delays that recur exactly to the millisecond, rather than on missing sources or a neatly reconstructable incident.

## Evidence For Synthetic

- [distribution_texture] Repeated Windows remote-administration launches replay the same delay for each destination. In `WS-MCHEN-01.meridianhcs.local/windows_event_sysmon.xml`, MAIL-EDGE PowerShell→SSH creation pairs are 13:18:02.956→13:18:08.671, 15:04:18.719→15:04:24.434, and 16:14:15.319→16:14:21.034: **5.715 seconds each**, with different process IDs. MAIL-CLIN pairs independently repeat **4.235 seconds**, and LOG-MON pairs repeat **5.097 seconds**. Event-start line references are supplied below. Several destination-specific, millisecond-exact replays across hours look like reusable timing parameters.
- [distribution_texture] The developer workstation has a tight approximately 96-second editor-launch lattice across different editors and repositories. `WS-LNGUYEN-01.meridianhcs.local/ecar.json` lines 399, 419, 436, and 472 create Vim, Emacs, Vim, and VS Code at timestamp_ms 1793639623574, 1793639719305, 1793639815093, and 1793639911173: gaps **95.731, 95.788, 96.080 seconds**. Lines 375, 388, and 391 also show consecutive Emacs/Vim/Nano launches separated by **96.236 and 96.261 seconds**. Bash history lines 43–58 corroborate the command sequence. This is a concrete timing/command-pool texture concern, not an objection to development tools being present.
- [distribution_texture] Native macOS executable inode values resemble a path-indexed catalog shared between machines. Of 24 executable paths visible on both Macs, **21 have exactly the same cross-host inode difference, 482684**; the three Chrome paths differ by 482685. For example, `/bin/cat`, `/bin/df`, `/bin/ls`, `/bin/ps`, and `/bin/pwd` have inode sequences 2509808, 2509809, 2509811, 2509812, 2509813 on MAC-MROSS-02 and 2992492, 2992493, 2992495, 2992496, 2992497 on MAC-MROSS-01. The same offset extends through `/sbin/launchd`, `/usr/bin/login`, and `/usr/libexec/xpcproxy`, despite different per-file birth dates. This is suspicious metadata regularity, not proof of an impossible filesystem: imaging or identifier sanitization could explain part of it.

## Evidence For Real

- Windows process creation has strong semantic agreement. I parsed **876 Sysmon Event 1 records** across ten hosts; **875** have a Security 4688 companion matching PID, image, and full command line. The remaining Sysmon process, WS-AJOHNSON PID 5324 at 13:56:55.728, lacks that companion; an isolated collection omission is plausible and is not scored as synthetic.
- Visible process lifetimes are consistent. Across the supplied Sysmon streams, I found no later same-ProcessGuid event after Event 5, no known child created after its visible parent's exit, and no ProcessAccess/CreateRemoteThread source or target reference beyond the corresponding visible lifetime. eCAR actor references likewise did not produce an after-exit contradiction in these checks.
- The Macs distinguish process birth from successive execution images. MAC-MROSS-01 ES lines 1–7 show launchd fork, xpcproxy exec, Terminal exec, Terminal fork, login exec, login fork, and zsh exec. PID 42171 persists through the first exec chain while pidversion changes. MAC-MROSS-02 lines 1–10 include the separate iTerm server and ShellLauncher path, rather than copying the Terminal tree wholesale.
- macOS credential semantics show care: MAC-MROSS-01 ES line 5 and MAC-MROSS-02 line 7 give `/usr/bin/login` `euid=0`, `ruid=501`, with root-owned `st_mode=35181` (octal 0104555, including setuid). The shell then has ordinary user credentials. These fields do not support an alleged unauthorized privilege jump.
- SSH authentication modes vary and align with the native evidence. MAC-MROSS-02 Unified Log line 2 reports keyboard-interactive/PAM at 14:24:35.344259, followed by its ES shell exec at 14:24:35.486806; MAC-MROSS-01 Unified Log line 3 reports public-key acceptance at 16:01:31.465667, followed by shell exec at 16:01:31.639524.
- Linux operational logs contain believable service/session groupings. APP-INT syslog lines 14–17 progress from inbound SSH connection through password acceptance and PAM session open to logind session allocation. WS-LNGUYEN syslog lines 19–30 show anacron start, delayed daily-job execution, termination, and normal exit, interleaved with DHCP renewal.

## Detailed Analysis

### Scope and method

I examined only the supplied data directory. I parsed the Windows XML, read native and normalized endpoint records, examined shell histories, and checked same-identity ordering against visible process starts and exits. Most endpoint activity is on 2026-11-02, roughly 13:00–19:00 UTC. I did not require pre-window starts or post-window closure, and I did not use source absence, suspicious-activity completeness, domain validity, or file modification times as authenticity indicators.

### Windows timing: the principal concern

The following references are the opening line of each Sysmon XML event. The `UtcTime`, `ProcessId`, `ParentProcessId`, and command line identify the records independently of line numbering.

| Destination | PowerShell event line / PID / UtcTime | SSH event line / PID / UtcTime | Delay |
|---|---|---|---|
| MAIL-EDGE-01 | 688 / 7496 / 13:18:02.956 | 733 / 7508 / 13:18:08.671 | 5.715 s |
| MAIL-EDGE-01 | 4932 / 8364 / 15:04:18.719 | 4977 / 8400 / 15:04:24.434 | 5.715 s |
| MAIL-EDGE-01 | 9331 / 8836 / 16:14:15.319 | 9376 / 8844 / 16:14:21.034 | 5.715 s |
| MAIL-CLIN-01 | 3298 / 7824 / 14:16:18.010 | 3343 / 7832 / 14:16:22.245 | 4.235 s |
| MAIL-CLIN-01 | 7224 / 8412 / 15:32:35.166 | 7269 / 8432 / 15:32:39.401 | 4.235 s |
| LOG-MON-01 | 314 / 7516 / 13:13:05.169 | 359 / 7520 / 13:13:10.266 | 5.097 s |
| LOG-MON-01 | 13367 / 9052 / 17:57:22.164 | 13412 / 9068 / 17:57:27.261 | 5.097 s |

All rows are from WS-MCHEN's `windows_event_sysmon.xml`; each SSH ParentProcessId equals the paired PowerShell PID. The parent command is simply `powershell.exe`, and each child invokes `ssh.exe marcus.chen@<destination>`. A scripted launcher could intentionally wait before starting SSH, so this is not an impossible ordering. However, several distinct delays recurring exactly by destination are more consistent with repeated generation parameters than with ordinary interactive typing plus startup/scheduler variation. This is stronger than the neutral observation that administrators repeatedly visit the same hosts.

Windows trees otherwise include appropriate SearchIndexer→SearchProtocolHost, services→service-host, and userinit→explorer relationships. Working directories are varied and include actual application and user directories; I did not find evidence for an all-processes-use-System32 defect.

### Linux user activity

Lina's history includes Git, Docker, Kubernetes, editors, and operational diagnostics, so the broad tool selection is plausible. The specific sequence nevertheless alternates Emacs, Vim, Nano, and VS Code over several unrelated project paths while repeatedly falling on a 96-second cadence. The editor lifetimes themselves vary: Nano at eCAR line 328 lasts 93.152 seconds, Vim at line 331 lasts 53.432 seconds, and Emacs at line 375 lasts 40.555 seconds. Thus the repeated spacing is not simply all editors blocking for the same duration before the user can issue another command.

A local benchmark, tutorial, or automation could create such a pattern in production. I retain that alternative and give this indicator moderate weight. I do not call it a hard contradiction or infer authenticity from the apparent purpose of the suspicious commands.

### macOS process and filesystem identity

These are structured Endpoint Security records declaring message `version=11`, plus separate Unified Log exports and eCAR records. I did not interpret ES notifications as authorization decisions, equate audit-session IDs with POSIX sessions, or treat successive exec images as newly forked processes.

The inode observation can be reproduced by deduplicating `process.executable` and `event.exec.target.executable` by path and comparing `stat.st_ino` across hosts. Examples:

| Path | MAC-MROSS-02 ES line / inode | MAC-MROSS-01 ES line / inode | Difference |
|---|---|---|---|
| /bin/cat | 48 / 2509808 | 61 / 2992492 | 482684 |
| /bin/df | 144 / 2509809 | 52 / 2992493 | 482684 |
| /bin/ls | 42 / 2509811 | 36 / 2992495 | 482684 |
| /bin/ps | 77 / 2509812 | 55 / 2992496 | 482684 |
| /bin/pwd | 18 / 2509813 | 33 / 2992497 | 482684 |
| /sbin/launchd | 1 / 2509837 | 1 / 2992521 | 482684 |
| /usr/bin/login | 7 / 2509843 | 5 / 2992527 | 482684 |
| /usr/libexec/xpcproxy | 2 / 2509860 | 2 / 2992544 | 482684 |

The metadata is internally stable per path, which supports coherent file identity. The concern is the ordered shared numeric layout alongside independently varying installation timestamps. For example `/usr/bin/uname` is born 2026-05-09 on MAC-MROSS-02 and 2026-08-10 on MAC-MROSS-01, while `/sbin/launchd` has different September/October birth dates; these are not simply all files sharing a common image-install timestamp. I score the pattern as distribution texture, with imaging/sanitization as material alternative explanations.

MAC-MROSS-01 Unified Log line 2 says policy “would not allow” MeetingAssist. I did not infer that a child successfully ran from that message, nor demand effects or cleanup from an unproven execution. Native launch/policy coverage is too narrow to justify a separate completeness penalty.

### Confidence and limits

No single observed event is conclusively impossible. The repeated target-specific Windows delays are the strongest evidence, the editor cadence adds an independent behavioral texture concern, and the Mac metadata adds a separate numeric pattern. Together they justify a likely-synthetic score, while the substantial lifecycle consistency and plausible automation/imaging explanations keep the score below the hard-contradiction range.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Windows Sysmon process creation | Seven launch pairs, three recurring destinations on WS-MCHEN | Largest effect: repeated destination-specific delays identical to milliseconds |
| distribution_texture | Linux eCAR and bash history | Two clusters of editor/command launches on WS-LNGUYEN | Moderate effect: repeated approximately 96-second spacing across tools and paths |
| distribution_texture | macOS Endpoint Security stat metadata | 24 shared executable paths on two Macs | Moderate, qualified effect: 21 identical cross-host inode offsets and three near-identical offsets |

## Realism Score by Category

- **Field format accuracy:** 9 — Structured native fields, typed credentials, process identifiers, and source distinctions are mostly credible; numeric metadata texture remains a concern.
- **Temporal patterns:** 6 — Lifecycle ordering is sound, but repeated launch delays and editor cadence stand out.
- **Cross-source correlation:** 9 — Windows process companions and macOS auth-to-shell relationships align well; no demonstrated visible after-exit contradiction.
- **Behavioral realism:** 7 — Roles and broad activities fit, while rapid cycling among editors on a repeated cadence looks sampled or automated.
- **Environmental consistency:** 8 — Mixed-platform roles and service/session records are plausible; filesystem metadata has an unusually shared numeric structure.

## Recommendations

- If this were synthetic, vary each invocation's PowerShell→SSH delay independently while retaining parent identity and transport/auth ordering. Reusing a destination-level delay creates the exact repeated patterns documented above.
- If this were synthetic, give interactive development work task-dependent timing and persistent editor preferences. The identified launch lattice should vary with editing duration, project transitions, and the particular user's workflow.
- If this were synthetic, derive native file identity and installation metadata from coherent per-host filesystem histories. Avoid mapping many unrelated executable inodes to the same path rank plus a host offset. If these values were intentionally sanitized, document that transformation so numeric regularity is not mistaken for native telemetry texture.
- Preserve the current visible lifetime and credential coherence; the supplied evidence does not justify adding arbitrary missing events or deliberately breaking cross-source matches.

# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive
**Verdict Confidence:** 68
**Synthetic-Confidence Score:** 48

## Executive Summary

The Windows endpoint data has coherent process, logon, and cross-source relationships, and the macOS records show credible fork/exec/exit and SSH-session sequences. I found no clear host-side impossibility; the main synthetic-leaning observation is a repeated macOS shell-inventory command set across two machines used by the same person, which is suggestive but also has a plausible operational explanation. This review covers a bounded six-hour window, so missing pre-window starts or post-window closings alone are not synthetic evidence, and complete joins alone are not synthetic evidence.

## Evidence For Synthetic

- [distribution_texture] On both `MAC-MROSS-01` and `MAC-MROSS-02`, Maya Ross’s shell repeatedly runs the same small inventory set (`sw_vers`, `uname -a`, `id`, `ps aux`, `df -h`, `ls -la /Users/maya.ross/Documents`, and `find ... -name '*.pdf'`). For example, the first Terminal sequence on MAC-MROSS-01 runs `id`, `sw_vers`, and `uname` from 13:07:57–13:08:01 UTC; MAC-MROSS-02 runs `sw_vers`, `uname`, and `pwd` from 13:11:42–13:11:46 UTC. The same document-listing and process/disk checks recur later on both hosts. This repeated command vocabulary is a weak texture signal, not a contradiction: the same user owns both devices and could repeat routine checks.

## Evidence For Real

- Windows process creation records align closely across native sources. Of 963 Sysmon Event 1 process creations in the 10 reviewed Windows hosts with both feeds, 962 had a Security 4688 record with the same PID and image; the sole unmatched creation is on `WS-AJOHNSON-01`. Matched records have median timestamp deltas of about 0.12–0.15 seconds per host. The decimal Sysmon PIDs correspond to the hexadecimal Security `NewProcessId` values. This alignment supports a coherent shared event stream; completeness itself is not treated as evidence of either origin.
- Windows process ancestry includes plausible service and user-session chains. On `WS-MCHEN-01`, `smss.exe` → `winlogon.exe` → `userinit.exe` → `explorer.exe` occurs at 15:39:43–15:39:48 UTC for `marcus.chen`. User-launched applications such as Chrome, Google Drive File Stream, and GlobalProtect appear under Explorer, while service and maintenance processes appear under service/host processes on the domain controllers and workstations.
- Sysmon process GUIDs, process IDs, image paths, users, and command lines remain internally coherent in sampled records. For example, `WS-MCHEN-01` records `mstsc.exe /v:DC-02` at 17:38:06 UTC under Marcus Chen’s existing interactive logon, with `explorer.exe` as parent; the same executable identity and hash recur for later `mstsc.exe` launches.
- The macOS endpoint-security records preserve plausible successive exec identities and parent relationships rather than treating an exec as a new PID. On `MAC-MROSS-01`, launchd starts `xpcproxy`, which execs Terminal, followed by the login/zsh chain at 13:07:54–13:07:57 UTC. The later zsh child commands have matching fork/exec/exit observations.
- SSH evidence agrees across macOS endpoint and session records. On `MAC-MROSS-01`, the 16:01:32 UTC Unified Log line reports an accepted public-key login for `maya.ross` from `10.10.1.42:50859`; eCAR records an SSH login with that same source tuple and a matching logout at 16:18 UTC. On `MAC-MROSS-02`, the 14:24:37 UTC shell starts after an SSH session from `10.10.1.41:49402`, also represented by matching eCAR login/logout records.
- The visible host records contain varied workstation software and service activity, including Defender, SearchIndexer, Windows Update, Dropbox, Google Drive, browser launches, and scheduled/service-hosted work. The process families and user-vs-service principals are not reduced to one uniform host pattern.

## Detailed Analysis

### Windows process and EDR correlation

I inspected the Security and Sysmon feeds on the Windows hosts that have both. Across the 10 such hosts, 962 of 963 Sysmon Event 1 records matched a Security 4688 on PID and image. The one unmatched record is on `WS-AJOHNSON-01`; it is a single-record gap rather than a repeated correlation failure. Their timestamps are close but not identical: the median delta per host is approximately 0.12–0.15 seconds. Process lifecycle volume is also broadly consistent: eCAR `PROCESS/CREATE` and `PROCESS/TERMINATE` counts track the native process records, with small differences that can reflect the bounded observation window or source coverage. I do not infer synthetic origin from complete joins or small count differences alone.

Sampled Windows trees show normal service and user contexts. On `WS-MCHEN-01`, `SearchProtocolHost.exe` is associated with `SearchIndexer.exe`, service-launched processes use `services.exe` or `svchost.exe`, and the interactive Marcus Chen session launches `mstsc.exe` from Explorer. On `DC-01`, scheduled and management processes include `taskhostw.exe`, `WmiPrvSE.exe`, `Veeam.Backup.Service.exe`, Defender `MpCmdRun.exe`, and domain-controller processes. These are plausible for the recorded system roles.

The sampled Sysmon Event 1 records include populated command lines, product metadata, hashes, user, parent image and parent command line. In `WS-MCHEN-01`, repeated `mstsc.exe` launches at 17:38:06, 17:47:17, and 18:09:52 UTC target DC-02, MAIL-FIN-01, and DC-01 respectively and retain the same image hash. At 17:31:01 UTC, Marcus Chen’s PowerShell record includes `Get-WinEvent -LogName Security -MaxEvents 200 | Export-Csv C:\Reports\security-review.csv`; its recorded parent is `cmd.exe`. That is suspicious activity, but suspicious activity itself is not an authenticity defect.

### Logons and sessions

The Windows Security feeds contain varied logon, privilege, logoff, network, and workstation-lock/unlock records. Their relative counts differ by role: domain controllers show Kerberos and network-authentication activity; workstations show interactive-user activity; the file server has file-access auditing. Within the observed interval, session starts and ends do not all fall in the same files or window. I treat absent out-of-window starts or closings as neutral, not synthetic.

### macOS endpoint records

The two Mac hosts identify the endpoint source as an Endpoint Security export and include fork, exec, and exit records. In sampled chains, exec keeps the same PID while changing the current image, and child processes use the expected parent PID. The `MAC-MROSS-01` SSH chain includes launchd, `xpcproxy`, `sshd-keygen-wrapper`, `sshd`, `sshd-session`, `sshd-auth`, and zsh; the source-native Unified Log acceptance line and eCAR session tuple agree. Session logout and process exits are visible in the same general closing interval.

The repeated shell commands are the only concrete host-side realism concern I found. Their recurrence spans related devices and shared user ownership, so it is not strong enough to label as a generator fingerprint. The macOS Unified Log files are sparse relative to the six-hour interval, but coverage sparsity by itself is not evidence of synthetic generation, and the supplied records do not establish that those files are exhaustive.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS Endpoint Security / eCAR | Two Macs used by the same user | The same compact shell-inventory commands recur on both hosts and at multiple times. This raises a weak templating possibility, but shared ownership and lack of a contradictory lifecycle keep its impact limited. |

## Realism Score by Category

- **Field format accuracy:** 8 — Sampled Windows XML fields and macOS endpoint records have coherent source-specific structures and values.
- **Temporal patterns:** 7 — Process and session events have plausible ordering and nonuniform timestamps; the repeated Mac command set is a mild texture concern.
- **Cross-source correlation:** 9 — Windows process creations align by PID/image across Security and Sysmon, and Mac SSH sessions align across endpoint, Unified Log, and eCAR evidence. Completeness is not counted as a synthetic clue.
- **Behavioral realism:** 7 — Windows service and user activity is varied; Mac shell inventory is repetitive, though plausible for a shared user.
- **Environmental consistency:** 8 — Windows domain controllers, workstations, file server, and Macs show role-appropriate process and session activity in the visible records.

## Recommendations

- If this were synthetic, vary the repeated macOS shell-inventory command mix and its spacing across these two related endpoints, or include more distinct routine user commands in the observed shell sessions. This recommendation is tied to the repeated command pattern above; sparse Unified Log coverage alone is not a basis for expanding the dataset.

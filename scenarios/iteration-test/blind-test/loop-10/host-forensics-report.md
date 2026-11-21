# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 69

## Executive Summary

The endpoint evidence is substantially coherent: visible Windows and normalized EDR process lifecycles hold together, and the macOS records distinguish process creation from successive executable images. My synthetic verdict rests primarily on repeated microsecond-locked timing across separate macOS shell-command groups, with a smaller contribution from the unusually narrow representation of document access through command-line utilities. I found no demonstrated impossible process ordering, and the score reflects strong timing texture rather than a dataset-wide causal failure.

## Evidence For Synthetic

- [distribution_texture] Three distinct command groups retain an identical six-digit fractional second for every native process fork. In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, lines 35, 38, 41 and 44 are at `13:48:41.198588000Z`, `13:49:08.198588000Z`, `13:49:43.198588000Z` and `13:50:02.198588000Z`; lines 53, 56 and 59 similarly retain `.487145000` at `14:37:50`, `14:38:28` and `14:38:57`. On MAC-MROSS-02, the equivalent file's lines 83, 86 and 89 retain `.965208000` at `15:30:55`, `15:31:17` and `15:31:58`. These are three different groups, ten forks in total, with whole-second offsets and group-specific microsecond phases. The following exec notifications have differing millisecond offsets, so this is not simply coarse timestamp precision throughout the source.
- [distribution_texture] The MAC-MROSS-02 Endpoint Security file represents all ten visible `/Volumes/` command executions with only `cat` (seven), `ls` (two), and `tee` (one). All seven `cat` targets have PDF or Office document extensions, including `project-plan.pdf` at `13:37:11.214478Z`, `service-review.xlsx` at `16:05:48.676562Z`, `project-plan.docx` at `17:10:43.529782Z`, and `meeting-notes.docx` at `18:44:51.352962Z`. Their visible lifetimes are 8.9–22.6 seconds, and the normalized EDR attributes the reads to those same command-line utilities. This repeated choice of raw binary-document dumping is weaker behavioral texture, not an impossible operation or a claim that every document access must use a GUI.

## Evidence For Real

- Across the ten Windows hosts, I matched 921 Sysmon Event 1 records to nearby Security 4688 records using host, PID and timestamp. All matched records agreed on image path, command line and parent image. I found no varying `Hashes` values for the same Event 1 image path within an individual host.
- Automated checks of visible Sysmon process GUIDs found no termination preceding its matching creation, no child created before its visible parent creation or after that parent's visible termination, and no checked network/DNS/module/file/registry observation outside its identified process's visible lifetime. Source and target GUID checks on Events 8 and 10 also found no visible lifetime inversion.
- The normalized EDR checks found no actor referenced before a visible PROCESS/CREATE or after a visible PROCESS/TERMINATE, and no process termination preceding its visible creation. Pre-window processes and sessions account for some unmatched opening/closing records and were not penalized.
- macOS process identity is richer than a simplistic parent-child list. For example, MAC-MROSS-01 PID 25527 progresses from inherited launchd image to xpcproxy and Terminal; the PID stays the same while the pidversion changes and the start time is preserved. A separate child becomes login, then a further child becomes zsh. MAC-MROSS-02 has a distinct iTerm2/iTermServer/login chain.
- The macOS native executable identities are internally stable: repeated references to the same `(st_dev, st_ino)` retain the same path, size and cdhash in the reviewed ES records. No observed native process acts after its own recorded exit.
- Linux scheduled telemetry has an operational explanation for regularity. For example, APP-INT-01's sysstat job is logged by CRON at `13:05:00.186337Z`, with recurring ten-minute executions; its EDR `debian-sa1 1 1` child appears at `13:05:01.310Z`. Such periodic background jobs are not the same timing pattern as the shell-command groups cited above.
- Linux authentication includes useful host detail rather than only generic successes. APP-INT-01 logs an SSH connection for source `10.10.1.35:59751`, public-key acceptance for aisha.johnson at `13:00:18.225647Z`, and PAM session opening at `13:00:18.325445Z`, under sshd PID 3373783.

## Detailed Analysis

### Scope and method

I examined only files beneath the supplied data directory. The endpoint inventory includes ten Windows Security/Sysmon pairs, Linux syslog and bash histories, two macOS ES/Unified Log/zsh-history sets, and normalized eCAR records for the hosts. Most host records cover approximately `2026-11-02 13:00–19:00 UTC`. I parsed the Windows XML and endpoint JSON, inspected actual records and command histories, and checked identifiers and timing across visible process lifetimes.

I did not infer authenticity from file modification times, domain resolvability, the completeness of the intrusion narrative, or the availability of particular Sysmon event families. Nor did I count source alignment itself as suspicious. No external schema or product documentation was consulted; unfamiliar platform-specific details were therefore not promoted into alleged native-format errors.

### Windows process trees, hashes and sessions

The Windows trees contain service-host children, WMI providers, task hosts, console hosts, search helpers, updaters, browsers and remote-administration clients. The distributions differ across hosts: DC-01 has 154 Sysmon process creations, WS-MCHEN-01 has 107, and WS-DRAMIREZ-01 has 50. This is not a single identical process list copied across endpoints.

For a concrete example, DC-01's `13:02:10.5386857Z` Sysmon Event 1 creates PID 3712, `C:\Windows\System32\svchost.exe`, command `svchost.exe -k netsvcs -p -s Winmgmt`, under services.exe PID 2332. The record includes SYSTEM identity, LogonId `0x3e7`, terminal session zero, system integrity, version information and multiple hash types. The corresponding Security process records are consistent with the same creation facts.

The 921 paired process records are positive evidence of a coherent endpoint model. Their Security timestamp follows Sysmon by approximately 36–650 ms across the matched set; I treat this as a possible source timing characteristic, not an impossible ordering. Matching was restricted to the same host and PID within three seconds, rather than assuming a PID is globally or permanently unique.

Logon mixes reflect endpoint roles. DC-01 has visible successful logons of types 3 (151), 5 (125), and 10 (3). WS-MCHEN-01 includes types 2, 3, 5, 7 and 9; its two type-7 events accompany a source that also contains two lock and two unlock events. For 387 logoff records matched to a unique visible non-built-in logon identifier, no type-4634 timestamp preceded its matching type-4624 timestamp. Well-known service LUIDs were excluded from that unique-session check. I do not interpret an unmatched boundary session as a fault.

### Linux processes and operator activity

Linux histories show role-related commands rather than Windows defaults: a developer workstation has Git, make, pytest, Docker and editors, while DB-PROD-01 has MySQL/PostgreSQL inspection commands and slow-query analysis. Pipelines appear in histories, and the EDR contains their constituent commands, such as `head` and `grep`. Sudo syslog lines include invoking users, target root identities, TTY/PWD context, and session opens and closes.

The exactly 36 sysstat executions on many six-hour Linux slices have a visible ten-minute scheduler explanation. I did not use their equal counts or routine periodicity to increase the synthetic score. Similarly, service traffic without an available initiating process creation may belong to an already-running daemon.

### macOS lifecycle fidelity

The native files identify ES message version 11 and distinguish fork, exec and exit notifications. MAC-MROSS-01 contains 45 forks, 52 execs and 44 exits; MAC-MROSS-02 contains 56 forks, 65 execs and 55 exits. More execs than forks is expected when one process changes executable image more than once. It is not a duplicate-process defect.

The two hosts' GUI terminal chains differ, and the SSH chains include sshd-keygen-wrapper, sshd, sshd-session, sshd-auth and eventual user shells. On MAC-MROSS-01, an inbound EDR FLOW from `10.10.1.42:55467` to `10.10.1.41:22` appears at `16:02:03.012Z`; the Unified Log records public-key acceptance at `16:02:06.488664Z`, followed by native zsh exec at `16:02:06.653197Z`. That sequence is compatible with transport before authentication before shell execution.

The normalized EDR also records a plist creation and later removal for `com.meridianhcs.endpoint-inventory`, and native ES records show inventory executions. I do not equate plist existence or removal with immediate activation or termination. Likewise, the MAC-MROSS-01 Unified Log's `15:42:09.009673Z` policy message about MeetingAssist is not by itself proof of a successful child or a particular authorization result.

### Timing texture and document-access behavior

The principal defect is the repeated fractional-second phase in separate shell groups. Seven of MAC-MROSS-01's 26 zsh-parent forks and three of MAC-MROSS-02's 35 zsh-parent forks belong to the repeated-phase groups listed above. The groups involve different commands and gaps of 19–41 seconds, rather than a high-frequency burst sharing one timestamp because of ordinary source resolution.

A script or replay harness could deliberately schedule commands on absolute deadlines. That is a plausible alternative to synthetic generation, so I do not call these timestamps impossible. Nevertheless, repeated preservation of arbitrary microsecond phases across three groups is strong evidence of scheduled event construction or replay, and meaningfully reduces production likeness.

The storage command pattern has less weight. Raw `cat` can read any byte stream, and terminals, automated checks or troubleshooting can legitimately dump binary documents. Still, representing seven distinct PDF/Office reads on one Mac with `cat`, together with a document-writing `tee`, gives these otherwise varied storage operations a narrow helper-command texture. Their multi-second durations are not impossible over mounted storage and are not independently scored as a timing contradiction. I did not penalize the dataset for lacking GUI companion events.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| distribution_texture | Native macOS Endpoint Security fork timestamps | Three shell-command groups; ten forks across two hosts | Primary reason for the synthetic verdict: exact group-specific microsecond phases survive many-second gaps while exec timestamps retain finer variation. |
| distribution_texture | macOS ES process commands and normalized EDR file reads | All ten visible MAC-MROSS-02 `/Volumes/` executions; seven PDF/Office reads use cat | Smaller supporting contribution: repeated command-line representation of varied document operations; possible legitimate automation limits its weight. |

No hard contradiction or demonstrated native schema error was established. The verdict-confidence value expresses confidence in the classification; the synthetic-confidence score places this well-correlated but visibly patterned data in the rubric's 61–80 range.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows fields and macOS process/file identities are detailed and internally coherent; no demonstrated native schema defect.
- **Temporal patterns:** 6 — Most lifecycles work, but three microsecond-locked shell-command groups strongly suggest constructed scheduling.
- **Cross-source correlation:** 9 — Checked Windows process fields match, normalized actors remain within visible lifetimes, and inspected SSH transport/auth/shell ordering is compatible.
- **Behavioral realism:** 6 — Host-specific tools are present, but the Mac storage workload repeatedly maps binary documents to cat and tee.
- **Environmental consistency:** 8 — Platform-specific service, session and terminal behavior is generally plausible within the observed collection window.

## Recommendations

- If this were synthetic, derive native fork times from independently timed command execution, including elapsed runtime and scheduling variability; avoid retaining a single arbitrary microsecond fraction across every command in a multi-minute group. Preserve the already-correct lifecycle order when doing so.
- If this were synthetic, diversify the actual mechanisms behind the demonstrated Mac document workload. Use raw cat/tee when those commands are intended, and model application or file-provider activity when users are opening or editing Office/PDF documents; base the choice on the intended operation rather than only the file path.
- If the repeated fork timing instead comes from a replay or export transformation, document that transformation. It materially changes the interpretation of native notification timestamps even when process identities remain reliable.

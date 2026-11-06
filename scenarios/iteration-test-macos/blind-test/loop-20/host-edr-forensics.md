# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 56

## Executive Summary

The sampled macOS Endpoint Security, eCAR, Unified Log, Windows event, and Linux syslog records have credible source-specific shapes and generally coherent process, session, and identity relationships. The strongest host-side synthetic indicators are the recurring, similar Maya Ross command inventories on both Macs and the same root-owned LaunchDaemons plist create/delete lifecycle on each host. I found no demonstrated impossible host process tree; an equal-millisecond SMB FLOW/LOGIN pair and three same-second zsh history entries are concerns at the available timestamp resolution, not decisive contradictions.

## Evidence For Synthetic

- [distribution_texture] The two `maya.ross` zsh histories reuse a narrow system-inventory sequence. `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history:1-6` contains `id`, `sw_vers -productVersion`, `uname -a`, `pwd`, a Documents listing, and `du`; `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history:1-5` has nearly the same sequence. The same hosts later repeat `ps aux`, `find ... '*.pdf'`, and `df -h` (history lines 8-10 and 19-22 on Mac 1; lines 7-8 and 14-20 on Mac 2). Endpoint Security independently shows these commands as shell children (Mac 1 lines 8-15 and Mac 2 lines 11-15).
- [distribution_texture] Both Macs show the same root-owned `/Library/LaunchDaemons/com.meridianhcs.endpoint-inventory.plist` file lifecycle in eCAR: CREATE on Mac 1 line 37 and Mac 2 line 33, then DELETE on Mac 1 line 529 and Mac 2 line 471. The file actions are attributed to `/bin/sh` on both hosts and occur at similar times. eCAR also records `xpcproxy com.meridianhcs.endpoint-inventory` process observations (Mac 1 lines 46-48 and Mac 2 lines 64-65), so the records show a running job as well as file placement/removal; they do not show the registration or unload operation itself.
- [weak_signal] Mac 2 zsh history lines 18-20 assign the same integer-second timestamp (`1793644147`) to `find`, `ps aux`, and `pwd`. The format is second-resolution, so quick successive commands can collide in the visible timestamp; I treat this as weak evidence only.
- [weak_signal] DC-02 eCAR lines 1035-1036 put the successful network LOGIN and matching inbound TCP/445 FLOW for `10.10.1.34:55083 -> 10.10.2.11:445` at the same millisecond (`1793629313776`), with the LOGIN listed first. The tie leaves no visible sub-millisecond ordering; the host records alone do not establish an impossible sequence.

## Evidence For Real

- Mac 1 Endpoint Security lines 1-7 show a credible launch chain: launchd forks PID 42198, which execs xpcproxy then Terminal with successive PID versions 10-12; Terminal forks PID 42199, which execs `/usr/bin/login`; login forks PID 42200, which execs `/bin/zsh`. PID, parent PID, audit tokens, and exec target fields agree with those transitions.
- Mac 2 Endpoint Security lines 1-10 show a different but plausible iTerm chain: launchd → xpcproxy → iTerm2 → iTermServer → login → ShellLauncher → zsh. The same PID advances through exec images while children receive distinct PIDs and parent relationships.
- The reciprocal SSH evidence is chronologically credible. Mac 2 Endpoint Security lines 98-99 records an outbound `ssh -tt maya.ross@MAC-MROSS-01...` process at 16:02:02.357Z. Mac 1 Unified Log line 3 records `sshd-session` accepting Maya's public key from `10.10.1.42:62470` at 16:02:17.562108Z; Mac 1 Endpoint Security line 88 records the remote shell exec at 16:02:17.723014Z, after authentication. Mac 1 eCAR line 248 records the matching SSH session with the same source tuple, followed by logout at line 299.
- The other SSH path aligns as well. Mac 1 Endpoint Security lines 46-47 shows Maya's SSH client to Mac 2 at 14:24:37Z. Mac 2 Unified Log line 2 records `sshd-session` accepting keyboard-interactive/PAM authentication from `10.10.1.41:59129` at 14:24:53.650676Z, before the Mac 2 zsh exec at Endpoint Security line 65 (14:24:53.750785Z). eCAR records the corresponding session and later logout at Mac 2 lines 146 and 176.
- The Windows service sample has source-consistent lineage rather than just a service-name assertion. DC-02 eCAR lines 3308-3315 show `DirectoryCacheSvc` creation, a subsequent SYSTEM process start as a child of `services.exe`, and module loads. The same image and command line appear in the DC-02 Sysmon export around lines 100828-100873, and later `sc.exe stop/delete` activity appears in eCAR and Sysmon. The observed process identity and service account agree across these records.
- Linux syslog includes ordinary service and host activity, including cron/sysstat, snapd, unattended-upgrades, irqbalance, D-Bus, resolved, and systemd-logind entries (for example `APP-INT-01.../syslog.log:1-20`). The sampled logs are not limited to the conspicuous process or session events.
- The macOS Endpoint Security records declare schema version 1 and message version 11 and use event-specific `fork` (type 11), `exec` (type 9), and `exit` (type 15) payloads. The two hosts have varied process counts and event mixes; I found no malformed audit-token shape in the inspected samples. Unified Log lines retain wall timestamps, Mach timestamps, boot UUIDs, process image paths, sender paths, and message metadata. I did not interpret the Apple System Policy message on Mac 1 Unified Log line 2 as proof that a child process ran.

## Detailed Analysis

### macOS process identity and sessions

Mac 1's initial Terminal start is represented as multiple exec epochs for PID 42198 rather than unrelated process identities. Its audit-token PID version increments as the process image changes, and later login/zsh children receive separate PIDs. Mac 2 similarly captures iTerm2 and its helper/login shell chain. In the sampled records, actor/target executable paths and parent PIDs are plausible. eCAR's process observations retain operation names and PID-version transitions, providing a usable normalized view alongside the native ES records.

The Mac session records are broadly consistent with the interactive and remote access observed elsewhere. The 16:02 Mac-to-Mac SSH sequence is especially clear: client process, destination authentication, shell execution, eCAR login, and eventual logout all retain the expected endpoints and source port. The Unified Log authentication messages precede the remote shells. I do not treat differences between native and normalized eCAR timestamp values as contradictions without an observed impossible order.

### Shell behavior and file activity

Maya's two histories contain similar command vocabularies and ordering, including OS/version inspection, identity, home-directory inventory, process listings, and disk checks. Their Endpoint Security rows confirm actual executions, so this is not merely a free-standing history artifact. Repetition across two Macs under one user is plausible for a person who uses the same troubleshooting checklist, but the similarity is a visible distribution pattern.

The root-owned inventory plist is created and later deleted on both Macs. eCAR records the file path and `/bin/sh` actor, and shows `xpcproxy` observations for the named job between creation and removal. The artifacts support file placement and job activity; they do not prove a particular `launchctl` registration/unload command. I found no basis to infer more than the visible operations.

### Windows and Linux host evidence

The sampled DC-02 `DirectoryCacheSvc` records retain a SYSTEM service process with `services.exe` as parent, followed by module loads. The later stop/delete commands are visible under the named interactive principal. These are suspicious actions, but their process and service fields are coherent across the sampled endpoint sources. I found no PID, parent-image, or account mismatch in these examples.

Linux records show normal service activity and user-session context alongside eCAR process and flow evidence. I did not require Windows event IDs on Linux or Windows artifacts on macOS, and I did not treat missing events outside the visible interval as defects.

### Timestamp ties and source precision

The Mac 2 zsh history stores integer Unix seconds, so three commands at one visible second cannot establish their sub-second execution order. Separately, the DC-02 eCAR network LOGIN and inbound FLOW share one millisecond for an exact tuple. The row order and equal timestamp raise a small chronology question, but the available precision does not establish which occurred first. I would retain these as weak signals rather than assert an impossible lifecycle.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `distribution_texture` | macOS zsh history and Endpoint Security | Two Macs; one user | Similar ordered system-inventory commands recur across both hosts and later sessions. |
| `distribution_texture` | eCAR FILE and PROCESS | Two Macs | The same root-owned inventory plist is created and removed on each host with similar timing, alongside observations of the named xpcproxy job. |
| `weak_signal` | zsh history / eCAR | Mac 2 history and one DC-02 SMB tuple | Three commands share one second; a matching eCAR login and FLOW share one millisecond. Neither tie proves impossible ordering at the source's visible precision. |

## Realism Score by Category

- **Field format accuracy:** 8 — The sampled ES v11 payloads, Unified Log records, eCAR rows, Windows XML, Sysmon, and Linux syslog use plausible source-specific shapes.
- **Temporal patterns:** 6 — Both sampled SSH authentication-to-shell paths are ordered plausibly; one SMB tuple and three history entries are timestamp ties at limited precision.
- **Cross-source correlation:** 8 — Sampled SSH sessions, process identity transitions, and the Windows service lifecycle align across endpoint sources.
- **Behavioral realism:** 6 — The two Macs repeat a relatively narrow inventory checklist and matching root-owned plist activity.
- **Environmental consistency:** 7 — The Mac, Windows server, and Linux host roles fit the observed process families; repeated inventory-job behavior is possible but uniform across both Macs.

## Recommendations

- If this were synthetic, vary the exact inventory commands and their ordering across Maya's sessions while retaining the endpoint process/history correlation.
- If this were synthetic, preserve separate file placement, launchd registration, activation, unload, and removal semantics in any future records; do not infer unobserved stages from the plist path alone.
- Keep the SMB FLOW/LOGIN timestamps at a precision that does not imply an ordering the records cannot establish, or retain a strict source-local order when the collector provides one.

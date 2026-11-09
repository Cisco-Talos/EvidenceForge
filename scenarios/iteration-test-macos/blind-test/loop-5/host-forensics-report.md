# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 90
**Synthetic-Confidence Score:** 74

## Executive Summary

The most significant endpoint defect is impossible-looking macOS process identity chronology: later fork/exec target records on both Macs carry lower PID-version values than earlier process births in the same host stream, despite increasing native event times. The repeated, nearly identical user inventory-command sequences across both Macs add a separate distribution fingerprint. Windows, Linux, SSH/session evidence, and most individual macOS process chains otherwise show convincing role and lifecycle detail.

## Evidence For Synthetic

- [hard_contradiction] New process identities in `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson` do not maintain increasing PID-version allocation order across native event time. For example, the SSH target PID 51632 has PID version 53 at 14:24:24Z, but the later `cat` target PID 55151 has PID version 51 at 14:43:40Z. Likewise, a `cat` process receives version 68 at 15:10:37Z, followed by a later `sw_vers` process with version 62 at 15:16:05Z; an SSH process has versions 93/94 at 16:33:55Z, followed by `sw_vers` versions 85/86 at 16:34:23Z. These are fork/exec target audit tokens for new PIDs, not successive images of one process. The ordering is a source-visible identity chronology defect.
- [hard_contradiction] The same pattern occurs in `MAC-MROSS-02.../macos_endpoint_security.ndjson`: Zoom's target PID 21374 reaches PID version 54 at 13:37:29Z, while a later `sw_vers` target PID 21921 at 13:43:12Z has version 39. At 16:01:46Z SSH target PID 45502 has version 96; a later `uname` target PID 49779 at 16:46:20Z has version 98 (this pair is monotonic), but the subsequent `cat` PID 46802 at 16:15:36Z has version 102, demonstrating nonchronological allocation relative to the later 16:46 process. The clearest additional inversion is `find` PID 61318 at 18:23:37Z, versions 124/125, followed by `cat` PID 65281 at 18:53:00Z, versions 122/123. Repeated backtracking on both Macs is difficult to explain as ordinary process reuse.
- [distribution_texture] Maya Ross repeatedly executes nearly the same host-inventory commands on both Mac endpoints: `id`, `sw_vers`, `uname`, `pwd`, document-directory `ls`/`du`, `df`, `ps`, `find`, `ifconfig`, and `dscl`. The sequence repeats at similar points in the day, and ES/eCAR process events corroborate actual executions. This repeated command mix and ordering is a strong behavioral template signal.

## Evidence For Real

- Mac ES records include structured version-11-shaped fork/exec/exit notifications with audit tokens, parent and responsible tokens, PID versions, signing identifiers, code-signing fields, executable paths and stat metadata. The local chain on MAC-MROSS-01 is sensible: `launchd`/`xpcproxy` → Terminal → `/usr/bin/login` → user `zsh`, followed by short command children.
- Interactive SSH evidence is plausible across hosts. MAC-MROSS-02 Unified Log records `Accepted keyboard-interactive/pam for maya.ross from 10.10.1.41 port 50952 ssh2` at 14:24:42Z, near the ES sshd-session startup at 14:24:38–42Z and Maya's SSH command on the other Mac. MAC-MROSS-01 records accepted public-key authentication from 10.10.1.42 at 16:02:03Z, with ES sshd/session records at 16:02:00–02Z. The accepted-auth messages and endpoint process chains agree within seconds.
- eCAR process create/modify/terminate records generally correspond to the observed Mac ES images, PIDs and parent PIDs. The end-of-window process terminations on both Macs are accompanied by eCAR user-session logout rows, so the clustered exits have a visible lifecycle explanation and are not counted as a contradiction.
- Windows workstation Security logs contain logon/logoff, process start/stop, privilege, explicit-credential, lock/unlock and filtering records; Sysmon provides process/network/image/registry/file/DNS events. On WS-MCHEN-01, Security has 88 Event 4688 and 59 Event 4689 records, matching Sysmon's 88 Event 1 and 59 Event 5 counts. This is useful correlation, not a synthetic clue by itself.
- DC-01 shows role-consistent Kerberos and account activity alongside ordinary process and logon records. Linux syslog contains DHCP, cron/sysstat, NetworkManager, polkit, package/update and Samba events; a FILE-LNX-01 Samba audit example records successful Kerberos authentication followed by share connect/open/read/close activity for a workbook.

## Detailed Analysis

### macOS process identity and chronology

Each ES event type 11 fork record exposes the child's audit token, and each type 9 exec record exposes a target audit token for the process image transition. These are the identities to compare, rather than the event actor's parent token. In the MAC-MROSS-01 stream, the early interactive shell receives versions 15/16, and command children advance through the 17–49 range. Later children then move backward: the 14:43:40Z `cat` has versions 50/51 even though the 14:24:24Z SSH process already had 52/53; the 15:16:05Z inventory `sw_vers` has 60–62 even though the 15:10:37Z `cat` reached 67/68; and the 16:34:23Z `sw_vers` has 85/86 after the 16:33:55Z SSH reached 93/94. Native timestamps and Mach times continue forward, so this is not explained by event sorting.

MAC-MROSS-02 has the same identity-order problem: Zoom at 13:37:29Z reaches versions 52–54, then `sw_vers` at 13:43:12Z receives 37–39. At the end of the window, the 18:23:37Z `find` gets 124/125, while the later 18:53:00Z `cat` gets 122/123. PID version is carried as part of the process audit token and matters for distinguishing process instances. The repeated backtracking across independently observed child processes is the strongest authenticity defect in this endpoint review.

### macOS session, command and source alignment

The normal local shell chain is credible. On MAC-MROSS-02, the initial Terminal session transitions through login and zsh; a separate iTerm2/iTermServer terminal session also reaches login and zsh. Maya's history commands are reflected as ES fork/exec observations and eCAR process rows with the same user and parent shell. SSH client and server activity similarly aligns: the keyboard-interactive session begins around 14:24:38–42Z and ends around 14:34:59Z; the MAC-MROSS-01 public-key session begins around 16:02Z and its session children exit around 16:17:59Z. The ES observations are notifications; the Unified Log accepted-auth messages provide the authentication result.

The histories nevertheless have a repeated inventory pattern. On MAC-MROSS-01, Maya runs `id`, `sw_vers -productVersion`, and `uname -a` near 13:07–13:08Z, followed by document and system inspection later. MAC-MROSS-02 repeats `sw_vers`, `uname`, `pwd`, then the same document-directory and system commands, and later repeats several of them again. This is not merely similar user intent; the exact command set and ordering recur, including the same path and flags, and the endpoint process sources confirm execution.

The ES exit clusters at the end of each visible window are not independently treated as defects. MAC-MROSS-01 exits the remaining foreground applications and shell at 18:54:59Z; MAC-MROSS-02 exits them at 18:56:58–18:57:00Z. eCAR includes corresponding `USER_SESSION/LOGOUT` records and process termination rows. That is coherent with a user logout near collection end, and missing out-of-window session context is not penalized.

### Windows and Linux endpoint context

The Windows workstation mix includes Security 4624/4625/4634, 4648, 4672, 4688/4689, 4800/4801 and 5156, plus Sysmon 1/3/5/7/10/11/13/22. On WS-MCHEN-01, equal Security/Sysmon process-start and process-exit counts and corresponding eCAR process records make pivots feasible. DC-01's larger Kerberos 4768/4769 volume is appropriate for a domain controller; the small number of account/service/task events is not used to infer missing coverage or synthetic origin.

Linux host logs show multiple service families and plausible operational detail. For example, FILE-LNX-01 reports Samba authentication for `lina.nguyen` from 10.10.1.21, then connect/open/read/close activity on a share file. WS-LNGUYEN-01 records DHCP request/ack/bind and NetworkManager state changes, while histories on Linux hosts contain varied administration and SSH use. The inspected samples contain no concrete impossible process or session relationship.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | macOS Endpoint Security process audit tokens | Both MAC-MROSS hosts | Later fork/exec target PIDs repeatedly carry lower PID-version values than earlier births; native event times advance. This undermines process-instance chronology. |
| `distribution_texture` | macOS zsh history, ES, and eCAR | Maya Ross across both Macs | The same ordered host-inventory command set recurs multiple times and is confirmed in endpoint execution evidence. |

## Realism Score by Category

- **Field format accuracy:** 7 — Sampled records use plausible native shapes, but PID-version chronology is a source-level identity defect.
- **Temporal patterns:** 5 — Shell and SSH ordering is coherent, but process identity allocation backtracks in native event time.
- **Cross-source correlation:** 8 — SSH authentication, ES process chains and eCAR activity generally line up.
- **Behavioral realism:** 5 — Repeated exact inventory command sets on two Macs are a conspicuous pattern.
- **Environmental consistency:** 8 — Windows, Linux and Mac host roles and activity look plausible in the visible slice.

## Recommendations

- If this were synthetic, allocate macOS PID-version identities in the same order as canonical process births and preserve the assigned identity across fork/exec references. Verify across the full ES process stream, including launchd-created applications and shell children.
- Vary routine Mac user command selection and ordering across hosts and time so the same inventory bundle does not recur as a fixed sequence. Keep the ES/eCAR command evidence aligned with the underlying activity.

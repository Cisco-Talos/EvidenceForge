# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 84  
**Synthetic-Confidence Score:** 69

## Executive Summary

Host telemetry is generally coherent: Windows Security 4688 records align with Sysmon Event 1 process IDs, images and command lines across nearly all sampled Windows hosts, and eCAR process/session records usually preserve plausible parent and identity relationships. The strongest contrary evidence is a macOS SSH lifecycle ordering conflict on MAC-MROSS-01: the Endpoint Security export records the remote shell exec before both the native sshd “Accepted publickey” message and eCAR’s successful SSH login. That narrow but material cross-source contradiction supports a synthetic verdict; I did not treat the compact suspicious activity or selected source coverage as evidence on its own.

## Evidence For Synthetic

- [contract_gap] **MAC-MROSS-01 remote SSH session is ordered inconsistently across endpoint sources.** In `MAC-MROSS-01.meridianhcs.local/macos_endpoint_security.ndjson`, an ES exec event at **2026-11-02 16:02:17.723014Z** (record 88) has target `/bin/zsh`, launched by `/usr/libexec/sshd-session`. The same host’s `macos_unified_log.ndjson` records `Accepted publickey for maya.ross from 10.10.1.42 port 62470` at **16:02:18.539009Z** (record 3), and `ecar.json` records the successful SSH `USER_SESSION/LOGIN` for that source IP and port at **16:02:19.207Z** (record 248). A user shell appearing roughly 0.8 seconds before the authentication-success log and 1.5 seconds before the normalized successful login is an anomalous lifecycle order for this same connection.
- [distribution_texture] **The two Mac shell histories reuse a narrow, repeated inventory-command pattern.** `MAC-MROSS-01.../zsh_history/maya.ross.zsh_history` and `MAC-MROSS-02.../zsh_history/maya.ross.zsh_history` both repeat combinations of `sw_vers`, `uname -a`, `id`, `pwd`, `ls -la .../Documents`, `du -sh .../Documents`, `ps aux`, and `df -h`, alongside SSH pivots. On the first host, examples recur at 13:08–13:09, 13:48–13:50, 14:38–14:39, 16:34, 17:25, and 18:12 UTC; the second host has a similar inventory sequence. This is a weak supporting texture signal, not an independent basis for the verdict.

## Evidence For Real

- Windows process creation correlation is strong and field-level consistent. After converting Security 4688 `NewProcessId` hex values to decimal, all 139 records on `DC-01`, 109 on `DC-02`, 91 on `FILE-SRV-01`, 99 on `MAIL-FIN-01`, 57 on `WS-DRAMIREZ-01`, 75 on `WS-EBROOKS-01`, and 59 on `WS-PPATEL-01` match Sysmon Event 1 PIDs. Matched image and command-line values agreed in each comparison. For example, `WS-AJOHNSON-01.../windows_event_security.xml` has 4688 PID `0x1454` for `taskhostw.exe /Run` at **13:06:37.625Z**; `windows_event_sysmon.xml` has PID `5204` for the same image and command line at **13:06:37.576Z**, with the same SYSTEM identity and `svchost.exe` parent.
- Windows process parents and user context are plausible in representative records. On `WS-AJOHNSON-01`, eCAR at **13:41:50.136Z** records `userinit.exe` → `explorer.exe` → Outlook under `aisha.johnson`; service activity on `WS-SMARTINEZ-01` includes SYSTEM `svchost.exe` → `taskhostw.exe` and `services.exe` → `DropboxUpdate.exe`.
- Endpoint Security and eCAR on the Macs generally show coherent identity and process transitions. On MAC-MROSS-01, a local Terminal session becomes `login` and then `zsh` under UID 501, with matching session identity in eCAR; short commands such as `id`, `sw_vers`, `uname`, `pwd`, and `ls` have exits with success status in ES. On MAC-MROSS-02, eCAR logs the local `maya.ross` session in at **13:04:23.118Z** and logs it out at **18:57:02.792Z**, consistent with a long lived user session and final process cleanup in the visible window.
- The macOS policy message is not used as proof of successful or denied execution. `MAC-MROSS-02.../macos_unified_log.ndjson` says at **15:42:30.945Z** that Apple System Policy “would not allow” `/Applications/MeetingAssist.app/Contents/MacOS/MeetingAssist` (PID 62521). I found no matching child execution in the scoped endpoint records, which is consistent with a policy block; the message alone does not establish effects.

## Detailed Analysis

### Windows process and session evidence

The visible Windows Security and Sysmon windows span approximately **13:00–19:00Z on 2026-11-02**. I compared Security 4688 and Sysmon Event 1 on ten hosts. Seven hosts have a one-to-one PID match for all compared process starts; the other three have only small count differences (WS-AJOHNSON-01: one unmatched record per source; WS-MCHEN-01: three Security-only starts; WS-SMARTINEZ-01: one Security-only start). Among matched PIDs, image and command line were consistent. The small unmatched counts are not enough by themselves to establish a collection defect, especially with source observation differences possible.

Security event volumes and eCAR process activity are plausible for a mixed endpoint/server fleet. For instance, DC-01 includes 296 Event 4624, 151 Event 4634, 139 Event 4688 and 135 Event 4689 records over nearly six hours, while its Sysmon export has 139 Event 1 and 135 Event 5 records. The workstation records include user shell/app startup chains and ordinary system services, rather than only the suspicious actions. User sessions in eCAR show expected network, service, and interactive logon types, with logon IDs preserved between login and logout where both are visible.

### macOS session and process evidence

Both Mac hosts expose three different endpoint evidence types: eCAR normalized records, Endpoint Security-shaped NDJSON, and sparse Unified Log exports. I treated their fields according to source: ES exec records expose actor/target process identities and an authorization result, while Unified Log messages provide native message text and timestamp. I did not assume that missing Unified Log rows meant missing process activity.

MAC-MROSS-01 has a local Terminal chain beginning at **13:08:01Z**: `launchd`/`xpcproxy` starts Terminal, Terminal starts `/usr/bin/login`, and login execs `/bin/zsh`. Subsequent shell commands have matching user/session identity and short successful exits. Its SSH activity is the one clear defect: ES records the SSH service startup chain beginning **16:02:16.195Z**, then `/bin/zsh` as the target of an exec at **16:02:17.723Z**. The native Unified Log says the public key was accepted for the same user/source tuple at **16:02:18.539Z**. eCAR then records the successful session with that same `10.10.1.42:62470` tuple at **16:02:19.207Z**. The authentication and session evidence should precede the user shell; the shown timestamps put it after.

MAC-MROSS-02 has a long local session and ordinary application process activity. The Unified Log export includes the MeetingAssist policy message and an SSH acceptance message. A separate SSH `USER_SESSION/LOGIN` in its eCAR records source `10.10.1.41:59129` at **14:24:54.383Z**; that is a different tuple from the MAC-MROSS-01 SSH session above. No claim about the policy message’s child effects is warranted from these records.

### Shell histories and behavioral texture

The two Mac zsh histories are timestamped and largely correspond to ES/eCAR process starts. They contain ordinary host inspection and document reads as well as repeated inventory probes. The repetition is noticeable across the two hosts but not impossible for one user administering or troubleshooting both systems. I assign it low weight and do not count the terse, linear nature of the suspicious sequence as synthetic evidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `contract_gap` | macOS ES + Unified Log + eCAR | One SSH session on MAC-MROSS-01 | High: shell exec timestamp precedes authentication-success evidence for the matching source tuple. |
| `distribution_texture` | macOS zsh histories | Two hosts, same user | Low: repeated inventory command set supports but does not determine the verdict. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows event fields and the sampled macOS record shapes are internally coherent; no demonstrated format defect.
- **Temporal patterns:** 6 — Most observed lifecycles are plausible, but the MAC-MROSS-01 SSH ordering is a meaningful exception.
- **Cross-source correlation:** 7 — Windows Security/Sysmon process evidence correlates closely; one macOS SSH lifecycle does not.
- **Behavioral realism:** 7 — Mixed system and user activity is credible, though the repeated Mac inventory sequence is somewhat narrow.
- **Environmental consistency:** 8 — Host and process roles fit the visible Windows, Linux, and macOS endpoint evidence.

## Recommendations

- If this were synthetic, align the MAC-MROSS-01 SSH endpoint timeline so the accepted-key evidence and successful session record precede the first user-shell exec for the same tuple (`10.10.1.42:62470`). Preserve source-specific timestamps, while keeping the shell’s process identity and session correlation intact.
- If tuning command texture, vary the repeated macOS inventory-command combinations and spacing between the two hosts; the observed repetitions are a minor signal, not a required correction.

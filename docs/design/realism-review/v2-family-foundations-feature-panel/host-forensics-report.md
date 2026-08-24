# Host/EDR Forensics Analyst — Feature-Branch Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 98
**Synthetic-Confidence Score:** 95

## Executive Summary

The endpoint telemetry contains excellent process, hash, PID, and attack-chain correlation, but repeated source-native contradictions make a real-production origin highly unlikely. The strongest defects are RDP sessions that keep normally transient `userinit.exe` processes alive for hours, internally contradictory Sysmon parent fields, and five Linux SSH closes whose `systemd-logind` removals reference the wrong session IDs.

## Evidence For Synthetic

- **[hard_contradiction] RDP `userinit.exe` processes remain alive for entire multi-hour sessions.**
  - `WS-AJOHNSON-01` Security 4624 records Type 10 logons from `LT-MRIVERA-02` at `15:00:28.455` and `15:20:00.396`. Their Sysmon `userinit.exe` processes live for 8,857 and 7,876 seconds, respectively.
  - `DC-01` Type 10 sessions for Aisha Johnson at `14:42:47.246` and Marcus Chen at `17:10:06.114` retain `userinit.exe` for 8,669 and 2,823 seconds.
  - This conflicts with normal Windows behavior: `userinit.exe` performs logon initialization, launches the user shell, and exits. The same dataset models local interactive `userinit.exe` lifetimes correctly at roughly 3–5 seconds on `FILE-SRV-01`, `WS-DRAMIREZ-01`, `WS-EBROOKS-01`, `WS-PPATEL-01`, and `WS-SMARTINEZ-01`. The defect is isolated to all four visible RDP lifecycles.
- **[hard_contradiction] Sysmon RDP parent identity disagrees with visible parent events.**
  - At `WS-AJOHNSON-01` `15:00:28.563`, Sysmon Event 1 for `userinit.exe` PID `5768` names parent PID `5756` and its ProcessGUID. The immediately preceding Event 1 shows PID `5756` is `C:\Windows\System32\winlogon.exe` running as `NT AUTHORITY\SYSTEM`.
  - Despite that visible parent, the child record reports `ParentImage=-`, `ParentCommandLine=-`, and `ParentUser=MERIDIANHCS\aisha.johnson`.
  - The same contradiction recurs for PID `5808` on `WS-AJOHNSON-01` and PIDs `4668` and `5852` on `DC-01`: each visible parent is SYSTEM-owned `winlogon.exe`, while the child’s `ParentUser` is the interactive user.
  - Explorer children in the same four chains also report `ParentImage=-` and `ParentCommandLine=-` even though their `userinit.exe` parents are present in the immediately preceding telemetry.
  - eCAR contains the correct source facts—`source_image_path=...\winlogon.exe` and `source_principal=SYSTEM`—so the contradiction is source-native rendering, not missing canonical context.
- **[hard_contradiction] Repeated SSH close bundles remove the wrong `systemd-logind` session.**
  - `APP-INT-01` eCAR session `378847` receives the SCP transfer at `17:28:27`; syslog closes its root sshd process at `17:28:41.109` but removes session `375894`.
  - `APP-INT-01` session `378710` closes at `17:59:40.341`, followed by removal of `375891`.
  - `MAIL-CLIN-01` session `198445` closes at `17:22:15.234`, followed by removal of `196864`.
  - `MAIL-EDGE-01` session `275297` closes at `17:59:39.379`, followed by removal of `272328`.
  - `PROXY-01` session `267743` closes at `17:59:39.682`, followed by removal of `266605`.
  - These are visible in-window sessions tied to the closing sshd PIDs, not merely terminations whose starts predate the slice.
- **[schema_or_format] File-server network logons contain impossible or blank source fields.**
  - Ten Security 4624 Type 3 records on `FILE-SRV-01` have an empty `LogonProcessName`, not a source-native process such as `Kerberos` or `NtLmSsp` and not even the conventional placeholder `-`.
  - Those same remote logons set `WorkstationName=FILE-SRV-01`, the target host, while their source addresses are workstations such as `10.10.1.34`, `10.10.1.31`, and `10.10.1.35`.
  - Examples occur from `16:04:44.582` through `17:00:44.797`.
- **[distribution_texture] Endpoint lifecycles converge on the collection boundary.**
  - Unrelated Linux SSH sessions on `APP-INT-01`, `DB-PROD-01`, `MAIL-EDGE-01`, and `PROXY-01` close around `17:59:39–17:59:41`.
  - Several Windows interactive sessions also log off or terminate their shell chains in the final seconds before `18:00`.
  - This tight, cross-host convergence is more consistent with forced lifecycle completion than independent user behavior.

## Evidence For Real

- All visible Sysmon Event 1 records correlate to Security 4688 by PID, image, command line, and sub-second timing. Across the Windows hosts, no image or command-line mismatches were found.
- eCAR process-create records agree with Sysmon on PID, image, and PPID. Visible Sysmon Event 5 records never precede their corresponding Event 1, and their ProcessGUID/image pairs remain stable.
- Same-host hashes are stable for repeated executions of each image. Hash clusters across hosts plausibly reflect different Windows builds or software versions rather than per-process randomization.
- Local interactive process lifecycles are convincing: `winlogon.exe`, transient `userinit.exe`, and persistent `explorer.exe` have appropriate relative roles on several workstations.
- Most Linux SSH lifecycles are strong:
  - Connection, authentication, PAM open, `systemd-logind` creation, shell activity, PAM close, and session removal occur in plausible order.
  - Source ports, users, sshd PIDs, and session IDs usually match across eCAR and syslog.
- Bash histories use epoch timestamp entries and correspond naturally to endpoint process evidence. Shell redirection and pipelines are represented as shell history plus their actual child processes rather than copied mechanically into every process command line.
- Background activity is role-aware and varied:
  - Windows hosts show Defender, WMI, search indexing, GPO, Windows Update, application updaters, Office, browsers, collaboration clients, and service processes.
  - Linux hosts show cron/sysstat, snapd, journald, logind, package maintenance, irqbalance, and role-specific application activity.
- The attack-related process trees are technically useful. On `DC-01`, WMI/PsExec activity leads through `cmd.exe` to `net.exe`, service creation, scheduled-task creation, encoded PowerShell, and `wevtutil`, with corresponding Security, Sysmon, and eCAR evidence.

## Detailed Analysis

The Windows telemetry initially appears highly authentic. Security 4688, Sysmon Event 1, and eCAR process creation agree on the essential executable and process identity fields. Provider-specific timestamp offsets are positive and small, generally tens to hundreds of milliseconds. Process termination records preserve ProcessGUID and image identity, and unmatched termination events are explainable as processes created before the bounded window.

The hash behavior is also internally sound. Repeated images on one host retain identical SHA1, MD5, SHA256, and IMPHASH values. Some Windows binaries share hashes across machines, while other hosts form different but internally consistent groups, which is compatible with heterogeneous patch levels.

RDP processing exposes a clear family-specific defect. Every visible Type 10 session creates `winlogon.exe → userinit.exe → explorer.exe`, but unlike local interactive paths, the RDP `userinit.exe` processes persist for tens of minutes or hours. The mismatch is systematic across both RDP targets and all four sessions. The associated Sysmon records then discard known parent image and command-line data and misstate `winlogon.exe`’s principal as the interactive user. Because eCAR retains the correct parent source principal and image, collection loss cannot explain the inconsistency.

Linux endpoint evidence has a similar family-level problem. Most SSH sessions maintain correct logind IDs end to end, establishing the expected native behavior. Five later sessions instead close the correct sshd PID and user but remove an unrelated earlier session ID. The repeated pattern across four hosts strongly indicates incorrect session-state selection during lifecycle termination.

The file-server Type 3 records are a separate source-native problem. An empty `LogonProcessName` and target-host `WorkstationName` on remote network logons weaken both DFIR interpretation and source authenticity. Other hosts populate these fields more plausibly, making the defect path-specific rather than a simple normalization convention.

The environment otherwise has credible endpoint texture. User applications, server roles, maintenance processes, AV activity, updates, scheduled tasks, administrative commands, and malicious processes coexist without obvious global PID or hash corruption. The verdict therefore rests on concrete lifecycle and field contradictions, not on the attack’s compactness or the breadth of correlation.

## Synthetic Indicator Summary

| Category | Source family | Scope | Score impact |
|---|---|---:|---:|
| hard_contradiction | Sysmon/Security/eCAR RDP | All four visible Type 10 sessions on two hosts | Very high |
| hard_contradiction | Linux eCAR + PAM/logind syslog | Five sessions across four hosts | Very high |
| schema_or_format | Security 4624 | Ten FILE-SRV Type 3 records | Moderate |
| distribution_texture | Windows and Linux endpoint lifecycles | Multi-host collection boundary | High |

## Realism Score by Category

- **Field format accuracy:** 6/10 — Most fields are strong, but empty 4624 logon-process values, incorrect workstation identity, and contradictory Sysmon parent fields are material defects.
- **Temporal patterns:** 4/10 — Ordinary process timing is convincing, but multi-hour RDP `userinit.exe` lifetimes and boundary-convergent closures are strong synthetic indicators.
- **Cross-source correlation:** 8/10 — PID, image, PPID, command, hash, and attack correlations are excellent; the SSH and RDP contradictions prevent a higher score.
- **Behavioral realism:** 6/10 — User, service, update, AV, and administrator activity is credible, but RDP process lifecycle semantics are substantially wrong.
- **Environmental consistency:** 8/10 — Host roles and background endpoint activity are well differentiated.

## Recommendations

If synthetic:

- Make RDP and local interactive logons share the same native `userinit.exe` lifecycle: it should exit seconds after launching the user shell, while `winlogon.exe` and `explorer.exe` may persist.
- Render Sysmon parent fields from the canonical parent process: if ParentProcessGUID/PID identifies a visible `winlogon.exe`, populate its image, command line, and SYSTEM principal consistently.
- Carry one SSH session ID through PAM open/close and `systemd-logind` New/Removed records. Termination must select the active session associated with the closing sshd PID rather than a stale session for the same user or host.
- For Security 4624 Type 3 events, populate a valid `LogonProcessName` and derive `WorkstationName` from the source system when known; do not substitute the target file server.
- Add family-level validation for RDP transient-process duration, visible-parent field agreement, and SSH logind identity continuity.
- Preserve the existing PID, image, command-line, ProcessGUID, hash, and background-activity correlations, which are strong.

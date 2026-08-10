# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 78
**Synthetic-Confidence Score:** 67

## Executive Summary

The endpoint collection is technically strong: process identities, Security 4688/Sysmon 1 pairs, SSH authentication sequences, and the visible Security-log clear all correlate unusually well without obvious impossible attack ordering. However, repeated exact-duration session artifacts, highly templated SSH volume, fixed per-host Sysmon call traces, and a duplicated receiver-side SSH process around an SCP transfer provide multiple concrete distribution and lifecycle indicators that make the dataset more likely synthetic than production-derived.

## Evidence For Synthetic

- `[distribution_texture]` Five visible Windows network-logon pairs have an exact 1 ms lifetime: four on `DC-01` (2024-03-18 12:35:32.120/.121, 14:16:25.547/.548, 14:38:27.130/.131, and 16:24:28.150/.151 UTC) and one on `WS-MCHEN-01` (13:14:51.926/.927 UTC). The repeated exact floor appears across machine-account LDAP, anonymous SMB, and user SMB sessions rather than as a single odd capture.
- `[distribution_texture]` SSH activity is dominated by a small reusable persona/host matrix over only six hours. Linux syslogs contain 46 accepted public-key sessions for `marcus.chen`, 43 for `aisha.johnson`, and 16 for `lina.nguyen`; eCAR repeats `sshd: <user> [priv]` 47, 46, and 23 times respectively. This volume and vocabulary are conspicuously repetitive for interactive-looking sessions across unrelated mail, web, proxy, application, and database hosts.
- `[distribution_texture]` Sysmon Event 10 uses one invariant Defender call trace per host for every sampled `MsMpEng.exe` process access, while the offsets change to a different apparently arbitrary template on every host. Examples include 38 identical instances on `DC-01` (`ntdll.dll+9C4AB|KERNELBASE.dll+2E9B8|advapi32.dll+4C156`), 15 on `MAIL-FIN-01` (`+9C756|+2D451|+4B0E1`), and eight on `WS-PPATEL-01` (`+9E84F|+2D123|+4A462`). Relative offsets are build/code-path properties, not ASLR addresses; perfect within-host constancy combined with fleet-wide one-off variation looks parameterized.
- `[contract_gap]` The SCP receive on `APP-INT-01` creates two consecutive receiver-side sshd processes for one tuple/session: PID 980770 at 17:20:00.924 and PID 980771 at 17:20:01.780, both parented directly to daemon PID 36202 and both initially labeled `sshd: root [priv]`. Syslog attributes the connection/auth/session to PID 980771, while the received file at 17:20:06.407 is attributed to PID 980770 (whose eCAR command line has changed to `sshd: root@notty`); only PID 980771 has a visible termination at 17:20:21.049. OpenSSH privilege separation can involve multiple processes and process-title changes, but the two sibling `[priv]` creates split across session and file ownership form an implausibly modeled lifecycle.
- `[distribution_texture]` Initial eCAR module loads are heavily quantized into millisecond-scale template bursts: among 575 process/module groups, 635 adjacent module records are 1 ms apart, 452 are 2 ms apart, and 283 are 3 ms apart. Repeated ordered subsets such as `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `rpcrt4.dll`, and `bcryptprimitives.dll` recur across many independent `ssh.exe` instances, giving the endpoint feed a rendered rather than collector-driven texture.
- `[environment_or_collection_plausibility]` The same generic maintenance commands recur broadly across unlike endpoints: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\service-health.ps1` appears 11 times and `backup-check.ps1` seven times on workstations and a mail server, while Linux systems contribute 88 identical `debian-sa1 1 1` children and 88 identical shell wrappers. The cron pattern is individually plausible, but the combined cross-fleet command vocabulary is narrow for the observed host diversity.

## Evidence For Real

- Security 4688 and Sysmon Event 1 process-create pairs are excellent. Across nine Windows hosts, 988 of 993 Security creates had a matching Sysmon record by PID/image; command lines and parent PIDs agreed in every matched pair, and source timestamp differences were varied (generally about -22 to +21 ms rather than a fixed offset).
- Process and session state is largely causally sound. No visible eCAR child referenced a parent created later, no dependent event used a parent after its visible termination, all event files were timestamp-sorted, and no paired process or session lifecycle had negative duration.
- The Linux SSH source-native sequences are convincing. For example, `MAIL-CLIN-01` shows connection at 12:03:13.679, public-key acceptance at 12:03:15.924, PAM open at 12:03:16.079, and logind session creation at 12:03:16.641; eCAR carries the same tuple `10.10.1.31:61164 -> 10.10.2.26:22`, user, PID, and shell ancestry.
- The malicious-looking SCP/database sequence preserves credible host artifacts: `DB-PROD-01` creates `/tmp/rpt_0318.sql`, compresses it, reads it through `scp`, and `APP-INT-01` records the receiving SSH session and `/tmp/.cache/rpt_0318.sql.gz`. The receiver syslog orders connection, public-key acceptance, PAM open, logind session, close, and removal coherently.
- The `DC-01` Security-log clear is unusually well represented. `cmd.exe /c wevtutil cl Security` and child `wevtutil.exe` appear at 17:41:47.603 and 17:41:48.013, Event 1102 follows at 17:41:49.021 with correct `Microsoft-Windows-Eventlog` provider and `LogFileCleared` UserData, and the Security `EventRecordID` resets from 28262119 to 1. This is concrete, source-native behavior rather than a superficial attack label.
- Windows background activity has meaningful host texture: service logons, network logons, lock/unlock events, Defender process access, DNS and firewall events, browser/Office processes, module loads, and terminations vary materially by host rather than appearing as one identical workstation image.

## Detailed Analysis

The visible collection spans approximately 12:00-18:00 UTC on 2024-03-18 and covers nine Windows hosts with Security/Sysmon/eCAR plus nine Linux hosts with syslog/eCAR. Windows Security volume is role-sensitive: `DC-01` has 7,652 records dominated by 4,394 Event 5156 records, 1,223 Event 4769 records, 542 Event 4768 records, and 535 Event 4624 records; workstations are much smaller and primarily contain process, firewall, and limited logon telemetry. That asymmetry is credible for a domain controller.

Process correlation is the strongest part of the dataset. Security 4688 and Sysmon 1 preserve hexadecimal versus decimal PIDs correctly, agree on image, command line, and parent, and use distinct but nearby source timestamps. The sampled `WS-AJOHNSON-01` Google updater create at 12:01:51 has PID 5232 / `0x1470`, parent services PID 4284 / `0x10bc`, SYSTEM identity, and matching eCAR actor ownership. Process termination coverage is incomplete at both collection boundaries, but the bounded six-hour window explains visible pre-window terminations and unclosed long-running processes; I did not score those as synthetic.

Logon correlation is also generally credible. Domain-controller network logons are dominated by Type 3, with service Type 5 and a small number of Type 10 sessions. Workstations include Type 2, 3, 5, 7, and 10 where appropriate. The concern is not missing closes at the right boundary; it is the exact 1 ms lifetime repeatedly assigned to five unrelated network logons. A 1 ms authentication can occur, but repeated `.timestamp`/`.timestamp+1` pairs across LDAP and SMB look like a minimum-duration rule.

Sysmon schemas are mostly persuasive. Event 1 contains expected version metadata, hashes, LogonId, TerminalSessionId, IntegrityLevel, parent fields, and ProcessGuid. Event 3 uses sensible endpoint fields and port names; Event 10 includes source/target identities, access masks, users, and call traces. The main Event 10 authenticity concern is statistical: each host receives exactly one call-trace template for all Defender accesses, yet each host's relative offsets are different. A mixed-patch fleet could explain some variation, but the observed one-template-per-host pattern is stronger than ordinary code-path diversity.

Linux syslog is rich enough to look lived-in: SSH/PAM/logind, sudo open/close, cron, resolver fallback, rsyslog queues, IRQ balancing, snap updates, multipath, desktop services, DHCP, and mail daemons are present. The SCP receive sequence on `APP-INT-01` is temporally good at the syslog level. The eCAR representation of that same session is weaker because it duplicates the privileged sshd receiver process and divides lifecycle ownership between PIDs 980770 and 980771.

User behavior is differentiated at a broad level—administrative SSH is concentrated in Aisha/Marcus/Lina, while workstation software differs by user—but the long tail is shallow. The frequency table is led by paired `debian-sa1` commands, a few Windows task/service commands, and the same `sshd: <user> [priv]` strings. This does not create an impossible incident, but it makes independent systems look sampled from compact reusable pools.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `distribution_texture` | eCAR/Windows logons | Five sessions on two hosts | Exact repeated 1 ms lifecycle floor is a strong generator-like timing artifact. |
| `distribution_texture` | Linux syslog/eCAR | Dataset-wide | Small persona/host SSH matrix produces 100+ accepted sessions with highly repeated process titles. |
| `distribution_texture` | Sysmon Event 10 | All nine Windows hosts | One fixed Defender trace per host, but arbitrary-looking different offsets across hosts. |
| `contract_gap` | Linux eCAR/syslog | One high-value SCP receive | Duplicate sibling privileged sshd processes split session and file ownership. |
| `distribution_texture` | eCAR module telemetry | Hundreds of records | Quantized 0-3 ms template bursts and repeated ordered module subsets. |
| `environment_or_collection_plausibility` | Windows/Linux process telemetry | Repeated across roles | Narrow generic maintenance-command vocabulary relative to host diversity. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Security, Sysmon, syslog, and eCAR fields are generally source-appropriate; no broad parsing defect was found.
- **Temporal patterns:** 6/10 — Most chains order correctly, but exact 1 ms logon pairs and quantized module bursts are conspicuous.
- **Cross-source correlation:** 8/10 — Process, SSH, and log-clear pivots are strong, with the SCP receiver process split as the main exception.
- **Behavioral realism:** 6/10 — Role differentiation exists, but SSH and maintenance behavior reuse compact pools at high frequency.
- **Environmental consistency:** 7/10 — Host volumes broadly fit server/workstation roles, though cross-fleet command and trace templates remain artificial-looking.

## Recommendations

- If this were synthetic, replace the 1 ms network-logon minimum with source-native, service-dependent duration distributions and verify LDAP, SMB machine-account, anonymous, and user-network sibling paths.
- Model receiver-side OpenSSH process ownership as one coherent hierarchy: listener -> privileged monitor -> session child, with the accepted tuple, syslog PID, file writer, process title changes, and termination attached to the appropriate processes.
- Derive Sysmon call traces from OS/build plus code path rather than a per-host template. Hosts on the same build should share valid relative offsets, while distinct access paths on one host should sometimes differ.
- Broaden administrative SSH behavior by user, destination role, authentication method, command/session duration, and frequency. Preserve legitimate automation, but avoid dozens of interactive-looking sessions from the same two principals to nearly every Linux role in six hours.
- Add jitter and collector/source-timing behavior to initial module bursts, and increase image-specific variation in ordered module subsets without breaking process identity correlation.
- Expand maintenance command pools by host role and software inventory so domain controllers, mail servers, user workstations, and Linux application/database hosts do not repeatedly draw the same small set of scripts and commands.

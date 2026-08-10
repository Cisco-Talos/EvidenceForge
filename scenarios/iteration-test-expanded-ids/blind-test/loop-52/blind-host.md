# Host/EDR Forensics — Authenticity Assessment

## Verdict

- Assessment: **Synthetic**
- Verdict Confidence: **79%**
- Synthetic-Confidence Score: **68/100 — likely synthetic**

## Executive Summary

The host evidence is technically sophisticated and internally plausible, but fleet-wide behavioral regularities indicate deterministic construction. Windows process, authentication, and Sysmon records exhibit strong source-native detail, while Linux SSH, cron, shell-history, and administrative activity reuse a conspicuously narrow behavioral grammar across many unrelated systems.

The strongest synthetic signal is not correlation completeness or collection boundaries; it is repeated actor-role and activity-template structure across the fleet. The dataset remains substantially more realistic than simple event fabrication.

## Evidence For Synthetic

- **Fleet-wide administrative homogeneity:** `marcus.chen` and `aisha.johnson` dominate SSH activity across APP, DB, mail, proxy, and web systems. Repeated sessions use the same small command vocabulary: `journalctl`, `systemctl`, `ss`, `stat /etc/passwd`, resolver checks, auth-log greps, and generic resource inspection.
- **Mechanically phased cron execution:** `debian-sa1 1 1` occurs at almost exact 1,800-second intervals per Linux host, with stable host-specific minute phases and only occasional skipped slots. Examples include APP-INT-01 at approximately `12:00:01`, `12:30:02`, `13:00:01`, and so on.
- **Template-like Windows process populations:** Identical command lines recur at high fleet-wide counts, including 60 `WmiPrvSE.exe -secured -Embedding`, 46 `taskhostw.exe /Run`, 44 `wsqmcons.exe`, and repeated fixed `dllhost.exe /Processid:{...}` variants.
- **Overgeneralized interactive administration:** Human users repeatedly access nearly every server role during the same short period. The behavior resembles broad persona-to-host sampling more than naturally concentrated operational ownership.
- **Command-pool artifacts:** Linux histories mix highly generic diagnostics in short, isolated sequences. Similar interchangeable commands appear under different people and system roles without much durable task context.
- **Synthetic-looking PID progression:** Linux PIDs advance smoothly by thousands between recurring events on multiple hosts, while the visible telemetry contains comparatively little process activity explaining that churn. Hidden activity is possible, but the same texture across the fleet is suspicious.
- **Curated behavioral breadth:** Windows endpoints repeatedly exhibit a broad application inventory—multiple browsers, cloud-drive clients, collaboration tools, VPN software, Citrix, and Office—with similarly structured launch/termination patterns across users.

## Evidence For Real

- **Strong process ownership semantics:** Process creation records preserve principal, PID, PPID, parent image, logon ID, session ID, and stable process identifiers. Child processes correctly reference their parent process identity.
- **Credible process chains:** A representative chain on WS-MCHEN-01 is `explorer.exe → powershell.exe → ssh.exe`, with consistent user ownership and logon context.
- **Lifecycle modeling:** Of 1,781 process creations, 1,488 have termination records; matched processes terminate after creation with host-appropriate lifetime variation.
- **Authentication detail:** Windows sessions include distinct Type 2, 3, 5, 7, and 10 semantics, machine accounts, service principals, source tuples, logon GUIDs, and paired short-lived network-session logoffs.
- **Linux session fidelity:** SSH activity includes privileged `sshd` children, shell processes, PAM/session records, and source-native syslog wording. Sudo open/close pairs preserve invoking and target identities.
- **Windows source fidelity:** Security and Sysmon XML includes credible providers, tasks, versions, keywords, record IDs, hexadecimal PIDs/logon IDs, ProcessGuids, hashes, and channel-specific field layouts.
- **Realistic record-number behavior:** Security and Sysmon record IDs are monotonic with plausible gaps. DC Security resets to record 1 in conjunction with Event 1102, consistent with a cleared audit log.
- **Nonuniform lifetimes:** Median matched process lifetime varies materially by host—from roughly 2–8 seconds on several Linux systems to hundreds or thousands of seconds on interactive Windows endpoints.

## Detailed Analysis

### Process execution and ownership

Windows evidence is the strongest part of the dataset. Parent images, PPIDs, principals, session identifiers, and process UUIDs generally form credible ownership chains. Service-owned processes remain under SYSTEM, while interactive applications inherit user contexts. Process termination timing is variable rather than fixed.

Linux SSH children appropriately execute as root before transitioning into user shells. However, the same few identities account for unusually broad administration across different server functions.

### Authentication and sessions

Windows Type 3 activity is concentrated on the domain controller and file server, while Type 5 service logons appear on Windows infrastructure and endpoints. Short network logons commonly receive prompt logoffs, whereas interactive sessions persist longer.

Linux PAM, `sshd`, `systemd-logind`, and shell evidence uses realistic vocabulary and ordering. The weakness is behavioral population modeling: session targets and command choices are too interchangeable across administrators.

### Temporal behavior

Recurring jobs have jitter at the millisecond level, but their higher-level cadence is strongly regular. The `debian-sa1` pattern is especially revealing: per-host phase offsets are realistic, yet the recurring 30-minute schedule is implemented with near-mechanical precision across the fleet.

Interactive process durations show useful variation, although many baseline process families repeat from a small collection of canonical lifetimes and command lines.

### Source-native fidelity

Security XML, Sysmon XML, ECAR JSON, syslog, and shell histories are syntactically convincing. Windows PID alignment, event identifiers, fields, and process hashes are plausible. Linux RFC-style syslog records include believable facilities, PIDs, PAM text, DHCP transitions, and service messages.

The primary authenticity deficit is therefore behavioral, not structural.

## Synthetic Indicator Summary

- Fleet-wide reusable administrator and command pools
- Near-periodic recurring-job schedules
- Repeated canonical Windows process command lines
- Excessively broad host access by a small set of people
- Generic, interchangeable shell-work patterns
- Similar background-activity texture across different host roles

## Realism Score by Category

| Category | Score |
|---|---:|
| Process trees and ownership | 8/10 |
| Authentication and session behavior | 7/10 |
| Lifecycle and temporal realism | 6/10 |
| Persona/host-role realism | 5/10 |
| Source-native host telemetry | 8/10 |

## Recommendations

- Give each administrator a narrower, role-based host-access graph and reserve cross-fleet access for explicit incidents or on-call activity.
- Replace shared diagnostic-command pools with persona-, host-role-, and task-specific workflows that maintain working-directory and command-history continuity.
- Derive recurring jobs from realistic host configuration, including per-package defaults, missed executions, downtime, and configuration changes.
- Expand persistent process-tree state so background PID churn is supported by visible or intentionally modeled process populations.
- Diversify Windows software inventory and recurring process families by department, endpoint age, patch state, and user role.
- Model multi-command administrative sessions as coherent objectives rather than independent command samples.

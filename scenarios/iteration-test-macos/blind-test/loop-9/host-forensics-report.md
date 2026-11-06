# Loop 9 Blind Authenticity Review — Host / EDR Forensics

## Verdict

**Leans synthetic, with a substantial real-like host telemetry layer.** The logs show believable host-native process, session, and cross-source relationships. A coordinated, highly explicit persistence and cleanup sequence on DC-01 is the strongest synthetic-looking feature, though it is also a plausible record of an actual intrusion. One odd Windows credential-use record targets a macOS host through `mstsc.exe`; it is inconclusive without a corresponding connection record.

## Verdict Confidence (0-100)

**65**

## Synthetic-Confidence Score (0-100, lower is more production-like)

**68**

## Executive Summary

The host evidence has good operational texture across Windows, Linux, and macOS. Process creation and termination records, Windows Security and Sysmon views, Unix shell histories, macOS Endpoint Security records, and eCAR objects commonly agree on process identities and timing. Examples include a macOS SSH command represented in shell history, eCAR process execution, and a matching TCP/22 flow, and a Windows RDP flow whose source port and time agree with a Type 10 logon.

The clearest synthetic-leaning evidence is a compact, unusually explicit DC-01 sequence: a SYSTEM-context command creates `svc_dirsync` with a literal password, adds it to Domain Admins, installs a service and scheduled task, clears the Security log, then deletes the account. Each operation has corroborating process or Windows Security records, so this is not merely narrative ordering; the exact, unusually complete operator-style trace is the concern. Those same details would also be important evidence in a genuine compromise.

A separate Linux workstation shows a coherent but sensitive support-log archive and upload to an external health-support hostname through the corporate proxy. Host process, file, command-history, and proxy-flow evidence support one another. This looks like plausible activity that merits investigation, rather than an artifact-level contradiction.

## Evidence For Synthetic

- **Highly explicit DC-01 persistence and cleanup.** At 17:14:45–17:14:50 UTC, eCAR records `cmd.exe`/`net.exe` commands creating `svc_dirsync` with a literal password and adding it to Domain Admins. Security 4720, 4724, and 4728 follow at 17:14:49–17:14:54 UTC, with SYSTEM as the subject. At 17:19–17:20 UTC, eCAR records service and scheduled-task creation; Security 4697 and 4698 corroborate them. At 18:41:49 UTC, eCAR records `wevtutil cl Security`, followed by Security 1102 at 18:41:53 UTC. At 18:50 UTC, eCAR and Security 4726 show the account being deleted. The exceptionally specific and end-to-end instrumented sequence is a synthetic signal, although each individual action is feasible in real incident data.
- **A Windows 4648 target is unusual.** On WS-AJOHNSON-01 at 15:21:03 UTC, Security 4648 records `mstsc.exe` using credentials for `maya.ross` against `MAC-MROSS-01`. The inspected host eCAR flow entries do not show a matching TCP/3389 flow to that Mac. This is a plausibility concern, not a proven contradiction: 4648 records explicit credential use, not a successful RDP session, and log coverage can omit a connection.
- **Linux support upload merits scrutiny.** On WS-LNGUYEN-01, shell history records archiving EHR connector logs and submitting the archive to `support.valeworks-health.net` over an HTTP URL via the corporate proxy. eCAR independently records tar creation, the archive write, curl execution, and a read of that archive. The behavior is coherent but highly specific and sensitive; it should not be treated as routine without organizational context.

## Evidence For Real

- **Windows event families have ordinary lifecycle shapes.** Across the inspected Windows hosts, Security 4688/4689 and Sysmon 1/5 counts are broadly close, consistent with process creation and termination observations over a bounded capture. No claim is made that every process must be present in each source.
- **RDP source-port correlation is concrete.** On WS-AJOHNSON-01, eCAR records inbound TCP/3389 from `10.10.1.99:50545` at 15:59:37 UTC. Security 4624 records a Type 10 logon from the same source port at 15:59:42 UTC. Nearby failed connection records make the successful session more operationally plausible than a lone isolated event.
- **Windows process ancestry is rendered coherently.** On WS-MCHEN-01, a PowerShell eCAR process has `explorer.exe` as parent and the same user/logon context as the corresponding Security 4688 record. Typical process image paths and Windows session fields are present.
- **macOS records include native process transitions.** Endpoint Security NDJSON uses audit tokens, PID versions, exec transitions, and UID changes. eCAR records corresponding fork/exec/privilege-drop behavior rather than presenting every change as a fresh unrelated process.
- **Mac SSH evidence is mutually plausible.** On MAC-MROSS-02, the 13:05:36 UTC `zsh_history` SSH command to WEB-EXT-01 aligns with eCAR's `ssh` exec and a TCP/22 flow from `10.10.1.42`. Other visible Mac SSH sessions similarly carry plausible source tuples and user identities.
- **The Linux archive workflow is corroborated at host level.** The shell-history command, eCAR tar and curl processes, file creation/read, and proxy-directed network flows agree on the user, archive path, and sequence. The proxy flow explains why the endpoint's visible destination is the internal proxy rather than the external hostname.
- **Timestamps have useful variation and source-specific precision.** The bundle spans about six hours on 2026-11-02, with milliseconds in eCAR, higher precision in Windows event timestamps, and nanosecond-style timestamps in macOS Endpoint Security. Similar windows can reflect a capture boundary and are not used alone as evidence of synthetic origin.

## Detailed Analysis

### Windows process, logon, and administration behavior

The Windows Security and Sysmon files contain common process, network, authentication, and file observations. Their counts are substantial on domain controllers (for example, DC-01 has 139 Security 4688 events and 138 Security 4689 events, alongside 138 Sysmon Event ID 1 and 138 Event ID 5 records). That pairing is plausible for a six-hour sample and does not establish synthetic origin by itself.

The DC-01 account/service sequence is the most concerning host story. eCAR exposes the exact `net user` password and `net group` commands under SYSTEM, while Security records the resulting account creation, password set, and Domain Admins membership. eCAR then records `sc.exe` and `schtasks.exe` commands for `DeviceSyncSvc`; Security records service installation and a task with the same executable and hourly trigger. Later, the Security log is cleared and the account is removed. This is strong evidence of a real-looking compromise sequence, but the unusually complete, deliberately named artifacts and the synchronized record coverage lean synthetic. The source logs do not prove whether SYSTEM context arose through remote WMI, scheduled execution, or another mechanism.

On WS-AJOHNSON-01, explicit-credential records include administrative and remote-support activity. The `mstsc.exe` record targeting a Mac is atypical, but it does not prove a successful RDP session. By contrast, the inbound TCP/3389 record and Type 10 logon from `10.10.1.99:50545` agree within seconds and match the source port. I treat the latter as positive evidence of credible cross-source behavior.

### Linux shell and process evidence

The bash histories contain ordinary administration and development commands, with varied inter-command intervals. On WS-LNGUYEN-01, history records `tar` of `/var/log/ehr-connector/connector.log` and `queue.log`, then a `curl` multipart upload for ticket MHS-48217. eCAR records the tar process and archive write around 16:32:28–16:32:32 UTC, curl around 16:32:47 UTC, and a read of `/tmp/mhs-support-48217.tar.gz` shortly before curl terminates. Flow records point to the internal proxy on port 8080. This is a strong, internally consistent artifact chain; its security significance depends on whether this destination and transfer were authorized.

On DB-PROD-01, the `root` history records a database dump, compression, and `scp` to `10.10.2.30`. eCAR records a root SSH session from `10.10.2.30`, then `mysqldump`, gzip, archive writes, and the SCP flow/read. The process and file timing fits the visible shell actions. The archive contents and destination deserve review because the tables are named `patients` and `insurance_claims`, but no host-visible contradiction was found.

### macOS host evidence

Both Macs show local Maya Ross sessions, shell histories, SSH commands, process exec transitions, and matching transport flows. Endpoint Security records preserve process ancestry and UID transitions; eCAR process objects use `MODIFY` for exec/credential changes and `CREATE` for forks. Unified-log entries include login-window messages and accepted SSH authentication records. The unified logs are sparse relative to eCAR, but sparse source coverage alone is not treated as an authenticity defect.

### Field and timing review

The reviewed examples preserve sensible parent/child image relationships and user/logon IDs. eCAR process times precede dependent file or flow records in the examples inspected. Windows Type 10/Type 3 source addresses and port values look source-native, and the matched RDP tuple is a positive correlation. The Mac-targeting `mstsc.exe` credential record remains the only notable platform/tool mismatch found in the reviewed cases; absence of a corresponding connection is not elevated to a definitive contradiction.

## Synthetic Indicator Summary

| Category | Indicator | Strength |
|---|---|---|
| Admin / persistence | DC-01 has a single unusually explicit account-to-Domain-Admins, service, task, log-clear, and account-delete sequence | Strong, but compatible with a genuine intrusion |
| Cross-platform plausibility | `mstsc.exe` explicit-credential record names a macOS target without an observed matching TCP/3389 flow | Weak to moderate; not proof of a successful session |
| Sensitive host activity | EHR diagnostic archive is uploaded to an external support hostname | Security-relevant, but corroborated and not intrinsically synthetic |
| Volume / distribution | Domain controller network and authentication volume is high but not clearly implausible for the sample window | Weak / neutral |
| Cross-source correlation | Several process, session, and network records agree across sources | Counted as evidence of realism; correlation alone is not treated as synthetic |
| Coverage gaps | Some source files are sparse or absent on hosts | Not counted without a concrete contradiction |

## Realism Score by Category

Scores estimate how production-like the host evidence appears (0 = very synthetic-looking, 100 = highly production-like).

| Category | Score |
|---|---:|
| Windows process and session semantics | 75 |
| Windows administration and persistence activity | 52 |
| Linux process, file, and shell behavior | 79 |
| macOS Endpoint Security and session behavior | 82 |
| eCAR process/network correlation | 84 |
| Timing and source-native fields | 78 |
| Overall host evidence | 72 |

## Recommendations

- For a real environment, preserve DC-01 Security, Sysmon, and eCAR data; verify the `svc_dirsync` creation and group change, `DeviceSyncSvc` artifacts, log clear, and account deletion against change-management and administrative records. Rotate any exposed credential if this host is real.
- Confirm the WS-LNGUYEN-01 support ticket and external upload with the EHR connector owner and proxy records; the endpoint records show a sensitive archive being read by curl and sent through the proxy.
- Check whether MAC-MROSS-01 runs an RDP-compatible service and whether an RDP attempt was expected. Treat the 4648 record as credential use until a successful session is independently established.
- For future authenticity review, retain host-local command and parent context for unusual remote-administration events. Keep source-native timestamps and identity/tuple fields so that genuine lifecycle agreement remains inspectable without relying on narrative sequence alone.

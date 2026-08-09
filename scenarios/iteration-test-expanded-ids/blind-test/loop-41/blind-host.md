# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 67

## Executive Summary

The endpoint telemetry is technically strong: Windows Security, Sysmon, eCAR, and Linux syslog frequently agree on process identity, timing, sessions, and network tuples without visible causality reversals. The decisive synthetic indicator is a dataset-wide Windows service-logon lifecycle defect—316 Type 5 logons in six hours, including rapid churn on servers, with none receiving a visible 4634 logoff and with sampled logon IDs disconnected from any corresponding service/process lifecycle—combined with implausibly frequent updater-service recycling across the workstation fleet.

## Evidence For Synthetic

- `[contract_gap]` Across the nine Windows hosts, there are 316 successful Security 4624 Type 5 service logons—143 on `DC-01`, 67 on `MAIL-FIN-01`, and 59 on `FILE-SRV-01`—but zero of those 316 logon IDs has a visible 4634 termination. This is not just an edge-window orphan: server-side Type 5 sessions are created continuously throughout the window, with median host-local interarrival times of 103.5 seconds on `DC-01`, 191.4 seconds on `FILE-SRV-01`, and 212.6 seconds on `MAIL-FIN-01`; 71 intervals are under one minute and 13 are under ten seconds.
- `[contract_gap]` The Type 5 identities often have no visible service lifecycle beyond 4624 plus 4672. For example, `WS-AJOHNSON-01/windows_event_security.xml` records a SYSTEM Type 5 logon at `2024-03-18T12:33:28.6384456Z` with `TargetLogonId=0x25b316c`, followed 26 ms later by 4672, but that ID appears nowhere else in Security, Sysmon, or eCAR—no associated process/session use and no logoff. The same disconnected pattern recurs fleet-wide.
- `[distribution_texture]` Windows updater services recycle far too often for a six-hour slice. Across six Windows workstations there are 59 creates of just three updater binaries: 20 `AdobeARMservice.exe`, 21 `DropboxUpdate.exe`, and 18 `GoogleUpdater.exe`. On `WS-AJOHNSON-01`, five Adobe ARM service instances start between 14:29 and 16:31, six Google updater instances appear between 12:24 and 16:57, and two Dropbox updater instances start only 76 seconds apart at 17:04:49 and 17:06:05; many terminate after only 4–188 seconds. `WS-EBROOKS-01` and `WS-SMARTINEZ-01` show similar repeated short-lived restarts.
- `[distribution_texture]` The broader Windows background-process mix reinforces the churn texture. Across the Windows fleet, exact templates recur at high frequency, including 45 `svchost.exe -> wsqmcons.exe`, 42 `svchost.exe -> taskhostw.exe` with command `taskhostw.exe`, and another 42 with `taskhostw.exe /Run`. Standardized enterprise fleets do repeat binaries, but this narrow pool cycling dozens of times within six hours—alongside the unowned Type 5 sessions—looks modeled rather than organically scheduled.
- `[weak_signal]` Remote-administration activity is unusually concentrated in a small command pool: 60 Windows `ssh.exe` creations use exact `ssh.exe user@host` templates, including 11 identical Aisha-to-`MAIL-CLIN-01` commands and eight identical Marcus-to-`WEB-EXT-01` commands. This could represent a very active operations team and is not independently decisive, but it adds to the repeated-process texture.

## Evidence For Real

- Windows process correlation is excellent without being timestamp-identical. Across the Windows hosts, 890 Security 4688 events and 887 Sysmon Event 1 records produce 885 matching PID/image pairs; only five Security-only and two Sysmon-only creations remain. The 885 Security-minus-Sysmon time offsets contain 842 distinct values and range from approximately -179 to +23 ms, which resembles independent sensor timing rather than one copied timestamp.
- A concrete example on `WS-AJOHNSON-01` is the Dropbox updater PID 5188: Security 4688 occurs at `2024-03-18T12:04:22.5770170Z`, Sysmon Event 1 at `12:04:22.5834885Z`, and eCAR PROCESS/CREATE at `12:04:23.244Z`. All three agree on image, command line, PID, principal, and `services.exe` parent while retaining plausible collection latency.
- Sysmon ProcessGUIDs have credible host-specific structure. Each host keeps one stable machine prefix—for example `fd907e59` on `WS-AJOHNSON-01`—while the encoded creation-time component agrees with the Event 1 timestamp. Hashes remain stable for a given image within each host.
- Visible eCAR process causality is coherent. I found no dependent record whose `actorID` points to a process created later, no actor-attributed record after that process’s termination, and no matched PROCESS/TERMINATE preceding its PROCESS/CREATE. Unmatched starts and exits sit naturally at collection boundaries.
- Network-logon lifecycle is much stronger than the service-logon lifecycle. `DC-01` has 414 Type 3 logons and 409 matching logoffs; `FILE-SRV-01` has 299/299; `MAIL-FIN-01` has 39/39. Visible matched logoffs do not precede their logins.
- Linux SSH evidence is detailed and source-native. On `APP-INT-01`, source `10.10.1.35:58919` connects at `2024-03-18T13:00:43.524174Z`, authenticates as `aisha.johnson` at `13:00:46.696395Z`, opens PAM at `13:00:46.819639Z`, and produces the corresponding eCAR login at `13:00:47.227Z`; its later PAM close and eCAR logout agree near `14:01:33`. Other sessions mix password/public-key authentication, failures, invalid users, PAM, and systemd-logind records.
- The Linux host families are environmentally differentiated: mail hosts contain Postfix/Dovecot activity, external web telemetry includes UFW scan noise, Linux workstations contain NetworkManager, dhclient, GNOME, packagekit, and desktop services, while servers contain rsyslog, irqbalance, sudo, cron, snapd, and host-role-specific processes.

## Detailed Analysis

### Windows process trees and lifecycle

The principal Windows process trees are source-native and mostly credible: `services.exe` launches services and update agents; `svchost.exe` launches WMI, taskhost, and COM activity; `csrss.exe` launches `conhost.exe`; `SearchIndexer.exe` launches filter/protocol hosts; and interactive shells launch `ssh.exe`, `mstsc.exe`, MMC, browsers, and Office-adjacent tools. Parent UUIDs and `actorID` references in eCAR remain live at the dependent event time.

The strongest negative feature is not an impossible parent-child relation but excessive recycling. On `WS-AJOHNSON-01`, Dropbox update instances start at 12:04:23, 13:35:25, 17:04:49, and 17:06:05; Adobe ARM service starts at 14:29:20, 15:30:14, 15:49:07, 16:20:42, and 16:31:44. Comparable clusters recur independently on `WS-EBROOKS-01` and `WS-SMARTINEZ-01`. This creates a fleet-wide “background realism pool” signature.

### Security/Sysmon/eCAR alignment

Process creation alignment is a major strength. The near-complete 4688/Event 1 pairing preserves source-specific fields: Security uses hexadecimal NewProcessId and audit-token fields, Sysmon uses decimal PID, ProcessGUID, hashes, integrity, and parent GUID, while eCAR maintains durable object/actor IDs. Timing offsets are noisy rather than fixed.

Sysmon Event 5 termination data also aligns with Security 4689 and eCAR when all three observations exist. The dataset correctly permits a small number of source-local misses rather than forcing perfect equality.

### Logon sessions

Interactive, network, unlock, and remote-interactive records show reasonable source variation. Workstations contain Type 2, Type 7, and occasional Type 10 activity; DC and file-server Type 3 sessions are numerous and usually short-lived with paired 4634s. No visible same-ID logout-before-login contradiction was found.

Type 5 is qualitatively different. All 316 service logons are for `SYSTEM`, `LOCAL SERVICE`, or `NETWORK SERVICE`; all lack a 4634. On servers, the high rate means these cannot all be explained as a handful of pre-window services persisting beyond the window. The records also do not resolve into an intelligible service-start stream: on `DC-01`, examples at 12:04:29, 12:06:33, 12:07:32, 12:11:19, 12:13:41, 12:14:15, and 12:14:58 are separated from the next visible process creation by 44–308 seconds. This looks like independently generated service-logon noise rather than sessions owned by service actions.

### Linux endpoint evidence

The Linux syslogs use plausible RFC 5424 shapes, facilities, severities, PIDs, and host-specific daemon mixes. SSH records preserve source address/port across connection, authentication, PAM open, and close. Successful sessions have variable authentication delays and durations, and failure paths include both invalid-user and known-user failures.

`WEB-EXT-01`’s UFW block stream has believable per-source TTL/packet-length characteristics and broad destination-port scanning. Cron/sysstat repetition is expected scheduled behavior and was not treated as synthetic evidence. No impossible visible Linux session ordering was found.

### User and administrative behavior

The endpoint data distinguishes ordinary desktop processes from administrative tooling and preserves user principals through process and flow records. The volume of SSH/RDP activity is operationally possible, so I did not score linearity or ease of reconstruction. Its concern is narrower: exact `ssh.exe user@host` commands recur many times against a small host pool, adding weak support to the stronger repeated updater/system-process distribution finding.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | Windows Security / eCAR service sessions | Dataset-wide: 316 Type 5 logons, zero visible 4634s | High. This is a sustained lifecycle deficit, not merely a boundary orphan. |
| `contract_gap` | Windows Security / Sysmon / eCAR | Repeated: Type 5 IDs generally stop at 4624/4672 without owned service/process context | High. The semantic event is disconnected from the activity that should create and consume it. |
| `distribution_texture` | Windows process telemetry | Fleet-wide: 59 creates from three updater-service binaries in six hours | Medium-high. Frequencies and short lifetimes resemble a reusable noise pool. |
| `distribution_texture` | Windows background processes | Repeated across unrelated hosts | Medium. High reuse of a narrow set of exact process/command templates reinforces modeled texture. |
| `weak_signal` | Windows remote-admin process telemetry | Repeated but operationally plausible | Low. Concentrated exact SSH command reuse supports, but does not establish, the verdict. |

## Realism Score by Category

- **Field format accuracy:** 9 — Security XML, Sysmon fields, ProcessGUIDs, hashes, eCAR records, and Linux syslog are structurally convincing.
- **Temporal patterns:** 7 — Cross-source latency and visible ordering are good, but service-logon and updater-process churn are implausibly dense.
- **Cross-source correlation:** 9 — Process and SSH correlations are excellent, with realistic source-local misses and no observed actor-lifecycle reversal.
- **Behavioral realism:** 6 — Host roles and user tooling are credible, but repeated updater/system-process pools and remote-admin command reuse weaken the lived-in feel.
- **Environmental consistency:** 7 — Windows/Linux and server/workstation differentiation is strong; fleet-wide service-session behavior is the main inconsistency.

## Recommendations

- If this were synthetic, make Type 5 logons action-owned. Emit them only when a concrete service start requires a new service-account token, attach that logon identity to the service/process context where source semantics permit, and close it when the service token/session actually ends. Preserve long-running sessions when appropriate, but do not generate hundreds of independent unconsumed Type 5 identities.
- Reduce updater-service churn using per-product schedules and persistent lifecycle state. Dropbox update service should generally persist or run on a much lower cadence; Google/Adobe checks should follow product-specific scheduled-task timing, backoff, version state, and success/failure outcomes rather than repeated generic restarts.
- Broaden and role-condition Windows background activity while lowering recurrence of `wsqmcons.exe`, `taskhostw.exe`, and updater templates. Tie process creation to actual scheduled-task/service state so timing, logon sessions, processes, and termination records emerge from one lifecycle.
- Diversify remote-admin workflow only where operational state supports it: persistent shells, multiplexed sessions, scripted remoting, management platforms, and host-role-specific commands would reduce repeated one-command/one-session texture without adding arbitrary narrative noise.

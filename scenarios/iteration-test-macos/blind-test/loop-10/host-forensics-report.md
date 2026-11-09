# Host / EDR Forensics Analyst Report

## Verdict

Likely synthetic, with convincing host-level correlation in several high-value sequences.

## Verdict Confidence (0–100)

83

## Synthetic-Confidence Score (0–100; lower is more production-like)

81

## Executive Summary

The bundle contains plausible and internally coherent Windows, Linux, and macOS host evidence. Process create/terminate pairs, user sessions, and native Mac Endpoint Security sequences are generally well formed. The clearest real-like evidence is the macOS SSH session between MAC-MROSS-01 and MAC-MROSS-02: source and target records agree on the IP tuple and port, followed by a target login and matching logout, with native macOS process/session evidence around the activity.

The strongest synthetic indicators are unusually elevated Linux PID ranges across every Linux host examined, and a burst in which almost all remaining interactive and application processes exit within roughly one second on each Mac. Those patterns recur across hosts and are difficult to explain as ordinary host activity without a corresponding PID-churn explanation or shutdown evidence. The bundle looks like carefully correlated synthetic telemetry rather than unstructured production collection.

## Evidence For Synthetic

- **Linux PID allocation is uniformly very high across hosts.** Every observed Linux `PROCESS/CREATE` PID in the reviewed Linux eCAR files exceeds 100,000. Examples include APP-INT-01 at 2.93–2.99 million, DB-PROD-01 at 1.04–1.09 million, MAIL-CLIN-01 at 451,815–516,215, and WS-OHADDAD-01 at 4.03–4.09 million. The values are individually possible on systems configured for a large PID space, but the same elevated-range behavior across all Linux hosts is an unusual fleet-wide distribution and a strong synthetic cue.
- **Both Mac hosts have concentrated process teardown.** On MAC-MROSS-01, the zsh, Terminal login, Chrome helpers, Chrome, and Slack exit between 18:54:59.108 and 18:54:59.795 UTC. On MAC-MROSS-02, zsh/login, Chrome helpers, iTerm, Zoom, DBeaver, Word, Outlook, Chrome, and Terminal exit between 18:56:58.302 and 18:56:59.800 UTC. This resembles coordinated end-of-window cleanup more than natural process lifetimes. The nearby user logouts make a session close plausible, but the synchronized exits of unrelated apps on both Macs remain conspicuous.
- **Process/session activity has highly regular authored rhythms.** The Mac histories and Endpoint Security records repeatedly pair shell commands with short-lived fork/exec/exit sequences, while endpoint inventory and user application launches recur in a compact modeled window. Individual sequences are credible; the repeated, coordinated cadence across the two otherwise independent Macs is less production-like.
- **Linux process IDs cluster in narrow, host-specific bands.** The reviewed hosts have ranges such as roughly 2.66–2.74 million on FILE-LNX-01 and 2.94–3.00 million on WS-LNGUYEN-01, with many sequential or near-sequential values. This pattern, combined with elevated IDs on every Linux host, suggests assigned or generated PID bands rather than naturally mixed uptime/churn histories.

## Evidence For Real

- **The Mac SSH exchange is unusually well correlated.** At 14:24 UTC, MAC-MROSS-01 records outbound TCP/22 from `10.10.1.41:50952` to `10.10.1.42`; MAC-MROSS-02 records the matching inbound tuple. The target then records Maya Ross's successful SSH login from that source and a corresponding logout. The unified log reports an accepted keyboard-interactive/PAM login from `10.10.1.41:50952`, and Endpoint Security shows the sshd/sshd-session/auth/session/shell chain. This agreement includes the source port and ordering, not just a shared narrative.
- **macOS Endpoint Security process chains preserve native semantics.** The Terminal session includes launchd, xpcproxy, Terminal, login, zsh, command execs, and exits with coherent parent PID relationships. The remote SSH sequence similarly contains sshd wrappers, sshd-session, auth/session processes, and a shell. The event records include realistic audit-token, executable, cwd, TTY, signing, and argument detail.
- **Windows endpoint evidence has believable source-native structure.** Sysmon includes common process create/terminate, network, DNS, process-access, image-load, registry, and file activity. eCAR uses matching Windows paths and host principals; ordinary service and desktop process behavior is represented alongside interactive and administrative activity.
- **Linux host artifacts are operationally plausible.** The eCAR streams contain shell, cron/systemd, syslog, network, file, and session behavior, while bash histories include ordinary discovery and administrative commands. Process create/terminate coverage is broadly balanced in the visible window.
- **Lifecycle and timing are mostly credible.** Many process creates have corresponding termination evidence, sessions have paired closure where both ends are visible, and the Mac Endpoint Security timeline agrees closely with eCAR event time. The observed SSH session durations and source/target ordering are plausible.

## Detailed Analysis

### Windows

The Windows hosts expose both Sysmon XML and eCAR. Sysmon event distributions include event IDs 1 and 5 for process create and termination, plus network connection, DNS query, process access, image load, registry, and file events. The populated paths, principals, parent images, and service identities are generally consistent with Windows conventions. DC hosts have substantial network and authentication-related activity; workstation/server records show a mix of interactive processes and background services.

The review did not find a standout host-local contradiction in the sampled Windows process/session evidence. Process-access and remote-thread events are sensitive signals but can be legitimate or malicious in real environments; their presence alone does not indicate synthetic origin. The host-specific process telemetry looks more realistic than the Linux PID distribution and Mac shutdown clustering.

### Linux

Linux eCAR and syslog records include plausible cron, systemd, user shell, service, file, network, and SSH-like behavior. Shell histories show recognizable command use. The principal concern is PID distribution: all inspected Linux process creates use very high IDs, concentrated into narrow host-specific bands. That remains possible under high PID churn and a large `pid_max`, so it is an indicator rather than a hard impossibility, but seeing the pattern across every Linux endpoint reduces production plausibility.

### macOS

The two Mac endpoints provide the richest host-local evidence. Their eCAR records align with Endpoint Security fork, exec, and exit events, including detailed process lineage and native application paths. Login sessions are represented with local and SSH session types. The first SSH session from MAC-MROSS-01 to MAC-MROSS-02 is coherent across source flow, target flow, eCAR session, unified log, and Endpoint Security.

The principal anomaly is at the end of the capture: each Mac closes a large set of unrelated processes in a sub-two-second interval. This may be an intentionally modeled session or capture boundary, but the records resemble a mass teardown, and there is no equally clear host shutdown sequence in the reviewed endpoint event tail to explain it. The target Mac's last exits occur just before its local logout, which partially mitigates but does not remove the concern.

### eCAR and timing

The eCAR records generally carry plausible host identity, principal, process path, and source/destination fields. The Mac endpoint event timestamps and matching eCAR process sequence agree at sub-second granularity. The SSH tuple is carried consistently across the initiating Mac, receiving Mac, and target session telemetry. This is strong positive evidence of careful event construction. I did not treat cross-source alignment by itself as proof of production origin; the positive finding is specifically the plausible host-local process/session semantics and matching transport-to-auth timing.

## Synthetic Indicator Summary

| Category | Indicator | Strength |
|---|---|---:|
| PID distribution | All observed Linux process-create PIDs exceed 100,000 and occupy narrow host-specific ranges | High |
| Host lifecycle | Both Macs emit broad application and shell exits within about one second | High |
| Timing / cadence | Repeated compact shell and inventory activity patterns across the two Mac endpoints | Medium |
| Windows host semantics | No strong local contradiction identified; records look plausible | Low synthetic evidence |
| macOS native evidence | Detailed, internally coherent native process records support realism | Strong real-like evidence |
| Cross-source host correlation | Matching Mac SSH source port, tuple, login, and logout | Strong real-like evidence |

## Realism Score by Category

| Category | Score (0–100) | Assessment |
|---|---:|---|
| Windows process and session semantics | 84 | Broad, source-native process/network telemetry with plausible identities and paths |
| Linux process and session semantics | 65 | Plausible behavior, but fleet-wide elevated PID bands are conspicuous |
| macOS process and session semantics | 82 | Rich native process chains and SSH evidence; mass exit bursts lower realism |
| Host-local lifecycle | 72 | Most visible create/terminate and login/logout relationships are credible; Mac teardown is abrupt |
| eCAR correlation | 94 | Detailed host, tuple, principal, and process alignment, especially for Mac SSH |
| Timing and event order | 82 | Strong local sequencing and plausible SSH timing; repetitive end-window closure is artificial-looking |
| Shell and administrative behavior | 77 | Commands are recognizable and plausible; repeated modeled cadence and PID behavior show through |
| Overall host realism | 79 | High-quality correlated telemetry with repeatable distribution/lifecycle artifacts |

## Recommendations

1. Vary Linux PID allocation using host-specific uptime and churn profiles, including a realistic mixture of low and high process IDs within each host's configured PID range.
2. Avoid ending unrelated Mac applications and shells in one-second exit bursts. Model distinct application lifetimes and preserve an explicit shutdown or logout sequence when a host-wide termination is intended.
3. Vary Mac inventory and interactive activity schedules independently by host and user so repeated activity does not share the same compact cadence.
4. Keep the existing Mac SSH tuple-to-auth ordering and Endpoint Security parent/child semantics; they are among the bundle's most production-like host details.

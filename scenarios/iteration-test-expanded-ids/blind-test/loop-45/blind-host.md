# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 82
**Synthetic-Confidence Score:** 28

## Executive Summary

The host telemetry is strongly production-like: process trees, process lifecycles, logon/unlock semantics, Linux SSH/PAM sequences, and an audit-log-clear record all preserve source-native ordering and identity behavior without a concrete contradiction. The main reservations are distributional—the Windows Sysmon population totals exactly 4,096 records across nine hosts, and two users generate an unusually concentrated volume of interactive SSH sessions—but both have plausible collection or operational explanations and do not outweigh the endpoint realism.

## Evidence For Synthetic

- `[environment_or_collection_plausibility]` The nine Windows Sysmon XML files contain exactly **4,096** parsed events in aggregate (host counts: 348, 547, 390, 439, 573, 398, 585, 457, and 359). A power-of-two estate-wide total is an unusual natural stopping point and suggests an export/sample quota. Because the records remain temporally distributed through the full window and the per-host files are not individually capped, this is only a collection-plausibility concern, not a hard contradiction.
- `[distribution_texture]` SSH activity is unusually concentrated in two identities. Linux `sshd` records contain 47 visible session opens for `aisha.johnson` and 39 for `marcus.chen`, each spanning six server targets in six hours. Their monitored Windows clients create 33 and 38 `ssh.exe` processes, respectively; the remaining target sessions are accounted for largely by client processes already active at the left boundary. The timing is not mechanical (median inter-open gaps are about 307 seconds and 541 seconds, with broad session-duration ranges), but this is still a high and repetitive interactive-admin workload.
- `[weak_signal]` Several Windows hosts draw a large share of process creation from the same compact maintenance pool. For example, DC-01 records 18 `conhost.exe 0x4`, 14 `wsqmcons.exe`, 13 `WmiPrvSE.exe -Embedding`, and 12 `WmiPrvSE.exe -secured -Embedding` creates; FILE-SRV-01 similarly has 12 secured WMI providers, 11 `wsqmcons.exe`, and two eight-event `taskhostw.exe` variants. These are legitimate binaries and parentage is credible, so repetition alone carries little weight, but the pool is cleaner than many lived-in Windows estates.

## Evidence For Real

- Process identity and lifecycle behavior is unusually sound in the technically meaningful sense. Across **1,889 eCAR process identities**, I found no duplicate create, duplicate terminate, create/terminate PID-image mismatch, visible terminate-before-create, child creation after a visible parent termination, or overlapping reuse of a live PID. A second check found no eCAR file, flow, registry, module, or process-access event outside the visible lifetime of its referenced process.
- The same lifecycle checks held for all nine Sysmon sources: no Event 1/Event 5 ProcessGUID mismatch or inversion, no dependent Event 3/7/8/10/11/13/22 use before a visible create or after a visible terminate, and no child process created before its visible parent or after the parent's visible termination.
- A concrete Windows process chain is source-native and temporally coherent. On WS-PPATEL-01, Sysmon Event 1 creates PID 6220 (`powershell.exe`) at `2024-03-18T12:09:50.4071536Z`; Security 4688 records PID `0x184c` at `12:09:50.4167072Z`; eCAR creates the same principal/image/PID at epoch `1710763791412` (`12:09:51.412Z`). PID 6220 then parents PID 6244 `ssh.exe` at about `12:10:27`, and the child terminates before the parent. The small, non-identical source delays look like collection latency rather than copied timestamps.
- Windows session behavior includes proper lock/unlock texture. WS-PPATEL-01 records Event 4800 for logon ID `0xd80858b` at `14:47:58.867Z`, then Type 7 Event 4624 at `15:04:24.788Z` and Event 4801 at `15:04:25.354Z`. Reuse of the original interactive logon ID on unlock is correct, and multiple workstations show different numbers and timings of locks and unlocks.
- DC-01's Security-log clear is rendered with subtle native behavior: Event 1102 at `2024-03-18T17:42:18.8498896Z` uses the `UserData/LogFileCleared` shape with SYSTEM (`0x3e7`), resets `EventRecordID` from 28262434 to 1, and the following records continue at IDs 2, 3, and 5. That is a strong source-specific realism detail.
- Linux SSH evidence has complete, correctly ordered PAM/logind phases without bit-identical timestamps. APP-INT-01 PID 946596 records connection at `12:01:55.521828Z`, password acceptance at `12:01:57.717047Z`, PAM open at `12:01:57.767203Z`, logind session 376081 at `12:01:58.360389Z`, PAM close at `12:22:57.792880Z`, and logind removal at `12:22:58.880662Z`. Its eCAR `/usr/sbin/sshd` process lifetime (`12:01:54.911Z`–`12:22:59.506Z`) encloses the sequence.
- Linux background behavior varies by role: WEB-EXT-01 has 1,028 visible UFW blocks and web-server activity, mail hosts have Postfix families, DB-PROD-01 has sustained `multipathd` texture, and workstations show NetworkManager, DHCP, thermald, login, and account-daemon events. This is not a uniform source-family stencil.
- Slice-boundary artifacts are handled naturally. Some files begin with process terminations or SSH session closes whose initiators precede `12:00Z`; I treated those as neutral, and found no case where the same identity later acquired a contradictory visible create.

## Detailed Analysis

### Scope and reproducible volume checks

The visible endpoint window spans approximately `2024-03-18T12:00Z` through `18:00Z`. Parsed source totals were 25,329 newline-delimited eCAR objects across 18 hosts, 14,264 Windows Security events across nine hosts, 4,096 Sysmon events across the same nine hosts, and 4,271 syslog lines across nine Linux hosts. Event-ID distributions are role-sensitive: DC-01 carries 601 Event 4624 records, 536 Event 4768 records, 1,267 Event 4769 records, and 4,498 Event 5156 records, whereas Windows workstations are dominated by smaller process, network, logon, and lock/unlock populations.

I reproduced lifecycle results by grouping eCAR `PROCESS` records on `(hostname, objectID)` and Sysmon Event 1/5 records on `(Computer, ProcessGuid)`, then comparing create, dependent-event, child, and termination timestamps. The zero-anomaly result was not inferred from missing companions: identities already live before the left edge were excluded from any requirement for a visible create.

### Windows process and Sysmon realism

Parent-child choices are credible. User shells are commonly parented by `explorer.exe`; OpenSSH clients are parented by PowerShell; `svchost.exe` service processes are parented by `services.exe`; and WMI, COM surrogate, search, update, Office, browser, VPN, antimalware, and monitoring processes appear in host-appropriate combinations. Sysmon Event 1 supplies internally stable ProcessGUIDs, logon IDs, session IDs, hashes, integrity levels, and parent identities. Event 5 terminates the same GUID/PID/image identity, while network, file, module, registry, and access records stay inside visible lifetimes.

The binary hash population is neither random per event nor implausibly single-valued estate-wide. For example, all 73 visible `C:\Windows\System32\OpenSSH\ssh.exe` creates share one hash tuple, while core OS binaries such as `taskhostw.exe`, `WmiPrvSE.exe`, `conhost.exe`, and `dllhost.exe` have four stable hash variants distributed across hosts, consistent with a small set of OS/build images.

### Logon and session lifecycle

Successful Windows logons use plausible type mixes: workstation interactive/unlock sessions, service sessions, and server network sessions. Type 7 unlock records correctly reuse the existing interactive logon ID. DC and file-server network logons are commonly paired with short 4634 lifetimes, while workstation interactive sessions can extend beyond the slice. Failed 4625 attempts carry coherent status/substatus combinations and were not forced into logout lifecycles.

Linux SSH sequences consistently order transport arrival, authentication, PAM open, logind creation, PAM close, and logind removal. Authentication methods vary between password and public key by user and session. Session durations have broad ranges rather than fixed slots: `aisha.johnson`'s 47 fully visible open/close pairs range from about 34 to 3,574 seconds with a median near 1,260 seconds; `marcus.chen`'s fully paired sessions range from about 55 to 3,636 seconds with a median near 1,333 seconds.

### User and host behavior

User behavior is differentiated. Aisha Johnson and Marcus Chen use Windows PowerShell/OpenSSH heavily across infrastructure; Lina Nguyen's Linux client shows a more varied SSH command vocabulary (`-i`, `-A`, `-tt`, `ConnectTimeout`, and `ServerAliveInterval`); Omar Haddad's Linux workstation emphasizes local administration and sudo; other Windows users show Office, browsers, VPN, Dropbox, Adobe, and Google update activity. That role texture is supported by distinct server-side source families rather than only usernames or filenames.

The two dominant SSH users are the most synthetic-looking behavioral feature because of their volume and broad target coverage. However, target `sshd` sessions correlate to their actual source addresses (`10.10.1.35` and `10.10.1.31`), sessions overlap organically, and durations/inter-arrival gaps are highly variable. I therefore scored this as distribution texture rather than an ownership or timing contract gap.

### System lifecycle and collection behavior

Scheduled Linux sysstat events occur on native cron boundaries with small millisecond variation and occasional absent slots (for example, WS-LNGUYEN-01 lacks a `14:33` line between otherwise half-hourly runs), which looks more like source observation texture than a rigid generator loop. DNS-resolver degradation/recovery messages, IRQ balancing, snapd, DHCP renewal, package management, Postfix, multipath, and firewall noise give hosts distinct operational residue.

The exact aggregate Sysmon count of 4,096 is the principal unexplained collection artifact. It could readily be an extraction cap applied before per-host splitting, and there is no end-of-window truncation inside individual files. Still, because the study presents the sources as a dataset rather than documenting such a cap, it modestly raises synthetic confidence.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `environment_or_collection_plausibility` | Sysmon | Exactly 4,096 events across nine host files | Moderate: unlikely natural total, but plausible central export cap and no semantic contradiction |
| `distribution_texture` | eCAR + Linux syslog/sshd | 47 Aisha and 39 Marcus session opens across six targets each in six hours | Moderate-low: concentrated and repetitive, but timing, methods, durations, and client ownership are varied and coherent |
| `weak_signal` | Security 4688 + Sysmon 1 + eCAR PROCESS | Recurrent WMI/taskhost/conhost/wsqmcons pool across Windows hosts | Low: compact pool, but binaries, parents, hashes, principals, and lifetimes are source-native and credible |

No `hard_contradiction`, `contract_gap`, or `schema_or_format` indicator was found in the examined host/EDR data.

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Sysmon fields, eCAR identities, and RFC 5424-style syslog preserve source-native structure and values.
- **Temporal patterns:** 9 — Lifecycles and source delays are coherent, with no same-identity visible-ordering violation and substantial timing entropy.
- **Cross-source correlation:** 9 — Representative Windows and Linux processes agree on actor, PID, image, session, and lifecycle without impossible source ordering.
- **Behavioral realism:** 7 — Host/user roles differ credibly, but the concentrated high-volume SSH behavior and compact Windows maintenance pool remain noticeable.
- **Environmental consistency:** 8 — Server roles have distinct operational residue; the exact estate-wide 4,096-event Sysmon population is the main collection-plausibility blemish.

## Recommendations

- If this were synthetic, avoid power-of-two estate-wide source quotas, or expose an explicit export-limit marker so a 4,096-record Sysmon population reads as collection behavior rather than a generator boundary.
- If this were synthetic, reduce the concentration of interactive SSH in two identities or add more role-specific client command diversity for those users; preserve the existing variable durations, authentication methods, overlapping sessions, and correct left-boundary handling.
- If this were synthetic, broaden the long-tail Windows maintenance process population per host while retaining the current stable hash-per-image/build behavior and parent/child lifecycle correctness.

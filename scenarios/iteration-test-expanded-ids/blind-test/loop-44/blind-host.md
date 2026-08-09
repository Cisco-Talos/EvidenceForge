# Host/EDR Forensics Analyst — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 84
**Synthetic-Confidence Score:** 58

## Executive Summary

The host telemetry is unusually strong in field structure, lifecycle pairing, and Security/Sysmon/eCAR alignment, and several sequences would be credible in a production investigation. I nevertheless assess it as synthetic because of one impossible process-ownership relationship, reinforced by repeated endpoint behavior textures that look selected from shared pools rather than produced by independently lived-in systems.

## Evidence For Synthetic

- `[hard_contradiction]` On `WS-AJOHNSON-01`, PID 5232 (`0x1470`) is created as `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\backup-check.ps1` at `2024-03-18T12:44:20.3399696Z` in Security 4688 and `12:44:20.3523804Z` in Sysmon Event 1. Security 4689 ends it at `12:44:58.2715384Z`, Sysmon Event 5 ends the same ProcessGuid `{fd907e59-3724-65f8-5702-000044f48ae4}` at `12:44:58.2009681Z`, and eCAR terminates object `6dbd5c9d-deea-460f-9518-850550005132` at `12:44:59.932Z`. Despite that, Security 4648 at `12:45:29.4890109Z` says the same PID and image used explicit `svc_backup` credentials toward `PROXY-01`. There is no intervening 4688/Sysmon Event 1 reuse of PID 5232. A dead process cannot perform a credentialed operation 31.2 seconds after its source-native termination.
- `[distribution_texture]` Remote administration is disproportionately dominated by a tiny command shape. `WS-AJOHNSON-01` has 33 Security 4688 creations of `C:\Windows\System32\OpenSSH\ssh.exe` among only 121 total process creations, while `WS-MCHEN-01` has 39 among 159. Across six hours the same two users repeatedly launch `ssh.exe user@host` to APP, DB, proxy, web, and both mail servers, often every few minutes. The destinations and timestamps vary, but the process vocabulary and parent pattern are conspicuously narrow for 72 interactive SSH launches on two desktops.
- `[environment_or_collection_plausibility]` Linux eCAR attributes a surprisingly broad set of server egress to short-lived root-owned `wget` processes parented by `/usr/lib/systemd/systemd`. On `DB-PROD-01`, 18 separate creates use the byte-for-byte command `wget -q -e use_proxy=yes -O - https://internal-service/`, including a burst at `15:20:58.537Z`, `15:21:36.266Z`, and `15:22:39.300Z`. On `WEB-EXT-01`, the same root/systemd process shape fetches unrelated third-party names such as `embed.growthkit.io`, `p.typekit.net`, `cdn.mouseflow.com`, `app.launchdarkly.com`, `static.hotjar.com`, and `pypi.org`. It is possible to implement health checks this way, but the identical generic process wrapper attached to unrelated destinations and host roles resembles connection-to-process synthesis more than normal service-specific ownership.
- `[distribution_texture]` Linux administrative command texture repeats across otherwise separate systems. There are 71 visible `sudo ... COMMAND=` records but only 43 unique commands; `/usr/sbin/ss -s`, `/usr/bin/systemctl list-timers --all --no-pager`, and `/usr/sbin/iptables -L -n -v` each occur on four different hosts, while several other exact commands occur on two or three. Standard checks naturally repeat, but the shared small pool, combined with randomized user/TTY/PWD combinations, gives the server syslogs a templated feel.
- `[weak_signal]` The normal Windows process foreground is built from substantially the same small family on every host: `taskhostw.exe`, `WmiPrvSE.exe`, `dllhost.exe`, `wsqmcons.exe`, `conhost.exe`, Search hosts, updater binaries, and a few PowerShell health scripts. Counts and timing are varied and host software differs, so this is not decisive, but the long tail remains thinner and more interchangeable than I normally see across domain controllers, servers, and user workstations.

## Evidence For Real

- Windows process evidence correlates very well without impossible ordering in almost every sampled lifecycle. Security 4688 and Sysmon Event 1 match by PID and image for all 144 DC creates, all 69 file-server creates, all 91 mail-server creates, and all creates on most workstations; their timestamps differ by roughly only -21 to +18 ms. eCAR observations generally follow with plausible sub-second collection delay.
- Process termination modeling is materially credible. Across the nine Windows hosts I found no Sysmon Event 5 preceding its matching Event 1, and later Sysmon network, DNS, image-load, file, registry, remote-thread, and process-access events do not refer to a ProcessGuid after that GUID's termination.
- The DC Security-log clearing sequence is exceptionally coherent: WMI-spawned `cmd.exe /c wevtutil cl Security` appears at `17:42:16.5704097Z` (Security) and `17:42:16.5738636Z` (Sysmon); child `wevtutil.exe` appears at `17:42:16.9606364Z`/`17:42:16.9657468Z`; Event 1102 follows at `17:42:18.8498896Z`; and the Security `EventRecordID` resets from the 28-million range to 1, then continues at 2. That is source-native behavior, not merely a correlated duplicate.
- Windows session behavior includes credible lock/unlock reuse. For example, `WS-AJOHNSON-01` locks logon `0x257cca3` at `14:39:46.973Z`, emits Type 7 4624 for the same ID at `15:08:31.612Z`, then 4801 at `15:08:31.822Z`; the pattern repeats at `17:19:43.944Z`/`17:34:39.524Z`/`17:34:39.916Z`. Similar reuse is visible for Priya Patel and Marcus Chen.
- Linux SSH sessions have believable source-native phase ordering. On `APP-INT-01`, the Aisha Johnson session from `10.10.1.35:60674` shows connection at `12:01:55.521828Z`, password acceptance at `12:01:57.717047Z`, PAM open at `12:01:57.767203Z`, logind session 376081 at `12:01:58.360389Z`, PAM close at `12:22:57.792880Z`, and logind removal at `12:22:58.880662Z`. Equivalent patterns recur with varying authentication methods and durations.
- Binary identity is stable within a host and sensible across apparent OS cohorts. Repeated executions of a given image retain the same Sysmon hash set; common workstation images often share hashes across a subset of similar machines, while server builds and another workstation cohort carry different hashes.
- Domain identities remain stable. Sampled domain users retain the same SID across hosts, and Security/eCAR logon IDs, principals, source addresses, and process identities usually agree.

## Detailed Analysis

### Scope and collection shape

The visible host window is approximately `2024-03-18T12:00Z` through `18:00Z`. Host telemetry covers nine Windows machines with Security XML, Sysmon XML, and eCAR, plus nine Linux machines with syslog and eCAR. The Windows Security volume is role-sensitive: DC-01 carries 7,915 selected records, including 4,498 Event 5156 records and 1,267 Event 4769 records; FILE-SRV-01 has 1,799; user workstations generally have 477-757. Linux syslog volume ranges from 215 records on `WS-LNGUYEN-01` to 1,748 on `WEB-EXT-01`, whose 1,028 kernel messages create genuinely different texture from the other machines.

### Process trees and lifecycle

Common parent-child relationships are technically plausible: `csrss.exe -> conhost.exe`, `svchost.exe -> WmiPrvSE.exe/dllhost.exe/taskhostw.exe`, `SearchIndexer.exe -> SearchFilterHost.exe/SearchProtocolHost.exe`, and `services.exe` into service/updater processes. More distinctive activity also forms sensible trees, including `WmiPrvSE.exe -> cmd.exe -> net.exe`, `PSEXESVC.exe -> cmd.exe`, `explorer.exe -> powershell.exe`, and `powershell.exe/cmd.exe -> ssh.exe`.

The broad lifecycle check was strong. Sysmon creates/terminates matched by ProcessGuid without negative durations; starts before the observation window explain many initial termination-only rows, while processes left running at 18:00 explain unmatched creates. Security 4689 and Sysmon Event 5 generally agree on PID/image and occur close together, and eCAR uses durable object IDs for matched create/terminate records.

The exception is the `WS-AJOHNSON-01` PID 5232 sequence detailed above. This is not a harmless source-latency inversion: three independent host representations agree that the PowerShell process stopped roughly half a minute before 4648 attributes a new credential action to it. Because 4648 explicitly supplies `ProcessId` and `ProcessName`, this is a direct ownership contradiction.

### Logon sessions

Windows network logons are mostly paired with 4634 records and short plausible durations, while service logons commonly remain open through the end of the six-hour capture. DC-01 pairs 464 of 468 Type 3 logons; FILE-SRV-01 pairs 270 of 271. Longer Type 10 sessions last from roughly 85 minutes to more than four hours. The lock/unlock sequences preserve original interactive logon IDs instead of inventing new identities.

Linux SSH coverage is similarly coherent. Accepted-password/public-key messages precede PAM opens and logind New session messages, with closes preceding logind removal. Authentication methods and key types vary. Sessions begun before noon appear as early close-only evidence, and sessions surviving past 18:00 remain open, both of which make the window boundary look natural.

### Sysmon and eCAR correlation

Security 4688 and Sysmon Event 1 are almost one-to-one. Examples include the DC attack-adjacent process chain at `16:14:34Z`-`16:14:38Z` (`WmiPrvSE -> cmd -> net`) and the log-clear chain at `17:42:16Z`. Sysmon hashes remain stable for repeated binaries, ProcessGuid use is consistent, and dependent Sysmon records do not outlive their source process.

eCAR generally adds believable collection delay rather than timestamp identity. For Windows Security 4688-to-eCAR CREATE matches, delays are typically fractions of a second to roughly 1.3 seconds, with a longer but still plausible 2.745-second maximum observed on `WS-MCHEN-01`. Linux eCAR session identities and syslog session IDs line up closely; for instance APP-INT session 376081 uses matching user, source tuple, and close.

### User and environment behavior

There is some genuine differentiation: Marcus Chen launches VS Code, Notepad++, PowerShell, RDP, and many SSH sessions; Lina Nguyen uses Git, Python/pytest, Docker, Chrome, and SSH from a Linux workstation; Sophia Martinez shows Office/collaboration applications; server roles carry Exchange/Postfix/Dovecot, Squid-like proxy, web, backup, and database-flavored activity.

The weakness is not total absence of differentiation but repetitive density within it. The two Windows administrators account for 72 nearly identically shaped SSH client starts in six hours. Server-side administration repeatedly samples a common exact `sudo` command pool. The generic root/systemd `wget` wrapper on DB and web servers further flattens application-specific process ownership. Together these patterns form a recognizable generator-like texture even though individual rows remain plausible.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---|---|
| `hard_contradiction` | Windows Security, Sysmon, eCAR | One process on WS-AJOHNSON-01 | Event 4648 attributes credential use to PID 5232 31.2 seconds after Security 4689 and Sysmon Event 5 terminate it; eCAR agrees it is dead. |
| `distribution_texture` | Security 4688, Sysmon 1, eCAR PROCESS | WS-AJOHNSON-01 and WS-MCHEN-01 | 72 SSH launches dominate the two desktops and repeatedly use the same minimal command/parent shapes across the full server estate. |
| `environment_or_collection_plausibility` | Linux eCAR PROCESS | DB-PROD-01 and WEB-EXT-01 | Generic root-owned, systemd-parented wget processes represent many unrelated destinations and host purposes, including identical bursty DB checks. |
| `distribution_texture` | Linux syslog | Fleet-wide | Exact administrative checks recur across unrelated machines from a relatively small shared command pool. |
| `weak_signal` | Windows Security/Sysmon process events | Fleet-wide | Normal-process families are role-aware but still share a relatively shallow, interchangeable long tail. |

## Realism Score by Category

- **Field format accuracy:** 9/10 — Windows XML, Sysmon fields, RFC 5424-like syslog, hashes, SIDs, GUIDs, and eCAR structures are consistently convincing.
- **Temporal patterns:** 7/10 — Most lifecycle ordering and source delay are excellent, but the dead-PID 4648 is impossible and some behavior families have conspicuous burst/cadence texture.
- **Cross-source correlation:** 9/10 — Security, Sysmon, syslog, and eCAR usually agree on PID, image, user, session, tuple, and timing; the principal exception is localized but severe.
- **Behavioral realism:** 6/10 — Role differentiation exists, but high-volume minimal-form SSH and the repeated Linux administration/process pools remain synthetic-looking.
- **Environmental consistency:** 6/10 — Host roles and software are mostly coherent, while generic root/systemd web-fetch ownership across DB and public-web roles is difficult to justify operationally.

## Recommendations

1. If this were synthetic, enforce process-liveness validation at every event that carries a caller PID or process identity, especially Security 4648. At `12:45:29Z`, either keep PID 5232 alive through the credential action, move 4648 before its termination, or attach the event to the actual live process that performed it. Validate against both the canonical process object and rendered 4689/Sysmon Event 5 timestamps.
2. Make interactive SSH behavior session-driven rather than repeatedly sampling standalone `ssh.exe user@host` starts. Reduce the 72-launch density, preserve longer-lived terminals, add role-appropriate command-line diversity only where log-visible, and model stronger per-user destination/preferences so Aisha and Marcus do not share such similar fleet-wide cadence.
3. Replace generic Linux egress-to-`wget` attribution with role-owned daemons, scheduled units, package managers, application workers, or explicit health-check services. A DB health check should have a stable unit/timer and purposeful target cadence; public-web asset activity should normally belong to an application/browser/client context rather than many root `wget` children of systemd.
4. Expand and condition the Linux administrative command model by host role, operator, active session/TTY, and current directory. Exact common commands are reasonable, but their fleet-wide frequency should arise from maintenance jobs or operator sessions with durable context rather than interchangeable random combinations.
5. Continue the strong source-native lifecycle work already visible: retain record-ID gaps and reset behavior, stable binary hashes, lock/unlock logon-ID reuse, pre-window/post-window lifecycle boundaries, and non-identical but compatible collection timestamps.

# Host/EDR Forensics Expert — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 80  
**Synthetic-Confidence Score:** 68

## Executive Summary

The corpus has unusually strong schema fidelity, lifecycle ordering, and cross-source correlation, but several endpoint behaviors look modeled rather than observed. The strongest tell is the unrealistic browser process model, reinforced by low process volume, heavily reused Linux background templates, and a narrow Internet-scanner population.

## Evidence For Synthetic

- `[contract_gap]` Browser process trees are structurally implausible. Across 44 Chrome, Edge, and Firefox creates on eight hosts, only two browser roots had any visible children—six children total. Twenty-three of 30 completed browser processes lived longer than one hour, while only two lasted under 60 seconds.

- `[behavioral_realism]` On `WS-AJOHNSON-01`, four separate Firefox processes were launched by `explorer.exe` between `14:58:16Z` and `16:25:10Z`. Each remained alive for approximately 89–99 minutes, none spawned content, GPU, socket, or utility children, and all represented independent URL-bearing invocations. Firefox without `-no-remote` should normally reuse an existing instance or establish a multiprocess tree.

- `[distribution_texture]` Windows process telemetry is extremely sparse and concentrated. Ten Windows hosts produced only 970 Sysmon Event 1 records across 60 host-hours—16.2 creates per host-hour. Servers were dominated by four generic executables: on `DC-02`, `taskhostw.exe`, `WmiPrvSE.exe`, `dllhost.exe`, and `conhost.exe` account for 107 of 132 creates (81.1%); on `FILE-SRV-01`, four equivalents account for 66 of 83 (79.5%).

- `[distribution_texture]` Linux syslog has a repeated fleet-wide background-noise palette. Across 3,869 messages, `irqbalance` contributes 528 and `snapd` 494. The same normalized `irqbalance` “NUMA node … balancing pass complete” template occurs 131 times on all 11 Linux hosts. Ten hosts each contain exactly five `anacron` records, and all 110 CRON records contain the identical `debian-sa1 1 1` command.

- `[distribution_texture]` The public-facing host records 918 UFW blocks but only 11 source IPs. Five addresses generate 856 blocks (93.2%); each dominant address has an invariant TTL and packet length, and traffic is confined to 18 destination ports and three TCP-window values. Persistent scanners can repeat, but this six-hour population lacks a credible long tail.

- `[contract_gap]` The credential-access sequence on `WS-AJOHNSON-01` includes a questionable Sysmon Event 8. The process `ms-index-service.exe` runs explicit Mimikatz-style `sekurlsa::logonpasswords`, opens LSASS with `0x1FFFFF`, and then creates a remote thread whose reported start function is `ntdll!NtCreateThreadEx`. Credential reads do not inherently require remote-thread creation, and the thread-creation API itself is an implausible target-thread entry point.

- `[weak_signal]` All 969 matched Sysmon Event 1 records precede their Security 4688 counterparts. The offset is bounded from 35.0 to 636.1 milliseconds, with a 132.9-millisecond median and no zero or reversed cases. Provider ordering can be systematic, but the universal direction and sharply bounded latency resemble a source-timing model.

## Evidence For Real

- All inspected XML and JSON records parsed successfully. Windows provider metadata, Event IDs, paths, SIDs, GUIDs, hexadecimal IDs, and Sysmon field structures were generally source-appropriate.

- Process evidence correlates exceptionally well without visible identity contradictions: 969 of 976 Security 4688 events matched both Sysmon Event 1 and eCAR process creates by host, PID, and image within two seconds.

- Network-to-endpoint correlation is similarly strong. Of 11,605 Security 5156 records, 11,499 (99.1%) matched an eCAR flow by PID, tuple, and protocol within three seconds.

- Across 1,689 eCAR process lifecycles with both endpoints visible, none terminated before creation. Actor references also produced no events before a known actor’s creation or after its termination.

- SSH and RDP ordering is credible. Thirty-eight successful SSH sessions with complete evidence had transport before login and shell creation after login; all 15 RDP sessions had matching TCP/3389 transport before authentication.

- Hash modeling is internally sound. Identical image/version combinations retained stable hashes, while shared Windows binaries had four distinct hash sets corresponding to four OS versions (`17763`, `19041`, `20348`, and `22621`). No within-host image/version hash drift was observed.

- The Security-log clearing sequence is technically convincing: `wevtutil cl Security` runs at `17:42:29Z`, Event 1102 appears at `17:42:33Z` with `EventRecordID=1`, and subsequent records restart from the new log sequence.

- The PsExec sequence on `DC-01` has plausible ordering: `C:\Windows\PSEXESVC.exe` is created at `15:59:33.823Z`, the service is registered at `15:59:34.090Z`, the process starts at `15:59:35.147Z`, and its command child follows at `15:59:37.993Z`.

## Detailed Analysis

### Corpus Orientation

The evidence spans approximately `2024-03-18 12:00Z–18:00Z` and contains 21 endpoint directories: ten Windows hosts with Security, Sysmon, and eCAR telemetry, and eleven Linux-style hosts with syslog and eCAR. I counted 32,991 eCAR records, 18,232 Security events, 11,542 Sysmon events, and 3,869 syslog messages.

### Process Trees and Lifecycles

Ordinary process relationships are mostly coherent. Known eCAR parents always appeared before their children, and PIDs, images, principals, logon IDs, and process UUIDs usually remained stable through creation, dependent activity, and termination.

Browser behavior is the major exception. Most browser launches are represented as monolithic, long-lived processes directly under `explorer.exe`. Only one Chrome launch on `WS-DRAMIREZ-01` has a credible GPU/renderer/utility family; the other workstations generally lack browser subprocesses entirely. Because the same corpus captures nearly every modeled 4688/Sysmon/eCAR process occurrence, this is more consequential than an isolated collection gap.

### Logon and Remote-Session Evidence

Interactive, network, service, unlock, SSH, and RDP sessions are represented. Visible RDP sessions had transport-to-login delays of 4.663–6.310 seconds. Complete SSH chains had transport-to-login delays of 5.980–16.730 seconds and login-to-shell delays of 0.301–2.925 seconds. No visible authentication-before-transport inversions were found.

Many server-side type 3 sessions terminate quickly, but the corpus also contains longer sessions and pre-window/open-ended state, so I did not treat unmatched boundaries as defects.

### Windows and Sysmon Fidelity

Windows XML metadata is strong. Event versions, tasks, channels, keywords, process-ID formats, and Sysmon schemas were generally credible. Sysmon ProcessGUIDs remained consistent across create, process-access, remote-thread, and terminate records.

The suspicious credential-access chain is well correlated but semantically overproduced. The `ms-index-service.exe` Event 1, two Event 10 accesses, Event 8, and Event 5 all share PID 6200 and the same ProcessGUID. The LSASS open is appropriate; the subsequent `NtCreateThreadEx` target entry is not a convincing representation of that command’s actual behavior.

### Linux and Syslog Evidence

The RFC5424-style framing and SSH/PAM sequences are mostly credible, including connection, acceptance, PAM open/close, and logind lifecycle messages. Role-specific evidence exists—Samba auditing on `FILE-LNX-01`, mail services on the mail hosts, workstation services on Linux endpoints, and UFW noise on the external web server.

However, shared generic noise is too prominent and too evenly templated. `snapd`, `irqbalance`, `anacron`, DBus, and the identical half-hourly sysstat command recur across nearly every host with a small normalized vocabulary. This produces fleet uniformity beyond what the role-specific records can fully offset.

### Limitations

This is a six-hour bounded window, not boot-to-shutdown telemetry; missing pre-window parents, sessions, and initiators were not treated as defects. Collection and filtering policy are unknown, so low volume and absent process families have some ambiguity. No disk images, memory, raw EVTX containers, packet capture, or longer-term day-over-day behavior were available.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | eCAR, Sysmon, Security process telemetry | 44 browser creates across eight hosts | Highest-impact defect; browser ownership and lifecycle are not credible |
| `distribution_texture` | Linux syslog | Dataset-wide across 11 hosts | Repeated daemon/message pools create strong generator-like fleet uniformity |
| `distribution_texture` | UFW syslog | 918 records on `WEB-EXT-01` | Scanner population is dominated by five invariant profiles |
| `environment_or_collection_plausibility` | Sysmon Event 1, Security 4688 | Ten Windows hosts | Process volume and server executable diversity are unusually thin |
| `contract_gap` | Sysmon Event 8/10 | One credential-access chain | The remote-thread semantics do not fit the visible command behavior |
| `weak_signal` | Sysmon Event 1 vs. Security 4688 | 969 correlated creates | Universal one-sided provider latency appears modeled |

## Realism Score by Category

- **Field format accuracy:** 8/10 — Windows, Sysmon, syslog, and eCAR fields are generally well formed.
- **Temporal patterns:** 7/10 — Session and attack ordering are strong, but some source delays and background cadences are visibly bounded.
- **Cross-source correlation:** 9/10 — PIDs, tuples, logon IDs, GUIDs, and timestamps align with very few contradictions.
- **Behavioral realism:** 4/10 — Browser multiprocess behavior and one credential-access semantic are materially implausible.
- **Environmental consistency:** 5/10 — Roles are recognizable, but endpoint volume and Linux/scanner populations have limited long-tail texture.

## Recommendations

- **P0:** None observed. I found no unequivocal create-after-terminate, authentication-before-transport, impossible identifier reuse, or malformed source-native value.

- **P1 — Rebuild browser process lifecycles.** Model one persistent browser parent, realistic renderer/GPU/network/utility children, and appropriate child turnover. Subsequent URL invocations should usually hand off to an existing browser and terminate quickly unless an explicit independent-profile option is present.

- **P1 — Diversify Linux host noise by role and installation history.** Reduce the fleet-wide dominance of `snapd` and `irqbalance`; vary daemon availability, cadence, message vocabulary, package state, and maintenance behavior. Preserve common configuration where appropriate without giving ten hosts identical CRON and anacron textures.

- **P1 — Add a long-tailed scanner population.** Retain per-source TCP fingerprints, but introduce many low-frequency sources, campaign-specific port strategies, and natural churn. Avoid having 93.2% of public-host blocks originate from five profiles.

- **P2 — Expand endpoint process texture.** Add believable updater helpers, scheduled-task children, service utilities, application subprocesses, short-lived shell helpers, and host-specific long-tail software. Server roles should not be dominated so heavily by the same four generic executables.

- **P2 — Correct the credential-access Event 8 semantics.** For read-oriented LSASS credential dumping, stop after the process-access evidence. If injection is intended, model a plausible injected entry point and memory/module relationship rather than reporting `NtCreateThreadEx` as the target thread’s start routine.

- **P3 — Broaden provider timing behavior.** Preserve causal ordering while allowing host/load-dependent queueing, near-zero deltas, and occasional legitimate provider-order variation instead of placing every Sysmon-create observation inside the same one-sided latency envelope.


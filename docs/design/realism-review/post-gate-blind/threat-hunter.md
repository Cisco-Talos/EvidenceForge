# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic
**Verdict Confidence:** 86
**Synthetic-Confidence Score:** 72

## Executive Summary

The evidence is unusually well correlated and largely schema-correct, but several independent
operational artifacts point toward synthetic construction. The strongest are a selective endpoint-
evidence gap around sustained scanning from `WS-MPATEL-01`, implausibly broad software deployment
across workstation roles, a compact and heavily reused Internet-scanner population, and excessive
concurrent interactive SSH activity attributed to one user.

I found no decisive impossible ordering or malformed record that alone proves synthesis. The
verdict therefore rests on the combined weight of contract, environmental, and distributional
indicators rather than a single hard contradiction.

## Evidence For Synthetic

- **contract_gap — selective absence around an active scanner.** `ZEEK-BO-CORE/conn.json` contains
  187 `S0` connections sourced by `10.44.10.21` (`WS-MPATEL-01`), including 74 Internet
  destinations on database ports 1433, 3306, 5432, and 6379. For example, at
  `2024-05-14T12:01:20.320222Z`, UID `CL8KHK0pC0KEsNbpM0` is
  `10.44.10.21:52533 -> 25.8.158.103:6379`, one SYN and no response. The ASA independently records
  the matching deny. Yet an exhaustive tuple/time join found only 2 of the 187 attempts in the
  workstation's Windows Security log and none in its eCAR log, despite hundreds of ordinary
  endpoint flow records. Raw-packet tooling or selective collection could explain this in
  production, so it is a contract gap rather than a hard contradiction.

- **environment_or_collection_plausibility — server backup software distributed like a random
  process pool.** The server-side Veeam Backup & Replication service path appears on the domain
  controller, file server, and three employee workstations. `WS-MPATEL-01` also runs Commvault
  `GxCVD.exe`. Installing full server backup services alongside another backup stack on ordinary
  workstations is possible, but the cross-role repetition looks pool-driven.

- **environment_or_collection_plausibility — mutually overlapping secure-access stacks.**
  `WS-NKAPOOR-01` starts Zscaler `ZSAService.exe`, Palo Alto `PanGPS.exe`, and Cisco AnyConnect
  `vpnui.exe`. Other workstations run varying pairs of those products. Migration overlap is
  plausible, but three active competing stacks on one endpoint, repeated across the fleet,
  materially weakens host-role authenticity.

- **distribution_texture — compact, curated-looking scanner population.** The WEB syslog contains
  864 UFW blocks, but 861 come from only eight recurring IPs. Each source retains an invariant TTL
  and packet length across hours. Stable fingerprints per scanner are realistic; the suspicious
  aspect is the six-hour environment being dominated by a small set of cleanly themed, repeatedly
  sampled scanners.

- **distribution_texture — excessive interactive-session concurrency.** The WEB and PROXY eCAR
  logs contain 41 successful SSH sessions for `nina.kapoor` from `10.44.10.24`. At
  `2024-05-14T17:41:26.311Z`, eight are concurrently open. Multiple admin terminals are plausible,
  but sustained session churn and eight concurrent interactive sessions are atypical.

- **weak_signal — highly regular executable module bursts.** New Windows processes repeatedly
  receive the same nine-module sequence at approximately 2–3 ms spacing. Ordered startup loading
  is real, but repeated perfectly compact templates across processes are a mild generation
  signature.

- **hard_contradiction — none found.** No visible initiator occurred after its dependent, identity
  SID inconsistency, reversed lifecycle, or impossible host/network ordering was found.

## Evidence For Real

- The major RDP sequence is operationally coherent: network transport precedes the Type 10 login,
  and later processes retain its Logon ID and terminal Session ID.
- Process lifecycle checks were clean. No eCAR dependent with a known actor preceded its visible
  creation, and no matched termination preceded creation.
- AD identities are exceptionally consistent across hosts.
- Network joins are highly usable across DNS, proxy, ASA, Zeek, and endpoint telemetry.
- Source-native formats are convincing, including Windows XML, Zeek JSON, ASA, RFC5424 syslog,
  proxy, and web access records.
- DHCP renewals occur near half-life with substantial jitter rather than exact periodicity.
- Linux uptime values progress consistently with wall time.
- Human mistakes such as `userrs` and `ummask` appear in Bash history.

## Detailed Analysis

The core network window runs from `2024-05-14T12:00:24Z` through approximately `17:59:54Z`. It
contains 5,957 Zeek connections, 967 DNS records, 1,016 TLS records, 649 HTTP records, 785 file
records, 587 X.509 records, 50 DHCP records, 6,586 ASA lines, 51 IDS alerts, 726 proxy requests, and
550 web requests. This is a plausible source-family balance for a small branch, although endpoint
lifecycle cleanup extends later.

Host roles are recognizable: DC/DNS/Kerberos at `10.44.20.10`, SMB at `10.44.20.20`, Squid at
`10.44.20.30`, a DMZ web/SSH host at `10.44.30.10`, and workstations at `10.44.10.21–25`. Normal
flows generally respect those roles. The main environmental concern is installed-software
composition, not IP or service placement.

The data is highly pivotable. User, Logon ID, PID, process identity, network tuple, Zeek UID, and
file identity often survive across sources. Temporal order is mostly strong. SSH and RDP transport
generally precedes authentication, commands fall within sessions, and process dependents follow
creation. Open sessions and unmatched processes were not treated as contradictions because the
window is bounded and disconnected sessions can outlive transport.

The clearest hunting anomaly is `WS-MPATEL-01`'s broad outbound scan. Its slow, scattered timing
and exclusive `S0` results could represent malware, reconnaissance, or a red herring. Operationally,
the inability to pivot from 185 of 187 network attempts into otherwise active endpoint sources is
conspicuous. Schema quality is otherwise high; concerns are behavioral and deployment-related
rather than parser-level defects.

## Synthetic Indicator Summary

- **hard_contradiction:** None.
- **contract_gap:** 185 of 187 `WS-MPATEL-01` S0 scan attempts lack matching endpoint evidence.
- **distribution_texture:** Small repeated scanner population, high same-user SSH concurrency, and
  templated module-load bursts.
- **schema_or_format:** No decisive synthetic indicator.
- **environment_or_collection_plausibility:** Server backup services and overlapping secure-access
  products on workstations.
- **weak_signal:** Repeated process/module patterns and neatly themed scanner behavior.

## Realism Score by Category

- **Field format accuracy:** 9
- **Temporal patterns:** 7
- **Cross-source correlation:** 8
- **Behavioral realism:** 6
- **Environmental consistency:** 5

## Recommendations

- Determine whether raw-socket behavior or endpoint collection policy explains the scan gap.
- Validate workstation software inventory against intended fleet profiles.
- Compare a longer Internet-facing window to assess scanner-population closure.
- Review the SSH session demand and terminal/process ownership model.
- Preserve the current SID, tuple, UID, timing, and lifecycle fidelity.

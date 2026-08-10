# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 74

## Executive Summary

The six-hour corpus is unusually strong at preserving a technically workable intrusion trail across endpoint, Windows, Linux, proxy, firewall, and Zeek evidence. However, a dataset-wide endpoint lifecycle defect and a repeated, role-incoherent health-check pattern are concrete synthetic tells that outweigh the otherwise convincing correlations.

## Evidence For Synthetic

- `[contract_gap]` eCAR records contain 84 `taskhostw.exe` process creations across nine Windows systems, but only one matching `PROCESS/TERMINATE` for the same object identity. The gap includes processes created near the beginning of the window—for example PID 6772 on `WS-DRAMIREZ-01` at `2024-03-18T12:05:11.640Z` and PID 3384 on `MAIL-FIN-01` at `12:09:49.509Z`—so it cannot be explained by the six-hour right boundary. The skew is also command-family-specific: 43/44 bare `taskhostw.exe` and 40/40 `taskhostw.exe /Run` instances lack termination, while the same source does emit 1,425 process terminations overall.
- `[environment_or_collection_plausibility]` The eCAR process stream shows 45 root/system service “health checks” on four Linux servers, with 37 distinct command lines aimed largely at unrelated public tracking/content endpoints. Examples include `service-healthcheck --url https://sdk.snapwidget.com/`, `...tracking.amplitude.app/`, `...cache.fullstory.io/`, and `/opt/meridian/bin/proxy_healthcheck.py --target connect.facebook.net`. The pattern spans mail-edge, mail-client, app, and web roles and looks like one generic URL pool painted onto several server roles rather than a coherent set of service dependencies.
- `[distribution_texture]` The lifecycle asymmetry extends to other repeatedly spawned transient/background families: 22/30 `GoogleUpdater.exe -Embedding` creates and all six `sshd: unknown [priv]` creates have no matching eCAR termination. Individually these could be collection loss or window censoring; in combination with the near-total `taskhostw` gap, the missingness is too family-shaped to resemble a normal uniform endpoint collection failure.

## Evidence For Real

- The malicious lifecycle is operationally coherent. A `www-data` Apache child on `WEB-EXT-01` launches a base64-decoded reverse shell at `13:19:56.255Z`, followed by an outbound 8443 flow to `45.33.32.30` at `13:19:59.413Z`. Later root shells read `config.php` and `/root/.ssh/id_rsa`, pivot to internal systems, and access `/etc/shadow` on `APP-INT-01`.
- Windows lateral movement has convincing source-native detail: `PSEXESVC.exe` is dropped on `DC-01` at `15:59:36.492Z`, service creation follows 200 ms later, the service process starts beneath `services.exe`, and its child runs `whoami && hostname`. Later WMI-hosted commands create `svc_mhsync`, add it to Domain Admins, create `DeviceSyncSvc`, and schedule it.
- The database-staging and transfer trail pivots cleanly. `DB-PROD-01` creates `/tmp/rpt_0318.sql`, compresses and hashes it, then `scp` PID 160674 reads the archive and opens `10.10.4.10:43941 -> 10.10.2.30:22`; `APP-INT-01` records the receiving `sshd` PID 981768 creating `/tmp/.cache/rpt_0318.sql.gz` at `17:30:03.699Z`.
- The volume is credible enough to require hunting: the dataset covers 18 named hosts plus network sensors and includes 23,656 eCAR records, more than 11,000 Zeek connections, 11,538 ASA lines, thousands of Windows events, and ordinary authentication, software-update, scheduled-task, DHCP, DNS, proxy, mail, and administrative noise.
- User/session ownership is often carefully preserved. For example, Marcus Chen's activity on `WS-DRAMIREZ-01` is preceded by a Type 2 login with LogonId `0x97e1217`, and its explorer, Chrome, OneDrive, Citrix, and RDP-client children retain that logon/session identity until their clustered session close.

## Detailed Analysis

The visible interval runs from approximately `2024-03-18T12:00:00Z` through `17:59:59Z`. The apparent estate has Windows workstations, a domain controller, file and finance-mail servers, Linux application/database/mail/proxy/web systems, core and DMZ Zeek sensors, a perimeter ASA, and two IDS feeds. eCAR alone contains 15,355 flow observations, 1,647 process creates, 1,425 process terminations, 1,112 session logins, and 767 logouts.

The attack can be reconstructed without relying on a single source. The early web compromise produces a process-to-flow pivot; subsequent Linux discovery and credential access retain principals, shell parents, session IDs, and target roles. The Windows phase similarly moves through PsExec, WMI, account manipulation, service persistence, scheduled-task persistence, and Security-log clearing. `DC-01` includes Security Event 1102 at `17:41:53.4217549Z`, immediately after `wevtutil cl Security`, which is the expected companion record. Data staging on the database and the SCP receiver artifact also agree on filename, source/destination, port, process ownership, and ordering.

That realism makes the endpoint process defect more probative, not less. Process terminations are clearly in collection, and many short-lived commands receive them, yet 83 of 84 `taskhostw` object identities never close. These processes are distributed across `DC-01` (31), `FILE-SRV-01` (14), `WS-MCHEN-01` (12), `MAIL-FIN-01` (10), and five other systems. Many were born hours before the observation boundary. A live deployment could lose individual endpoint events, but a 98.8% family-specific loss rate alongside abundant termination telemetry is a source-behavior contradiction.

The health-check family is the next strongest authenticity problem. The command shapes and parentage are plausible in isolation, but the destinations do not fit the host roles as a set. Mail-edge and internal application hosts repeatedly probe advertising, analytics, font, widget, and social-content domains as root-run health checks. The combination of 45 launches, 37 variants, and reuse across distinct roles resembles randomized destination substitution rather than an organically configured monitoring estate.

Overall, the corpus would make a useful hunt because the intrusion is embedded in substantial noise and the principal pivots work. I nevertheless assess it as synthetic because the strongest defects are measurable source-family contracts, not merely a clean storyline or unusually complete correlation.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the score |
|---|---|---:|---|
| `contract_gap` | eCAR process lifecycle | 83 of 84 `taskhostw` creates lack matching termination across nine hosts | Strong family-specific lifecycle failure despite abundant termination telemetry |
| `environment_or_collection_plausibility` | Linux eCAR process/network | 45 service checks, 37 command variants, four server roles | Public ad/content targets do not form a credible shared server dependency set |
| `distribution_texture` | eCAR process lifecycle | Several repeated process families | Missingness is strongly conditioned on executable family rather than source availability or window edge |

## Realism Score by Category

- **Field format accuracy:** 9 — The reviewed eCAR, Windows, Linux, and network fields are consistently usable and source-appropriate.
- **Temporal patterns:** 8 — Attack and baseline ordering are convincing, with varied precision and plausible session durations.
- **Cross-source correlation:** 9 — Process, session, flow, service, file, and network pivots usually agree exceptionally well.
- **Behavioral realism:** 7 — User/admin/attacker behaviors work, but generic role-spanning health checks reduce authenticity.
- **Environmental consistency:** 6 — The estate is coherent overall, but the process lifecycle and server dependency patterns are difficult to reconcile with production collection.

## Recommendations

- If this were synthetic, give every finite `taskhostw.exe` execution a lifecycle-compatible termination and apply any observation drop coherently to both create and termination events. Re-test by executable family, host, and distance from the dataset boundary.
- If this were synthetic, derive service-health destinations from explicit host/application dependencies. Mail services, proxy checks, web applications, and internal application servers should probe different, role-justified endpoint sets rather than a shared pool of ad-tech and content domains.
- If this were synthetic, audit other repeated transient process families (`GoogleUpdater`, unknown-user `sshd`, scheduled PowerShell) for family-conditioned lifecycle omission and make source missingness independent of executable vocabulary.

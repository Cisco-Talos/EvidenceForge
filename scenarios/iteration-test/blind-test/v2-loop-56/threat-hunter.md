# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 96  
**Synthetic-Confidence Score:** 86

## Executive Summary

This is a sophisticated, largely coherent dataset with credible enterprise background traffic and an attack chain that pivots cleanly across endpoint, network, proxy, authentication, and Windows audit sources. However, a near-impossible DHCP timestamp fingerprint repeated across every observed Linux lease transaction, together with scan-packet inconsistencies and incorrect reverse-shell process ownership, provides strong evidence of deterministic generation.

## Evidence For Synthetic

- `[hard_contradiction]` All 18 complete DHCP lifecycle triplets in the Linux syslogs preserve the exact same final three microsecond digits across their separate `DHCPREQUEST`, `DHCPACK`, and `bound` records. For example, [WS-LNGUYEN-01 syslog lines 3–5](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/WS-LNGUYEN-01.meridianhcs.local/syslog.log:3>) use `.584464`, `.240464`, and `.577464`; lines 29–31 use `.545114`, `.006114`, and `.532114`. The suffix pattern occurs in 12/12 WS-LNGUYEN transactions, 3/3 WS-OHADDAD transactions, and 3/3 LT-MRIVERA transactions. Separate real log writes should not repeatedly retain a transaction-level microsecond suffix; this looks like integer-millisecond offsets applied to a shared synthetic timestamp.

- `[contract_gap]` The same DHCP records disagree about transaction completion. The first WS-LNGUYEN Zeek record starts at `12:01:19.530427Z` with `msg_types=["REQUEST","ACK"]` and `duration=0.476531`, implying completion near `12:01:20.006958Z`; the endpoint records its request at `12:01:19.584464Z` but ACK at `12:01:21.240464Z`. A similar discrepancy occurs for WS-OHADDAD: Zeek starts at `12:04:02.515756Z` with `duration=0.377875`, while its endpoint ACK is timestamped `12:04:04.193434Z`. The request clocks are closely aligned, making a repeated 1.2–1.3 second ACK discrepancy difficult to attribute to ordinary sensor skew.

- `[distribution_texture]` A single Nmap connect scan—`nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`—produces 1,238 one-packet `S0` probes whose `orig_ip_bytes` vary among 40 (141 records), 52 (919), 60 (105), and 64 (73). Adjacent probes from the same scanner and interface include 52 bytes at `13:51:46.127025Z`, 60 at `13:51:46.182468Z`, and 40 at `13:51:46.199355Z` in [zeek-core/conn.json](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/zeek-core/conn.json:4241>). A single host’s kernel TCP stack should use substantially consistent SYN headers/options for same-route IPv4 targets during one scan.

- `[contract_gap]` The reverse-shell flow is assigned to the wrong visible process layer. [WEB-EXT-01 eCAR lines 748–751](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/WEB-EXT-01.meridianhcs.local/ecar.json:748>) show PID 1480967 executing `bash -c 'echo … | base64 -d | bash'`, and the subsequent `10.10.3.10:60568 -> 45.33.32.30:8443` flow is attributed to that same outer shell. The command necessarily launches pipeline children and another `bash` that executes the `/dev/tcp` redirection, but no `base64` or inner-shell process exists despite detailed child-process collection elsewhere. Either the socket-owning child is missing or the flow is attached to its parent.

- `[distribution_texture]` Browser-like sessions in [WEB-EXT-01 web access](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/WEB-EXT-01.meridianhcs.local/web_access.log:1>) frequently serialize asset retrieval into one-second steps. The `76.44.118.248` session requests `/products` at `12:00:04`, then two assets at `12:00:06` and `12:00:07`; the following iPhone session repeats page-plus-assets at one-second increments. Some later sessions show realistic same-second concurrency, but the repeated serial pattern suggests a synthetic browser-session template.

- `[distribution_texture]` SYSVOL and general SMB filename vocabulary has a templated texture across otherwise unrelated accesses: `User\gpt.xml`, `Preferences\registry.bat`, `Policies\logon.ini`, `Preferences\2026\policy.ps1`, `User\2025\gpt.ps1`, and many combinations of `draft`, `final`, `approved`, `onboarding`, `project-plan`, and `meeting-notes`. In March 2024, the future-year paths and shallow policy-like names directly under SYSVOL are possible but collectively unlike normal GUID-oriented GPO storage.

- `[environment_or_collection_plausibility]` The same `debian-sa1 1 1` cron pattern appears across nearly every Linux role on a roughly 30-minute cadence and runs as principal `sysstat`. The command resembles Debian/Ubuntu’s packaged sysstat job, which is ordinarily a root-owned cron workload and commonly runs more frequently. A custom fleet configuration could explain this, but its uniform deployment across workstations, mail servers, proxy, application, and web roles reinforces the generated baseline texture.

## Evidence For Real

- The environment has a credible topology: workstations in `10.10.1.0/24`, core services in `10.10.2.0/24`, DMZ/proxy systems in `10.10.3.0/24`, and the database in `10.10.4.0/24`. Traffic paths generally respect those roles.

- The six-hour window from approximately `2024-03-18T12:00:00Z` through `17:59:59Z` contains substantial background evidence: 32,825 Zeek records across three sensor zones, 18,416 ASA records, 2,353 proxy records, 748 web requests, DHCP renewals, SMB activity, SMTP, TLS/X.509, OCSP, Windows authentication, scheduled activity, package management, and external scanning.

- Zeek connection texture is meaningfully varied rather than uniformly successful. Core `conn.log` includes 8,638 `SF`, 1,952 `S0`, 118 `RSTO`, 86 `RSTR`, and smaller `S1/S2/S3/OTH/REJ` populations. There are nonzero `missed_bytes`, diverse TCP histories, both TLS 1.2 and 1.3, certificate-chain reuse, and realistic HTTP 301/304/403 behavior.

- The initial reverse-shell pivot correlates credibly: endpoint telemetry records `10.10.3.10:60568 -> 45.33.32.30:8443` at `13:20:43.377Z`, while [zeek-dmz/conn.json](</Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test/data/zeek-dmz/conn.json:1491>) observes the same tuple at `13:20:43.245317Z`, with a 10.292-second `SF` connection and bidirectional data.

- SSH lifecycles are especially convincing. The root session from `10.10.1.22:32825` to WEB-EXT-01 is seen by core and DMZ sensors, followed by `sshd`, `USER_SESSION LOGIN`, and shell creation on the target. Its Zeek duration of about 15,424.919 seconds agrees with the target logout near `17:57:22Z`.

- The WEB-EXT-01 to APP-INT-01 pivot likewise works operationally: Zeek sees `10.10.3.10:46259 -> 10.10.2.30:22` at `14:15:09.542703Z`; APP-INT syslog records accepted root authentication at `14:15:20.822247Z`, PAM opening, and a systemd-logind session.

- Windows attack evidence follows plausible causal sequences. DC-01 shows a PSEXESVC file creation before service and process startup; later WMI-launched commands create `svc_dirsync`, add it to Domain Admins, create `DeviceSyncSvc`, and register a scheduled task. The service subsequently starts under `services.exe` and performs jittered proxy-mediated check-ins.

- Security-log clearing is rendered convincingly. DC-01 records `wevtutil cl Security` at `17:42:07Z`, followed by Event 1102 at `17:42:10.9908924Z`; `EventRecordID` resets from `28261032` to `1`, exactly where a real cleared Security channel would reset.

- Windows process lifecycles contain no visible terminate-before-create contradictions. Across the reviewed eCAR files, actor references also did not visibly occur before their process creation or after the referenced process terminated.

## Detailed Analysis

The dataset represents approximately 21 named hosts plus core, database, and DMZ Zeek sensors, perimeter firewall and Snort telemetry. The visible topology includes two domain controllers, Windows and Linux file servers, application and database systems, three mail roles, a proxy, a monitoring server, a public web server, and a mixture of Windows and Linux workstations.

The network baseline is broad enough to require actual hunting. Core Zeek has 10,877 connections, DMZ has 7,918, and the database sensor has 420. Core services are dominated by DNS, Kerberos, HTTP proxying, LDAP, SMB, TLS, syslog, SSH, DHCP, and SMTP. Normal activity includes domain-controller replication, endpoint DNS and Kerberos, workstation proxy use, web-to-database MySQL, SMTP relay, SSH administration, file-share access, and DHCP renewal. External probes and failed connections provide additional noise.

The attack begins visibly on WEB-EXT-01. At `13:20:32.524Z`, Apache PID 23958 launches PID 1480967 as `www-data` with a base64-decoded Bash reverse-shell command. At `13:20:43.245317Z`, Zeek sees the resulting outbound `10.10.3.10:60568 -> 45.33.32.30:8443` connection; endpoint telemetry follows 132 milliseconds later. This network correlation is strong, although the missing pipeline children and parent-owned socket weaken host-level authenticity.

At `13:40:16.6Z`, an SSH connection begins from WS-OHADDAD-01 (`10.10.1.22:32825`) to WEB-EXT-01. The target creates a privileged `sshd` process, records root login, and creates an interactive Bash shell. The actor enumerates interfaces, hosts and resolver configuration, searches `/opt/ehr` for credentials, reads `/var/www/html/config.php`, inspects `/root/.ssh/id_rsa`, and performs ICMP and TCP discovery of `10.10.2.0/24`.

The Nmap activity is operationally plausible at the behavioral level. The ping sweep and five-port connect scan create a large burst of unsuccessful `S0` connections with a small number of responsive services. Snort generates thresholded scan alerts rather than one alert per probe. The packet-size distribution inside the single connect scan is nevertheless inconsistent with a stable source TCP implementation and materially affects authenticity.

At `14:15:09Z`, WEB-EXT-01 opens SSH to APP-INT-01, where root authentication and shell startup follow. The connection remains active for approximately 13,309 seconds. At `17:14:32Z`, APP-INT-01 pivots to DB-PROD-01 as root. Database commands enumerate schemas and tables, dump `ehr` data into `/tmp/rpt_0318.sql`, compress it, and use `scp` to transfer it back to `10.10.2.30`. The destination path and transfer evidence are visible through endpoint and SMB/file telemetry.

The Windows phase includes PsExec and WMI-style execution. DC-01 receives `PSEXESVC.exe`, creates the PSEXESVC service, launches it under `services.exe`, and runs `cmd.exe /c whoami && hostname`. WMI-launched SYSTEM processes later create the `svc_dirsync` domain account, add it to Domain Admins, install `DeviceSyncSvc`, and create an hourly task. DeviceSyncSvc starts at `16:29:44.335Z`, then begins approximately ten-minute proxy-mediated check-ins to `api.westbridge-services.net`, with realistic jitter and one larger gap.

At `17:42:06Z`, DC-01 launches encoded PowerShell that decodes to a `WebClient.DownloadString` request for `/v2/manifest`. The proxy records the matching CONNECT and GET at `17:42:10Z`. Concurrent WMI-launched `wevtutil` clears the Security channel, with Event 1102 and the record-ID reset appearing immediately afterward. These are strong, source-native pivots.

Authentication and lifecycle behavior is mostly credible. SSH accepted-key records carry stable per-user fingerprints across hosts, PAM and logind records are correctly ordered, and session removals follow SSH closure. Windows process and logon identifiers similarly showed no visible reversal for matching IDs. The DHCP event family is the conspicuous exception: its copied microsecond suffixes and cross-source completion disagreement look algorithmically produced.

The background environment contains useful long-tail details: `irqbalance`, `snapd`, `polkitd`, `rsyslogd` queue status, `systemd-resolved`, unattended upgrades, DHCP renewals, failed authentication, scheduled Windows health checks, service traffic, browser sessions, external port scanning, TLS resumption, partial packet loss, and varied connection states. This realism prevents the malicious activity from being the sole content and weighs against a simplistic synthetic dataset.

Nonetheless, the DHCP timestamp fingerprint is statistically overwhelming. Combined with the per-probe randomization of a host-stack property and the reverse-shell process-ownership gap, it moves the result beyond “mixed” and into confidently synthetic territory.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `hard_contradiction` | Linux syslog / DHCP | 18 of 18 complete transactions across three hosts | Repeatedly preserves an identical transaction-level microsecond suffix across independent log writes; strongest generator fingerprint. |
| `contract_gap` | Zeek DHCP and Linux syslog | Repeated across all three DHCP-enabled Linux endpoints | Zeek’s request/ACK transaction ends more than a second before the closely synchronized endpoint records the ACK. |
| `distribution_texture` | Zeek `conn.log` | 1,238 probes in one Nmap scan | Same source stack randomly alternates among four one-SYN packet sizes on the same route. |
| `contract_gap` | Linux eCAR process/network | One pivotal reverse-shell execution | Flow belongs to the outer encoded-command shell while the actual pipeline/socket-owning children are absent. |
| `distribution_texture` | Web access | Repeated browser sessions | Asset requests frequently follow one-second serial templates instead of normal concurrent browser bursts. |
| `distribution_texture` | Zeek SMB | Repeated across SYSVOL and business shares | Shallow, adjective-combinator filename vocabulary and future-year policy paths look templated. |
| `environment_or_collection_plausibility` | Linux eCAR/syslog | Fleet-wide | Nearly uniform `debian-sa1` identity and cadence across unrelated Linux roles. |

## Realism Score by Category

- **Field format accuracy:** 8 — Windows XML, Zeek JSON, ASA, proxy, syslog, TLS, and SMTP fields are mostly source-appropriate, with no widespread parsing or type defects.
- **Temporal patterns:** 5 — Attack and session ordering is strong, but the DHCP microsecond fingerprint and repeated browser timing materially reduce realism.
- **Cross-source correlation:** 8 — Most pivots align by tuple, port, user, service, and lifecycle; DHCP timing and reverse-shell process ownership are the notable exceptions.
- **Behavioral realism:** 8 — The threat activity is technically workable and the background includes credible administrative, application, service, and hostile Internet behavior.
- **Environmental consistency:** 7 — Host roles and network zones generally fit, but fleet-uniform Linux jobs and templated SMB/SYSVOL vocabulary weaken the environment’s organic texture.

## Recommendations

If this were synthetic, the following changes would improve it:

- Generate each DHCP syslog record from an independently resolved timestamp. Preserve causal order, but do not create lifecycle timestamps by adding integer milliseconds to a shared microsecond-valued base.

- Make Zeek DHCP `duration` and the endpoint ACK time describe the same transaction. Any modeled endpoint collection delay should be small, variable, and explicitly applied after the network-observed ACK.

- Model TCP SYN header/options from a stable per-host network-stack profile. Within a single same-route Nmap scan, one-packet `S0` probes should normally retain the same IP-byte size unless a concrete route or protocol difference explains it.

- Materialize the `echo`, `base64`, and nested Bash children for shell pipelines and assign the `/dev/tcp` flow to the process that actually owns the socket. If process identity cannot be observed, omit it rather than attaching the flow to an incorrect parent.

- Increase browser timing realism by allowing same-second or subsecond parallel asset fetches, variable connection reuse, cache-dependent omissions, and HTTP/2-style multiplexing where applicable.

- Use structurally realistic SYSVOL paths—domain and GPO GUID hierarchy, `Machine`/`User` subtrees, and source-native policy files—and reduce generic adjective/filename recombination across unrelated shares.

- Vary scheduled Linux activity by distribution, operating-system version, and host role. In particular, ensure the `debian-sa1` account and cadence match the represented package configuration.

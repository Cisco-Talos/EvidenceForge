# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 82  
**Synthetic-Confidence Score:** 26

## Executive Summary

This six-hour dataset is strongly production-like: the suspicious activity is buried within 84,125 records from 18 hosts and can be reconstructed through independently useful host, authentication, network, proxy, firewall, IDS, DNS, and web pivots without visible ordering contradictions. Two modest distribution artifacts—the repeated PID-1/root `wget` health-check shape and unusually even hourly volumes—keep it from the indistinguishable range, but neither outweighs the source-native timing, lifecycle, and collection details.

## Evidence For Synthetic

- `[distribution_texture]` Across `WEB-EXT-01` and `DB-PROD-01`, 39 root-owned processes with PPID 1 use the identical command shape `wget -q -e use_proxy=yes -O - https://.../`. All 16 database-server instances target `internal-service`, while 23 web-server instances rotate through analytics, package, and SaaS domains such as `cdn.heapanalytics.com`, `pypi.org`, `api.logz.io`, and `api.segment.io`. This looks more like a shared baseline template than two independently operated services, although a scripted health-check framework could explain it.
- `[weak_signal]` Hourly activity is comparatively smooth for an 18-host slice. eCAR volume by hour is 4,123, 3,949, 3,983, 4,416, 4,674, and 4,390; combined Zeek `conn.json` volume is 1,978, 1,877, 1,857, 1,911, 2,145, and 2,020. The attack-related lift after 16:00 is credible, but the low baseline variation is mildly generator-like.
- `[weak_signal]` Endpoint collections are heavily network-event weighted: 16,057 of 25,535 eCAR records are `FLOW/CONNECT`, and Windows Security contains 8,250 Event 5156 records out of 13,985 total events. This is entirely possible under an enabled WFP/EDR collection policy, so it had little effect on the score.

## Evidence For Real

- The source inventory and volume are credible for a focused six-hour collection: 84,125 records across 18 endpoint directories, two Zeek sensors, an ASA firewall, two Snort sensors, proxy and web access logs, Linux syslog and shell histories, Windows Security/Sysmon, and eCAR.
- Cross-source network timing is convincing rather than bit-identical. Across 4,860 exact ASA/Zeek tuple matches, the median absolute start-time difference is 0.52 seconds and the 95th percentile is 0.97 seconds.
- The initial compromise pivots cleanly: `WEB-EXT-01` records `185.70.41.45` posting to `/ehr/admin/upload.php` at 13:20:07; eCAR shows Apache spawning the base64-decoding `www-data` shell at 13:20:10; Zeek sees `10.10.3.10:43383 -> 45.33.32.30:8443` at 13:20:17 for 7.041919 seconds; ASA builds the same connection at 13:20:16 and tears it down at 13:20:24.
- Windows credential access is source-coherent. `WS-AJOHNSON-01` records `ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit` at 15:45:12–13 and a remote thread into PID 4292 `lsass.exe` at 15:45:21.
- PsExec lateral movement is internally consistent: DC Security Event 4624 records `aisha.johnson` from `10.10.1.35:62306` at 15:59:48; Event 4697 creates `PSEXESVC` at 15:59:55; eCAR records the binary at 15:59:57 and child `cmd.exe /c whoami && hostname` at 16:00:00. The service process terminates at 16:00:05, while later activity correctly uses `WmiPrvSE.exe` rather than reusing a dead PsExec process.
- Domain persistence has plausible causal ordering: WMI-spawned `net user` and `net group` commands begin at 16:15:19; Events 4720, 4724, 4738, and 4728 create, password-set, enable, and add `svc_mhsync` to Domain Admins by 16:15:25. Service and scheduled-task persistence follows at 16:19:47–51.
- File-server collection and egress are huntable. `svc_mhsync` logs onto `FILE-SRV-01` from `10.10.1.35` at 16:34:19, starts `Compress-Archive`, and creates `cache_7f3a.zip`. Zeek later observes a 314,330,708-byte SMB file at 17:21:58, followed by proxy egress to `45.33.32.30:443` at 17:24:50 with 315,436,503 origin bytes; ASA independently records the 11-second connection and 329,732,267 total bytes.
- Database staging also works end to end. The root session on `DB-PROD-01` performs MySQL discovery, `mysqldump`, gzip, and SCP; Zeek sees `10.10.4.10:58569 -> 10.10.2.30:22` at 17:39:13 with 201,289 origin bytes; `APP-INT-01` records the SSH login and `/tmp/.cache/rpt_0318.sql.gz` creation at 17:39:19.
- Cleanup is source-native. `APP-INT-01` clears root shell history at 17:40:37. DC process events show `wevtutil cl Security` at 17:41:42, Event 1102 appears at 17:41:43 with EventRecordID 1, and subsequent Security records restart at IDs 4, 6, 7, and 8. The temporary account is deleted at 17:50:27–38.
- Quantitative lifecycle checks found no visible impossibilities: 1,268 eCAR process creates had matching termination records with zero terminate-before-create cases; 847 logon IDs had both login and logout records with zero logout-before-login cases.
- Background evidence has useful entropy: DHCP, Kerberos, LDAP, SMB, SMTP, TLS, OCSP, software updates, proxy failures, web scanners, failed authentication, scheduled tasks, service traffic, and IDS red herrings are mixed through the attack. The DNS tunnel itself has variable 0.006–44.067 second gaps rather than a fixed beacon interval.

## Detailed Analysis

### Scope, volume, and source mix

The collection covers approximately 12:00–18:00 UTC on 18 March 2024. Record counts are:

- eCAR: 25,535
- Zeek: 20,415
- Windows Security: 13,985
- ASA: 12,259
- Sysmon: 4,362
- Linux syslog: 4,166
- Proxy access: 1,935
- Web access: 837
- Bash-history lines: 434
- Snort alerts: 197

The environment contains Windows workstations, a domain controller, file and mail servers, Linux application/database/web/mail/proxy systems, and a laptop. Addressing is internally coherent: the public web server is `10.10.3.10`, proxy is `10.10.3.20`, DC is `10.10.2.10`, file server is `10.10.2.20`, application server is `10.10.2.30`, and database server is `10.10.4.10`.

### Initial access and execution

At 13:20:07, `WEB-EXT-01/web_access.log` records:

`185.70.41.45 ... "POST /ehr/admin/upload.php HTTP/1.1" 200 912`

At 13:20:10.110, endpoint telemetry shows Apache spawning:

`bash -c 'echo ... | base64 -d | bash'`

as `www-data`, with `/usr/sbin/apache2` as parent. The decoded payload opens a reverse shell to `45.33.32.30:8443`. eCAR records that flow at 13:20:18.359, Zeek starts it at 13:20:17.045, and ASA builds it at 13:20:16. The tuple, direction, duration, and teardown agree closely without implausibly identical timestamps.

### Discovery and credential access

A later root SSH session on `WEB-EXT-01` from `10.10.1.36` begins at 13:40:14 and runs host/network discovery, searches `/opt/ehr` for credentials, scans `10.10.2.0/24`, reads `/var/www/html/config.php`, and reads `/root/.ssh/id_rsa`. These processes share the same shell PID, logon ID `0x136670cd`, and session ID 350935.

At 15:45:12–21, `WS-AJOHNSON-01` records the renamed credential-dumping tool and LSASS access. Security 4688, Sysmon/eCAR process telemetry, and eCAR remote-thread telemetry agree on executable, principal, PID, logon context, and target.

### Lateral movement and domain control

The move to `DC-01` uses ordinary network authentication followed by PsExec semantics. Source `10.10.1.35:62306`, target account `aisha.johnson`, target logon ID `0x5553376`, PSEXESVC service creation, dropped binary, service process, and child command are all present in proper order.

Subsequent domain changes originate from a live `WmiPrvSE.exe` PID 2428, not the already terminated PSEXESVC PID 5584. This is a particularly convincing ownership detail. The Windows account-management events follow the process commands with sub-second to two-second delays and maintain one SID for `svc_mhsync`.

Persistence creation similarly aligns across 4688 process events, 4697 service installation, 4698 scheduled task creation, eCAR service records, and later execution of `DeviceSyncSvc.exe`.

### Collection and exfiltration

The temporary privileged account reaches `FILE-SRV-01` over SMB and executes `net view` plus a PowerShell archive operation. The output archive is 314 MB when later observed over SMB. Proxy-side Zeek and ASA then observe an approximately 315 MB TLS upload to the same external infrastructure, with plausible packet and ACK accounting.

Separately, a root SSH session on `DB-PROD-01` conducts MySQL discovery, dumps the `patients` and `insurance_claims` tables, compresses the output, and sends it via SCP to `APP-INT-01`. Bash history, process telemetry, file events, SSH transport, receiver session, and receiver file creation all align.

### Cleanup and lifecycle behavior

The Linux cleanup command appears under the same root session that had been active on `APP-INT-01`. On the DC, clearing Security produces the expected event-record reset. Account deletion occurs after the attack account’s use, and no subsequent use of `svc_mhsync` was found.

The bounded window produces some unmatched process and session endpoints, but matched lifecycle objects contain no visible reversed ordering. This supports a slice-of-time collection rather than a generator that neglected state transitions.

### Baseline and hunt difficulty

The attack is discoverable but not isolated. More than 84,000 records surround it, and suspicious indicators coexist with legitimate administrator SSH/RDP, service-account SMB/Kerberos activity, public web scanning, denied proxy requests, NTP/DHCP, software updates, mail traffic, DNS failures, and IDS policy noise. The hunter can pivot using tuples, logon IDs, process IDs, object IDs, filenames, hashes, and accounts.

The main baseline weakness is the repeated root/PID-1 `wget` construction on both Linux servers. Its timing is jittered—the database median inter-arrival is about 1,457 seconds and the web-server median about 737 seconds—but the identical invocation and target-pool behavior still feel designed.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `distribution_texture` | Linux eCAR/process baseline | 39 processes on 2 hosts | Repeated root/PID-1 `wget` template across unrelated service roles is the strongest synthetic-looking artifact, but remains operationally possible. |
| `weak_signal` | Dataset-wide volume | Six hourly buckets | eCAR and Zeek hourly counts are smoother than expected from many small enterprise collections; attack hours still show a credible lift. |
| `weak_signal` | eCAR and Windows Security | Dataset-wide | Heavy FLOW/5156 concentration makes the collection profile look tuned, but no concrete coverage contradiction results. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows, Zeek, ASA, proxy, web, syslog, and eCAR fields are internally credible, including Security EventRecordID reset after log clearing.
- **Temporal patterns:** 8 — Source latency, connection durations, attack sequencing, and background jitter are convincing; hourly totals are slightly smooth.
- **Cross-source correlation:** 9 — Host, authentication, process, network, file, and proxy pivots work with realistic non-identical timing.
- **Behavioral realism:** 9 — The observed tradecraft is executable and account, privilege, process-parent, host-role, and network-path choices generally make sense.
- **Environmental consistency:** 8 — Roles, subnets, source volumes, and baseline services fit; the uniform root/PID-1 `wget` behavior is the main environmental blemish.

## Recommendations

- If this were synthetic, replace the shared root/PID-1 `wget -q -e use_proxy=yes -O - ...` pattern with service-specific health-check implementations. Use named systemd units or application principals, host-role-appropriate destinations, distinct clients, retry/backoff behavior, and more varied cadence.
- Add somewhat more day-phase and entity-specific variation to baseline volumes so eCAR and connection counts do not remain as even across successive hours. Preserve the current attack-hour lift and variable DNS-tunnel cadence.
- If the FLOW/5156-heavy mix is intentional, retain it; otherwise, vary network-audit observation rates by host role and collector policy so the collection profile is less uniformly network-centric without breaking lifecycle groups.

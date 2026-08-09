# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 76
**Synthetic-Confidence Score:** 29

## Executive Summary

This looks more like a sanitized production collection than a generated exercise: the six-hour environment has believable source volume, noisy role-specific background activity, and several technically coherent attack pivots whose host, network, and lifecycle evidence agree without becoming source-native contradictions. The clearest authenticity marker is the DC Security log reset at 17:42:18Z, where `wevtutil cl Security` is followed by Event 1102 and an `EventRecordID` reset from 28,262,434 to 1; the main residual synthetic concerns are repetitive Linux administration vocabulary and the absence of any UDP/123 traffic from an otherwise broad network collection.

## Evidence For Synthetic

- [distribution_texture] Linux interactive command vocabulary repeats across unrelated users and roles more than I would expect from a small real sample. Exact commands such as `uptime`, `hostname`, `free -h`, `groups`, `journalctl --since '10 min ago' --no-pager -n 20`, and `netstat -an | grep ESTABLISHED | wc -l` recur on multiple hosts, while several administrators repeatedly inspect `systemd-resolved`, `sshd`, and generic resource status. This is not impossible, but the shared diagnostic pool is visible in `APP-INT-01`, `DB-PROD-01`, `MAIL-EDGE-01`, `PROXY-01`, and the Linux workstation histories.
- [environment_or_collection_plausibility] `zeek-core/conn.json` contains 6,408 connections spanning DNS, Kerberos, SMB, LDAP, DHCP, SSH, HTTP(S), mail, RDP, database traffic, and ICMP, but zero UDP/123 connections during the entire six-hour window. With roughly 18 visible endpoints, Windows domain infrastructure, multiple Linux servers, and otherwise detailed infrastructure traffic, at least some NTP/W32Time observation would be expected unless time traffic is specifically routed away from this sensor.
- [distribution_texture] The Linux `sysstat` CRON records are extremely uniform: the identical `debian-sa1 1 1` command appears on fixed 30-minute schedules on many hosts, generally with only a host-specific minute offset and subsecond jitter. This is a legitimate scheduled job, so it is weak evidence by itself, but the environment-wide texture is unusually homogeneous.
- [weak_signal] Several unrelated Linux administrative sessions use the same small set of generic `admin`, `ops`, and `backup` sudo identities and commands such as package checks, `/var/log` inspection, and disk/cache checks. The records are individually plausible, but together they contribute to a curated baseline feel.

## Evidence For Real

- The DC Security lifecycle around log clearing is exceptionally convincing. At 2024-03-18 17:42:16.5704097Z, Event 4688 records `cmd.exe /c wevtutil cl Security`; at 17:42:16.9606364Z another 4688 records `wevtutil.exe`; Event 1102 follows at 17:42:18.8498896Z, and `EventRecordID` resets from 28,262,434 to 1. Earlier records remain in the exported sequence, consistent with forward collection or an event stream that captured them before the local clear.
- The reconnaissance evidence behaves like real Nmap rather than a list of labels. `WEB-EXT-01` runs `nmap -sn 10.10.2.0/24` followed by `nmap -sT -p 22,80,443,445,3306 10.10.2.0/24` at about 13:42:08–29Z. Zeek shows five tested ports across six live targets (approximately 30 scan connections), with a credible mix of `S0`, `REJ`, and short `SF` results; open services return small application exchanges while closed/unanswered ports produce `Sr` or `S` histories.
- A later database-theft pivot is internally coherent across four evidence types. `DB-PROD-01` accepts root SSH from `10.10.2.30:36635` at 17:14:48Z, opens the session at 17:14:51Z, creates `/tmp/rpt_0318.sql` with `mysqldump`, compresses it, then runs `scp` at 17:21:57Z. Zeek records `10.10.4.10:42861 -> 10.10.2.30:22` at 17:21:58.133444Z for 29.213191 seconds with 231,026 origin bytes, while `APP-INT-01` syslog records connection, public-key acceptance, PAM open/close, and logind creation/removal; eCAR records the receiver-side file creation at `/tmp/.cache/rpt_0318.sql.gz`.
- Separate Zeek sensors show plausible independent observations rather than copied rows. The 12:00:10 internal-to-DMZ HTTP request appears in core and DMZ sensors with different UIDs, a roughly 45 ms timestamp offset, slightly different byte/packet counts, and different `missed_bytes`/history texture, while preserving the same tuple and duration.
- DNS has a credible long tail: A, AAAA, PTR, SRV, TXT, MX, NS, and SOA queries are present; results include NOERROR, NXDOMAIN, SERVFAIL, and REFUSED; Windows-style `wpad`, `isatap`, suffix-qualified names, reverse lookups, AD LDAP/Kerberos discovery, and low-frequency failed names appear alongside application lookups.
- Network transport accounting passes basic sanity checks. Across both Zeek connection files, IP byte totals never fall below payload byte totals, TCP `SF` sessions have response packets and positive duration, and states include `SF`, `S0`, `REJ`, `RSTO`, `RSTR`, `S1`, `S2`, `S3`, and `OTH` rather than a single success template.
- TLS behavior includes both TLS 1.2 and 1.3, session resumption, reused certificate serials/fingerprints, certificate-chain fan-out, OCSP, and SNI-specific patterns. For example, repeated `ehr-portal.meridianhcs.com` sessions reuse the same leaf serial/fingerprint across many observations instead of minting a new certificate per flow.
- The source-family mix fits host roles: the DC and file server dominate Windows Security and eCAR volumes; the proxy dominates proxy access and FLOW events; the public web server has high inbound scan/kernel/web activity; mail hosts contain Postfix/Dovecot/SMTP evidence; and Linux workstations contain DHCP/NetworkManager/login noise.
- Background evidence is messy but operationally plausible: DHCP renewals, password/service-account failures, SMB/LDAP/Kerberos traffic, package activity, logrotate/anacron, snapd, irqbalance, mail queues, interactive SSH sessions with variable durations, browser/proxy traffic, certificate validation, and external scan noise all coexist with the intrusion.

## Detailed Analysis

### Scope and orientation

The collection spans approximately 2024-03-18 12:00–18:00Z and exposes about 18 named hosts across workstation, laptop, domain controller, file, application, database, proxy, web, and mail roles. Sources include Windows Security and Sysmon XML, host eCAR JSON, Linux RFC 5424-style syslog and timestamped bash histories, proxy and web access logs, Cisco ASA, two Snort sensors, and two Zeek sensors with connection, DNS, HTTP, TLS/X.509/OCSP, file, SMTP, and DHCP views. Volume is substantial enough to hunt: 6,408 core Zeek connections, 5,467 DMZ connections, 12,176 ASA lines, 7,915 DC Security events, and thousands of endpoint and application events.

### Intrusion hunting and tradecraft

The apparent compromise progresses through technically viable pivots. On `WEB-EXT-01`, a root shell performs host discovery and targeted TCP connect scanning at 13:42Z. The resulting connections are visible as actual port/state combinations rather than merely a host process artifact. Later Windows activity includes credential/account discovery, PsExec/WMI-shaped execution on the DC, creation of `svc_mhsync`, addition to `Domain Admins`, service and scheduled-task persistence, use of that identity on `FILE-SRV-01`, archive staging at `C:\ProgramData\Microsoft\cache_7f3a.zip`, encoded PowerShell egress through the proxy, Security log clearing, and eventual deletion of the temporary domain account.

The activity has plausible ownership. DC commands spawned under `WmiPrvSE.exe` or `PSEXESVC.exe` run as SYSTEM; `DeviceSyncSvc.exe` is subsequently launched by `services.exe`; file-server archive creation is attributed to the newly created account and tied to the appropriate logon ID and process ancestry. The attacker does not depend on an impossible protocol path: network observations show SMB, RPC, Kerberos/LDAP, SSH, proxy, and application transports at the points where the endpoint evidence requires them.

The DB staging sequence is especially strong. The root SSH source is the application server, shell child processes retain one session/logon identity, the dump precedes gzip, gzip output precedes SCP read, the source transport precedes receiver authentication, and the receiver creates the same staged pathname during the SSH window. Zeek's 231 KB source-heavy SSH byte direction is consistent with a compressed file upload, and the receiver's PAM close occurs shortly after transport completion.

### Pivot feasibility and cross-source timing

The collection supports practical pivots by tuple, user, process, and object identity. SSH source ports in syslog match Zeek and eCAR (`42861` in the DB-to-application transfer). Zeek protocol rows share UIDs with connection records, while the two sensor domains appropriately use independent UIDs. Endpoint FLOW records are close to network open time but not mechanically identical, and auth evidence follows the transport rather than preceding it.

The DC log-clear sequence is a particularly useful test of causal ordering. Process creation precedes Event 1102; the EventRecordID reset occurs exactly at the clear boundary; subsequent events continue from the new local record-number epoch. That is an environmental side effect easy to miss in handcrafted data and strongly favors authenticity.

### Baseline and signal-to-noise

The malicious sequence is discoverable but not isolated. The DC and file server produce high-volume authentication, Kerberos, process, module, and SMB activity. External scans create substantial `S0` texture in the DMZ. User browsing, proxy tunnels, mail delivery, web requests, certificate validation, DHCP, scheduled work, administrative SSH, update checks, service health checks, and red-herring DNS/connection anomalies overlap the attack window.

The baseline is also role-sensitive. `WEB-EXT-01` carries 1,028 kernel messages and dense inbound connection noise; `PROXY-01` has 2,576 eCAR FLOW records and 1,741 proxy lines; the DC has 4,556 FLOW observations and hundreds of logon lifecycles; mail servers show Postfix/Dovecot-specific records rather than generic server noise. These distributions make hunting materially different on each host.

The main weakness is vocabulary reuse within interactive Linux activity. Many histories read as selections from the same diagnostic repertoire despite different people and server roles. The repetition is not enough to outweigh the lifecycle and source-native detail, but it lowers behavioral realism. The complete lack of visible NTP is the other notable environmental gap because this is not a narrow endpoint-only collection: Zeek captures other infrastructure UDP traffic, including DNS, Kerberos, and DHCP.

### Network and source-native plausibility

The network sources exhibit healthy entropy. Core connection counts vary from 1 to 71 per minute while every minute remains active; states are dominated by successful connections but include a meaningful failure/reset tail. DMZ traffic is much more failure-heavy because of Internet scanning (1,280 `S0` of 5,467 records), which fits sensor position. DNS includes response-time variation, authoritative and recursive behaviors, missing answers on errors, realistic TTL reuse, and Windows suffix-search artifacts.

The dual view of cross-zone flows is not a suspicious duplicate: sensor-local UIDs and accounting differ in ways consistent with observation position. ASA build/teardown evidence supplies another independent path. TLS leaf certificates reuse serials and fingerprints while Zeek file IDs vary per certificate observation, which is the expected distinction between certificate identity and file-analysis identity.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact on score |
|---|---|---|---|
| `distribution_texture` | Bash history / Linux eCAR process telemetry | Multiple Linux hosts and users | Recurrent exact diagnostic commands and shared troubleshooting themes make user activity feel partially pool-driven; moderate, not decisive. |
| `environment_or_collection_plausibility` | Zeek connection telemetry | Entire six-hour core view | Zero UDP/123 among 6,408 otherwise broad connections is an unexplained infrastructure-traffic gap; moderate-low impact because routing could explain it. |
| `distribution_texture` | Linux syslog | Most Linux hosts | Identical `debian-sa1 1 1` jobs on uniform 30-minute host-staggered schedules add smoothness, though legitimate configuration management could produce this; low impact. |
| `weak_signal` | Linux syslog / histories | Several servers | Reuse of generic admin identities and maintenance commands across roles suggests curated noise; low impact. |

No `hard_contradiction`, material `contract_gap`, or consequential `schema_or_format` defect was found. That absence, together with the log-clear reset and coherent scan/SSH/file-transfer lifecycles, keeps the synthetic-confidence score in the mostly realistic range.

## Realism Score by Category

- **Field format accuracy:** 9/10 — Source-native fields, protocol states, Windows record IDs, certificate identity, and byte accounting are consistently plausible.
- **Temporal patterns:** 9/10 — Transport-before-auth ordering, variable session durations, sensor offsets, log clearing, and scheduled/background activity are coherent; scheduled Linux texture is slightly too homogeneous.
- **Cross-source correlation:** 9/10 — Host, Zeek, firewall, syslog, eCAR, file, proxy, and Windows evidence pivot cleanly without impossible ordering.
- **Behavioral realism:** 8/10 — Tradecraft and role behavior work technically, but repeated Linux diagnostic vocabulary reduces individual human texture.
- **Environmental consistency:** 8/10 — Host-role volumes and services fit well; unexplained absence of NTP from a broad core sensor is the principal gap.

## Recommendations

- If this were synthetic, diversify Linux administrative behavior by persona and host role. Reduce exact cross-user repeats of generic commands and give DB, mail, proxy, application, and workstation administrators distinct tools, path conventions, investigation sequences, and command parameterization.
- Add realistic NTP/W32Time traffic, or make the collection topology visibly explain why UDP/123 is absent. A small number of stable per-client polls with jitter, retries, and source-appropriate servers would close the largest environmental distribution gap.
- Vary scheduled Linux maintenance profiles across operating-system images. Keep legitimate fixed CRON timing where configured, but mix sysstat presence/cadence, systemd timers, cron/anacron behavior, and occasional collection loss rather than applying the same half-hour job broadly.
- Preserve the source-native strengths: independent sensor UIDs/accounting, certificate identity reuse, EventRecordID reset on log clearing, transport-before-auth ordering, and file-transfer lifecycle correlation materially improve authenticity.

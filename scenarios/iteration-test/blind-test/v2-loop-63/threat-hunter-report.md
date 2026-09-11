# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 29

## Executive Summary

The dataset appears production-like: its six-hour window contains role-appropriate background activity across 21 endpoints, substantial network and endpoint noise, and technically coherent attack activity with realistic timing differences between independent sources. I found no hard contradictions or impossible lifecycle ordering, although a small number of orphaned SSH syslog closures and unusually repetitive Sysmon ProcessAccess bursts create limited synthetic suspicion.

## Evidence For Synthetic

- `[contract_gap]` Four SSH sessions contain only a source-local `pam_unix(sshd:session): session closed` record despite the corresponding `sshd` process visibly starting inside the capture window. Examples include APP-INT-01 PID `1935728` closing at `17:16:38.475216Z`, DB-PROD-01 PID `869004` at `16:00:24.432524Z`, LOG-MON-01 PID `683093` at `13:09:45.623088Z`, and WEB-EXT-01 PID `1489244` at `14:58:49.824773Z`. Their eCAR records show process creation, activity, and termination, so these are not merely pre-window sessions.
- `[distribution_texture]` Of 709 Sysmon Event ID 10 ProcessAccess records, 144 occur in 65 clusters where identical source process, target process, thread, access mask, and call trace repeat within 50 milliseconds. Most are defensible two-record bursts, but DC-01 contains five identical accesses at `17:56:27.527717Z–17:56:27.543905Z`, exactly 4.047 milliseconds apart, while DC-02 has similarly repeated microsecond-scale spacing. Real applications can generate such loops, but the precise cadence is mildly generator-like.
- `[weak_signal]` The ProcessAccess burst behavior is mirrored in eCAR rather than appearing as a Sysmon-only collection artifact. This does not create a contradiction, but it preserves the unusually regular texture across two representations.

## Evidence For Real

- The source mix and volume fit the visible environment: 10 Windows and 11 Linux endpoints, approximately 34,667 eCAR records, 20,723 Zeek connection records across three sensors, 20,448 ASA messages, 2,887 proxy records, 700 web requests, and 178 Snort alerts.
- Host roles affect volume and vocabulary. Domain controllers carry substantially more Kerberos, logon, WFP, process, and module activity; the proxy has paired client and upstream flows; the web server has Apache traffic and internet scanning; and the database, mail, monitoring, and file systems show role-specific services and commands.
- Initial access is technically consistent. A `POST /ehr/admin/upload.php` from `185.70.41.45` returns HTTP 200 at `13:19:36`; Apache spawns a base64-decoding reverse-shell command at `13:19:42.672`; and WEB-EXT-01 connects to `45.33.32.30:8443` shortly afterward. Zeek records an `SF` connection beginning `13:19:45.880022`, and the ASA records connection `1683224` from `13:19:46` to `13:20:02`, with compatible duration and byte accounting.
- SSH activity preserves operational ordering. For the `13:39` LT-MRIVERA-02-to-WEB-EXT-01 session, the source `ssh` process starts at `13:39:17.399`, transport appears at `13:39:26.622585`, the target reports connection and public-key acceptance at `13:39:30.927` and `13:39:37.028`, and subsequent shell and `nmap` activity uses the same session.
- Independent sensors are not unrealistically identical. The same SSH flow begins at `13:39:26.622585` on the DMZ Zeek sensor and `13:39:26.736864` on the core sensor, with different UIDs and `370` missed bytes on one observation.
- The Windows portion contains realistic state changes rather than isolated command strings: PSEXESVC file and service creation, account creation Event ID 4720, Domain Admins membership Event ID 4728, service installation Event ID 4697, and later account deletion Event ID 4726.
- Exfiltration is internally consistent. WS-AJOHNSON-01 launches `curl.exe` using proxy `10.10.3.20:8080`, reads `cache_7f3a.zip`, and opens source port `61811`. The proxy logs the same port and an `18,782,996`-byte POST at `17:24:44`; its upstream flow uses port `57890`; Zeek observes `18,788,574` application bytes plus packet overhead; and the ASA closes the connection after 18 seconds with `19,727,547` bytes.
- Background traffic includes failed and successful web requests, browsing asset fan-out, Windows Update, monitoring APIs, mail, DNS failures, DHCP renewals, service-account noise, internet scans, STUN, P2P alerts, and varied TCP terminal states.
- Automated lifecycle checks found no same-identifier logoff-before-logon, process-termination-before-create, authentication-before-transport, negative duration, invalid port, overlapping Zeek TCP tuple, or file-byte-accounting contradiction.

## Detailed Analysis

### Scope and source orientation

The logs cover approximately `2024-03-18 12:00–18:00 UTC`. The environment contains three Zeek observation points (`core`, `db`, and `dmz`), a perimeter ASA, core and perimeter Snort sensors, a proxy, a public web server, two domain controllers, Windows workstations and servers, and multiple Linux application, database, mail, file, and monitoring systems.

The source-family distribution is plausible for that topology. Zeek-core records 11,553 connections, Zeek-DMZ 8,663, and the database sensor 507. DC-01 and DC-02 each produce several thousand Windows Security, Sysmon, and eCAR records, while ordinary endpoints produce markedly less. This is preferable to a flat per-host event budget.

### Initial access and foothold

Snort shows repeated HTTP/HTTPS scanning by `185.70.41.45` beginning around `12:32`, while the web log contains a mixture of successful, forbidden, redirected, server-error, and not-found responses. The scanning is not mechanically uniform: source ports, intervals, durations, and Zeek terminal states vary.

At `13:19:36`, the same source posts to `/ehr/admin/upload.php` and receives status 200. At `13:19:42.672`, WEB-EXT-01 records an Apache child launching:

`bash -c 'echo … | base64 -d | bash'`

The decoded payload opens a reverse shell to `45.33.32.30:8443`. The subsequent Zeek, eCAR, and ASA records agree on source `10.10.3.10:57346`, destination `45.33.32.30:8443`, and a roughly 16-second completed TCP session. The process terminates at `13:20:12.049`, after the transport closes.

### Discovery and lateral movement

A modeled SSH session from LT-MRIVERA-02 (`10.10.1.99:49752`) to WEB-EXT-01 begins with a real source-side `/usr/bin/ssh` process, followed by network transport, target authentication, shell creation, recon commands, and process termination. Commands include interface and resolver inspection, credential-file discovery, an ICMP-style subnet discovery, and a TCP connect scan of ports `22,80,443,445,3306`.

The long-running SSH transport remains open until approximately `14:24:51`, and its source and target process/session closures occur around the network close. A second root session from WS-PPATEL-01 at `14:00` similarly has transport before authentication and accesses `/var/www/html/config.php` and `/root/.ssh/id_rsa`.

Across 66 examined SSH and RDP target logins, every authentication had a compatible transport flow visible before it. I found no self-sourced remote login or source-port disagreement.

### Windows privilege and persistence activity

At `15:59:45.7957184Z`, DC-01 Security Event ID 4697 records installation of `PSEXESVC` by `aisha.johnson`. The endpoint evidence also includes the dropped `C:\Windows\PSEXESVC.exe`, service creation, execution under SYSTEM, child `cmd.exe`, module loads, and termination.

At `16:14:42.7009749Z`, Event ID 4720 records creation of `svc_dirsync`. Event ID 4728 at `16:14:47.6687406Z` adds its SID to Domain Admins. At `16:20:33.2822515Z`, Event ID 4697 records `DeviceSyncSvc`, accompanied by `sc.exe`, `schtasks.exe`, service execution, and module-load evidence.

At `17:42:22`, `wevtutil cl Security` executes. Security Event ID 1102 appears at `17:42:26.1855251Z` with EventRecordID `1`, and later records continue from the reset sequence. That is a particularly strong source-native effect rather than merely a command claiming to clear the log.

### Collection and exfiltration

DB-PROD-01 runs `mysqldump --single-transaction ehr patients insurance_claims` at approximately `17:15:18`, compresses the result, and transfers it by SCP to APP-INT-01. The target eCAR record attributes creation of `/tmp/.cache/rpt_0318.sql.gz` to the receiving `sshd` process. The file is subsequently staged through SMB before outbound transfer.

At `17:24:44`, WS-AJOHNSON-01 executes `curl.exe --proxy http://10.10.3.20:8080` against an upload endpoint. Client eCAR, inbound proxy eCAR, the proxy access record, proxy upstream eCAR, Zeek-DMZ, TLS metadata, and ASA NAT/teardown records agree on the two transport legs and byte direction. The large byte count is surrounded by numerous much smaller contacts to the same destination, making the anomalous transfer visible without requiring an implausibly empty baseline.

### Lifecycle and temporal integrity

The eCAR corpus contains 2,082 process creates and 1,896 process terminations. Of those terminations, 1,802 match a visible create by object ID and none precedes its create. The unmatched terminations are compatible with processes that started before the six-hour slice.

Windows Security logs contain no logoff whose same LogonID is first created later, and Sysmon contains no Event ID 5 whose ProcessGuid is created afterward. Zeek records have non-negative durations, valid port ranges, internally consistent IP-byte calculations, and no overlapping reuse of the same TCP five-tuple on one sensor. DHCP conversations use correct client/server ports and show lease renewals near T/2 with per-host jitter.

### Collection anomalies

The clearest defect is the four close-only SSH syslog lifecycles. Because each corresponding `sshd` child is created inside the window and other SSH sessions on the same hosts contain connection, acceptance, PAM-open, and close messages, the slice-boundary explanation does not apply. UDP syslog loss or selective forwarding could explain this in a real environment, but the repeated shape across four hosts resembles an event-level observation model that dropped related records independently.

The Sysmon Event ID 10 bursts are less decisive. Tight repeated OpenProcess calls are normal for some services and security products, and 55 of the 65 clusters contain only two records. The two five-record bursts with identical metadata and exact repeated spacing nevertheless contribute modestly to the synthetic score.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---:|---|
| `contract_gap` | Linux syslog versus eCAR/transport | 4 SSH sessions on 4 hosts, out of approximately 72 observed SSH PID groups | In-window sessions retain only their close message, creating repeated source-local orphan closures. |
| `distribution_texture` | Sysmon Event ID 10 and eCAR ProcessAccess | 144 of 709 records in 65 sub-50 ms clusters; two clusters contain 5 records | Exact repeated metadata and microsecond cadence are somewhat more regular than expected, although rapid API loops remain plausible. |
| `hard_contradiction` | All examined families | None found | No impossible ordering, field value, tuple reuse, byte accounting, or identity leak materially raised the score. |

## Realism Score by Category

- **Field format accuracy:** 9 — Windows XML, Zeek JSON, RFC 5424 syslog, ASA, Snort, proxy, and web fields are source-appropriate and internally valid.
- **Temporal patterns:** 8 — Broad activity timing and lifecycle durations are convincing, reduced by the tightly repeated ProcessAccess bursts.
- **Cross-source correlation:** 8 — Network, authentication, process, file, proxy, and firewall evidence pivot cleanly, with four source-local SSH lifecycle gaps.
- **Behavioral realism:** 9 — Host placement, commands, privilege context, network paths, and observable effects are operationally credible.
- **Environmental consistency:** 9 — Volumes, services, users, traffic, and alert families vary appropriately by endpoint and network role.

## Recommendations

If this were synthetic, the following changes would improve it:

- Apply syslog observation loss coherently to SSH lifecycle groups. If authentication/open records are intentionally absent, either suppress the corresponding close or model an explainable collector outage or message-loss interval affecting adjacent records, rather than producing isolated close-only sessions across unrelated hosts.
- Vary rapid ProcessAccess burst size and inter-call timing from an application-specific distribution. Avoid five identical records at exactly repeated millisecond intervals unless that cadence is tied to a modeled polling loop.
- Preserve the existing role-scaled volume, independent sensor offsets, incomplete packet visibility, lifecycle termination, and proxy-leg accounting; these features materially improve production realism.

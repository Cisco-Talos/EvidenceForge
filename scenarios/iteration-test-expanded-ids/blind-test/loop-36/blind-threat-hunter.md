# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real
**Verdict Confidence:** 67
**Synthetic-Confidence Score:** 32

## Executive Summary

This six-hour collection looks more like sanitized production telemetry than a synthetic exercise: suspicious activity is embedded in substantial, role-appropriate background traffic, and the key file-access, staging, lateral-transfer, and exfiltration pivots remain coherent across endpoint, Windows, Zeek, and proxy sources. The main authenticity concern is a missing network-management transport for a target-side WMI process chain on FILE-SRV-01; otherwise, the collection has convincing environmental entropy, source-specific observation differences, and lifecycle detail.

## Evidence For Synthetic

- `[contract_gap]` At 2024-03-18T17:01:02Z, FILE-SRV-01 records a successful type-3 login for `svc_mhsync` from `10.10.1.35`, followed by `cmd.exe /c net view \\FILE-SRV-01` whose parent is `WmiPrvSE.exe`, and then PowerShell archive staging. In `zeek-core/conn.json`, the only contemporaneous connection between `10.10.1.35` and `10.10.2.20` is TCP/445 (`CVaEBuWJyWvuEgWULD6`, 17:01:00.643Z); there is no TCP/135 or dynamic RPC/DCOM flow. If this was remote WMI execution, the visible transport is incomplete despite otherwise detailed internal-flow collection.
- `[distribution_texture]` Eight Linux systems repeatedly launch the identical `debian-sa1 1 1` process pair on nearly exact 1,800-second boundaries. Missed intervals and per-host phase offsets soften this indicator, and cron can naturally be regular, but the shared command vocabulary and near-zero interval variance create a mildly templated background texture.
- `[weak_signal]` Endpoint process/module telemetry is unusually normalized: many short Windows processes receive the same compact set of DLL-load observations within milliseconds, while some operationally important processes are observed only in Security/Sysmon and not eCAR. This can be explained by selective EDR collection, but the consistency of the selection profile is cleaner than many production deployments.

## Evidence For Real

- The suspicious archive path has a technically credible cross-source lifecycle. FILE-SRV-01 creates `C:\ProgramData\Microsoft\cache_7f3a.zip` at 17:01:04.645Z. At 17:22:04.114Z, Zeek observes an SMB transfer from `10.10.2.20` to `10.10.1.35` with 314,340,609 response bytes; endpoint telemetry then records Chrome reading `C:\Users\aisha.johnson\AppData\Local\Temp\cache_7f3a.zip` at 17:22:15.504Z.
- The subsequent upload correlates independently across endpoint, proxy, and network data. WS-AJOHNSON-01 records Chrome connecting to proxy `10.10.3.20:8080` at 17:24:57.187Z. Zeek records the corresponding flow at 17:24:57.209Z with 314,783,385 origin bytes, and `proxy_access.log` records an authenticated POST by `MERIDIANHCS\aisha.johnson` to `/upload/telemetry/7f3a2b19` with `cs_bytes=314782961`.
- DB collection and staging are operationally coherent. DB-PROD-01 records `mysqldump --single-transaction ehr patients insurance_claims`, creation and gzip compression of `/tmp/rpt_0318.sql`, and later `scp` to `10.10.2.30`. Zeek records the matching SSH connection at 17:41:06.832Z from `10.10.4.10:43584` to `10.10.2.30:22`, while APP-INT-01 records the receiver-side file creation at `/tmp/.cache/rpt_0318.sql.gz`.
- The malicious activity is genuinely buried in baseline volume. The collection contains roughly 6,152 core Zeek connections, 5,624 DMZ connections, and over 36,000 eCAR records across 17 named hosts. eCAR alone includes 15,960 flows, 1,755 process creates, 1,170 logins, registry activity, file activity, and lifecycle terminations.
- Network behavior is not uniformly successful or smooth. Core Zeek includes `SF`, `RSTO`, `RSTR`, `REJ`, `OTH`, `S0`, `S1`, `S2`, and `S3` states. The DMZ includes unsolicited SSH, Telnet, SMTP, database, and ICMP traffic from varied external addresses, with firewall teardowns such as a 30-second SSH SYN timeout at 12:01:21.
- Host roles and user behavior differ visibly. The DC produces Kerberos, LDAP, DNS, account-management, service, and scheduled-task evidence; FILE-SRV-01 carries SMB and archive activity; PROXY-01 supplies explicit CONNECT/inspection records; WEB-EXT-01 receives noisy public traffic; Linux administrators use SSH, `systemctl`, `journalctl`, Docker, Git, and database clients; workstation users generate browser, Office, VPN, Zoom, SMB, and RDP activity.
- Dual Zeek sensors observe some shared DMZ-bound flows with close but non-identical timestamps and independent UIDs—for example the 17:24:57 proxy upload appears in both sensor views. That is consistent with separately running sensors rather than one mechanically reused record.
- Cleanup behavior has source-native companions: DC-01 records encoded PowerShell at 17:42:28.438Z, `wevtutil cl Security` at 17:42:28.713Z, and Security Event 1102 at 17:42:29.678Z. The temporary domain account is deleted at 17:50:22.

## Detailed Analysis

The visible window is approximately 2024-03-18T12:00:00Z through 18:00:00Z. The environment includes Windows workstations, a domain controller, a file server, a Windows mail server, Linux workstations and servers, a proxy, an external web server, an application server, a database server, core and DMZ Zeek sensors, perimeter ASA telemetry, and core/perimeter Snort alerts.

The main suspicious chain begins on DC-01. At 16:14:56.264Z, `WmiPrvSE.exe` spawns:

`C:\Windows\System32\cmd.exe /c net user svc_mhsync MhsSvc!2024 /add /domain`

The child `net.exe` runs at 16:14:56.410Z. At 16:14:59.492Z, the same WMI parent launches `net group "Domain Admins" svc_mhsync /add /domain`. Windows Security records account-management and group-membership events, while Sysmon and eCAR expose the process lineage. At 16:20:00Z, the same parent creates `DeviceSyncSvc`, pointing to `C:\Windows\System32\DeviceSyncSvc.exe`, and schedules `\Microsoft\Windows\Maintenance\DeviceSync` hourly. The binary executes as SYSTEM at 16:31:42.184Z.

At 17:01:02.455Z, FILE-SRV-01 accepts a type-3 session for `svc_mhsync` from Aisha Johnson's workstation address, `10.10.1.35`, using source port 51268. The corresponding Zeek SMB connection begins at 17:01:00.643Z and remains open for 27.615970 seconds. The target then executes share discovery and creates a ZIP containing the Finance Q1 and Patients Exports trees. This is technically plausible target-side execution, but the WMI parentage without RPC/DCOM transport is the collection's clearest contract concern.

At 17:15:44Z, DB-PROD-01 runs `mysqldump --single-transaction ehr patients insurance_claims`, creating `/tmp/rpt_0318.sql`; it checks the artifact, compresses it with `gzip -9`, and later transfers it to APP-INT-01 over SCP. The receiver creates `/tmp/.cache/rpt_0318.sql.gz` at 17:41:12.534Z, approximately six seconds after the source-side SSH connection begins. These timestamps, host addresses, user context, and file paths align.

The file-server archive follows an even stronger transfer path. Zeek records a large SMB response to WS-AJOHNSON-01 beginning at 17:22:04.114Z and ending about 10.4 seconds later. Chrome reads the local copy at 17:22:15.504Z, then opens the proxy flow at 17:24:57. Endpoint eCAR, two network-sensor views, and the proxy agree on the client, proxy, destination, method, object, and approximate byte magnitude. This is a feasible threat-hunting pivot rather than merely matching labels.

The proxy also contains background requests to the same destination family from DC-01 and WEB-EXT-01, including periodic `/api/v2/checkin` and `/assets/status` requests. That complicates a simple domain-based hunt and is realistic from an analyst's perspective: the high-volume authenticated POST and source process matter more than the hostname alone.

Signal-to-noise is believable for a bounded collection. Core traffic is dominated by successful DNS, HTTP, Kerberos, SMB, and LDAP, but it includes failed and reset connections. The DMZ supplies a separate layer of public scan noise. Endpoint telemetry contains regular system processes, updates, monitoring, logons, RDP, SSH, browser sessions, file-share access, and admin activity. The suspicious records remain discoverable but do not dominate total volume.

The cleanup phase is also coherent. Encoded PowerShell on DC-01 downloads from `/v2/manifest` through the explicit proxy path, then `wevtutil` clears the Security log and generates Event 1102. The account is deleted eight minutes later. Earlier Security records surviving in the supplied XML are plausible if this collection represents forwarded telemetry rather than a post-incident export of the local channel.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Effect on score |
|---|---|---|---|
| `contract_gap` | eCAR, Zeek core | FILE-SRV-01 remote WMI-like execution at 17:01 | No visible DCOM/RPC transport accompanies target-side `WmiPrvSE.exe` children; this was the largest upward pressure on the synthetic score. |
| `distribution_texture` | Linux eCAR/process telemetry | Eight Linux hosts across the window | Identical sysstat command pairs recur at nearly exact 30-minute intervals; plausible cron behavior, but with limited command and timing variance. |
| `weak_signal` | Windows eCAR/Sysmon | Multiple Windows hosts | Compact, consistently selected DLL-load sets and uneven cross-source process observation look normalized, though a selective collection policy could explain them. |

## Realism Score by Category

- **Field format accuracy:** 8 — Source-native values, paths, account names, ports, logon types, proxy fields, and Zeek connection states are generally credible.
- **Temporal patterns:** 8 — Human, service, public-scan, transfer, and cleanup timing is varied and causally ordered; cron telemetry is the main overly regular element.
- **Cross-source correlation:** 9 — SMB staging, proxy upload, SSH/SCP transfer, account changes, and log clearing pivot cleanly across independent sources.
- **Behavioral realism:** 8 — Host roles, user tools, administrative behavior, public noise, and attacker actions are operationally plausible and well buried.
- **Environmental consistency:** 8 — Source volumes and service placement fit a small segmented enterprise, with the remote-WMI transport gap preventing a higher score.

## Recommendations

If this were synthetic, here's what would improve it:

- Add the required RPC endpoint-mapper and negotiated high-port DCOM connections when a remote source causes `WmiPrvSE.exe` to launch target-side commands. Tie those flows to the same source host, session, and execution window as the type-3 login.
- Increase Linux scheduled-workload texture by varying sysstat schedule policies among hosts, including realistic package/version differences, service-disabled hosts, delayed cron execution, and occasional collection gaps.
- Make the endpoint observation profile visibly host- or policy-dependent. Vary which module-load families are collected and preserve coherent process-level sampling so Security, Sysmon, and eCAR omissions resemble distinct deployed policies rather than one normalized global filter.

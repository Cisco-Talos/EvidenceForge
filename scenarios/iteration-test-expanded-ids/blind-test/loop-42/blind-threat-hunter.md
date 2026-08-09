# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Inconclusive  
**Verdict Confidence:** 74  
**Synthetic-Confidence Score:** 43

## Executive Summary

This is a broadly production-like six-hour enterprise telemetry slice with convincing background volume, host roles, attack tradecraft, lifecycle timing, and pivots across endpoint, network, authentication, proxy, firewall, and application sources. The principal authenticity concern is a recurring remote-execution contract gap: WMI-attributed commands appear on Windows targets without the required visible RPC/DCOM or WinRM transport and without a source-side caller, while a separate WEB-EXT-01-to-APP-INT-01 SSH pivot similarly lacks a source client process despite dense endpoint coverage.

## Evidence For Synthetic

- `[contract_gap]` At `2024-03-18T17:01:28Z`, FILE-SRV-01 records a successful `svc_mhsync` network session from `10.10.1.35:65259`, followed immediately by `cmd.exe /c net view \\FILE-SRV-01` under `WmiPrvSE.exe` and a PowerShell archive command. The only corresponding Zeek connection from `10.10.1.35` to `10.10.2.20` is SMB/445 (`Cuc97ExCrqHBTqqGKd`); there is no DCOM endpoint-mapper/dynamic RPC or WinRM transport, nor a source-side WMI/PowerShell caller on WS-AJOHNSON-01.
- `[contract_gap]` The same unexplained WMI execution texture recurs on DC-01. Every visible `WmiPrvSE.exe` child is attack-related: domain-account creation and group addition around `16:14:42Z`, service/task persistence around `16:19:38Z`, Security-log clearing at `17:42:13Z`, and account deletion at `17:49:48Z`. The earlier `10.10.1.35 -> 10.10.2.10:135` DCE/RPC connection at `15:59:53Z` lasts only 0.768 seconds and cannot carry commands occurring 15–110 minutes later; no corresponding dynamic RPC or WinRM sessions explain the later actions.
- `[contract_gap]` Zeek shows a successful, long-lived SSH connection from WEB-EXT-01 `10.10.3.10:34882` to APP-INT-01 `10.10.2.30:22` beginning at `14:15:07Z`. APP-INT-01 has destination-side `sshd`, login, shell, and closure evidence, but WEB-EXT-01 has only an actorless FLOW record—no visible `/usr/bin/ssh` process or client command—despite recording the contemporaneous root shell and its other child commands.
- `[weak_signal]` Source-side omission is concentrated on operationally important remote-execution steps rather than appearing as an obvious general collection-loss pattern. Real endpoint telemetry can drop individual records, but repeated gaps at the same semantic boundary look more modeled than organically incomplete.

## Evidence For Real

- The collection covers approximately `12:00–18:00 UTC` across 18 instrumented hosts and several additional observed systems, with 24,499 eCAR records, 6,051 core and 5,037 DMZ Zeek connections, substantial Windows Security/Sysmon volume, firewall, IDS, proxy, web, syslog, DHCP, DNS, TLS, SMTP, and file telemetry.
- The initial compromise is technically coherent: a `13:20:07Z` POST to `/ehr/admin/upload.php`, an Apache/PHP error naming the same client, a `www-data` shell spawned under Apache at `13:20:09Z`, and an outbound reverse-shell connection to `45.33.32.30:8443` at `13:20:12Z`. Firewall and Zeek connection timing agree with the endpoint evidence.
- Follow-on tradecraft is credible: internal discovery with `nmap`, configuration and SSH-key access, credential dumping through renamed `ms-index-service.exe` with high-access LSASS open and remote-thread evidence, PsExec service deployment, domain-account creation, persistence, file-server collection, database dumping, SCP staging, proxy-mediated upload, DNS tunneling, and anti-forensic cleanup.
- Several pivots have strong source/destination symmetry. Examples include WS-EBROOKS-01 `ssh.exe` to WEB-EXT-01 at `13:39`, APP-INT-01 `ssh` to DB-PROD-01 at `17:15`, and DB-PROD-01 `scp` to APP-INT-01 at `17:25`; tuples, principals, ports, destination sessions, and process lifetimes align.
- Baseline activity is substantial and role-aware: Kerberos, LDAP, SMB, proxy use, web traffic, DHCP, DNS, NTP-like infrastructure traffic, external scanning, SSH administration, scheduled maintenance, mail traffic, Windows Update, health checks, package activity, service-account noise, and ordinary user applications obscure the malicious activity.
- Visible same-identifier lifecycle ordering is coherent. Processes, sessions, and positive-duration network observations examined did not show dependents preceding visible initiators. I did not penalize closures at the beginning or missing closures beyond the bounded collection window.
- Source-native visibility is appropriately different in many places: encrypted web requests are detailed in Apache rather than Zeek HTTP, proxy clients connect to the proxy while the proxy resolves and reaches the origin, and inbound scanning produces S0/REJ texture rather than fabricated successful sessions.

## Detailed Analysis

### Scope and Environment Orientation

The visible environment contains a domain controller, file server, Windows mail server, external web server, application and database tiers, explicit proxy, Linux mail infrastructure, and mixed Windows/Linux workstations. Core Zeek traffic is dominated by DNS, Kerberos, SMB, HTTP/proxy, LDAP, SSH, DHCP, SMTP, and RDP; DMZ traffic includes public web service exposure, proxy egress, database access, and realistic unsolicited scanning.

Traffic is not unnaturally flat. Core Zeek minute volumes vary from 1 to 66 connections, while DMZ volumes vary from 1 to 45. Connection states include successful sessions plus RST, REJ, S0, OTH, S2, and S3 outcomes. The visible source-family mix is believable for a small healthcare-like environment with unusually rich endpoint and network collection.

### Initial Access and Web Compromise

At `13:20:07Z`, WEB-EXT-01 receives:

`POST /ehr/admin/upload.php HTTP/1.1` from `185.70.41.45`, status 200.

The same inbound connection is visible in the firewall and Zeek TLS logs. Apache logs an SQL syntax/access-violation message for the same client and worker process. At `13:20:09.727Z`, Apache PID 23965 spawns:

`bash -c 'echo ... | base64 -d | bash'`

as `www-data`, followed at `13:20:12.096Z` by `10.10.3.10:48697 -> 45.33.32.30:8443`. This is a strong, technically credible server-side execution chain.

### Discovery, Credential Access, and Lateral Movement

A root SSH session from WS-EBROOKS-01 to WEB-EXT-01 begins around `13:39:39Z`. Source-side `cmd.exe -> ssh.exe root@WEB-EXT-01...`, destination `sshd`, login, shell, and network telemetry align. That session runs network discovery, accesses `/var/www/html/config.php` and `/root/.ssh/id_rsa`, and remains alive through later actions.

At `14:15:07Z`, WEB-EXT-01 connects to APP-INT-01 over SSH, and APP-INT-01 establishes a root shell that lasts until `17:57`. The destination lifecycle and Zeek duration agree closely. The missing source SSH process on WEB-EXT-01 is the notable break in this otherwise convincing path.

WS-AJOHNSON-01 later executes renamed credential-dumping tooling:

`ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit`

at `15:44:52Z`. It opens winlogon and LSASS, requests `0x1FFFFF` access to LSASS, and creates a remote thread. This sequence is operationally convincing and distinguishable from the plentiful low-access benign LSASS opens by Windows components.

At `15:59:53Z`, WS-AJOHNSON-01 initiates SMB and RPC traffic to DC-01; DC-01 receives `PSEXESVC.exe`, creates the PSEXESVC service, launches it, and executes `cmd.exe /c whoami && hostname`. This specific remote-service bundle is coherent.

### Privilege, Collection, and Exfiltration

DC-01 creates `svc_mhsync`, adds it to Domain Admins, and installs `DeviceSyncSvc` plus an hourly scheduled task. Appropriate process, service, and Security log evidence is present.

At `17:01:28Z`, FILE-SRV-01 receives a Type 3-style session for `svc_mhsync` from WS-AJOHNSON-01, runs self-enumeration, and creates `C:\ProgramData\Microsoft\cache_7f3a.zip` from Finance and patient-export paths. Later, WS-AJOHNSON-01 copies the archive locally; Zeek reports approximately 313 MB transferred over SMB, Chrome reads the local archive, and the client uses the explicit proxy to reach the upload endpoint.

Separately, APP-INT-01 opens an attributable SSH client connection to DB-PROD-01. DB-PROD-01 runs MySQL discovery, dumps selected healthcare-related tables, compresses the result, and transfers `/tmp/rpt_0318.sql.gz` back to APP-INT-01 via SCP. Source `scp`, network transport, target `sshd`, target-side file creation, and session closure are aligned.

Proxy behavior is especially convincing: the client connects to `10.10.3.20:8080`, while PROXY-01 performs resolver and origin egress activity. Denied direct-IP CONNECT attempts and successful hostname tunnels have plausible status and timing differences.

### Cleanup and Lifecycle Coherence

APP-INT-01 clears root shell history, WEB-EXT-01 shreds its root history, DC-01 clears the Security log, and the temporary domain account is later deleted. These actions occur after the dependent collection and staging steps.

The dataset includes many sessions and processes already active at the beginning and others still active near the end. I treated those as bounded-window artifacts. I found no same-ID visible close-before-open or child-before-visible-parent contradiction.

### Main Authenticity Concern

The remote-WMI family does not carry the operational prerequisites needed to explain the target processes. SMB authentication alone does not transport remote `Win32_Process.Create`; classic WMI requires DCOM/RPC endpoint mapping and a dynamic RPC connection, while CIM/WinRM requires 5985/5986. Dense source endpoint and Zeek collection makes the repeated absence of both the client process and transport harder to explain as an ordinary collection gap.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Score impact |
|---|---|---|---|
| `contract_gap` | eCAR, Zeek, Windows remote execution | Repeated across FILE-SRV-01 and DC-01 WMI-attributed attack commands | High: target execution lacks a viable remote transport and source caller |
| `contract_gap` | eCAR and Zeek SSH | One critical WEB-EXT-01 → APP-INT-01 pivot | Medium: destination lifecycle is complete, but the initiating host has no SSH client process |
| `weak_signal` | Endpoint collection profile | Concentrated around remote-execution initiators | Low-to-medium: omissions are possible in production, but their semantic concentration looks modeled |

## Realism Score by Category

- **Field format accuracy:** 8 — Major fields, principals, ports, commands, and identifiers are operationally useful and largely source-appropriate.
- **Temporal patterns:** 9 — Baseline timing varies, attack prerequisites precede effects, and session/process/network lifetimes are coherent.
- **Cross-source correlation:** 7 — Most pivots correlate very well, but WMI transport and one SSH initiator are materially incomplete.
- **Behavioral realism:** 8 — Both adversary tradecraft and routine administrative/user behavior fit the visible host roles.
- **Environmental consistency:** 8 — Source volumes and families suit the environment, with convincing infrastructure, user, maintenance, and Internet noise.

## Recommendations

- If this were synthetic, model remote WMI as a complete source-to-target action: source `wmic.exe`, PowerShell/CIM, or another named caller; authentication under the initiating identity; TCP/135 plus dynamic RPC for DCOM, or 5985/5986 for WinRM; and target `WmiPrvSE.exe` execution tied to that transport.
- Add a source-side SSH client process for the WEB-EXT-01-to-APP-INT-01 pivot and attach its flow to the live root shell. If the intended collection profile drops that process, represent source-local observation loss coherently rather than leaving only the attack-critical initiator actorless.
- Apply source-observation gaps consistently across lifecycle groups. A dropped client process should have an explainable collection pattern and should not selectively affect remote-execution initiators while adjacent source processes remain richly observed.

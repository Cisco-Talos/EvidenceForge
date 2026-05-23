---
description: "Evidence Formats Reference"
---

# Evidence Formats Reference

This document lists every evidence type EvidenceForge can generate, where to find it in the output, and any known limitations.

## Output Directory Structure

One generation run emits one output target. The tree below shows both default
and SOF-ELK target-specific files where they differ; they are not emitted
together.

```
output/
  GROUND_TRUTH.md                          # Ground truth sidecar; empty for baseline-only runs
  OBSERVATION_MANIFEST.json                # Source-observation sidecar for eval
  OUTPUT_TARGET.txt                        # "default" or "sof-elk"; missing legacy marker means default
  ENVIRONMENT.md                           # Student-facing environment description (created by /eforge scenario skill)
  <hostname.domain>/                       # Per-host directories (FQDN)
    windows_event_security.xml             # Windows Security channel events
    windows_event_sysmon.xml               # Sysmon operational channel events
    syslog.log                             # Linux syslog (default target; RFC5424)
    bash_history/<username>.bash_history    # Per-user bash history (Linux only)
    <year>/windows_event_security_snare.log # Windows Security Snare/RFC3164 (sof-elk target)
    <year>/windows_event_sysmon_snare.log   # Sysmon Snare/RFC3164 (sof-elk target)
    <year>/syslog.log                      # Linux syslog (sof-elk target; RFC3164)
  <sensor-name>/                           # Per-sensor directories (network)
    conn.json                              # Zeek conn.log (NDJSON)
    dns.json                               # Zeek dns.log
    http.json                              # Zeek http.log
    ssl.json                               # Zeek ssl.log
    files.json                             # Zeek files.log
    ...                                    # Other Zeek logs
  ecar.json                                # Simulated EDR telemetry in eCAR format (NDJSON)
  snort_alert.log                          # Snort/Suricata IDS alerts
  <fw-hostname>/                           # Per-firewall directories
    cisco_asa.log                          # Cisco ASA firewall syslog (default target)
    <year>/cisco_asa.log                   # Cisco ASA firewall syslog (sof-elk target)
  web_access.log                           # Apache/Nginx access log
  <proxy-hostname.domain>/                 # Per-proxy-host directories
    proxy_access.log                       # HTTP forward proxy access log (W3C Extended)
```

## Output Targets

`eforge generate --target default|sof-elk` selects the on-disk rendering and
layout for tools that expect different formats. Scenario YAML and `--formats`
remain canonical: request `windows_event_security`, `windows_event_sysmon`,
`syslog`, `cisco_asa`, and so on, then choose the target at generation time.
When `OUTPUT_TARGET.txt` is missing, `eforge eval` treats the dataset as
legacy/default output.

Target-specific behavior in V1:

| Canonical format | `default` target | `sof-elk` target |
| --- | --- | --- |
| `windows_event_security` | `<host>/windows_event_security.xml` | `<host>/<year>/windows_event_security_snare.log` |
| `windows_event_sysmon` | `<host>/windows_event_sysmon.xml` | `<host>/<year>/windows_event_sysmon_snare.log` |
| `syslog` | `<host>/syslog.log` as RFC5424 | `<host>/<year>/syslog.log` as RFC3164/BSD |
| `cisco_asa` | `<firewall>/cisco_asa.log` | `<firewall>/<year>/cisco_asa.log` |
| Zeek, proxy, web access, IDS, eCAR, bash history | Unchanged | Unchanged |

---

## Windows Security Events

**Default target file:** `<hostname.domain>/windows_event_security.xml`
**Default target format:** XML (`<Events><Event>...</Event></Events>`)
**SOF-ELK target file:** `<hostname.domain>/<year>/windows_event_security_snare.log`
**SOF-ELK target format:** Snare-style Windows Event Log fields inside an RFC3164 syslog envelope
**Provider:** Microsoft-Windows-Security-Auditing (except 1102)
**Channel:** Security

The `default` target emits XML only. The `sof-elk` target emits Snare syslog
only so SOF-ELK and other syslog/Snare-aware tools can parse the same canonical
Windows Security events without requiring binary EVTX files.

| Event ID | Name | Category | Notes |
|----------|------|----------|-------|
| 1102 | Security Log Cleared | Defense Evasion | Different provider (Microsoft-Windows-Eventlog). Uses `<UserData>` instead of `<EventData>`. Level=4, Keywords=0x4020. |
| 4624 | Successful Logon | Authentication | Version 2 format. Includes ImpersonationLevel, VirtualAccount, ElevatedToken, TargetLinkedLogonId. LogonTypes: 2 (interactive), 3 (network), 5 (service), 7 (unlock), 10 (RDP), 11 (cached). IPv4 rendered as `::ffff:x.x.x.x`. |
| 4625 | Failed Logon | Authentication | Version 0. Keywords=0x8010 (Audit Failure). Includes Status/SubStatus failure codes. Remote failed-auth attempts use established/reset-after-payload network evidence rather than SYN-only probes. |
| 4634 | Logoff | Authentication | Paired with 4624 via matching TargetLogonId. Generated for interactive sessions (type 2/10) at work-day end and for type 3 network logons (including machine account logons on DCs) after short delays. |
| 4648 | Explicit Credentials | Lateral Movement | Fires when RunAs, PsExec, WMIC, or scheduled tasks use alternate credentials. Emitted on the source system. |
| 4672 | Special Privileges Assigned | Privilege Use | Auto-emitted alongside the target-host 4624 for elevated accounts. Privilege lists are selected from data-driven service/admin/UAC profiles in `windows_auth_realism.yaml`. |
| 4688 | Process Created | Execution | Version 2. Includes CommandLine, ParentProcessName, MandatoryLabel. TokenElevationType indicates UAC status. |
| 4689 | Process Exited | Execution | Paired with 4688. Status always 0x0. |
| 4697 | Service Installed | Persistence | ServiceFileName can contain full command lines. ServiceType 0x10=Own Process. |
| 4698 | Scheduled Task Created | Persistence | TaskContent contains HTML-escaped XML task definition. |
| 4699 | Scheduled Task Deleted | Persistence | Same field structure as 4698. |
| 4700 | Scheduled Task Enabled | Persistence | Same field structure as 4698. No sample data verification (MS docs only). |
| 4701 | Scheduled Task Disabled | Persistence | Same field structure as 4698. No sample data verification (MS docs only). |
| 4720 | User Account Created | Account Management | Full account property fields (25+). Most default to "-". |
| 4723 | Password Change Attempt | Account Management | User changing own password. Can be Audit Failure (0x8010) if policy rejects. |
| 4724 | Password Reset Attempt | Account Management | Admin resetting another user's password. Minimal fields. |
| 4726 | User Account Deleted | Account Management | Minimal fields (Subject + Target + PrivilegeList). |
| 4728 | Member Added to Global Group | Privilege Escalation | e.g., adding user to Domain Admins. |
| 4729 | Member Removed from Global Group | Privilege Escalation | No sample data verification (identical structure to 4728). |
| 4732 | Member Added to Local Group | Privilege Escalation | e.g., adding user to local Administrators. |
| 4733 | Member Removed from Local Group | Privilege Escalation | |
| 4738 | User Account Changed | Account Management | Has unique leading `Dummy` field (always "-"). Full account property fields. |
| 4756 | Member Added to Universal Group | Privilege Escalation | e.g., Enterprise Admins. |
| 4757 | Member Removed from Universal Group | Privilege Escalation | No sample data verification (identical structure to 4756). |
| 4768 | Kerberos TGT Request | Authentication | Keywords reflect success/failure based on Status field. Successful TGTs use data-driven PreAuthType/TicketOptions/encryption distributions; PKINIT (`PreAuthType=15`) populates CertIssuerName/CertSerialNumber/CertThumbprint. |
| 4769 | Kerberos Service Ticket | Authentication | TargetUserName includes @DOMAIN suffix. Keywords reflect success/failure. |
| 4770 | Kerberos TGT Renewal | Authentication | Always success. |
| 4771 | Kerberos Pre-Auth Failed | Credential Access | Keywords always 0x8010 (Audit Failure). Key indicator for password spraying. |
| 4776 | NTLM Credential Validation | Authentication | Field names: TargetUserName (not LogonAccount), Workstation (not SourceWorkstation). Status reflects validation success or failure. |
| 5156 | WFP Connection Permitted | Network | Application path uses device format (`\device\harddiskvolume1\...`). Direction: %%14592=Inbound, %%14593=Outbound. |

**Known Limitations:**
- EventRecordIDs use probabilistic gaps (15% chance +2-8, 3% chance +20-200) rather than correlating with unlogged events
- Execution ProcessID for auth events uses the lsass.exe PID; for process/WFP events uses the System process (PID 4, now properly registered)
- Account management events (4720-4738) and group membership events (4728-4757) require storyline triggers; they are not generated in baseline activity
- SubjectDomainName correctly uses "NT AUTHORITY" for SYSTEM, NETWORK SERVICE, and LOCAL SERVICE accounts
- 4648 (explicit credentials) fires in baseline for scheduled task execution with randomized counts (2-5/hour) plus storyline lateral movement
- Successful logons, failed logons, logoffs, service logons, machine-account logons, anonymous logons, NTLM validation, and workstation lock/unlock evidence route through the internal auth/session bundles so Windows Security, Linux syslog, EDR/eCAR, DC validation, lock state, and companion network evidence share session IDs, source endpoints, and lifecycle ordering.
- DC-side Kerberos 4768/4769/4770/4771 evidence routes through the internal Kerberos/DC bundle so ticket timing, source IP/port, TGT cache behavior, service-principal identity, and companion KDC network evidence stay aligned.
- Windows audit/account-management events route through the internal Windows audit bundle so subject LogonID/session ownership, target account/group identity, scheduled-task XML, log-clear subject identity, and Sysmon/eCAR thread/process-access context stay aligned.
- Canonical connections route through the internal network-connection bundle so Zeek, EDR/eCAR FLOW, proxy/firewall/IDS companions, DNS/TLS/HTTP/file metadata, endpoint process ownership, and Windows WFP rows share one tuple, source port, hostname, UID/state, and visibility decision.
- Domain controllers receive admin-only baseline activity: type 3 logons from RSAT sessions (mmc.exe runs on the admin workstation, not the DC), type 10 RDP for direct admin access, and no user desktop sessions (no browsers, Office, or user profile artifacts)
- RSAT sessions produce correlated cross-host events: mmc.exe + DLL loads on the workstation, LDAP/RPC connections from workstation to DC, and a type 3 logon on the DC — all within seconds

---

## Windows Sysmon Events

**Default target file:** `<hostname.domain>/windows_event_sysmon.xml`
**Default target format:** XML (`<Events><Event>...</Event></Events>`)
**SOF-ELK target file:** `<hostname.domain>/<year>/windows_event_sysmon_snare.log`
**SOF-ELK target format:** Snare-style Windows Event Log fields inside an RFC3164 syslog envelope
**Provider:** Microsoft-Windows-Sysmon
**Channel:** Microsoft-Windows-Sysmon/Operational

The `default` target emits XML only. The `sof-elk` target emits Snare syslog
only and `eforge eval` maps both variants back to the canonical
`windows_event_sysmon` format bucket.

| Event ID | Name | Category | Notes |
|----------|------|----------|-------|
| 1 | ProcessCreate | Execution | Version 5. Enriches 4688 with file hashes (SHA1/MD5/SHA256/IMPHASH), FileVersion, Description, Product, Company, OriginalFileName, ParentCommandLine. Hashes are deterministic fakes seeded from image path + hostname. ParentCommandLine is populated from the parent process's actual command line in StateManager (e.g., `powershell.exe`, `cmd.exe /k`, `Code.exe --folder-uri ...`). ParentImage reflects realistic parent-child relationships driven by `spawn_rules.yaml` — CLI tools parent from shells, GUI apps from explorer.exe, system services from services.exe/svchost.exe. |
| 5 | ProcessTerminate | Execution | Version 3. Emitted alongside Security 4689 and eCAR PROCESS/TERMINATE for the same process exit. Storyline processes terminate with realistic delays based on command type (recon: 0.3-5s, attack tools: 5-30s, persistent/C2: no termination). Fields: ProcessGuid, ProcessId, Image, User. |
| 8 | CreateRemoteThread | Defense Evasion | Version 2. Detects process injection. Source and target process GUIDs, thread start address, StartModule, and StartFunction. Baseline generates benign noise (1-3/hr) from Defender, CSRSS, svchost. Correlated with eCAR THREAD/REMOTE_CREATE. |
| 10 | ProcessAccess | Credential Access | Version 3. Detects credential dumping (e.g., mimikatz accessing lsass.exe). Includes GrantedAccess mask, CallTrace. Baseline generates benign noise (3-8/hr) from Defender, CSRSS, Services.exe. Correlated with eCAR PROCESS/OPEN. |

**Known Limitations:**
- ProcessGuid is deterministic from (hostname, PID, process creation time), so Events 1/3/5/7/8/10/11/12/13/22 agree for the same known process. The rendered shape follows Sysmon-style machine/time/token morphology rather than RFC UUID version bits.
- File hashes are fake but consistent (same binary on same host always produces same hash)
- Sysmon Event 1 is emitted alongside Security 4688 for the same process creation — both emitters handle `process_create` events
- Process create/terminate lifecycle and process-owned file/module/registry/network side effects are coordinated through the internal process-execution bundle so endpoint sources share parent/session identity and source-visible ordering.
- Implemented events focus on the project evidence model: 1, 3, 5, 7, 8, 10, 11, 12, 13, and 22.

---

## Zeek Network Logs

**File:** `<sensor-name>/<logtype>.json`
**Format:** NDJSON (one JSON object per line)

Zeek logs are per-sensor. Which connections appear depends on sensor placement (SPAN/TAP), monitored segments, and direction. All Zeek logs for the same connection share a common UID.

| Log Type | File | Description | Notes |
|----------|------|-------------|-------|
| conn.log | `conn.json` | Connection metadata | TCP, UDP, ICMP. Includes duration, bytes, packets, conn_state, history. |
| dns.log | `dns.json` | DNS queries/responses | A, AAAA, PTR, SRV, TXT, MX, NS, and SOA query types. Automatic connection-prerequisite lookups route through the internal DNS lookup bundle so resolver choice, cache behavior, TTL observations, Zeek DNS/conn fan-out, Sysmon DNS visibility, and companion resolver questions stay consistent with connection hostnames. MX generation avoids CDN-style hostnames; TXT covers SPF/DKIM/DMARC-style background lookups. NXDOMAIN for suffix search. AA flag for internal zones. |
| http.log | `http.json` | HTTP transactions | Method, URI, status code, user-agent, response body length. Only for port 80 TCP connections. |
| ssl.log | `ssl.json` | TLS handshakes | TLS version, cipher suite, SNI server_name, and `cert_chain_fuids` linking to x509 certificates. Generated for port 443 connections. Certificate-chain depth is driven by `tls_realism.yaml`. |
| files.log | `files.json` | File transfers | Extracted from HTTP responses, OCSP responses, and substantial SMB transfers. Uses Zeek-native `tx_hosts`, `rx_hosts`, and `conn_uids` arrays plus `fuid`, optional `filename` for SMB, MIME type, byte counts, and `md5`/`sha1`/`sha256` when the matching analyzer ran. Transfer metadata is built through the internal file-transfer bundle path so FUIDs, hashes, filenames, direction, byte counts, and optional PE analysis stay coordinated. SMB thresholds, filename templates, and MIME/analyzer mix are driven by `smb_file_transfers.yaml`. |
| dhcp.log | `dhcp.json` | DHCP transactions | Client address, MAC (diversified OUI from network_params.yaml), hostname. Acquisition and renewal route through the internal DHCP lease bundle so Zeek DHCP/conn rows and Linux `dhclient` syslog companions share one lease identity. DHCP broadcast is treated as link-local: visible to SPAN sensors on the client segment, not routed through unrelated TAP/firewall segments. |
| ntp.log | `ntp.json` | NTP synchronization | Server-response records with version, mode 4, stratum, poll interval, and timing fields. Version, poll, precision, root delay, and root dispersion are stable per client/server association. Scenario-defined internal/domain NTP servers are preferred; public fallback servers come from `network_params.yaml`. |
| x509.log | `x509.json` | X.509 certificates | Leaf and intermediate certificate `id`/fingerprint, subject/issuer, validity (issuer-aware from tls_issuers.yaml), key info, and CA constraints. Intermediate CA certificate profiles are reused by subject/issuer so the same CA does not appear as many different certificates in one dataset. |
| weird.log | `weird.json` | Protocol anomalies | Unusual network behavior. Automatic weird generation is currently disabled pending a data-driven Zeek weird compatibility model; explicitly supplied `WeirdContext` events still render. |
| pe.log | `pe.json` | Portable Executable | Windows binary metadata over network. |
| ocsp.log | `ocsp.json` | OCSP responses | Certificate revocation responses whose `id` joins to `files.log` `fuid`, matching Zeek file-analysis semantics. |
| packet_filter.log | `packet_filter.json` | BPF filter changes | Zeek packet filter status. |
| reporter.log | `reporter.json` | Zeek internal messages | Zeek operational status. |

**Known Limitations:**
- No SMB-specific Zeek log (smb_files.log, smb_mapping.log) — SMB traffic appears in conn.log, substantial transfers can appear in files.log, and file-server activity can also produce host-side eCAR FILE records
- No SMTP log — email traffic appears in conn.log only
- http.log only for port 80; HTTPS content is not decrypted (as expected)
- `missed_bytes` is probabilistic (~3% of long TCP connections) rather than from actual packet capture
- All timestamps use 6-digit microsecond precision

---

## eCAR Format (Simulated EDR Telemetry)

**File:** `ecar.json`
**Format:** NDJSON

Simulated EDR telemetry rendered in MITRE CAR-based eCAR format. Represents what an EDR agent would observe.

**Record structure:** Every eCAR record contains `pid` and `tid` as always-present top-level integers (`-1` = unavailable). `ppid` appears on PROCESS events only. The `properties` map contains event-specific key-value pairs where all values are strings (including ports).

**Entity correlation (objectID/actorID graph):** Each record carries a persistent `objectID` (UUID) that identifies the entity being acted upon. Entity lifecycle events share the same objectID — e.g., a PROCESS/CREATE and PROCESS/TERMINATE for the same process, or a USER_SESSION/LOGIN and USER_SESSION/LOGOUT for the same session. The optional `actorID` field links to the objectID of the entity that performed the action — e.g., a PROCESS/CREATE's actorID points to its parent process's objectID, and a FILE/CREATE's actorID points to the process that created it.

| Object Type | Actions | Notes |
|-------------|---------|-------|
| PROCESS | CREATE, TERMINATE, OPEN | CREATE/TERMINATE include pid, ppid, image_path, parent_image_path, command_line, user. Correlated with syslog for CRON jobs and systemd service start/stop on Linux. OPEN maps to Sysmon Event 10 (ProcessAccess) — includes granted_access, target_pid, target_image_path, and target_process_uuid in properties. |
| THREAD | REMOTE_CREATE | Maps to Sysmon Event 8 (CreateRemoteThread). Properties include src_pid, target_pid, target_process_uuid, start_address, and stack addresses matching OpTC eCAR format. Thread ID, target PID, and start address are generated once in `RemoteThreadContext` and rendered consistently across Sysmon and eCAR. |
| FILE | READ, CREATE, WRITE, DELETE | Generated alongside process activity, baseline SMB file-server access, and modeled transfer receiver evidence such as SCP target-side file creation. |
| FLOW | CONNECT | Network connections from host perspective. Includes src/dst IP, port, protocol. |
| REGISTRY | MODIFY | Windows registry operations. |
| MODULE | LOAD | DLL loads for Windows processes using the same process-aware DLL profile data as Sysmon ImageLoaded events. |
| USER_SESSION | LOGIN, LOGOUT | Logon/logoff events. LOGIN includes outcome (`success` or `failure`); Windows successful logons include `logon_type`, while non-Windows sessions use OS-native `session_type` values such as `ssh`, `remote`, `local`, or `service`. Failed attempts include failure_reason/status fields and do not imply an established session. |
| SERVICE | CREATE | Service installation. Correlated with Windows 4697. Includes service_name, image_path (binary path), service_account in properties. |

**Known Limitations:**
- eCAR format represents an optional EDR layer — not all systems may have it enabled
- FLOW events carry the initiating system process pid when endpoint attribution is available (svchost for DNS/NTP, lsass for Kerberos/LDAP, System PID 4 for SMB, mstsc.exe for RDP); pid/tid fields are omitted when unavailable instead of rendering placeholder IDs
- Limited EDR object diversity on Linux (mainly PROCESS + USER_SESSION)
- File paths cycle through a small set of templates

---

## Linux Syslog

**Default target file:** `<hostname.domain>/syslog.log`
**Default target format:** RFC5424 syslog with full timestamp year
**SOF-ELK target file:** `<hostname.domain>/<year>/syslog.log`
**SOF-ELK target format:** RFC3164/BSD syslog with PRI

Authentication and system logs from Linux hosts. The `default` target emits
flat per-host RFC5424 syslog for SIEM-neutral output. The `sof-elk` target emits
a BSD/RFC3164 envelope (`<PRI>MMM DD HH:MM:SS HOST APP[PID]: MESSAGE`) and
partitions files by event year so SOF-ELK can recover the timestamp year from
the archive path. `eforge eval` accepts both current target variants plus older
legacy RFC5424 and flat BSD/RFC3164 files. All generated syslog entries are
rendered from `SyslogContext` on `SecurityEvent` — the emitter doesn't derive
messages from other contexts. Multi-phase activities such as SSH sessions are
coordinated by action-bundle semantics above individual `SecurityEvent`s: the
bundle owns lifecycle, ordering, source timing, and shared identities, while each
syslog row remains a distinct canonical occurrence. Remote Linux `sshd`
failed-password rows reuse the same source port as the companion Zeek SSH
connection tuple.

| Program | Description | Notes |
|---------|-------------|-------|
| sshd | SSH authentication | Accepted/Failed password, session opened/closed, pam_unix messages. |
| systemd | Service management | Started/stopped service units. |
| systemd-logind | Login sessions | New session, removed session. |
| CRON | Scheduled tasks | cron job execution. |
| kernel | Kernel messages | UFW firewall blocks, uptime, hardware. |
| sudo | Privilege escalation | Command execution via sudo. |
| su | User switching | Switch user events. |
| systemd-timesyncd | NTP sync | Time synchronization status. |
| snapd | Snap packages | Ubuntu snap daemon messages. |

**Known Limitations:**
- Limited program variety (~9 programs vs 30+ on real servers)
- No application-specific logs (nginx, postfix, mysql, etc.) even when services are declared
- No SSH protocol negotiation messages (key exchange, cipher selection) before auth
- Bash history may be sparse relative to SSH session duration

---

## Bash History

**File:** `<hostname.domain>/bash_history/<username>.bash_history`
**Format:** Timestamped bash history (`#<epoch>\n<command>`)

Per-user command history for Linux systems. Baseline SSH sessions to Linux servers generate organic admin commands (ls, df, ps, systemctl, etc.) for realistic admin users (sysadmin, help_desk, developer, security_analyst personas), creating per-user history files on all Linux hosts. Storyline process events inject 0-3 organic noise commands around each attack command for realistic interleaving. Bash-history timing and optional foreground process telemetry are coordinated by the internal Linux shell-command bundle so command text, source-visible timing, and endpoint process evidence stay aligned.

**Known Limitations:**
- No command typos, tab-completion artifacts, or repeated commands
- No command output or error messages

---

## Snort/Suricata IDS Alerts

**File:** `snort_alert.log`
**Format:** Snort fast alert format

Network intrusion detection alerts. Baseline generates false-positive alerts (e.g., ICMP PING, SSH scan, policy violations) correlated with Zeek conn records via canonical SecurityEvent dispatch. Storyline generates true-positive alerts for malicious connections. IDS signature-to-context construction is owned by the internal IDS alert action bundle so Snort/Suricata rows render canonical network/DNS/HTTP evidence rather than independently inventing alert payloads.

Web scan events (`web_scan` storyline type) generate three layers of IDS alerts:
1. **Scanner UA detection** — identifies the scanning tool by user-agent (non-TLS only)
2. **Per-path content alerts** — curated SID mappings for specific probe paths (non-TLS only)
3. **Connection-rate threshold** — generic scan-rate alerts (both TLS and non-TLS)

Alert format: `[gid:sid:rev]` where `gid` defaults to 1, `sid` identifies the rule, and `rev` reflects real ET/Community ruleset revision numbers sourced from `sample_data/snort/`. Each `(gid, sid)` pair has stable rule identity and carries a `rev` field.

**Known Limitations:**
- IDS alert variety is limited to curated SID pools (not full ruleset simulation)

---

## Cisco ASA Firewall Syslog

**Default target file:** `<fw-hostname>/cisco_asa.log`
**SOF-ELK target file:** `<fw-hostname>/<year>/cisco_asa.log`
**Format:** Cisco ASA syslog (RFC 3164 BSD syslog with ASA message IDs)

Cisco ASA firewall logs for permitted and denied connections. Produced by firewall-type network sensors with `cisco_asa` in their `log_formats`. Each permitted connection generates a Built + Teardown pair; denied connections generate a single Deny record.

| Message ID | Severity | Protocol | Description |
|------------|----------|----------|-------------|
| 302013 | 6 (info) | TCP | Built inbound/outbound TCP connection |
| 302014 | 6 (info) | TCP | Teardown TCP connection (with duration, bytes, reason) |
| 302015 | 6 (info) | UDP | Built inbound/outbound UDP connection |
| 302016 | 6 (info) | UDP | Teardown UDP connection |
| 302020 | 6 (info) | ICMP | Built inbound/outbound ICMP connection |
| 302021 | 6 (info) | ICMP | Teardown ICMP connection |
| 106023 | 4 (warn) | any | Deny by access-group |
| 305011 | 6 (info) | any | Built dynamic/static NAT translation |
| 305012 | 6 (info) | any | Teardown dynamic/static NAT translation |
| 733100 | 4 (warn) | — | Threat detection scanning alert (automatic, rate-based) |

**Example records:**
```
<166>Jun 15 14:23:05 fw01 %ASA-6-302013: Built outbound TCP connection 100042 for inside:10.0.10.50/54321 (10.0.10.50/54321) to outside:45.83.221.50/443 (45.83.221.50/443)
<166>Jun 15 14:24:28 fw01 %ASA-6-302014: Teardown TCP connection 100042 for inside:10.0.10.50/54321 to outside:45.83.221.50/443 duration 0:01:23 bytes 5120 TCP FINs
<164>Jun 15 14:23:10 fw01 %ASA-4-106023: Deny tcp src outside:104.248.71.33/44231 dst inside:10.0.10.50/445 by access-group "outside_access_in" [0x0, 0x0]
<164>Jun 15 14:23:15 fw01 %ASA-4-733100: [Scanning] drop rate-1 exceeded. Current burst rate is 87 per second, max configured rate is 10; Current average rate is 45 per second, max configured rate is 5; Cumulative total count is 2340
```

**Threat detection (733100):** The ASA emitter automatically tracks per-source-IP deny rates. When both burst rate (default 10 drops/sec over 20s) and average rate (default 5 drops/sec over 60s) are exceeded, a 733100 alert fires. Can re-fire after a 20-second cooldown if rates remain elevated. Configurable via `threat_detection_rate` on the firewall sensor (set to 0 to disable).

**NAT translation (305011/305012):** When `nat_rules` are configured on the firewall sensor, permitted connections that cross the NAT boundary produce 305011 (Built) and 305012 (Teardown) translation records alongside the normal 302013/302014 connection records. Built messages show post-NAT mapped addresses in parentheses. Outside Zeek sensors see post-NAT IPs; inside Zeek sensors see real IPs.

**Baseline deny generation:** When `deny_ratio > 0` on the firewall sensor, the baseline generates denied connection attempts proportional to allowed traffic. Patterns include external scanning (60%), cross-segment blocked (20%), outbound blocked (10%), and ICMP noise (10%).

**Storyline event types:** `port_scan` generates bulk 106023 denies for reconnaissance/scanning. `beacon` with `action: deny` generates periodic 106023 denies for blocked malware beaconing. Both produce correlated Zeek conn.log entries on sensors that can see the source-side traffic. Port scans with sufficient rate automatically trigger 733100 threat detection alerts.

**Source-only visibility:** Denied connections are only visible to sensors on the source side of the firewall. Sensors on the destination side do not see blocked traffic.

**Known Limitations:**
- Simplified message format — omits IDFW user, internal port numbers, rx_ring metadata

---

## Web Access Log

**File:** `web_access.log`
**Format:** Apache/Nginx combined log format

HTTP access logs for web server systems.

Entries use Apache/Nginx combined syntax:

```text
client-ip - username [dd/Mon/yyyy:HH:MM:SS zone] "METHOD path HTTP/version" status bytes "Referer" "User-Agent"
```

**Referer field:** Browser-originated traffic carries a realistic Referer distribution — roughly 55% blank (direct/bookmark), 20% search engine (Google/Bing), 20% same-origin, 5% social/news. Bot user-agents (Googlebot, bingbot, AhrefsBot) always have blank Referer. Scanner traffic (`web_scan` events) follows per-preset rules grounded in real scanner behavior: Nikto sends same-origin Referer on ~30% of requests (partial-crawl mode); gobuster, sqlmap, dirb, and nmap_http send no Referer. This means the Referer field is useful for distinguishing human browsing from automated scans in training exercises.

**Known Limitations:**
- Only generated for systems with web server role

---

## HTTP Proxy Log

**File:** `<proxy-hostname.domain>/proxy_access.log`
**Format:** W3C Extended Log Format

Forward proxy access logs for systems with the `forward_proxy` role. Outbound HTTP/HTTPS traffic is routed through the proxy system. In `environment.proxy.mode: transparent`, network sensors can still show direct-looking client-to-origin traffic. In `mode: explicit`, the generator emits client-to-proxy and proxy-to-origin network legs; each Zeek/IDS/firewall sensor sees only the leg its topology can observe. If the proxy denies a request, the transaction stops at the proxy and no proxy-to-origin Zeek, IDS, or firewall evidence is emitted. HTTP/S storyline `beacon` events from proxied hosts use the same explicit proxy routing, including proxy-side denied CONNECT/GET evidence for `action: deny`.

The proxy log uses a W3C Extended-style `#Fields` header:

```text
#Fields: date time c-ip cs-username cs-method cs-uri cs-version sc-status sc-bytes cs-bytes time-taken cs-host cs(User-Agent) cs(Referer) rs(Content-Type) s-cache-result x-proxy-action
```

Fields are whitespace-delimited; values with spaces, such as User-Agent strings, are rendered with `+` separators. Missing values are `-`.

**Referrer field:** The W3C Extended format output includes a `cs(Referer)` field, linking subresource requests back to the page that triggered them.

**Proxy action field:** The `x-proxy-action` field disambiguates source-native proxy behavior: `tunnel-setup` for CONNECT setup rows, `ssl-inspect` for decrypted HTTPS request rows, `forward` for ordinary forwarded HTTP, and `deny`/`auth-required`/`gateway-error` for proxy-side terminal failures.

**CONNECT tunnel behavior:** HTTPS traffic generates one CONNECT entry per unique (client_ip, host) pair per session, with a 5-minute idle timeout. Subsequent HTTPS requests to the same host within the timeout reuse the existing tunnel without emitting another CONNECT. The current proxy model assumes TLS interception, so inspected HTTPS requests can also appear as W3C Extended request rows such as `GET https://host/path HTTP/1.1`.

**Status and byte semantics:** For explicit proxy mode, client-side Zeek HTTP records describe the client-to-proxy exchange. Plain HTTP denials therefore show the proxy's status code and proxy response size, not the origin's status/body. For intercepted HTTPS, the CONNECT setup status is tracked separately from the inspected request status, so a successful tunnel setup can coexist with a denied inspected GET.

**Source-native HTTP semantics:** Domain/path planning is resolved before proxy
and Zeek HTTP rows are rendered. HTTPS-first identity/social domains redirect
plaintext port-80 requests instead of serving login pages, service/update
endpoints keep source-compatible User-Agents, and executable/download paths use
binary content types with download-scale body sizes.

**Session depth:** Persona HTTP traffic and inbound `web_server` human visitors generate multi-request browsing sessions with subresource cascades. Each page load triggers follow-on requests for JS, CSS, images, fonts, and same-origin API calls, producing realistic request clusters in proxy and web access logs. Persona browsing depth is controlled by `browsing_intensity`; inbound web visitor classes, tool/API requests, and User-Agent pools are controlled by `web_session_profiles.yaml`.

**Known Limitations:**
- Only generated for systems with the `forward_proxy` role declared
- Non-intercepting tunnel-only HTTPS proxy behavior is not yet modeled
- Cache hit/miss status is probabilistic, with stable web-route status generated upstream
- Limited to HTTP and HTTPS traffic

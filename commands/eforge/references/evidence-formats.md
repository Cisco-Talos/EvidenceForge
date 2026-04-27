# Evidence Formats Reference

This document lists every evidence type EvidenceForge can generate, where to find it in the output, and any known limitations.

## Output Directory Structure

```
output/
  GROUND_TRUTH.md                          # Attack narrative, timeline, IOCs, red herrings
  ENVIRONMENT.md                           # Student-facing environment description
  <hostname.domain>/                       # Per-host directories (FQDN)
    windows_event_security.xml             # Windows Security channel events
    windows_event_sysmon.xml               # Sysmon operational channel events
    bash_history/<username>.bash_history    # Per-user bash history (Linux only)
    ecar.json                              # eCAR EDR/XDR telemetry (NDJSON)
    syslog.log                             # Linux syslog (BSD format)
    web_access.log                         # Apache/Nginx access log
  <sensor-name>/                           # Per-sensor directories (network)
    conn.json                              # Zeek conn.log (NDJSON)
    dns.json                               # Zeek dns.log
    http.json                              # Zeek http.log
    ssl.json                               # Zeek ssl.log
    files.json                             # Zeek files.log
    ...                                    # Other Zeek logs
    snort_alert.log                        # Snort/Suricata IDS alerts
  <proxy-hostname.domain>/                 # Per-proxy-host directories
    proxy_access.log                       # HTTP forward proxy access log (W3C Extended)
```

---

## Windows Security Events

**File:** `<hostname.domain>/windows_event_security.xml`
**Format:** XML (`<Events><Event>...</Event></Events>`)
**Provider:** Microsoft-Windows-Security-Auditing (except 1102)
**Channel:** Security

| Event ID | Name | Category | Notes |
|----------|------|----------|-------|
| 1102 | Security Log Cleared | Defense Evasion | Different provider (Microsoft-Windows-Eventlog). Uses `<UserData>` instead of `<EventData>`. Level=4, Keywords=0x4020. |
| 4624 | Successful Logon | Authentication | Version 2 format. Includes ImpersonationLevel, VirtualAccount, ElevatedToken, TargetLinkedLogonId. LogonTypes: 2 (interactive), 3 (network), 5 (service), 7 (unlock), 10 (RDP), 11 (cached). IPv4 rendered as `::ffff:x.x.x.x`. |
| 4625 | Failed Logon | Authentication | Version 0. Keywords=0x8010 (Audit Failure). Includes Status/SubStatus failure codes. |
| 4634 | Logoff | Authentication | Paired with 4624 via matching TargetLogonId. |
| 4648 | Explicit Credentials | Lateral Movement | Fires when RunAs, PsExec, WMIC, or scheduled tasks use alternate credentials. Emitted on the source system. |
| 4672 | Special Privileges Assigned | Privilege Use | Auto-emitted alongside 4624 for elevated accounts. Admin accounts get full privilege set; regular users get limited set. |
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
| 4768 | Kerberos TGT Request | Authentication | Keywords reflect success/failure based on Status field. CertIssuerName/CertSerialNumber/CertThumbprint always empty. |
| 4769 | Kerberos Service Ticket | Authentication | TargetUserName includes @DOMAIN suffix. Keywords reflect success/failure. |
| 4770 | Kerberos TGT Renewal | Authentication | Always success. |
| 4771 | Kerberos Pre-Auth Failed | Credential Access | Keywords always 0x8010 (Audit Failure). Key indicator for password spraying. |
| 4776 | NTLM Credential Validation | Authentication | Field names: TargetUserName (not LogonAccount), Workstation (not SourceWorkstation). |
| 5156 | WFP Connection Permitted | Network | Application path uses device format (`\device\harddiskvolume1\...`). Direction: %%14592=Inbound, %%14593=Outbound. |

**Known Limitations:**
- EventRecordIDs use probabilistic gaps (15% chance +2-8, 3% chance +20-200) rather than correlating with unlogged events
- Execution ProcessID for auth events uses the lsass.exe PID; for process/WFP events uses System (4)
- 4648 only fires for storyline lateral movement and explicit-credential tool processes, not for all service logons
- Account management events (4720-4738) and group membership events (4728-4757) require storyline triggers; they are not generated in baseline activity

---

## Windows Sysmon Events

**File:** `<hostname.domain>/windows_event_sysmon.xml`
**Format:** XML (`<Events><Event>...</Event></Events>`)
**Provider:** Microsoft-Windows-Sysmon
**Channel:** Microsoft-Windows-Sysmon/Operational

| Event ID | Name | Category | Notes |
|----------|------|----------|-------|
| 1 | ProcessCreate | Execution | Version 5. Enriches 4688 with file hashes (SHA1/MD5/SHA256/IMPHASH), FileVersion, Description, Product, Company, OriginalFileName, ParentCommandLine. Hashes are deterministic fakes seeded from image path + hostname. |
| 3 | NetworkConnect | Network | Outbound connection attributed to originating process. Source/destination IP, port, protocol. Skipped if the process cannot be resolved. svchost.exe is used for DNS/NTP; shows initiating process for attack tool connections. |
| 5 | ProcessTerminate | Execution | Version 3. Emitted for both baseline stale-process cleanup and storyline process completions. Storyline processes terminate with realistic delays based on command type (recon: 0.3-5s, attack tools: 5-30s, persistent/C2: no termination). ProcessGuid matches the Event 1 that created the process. |
| 7 | ImageLoaded | Execution | DLL/module loads. Includes file hashes, signing status, and signature details. |
| 8 | CreateRemoteThread | Defense Evasion | Version 2. Detects process injection. Source and target process GUIDs, thread start address. |
| 10 | ProcessAccess | Credential Access | Version 3. Detects credential dumping (e.g., mimikatz -> lsass). Source and target process GUIDs, GrantedAccess mask. |
| 11 | FileCreate | Defense Evasion / Execution | File creation events. TargetFilename is the created file path. |
| 12/13 | RegistryEvent | Persistence | Event 12 for key create/delete; Event 13 for value set. Includes target registry key and (for Event 13) the value written. |
| 22 | DNSQuery | Discovery | DNS lookups as seen by the Windows DNS Client service (svchost.exe). QueryName, QueryStatus, and resolved addresses. |

**Known Limitations:**
- ProcessGuid is deterministic from (hostname, PID, timestamp) — not a real Windows GUID
- File hashes are fake but consistent (same binary on same host always produces same hash)
- Sysmon Event 1 is emitted alongside Security 4688 for the same process creation — both emitters handle `process_create` events
- Events 1, 3, 5, 7, 8, 10, 11, 12/13, and 22 are implemented; real Sysmon has 30+ event types

---

## Zeek Network Logs

**File:** `<sensor-name>/<logtype>.json`
**Format:** NDJSON (one JSON object per line)

Zeek logs are per-sensor. Which connections appear depends on sensor placement (SPAN/TAP), monitored segments, and direction. All Zeek logs for the same connection share a common UID.

| Log Type | File | Description | Notes |
|----------|------|-------------|-------|
| conn.log | `conn.json` | Connection metadata | TCP, UDP, ICMP. Includes duration, bytes, packets, conn_state, history. |
| dns.log | `dns.json` | DNS queries/responses | A, AAAA, PTR, SRV, TXT, and MX query types. MX generation avoids CDN-style hostnames; TXT covers SPF/DKIM/DMARC-style background lookups. NXDOMAIN for suffix search. AA flag for internal zones. |
| http.log | `http.json` | HTTP transactions | Method, URI, status code, user-agent, response body length. Generated for unencrypted HTTP connections (any port); excludes TLS/SSL traffic. |
| ssl.log | `ssl.json` | TLS handshakes | TLS version, cipher suite, SNI server_name, and `cert_chain_fuids` linking to x509 certificates. Generated for any connection carrying TLS context, not restricted to port 443. Certificate-chain depth is driven by `tls_realism.yaml`. |
| files.log | `files.json` | File transfers | Extracted from HTTP responses and substantial SMB transfers. MIME type, seen_bytes, fuid correlation. SMB thresholds and MIME mix are driven by `smb_file_transfers.yaml`. |
| dhcp.log | `dhcp.json` | DHCP transactions | Client address, MAC, hostname. |
| ntp.log | `ntp.json` | NTP synchronization | Version, mode, stratum, poll interval. |
| x509.log | `x509.json` | X.509 certificates | Leaf and intermediate certificate `id`/fingerprint, subject/issuer, validity, key info, and CA constraints. |
| weird.log | `weird.json` | Protocol anomalies | Unusual network behavior. |
| pe.log | `pe.json` | Portable Executable | Windows binary metadata over network. |
| ocsp.log | `ocsp.json` | OCSP responses | Certificate revocation checks with connection UID and tuple fields for joining back to conn.log. |
| packet_filter.log | `packet_filter.json` | BPF filter changes | Zeek packet filter status. |
| reporter.log | `reporter.json` | Zeek internal messages | Zeek operational status. |

**Known Limitations:**
- No SMB-specific Zeek log (smb_files.log, smb_mapping.log) — SMB traffic appears in conn.log, substantial transfers can appear in files.log, and file-server activity can also produce host-side eCAR FILE records
- No SMTP log — email traffic appears in conn.log only
- http.log covers unencrypted HTTP on any port; HTTPS content is not decrypted (as expected)
- `missed_bytes` is probabilistic (~3% of long TCP connections) rather than from actual packet capture
- All timestamps use 6-digit microsecond precision

---

## eCAR Format (EDR/XDR Telemetry)

**File:** `<hostname.domain>/ecar.json`
**Format:** NDJSON

EDR/XDR telemetry rendered in MITRE CAR-based eCAR format. Represents what an EDR agent would observe.

**Record structure:** Every eCAR record contains `pid` and `tid` as always-present top-level integers (`-1` = unavailable). `ppid` appears on PROCESS events only. The `properties` map contains event-specific key-value pairs where all values are strings (including ports).

**Entity correlation (objectID/actorID graph):** Each record carries a persistent `objectID` (UUID) that identifies the entity being acted upon. Entity lifecycle events share the same objectID — e.g., a PROCESS/CREATE and PROCESS/TERMINATE for the same process, or a USER_SESSION/LOGIN and USER_SESSION/LOGOUT for the same session. The optional `actorID` field links to the objectID of the entity that performed the action — e.g., a PROCESS/CREATE's actorID points to its parent process's objectID, and a FILE/CREATE's actorID points to the process that created it.

| Object Type | Actions | Notes |
|-------------|---------|-------|
| PROCESS | CREATE, TERMINATE | Includes pid, ppid, image_path, parent_image_path, command_line, user. Correlated with syslog for CRON jobs and systemd service start/stop on Linux. |
| FILE | READ, CREATE, WRITE, DELETE | Generated alongside process activity and baseline SMB file-server access. |
| FLOW | CONNECT | Network connections from host perspective. Includes src/dst IP, port, protocol. |
| REGISTRY | MODIFY | Windows registry operations. |
| MODULE | LOAD | DLL loads for Windows processes. |
| USER_SESSION | LOGIN, LOGOUT | Logon/logoff events. |
| SERVICE | CREATE | Service installation. Correlated with Windows 4697. Includes service_name, image_path (binary path), service_account. |

**Known Limitations:**
- eCAR format represents an optional EDR layer — not all systems may have it enabled
- FLOW events carry the initiating system process pid (svchost for DNS/NTP, lsass for Kerberos/LDAP, System PID 4 for SMB, mstsc.exe for RDP); `-1` for kernel/unknown/app-specific traffic
- Limited EDR object diversity on Linux (mainly PROCESS + USER_SESSION)
- File paths cycle through a small set of templates

---

## Linux Syslog

**File:** `<hostname.domain>/syslog.log`
**Format:** BSD syslog (RFC 3164 text format)

Authentication and system logs from Linux hosts. All syslog entries are rendered from `SyslogContext` on `SecurityEvent` — the emitter doesn't derive messages from other contexts. This enables correlated dispatch: a logon event carries both `AuthContext` (for Windows 4624) and `SyslogContext` (for sshd accepted) on the same SecurityEvent.

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

Per-user command history for Linux systems.

**Known Limitations:**
- Commands generated from persona activity templates, not interactive session simulation
- May be sparse for long SSH sessions
- No command output or error messages

---

## Snort/Suricata IDS Alerts

**File:** `<sensor-name>/snort_alert.log`
**Format:** Snort fast alert format

Network intrusion detection alerts. Baseline generates false-positive alerts (e.g., ICMP PING, SSH scan, policy violations) correlated with Zeek conn records via canonical SecurityEvent dispatch. Storyline generates true-positive alerts for malicious connections.

**Known Limitations:**
- Limited SID/classification variety

---

## Web Access Log

**File:** `<hostname.domain>/web_access.log`
**Format:** Apache/Nginx combined log format

HTTP access logs for web server systems.

**Known Limitations:**
- All responses return HTTP 200 (no 301/302/404/500 mix)
- Limited User-Agent diversity (~4 strings)
- Only generated for systems with web server role

---

## HTTP Proxy Log

**File:** `<proxy-hostname.domain>/proxy_access.log`
**Format:** W3C Extended Log Format

Forward proxy access logs for systems with the `forward_proxy` role. Outbound HTTP/HTTPS traffic is routed through the proxy system. In `environment.proxy.mode: transparent`, network sensors can still show direct-looking client-to-origin traffic. In `mode: explicit`, the generator emits client-to-proxy and proxy-to-origin network legs; each Zeek/IDS/firewall sensor sees only the leg its topology can observe. If the proxy denies a request, the transaction stops at the proxy and no proxy-to-origin Zeek, IDS, or firewall evidence is emitted. HTTP/S storyline beacons from proxied hosts use the same explicit proxy path, including proxy-denied evidence for `action: deny`.

**Referrer field:** The W3C Extended format output includes a `cs(Referer)` field, linking subresource requests back to the page that triggered them.

**CONNECT tunnel behavior:** HTTPS traffic generates one CONNECT entry per unique (client_ip, host) pair per session, with a 5-minute idle timeout. Subsequent HTTPS requests to the same host within the timeout reuse the existing tunnel without emitting another CONNECT.

**Session depth:** Persona HTTP traffic generates multi-request browsing sessions with subresource cascades. Each page load triggers follow-on requests for JS, CSS, images, and fonts, producing realistic request clusters in the proxy log. The number of pages and subresources per session is controlled by the persona's `browsing_intensity` setting (light/normal/heavy).

**Known Limitations:**
- Only generated for systems with the `forward_proxy` role declared
- SSL inspection / SSL bump is not yet modeled
- Cache hit/miss status is probabilistic, not based on actual content caching logic
- Limited to HTTP and HTTPS traffic

---
description: "Evidence Formats Reference"
---

# Evidence Formats Reference

This document lists every evidence type EvidenceForge can generate, where to find it in the output, and any known limitations.

## Contents

[Output layout](#output-directory-structure) · [targets](#output-targets) ·
[email](#email-artifacts-and-zeek-smtp) · [Windows Security](#windows-security-events) ·
[Sysmon](#windows-sysmon-events) · [Zeek](#zeek-network-logs) ·
[eCAR](#ecar-format-simulated-edr-telemetry) · [Linux syslog](#linux-syslog) ·
[bash](#bash-history) · [IDS](#snortsuricata-ids-alerts) ·
[Cisco ASA](#cisco-asa-firewall-syslog) · [web](#web-access-log) ·
[proxy](#http-proxy-log)

## Output Directory Structure

One generation run emits one output target. The tree below shows default,
SOF-ELK®, and Splunk target-specific files where they differ; they are not
emitted together.

```
output/
  GROUND_TRUTH.json                        # Canonical machine-readable ground-truth document
  GROUND_TRUTH.md                          # Human-readable answer key rendered from the JSON document
  OBSERVATION_MANIFEST.json                # Source-observation manifest for eval
  ARTIFACTS_MANIFEST.json                  # Generated artifact manifest, when artifacts exist
  COLLECTION_PROFILE.json                 # Blind-safe collection/export semantics
  STORAGE_MANIFEST.json                    # Compiled cross-platform SMB storage model, schema v2
  OUTPUT_TARGET.txt                        # "default", "sof-elk", or "splunk"; missing legacy marker means default
  RESOLVED_SCENARIO.yaml                   # Authoritative self-contained generation input
  GENERATION_MANIFEST.json                 # Run identity and hashes; written last
  ENVIRONMENT.md                           # Optional authored collateral; generation does not create it
  artifacts/
    email/
      <artifact-id>.eml                    # Optional RFC 5322 message artifacts
  data/                                    # Generated logs for every output target
    <hostname.domain>/                     # Per-host directories (FQDN)
      windows_event_security.xml           # Windows Security XML document, or splunk XML event stream
      windows_event_sysmon.xml             # Sysmon XML document, or splunk XML event stream
      ecar.json                            # Simulated EDR telemetry in eCAR format (NDJSON)
      syslog.log                           # Linux syslog (default/splunk target; RFC5424)
      bash_history/<username>.bash_history # Per-user bash history (Linux only)
      web_access.log                       # Web server access log on web_server hosts
      proxy_access.log                     # Forward proxy access log on forward_proxy hosts
      <year>/windows_event_security_snare.log # Windows Security Snare/RFC3164 (sof-elk target)
      <year>/windows_event_sysmon_snare.log   # Sysmon Snare/RFC3164 (sof-elk target)
      <year>/syslog.log                    # Linux syslog (sof-elk target; RFC3164)
    <sensor-name>/                         # Per-sensor directories (network)
      conn.json                            # Zeek conn.log (NDJSON)
      dns.json                             # Zeek dns.log
      http.json                            # Zeek http.log
      smtp.json                            # Zeek smtp.log
      ssl.json                             # Zeek ssl.log
      files.json                           # Zeek files.log
      ...                                  # Other Zeek logs
    <ids-sensor-name>/                     # Per-IDS-sensor directories
      snort_alert.log                      # Snort/Suricata IDS alerts
    <fw-hostname>/                         # Per-firewall-sensor directories
      cisco_asa.log                        # Cisco ASA firewall syslog (default/splunk target)
      <year>/cisco_asa.log                 # Cisco ASA firewall syslog (sof-elk target)
```

## Output Targets

`eforge generate --target default|sof-elk|splunk` selects the on-disk rendering and
layout inside the generated `data/` directory for tools that expect different
formats. Scenario YAML and `--formats` remain canonical: request
`windows_event_security`, `windows_event_sysmon`, `syslog`, `cisco_asa`, and so
on, then choose the target at generation time.
When `OUTPUT_TARGET.txt` is missing, `eforge eval` treats the dataset as
legacy/default output.
For practical ingestion and validation guidance by target, see the
[Output Target Ingest Guides](https://github.com/Cisco-Talos/EvidenceForge/blob/main/docs/output-targets/README.md).

`COLLECTION_PROFILE.json` at the output root is a blind-safe source collection
sidecar. It records the primary collection window, selected observation profile,
source-family tail policies, and export ordering semantics without storyline
identifiers, exercise labels, ground-truth events, or scenario narrative details.

`STORAGE_MANIFEST.json` is emitted when storage is configured. Schema version 2 separates each
volume's server platform and backing filesystem from each share's `provider`, `platform`,
`network_root`, `server_native_root`, `backing_filesystem`, `advertised_filesystem`,
`case_policy`, and `audit_profile`. Mappings retain `drive` and `mount` fields and add explicit
platform/type/root `presentations`, credential mode, and non-secret principal identity. The file
also carries deterministic catalog summaries and resolved storyline targets. Canonical
share-relative paths remain SMB paths; server-local and client-presented paths are OS-native. The
manifest contains metadata only—never credentials or file payloads.

Current target-specific behavior:

| Canonical format | `default` target | `sof-elk` target | `splunk` target |
| --- | --- | --- | --- |
| `windows_event_security` | `<host>/windows_event_security.xml` rooted XML document | `<host>/<year>/windows_event_security_snare.log` | `<host>/windows_event_security.xml` as one `<Event>` per line |
| `windows_event_sysmon` | `<host>/windows_event_sysmon.xml` rooted XML document | `<host>/<year>/windows_event_sysmon_snare.log` | `<host>/windows_event_sysmon.xml` as one `<Event>` per line |
| `syslog` | `<host>/syslog.log` as RFC5424 | `<host>/<year>/syslog.log` as RFC3164/BSD | `<host>/syslog.log` as RFC5424 |
| `cisco_asa` | `<firewall>/cisco_asa.log` | `<firewall>/<year>/cisco_asa.log` | `<firewall>/cisco_asa.log` |
| Zeek | `<sensor>/<logtype>.json` only when Zeek sensors are configured | Unchanged | Unchanged |
| `web_access` | `<host>/web_access.log` as combined text | Combined text | `<host>/web_access.log` as Apache TA-compatible JSON |
| `proxy_access` | `<host>/proxy_access.log` as extended combined text | Plain combined text | `<host>/proxy_access.log` as Apache TA-compatible proxy JSON with CIM tagging |
| IDS, eCAR, bash history | Unchanged | Unchanged | Unchanged |

---

## Email Artifacts And Zeek SMTP

When `environment.email` is configured, `email_message` storyline events and
optional deterministic background email produce SMTP route evidence through the
normal DNS and network-visibility layers. Generated artifact metadata lives in
top-level `ARTIFACTS_MANIFEST.json`; materialized email messages live outside
`data/` under `artifacts/email/`.

**Files:**

- `ARTIFACTS_MANIFEST.json` — production-facing generated artifact manifest.
  Email records live under `email.messages` for materialized and metadata-only
  messages. They record message IDs, sender/recipient metadata, subject/date,
  optional `eml_path`, and blind-safe `artifact_export_status` /
  `artifact_export_reason` fields explaining whether an `.eml` was materialized
  or the row is metadata-only. They do not include storyline/internal case IDs,
  exercise verdict or classification labels, local filesystem artifact paths,
  expanded delivery recipients, or SMTP transport-route internals.
- `artifacts/email/<artifact-id>.eml` — RFC 5322 message artifacts for selected
  or storyline-backed messages.
- `<sensor>/smtp.json` — Zeek `smtp.log` NDJSON for visible SMTP transactions.
- `<sensor>/files.json` — Zeek `files.log` rows for every MIME part on plaintext
  SMTP hops, including the text body and attachments.

Zeek SMTP rows share UIDs with `conn.json`, include envelope/header metadata for
plaintext transfer, and honor STARTTLS visibility. If a client-submission or
server-to-server hop uses STARTTLS before message transfer, protected fields such as `subject`,
`msg_id`, `from`, `to`, `user_agent`, and attachment `fuids` are omitted from
the `smtp.json` row. Client submission uses port 587 and may upgrade to STARTTLS;
server relay uses port 25. Every SMTP server hop contributes a `Received` header in the
materialized `.eml` artifact.

Mailbox reads from `email_read` and automatic recipient-read behavior are opaque
TLS sessions only: IMAPS uses port 993 and OWA-style access uses HTTPS on 443.
Zeek can see DNS/connection/TLS evidence, not mailbox commands or message
content.

Exchange is modeled as a behavioral flavor for SMTP and HTTPS/OWA-style mailbox
access only. Native Exchange message-tracking or IIS/Exchange logs are not
currently emitted.

## Windows Security Events

**Default target file:** `<hostname.domain>/windows_event_security.xml`
**Default target format:** XML (`<Events><Event>...</Event></Events>`)
**SOF-ELK target file:** `<hostname.domain>/<year>/windows_event_security_snare.log`
**SOF-ELK target format:** Snare-style Windows Event Log fields inside an RFC3164 syslog envelope
**Splunk target file:** `<hostname.domain>/windows_event_security.xml`
**Splunk target format:** XML event stream (one complete `<Event>...</Event>` per line)
**Provider:** Microsoft-Windows-Security-Auditing (except 1102)
**Channel:** Security

The `default` target emits one rooted XML document. The `sof-elk` target emits
Snare syslog only so SOF-ELK and other syslog/Snare-aware tools can parse the
same canonical Windows Security events without requiring binary EVTX files. The
`splunk` target reuses the same XML event content as default output but removes
the global `<Events>` wrapper so Splunk file monitoring can ingest each Windows
event as a separate record on Linux.

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

EventRecordIDs are assigned in one final chronological pass per host/channel. Because this format
is a selected projection rather than a complete EVTX channel, gaps model omitted same-channel
records. Hidden counts are derived from elapsed time and conservative host/channel background
rates, with a peak-rate safety bound; Security Event 1102 starts a new channel epoch at record 1.

**Known Limitations:**
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
**Splunk target file:** `<hostname.domain>/windows_event_sysmon.xml`
**Splunk target format:** XML event stream (one complete `<Event>...</Event>` per line)
**Provider:** Microsoft-Windows-Sysmon
**Channel:** Microsoft-Windows-Sysmon/Operational

The `default` target emits one rooted XML document. The `sof-elk` target emits
Snare syslog only and `eforge eval` maps both variants back to the canonical
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

Zeek logs are per-sensor. Which connections appear depends on sensor placement (SPAN/TAP), monitored segments, and direction. All Zeek logs for the same connection share a common UID. If no Zeek sensors are configured, EvidenceForge does not emit Zeek logs.

| Log Type | File | Description | Notes |
|----------|------|-------------|-------|
| conn.log | `conn.json` | Connection metadata | TCP, UDP, ICMP. Includes duration, bytes, packets, conn_state, history. |
| dns.log | `dns.json` | DNS queries/responses | A, AAAA, PTR, SRV, TXT, MX, NS, and SOA query types. Automatic connection-prerequisite lookups route through the internal DNS lookup bundle so resolver choice, cache behavior, TTL observations, Zeek DNS/conn fan-out, Sysmon DNS visibility, and companion resolver questions stay consistent with connection hostnames. MX generation avoids CDN-style hostnames; TXT covers SPF/DKIM/DMARC-style background lookups. NXDOMAIN for suffix search. AA flag for internal zones. |
| http.log | `http.json` | HTTP transactions | Method, URI, status code, user-agent, request/response body lengths, and Zeek `trans_depth`. Only for plaintext/decrypted HTTP. Browser/page-load sessions can reuse one UID for multiple same-flow transactions. File-analyzed requests use `orig_fuids`/`orig_filenames`/`orig_mime_types`; responses use the corresponding `resp_*` vectors, all linked to `files.log`. Filename vectors are absent unless the message exposes a filename. |
| ssl.log | `ssl.json` | TLS handshakes | TLS version, cipher suite, SNI server_name, and `cert_chain_fuids` linking to x509 certificates. Generated for port 443 connections. Certificate-chain depth is driven by `tls_realism.yaml`. |
| files.log | `files.json` | File transfers | Extracted from visible HTTP request and response entities, OCSP responses, canonical plaintext SMB reads/writes, and plaintext SMTP MIME parts. Every successfully transmitted visible nonempty HTTP request body is represented with `is_orig: true`, and every visible nonempty response entity is represented with `is_orig: false`, including tiny, redirect, authentication-failure, and other error bodies. HEAD, 1xx, 204, 205, 304, successful CONNECT, zero-byte, failed-transport, and opaque HTTPS responses are fileless. Filename absence is normal; response URLs never invent filenames. Uses Zeek-native `tx_hosts`, `rx_hosts`, and `conn_uids` arrays plus `fuid`, optional filename, MIME type, byte counts, and hashes when analyzers ran. A plaintext proxy MISS creates origin→proxy and proxy→client files with different leg-local FUIDs but matching content metadata and hashes; HITs and proxy-generated errors create only client-leg files. Coherent observation loss can hide or truncate the file and suppress its matching HTTP vector. SMB reads are responder-to-originator and writes are originator-to-responder; each visible nonempty logical operation/content-version/direction gets a sensor-local FUID. Encrypted-share operations remain opaque. MIME is present only when leading content is observed and hashes require complete ordered analyzer observations. HTTP MIME/extension behavior is driven by `http_file_profiles.yaml`. |
| smb_mapping.log | `smb_mapping.json` | SMB tree connections | One sparse visible mapping row per successful canonical share tree. `native_file_system` is the server's wire-advertised value, not necessarily its backing filesystem; Samba commonly advertises NTFS over ext4/XFS. Mapping may remain visible when encrypted operations are opaque. |
| smb_files.log | `smb_files.json` | SMB file actions | Sparse successful OPEN/READ/WRITE/RENAME/DELETE observations. FUID is optional and appears only when the matching operation produced visible file analysis. |
| dhcp.log | `dhcp.json` | DHCP transactions | Client address, MAC (diversified OUI from network_params.yaml), hostname. Acquisition and renewal route through the internal DHCP lease bundle so Zeek DHCP/conn rows and Linux `dhclient` syslog companions share one lease identity. DHCP broadcast is treated as link-local: visible to SPAN sensors on the client segment, not routed through unrelated TAP/firewall segments. |
| ntp.log | `ntp.json` | NTP synchronization | Server-response records with version, mode 4, stratum, poll interval, and timing fields. NTP rows are emitted only when the matching UDP/123 conn row is response-bearing, so Zeek UID, conn_state/history, bytes, packets, duration, and parser timing agree. Version and poll are stable per client/server association, while stratum, ref-id, precision, root delay, and root dispersion are owned by the responding server. Scenario-defined internal/domain NTP servers are preferred; public fallback servers come from `network_params.yaml`. |
| x509.log | `x509.json` | X.509 certificates | Leaf and intermediate certificate `id`/fingerprint, subject/issuer, validity (issuer-aware from tls_issuers.yaml), key info, and CA constraints. Intermediate CA certificate profiles are reused by subject/issuer so the same CA does not appear as many different certificates in one dataset. |
| weird.log | `weird.json` | Protocol anomalies | Unusual network behavior. Automatic weird generation is currently disabled pending a data-driven Zeek weird compatibility model; explicitly supplied `WeirdContext` events still render. |
| pe.log | `pe.json` | Portable Executable | Windows binary metadata over network. |
| ocsp.log | `ocsp.json` | OCSP responses | Certificate revocation responses whose `id` joins to `files.log` `fuid`, matching Zeek file-analysis semantics. |
| packet_filter.log | `packet_filter.json` | BPF filter changes | Zeek packet filter status. |
| reporter.log | `reporter.json` | Zeek internal messages | Zeek operational status. |

The SMB field and visibility semantics follow the upstream
[Zeek SMB log contract](https://docs.zeek.org/en/lts/logs/smb.html); exact fields remain
version-sensitive.

**Known Limitations:**
- Native Zeek `kerberos.log` and `ntlm.log` authentication projections are deferred; SMB authentication can still have platform-eligible Windows, Samba syslog, and eCAR evidence
- Encrypted SMB share operations are intentionally opaque to `smb_files.log` and `files.log`; eligible endpoint evidence is independent. A visible SMB3 transform header does not imply payload decryption, and tree details are only present when negotiation was visible before encryption took effect
- Ordinary TLS (`service: ssl`) remains opaque, so its HTTPS content does not produce `http.log`; `http.log` is not limited to port 80 and can represent cleartext or proxy-inspected HTTP on other ports
- `missed_bytes` is probabilistic (~3% of long TCP connections) rather than from actual packet capture
- All timestamps use 6-digit microsecond precision

---

## eCAR Format (Simulated EDR Telemetry)

**File:** `ecar.json`
**Format:** NDJSON

Simulated EDR telemetry rendered in MITRE CAR-based eCAR format. Represents what an EDR agent would observe.

**Record structure:** `pid`, `tid`, and `ppid` are optional top-level integers, emitted only when a source-native nonnegative value is known. The `properties` map contains event-specific key-value pairs where all values are strings (including ports).

**Entity correlation (objectID/actorID graph):** Each record carries a persistent `objectID` (UUID) that identifies the entity being acted upon. Entity lifecycle events share the same objectID — e.g., a PROCESS/CREATE and PROCESS/TERMINATE for the same process, or a USER_SESSION/LOGIN and USER_SESSION/LOGOUT for the same session. The optional `actorID` field links to the objectID of the entity that performed the action — e.g., a PROCESS/CREATE's actorID points to its parent process's objectID, and a FILE/CREATE's actorID points to the process that created it.

| Object Type | Actions | Notes |
|-------------|---------|-------|
| PROCESS | CREATE, TERMINATE, OPEN | CREATE/TERMINATE include pid, ppid, image_path, parent_image_path, command_line, user. Correlated with syslog for CRON jobs and systemd service start/stop on Linux. OPEN maps to Sysmon Event 10 (ProcessAccess) — includes granted_access, target_pid, target_image_path, and target_process_uuid in properties. |
| THREAD | REMOTE_CREATE | Maps to Sysmon Event 8 (CreateRemoteThread). Properties include src_pid, target_pid, target_process_uuid, start_address, and stack addresses matching OpTC eCAR format. Thread ID, target PID, and start address are generated once in `RemoteThreadContext` and rendered consistently across Sysmon and eCAR. |
| FILE | READ, CREATE, WRITE, RENAME, DELETE | Generated alongside process activity, canonical SMB server operations and required client-local copy/move effects, and modeled transfer receiver evidence such as SCP target-side file creation. Windows server objects use Windows paths; Samba server objects use POSIX backing paths and live `smbd` worker provenance. Linux client-local effects use POSIX paths and the initiating client process when attributable. Remote share objects never fabricate a client Sysmon Event 11. |
| FLOW | CONNECT | Network connections from host perspective. Includes src/dst IP, port, protocol. |
| REGISTRY | MODIFY | Windows registry operations. |
| MODULE | LOAD | DLL loads for Windows processes using the same process-aware DLL profile data as Sysmon ImageLoaded events. |
| USER_SESSION | LOGIN, LOGOUT | Logon/logoff events. LOGIN includes outcome (`success` or `failure`); Windows successful logons include `logon_type`, while non-Windows sessions use OS-native `session_type` values such as `ssh`, `smb`, `remote`, `local`, or `service`. Samba sessions use neutral `auth_session_ref`/`session_id`, protocol/scope, and optional effective UID/GID; they do not invent Windows logon ID/type/GUID fields. Failed attempts include failure_reason/status fields and do not imply an established session. |
| SERVICE | CREATE | Service installation. Correlated with Windows 4697. Includes service_name, image_path (binary path), service_account in properties. |

Modeled successful SSH and RDP sessions have complete terminal ownership: their source client and target receiver/session processes terminate, and the target `USER_SESSION/LOGOUT` is emitted exactly once even when initial source publication loses its return or an SSH channel is retired by a long watermark. Watermark retirement transfers authenticated ownership only; it does not itself render endpoint or session close rows.

For bounded Linux foreground commands, PROCESS/TERMINATE reflects the modeled command lifetime. Exact numeric `sleep <duration>` commands use the requested seconds up to 86,400, while unsupported sleep syntax keeps the short fallback. When a session has an owning close deadline, foreground termination plus shell-release jitter remains before that owner closes.

**Known Limitations:**
- eCAR format represents an optional EDR layer — not all systems may have it enabled
- FLOW events carry endpoint process attribution only when the platform owns one. Examples include svchost for DNS/NTP, lsass for Kerberos/LDAP, System PID 4 for Windows-native SMB, mstsc.exe for RDP, a direct `smbclient` operation process, or the active Samba `smbd` worker. Mounted CIFS transport is kernel-owned and must not be attributed to `mount.cifs` for every operation. GVFS remains opaque background TCP/445/process texture and does not produce typed SMB file/auth/session semantics. Unavailable pid/tid identity is omitted rather than rendered as a placeholder
- Linux coverage focuses on PROCESS, USER_SESSION, FLOW, and FILE evidence rather than every endpoint object family
- File paths come from curated, OS-aware profiles rather than a complete endpoint inventory

---

## Linux Syslog

**Default target file:** `<hostname.domain>/syslog.log`
**Default target format:** RFC5424 syslog with full timestamp year
**SOF-ELK target file:** `<hostname.domain>/<year>/syslog.log`
**SOF-ELK target format:** RFC3164/BSD syslog with PRI
**Splunk target file:** `<hostname.domain>/syslog.log`
**Splunk target format:** RFC5424 syslog with full timestamp year

Authentication and system logs from Linux hosts. The `default` target emits
flat per-host RFC5424 syslog for SIEM-neutral output. The `splunk` target keeps
that RFC5424 shape. The `sof-elk` target emits a BSD/RFC3164 envelope
(`<PRI>MMM DD HH:MM:SS HOST APP[PID]: MESSAGE`) and
partitions files by event year so SOF-ELK can recover the timestamp year from
the archive path. `eforge eval` accepts both current target variants plus older
legacy RFC5424 and flat BSD/RFC3164 files. All generated syslog entries are
rendered from `SyslogContext` on `CanonicalOccurrence` — the emitter doesn't derive
messages from other contexts. Multi-phase activities such as SSH sessions are
coordinated by action-bundle semantics above individual canonical occurrences: the
bundle owns lifecycle, ordering, source timing, and shared identities, while each
syslog row remains a distinct canonical occurrence. Remote Linux `sshd`
failed-password rows reuse the same source port as the companion Zeek SSH
connection tuple. SSH terminal syslog and endpoint evidence remains complete after application
channel tombstone eviction because the lifecycle owner retains an authenticated retirement proof;
watermark advancement does not render PAM/logind or session termination rows itself.

Samba server evidence is rendered through this existing syslog family; there is no separate
journal or audit-log output format. `smbd` records authentication and share connection lifecycle.
`smbd_audit` records modeled VFS operations using
`smbd_audit: PRINCIPAL|SOURCE|SHARE|OPERATION|RESULT|POSIX-PATH`. The storage server's `audit`
level controls eligibility: `minimal` keeps lifecycle, `standard` adds selected open/close,
directory, rename/unlink, and failure evidence, and `high` emits full-audit rows for modeled
operations. These are target-version profiles derived from Samba's
[`smb.conf`](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) and
[`vfs_full_audit`](https://www.samba.org/samba/docs/current/man-html/vfs_full_audit.8.html)
contracts; exact upstream operation names vary by Samba release.

Routine successful Linux client operations do not produce client syslog. Kernel CIFS debug output
and optional Linux Audit policy are not implied by mounting a share and are not currently rendered
as SMB evidence. Client-side endpoint rows, when requested, come from eCAR and retain the selected
kernel-mounted or one-shot `smbclient` ownership model. GVFS remains background transport texture,
not canonical typed file activity.

| Activity/program family | Description | Notes |
|---------|-------------|-------|
| `sshd` and PAM | SSH authentication | Public-key/password authentication, accepted/failed auth, and session lifecycle. |
| `systemd`, `systemd-logind`, `systemd-journald`, `systemd-timesyncd` | Service, session, journal, and time lifecycle | Includes timer activity and sparse journald housekeeping. |
| `CRON`, `cron`, `anacron` | Scheduled work | Distro-aware scheduled jobs and coherent anacron runs. |
| Package maintenance | Package management | Distro-aware systemd lifecycle and `unattended-upgr`/PackageKit detail for apt/dnf activity. |
| `logrotate` and related service/timer rows | Log maintenance | Start/finish and per-file rotation detail. |
| `kernel` and UFW | Kernel and firewall | Boot/uptime, audit, and blocked-network evidence. |
| `sudo`, `su`, `polkitd` | Privilege and authorization | Command, user-switch, and host-appropriate policy events. |
| Host/role-specific daemons | Workstation and server background activity | Includes network, resolver, logging, snap, firmware, desktop, storage, and service-aware programs. |
| `smbd` | Samba authentication and connection lifecycle | Authentication result, effective Unix identity, share connect, and disconnect on modeled Samba servers. |
| `smbd_audit` | Samba VFS audit | Audit-level-dependent operation/result rows with the POSIX server path. |

**Known Limitations:**
- Program and message coverage is curated and role/distro-aware, not a complete operating-system journal
- Apart from modeled Samba evidence, most application-specific logs (nginx, postfix, mysql, etc.) remain separate or unavailable even when services are declared
- No SSH protocol negotiation messages (key exchange, cipher selection) before auth
- Bash history may be sparse relative to SSH session duration

---

## Bash History

**File:** `<hostname.domain>/bash_history/<username>.bash_history`
**Format:** Timestamped bash history (`#<epoch>\n<command>`)

Per-user command history for Linux systems. Baseline SSH sessions to Linux servers generate organic admin commands (ls, df, ps, systemctl, etc.) for realistic admin users (sysadmin, help_desk, developer, security_analyst personas), creating per-user history files on all Linux hosts. Storyline process events inject 0-3 organic noise commands around each attack command for realistic interleaving. Bash-history timing and optional foreground process telemetry are coordinated by the internal Linux shell-command bundle so command text, source-visible timing, and endpoint process evidence stay aligned.

An exact two-token numeric `sleep` command (for example, `sleep 30`, `sleep 30.5`, or `sleep .5`) models that process lifetime, capped at 86,400 seconds. Suffixes, signs, exponents, extra arguments, non-finite values, and malformed quoting use the existing short fallback. A bounded session clamps independent termination at least 1,425 ms before its owner closes so the full shell-release jitter fits.

**Known Limitations:**
- No command typos, tab-completion artifacts, or repeated commands
- No command output or error messages

---

## Snort/Suricata IDS Alerts

**File:** `snort_alert.log`
**Format:** Snort fast alert format

Network intrusion detection alerts. Baseline generates false-positive alerts (e.g., ICMP PING, SSH scan, policy violations) correlated with Zeek conn records via canonical CanonicalOccurrence dispatch. Storyline generates true-positive alerts for malicious connections. IDS signature-to-context construction is owned by the internal IDS alert action bundle so Snort/Suricata rows render canonical network/DNS/HTTP evidence rather than independently inventing alert payloads.

Typed `connection`, `beacon`, `ssh_session`, `rdp_session`, `dhcp_lease`,
`port_scan`, `dns_query`, `dga_queries`, `dns_tunnel`, and `web_scan` events can
attach multiple configured SIDs with `ids_alerts`. Attachments assert that a
signature matches; the generator does not run the full Snort rule predicate or
decrypt traffic. A network tuple without an explicit or built-in IDS context
does not alert. Candidates are projected through sensor
visibility, clock, and NAT/PAT views before per-sensor `detection_filter` and
`event_filter` state is applied. Deferred candidates use a disk-backed spool and
are deterministically ordered, so long beacons stay memory-bounded and authored
storyline order cannot change filtering results. Raw Snort events retain their
existing source-local behavior.

Each attachment follows only the physical transports owned by its authored
event. SSH/RDP attach to their session transport, DHCP only to the explicitly
authored transaction, scans and web scans to each probe/request, and DNS families
to their authored queries. Automatic DHCP renewals and DNS-tunnel background
cover queries do not inherit attachments. Authored web-scan SIDs coexist with
automatic preset/path/rate alerts and take precedence on a duplicate `(gid, sid)`.
Email transport attachments remain deferred.

`GROUND_TRUTH.json` and `.md` record each attached SID, its effective policy, and
candidate/emitted/policy-filtered sensor totals. Policy suppression is also
reported as `filtered` IDS evidence in `OBSERVATION_MANIFEST.json`; collection
drops and output-window clipping are distinct and never advance filter counters.

The optional `ids_evaluation` section in ground-truth schema v2 is the
automated acceptance contract. For each sensor and `(gid, sid)` it records
candidate, emitted, policy-filtered, visible/delayed, and authorized-origin
totals plus a SHA-256 digest over normalized alerts in file order. Normalization
covers sensor identity, UTC timestamp, signature metadata, protocol, full tuple,
and the sensor-visible NAT/PAT projection. Overall observation totals reconcile
visible, delayed, dropped, filtered, and out-of-window IDS attempts. The
Markdown IDS Evaluation Summary renders the same counts with abbreviated
digests.

Web scan events (`web_scan` storyline type) generate three layers of IDS alerts:
1. **Scanner UA detection** — identifies the scanning tool by user-agent (non-TLS only)
2. **Per-path content alerts** — curated SID mappings for specific probe paths (non-TLS only)
3. **Connection-rate threshold** — generic scan-rate alerts (both TLS and non-TLS)

Alert format: `[gid:sid:rev]` where `gid` defaults to 1, `sid` identifies the rule, and `rev` reflects real ET/Community ruleset revision numbers sourced from `sample_data/snort/`. Each `(gid, sid)` pair has stable rule identity and carries a `rev` field.

**Known Limitations:**
- IDS alert variety is limited to curated SID pools (not full ruleset simulation)
- Signature attachments declare matches; they do not parse or execute Snort rules,
  `rate_filter`, CIDR suppression, or IPS actions

---

## Cisco ASA Firewall Syslog

**Default target file:** `<fw-hostname>/cisco_asa.log`
**SOF-ELK target file:** `<fw-hostname>/<year>/cisco_asa.log`
**Splunk target file:** `<fw-hostname>/cisco_asa.log`
**Format:** Cisco ASA syslog (RFC 3164 BSD syslog with ASA message IDs)

Cisco ASA firewall logs for permitted and denied connections. Produced by
`environment.network.sensors` entries with `type: firewall` and `cisco_asa` in
their `log_formats`. These entries model active firewall control points
(policy, NAT, deny baseline, threat detection, and logging), even though they
currently live in the `sensors` list for compatibility. Requesting `cisco_asa`
without a matching firewall entry is a validation error.

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
**Default/SOF-ELK format:** Apache/Nginx combined log text
**Splunk format:** NDJSON records compatible with the Apache TA `apache:access:json` sourcetype

HTTP access logs for web server systems.

Default and SOF-ELK entries use Apache/Nginx combined syntax:

```text
client-ip - username [dd/Mon/yyyy:HH:MM:SS zone] "METHOD path HTTP/version" status bytes "Referer" "User-Agent"
```

**Referer field:** Browser-originated traffic carries a realistic Referer distribution — roughly 55% blank (direct/bookmark), 20% search engine (Google/Bing), 20% same-origin, 5% social/news. Bot user-agents (Googlebot, bingbot, AhrefsBot) always have blank Referer. Scanner traffic (`web_scan` events) follows per-preset rules grounded in real scanner behavior: Nikto sends same-origin Referer on ~30% of requests (partial-crawl mode); gobuster, sqlmap, dirb, and nmap_http send no Referer. This means the Referer field is useful for distinguishing human browsing from automated scans in training exercises.

**Known Limitations:**
- Only generated for systems with web server role

---

## HTTP Proxy Log

**File:** `<proxy-hostname.domain>/proxy_access.log`
**Default format:** Extended Apache/Nginx combined text with optional proxy metadata
**SOF-ELK format:** Plain Apache/Nginx combined text
**Splunk format:** Apache TA-compatible NDJSON with EvidenceForge proxy fields and CIM tagging

Forward proxy access logs for systems with the `forward_proxy` role. This is a
host/proxy log, not a network sensor log, so proxy-only labs do not need
placeholder Zeek sensors. Outbound HTTP/HTTPS traffic is routed through the
proxy system. In `environment.proxy.mode: transparent`, network sensors can
still show direct-looking client-to-origin traffic when matching sensors are
configured. In `mode: explicit`, the generator emits client-to-proxy and
proxy-to-origin network legs; each Zeek/IDS/firewall sensor sees only the leg
its topology can observe. If the proxy denies a request, the transaction stops
at the proxy and no proxy-to-origin Zeek, IDS, or firewall evidence is emitted.
HTTP/S storyline `beacon` events from proxied hosts use the same explicit proxy
routing, including proxy-side denied CONNECT/GET evidence for `action: deny`.

Default and SOF-ELK proxy logs use the same Apache/Nginx combined syntax as
`web_access.log`, with proxy request targets in the quoted request field:

```text
client-ip - username [dd/Mon/yyyy:HH:MM:SS zone] "METHOD request-target HTTP/version" status bytes "Referer" "User-Agent"
```

For forwarded HTTP/HTTPS requests, `request-target` is the absolute URL known
to the proxy, such as `https://host/path`. For CONNECT tunnel setup rows,
`request-target` is the authority form, such as `host:443`. Missing values are
`-`.

**Username field:** Default proxy auth realism attributes ordinary
browser/SaaS traffic to the assigned human user, while allowlisted
infrastructure classes such as software updates, telemetry, CRL, and OCSP can
render unauthenticated (`-`) rows. Machine/service-account proxy usernames are
opt-in through `environment.proxy.auth_policy`; `mode: legacy` preserves the
older machine-context User-Agent behavior. Default combined text output
preserves the full username value when one is present. The SOF-ELK target
strips the domain prefix from identities such as `DOMAIN\user` and the trailing
`$` from machine accounts such as `DOMAIN\HOST$` so SOF-ELK's HTTPD parser can
ingest the row. Splunk JSON proxy output also preserves the full username
value.

**Referrer field:** The combined format output includes the standard quoted
`Referer` field, linking subresource requests back to the page that triggered
them.

**CONNECT tunnel behavior:** HTTPS traffic generates one CONNECT entry per unique (client_ip, host) pair per session, with a 5-minute idle timeout. Subsequent HTTPS requests to the same host within the timeout reuse the existing tunnel without emitting another CONNECT. The current proxy model assumes TLS interception, so inspected HTTPS requests can also appear as combined-format request rows such as `"GET https://host/path HTTP/1.1"`.

**Status and byte semantics:** For explicit proxy mode, client-side Zeek HTTP records describe the client-to-proxy exchange. Plain HTTP denials therefore show the proxy's status code and proxy response size, not the origin's status/body. For intercepted HTTPS, the CONNECT setup status is tracked separately from the inspected request status, so a successful tunnel setup can coexist with a denied inspected GET.

**Proxy HTTP files:** For plaintext/decrypted HTTP, a cache MISS with a transmitted
origin body creates correlated responder files on both physical legs. A cache HIT
or proxy-generated denial/error body creates only the proxy-to-client file. A
failure before the origin responds creates no egress response file. Failed CONNECT
error bodies can be analyzed; successful CONNECT and opaque tunneled HTTPS cannot.

**Multipart HTTP files:** `multipart/form-data` and `multipart/mixed` bodies use
the outer serialized size in `request_body_len` or `response_body_len`, including
boundaries, MIME headers, separators, and transfer encoding. Each nonempty decoded
leaf produces its own directional `files.log` row; multipart containers and
envelope bytes do not. Leaf `seen_bytes`, hashes, detected MIME, and PE analysis
describe decoded content. `total_bytes` is absent unless that leaf has its own
Content-Length. `orig_fuids`/`resp_fuids` preserve discovery order and are capped
at 15, while all leaf rows remain in `files.log`. Filename and MIME vectors are
sparse present-value lists and must not be indexed positionally against FUIDs.
Missing-boundary analyzer input remains one ordinary whole-body file. Ordinary
byteranges, chunked multipart, and top-level content-coded multipart are outside
this model.

**Source-native HTTP semantics:** Domain/path planning is resolved before proxy
and Zeek HTTP rows are rendered. Public browser-like domains default to
HTTPS-first behavior, so plaintext port-80 requests redirect instead of serving
login pages; internal hosts and service/update endpoints can keep plaintext
source-native behavior. Browser requests also follow no-referrer-when-downgrade
semantics, service/update endpoints keep source-compatible User-Agents, and
executable/download paths use binary content types with download-scale body
sizes.

**Session depth:** Persona HTTP traffic and inbound `web_server` human visitors generate multi-request browsing sessions with subresource cascades. Each page load triggers follow-on requests for JS, CSS, images, fonts, and same-origin API calls, producing realistic request clusters in proxy and web access logs. Persona browsing depth is controlled by `browsing_intensity`; inbound web visitor classes, tool/API requests, and User-Agent pools are controlled by `web_session_profiles.yaml`.

**Scenario traffic affinities:** `baseline_activity.traffic_affinities` can add
benign population traffic to authored network identities. Web affinities render
through the same browser/proxy/Zeek/web-access paths as ordinary browsing, and
route profiles keep methods, statuses, body sizes, and content types tied to
specific paths. Generic connection affinities render through canonical
connection generation, so Zeek conn, eCAR FLOW, firewall/NAT, DNS, and TLS
companions appear according to normal visibility rules.

**Known Limitations:**
- Only generated for systems with the `forward_proxy` role declared
- Non-intercepting tunnel-only HTTPS proxy behavior is not yet modeled
- Cache hit/miss status is probabilistic, with stable web-route status generated upstream
- Limited to HTTP and HTTPS traffic

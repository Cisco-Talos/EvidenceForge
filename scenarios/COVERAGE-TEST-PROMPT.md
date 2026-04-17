  Create an EvidenceForge scenario for a comprehensive feature coverage test. Use these requirements:

  Environment: Meridian Healthcare Solutions, a mid-size healthcare IT company (~120 employees) providing
   EHR integration services. Corporate HQ with on-premises data center.

  Duration: 14 hours, starting 2024-03-18T12:00:00Z. Timezone: America/Chicago.

  Systems (mix of Windows and Linux, ~20+ total):
  - One workstation per user, distributed across departments: dev, IT,
  security, finance, data analytics, executive, PM, HR, sales, legal, marketing, front desk
  - Most workstations are Windows 10/11, but at least 3 users have Linux desktops (Ubuntu 22.04,
  type: workstation): typically developers and data analysts who prefer Linux for their daily work
  - 2 Windows servers: DC-01 (domain controller, Server 2022), FILE-SRV-01 (file server, Server 2019)
  - 5 Linux servers: WEB-EXT-01 (Ubuntu, web server in DMZ with roles: [web_server],
  public_hostnames: ["ehr-portal.meridianhcs.com"]), PROXY-01 (Ubuntu,
  roles: [forward_proxy]), APP-INT-01 (Ubuntu, internal app server), DB-PROD-01 (CentOS, MySQL),
  LOG-SRV-01 (Ubuntu, syslog/Elasticsearch)

  Network (4 segments):
  - corporate_lan (10.10.1.0/24) — workstations
  - server_vlan (10.10.2.0/24) — DC, file server, app server, log server
  - dmz (10.10.3.0/24, exposure: both) — web server, proxy
  - database_vlan (10.10.4.0/24) — MySQL (intentionally no sensor — blind spot)

  Sensors:
  - zeek-core: SPAN, monitors corporate_lan + server_vlan, bidirectional
  - zeek-dmz: SPAN, monitors dmz, bidirectional
  - snort-perimeter: TAP, monitors dmz, inbound
  - fw-perimeter: firewall, TAP, monitors corporate_lan + server_vlan + dmz, bidirectional,
    log_formats: [cisco_asa], interfaces: {corporate_lan: inside, server_vlan: inside, dmz: dmz},
    default_action: deny, deny_ratio: 5.0, nat_rules:
      - type: dynamic_pat
        src: [corporate_lan, server_vlan]
        mapped_ip: 45.33.32.1
      - type: static
        src: dmz
        real_ip: 10.10.3.10 (WEB-EXT-01)
        mapped_ip: 198.51.100.10
    policy:
      - {src: external, dst: dmz, ports: [80, 443]}          # Allow web traffic to DMZ
      - {src: corporate_lan, dst: any}                         # Users can reach anything
      - {src: server_vlan, dst: external, ports: [80, 443, 53]} # Servers: web + DNS out
      - {src: server_vlan, dst: server_vlan}                   # Inter-server
      - {src: dmz, dst: server_vlan, ports: [3306]}            # DMZ web -> database

  Users: 17 users spanning all 15 built-in personas (developer, analyst, sysadmin, executive,
   data_analyst, receptionist, help_desk, marketing, sales, accountant, engineer, lawyer,
   hr_specialist, security_analyst, intern). Realistic diverse names (first.last format). Every
   user must have a dedicated primary_system workstation (1:1 mapping — create one workstation per user).
   At least 2 users should have browsing_intensity: heavy, and 2 with browsing_intensity: light.
   Service accounts: svc_backup, svc_monitor, svc_sqlreader.

  Stale accounts (3):
  - jennifer.walsh: last_active 2023-11-15, reason "Transferred to London office"
  - svc_legacy_crm: last_active 2024-01-02, reason "CRM system decommissioned"
  - robert.kim: last_active 2023-09-30, reason "Former contractor, access not revoked"

  Red herrings (3-4 explicit events, in addition to automatic suspicious_noise):
  - After-hours IT maintenance: sysadmin RDP to DC-01 at an unusual hour, running legitimate
    diagnostic commands (Get-EventLog, Test-Connection). Should look suspicious but have an
    innocent explanation.
  - Failed logon burst from a legitimate user who fat-fingered their password 3-4 times before
    succeeding. Should trigger lockout-style alerts but is benign.
  - Large outbound file transfer from a developer workstation to a cloud storage IP — actually a
    legitimate backup or repo sync, but the volume looks like exfiltration.
  - Service account (svc_backup) authenticating from an unusual host (not its normal server) —
    legitimate scheduled task migration, but looks like lateral movement.

  All 10 log format groups: windows, zeek, ecar, syslog, bash_history, snort_alert, cisco_asa,
   web_access, proxy_access.
  (Note: "windows" expands to windows_event_security + windows_event_sysmon; "zeek" expands to
   zeek_conn, zeek_dns, zeek_http, zeek_ssl, zeek_files, zeek_dhcp, zeek_ntp, zeek_weird,
   zeek_x509, zeek_ocsp, zeek_pe, zeek_packet_filter, zeek_reporter — 22 individual formats total.)

  Attack storyline — APT via web app exploit, full kill chain:

  Attacker realism: The storyline MUST include 5-8 fumbles, dead ends, and mistakes
  interspersed naturally across the kill chain phases. Real intrusions are not clean
  walkthroughs — attackers mistype commands, try wrong credentials, connect to the wrong
  host, run tools that fail, and hit dead ends before pivoting. Examples of fumbles to
  weave into the steps:
  - Failed SSH to the wrong host (e.g., LOG-SRV-01 instead of APP-INT-01) before finding
    the actual target
  - Typo'd command (e.g., "mysqldumpp" or "net gruop") followed by a correction seconds later
  - A find/dir command that returns nothing, then a retry with a different path or wildcard
  - Denied RDP to a host that doesn't allow it, then switching to PsExec or SSH
  - Wrong password on the first lateral movement attempt (failed_logon) before the right one
  - Tool that crashes or times out (process with short duration, then re-execution)
  - Recon command that reveals a dead end (empty share, no users in a group, permission denied)
  - Connection attempt to a host in the database_vlan that has no sensor (attacker probing
    the blind spot — visible only on the firewall)
  These should NOT be in a separate section — scatter them within the existing phases so the
  timeline looks organic. Each fumble should use the appropriate event type (failed_logon,
  process with the wrong command, connection to wrong host, etc.).

  1. Rogue Device (+0h45m): Attacker plugs rogue laptop into network, obtains IP via DHCP
  (dhcp_lease event). Actor: attacker on rogue device.
  2. Initial Access (+1h): External attacker (185.70.41.45) scans and exploits SQL injection on
  WEB-EXT-01's EHR portal. Use connection events with HTTP fields (method: POST, uri with SQLi
  payload, status_code: 500, user_agent, hostname: "ehr-portal.meridianhcs.com") — NOT raw events.
  Actor: root.
  3. Execution (+1h20m): Web shell upload, reverse shell to C2 at 45.33.32.30:8443. Use real
  base64-encoded reverse shell payload.
  4. Discovery (+1h40m-2h): Network enumeration from WEB-EXT-01 — ip addr, /etc/hosts, nmap ping sweep
  and port scan of server_vlan.
  5. Credential Access (+2h15m): Harvest DB credentials from web app config files and SSH keys.
  6. Lateral Movement (+2h30m): SSH from WEB-EXT-01 to APP-INT-01 using stolen key (ssh_session event).
  7. Credential Access (+2h50m): Dump /etc/shadow and /etc/passwd on APP-INT-01.
  8. Explicit Credentials (+3h10m): Attacker uses RunAs with compromised sysadmin account
  (explicit_credentials event with target_username, target_server, process_name).
  9. Lateral Movement (+3h30m): Credential spray (credential_spray event with pattern: spray,
  target_accounts: [2-3 accounts], success: {account: "sarah.oconnell", after: 3},
  interval: "5s", count: 10) then successful RDP to WS-DEV-01 using sarah.oconnell.
  10. Discovery (+3h50m): AD enumeration — whoami /all, net user /domain, net group "Domain Admins",
  LDAP query to DC, net view file shares.
  11. Credential Access (+4h30m): Mimikatz (disguised as ms-index-service.exe) with
  create_remote_thread targeting lsass.exe (auto-generates process_access with 0x1FFFFF).
  12. Lateral Movement (+5h): PsExec to DC-01 via SMB.
  13. Privilege Escalation (+5h15m): Create backdoor account svc_sqlreader (account_created event),
  add to Domain Admins (group_member_added event).
  14. Persistence (+5h30m): Install service "HealthMonitorSvc" (service_installed event with
  service_name, service_file_name, service_account) and create scheduled task
  "\Microsoft\Windows\Maintenance\SystemHealthCheck" (scheduled_task_created event with task_name)
  on DC-01.
  15. C2 Beaconing (+5h45m): HTTPS beacon from DC-01 to 45.33.32.30:443 (beacon event with
  interval: "10m", duration: "8h", jitter: 0.3, hostname, user_agent, method: GET,
  orig_bytes/resp_bytes for realistic sizing).
  16. DNS Tunneling (+6h): Exfiltrate data via DNS tunnel from APP-INT-01 (dns_tunnel event with
  base_domain: "ns1.cdn-health-updates.net", encoding: hex, qtype: TXT, interval: "2s",
  duration: "15m", payload_size: 512).
  17. DGA Activity (+6h15m): DGA queries from WEB-EXT-01 (dga_queries event with tld: ".net",
  length_range: [10, 18], interval: "30s", duration: "2h", rcode_distribution for mostly NXDOMAIN).
  18. Collection (+6h30m): Authenticate to FILE-SRV-01 with backdoor account (logon event),
  stage financial and patient data, compress with PowerShell.
  19. Exfiltration (+7h15m): Upload archive to cdn-assets-update.com (45.33.32.30) over HTTPS
  (connection event with HTTP fields, method: POST, large orig_bytes).
  20. Database Access (+8h): SSH to DB-PROD-01 (ssh_session), mysqldump patient/insurance tables,
  gzip and SCP back to APP-INT-01.
  21. Defense Evasion (+9h): Clear bash history on Linux, encoded PowerShell download (real UTF-16LE
  base64), clear Security event log on DC-01 (log_cleared event).
  22. Workstation Lock/Unlock (+9h30m): Attacker locks compromised workstation before leaving
  (workstation_lock event), then unlocks later (workstation_unlock event) — exercises 4800/4801.
  23. DNS Queries (+10h): Standalone DNS queries for attacker infrastructure (dns_query events with
  query, qtype, rcode, answer fields).
  24. Web Scanning (+0h30m): External attacker (185.70.41.45) runs web vulnerability scan against
  WEB-EXT-01 (web_scan event with preset: nikto, rate: 10, duration: "20m", dst_port: 443,
  hostname: "ehr-portal.meridianhcs.com").
  25. Port Scan (+0h30m): External attacker (185.70.41.45) scans the DMZ segment looking for
  services before the initial exploit. Use port_scan event with target_segment: dmz, ports:
  [22, 80, 443, 8080, 8443, 3306], scan_rate: 50. This should produce firewall denies visible
  to the external Zeek/Snort sensors but NOT internal sensors.
  26. Blocked C2 (+6h): After compromising DC-01, attacker malware tries to beacon directly
  from DC-01 to 45.33.32.30:443 — but the firewall policy doesn't allow servers to reach
  external IPs on arbitrary ports. Use beacon event with action: deny, interval: "30m",
  duration: "6h". The denied outbound attempts should be visible to internal sensors only.
  27. Ongoing C2 (+10h, +12h): Periodic beacons from WEB-EXT-01 and DC-01.
  28. Account Cleanup (+13h): Delete the backdoor account (account_deleted event with
  target_username: svc_sqlreader).
  29. Logoff (+13h30m): Attacker logs off from compromised systems (logoff events).

  Key requirements:
  - Exercise all 26 storyline event types: process, logon, failed_logon, logoff, connection,
  ssh_session, rdp_session, account_created, account_deleted, group_member_added, service_installed,
  scheduled_task_created, log_cleared, create_remote_thread, dhcp_lease, port_scan, beacon,
  dns_query, web_scan, credential_spray, dga_queries, dns_tunnel, explicit_credentials,
  workstation_lock, workstation_unlock, raw
  - NOTE: process_access is NOT a scenario event type — it is auto-generated by create_remote_thread
  targeting lsass.exe via the causal expansion engine. Do not declare it in the YAML.
  - NOTE: "c2" is NOT a valid event type — use "beacon" for C2 communication
  - Use connection events with HTTP fields (method, uri, status_code, user_agent, hostname) for web
  access log entries showing the SQLi and web shell access — NOT raw events
  - Periodic events (beacon, web_scan, credential_spray, dga_queries, dns_tunnel) must each
  specify exactly one of: end_time, duration, or count — plus interval (or rate for web_scan)
  - All base64 payloads must be real (generated via Bash tool)
  - Attacker naming must be realistic (no "evil", "malware", "attacker" names)
  - External IPs from realistic public ranges (NOT RFC 5737 documentation ranges)
  - Baseline activity: medium intensity, medium variation, suspicious_noise: medium
  - Include technique (MITRE ATT&CK ID) and description fields on storyline events for ground truth

  Engine behavior expectations:
  - C2 connections to raw IPs (45.33.32.30) will NOT have DNS queries — realistic for direct-IP C2
  - DNS queries for baseline web traffic use domain-first selection — SNI, DNS, and proxy hostname will be consistent
  - DHCP events are routed to sensors by segment visibility (not duplicated across all sensors)
  - Windows service account events (SYSTEM, NETWORK SERVICE) show "NT AUTHORITY" as SubjectDomainName
  - Certificate validity periods match issuer (Let's Encrypt = 90 days, DigiCert = 397 days)
  - MAC addresses use diverse OUI prefixes (Dell, HP, Lenovo, Intel, VMware)
  - PID 4 resolves to "System" in parent process lookups
  - NAT rules produce: dynamic PAT (mapped_src_ip + translated src port for outbound), static NAT
  (1:1 mapping for DMZ server). Outside Zeek sensors see post-NAT IPs; inside sensors see real IPs
  - Firewall policy enforcement: external -> corporate_lan denied, external -> dmz:80/443 allowed

  eCAR format coverage (verify in generated data):
  - All eCAR records have pid and tid (always present, -1 sentinel when unavailable)
  - PROCESS events have ppid top-level; non-PROCESS events do NOT have ppid
  - All properties values are strings (including ports like "443", "53")
  - PROCESS/CREATE records include parent_image_path in properties
  - objectID persists across entity lifecycle: same objectID on logon/logoff pairs and
    process create/terminate pairs
  - actorID links to acting entity: PROCESS/CREATE actorID = parent process objectID;
    FILE/REGISTRY/MODULE actorID = initiating process objectID;
    PROCESS/OPEN actorID = source process objectID, objectID = target process objectID;
    THREAD/REMOTE_CREATE actorID = source process objectID, properties include
    tgt_pid, tgt_pid_uuid, start_address, and stack addresses
  - FLOW records carry realistic system process PIDs:
    - Windows DNS -> svchost NetworkService pid
    - Windows NTP -> svchost LocalService pid
    - Windows SMB -> System PID 4
    - Windows Kerberos/LDAP -> lsass pid
    - Windows RDP outbound -> mstsc.exe pid
    - Ubuntu DNS -> systemd-resolved pid
    - CentOS DNS -> pid -1 (apps resolve directly)
    - Ubuntu NTP -> systemd-timesyncd pid
    - CentOS NTP -> chronyd pid
  - Storyline connection events carry the attack process pid (from _last_storyline_pid)
  - The mix of Ubuntu (WEB-EXT-01, PROXY-01, APP-INT-01, LOG-SRV-01) and CentOS (DB-PROD-01)
    exercises distro-aware process tree seeding

  Sysmon coverage (verify in generated data):
  - Event 1 (ProcessCreate): baseline + storyline process events
  - Event 5 (ProcessTerminate): baseline process terminations for Windows hosts plus storyline
    process terminations with realistic delays (recon: 0.3-5s, attack tools: 5-30s, persistent/C2: no termination)
  - Event 7 (ImageLoad): baseline DLL loads (ntdll.dll, kernel32.dll, etc.)
  - Event 8 (CreateRemoteThread): baseline benign pairs (MsMpEng->explorer, csrss->svchost, etc.)
    plus storyline mimikatz create_remote_thread targeting lsass
  - Event 10 (ProcessAccess): baseline benign pairs (MsMpEng->lsass with 0x1410, services->svchost
    with 0x1000, etc.) plus storyline mimikatz process_access on lsass with 0x1FFFFF
  - Event 22 (DNSQuery): DNS lookups from Windows processes
  - Baseline Event 8/10 noise ensures storyline attack events are not instant red flags

  Cisco ASA firewall coverage (verify in generated data):
  - Built/Teardown pairs (302013/302014) for permitted TCP connections through the firewall
  - Built/Teardown pairs (302015/302016) for permitted UDP connections (DNS queries, etc.)
  - Deny records (106023) for blocked external scanning and unauthorized cross-segment traffic
  - Correct interface resolution: internal IPs -> "inside", DMZ IPs -> "dmz", external IPs -> "outside"
  - Per-sensor directory output: fw-perimeter/cisco_asa.log
  - Deny baseline volume proportional to deny_ratio (~5x allows)
  - Firewall policy enforcement: external -> corporate_lan denied, external -> dmz:80/443 allowed
  - Storyline connections through the firewall produce ASA allow records correlated with Zeek conn records
  - 305011 (Built NAT translation) present when nat_rules configured
  - 305012 (Teardown NAT translation) present
  - Built messages show mapped IPs in parentheses that differ from real IPs
  - Outside Zeek sensors show post-NAT source IPs; inside sensors show real IPs
  - Static NAT: inbound connections to VIP (198.51.100.10) translated to real IP (10.10.3.10)

  Data Realism coverage (verify in generated data):
  - Causal expansion: DNS queries precede TCP connections in zeek_dns/zeek_conn; Kerberos 4768/4769
    precede 4624 domain logons; process_access (Event 10) follows create_remote_thread targeting lsass
  - Hawkes temporal model: user events show bursty clusters (CV > 1.0 in eval), not uniform spacing
  - Typing cadence: multi-event storyline steps (e.g., step 4 discovery commands, step 10 AD enum)
    have 1-15 second gaps between events, not identical timestamps
  - Day-of-week variation: if scenario spans a weekend, Saturday/Sunday activity near-zero
  - Lateral movement: backup/monitoring/AD replication traffic between servers (conditional on topology)
  - Process->network correlation: chrome.exe/git/sqlcmd baseline processes produce matching connections
  - Stale account enrichment: if stale_accounts defined, expect Kerberos 4771 (0x12) failures on DC
    plus failed batch (type 4) and service (type 5) logons, not just network logon failures
  - Network red herrings: suspicious-but-benign DNS (high-entropy CDN subdomains), unusual outbound
    (cloud backup sync), and scan overlap patterns in Zeek conn/dns logs
  - Linux syslog depth: SSH "Accepted publickey/password" login messages, apt-daily or dnf-automatic
    package management, systemd timer trigger/deactivate, logrotate file rotation detail, journald
    runtime statistics. Verify distro-aware (Ubuntu vs CentOS paths/daemons).
  - Command diversification: baseline process commands contain user-specific paths and varied
    project/document names, not identical fixed strings across all users
  - Entity lifecycle: no process_access events targeting PIDs that don't exist in running_processes
  - Workstation lock/unlock (4800/4801): persona-driven lock frequency during work hours
  - Explicit credentials (4648): RunAs and scheduled task execution with alternate credentials

  Proxy coverage (verify in generated data):
  - Forward proxy (PROXY-01 with roles: [forward_proxy]) routes web traffic for internal systems
  - proxy_access logs show client_ip, username, method, url, host, status_code, cache_result
  - HTTP CONNECT method for HTTPS tunneling through proxy
  - Cache hit/miss distribution (HIT, MISS, NONE, DENIED)
  - Proxy logs correlate with Zeek HTTP/SSL logs for the same transactions

  Ground truth / answer key:
  - GROUND_TRUTH.md generated automatically from storyline events
  - Contains: attack summary narrative, chronological timeline table, IOCs by category
  (IPs, domains, usernames, processes, files, ports, protocols), red herring explanations
  - technique fields on storyline events map to MITRE ATT&CK for IOC categorization

  Save to scenarios/apt-healthcare-breach/scenario.yaml with accompanying ENVIRONMENT.md.

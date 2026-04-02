  Create an EvidenceForge scenario for a large-scale coverage test targeting ~1GB of generated data.
  Use these requirements:

  Environment: Meridian Healthcare Solutions, a growing healthcare IT company (~350 employees) providing
  EHR integration and managed health IT services. Corporate campus with primary data center, disaster
  recovery site references, and remote office VPN users.

  Duration: 72 hours (3 full business days), starting 2024-03-18T06:00:00Z (Monday morning).
  Timezone: America/Chicago. This spans Monday–Wednesday, exercising day-of-week variation with
  full business-day cycles including morning ramp-up, lunch dips, and evening wind-down.

  Scenario name: apt-healthcare-breach-large

  Systems (mix of Windows and Linux, ~75+ total):

  Windows workstations (Windows 10/11) — one per user (see Users section), with naming convention
  WS-{DEPT}-{NN} across departments: dev, IT, security, finance, data analytics, executive, PM, HR,
  sales, legal, marketing, front desk. Exception: IT helpdesk staff (sysadmin persona) share 2-3
  workstations to represent shift coverage (e.g., WS-IT-HELP-01, WS-IT-HELP-02).

  Windows servers (10, Server 2019/2022):
  - DC-01 (domain controller, Server 2022, roles: [domain_controller])
  - DC-02 (secondary domain controller, Server 2022, roles: [domain_controller])
  - FILE-SRV-01 (file server, Server 2019, roles: [file_server])
  - FILE-SRV-02 (departmental file server, Server 2019, roles: [file_server])
  - EXCH-01 (Exchange mail server, Server 2019, roles: [mail_server])
  - PRINT-SRV-01 (print server, Server 2019, roles: [print_server])
  - WSUS-01 (WSUS patch server, Server 2019)
  - SCCM-01 (SCCM management server, Server 2019)
  - RDS-01 (Remote Desktop Services gateway, Server 2022)
  - NPS-01 (Network Policy Server / RADIUS, Server 2019)

  Linux servers (15, Ubuntu 22.04 / CentOS 8 / RHEL 9 mix):
  - WEB-EXT-01 (Ubuntu, external EHR portal in DMZ, roles: [web_server])
  - WEB-EXT-02 (Ubuntu, patient portal in DMZ, roles: [web_server])
  - WEB-INT-01 (Ubuntu, internal intranet/wiki, roles: [web_server])
  - PROXY-01 (Ubuntu, forward proxy, roles: [forward_proxy])
  - PROXY-02 (Ubuntu, reverse proxy / WAF in DMZ)
  - APP-INT-01 (Ubuntu, EHR integration engine)
  - APP-INT-02 (Ubuntu, HL7/FHIR message broker)
  - DB-PROD-01 (CentOS, MySQL primary — patient data)
  - DB-PROD-02 (CentOS, MySQL replica — reporting)
  - DB-AUX-01 (RHEL, PostgreSQL — ticketing/internal apps)
  - LOG-SRV-01 (Ubuntu, syslog relay + Elasticsearch)
  - DNS-INT-01 (Ubuntu, internal recursive DNS, roles: [dns_server])
  - DNS-EXT-01 (Ubuntu, authoritative DNS in DMZ, roles: [dns_server])
  - BACKUP-01 (Ubuntu, Veeam/rsync backup target, roles: [backup_server])
  - BUILD-01 (Ubuntu, Jenkins CI/CD server)

  Network (7 segments):
  - corporate_lan (10.10.0.0/22) — workstations (larger subnet for ~50 hosts)
  - server_vlan (10.10.2.0/24) — DCs, file servers, Exchange, print, WSUS, SCCM, RDS, NPS
  - app_vlan (10.10.5.0/24) — app servers, build server, internal web, internal DNS
  - dmz (10.10.3.0/24, exposure: both) — external web servers, external DNS, reverse proxy, proxy
  - database_vlan (10.10.4.0/24) — MySQL, PostgreSQL (intentionally no sensor — blind spot)
  - management_vlan (10.10.6.0/24) — LOG-SRV-01, BACKUP-01 (monitoring/backup infrastructure)
  - vpn_pool (10.10.7.0/24) — VPN client address pool for remote users

  Sensors (8 — expanded coverage with overlaps, gaps, and firewall):
  - zeek-core: SPAN, monitors corporate_lan + server_vlan, bidirectional
  - zeek-dmz: SPAN, monitors dmz + app_vlan, bidirectional
  - zeek-mgmt: SPAN, monitors management_vlan + server_vlan, bidirectional (overlaps with zeek-core
    on server_vlan — realistic multi-sensor overlap)
  - snort-perimeter: TAP, monitors dmz, inbound
  - snort-internal: TAP, monitors corporate_lan + server_vlan, bidirectional
  - zeek-vpn: SPAN, monitors vpn_pool + corporate_lan, bidirectional
  - fw-external: firewall, TAP, monitors corporate_lan + server_vlan + dmz + app_vlan, bidirectional,
    log_formats: [cisco_asa], interfaces: {corporate_lan: inside, server_vlan: inside,
    app_vlan: inside, dmz: dmz, management_vlan: inside, vpn_pool: inside},
    default_action: deny, deny_ratio: 8.0, nat_rules:
      - type: dynamic_pat
        src: [corporate_lan, server_vlan, app_vlan]
        mapped_ip: 45.33.32.1
      - type: static
        real_ip: 10.10.3.10
        mapped_ip: 185.70.41.10
    policy:
      - {src: external, dst: dmz, ports: [80, 443, 53]}       # Allow web + DNS to DMZ
      - {src: corporate_lan, dst: any}                          # Users can reach anything
      - {src: server_vlan, dst: external, ports: [80, 443, 53, 25]} # Servers: web, DNS, SMTP out
      - {src: app_vlan, dst: external, ports: [80, 443]}       # App servers: web out
      - {src: app_vlan, dst: server_vlan}                       # App → server (AD, file shares)
      - {src: server_vlan, dst: server_vlan}                    # Inter-server
      - {src: server_vlan, dst: app_vlan}                       # Server → app
      - {src: dmz, dst: app_vlan, ports: [8080, 8443]}         # DMZ web → internal app servers
      - {src: dmz, dst: database_vlan, ports: [3306, 5432]}    # DMZ → database (web app queries)
      - {src: app_vlan, dst: database_vlan, ports: [3306, 5432]} # App → database
      - {src: vpn_pool, dst: corporate_lan}                     # VPN users → workstations
      - {src: vpn_pool, dst: server_vlan}                       # VPN users → servers
  - fw-internal: firewall, TAP, monitors database_vlan + management_vlan, bidirectional,
    log_formats: [cisco_asa], interfaces: {database_vlan: db-zone, management_vlan: mgmt-zone},
    default_action: deny, deny_ratio: 3.0, policy:
      - {src: app_vlan, dst: database_vlan, ports: [3306, 5432]}
      - {src: dmz, dst: database_vlan, ports: [3306, 5432]}
      - {src: management_vlan, dst: any}                        # Mgmt can reach everything
      - {src: any, dst: management_vlan, ports: [9997, 514]}   # Syslog/Splunk forwarding

  Note: database_vlan has NO sensor — intentional blind spot for analyst training (attacker activity
  in the database segment is only visible via host-level logs, not network).

  Users: 55 users spanning all 15 built-in personas. Realistic diverse names (first.last format).
  Each user has a dedicated primary_system workstation (1:1 mapping), except for IT helpdesk staff
  (sysadmin persona) who share 2-3 workstations to represent shift coverage. Ensure at least 5 users
  are designated as remote/VPN users whose primary_system is a workstation but who also generate VPN
  logon activity.

  Service accounts (8): svc_backup, svc_monitor, svc_sqlreader, svc_exchange, svc_sccm, svc_wsus,
  svc_jenkins, svc_replication.

  Stale accounts (5):
  - jennifer.walsh: last_active 2023-11-15, reason "Transferred to London office"
  - svc_legacy_crm: last_active 2024-01-02, reason "CRM system decommissioned"
  - robert.kim: last_active 2023-09-30, reason "Former contractor, access not revoked"
  - maria.santos: last_active 2024-01-20, reason "Maternity leave, account not disabled"
  - svc_old_monitoring: last_active 2023-08-01, reason "Replaced by new monitoring stack"

  Red herrings (6-8 explicit events, in addition to automatic suspicious_noise):
  - After-hours IT maintenance: sysadmin RDP to DC-01 at 2am Tuesday, running legitimate diagnostic
    commands (Get-EventLog, Test-Connection, dcdiag). Should look suspicious but has innocent explanation.
  - Failed logon burst from a legitimate user who fat-fingered their password 4-5 times before
    succeeding Monday morning. Should trigger lockout-style alerts but is benign.
  - Large outbound file transfer from a developer workstation to a cloud storage IP — actually a
    legitimate repo mirror sync, but the volume (~500MB) looks like exfiltration.
  - Service account (svc_backup) authenticating from an unusual host (not its normal server) —
    legitimate scheduled task migration to new backup infrastructure.
  - Security team vulnerability scan from WS-SEC-01 hitting multiple servers on unusual ports —
    legitimate quarterly scan, but overlaps in timing with the real attack's reconnaissance.
  - Developer running PowerShell with -EncodedCommand flag for a legitimate build script — looks
    exactly like attacker tooling but is a normal CI/CD deployment step.
  - Unusual DNS queries from WS-DATA-02 to high-entropy subdomains — actually a data analytics
    tool querying CDN-backed APIs, not DNS tunneling.
  - After-hours SSH from APP-INT-01 to DB-PROD-01 — legitimate cron-triggered ETL job that runs at
    odd hours, but looks like lateral movement.

  All 9 log formats: windows, zeek, ecar, syslog, bash_history, snort_alert, cisco_asa, web_access, proxy_access.

  Attack storyline — Sophisticated APT with false starts, fumbling, and dead ends. Full kill chain
  with realistic attacker mistakes. The attacker is skilled but not omniscient — they make wrong turns,
  hit dead ends, and have to regroup. This produces a messier, more realistic attack timeline.

  IMPORTANT: The storyline should feel like a real intrusion where the attacker doesn't have a perfect
  map of the network. Include explicit failed attempts, wrong guesses, and abandoned paths.

  Phase 1: Initial Access and Fumbling (+2h to +6h, Monday morning)
  1. Rogue Device (+2h): Attacker plugs rogue laptop into corporate_lan, obtains IP via DHCP
     (dhcp_lease event with explicit MAC address).
  2a. External Port Scan (+2h10m): External attacker (185.70.41.45) scans the DMZ segment for services.
     Use port_scan event with target_segment: dmz, ports: [22, 80, 443, 8080, 8443, 3306, 5432],
     scan_rate: 200, target_count: 15. Produces ASA 106023 denies + Zeek S0/REJ conn entries on
     external-facing sensors only.
  2b. External HTTP Recon (+2h15m): Attacker probes WEB-EXT-01 with HTTP scanning
     (multiple 404s, directory traversal attempts that fail). These should be visible in web_access logs.
  3. Failed Exploit Attempt (+2h30m): Attacker tries known CVE against WEB-EXT-02 patient portal —
     fails (patched). Connection events + web_access showing 403/500 errors.
  4. Successful SQLi (+3h): Attacker pivots to WEB-EXT-01 EHR portal, finds SQL injection.
     Multiple probing requests before successful exploitation.
  5. Web Shell Upload (+3h20m): Upload web shell, test execution. Reverse shell to C2 at
     45.33.32.30:8443. Use real base64-encoded payload.
  6. Initial Discovery (+3h40m–4h): Network enumeration from WEB-EXT-01 — ip addr, /etc/hosts,
     /etc/resolv.conf, ping sweep of nearby subnets. Attacker discovers DMZ topology.
  7. Dead End (+4h15m): Attacker tries to SSH to PROXY-01 — connection refused (SSH disabled on proxy).
     Tries PROXY-02 — also fails. Visible as failed TCP connections.
  8. Credential Harvesting (+4h30m): Read web app config files on WEB-EXT-01, find DB credentials
     and an SSH key for APP-INT-01.
  9. Lateral to App Server (+5h): SSH from WEB-EXT-01 to APP-INT-01 using stolen key.
  10. Failed Lateral (+5h15m): Attacker tries SSH to DB-PROD-01 from APP-INT-01 — wrong key,
      authentication fails. Tries again with password from config — also fails (different password
      for DB host). Two failed_logon events.

  Phase 2: Deeper Penetration and Credential Theft (+8h to +16h, Monday afternoon–evening)
  11. Credential Dump on App Server (+8h): Dump /etc/shadow and /etc/passwd on APP-INT-01.
      Crack a weak password for a developer account (use a developer username from the user list).
  12. Password Spray — Mostly Fails (+8h30m): Attempt password spray against 5 workstations using
      the cracked developer password. 4 fail (failed_logon events), 1 succeeds on WS-DEV-02.
  13. Discovery on Workstation (+9h): AD enumeration from WS-DEV-02 — whoami /all, net user /domain,
      net group "Domain Admins", LDAP query to DC-01, net view file shares.
  14. Wrong Turn (+9h30m): Attacker RDPs to WS-FIN-01 using compromised dev account — discovers it's
      a finance workstation with no useful admin tools. Browses around, finds nothing useful, disconnects.
      Visible as RDP session + a few process events + logoff.
  15. Mimikatz Attempt — Insufficient Privileges (+10h): Attacker runs mimikatz (disguised as
      ms-index-service.exe) on WS-DEV-02 under the compromised developer account. Process starts
      but fails to open lsass.exe — access denied because the developer account lacks
      SeDebugPrivilege. Process create + quick terminate (< 5 seconds). Attacker realizes they
      need elevated credentials.
  16. Mimikatz with Domain Admin (+10h30m): Attacker uses stolen domain admin credentials from the
      password spray to spawn an elevated process (runas /user:DOMAIN\admin_account). Re-runs
      mimikatz as ms-index-service.exe — succeeds: process_access (0x1FFFFF) and
      create_remote_thread targeting lsass.exe. Dumps additional credentials.
  17. C2 Check-in (+11h): HTTPS beacon from WS-DEV-02 to second C2 at 45.33.32.31:443.
      Attacker now has two C2 channels (WEB-EXT-01 and WS-DEV-02).

  Phase 3: Domain Compromise (+18h to +28h, Tuesday morning)
  18. Lateral to DC — Wrong DC (+18h): Attacker tries PsExec to DC-02 first (secondary DC) — gets
      access but realizes it's the secondary with limited tools. Runs a few recon commands, then pivots.
  19. Lateral to Primary DC (+18h30m): PsExec from DC-02 to DC-01 via SMB. Full domain admin access.
  20. Privilege Escalation (+19h): Create backdoor account svc_healthcheck, add to Domain Admins
      (account_created + group_member_added events).
  21. Persistence on DC (+19h15m): Install service "HealthMonitorSvc" (svchost_helper.exe) and create
      scheduled task "\Microsoft\Windows\Maintenance\SystemHealthCheck" on DC-01.
  22. AD Reconnaissance (+19h30m): Deep AD enumeration — enumerate all OUs, GPOs, trust relationships,
      service accounts. Multiple LDAP queries to DC-01.
  22b. Lateral Scan (+19h45m): From DC-01, attacker scans the database_vlan through the internal
      firewall (fw-internal) looking for database servers. Use port_scan with target_segment:
      database_vlan, ports: [3306, 5432, 1433, 27017], scan_rate: 30. Most will be denied by
      fw-internal policy (only app_vlan and dmz can reach database_vlan).
  23. Failed Exfil Path (+20h): Attacker tries to exfiltrate directly from DC-01 to C2 — blocked by
      firewall (DC can't reach external IPs). Use connection event with conn_state: REJ and
      firewall context (existing capability). Attacker must find another path.
  23b. Blocked C2 from DC (+20h): Malware installed on DC-01 attempts to beacon to second C2 at
      45.33.32.31:443 every 45 minutes. Use blocked_c2 with interval: "45m", duration: "24h",
      jitter: 0.15. Denied by fw-external policy (server_vlan can't reach external on 443).
      Visible to internal sensors only.
  24. Pivot Through Proxy (+20h30m): Attacker discovers PROXY-01 can reach external. Attempts to
      configure a SOCKS proxy but fails (no tools). Abandons this approach.
  25. C2 via WEB-EXT-01 (+21h): Attacker establishes C2 relay: DC-01 → APP-INT-01 → WEB-EXT-01 → C2.
      Multiple connection events showing the relay chain.

  Phase 4: Collection and Exfiltration (+30h to +48h, Tuesday afternoon–Wednesday)
  26. File Server Access (+30h): Authenticate to FILE-SRV-01 with backdoor account, enumerate shares.
      Browse patient records, financial data, board meeting minutes.
  27. Staging (+31h): Copy sensitive files to a staging directory on APP-INT-01. PowerShell
      Compress-Archive to create encrypted zip.
  28. Database Access — Wrong DB (+32h): SSH to DB-AUX-01 (PostgreSQL) — attacker expected patient data
      but finds only ticketing system data. Runs a few queries, realizes wrong database.
  29. Database Access — Correct DB (+33h): SSH to DB-PROD-01, mysqldump patient and insurance tables.
      gzip and SCP back to APP-INT-01.
  30. Second File Server (+34h): Access FILE-SRV-02 for departmental data. Additional staging.
  31. Email Access (+35h): Authenticate to EXCH-01, search mailboxes of executives and legal team
      for M&A related keywords. Export selected emails.
  32. Exfiltration — Slow (+36h to +42h): Staged exfiltration over 6 hours via HTTPS through
      WEB-EXT-01 to cdn-assets-update.com (45.33.32.30). Multiple small uploads to avoid
      bandwidth alerts. Each upload is a separate connection event.

  Phase 5: Cleanup and Persistence (+44h to +50h, Wednesday morning)
  33. Additional Persistence (+44h): Create second scheduled task on DC-02 as backup persistence.
      Also install service on FILE-SRV-01.
  34. Defense Evasion — Linux (+45h): Clear bash history on WEB-EXT-01 and APP-INT-01. Remove web
      shell access logs from WEB-EXT-01's local logs.
  35. Defense Evasion — Windows (+46h): Encoded PowerShell download (real UTF-16LE base64) of cleanup
      script. Clear Security event log on DC-01 (explicit log_cleared event). Attempt to clear DC-02
      log — partially succeeds.
  36. Backdoor Account Cleanup (+47h): Delete the svc_healthcheck account's Domain Admins membership
      but keep the account (account still exists, just demoted — harder to detect).
  37. Ongoing C2 (+24h, +36h, +48h, +60h, +72h): Periodic beacons from WEB-EXT-01 and DC-01
      throughout the 72-hour window. Varying intervals (30min–4h) to avoid pattern detection.

  Key requirements:
  - Exercise all 17 typed event types: process, logon, failed_logon, logoff (baseline), connection,
    ssh_session, rdp_session, account_created, account_deleted, group_member_added, service_installed,
    scheduled_task_created, log_cleared, create_remote_thread, dhcp_lease, port_scan, blocked_c2, raw
  - NOTE: process_access is NOT a scenario event type — it is auto-generated by create_remote_thread
    targeting lsass.exe via the causal expansion engine. Do not declare it in the YAML.
  - Use connection events with HTTP fields (method, uri, status_code, user_agent) for web access log
    entries showing the SQLi, web shell access, and failed exploit attempts — NOT raw events
  - All base64 payloads must be real (generated via Bash tool)
  - Attacker naming must be realistic (no "evil", "malware", "attacker" names)
  - External IPs from realistic public ranges (NOT RFC 5737 documentation ranges)
  - Baseline activity: high intensity, high variation (more users = more noise to hide in)

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
  - FLOW records carry realistic system process PIDs
  - Storyline connection events carry the attack process pid (from _last_storyline_pid)
  - Mix of Ubuntu, CentOS, and RHEL exercises distro-aware process tree seeding

  Sysmon coverage (verify in generated data):
  - Event 1 (ProcessCreate): baseline + storyline process events
  - Event 5 (ProcessTerminate): baseline process terminations plus storyline with realistic delays
  - Event 8 (CreateRemoteThread): baseline benign pairs plus storyline mimikatz
  - Event 10 (ProcessAccess): baseline benign pairs plus storyline mimikatz on lsass
  - Baseline Event 8/10 noise ensures storyline attack events are not instant red flags

  Cisco ASA firewall coverage (verify in generated data):
  - Two firewall sensors: fw-external (perimeter, high deny_ratio=8.0) and fw-internal (database/mgmt
    zone, lower deny_ratio=3.0) — exercises multi-firewall scenarios with different policies
  - Built/Teardown pairs (302013/302014) for permitted TCP connections through both firewalls
  - Built/Teardown pairs (302015/302016) for permitted UDP connections (DNS, NTP)
  - Deny records (106023) for blocked traffic: external scanning against internal hosts, blocked
    cross-zone database access attempts, unauthorized management zone access
  - Correct interface resolution per firewall: fw-external uses inside/dmz/outside; fw-internal
    uses db-zone/mgmt-zone/outside
  - Deny baseline proportional to deny_ratio: ~8x for external firewall, ~3x for internal
  - Policy enforcement: external → corporate_lan denied, external → dmz:80/443 allowed,
    app_vlan → database_vlan:3306 allowed, corporate_lan → database_vlan denied
  - Storyline step 23 (failed exfil from DC-01) should produce a firewall deny record since
    DC → external is not in fw-external's policy
  - Attack lateral movement through allowed paths (dmz → app_vlan, app_vlan → database_vlan)
    produces ASA allow records correlated with Zeek conn records
  - 305011 (Built NAT translation) present when nat_rules configured on fw-external
  - 305012 (Teardown NAT translation) present
  - Built messages show mapped IPs in parentheses that differ from real IPs
  - Outside Zeek sensors show post-NAT source IPs; inside sensors show real IPs

  Data Realism coverage (verify in generated data):
  - Causal expansion: DNS queries precede TCP connections; Kerberos precede domain logons;
    process_access follows create_remote_thread targeting lsass
  - Hawkes temporal model: user events show bursty clusters (CV > 1.0), not uniform spacing
  - Typing cadence: multi-event storyline steps have 1-15 second gaps between events
  - Day-of-week variation: 3-day span exercises full weekday patterns
  - Lateral movement: backup/monitoring/AD replication/mail routing between servers
  - Process→network correlation: baseline processes produce matching connections
  - Stale account enrichment: Kerberos failures, failed batch/service logons
  - Network red herrings: suspicious DNS, unusual outbound, scan overlap
  - Linux syslog depth: SSH login messages, package management, systemd timers, logrotate, journald
  - Command diversification: user-specific paths and varied project/document names
  - Entity lifecycle: no process_access targeting nonexistent PIDs

  Save to scenarios/apt-healthcare-breach-large/scenario.yaml with accompanying ENVIRONMENT.md.

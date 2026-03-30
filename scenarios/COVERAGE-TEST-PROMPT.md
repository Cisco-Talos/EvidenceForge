  Create an EvidenceForge scenario for a comprehensive feature coverage test. Use these requirements:

  Environment: Meridian Healthcare Solutions, a mid-size healthcare IT company (~120 employees) providing
   EHR integration services. Corporate HQ with on-premises data center.

  Duration: 14 hours, starting 2024-03-18T12:00:00Z. Timezone: America/Chicago.

  Systems (mix of Windows and Linux, ~20 total):
  - 13 Windows workstations (Windows 10/11) across departments: dev, IT, security, finance, data
  analytics, executive, PM, HR, sales, legal, marketing, front desk
  - 2 Windows servers: DC-01 (domain controller, Server 2022), FILE-SRV-01 (file server, Server 2019)
  - 5 Linux servers: WEB-EXT-01 (Ubuntu, web server in DMZ with roles: [web_server]), PROXY-01 (Ubuntu,
  roles: [forward_proxy]), APP-INT-01 (Ubuntu, internal app server), DB-PROD-01 (CentOS, MySQL),
  LOG-SRV-01 (Ubuntu, syslog/Elasticsearch)

  Network (4 segments):
  - corporate_lan (10.10.1.0/24) — workstations
  - server_vlan (10.10.2.0/24) — DC, file server, app server, log server
  - dmz (10.10.3.0/24, exposure: both) — web server, proxy
  - database_vlan (10.10.4.0/24) — MySQL (intentionally no sensor — blind spot)

  Sensors:
  - zeek-core: SPAN, monitors corporate_lan + server_vlan, bidirectional
  - zeek-dmz: SPAN, monitors server_vlan + dmz, bidirectional (overlaps with zeek-core on server_vlan)
  - snort-perimeter: TAP, monitors dmz, inbound

  Users: 17 users spanning all 15 built-in personas. Realistic diverse names (first.last format). Service
   accounts: svc_backup, svc_monitor, svc_sqlreader.

  All 8 log formats: windows, zeek, ecar, syslog, bash_history, snort_alert, web_access, proxy_access.

  Attack storyline — APT via web app exploit, full kill chain:
  1. Rogue Device (+0h45m): Attacker plugs rogue laptop into network, obtains IP via DHCP
  (dhcp_lease event with explicit MAC address). Actor: attacker on rogue device.
  2. Initial Access (+1h): External attacker (203.0.113.45) scans and exploits SQL injection on
  WEB-EXT-01's EHR portal. Actor: root.
  2. Execution (+1h20m): Web shell upload, reverse shell to C2 at 198.51.100.30:8443. Use real
  base64-encoded reverse shell payload.
  3. Discovery (+1h40m–2h): Network enumeration from WEB-EXT-01 — ip addr, /etc/hosts, nmap ping sweep
  and port scan of server_vlan.
  4. Credential Access (+2h15m): Harvest DB credentials from web app config files and SSH keys.
  5. Lateral Movement (+2h30m): SSH from WEB-EXT-01 to APP-INT-01 using stolen key.
  6. Credential Access (+2h50m): Dump /etc/shadow and /etc/passwd on APP-INT-01.
  7. Lateral Movement (+3h30m): Password spray (failed_logon x2) then successful RDP to WS-DEV-01 using
  compromised sysadmin account (sarah.oconnell).
  8. Discovery (+3h50m): AD enumeration — whoami /all, net user /domain, net group "Domain Admins", LDAP
  query to DC, net view file shares.
  9. Credential Access (+4h30m): Mimikatz (disguised as ms-index-service.exe) with process_access
  (granted_access: "0x1FFFFF") and create_remote_thread targeting lsass.exe.
  10. Lateral Movement (+5h): PsExec to DC-01 via SMB.
  11. Privilege Escalation (+5h15m): Create backdoor account svc_sqlreader, add to Domain Admins (with
  explicit account_created and group_member_added events).
  12. Persistence (+5h30m): Install service "HealthMonitorSvc" (svchost_helper.exe) and create scheduled
  task "\Microsoft\Windows\Maintenance\SystemHealthCheck" on DC-01.
  13. C2 (+5h45m): HTTPS beacon from DC-01 to 198.51.100.30:443.
  14. Collection (+6h30m): Authenticate to FILE-SRV-01 with backdoor account, stage financial and patient
   data, compress with PowerShell.
  15. Exfiltration (+7h15m): Upload archive to cdn-assets-update.com (198.51.100.30) over HTTPS.
  16. Database Access (+8h): SSH to DB-PROD-01, mysqldump patient/insurance tables, gzip and SCP back to
  APP-INT-01.
  17. Defense Evasion (+9h): Clear bash history on Linux, encoded PowerShell download (real UTF-16LE
  base64), clear Security event log on DC-01 (with explicit log_cleared event).
  18. Ongoing C2 (+10h, +12h): Periodic beacons from WEB-EXT-01 and DC-01.

  Key requirements:
  - Exercise all 16 typed event types: process, logon, failed_logon, logoff (baseline), connection,
  ssh_session, rdp_session, account_created, group_member_added, service_installed,
  scheduled_task_created, log_cleared, create_remote_thread, process_access, dhcp_lease, raw
  - Use connection events with HTTP fields (method, uri, status_code, user_agent) for web access log entries showing the SQLi and web shell access — NOT raw events
  - All base64 payloads must be real (generated via Bash tool)
  - Attacker naming must be realistic (no "evil", "malware", "attacker" names)
  - External IPs from RFC 5737 ranges
  - Baseline activity: medium intensity, medium variation

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
    - Windows DNS → svchost NetworkService pid
    - Windows NTP → svchost LocalService pid
    - Windows SMB → System PID 4
    - Windows Kerberos/LDAP → lsass pid
    - Windows RDP outbound → mstsc.exe pid
    - Ubuntu DNS → systemd-resolved pid
    - CentOS DNS → pid -1 (apps resolve directly)
    - Ubuntu NTP → systemd-timesyncd pid
    - CentOS NTP → chronyd pid
  - Storyline connection events carry the attack process pid (from _last_storyline_pid)
  - The mix of Ubuntu (WEB-EXT-01, PROXY-01, APP-INT-01, LOG-SRV-01) and CentOS (DB-PROD-01)
    exercises distro-aware process tree seeding

  Sysmon coverage (verify in generated data):
  - Event 1 (ProcessCreate): baseline + storyline process events
  - Event 5 (ProcessTerminate): baseline process terminations for Windows hosts plus storyline
    process terminations with realistic delays (recon: 0.3-5s, attack tools: 5-30s, persistent/C2: no termination)
  - Event 8 (CreateRemoteThread): baseline benign pairs (MsMpEng→explorer, csrss→svchost, etc.)
    plus storyline mimikatz create_remote_thread targeting lsass
  - Event 10 (ProcessAccess): baseline benign pairs (MsMpEng→lsass with 0x1410, services→svchost
    with 0x1000, etc.) plus storyline mimikatz process_access on lsass with 0x1FFFFF
  - Baseline Event 8/10 noise ensures storyline attack events are not instant red flags

  Save to scenarios/apt-healthcare-breach/scenario.yaml with accompanying ENVIRONMENT.md.
  Create an EvidenceForge scenario for a focused iteration-test, optimized for fast
  generate-evaluate-fix cycles while maintaining full event type and format group coverage.
  The goal is to cut volume (users, hosts, duration, baseline intensity, deny_ratio) without
  dropping any event types or format groups — variety is preserved, scale is not.

  Environment: Meridian Healthcare Solutions, a mid-size healthcare IT company (~60 employees)
  providing EHR integration services. Corporate HQ with on-premises data center.

  Duration: 6 hours, starting 2024-03-18T12:00:00Z. Timezone: America/Chicago.
  warmup: "2h" (minimum viable to pre-populate DNS cache, process trees, and sessions —
  cold-start artifacts are immediately visible to forensic reviewers).
  logon_grace_period: "30m"

  Systems (mix of Windows and Linux, ~15 total):
  - 8 workstations, one per user (1:1 mapping — create one workstation per user):
    - 2 Linux desktops (Ubuntu 22.04, type: workstation): developer and data_analyst personas
    - 6 Windows 10/11 workstations: remaining 6 users
  - 2 Windows servers: DC-01 (domain controller, Server 2022), FILE-SRV-01 (file server, Server 2019)
  - 4 Linux servers: WEB-EXT-01 (Ubuntu, web server in DMZ, roles: [web_server],
    public_hostnames: ["ehr-portal.meridianhcs.com"]), PROXY-01 (Ubuntu, roles: [forward_proxy]),
    APP-INT-01 (Ubuntu, internal app server), DB-PROD-01 (CentOS, MySQL)

  Network (4 segments):
  - corporate_lan (10.10.1.0/24) — workstations, exposure: internal
  - server_vlan (10.10.2.0/24) — DC, file server, app server, exposure: internal
  - dmz (10.10.3.0/24, exposure: both, external_ratio: 0.6) — web server, proxy
  - database_vlan (10.10.4.0/24, exposure: internal) — MySQL (intentionally no sensor — blind spot)

  public_cidrs: ["203.14.220.0/28"] at network level — the org's own public address block.

  Sensors:
  - zeek-core: SPAN, monitors corporate_lan + server_vlan, bidirectional
  - zeek-dmz: SPAN, monitors dmz, bidirectional
  - snort-perimeter: TAP, monitors dmz, inbound
  - fw-perimeter: firewall, TAP, monitors corporate_lan + server_vlan + dmz, bidirectional,
    log_formats: [cisco_asa], interfaces: {corporate_lan: inside, server_vlan: inside, dmz: dmz},
    default_action: deny, deny_ratio: 2.0, drop_mode: drop, threat_detection_rate: 10,
    nat_rules:
      - type: dynamic_pat
        src: [corporate_lan, server_vlan]
        mapped_ip: 45.33.32.1
      - type: static
        src: dmz
        real_ip: 10.10.3.10 (WEB-EXT-01)
        mapped_ip: 45.33.32.10
    policy:
      - {src: external, dst: dmz, ports: [80, 443]}
      - {src: corporate_lan, dst: any}
      - {src: server_vlan, dst: external, ports: [80, 443, 53]}
      - {src: server_vlan, dst: server_vlan}
      - {src: dmz, dst: server_vlan, ports: [3306]}

  Users: 8 users spanning these personas: developer, data_analyst, sysadmin, security_analyst,
  executive, accountant, help_desk, sales. Realistic diverse names (first.last format).
  At least 1 user with browsing_intensity: heavy, 1 with browsing_intensity: light.
  Service accounts: svc_backup, svc_monitor.

  Stale accounts (1):
  - jennifer.walsh: last_active 2023-11-15, reason "Transferred to London office"
  (Produces Kerberos 4771/0x12 failures and failed batch/service logons — expected background
  noise in any real AD environment.)

  Red herrings (2, in addition to automatic suspicious_noise). Each MUST include an `explanation`
  field describing why the activity is benign:
  - Failed logon burst: a legitimate user fat-fingers their password 3-4 times before succeeding.
    Looks like a lockout-pattern alert but is benign.
  - After-hours IT maintenance: sysadmin RDP to DC-01 at an unusual hour, running legitimate
    diagnostic commands (Get-EventLog, Test-Connection). Looks suspicious, has innocent explanation.

  All 9 log format groups: windows, zeek, ecar, syslog, bash_history, snort_alert, cisco_asa,
  web_access, proxy_access.
  (Note: "windows" expands to windows_event_security + windows_event_sysmon; "zeek" expands to
  zeek_conn, zeek_dns, zeek_http, zeek_ssl, zeek_files, zeek_dhcp, zeek_ntp, zeek_weird,
  zeek_x509, zeek_ocsp, zeek_pe, zeek_packet_filter, zeek_reporter.)

  Baseline: intensity: low, variation: medium, suspicious_noise: medium.
  Keep suspicious_noise at medium — high-entropy CDN subdomains, unusual outbound patterns,
  and scan overlap noise are specifically evaluated by human reviewers for realism.

  Attack storyline — APT via web app exploit, compressed kill chain:

  Attacker realism: Include 2-3 fumbles interspersed naturally within the phases below.
  Suggested fumbles:
  - Failed SSH to PROXY-01 (connection refused) before pivoting to APP-INT-01
  - One failed_logon with wrong password before the correct lateral movement credential
  - A find/ls command that returns nothing useful, followed by a retry with different path
  Do NOT put fumbles in a separate section — weave them into the existing steps so the
  timeline looks organic.

  1. Port Scan (+0h30m): External attacker scans the DMZ segment for services.
     Use a `port_scan` event with `source_ip: "185.70.41.45"`, `target_segment: dmz`,
     `ports: [22, 80, 443, 8080, 8443, 3306]`, and `scan_rate: 50`. Do not use
     `src_ip`. Produces ASA 106023 denies + Zeek S0 conn entries on external-facing
     sensors only (not internal sensors).

  2. Web Scan (+0h30m): External attacker runs web vulnerability scanning against WEB-EXT-01.
     Use a `web_scan` event with `source_ip: "185.70.41.45"`, `dst_ip: "10.10.3.10"`,
     `dst_port: 443`, `hostname: "ehr-portal.meridianhcs.com"`, `preset: nikto`,
     `rate: 10`, and exactly one termination field: `duration: "20m"`. Do not use
     `src_ip`. Run concurrently with the port scan. Expect 733100 threat-detection
     alerts during this phase.

  3. Rogue Device (+0h45m): Attacker plugs rogue laptop into network, obtains IP via DHCP.
     Use a `dhcp_lease` event on the parent storyline `system` for the rogue device.
     Inside the `dhcp_lease` event, use only `mac_address` and optionally `requested_ip`;
     do not include `hostname` because DHCP hostname is derived from parent `system`.
     Use a realistic MAC address with a known vendor OUI prefix (e.g., DC:A6:32 for
     Raspberry Pi, 00:50:56 for VMware). Do NOT use sequential/placeholder MACs like
     00:1A:2B:3C:4D:5E.

  4. Initial Access (+1h): External attacker (185.70.41.45) scans and exploits SQL injection on
     WEB-EXT-01's EHR portal. Use connection events with HTTP fields (method: POST, uri with SQLi
     payload, status_code: 500, user_agent, hostname: "ehr-portal.meridianhcs.com"). Actor: root.

  5. Execution (+1h20m): Web shell upload and reverse shell to C2 at 45.33.32.30:8443. Include:
     - connection event with HTTP fields showing the web shell upload (method: POST, status_code: 200)
     - process event for the reverse shell execution with a real base64-encoded reverse shell payload
       (generate via Bash tool)
     - raw event for a raw Apache error log entry triggered by the exploit attempt (exercises the
       raw event type — use a realistic Apache error format line)
     Actor: apache on WEB-EXT-01.

  6. Discovery (+1h40m): Network enumeration from WEB-EXT-01 — ip addr, cat /etc/hosts,
     cat /etc/resolv.conf, nmap ping sweep and port scan of server_vlan. Multiple process events
     with bash_history entries. Use typing cadence (1-15 second gaps between commands, not
     identical timestamps). Actor: root on WEB-EXT-01.

  7. Credential Access (+2h): Harvest DB credentials from web app config files and SSH keys.
     Process events reading /var/www/html/config.php and ~/.ssh/id_rsa. Actor: root on WEB-EXT-01.

  8. Lateral Movement (+2h15m): SSH from WEB-EXT-01 to APP-INT-01 using stolen SSH key
     (ssh_session event). Actor: root. Note: weave in the PROXY-01 fumble here or just before —
     failed TCP connection to PROXY-01, then successful ssh_session to APP-INT-01.

  9. Credential Access (+2h35m): Dump /etc/shadow and /etc/passwd on APP-INT-01.
     Process events with bash_history entries. Actor: root on APP-INT-01.

  10. Explicit Credentials (+2h50m): Attacker uses RunAs with compromised sysadmin account
      (explicit_credentials event with target_username, target_server, process_name).

  11. Credential Spray (+3h): credential_spray event with pattern: spray, target_accounts:
      [2-3 accounts from the 8 users], success: {account: one of the users, after: 3},
      interval: "5s", count: 10. Then successful RDP session (rdp_session) to that user's
      workstation. Weave in the wrong-password fumble: one failed_logon before the spray.
      Actor: attacker on rogue device / compromised host.

  12. Discovery (+3h20m): AD enumeration from the compromised workstation — whoami /all,
      net user /domain, net group "Domain Admins", net view. Include dns_query events for
      DC hostname lookups. Include LDAP connection to DC-01 (connection event).
      Use typing cadence between commands.

  13. Mimikatz (+3h45m): Mimikatz disguised as ms-index-service.exe with create_remote_thread
      targeting lsass.exe (auto-generates correlated process_access with 0x1FFFFF).
      Do NOT manually declare a second process_access on lsass in the same step — the causal
      expansion engine generates it automatically from create_remote_thread.

  14. Lateral Movement (+4h): PsExec to DC-01 via SMB. Model correctly:
      logon (type 3 from source workstation) + service_installed (service_name: "PSEXESVC",
      service_file_name: "%SystemRoot%\PSEXESVC.exe") + process events for commands run under
      the service. Do NOT use "cmd.exe /c PSEXESVC.exe" — that produces the wrong parent chain.

  15. Privilege Escalation (+4h15m): Create backdoor account svc_mhsync (account_created event),
      add to Domain Admins (group_member_added event). Actor: SYSTEM on DC-01.

  16. Persistence (+4h20m): Install service "DeviceSyncSvc" (service_installed event with
      service_name, service_file_name, service_account) and create scheduled task
      "\Microsoft\Windows\Maintenance\DeviceSync" (scheduled_task_created event) on DC-01.

  17. C2 Beaconing (+4h30m): HTTPS beacon from DC-01 to 45.33.32.30:443 (beacon event with
      interval: "10m", duration: "1h30m", jitter: 0.3, hostname, user_agent, method: GET,
      orig_bytes/resp_bytes for realistic sizing).

  18. Blocked C2 (+4h30m): Attacker malware on DC-01 also attempts to beacon directly to
      45.33.32.30:443 — blocked by firewall (server_vlan → external not in policy). Use beacon
      event with action: deny, interval: "30m", duration: "1h30m". Denied attempts visible to
      internal sensors only.

  19. DNS Tunneling (+4h45m): Exfiltrate data via DNS tunnel from APP-INT-01 (dns_tunnel event
      with base_domain: "ns1.westbridge-services.net", encoding: hex, qtype: TXT, interval: "2s",
      duration: "15m", payload_size: 512).

  20. DGA Activity (+5h): DGA queries from WEB-EXT-01 (dga_queries event with tld: ".net",
      length_range: [10, 18], interval: "30s", duration: "45m",
      rcode_distribution for mostly NXDOMAIN).

  21. Collection (+5h): Authenticate to FILE-SRV-01 with backdoor account svc_mhsync
      (logon event, type 3), enumerate shares, stage financial and patient data, compress
      with PowerShell Compress-Archive.

  22. Database Access (+5h15m): SSH to DB-PROD-01 (ssh_session), mysqldump patient and insurance
      tables, gzip and SCP back to APP-INT-01.

  23. Workstation Lock (+5h20m): Attacker locks the compromised workstation before stepping away
      (workstation_lock event) — exercises EventID 4800.

  24. Exfiltration (+5h25m): Upload archive to api.westbridge-services.net (45.33.32.30) over HTTPS
      (connection event with HTTP fields, method: POST, large orig_bytes — use a physically
      plausible value in the 100-500 MB range, NOT multi-GB).

  25. Workstation Unlock (+5h35m): Attacker returns, unlocks workstation (workstation_unlock
      event) — exercises EventID 4801.

  26. Defense Evasion (+5h40m): Clear bash history on Linux hosts (process), encoded PowerShell
      download (real UTF-16LE base64, generate via Bash tool), clear Security event log on DC-01
      (log_cleared event).

  27. DNS Queries (+5h45m): Standalone DNS queries for attacker infrastructure (dns_query events
      with query, qtype, rcode, answer fields).

  28. Ongoing C2 (+5h, +5h30m): Periodic beacons from WEB-EXT-01 to 45.33.32.30:443
      (separate beacon events).

  29. Account Cleanup (+5h50m): Delete the backdoor account svc_mhsync (account_deleted event
      with target_username: svc_mhsync).

  30. Logoff (+5h55m): Attacker logs off from compromised systems (logoff events).

  Key requirements:
  - Exercise all 27 storyline event types: process, logon, failed_logon, logoff, connection,
    ssh_session, rdp_session, account_created, account_deleted, group_member_added,
    service_installed, scheduled_task_created, log_cleared, create_remote_thread, process_access,
    dhcp_lease, port_scan, beacon, dns_query, web_scan, credential_spray, dga_queries,
    dns_tunnel, explicit_credentials, workstation_lock, workstation_unlock, raw
  - NOTE: process_access IS a valid scenario event type and can be declared directly (e.g., for
    a standalone Sysmon Event 10). However, when create_remote_thread targets lsass.exe, the
    causal expansion engine auto-generates a correlated process_access — do NOT manually declare
    a second process_access on lsass in the same step or you'll get duplicate events.
  - NOTE: "c2" is NOT a valid event type — use "beacon" for C2 communication
  - Use connection events with HTTP fields (method, uri, status_code, user_agent, hostname) for
    web access log entries — NOT raw events
  - Periodic events (beacon, web_scan, credential_spray, dga_queries, dns_tunnel) must each
    specify exactly one of: end_time, duration, or count — plus interval (or rate for web_scan)
  - Typed event fields are strict. Use `source_ip`, never `src_ip`. Do not add `hostname`
    to `dhcp_lease`; DHCP hostname comes from the parent storyline `system`.
  - All base64 payloads must be real (generated via Bash tool)
  - Attacker naming must be realistic (no "evil", "malware", "attacker" names)
  - External IPs from realistic public ranges (NOT RFC 5737 documentation ranges). Keep org
    public IPs (203.14.x.x) separate from attacker IPs (45.33.32.x, 185.70.41.x). Do NOT
    use 45.33.32.1 (scanme.nmap.org).
  - Include technique (MITRE ATT&CK ID) and description fields on all storyline events

  Engine behavior expectations:
  - C2 connections to raw IPs (45.33.32.30) will NOT have DNS queries — realistic for direct-IP C2
  - DNS queries for baseline web traffic use domain-first selection — SNI, DNS, and proxy
    hostname will be consistent
  - DHCP events are routed to sensors by segment visibility (not duplicated across all sensors)
  - Windows service account events (SYSTEM, NETWORK SERVICE) show "NT AUTHORITY" as SubjectDomainName
  - 4648 (explicit credentials) fires in baseline for scheduled task execution (2-5/hour) plus
    storyline lateral movement — do not expect 4648 to appear only on the attack path
  - DCs receive admin-only baseline: type 3 logons from RSAT sessions, type 10 RDP for direct
    admin access, no user desktop artifacts
  - RSAT sessions produce correlated cross-host events: mmc.exe + DLL loads on workstation,
    LDAP/RPC connections to DC, type 3 logon on DC — all within seconds
  - 4634 logoff pairs with 4624 on matching TargetLogonId
  - Certificate validity periods match issuer (Let's Encrypt = 90 days, DigiCert = 397 days)
  - PID 4 resolves to "System" in parent process lookups
  - NAT rules produce: dynamic PAT for outbound (mapped_src_ip + translated port), static NAT
    for WEB-EXT-01 VIP. Outside Zeek sensors see post-NAT IPs; inside sensors see real IPs
  - Firewall policy enforcement: external → corporate_lan denied, external → dmz:80/443 allowed
  - Stale SSH close / stale flow evidence is suppressed: teardown events only appear for sessions
    with a matching session-open event (no orphaned SSH disconnects)
  - drop_mode: drop produces conn_state S0 on denied traffic

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
    THREAD/REMOTE_CREATE actorID = source process objectID, properties include tgt_pid,
    tgt_pid_uuid, start_address, and stack addresses
  - FLOW records carry realistic system process PIDs (Windows DNS → svchost NetworkService;
    Ubuntu DNS → systemd-resolved; CentOS DNS → pid -1; Windows SMB → System PID 4)
  - Storyline connection events carry the attack process pid (from _last_storyline_pid)
  - Mix of Ubuntu (WEB-EXT-01, PROXY-01, APP-INT-01) and CentOS (DB-PROD-01) exercises
    distro-aware process tree seeding

  Sysmon coverage (verify in generated data):
  - Event 1 (ProcessCreate): baseline + storyline; ParentCommandLine from parent's actual
    command line; ParentImage reflects spawn_rules.yaml chains
  - Event 3 (NetworkConnect): outbound connections attributed to originating process
  - Event 5 (ProcessTerminate): paired 1:1 with Security 4689 + eCAR PROCESS/TERMINATE
  - Event 7 (ImageLoad): baseline DLL loads with signing status
  - Event 8 (CreateRemoteThread): baseline benign pairs (1-3/hr) plus storyline mimikatz
  - Event 10 (ProcessAccess): baseline benign pairs (3-8/hr) plus storyline mimikatz on lsass
  - Event 11/12/13: emitted for persistence steps (service install, scheduled task)
  - Event 22 (DNSQuery): DNS lookups from Windows processes
  - Baseline Event 8/10 noise ensures storyline attack events are not instant red flags
  - Sysmon/Security/eCAR for the same process chain are not bucketed at identical timestamps

  Cisco ASA firewall coverage (verify in generated data):
  - Built/Teardown pairs (302013/302014) for permitted TCP connections
  - Built/Teardown pairs (302015/302016) for permitted UDP connections (DNS, NTP)
  - Deny records (106023) for blocked traffic
  - 733100 threat-detection alerts during port_scan and web_scan phases (burst exceeds
    threat_detection_rate of 10 drops/sec). Verify rate_id, current_burst, max_burst,
    total_count fields present.
  - Correct interface resolution: internal IPs → "inside", DMZ IPs → "dmz", external → "outside"
  - 305011 (Built NAT translation) and 305012 (Teardown NAT translation) present
  - Built messages show mapped IPs in parentheses differing from real IPs
  - Outside Zeek sensors show post-NAT source IPs; inside sensors show real IPs
  - External baseline scans target org's public_cidrs (203.14.220.0/28), not attacker IPs

  Data Realism coverage (verify in generated data):
  - Causal expansion: DNS queries precede TCP connections; Kerberos 4768/4769 precede 4624
    domain logons; process_access follows create_remote_thread targeting lsass
  - Hawkes temporal model: user events show bursty clusters (CV > 1.0), not uniform spacing
  - Typing cadence: multi-event storyline steps have 1-15 second gaps, not identical timestamps
  - Process→network correlation: chrome.exe/git/sqlcmd baseline processes produce matching connections
  - Stale account enrichment: Kerberos 4771 (0x12) failures plus failed batch and service logons
  - Network red herrings: suspicious-but-benign DNS (high-entropy CDN subdomains), unusual
    outbound (cloud backup sync), scan overlap patterns
  - Linux syslog depth: SSH "Accepted publickey/password" messages, apt-daily package management,
    systemd timer trigger/deactivate, logrotate rotation, journald statistics
  - Command diversification: baseline process commands contain user-specific paths and varied
    project/document names, not identical fixed strings across users
  - Workstation lock/unlock (4800/4801): workstation_lock always precedes workstation_unlock
    for the same session — semantic ordering enforced
  - Explicit credentials (4648): RunAs and scheduled task execution with alternate credentials

  Proxy coverage (verify in generated data):
  - PROXY-01 (forward_proxy) routes web traffic for internal systems
  - proxy_access logs show client_ip, username, method, url, host, status_code, cache_result
  - HTTP CONNECT method for HTTPS tunneling through proxy
  - DENIED proxy requests stop at the proxy (no proxy→origin Zeek/IDS/firewall transactions)
  - Cache hit/miss distribution (HIT, MISS, NONE, DENIED)
  - Proxy logs correlate with Zeek HTTP/SSL logs for the same transactions
  - Client→proxy timestamps precede proxy→origin timestamps by the proxy latency budget

  Web log realism coverage (verify in generated data):
  - Referer distribution on web_access + zeek_http: ~55% blank, ~20% search engine,
    ~20% same-origin, ~5% social/news
  - Nikto User-Agent rotates per request via @NIKTO_TESTID@ token (unique 6-digit IDs),
    not a single static string
  - Web-scan Referer for nikto: ~30% same-origin; for sqlmap/dirb/nmap_http: always blank

  Ground truth / answer key:
  - GROUND_TRUTH.md generated automatically from storyline events
  - Contains: attack summary narrative, chronological timeline table, IOCs by category
    (IPs, domains, usernames, processes, files, ports, protocols), red herring explanations
  - technique fields on storyline events map to MITRE ATT&CK for IOC categorization

  Save to scenarios/iteration-test/scenario.yaml with accompanying ENVIRONMENT.md.

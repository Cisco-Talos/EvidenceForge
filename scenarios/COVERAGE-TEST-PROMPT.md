  Create an EvidenceForge scenario for a comprehensive feature coverage test. Use these requirements:

  Environment: Meridian Healthcare Solutions, a mid-size healthcare IT company (~120 employees) providing
   EHR integration services. Corporate HQ with on-premises data center.

  Duration: 14 hours, starting 2024-03-18T12:00:00Z. Timezone: America/Chicago.
  warmup: "8h" (minimum 1h — pre-populates DNS cache, process trees, and sessions so the
  first minute of output is realistic rather than cold-start).
  logon_grace_period: "30m" (suppresses "no prior logon" warnings for users assumed already
  at their desk at time_window.start).
  observation_profile: complete (explicit default — preserves training-friendly complete source
  coverage; use non-default profiles only when specifically testing collection gaps).

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
  - corporate_lan (10.10.1.0/24) — workstations, exposure: internal
  - server_vlan (10.10.2.0/24) — DC, file server, app server, log server, exposure: internal
  - dmz (10.10.3.0/24, exposure: both, external_ratio: 0.6) — web server, proxy
  - database_vlan (10.10.4.0/24, exposure: internal) — MySQL (intentionally no sensor — blind spot)

  public_cidrs: ["203.14.220.0/28"] at network level — the org's own public address block,
  distinct from NAT-inferred ranges. External scan/probe baselines target this range.

  Sensors:
  - zeek-core: SPAN, monitors corporate_lan + server_vlan, bidirectional
  - zeek-dmz: SPAN, monitors dmz, bidirectional
  - snort-perimeter: TAP, monitors dmz, inbound
  - fw-perimeter: firewall, TAP, monitors corporate_lan + server_vlan + dmz, bidirectional,
    log_formats: [cisco_asa], interfaces: {corporate_lan: inside, server_vlan: inside, dmz: dmz},
    default_action: deny, deny_ratio: 5.0, drop_mode: drop (silent drops -> S0 conn_state;
    use "reject" for RST-based drops -> REJ conn_state), threat_detection_rate: 10
    (burst threshold drops/sec for 733100 threat-detection alerts; set 0 to disable),
    nat_rules:
      - type: dynamic_pat
        src: [corporate_lan, server_vlan]
        mapped_ip: 45.33.32.1
      - type: static
        src: dmz
        real_ip: 10.10.3.10 (WEB-EXT-01)
        mapped_ip: 45.33.32.10
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

  Red herrings (3-4 explicit events, in addition to automatic suspicious_noise). Each red
  herring MUST include an `explanation` field describing why the activity is benign — this
  appears in GROUND_TRUTH.md's Red Herrings section for instructor answer keys:
  - After-hours IT maintenance: sysadmin RDP to DC-01 at an unusual hour, running legitimate
    diagnostic commands (Get-EventLog, Test-Connection). Should look suspicious but have an
    innocent explanation.
  - Failed logon burst from a legitimate user who fat-fingered their password 3-4 times before
    succeeding. Should trigger lockout-style alerts but is benign.
  - Large outbound file transfer from a developer workstation to a cloud storage IP — actually a
    legitimate backup or repo sync, but the volume looks like exfiltration. Use a physically
    plausible orig_bytes value (100-500 MB, NOT multi-GB — a 2GB upload in 25 seconds implies
    670 Mbps sustained throughput which is impossible on a typical corporate LAN uplink).
  - Service account (svc_backup) authenticating from an unusual host (not its normal server) —
    legitimate scheduled task migration, but looks like lateral movement.

  All 9 log format groups: windows, zeek, ecar, syslog, bash_history, snort_alert, cisco_asa,
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

  1. Rogue Device (+0h45m): Attacker plugs rogue laptop into network, obtains IP via DHCP.
  Use a `dhcp_lease` event on the parent storyline `system` for the rogue device. Inside
  the `dhcp_lease` event, use only `mac_address` and optionally `requested_ip`; do not
  include `hostname` because DHCP hostname is derived from parent `system`. Use a realistic
  MAC address with a known vendor OUI prefix (e.g., DC:A6:32 for Raspberry Pi, 00:50:56
  for VMware, 00:0C:29 for VMware, B4:2E:99 for Glenfly Tech). Do NOT use sequential/
  placeholder MACs like 00:1A:2B:3C:4D:5E. Actor should be a valid built-in, service
  account, or defined user — do not create an obvious `attacker` account.

  2. Initial Access (+1h): External attacker exploits SQL injection on WEB-EXT-01's EHR portal
  from `source_ip: "185.70.41.45"`. Use `connection` events with HTTP fields (`source_ip`,
  `dst_ip`, `dst_port`, `method: POST`, `uri` with SQLi payload, `status_code: 500`,
  `user_agent`, `hostname: "ehr-portal.meridianhcs.com"`) — NOT raw events. Actor: root.
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
  12. Lateral Movement (+5h): PsExec to DC-01 via SMB. Model this correctly:
  PsExec works by deploying PSEXESVC.exe as a Windows service on the remote host.
  Use a logon (type 3 from source workstation) + service_installed (service_name:
  "PSEXESVC", service_file_name: "%SystemRoot%\PSEXESVC.exe") + then process events
  for commands run under the service. Do NOT use "cmd.exe /c PSEXESVC.exe" — that
  produces the wrong parent chain (explorer→cmd→PSEXESVC instead of the correct
  services.exe→PSEXESVC).
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
  24. Web Scanning (+0h30m): External attacker runs web vulnerability scanning against WEB-EXT-01.
  Use a `web_scan` event with `source_ip: "185.70.41.45"`, `dst_ip: "10.10.3.10"`,
  `dst_port: 443`, `hostname: "ehr-portal.meridianhcs.com"`, `preset: nikto`,
  `rate: 10`, and exactly one termination field: `duration: "20m"`. Do not use `src_ip`.

  25. Port Scan (+0h30m): External attacker scans the DMZ segment looking for services before
  the initial exploit. Use a `port_scan` event with `source_ip: "185.70.41.45"`,
  `target_segment: dmz`, `ports: [22, 80, 443, 8080, 8443, 3306]`, and `scan_rate: 50`.
  Do not use `src_ip`. This should produce firewall denies visible to the external
  Zeek/Snort sensors but NOT internal sensors.
  26. Blocked C2 (+6h): After compromising DC-01, attacker malware tries to beacon directly
  from DC-01 to 45.33.32.30:443 — but the firewall policy doesn't allow servers to reach
  external IPs on arbitrary ports. Use beacon event with action: deny, interval: "30m",
  duration: "6h". The denied outbound attempts should be visible to internal sensors only.
  27. Ongoing C2 (+10h, +12h): Periodic beacons from WEB-EXT-01 and DC-01.
  28. Account Cleanup (+13h): Delete the backdoor account (account_deleted event with
  target_username: svc_sqlreader).
  29. Logoff (+13h30m): Attacker logs off from compromised systems (logoff events).

  Key requirements:
  - Exercise all 28 storyline event types: process, logon, failed_logon, logoff, connection,
  ssh_session, rdp_session, account_created, account_deleted, group_member_added, service_installed,
  scheduled_task_created, log_cleared, create_remote_thread, process_access, dhcp_lease, port_scan,
  beacon, dns_query, web_scan, credential_spray, dga_queries, dns_tunnel, explicit_credentials,
  workstation_lock, workstation_unlock, spillage, raw
  - NOTE: spillage emits a synthetic, provably-fake credential into a semantic surface
  (shell_history/process_command_line/syslog_message, or http_request_url/http_referrer which
  require a roles:[web_server] host). Full machine-readable labels live in
  GROUND_TRUTH.jsonl; GROUND_TRUTH.md carries a redacted human-readable summary.
  - NOTE: process_access IS a valid scenario event type and can be declared directly (e.g.,
  for a standalone Sysmon Event 10 probing LSASS without a preceding injection). However,
  when create_remote_thread targets lsass.exe, the causal expansion engine auto-generates
  a correlated process_access — do NOT manually declare a second process_access on lsass
  in the same step or you'll get duplicate events.
  - NOTE: "c2" is NOT a valid event type — use "beacon" for C2 communication
  - Use connection events with HTTP fields (method, uri, status_code, user_agent, hostname) for web
    access log entries showing the SQLi and web shell access — NOT raw events
  - Periodic events (beacon, web_scan, credential_spray, dga_queries, dns_tunnel) must each
    specify exactly one of: end_time, duration, or count — plus interval (or rate for web_scan)
  - Typed event fields are strict. Use `source_ip`, never `src_ip`. Do not add `hostname`
    to `dhcp_lease`; DHCP hostname comes from the parent storyline `system`. Do not put
    parent storyline fields (`time`, `actor`, `system`, `activity`) inside individual
    event objects.
  - All base64 payloads must be real (generated via Bash tool)
  - Attacker naming must be realistic (no "evil", "malware", "attacker" names)
  - External IPs from realistic public ranges (NOT RFC 5737 documentation ranges).
    This applies to ALL public IPs in the scenario — attacker infrastructure, the org's
    own public IP block (NAT mapped_ip values, static NAT VIPs), and any third-party IPs.
    The org's public IP block must NOT overlap with attacker infrastructure IPs or well-known
    security tools (e.g., do NOT use 45.33.32.1 which is scanme.nmap.org). Use separate
    realistic ranges for the org's public IPs (e.g., 203.14.x.x) vs attacker IPs (e.g.,
    45.33.32.x, 89.248.167.x)
  - Baseline activity: medium intensity, medium variation, suspicious_noise: medium
  - Include technique (MITRE ATT&CK ID) and description fields on storyline events for ground truth

  Engine behavior expectations:
  - C2 connections to raw IPs (45.33.32.30) will NOT have DNS queries — realistic for direct-IP C2
  - DNS queries for baseline web traffic use domain-first selection — SNI, DNS, and proxy hostname will be consistent
  - DHCP events are routed to sensors by segment visibility (not duplicated across all sensors)
  - Windows service account events (SYSTEM, NETWORK SERVICE) show "NT AUTHORITY" as SubjectDomainName
  - 4648 (explicit credentials) fires in baseline for scheduled task execution with
    randomized counts (2-5/hour) plus storyline lateral movement — do not expect 4648 to
    appear only on the attack path
  - DCs receive admin-only baseline: type 3 logons from RSAT sessions (mmc.exe on admin
    workstation, not DC), type 10 RDP for direct admin access, no user desktop artifacts
  - RSAT sessions produce correlated cross-host events: mmc.exe + DLL loads on the
    workstation, LDAP/RPC connections from workstation to DC, type 3 logon on the DC — all
    within seconds
  - ParentCommandLine in Sysmon 1 is populated from the parent's actual command line (not
    just the image name), reflecting spawn_rules.yaml realistic parent-child chains
  - 4634 logoff pairs with 4624 on matching TargetLogonId, including type 3 network logons
    and DC machine-account logons (after short delays)
  - Certificate validity periods match issuer (Let's Encrypt = 90 days, DigiCert = 397 days)
  - X.509 child certificate signatures are compatible with the issuer key family and CA profile
  - Certificate chain depth and CA reuse driven by tls_realism.yaml/tls_issuers.yaml —
    intermediate CAs appear as shared profiles, not unique per leaf
  - MAC addresses use diverse OUI prefixes from network_params.yaml (Dell, HP, Lenovo,
    Intel, VMware)
  - PID 4 resolves to "System" in parent process lookups (System PID 4 now properly
    registered so Sysmon/eCAR events attribute correctly)
  - NAT rules produce: dynamic PAT (mapped_src_ip + translated src port for outbound), static NAT
  (1:1 mapping for DMZ server). Outside Zeek sensors see post-NAT IPs; inside sensors see real IPs
  - Firewall policy enforcement: external -> corporate_lan denied, external -> dmz:80/443 allowed
  - Stale SSH close / stale flow process evidence is suppressed: teardown events only appear
    for sessions with a matching session-open event (no orphaned SSH disconnects or FLOW
    terminates for processes that never started)

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
  - Event 1 (ProcessCreate): baseline + storyline process events; ParentCommandLine
    populated from parent's actual command line (not image only); ParentImage reflects
    spawn_rules.yaml (CLI tools from shells, GUI apps from explorer.exe, services from
    services.exe/svchost.exe)
  - Event 3 (NetworkConnect): outbound connections attributed to originating process; skipped
    when process cannot be resolved; svchost.exe for DNS/NTP
  - Event 5 (ProcessTerminate): baseline process terminations for Windows hosts plus storyline
    process terminations with realistic delays (recon: 0.3-5s, attack tools: 5-30s, persistent/C2: no termination);
    paired 1:1 with Security 4689 + eCAR PROCESS/TERMINATE for the same exit
  - Event 7 (ImageLoad): baseline DLL loads (ntdll.dll, kernel32.dll, etc.) with
    signing status and signature details. Third-party DLLs preserve source-native signer,
    company, product, and version metadata instead of falling back to Microsoft identity.
  - Event 8 (CreateRemoteThread): baseline benign pairs 1-3/hr (MsMpEng->explorer,
    csrss->svchost, etc.) plus storyline mimikatz create_remote_thread targeting lsass;
    correlated with eCAR THREAD/REMOTE_CREATE
  - Event 10 (ProcessAccess): baseline benign pairs 3-8/hr (MsMpEng->lsass with 0x1410,
    services->svchost with 0x1000, etc.) plus storyline mimikatz process_access on lsass
    with 0x1FFFFF; correlated with eCAR PROCESS/OPEN
  - Event 11/12/13 (FileCreate, RegistryEvent create, RegistryEvent value set): emitted for
    persistence-related storyline steps (service install, scheduled task)
  - Event 22 (DNSQuery): DNS lookups from Windows processes; QueryName, QueryStatus, and
    resolved addresses
  - Baseline Event 8/10 noise ensures storyline attack events are not instant red flags
  - Sysmon/Security/eCAR events for the same process lifecycle are not bucketed at
    identical timestamps — collision-spacing knobs in timing_profiles.yaml stagger them

  Cisco ASA firewall coverage (verify in generated data):
  - Built/Teardown pairs (302013/302014) for permitted TCP connections through the firewall
  - Built/Teardown pairs (302015/302016) for permitted UDP connections (DNS queries, etc.)
  - Deny records (106023) for blocked external scanning and unauthorized cross-segment traffic
  - Threat detection 733100 alerts fire when scan deny bursts exceed threat_detection_rate
    (10 drops/sec burst, 5 drops/sec avg). Verify 733100 records show rate_id,
    current_burst, max_burst, total_count fields; expect them during the port_scan and
    web_scan phases.
  - drop_mode: drop produces conn_state S0 on denied traffic; drop_mode: reject produces REJ
  - Correct interface resolution: internal IPs -> "inside", DMZ IPs -> "dmz", external IPs -> "outside"
  - Per-sensor directory output: fw-perimeter/cisco_asa.log
  - Deny baseline volume proportional to deny_ratio (~5x allows)
  - Deny baseline timing uses burst/quiet cadence from host_activity_profiles.yaml, not evenly
    spaced attempts; 106023 hash pairs should vary when the profile calls for it, not always
    render as [0x0, 0x0]
  - Firewall policy enforcement: external -> corporate_lan denied, external -> dmz:80/443 allowed
  - Storyline connections through the firewall produce ASA allow records correlated with Zeek conn records
  - 305011 (Built NAT translation) present when nat_rules configured
  - 305012 (Teardown NAT translation) present
  - Built messages show mapped IPs in parentheses that differ from real IPs
  - Outside Zeek sensors show post-NAT source IPs; inside sensors show real IPs
  - Static NAT: inbound connections to VIP (45.33.32.10) translated to real IP (10.10.3.10)
  - External baseline scans target the org's public_cidrs (203.14.220.0/28), not attacker
    infrastructure — verify external->public_cidrs denies appear in the baseline noise

  Data Realism coverage (verify in generated data):
  - Causal expansion: DNS queries precede TCP connections in zeek_dns/zeek_conn; Kerberos 4768/4769
    precede 4624 domain logons; process_access (Event 10) follows create_remote_thread targeting lsass
  - Data-driven timing profiles (timing_profiles.yaml): all causal offsets (dns_before_tcp,
    kerberos_before_logon, remote_thread_lsass_access) and source-native timing (Zeek
    analyzer offsets, TLS duration floors, Windows/Sysmon collision spacing) are configurable.
    Verify DNS-to-TCP offsets are not uniform; verify Sysmon Events 1/5/8/10 for the same
    process chain are not bucketed at identical timestamps.
  - Hawkes temporal model: user events show bursty clusters (CV > 1.0 in eval), not uniform spacing
  - Host activity profiles: host type, roles, and persona shape broad rate families after
    traffic_rates/scenario overrides. Verify DC/file/web/proxy/server hosts and user workstations
    have distinct event-volume profiles rather than uniform per-host counts.
  - Typing cadence: multi-event storyline steps (e.g., step 4 discovery commands, step 10 AD enum)
    have 1-15 second gaps between events, not identical timestamps
  - Day-of-week variation: if scenario spans a weekend, Saturday/Sunday activity near-zero
  - Lateral movement: backup/monitoring/AD replication traffic between servers (conditional on topology)
  - Process->network correlation: chrome.exe/git/sqlcmd baseline processes produce matching connections
  - Stale account enrichment: if stale_accounts defined, expect Kerberos 4771 (0x12) failures on DC
    plus failed batch (type 4) and service (type 5) logons, not just network logon failures
  - Network red herrings: suspicious-but-benign DNS (high-entropy CDN subdomains), unusual outbound
    (cloud backup sync), and scan overlap patterns in Zeek conn/dns logs
  - HTTP status codes for proxied traffic honor the canonical connection status (storyline
    status_code passes through proxy unchanged, not rewritten to 200)
  - Linux syslog depth: SSH "Accepted publickey/password" login messages, apt-daily or dnf-automatic
    package management, systemd timer trigger/deactivate, logrotate file rotation detail, journald
    runtime statistics. Verify distro-aware (Ubuntu vs CentOS paths/daemons).
  - Command diversification: baseline process commands contain user-specific paths and varied
    project/document names, not identical fixed strings across all users
  - Entity lifecycle: no process_access events targeting PIDs that don't exist in running_processes
  - Workstation lock/unlock (4800/4801): persona-driven lock frequency during work hours
  - Explicit credentials (4648): RunAs and scheduled task execution with alternate credentials
  - Observation profile: `complete` keeps cross-source coverage training-friendly; source gaps,
    delays, and partial collection belong to named non-default profiles and should not appear here.

  Proxy coverage (verify in generated data):
  - Forward proxy (PROXY-01 with roles: [forward_proxy]) routes web traffic for internal systems
  - Include environment.proxy.mode; use explicit for PAC/browser-configured proxy coverage
  - proxy_access logs show client_ip, username, method, url, host, status_code, cache_result
  - HTTP CONNECT method for HTTPS tunneling through proxy
  - Explicit proxy mode shows client→proxy and proxy→origin Zeek/IDS/firewall legs, not direct client→origin, unless a sensor legitimately sees both sides
  - DENIED proxy requests stop at the proxy and do not produce proxy→origin Zeek, IDS, or firewall transactions
  - Cache hit/miss distribution (HIT, MISS, NONE, DENIED)
  - Proxy logs correlate with Zeek HTTP/SSL logs for the same transactions
  - Client→proxy and proxy→origin legs have correctly ordered timestamps (proxy leg precedes
    origin leg by the proxy latency budget; HTTP status flows back through the proxy leg
    using the canonical response code, not rewritten)
  - Proxy user agents are data-driven (proxy_user_agents.yaml) — verify User-Agent diversity
    rather than a single fixed value
  - OCSP evidence flows via zeek_files linking cert chains to their revocation checks

  Web log realism coverage (verify in generated data):
  - Referer header distribution on web_access + zeek_http: ~55% blank, ~20% search engine,
    ~20% same-origin, ~5% social/news; bot UAs always blank
  - Web-scan Referer per preset: Nikto ~30% same-origin (partial crawl); gobuster/sqlmap/
    dirb/nmap_http always blank
  - Nikto User-Agent rotates per request via @NIKTO_TESTID@ token (6-digit IDs unique per
    request), not a single static string
  - Browser-like page loads fan out into realistic CSS/JS/image/API subresource requests; the
    top-level request budget counts user-driven page/tool requests, not every render component
  - Event-specific jitter defaults: beacon 0.15 (tight), web_scan 0.4 (wide), credential_spray
    0.5 (self-pacing), dga_queries 0.3, dns_tunnel 0.25 — can be overridden per event

  Ground truth / answer key:
  - GROUND_TRUTH.md generated automatically from storyline events
  - Contains: attack summary narrative, chronological timeline table, IOCs by category
  (IPs, domains, usernames, processes, files, ports, protocols), red herring explanations
  - technique fields on storyline events map to MITRE ATT&CK for IOC categorization

  Save to scenarios/apt-healthcare-breach/scenario.yaml with accompanying ENVIRONMENT.md.

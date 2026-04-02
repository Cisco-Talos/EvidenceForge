# Scenario Schema Reference

This document describes the EvidenceForge scenario file schema, including Phase 2.4 enhanced fields.

## Overview

Scenario files are YAML documents that define the environment, users, systems, personas, and storyline for log generation. All fields marked "Phase 2.4+" are optional and backward compatible with Phase 1 scenarios.

## Top-Level Structure

```yaml
version: "1.0"
name: scenario-name          # Alphanumeric, dash, underscore
description: |
  Multi-line scenario description
environment: ...
personas: [...]               # Optional
time_window: ...
baseline_activity: ...
logon_grace_period: "30m"    # Optional (default: "30m") — suppresses "no prior logon" warnings within this duration of time_window.start
storyline: [...]              # Optional
red_herrings: [...]          # Optional: suspicious-but-benign events for analyst training
output: ...
```

## Environment

```yaml
environment:
  description: "Corporate office network"
  timezone:
    default: "America/New_York"
    systems:                  # Optional pattern-based overrides
      "EU-*": "Europe/London"
      "AP-*": "Asia/Tokyo"
  users: [...]
  systems: [...]
  service_accounts: [...]      # Optional: extra account names valid as storyline actors
  stale_accounts:              # Optional: inactive accounts that generate background noise
    - username: former.employee
      last_active: "2023-11-15"
      reason: "Transferred to another office"
    - username: svc_old_crm
      last_active: "2024-01-02"
      reason: "CRM system decommissioned"
  groups: [...]               # Optional
```

Stale accounts generate multiple types of background evidence: failed network logons (~15%/hour), Kerberos pre-auth failures (4771, status 0x12) on DCs (~5%/hour), scheduled task failures (batch logon type 4, ~3%/hour), and service startup failures (type 5, first hour only). Each field:
- `username`: Account name (must not collide with active users or service_accounts)
- `last_active`: ISO date when the account was last active (context only, not used by engine)
- `reason`: Why the account is stale (context only, for ground truth documentation)

### Timezone Configuration

All internal timestamps are stored in UTC. The timezone configuration controls output formatting.

- **default**: Applied to all systems unless overridden (default: `"UTC"`)
- **systems**: Pattern-based overrides using fnmatch glob syntax (`*`, `?`, `[seq]`)
  - First matching pattern wins
  - Unmatched hostnames use the default

Valid timezone names are any [pytz timezone](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones) (e.g., `America/New_York`, `Europe/London`, `Asia/Tokyo`, `UTC`).

### Users

```yaml
users:
  - username: jsmith           # Required: alphanumeric, dash, underscore
    full_name: "Jane Smith"    # Required
    email: jane@example.com    # Required
    groups: ["developers"]     # Optional
    enabled: true              # Optional (default: true)
    persona: developer         # Optional: reference to persona name
    primary_system: WS-01      # Required: reference to system hostname
```

### Systems

```yaml
systems:
  - hostname: WS-01            # Required: RFC 1123 compliant
    ip: "10.0.1.10"            # Required: IPv4 or IPv6
    os: "Windows 10"           # Required
    type: workstation          # Required: workstation|server|domain_controller
    assigned_user: jsmith      # Optional: reference to username
    services: ["IIS"]          # Optional
    roles: [web_server]        # Optional: forward_proxy, web_server, dns_server, mail_server
```

### System Roles

The `roles` field declares a system's function in the network. The engine uses roles for traffic routing decisions:

- `web_server` — generates web access logs for HTTP requests to this system
- `forward_proxy` — routes outbound HTTP/HTTPS traffic through this system; generates proxy access logs with CONNECT entries for HTTPS, cache hit/miss status, and full destination URLs
- `dns_server` — DNS resolution target
- `mail_server` — mail relay/server

### Network Segment Exposure

Segments can declare their internet exposure via the `exposure` field:

```yaml
network:
  segments:
    - name: workstations
      cidr: "10.0.1.0/24"
      exposure: internal        # Only internal clients (default)
    - name: dmz
      cidr: "10.0.2.0/24"
      exposure: both            # Internal + external clients
```

Values: `internal` (default), `external`, `both`. Affects web server client IP generation — `both` and `external` segments produce a mix of internal and external client IPs in web access logs.

### Network Sensors

Sensors define monitoring infrastructure. Each sensor type produces different log formats:

```yaml
network:
  sensors:
    - type: network             # network | ids | firewall
      name: core-tap
      hostname: zeek01          # Output directory name (falls back to name)
      monitoring_segments: [corporate_lan, server_vlan]
      direction: bidirectional  # bidirectional | inbound | outbound
      placement: span           # span (sees intra-segment) | tap (cross-segment only)
      log_formats: [zeek]       # Format groups or individual formats
```

#### Firewall Sensors

Firewall sensors produce Cisco ASA syslog records for permitted and denied connections. They require explicit policy rules to determine what traffic is allowed vs denied.

```yaml
    - type: firewall
      name: fw01
      hostname: fw01
      monitoring_segments: [workstations, servers, dmz]
      placement: tap
      direction: bidirectional
      log_formats: [cisco_asa]
      interfaces:               # Map segment names to ASA interface names
        workstations: inside
        servers: inside
        dmz: dmz
      default_action: deny      # deny (default) | permit
      deny_ratio: 5.0           # Deny events per allow event in baseline (default: 5.0)
      threat_detection_rate: 10 # Deny rate (drops/sec) triggering 733100 alerts (0=disabled)
      policy:                   # Ordered rules — first match wins
        - {src: external, dst: dmz, ports: [80, 443]}
        - {src: workstations, dst: any}
        - {src: servers, dst: external, ports: [80, 443, 53]}
        - {src: servers, dst: servers}
```

**Policy rules** (`FirewallRule`):
- `src` / `dst`: segment name, `"external"` (IPs not in any segment), specific IP, CIDR notation, or `"any"`
- `ports`: list of port numbers, or empty list / `"any"` for all ports
- `action`: `"permit"` (default) or `"deny"`
- Rules are evaluated in order; first match wins (like real ACLs)
- Traffic not matching any rule is subject to `default_action`

**Interfaces**: Map segment names to ASA interface names (e.g., `inside`, `outside`, `dmz`). IPs not in any mapped segment resolve to `"outside"`.

**Threat detection**: The ASA emitter automatically tracks per-source-IP deny rates and fires 733100 alerts when both burst (default 10 drops/sec over 20s) and average (default 5 drops/sec over 60s) thresholds are exceeded. Set `threat_detection_rate: 0` to disable.

## Personas

Personas define user behavior patterns for activity generation. EvidenceForge includes 15 pre-built personas (developer, analyst, sysadmin, executive, etc.) that are resolved automatically by name — reference them in user definitions without needing to define them inline. Define personas inline only if you need to customize behavior beyond what the pre-built library provides; inline definitions override pre-built ones with the same name.

```yaml
personas:
  - name: developer            # Required: unique identifier
    description: "Software developer who codes and browses"  # Required
    typical_activities:        # Optional list of activity strings
      - coding
      - web_browsing
    work_hours: "9am-5pm"     # Optional (default: "9am-5pm")
    application_usage:         # Optional
      - vscode
      - chrome
    risk_profile: low          # Optional: low|medium|high (default: "medium")
```

### Work Hours Format

The `work_hours` field supports these formats:
- `"9am-5pm"` - Basic range
- `"8:30am-5:30pm"` - Half-hour precision
- `"9am-5pm (lunch 12pm-1pm)"` - With lunch break
- `"8:30am-5:30pm (lunch 12:30pm-1:30pm)"` - Both combined

Work hours are automatically parsed into a `work_hours_parsed` dict containing:
- `start`: Start hour as float (e.g., 9.0, 8.5)
- `end`: End hour as float (e.g., 17.0, 17.5)
- `lunch`: Tuple of (start, end) if specified, else null
- `hours`: List of active integer hours (excluding lunch)
- `peak_hours`: Mid-morning and mid-afternoon hours

### Phase 2.4+ Optional Fields

These fields are for future LLM expansion (Phase 3.1) and are not required:

```yaml
personas:
  - name: developer
    # ... Phase 1 fields above ...

    expanded_activities:       # Phase 2.4+: LLM-populated activity sequences
      - activity_type: process_code
        sequence:
          - action: open_ide
            app: VS Code
          - action: edit_files
            duration_minutes: 30
        temporal_pattern: morning_focus
        frequency: daily

    activity_intensity:        # Phase 2.4+: Per-activity events/hour overrides
      process_code: 20
      connection_web: 5
```

**expanded_activities** items must have:
- `activity_type` (required): Maps to baseline activity types
- `sequence` (optional): List of action steps
- `temporal_pattern` (optional): When this activity typically occurs
- `frequency` (optional): How often (hourly, daily, weekly)

## Time Window

```yaml
time_window:
  start: "2024-01-15T10:00:00Z"  # Required: ISO 8601 UTC
  end: "2024-01-15T18:00:00Z"    # Either end OR duration required
  duration: "8h"                   # Supports: "10h", "3d", "2h30m", "5m30s", "500ms"
```

## Baseline Activity

```yaml
baseline_activity:
  description: "Normal office activity"
  intensity: medium              # low|medium|high (events/user/hour)
  variation: low                 # low|medium|high (timing variation)
```

Intensity mapping: low=5, medium=15, high=40 events/user/hour.

## Storyline

Storyline events define specific actions at specific times. Each entry declares what happened (`activity`, for documentation/GROUND_TRUTH.md) and what events to generate (`events` list with typed, validated fields).

```yaml
storyline:
  - id: evt-lateral-pth        # Required: unique event identifier — must be unique across all storyline events.
                               # Any string format is valid. Prefer descriptive labels (e.g., "evt-lateral-pth",
                               # "evt-c2-beacon-day2") but sequential IDs (e.g., "evt-001") are also fine.
    time: "+2h30m"             # Required: ISO 8601 or relative offset (d/h/m/s/ms)
    actor: john.doe            # Required: username, built-in account (SYSTEM/root), or service_account
    system: WS-01              # Required: system hostname
    activity: "lateral movement via pass-the-hash"  # Required: human-readable description (GROUND_TRUTH.md)
    events:                    # Required: typed event declarations
      - type: logon
        source_ip: "10.0.1.20"
        logon_type: 3
      - type: process
        process_name: "C:\\Windows\\System32\\cmd.exe"
        command_line: "cmd.exe /c whoami"
```

### Event Types

Each event in the `events` list has a `type` field that selects a validated schema. Unknown fields are rejected at load time.

| Type | Generates | Required Fields | Optional Fields |
|------|-----------|-----------------|-----------------|
| `process` | 4688, Sysmon 1, eCAR PROCESS | `process_name` | `command_line`, `supplementary` (auto/none) |
| `logon` | 4624, 4672, eCAR LOGIN | | `logon_type` (default 3), `source_ip` |
| `failed_logon` | 4625, eCAR LOGIN failure | | `source_ip`, `logon_type` (default 3) |
| `logoff` | 4634, eCAR LOGOUT | | |
| `connection` | Zeek conn, eCAR FLOW, + web_access/zeek_http when `service: http` | `dst_ip` | `dst_port` (default 443), `service`, `source_ip`, `method`, `uri`, `status_code`, `user_agent` |
| `ssh_session` | Zeek conn + syslog sshd + eCAR | | `source_ip` |
| `rdp_session` | Zeek conn + 4624 type 10 + eCAR | | `source_ip` |
| `account_created` | 4720 (on DC) | `target_username` | `target_sid` |
| `account_deleted` | 4726 (on DC) | `target_username` | `target_sid` |
| `group_member_added` | 4728/4732/4756 (on DC) | `group_name`, `member_name` | `scope` (global/local/universal) |
| `service_installed` | 4697, eCAR SERVICE/CREATE | `service_name`, `service_file_name` | `service_account` |
| `scheduled_task_created` | 4698 | `task_name` | `task_content` |
| `log_cleared` | 1102 | | |
| `create_remote_thread` | Sysmon 8, eCAR THREAD/REMOTE_CREATE | `target_process` | |
| `dhcp_lease` | Zeek dhcp.log | | `mac_address`, `requested_ip` |
| `port_scan` | ASA 106023 (bulk denies) | `target_ips` or `target_segment` | `target_count`, `ports`, `protocol`, `scan_rate` |
| `blocked_c2` | ASA 106023 (periodic denies) | `dst_ip` | `dst_port`, `interval`, `duration`, `jitter` |
| `raw` | Any single format | `target_format`, `fields` | |

All event types also accept optional `technique` (MITRE ATT&CK ID) and `description` (human-readable detail) fields for GROUND_TRUTH.md enrichment.

### Red Herrings

Red herrings are suspicious-but-benign events that create false leads for analysts. They use the same event types as the storyline but are documented in a separate "Red Herrings" section of `GROUND_TRUTH.md` with their benign explanations.

```yaml
red_herrings:
  - id: rh-afterhours-admin
    time: "+3h"
    actor: sarah.oconnell        # Must be in users list
    system: DC-01
    activity: "After-hours server maintenance"
    explanation: "Routine sysadmin maintenance performed outside business hours to avoid user impact"
    events:
      - type: logon
        logon_type: 10
        source_ip: "10.10.1.15"
      - type: process
        process_name: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        command_line: "powershell.exe -Command Get-EventLog -LogName System -Newest 50"
```

Each red herring requires:
- `id`: Unique event identifier (must not collide with storyline IDs)
- `time`: Same format as storyline (ISO 8601, relative offset, or seconds)
- `actor`: Username (must be in users list, service_accounts, or a builtin account)
- `system`: Target system hostname
- `activity`: Human-readable description (appears in Red Herrings section of GROUND_TRUTH.md)
- `explanation`: Why this activity is benign (instructor-only context in GROUND_TRUTH.md)
- `events`: Same typed event list as storyline (all event types supported)

Red herrings are separate from `baseline_activity.suspicious_noise`, which auto-generates ambient suspicious patterns (after-hours logins, suspicious CLI, failed logon bursts, etc.) without explicit scenario configuration.

### Causal Expansion

The generation engine automatically emits prerequisite events for certain event types. You do **not** need to manually specify these — they are generated with realistic timing offsets:

| Trigger Event | Auto-Generated Prerequisites | Timing |
|---|---|---|
| `connection` (TCP, not port 53) | DNS query (UDP/53) for destination hostname | 5-80ms before |
| `logon` (Kerberos auth, Windows, not on DC) | Kerberos TGT (4768) + TGS (4769) on DC, optional 4672 for elevated users | TGT 50-200ms before, TGS 20-100ms after TGT |
| `rdp_session` | DNS query + connection (port 3389) + logon (type 10) | Connection at event time, logon 50-200ms after |
| `ssh_session` | DNS query + connection (port 22) + syslog auth | Connection at event time |
| `process` (with admin commands) | Supplementary audit events (4720, 4726, 4728, 4697, 4698, 1102) inferred from command-line patterns | 100-500ms after |
| `create_remote_thread` (targeting lsass) | Process access (Sysmon Event 10) | 1-50ms after |

**When to manually specify these events:** Only when they are part of the attack narrative itself (e.g., DNS tunneling exfiltration, Kerberos golden ticket forging, explicit credential dumping via process access). The validator will warn if it detects potentially redundant manual specifications.

### Baseline Realism Features

The generation engine automatically provides several layers of realism in baseline activity:

**Hawkes temporal model:** User baseline events use a self-exciting Hawkes process — activity naturally clusters into bursts that taper off, producing realistic human work patterns. Parameters are derived from persona `risk_profile` (high = intense bursts, low = gentle clusters). System/service traffic uses periodic intervals with small jitter instead.

**Storyline typing cadence:** Events within a multi-event storyline step are spaced with human typing rhythm (~1.5s between actions, occasional 3-12s thinking pauses) instead of sharing a single timestamp.

**Day-of-week variation:** Scenarios spanning multiple days show weekly rhythm — Monday login storms, Friday early departures, near-zero weekend activity (only sysadmin/security_analyst/help_desk personas active on Saturday/Sunday).

**Stale account evidence:** Stale accounts defined in `environment.stale_accounts` generate not just failed logons but also Kerberos pre-auth failures (4771, status 0x12) on DCs, scheduled task failures (batch logon type 4), and service startup failures (service logon type 5, first hour only).

**Legitimate lateral movement:** 26 patterns of inter-server traffic are auto-generated based on the environment topology. These include backup agents, monitoring, AD replication, application-to-database connections, config management, and more. Patterns are conditional on having the required infrastructure (assign `roles` like `file_server`, `database`, `web_server`, `mail_server`, `print_server`, `dns_server`, `nfs_server` on systems to enable specific patterns).

**Network-level red herrings:** The suspicious noise generator includes network-layer patterns: high-entropy DNS queries (CDN subdomains, DoH providers), unusual outbound connections (cloud backup sync, dev tool endpoints), and scheduled vulnerability scan overlaps. Controlled by `baseline_activity.suspicious_noise` level.

**Entity lifecycle validation:** The engine validates that process injection events target existing PIDs and that event timestamps don't precede system boot times. Warnings are logged for impossible sequences.

**Process→network correlation:** Baseline processes that normally generate network traffic (browsers, Office, dev tools, DB clients) automatically emit corresponding connections (HTTPS, SQL, SSH) 50-500ms after process creation, with the process PID carried for cross-source correlation.

**Linux syslog depth:** Linux hosts generate 18 categories of syslog messages: SSH login/key exchange (70% key / 30% password), package management, systemd timer execution, logrotate detail, journald statistics, plus systemd lifecycle, cron, UFW, logind, and more. Distro-aware (Ubuntu vs RHEL) with appropriate daemon names and paths.

**Command diversification:** Baseline process commands are parameterized with varied project paths, document names, build configurations, and per-user file references instead of fixed strings.

### DHCP Lease Events

Use `dhcp_lease` for rogue or new devices appearing on the network (e.g., attacker plugging in a device during physical access, or a compromised host requesting a new IP).

```yaml
- time: "+5m"
  actor: attacker
  system: ROGUE-LAPTOP
  activity: "Rogue device obtains IP via DHCP"
  events:
    - type: dhcp_lease
      mac_address: "00:50:56:a1:b2:c3"
      requested_ip: "10.10.10.99"
      technique: "T1200 - Hardware Additions"
```

Both `mac_address` and `requested_ip` are optional — the engine auto-generates a MAC from the system IP and uses the system's configured IP if omitted.

### Port Scan Events

Use `port_scan` for network reconnaissance, host sweeps, lateral scans, or worm-like propagation. Generates many firewall deny records (ASA 106023) from a single storyline step.

```yaml
- time: "+1h"
  actor: attacker
  system: WEB-EXT-01
  activity: "Port scan of server VLAN from compromised DMZ host"
  events:
    - type: port_scan
      target_segment: server_vlan     # Or target_ips: ["10.0.20.1", "10.0.20.2"]
      target_count: 20                # Sample 20 IPs from the segment
      ports: [22, 80, 443, 445, 3389]
      protocol: tcp
      scan_rate: 50                   # 50 connections/second
      technique: "T1046 - Network Service Discovery"
```

Fields: `target_ips` (explicit list) or `target_segment` + `target_count` (sample from CIDR). `ports` (default: [22, 80, 443, 445, 3389]). `protocol` (tcp/udp/icmp). `scan_rate` (connections/second, default: 100).

Denied connections are only visible to sensors on the source side of the firewall. The firewall's `drop_mode` controls whether Zeek sees `S0` (silent drop) or `REJ` (RST response).

### Blocked C2 Events

Use `blocked_c2` for malware beaconing that the firewall blocks. Generates periodic denied outbound connection attempts over a specified duration.

```yaml
- time: "+5h"
  actor: attacker
  system: DC-01
  activity: "Blocked C2 beaconing — firewall denies outbound from DC"
  events:
    - type: blocked_c2
      dst_ip: "198.51.100.30"
      dst_port: 443
      interval: "30m"                 # Try every 30 minutes
      duration: "12h"                 # Keep trying for 12 hours
      jitter: 0.2                     # ±20% variation on interval
      technique: "T1071.001 - Web Protocols"
```

Fields: `dst_ip` (C2 server), `dst_port` (default: 443), `interval` (time between attempts), `duration` (total beaconing period), `jitter` (0.0-1.0, default: 0.2).

### HTTP Connection Events

For web-based attack steps (SQL injection, web shell access, etc.), use `connection` with `service: http` and `dst_port: 80` instead of `raw`. This produces **correlated records** across web_access + zeek_http + zeek_conn — a `raw` event only targets one format.

```yaml
- time: "+1h10m"
  actor: attacker
  system: WEB-01
  activity: "SQL injection probe against EHR portal"
  events:
    - type: connection
      dst_ip: "10.10.20.10"
      dst_port: 80
      service: http
      source_ip: "203.0.113.45"
      method: "GET"
      uri: "/ehr/login.php?id=1%27%20OR%201=1--"
      status_code: 200
      user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)"
```

HTTP optional fields on `connection` events: `method` (GET/POST/etc.), `uri`, `status_code`, `user_agent`. When these are provided with `service: http`, the engine generates correlated web_access, zeek_http, and zeek_conn records from a single SecurityEvent.

### Raw Events

The `raw` event type targets a specific output format with arbitrary field data. Use it **only** for events not covered by the typed event specs above. Prefer typed events (especially `connection` for web access) because `raw` events bypass cross-source correlation — they produce a single log entry with no matching records in other formats.

```yaml
- time: "+2h"
  actor: attacker
  system: WEB-01
  activity: "Custom syslog entry"
  events:
    - type: raw
      target_format: syslog
      fields:
        hostname: WEB-01
        app_name: "apache2"
        pid: 1234
        facility: 3
        severity: 6
        message: "custom message here"
```

`target_format` must be a supported format name (e.g., `syslog`, `windows_event_security`, `ecar`, `zeek_conn`). The `fields` dict is passed directly to the target emitter without schema validation — ensure field names match the format's expected structure. The event's timestamp is automatically injected if not provided in `fields`.

### Correlated Events for Process Commands

When a `process` event declares a command that would produce additional audit events in a real environment, those correlated events should be explicitly declared in the same step's `events` list. This ensures complete, realistic log output regardless of what command is being run.

The table below shows common categories of commands and the correlated event types to declare alongside the `process` event:

| Command Category | Example Commands | Correlated Event Type |
|-----------------|------------------|----------------------|
| Account creation | `net user /add`, `useradd`, `New-ADUser`, `dsadd user` | `account_created` |
| Account deletion | `net user /delete`, `userdel`, `Remove-ADUser` | `account_deleted` |
| Group membership changes | `net group /add`, `net localgroup /add`, `Add-ADGroupMember`, `usermod -aG` | `group_member_added` |
| Service creation | `sc create`, `New-Service`, `systemctl enable` | `service_installed` |
| Scheduled task creation | `schtasks /Create`, `at`, `crontab -e`, `Register-ScheduledTask` | `scheduled_task_created` |
| Log clearing | `wevtutil cl`, `Clear-EventLog`, `rm /var/log/*` | `log_cleared` |
| Process injection | mimikatz `sekurlsa::`, reflective DLL injection, process hollowing | `create_remote_thread` |

This is not an exhaustive list -- any command that would produce a distinct audit trail should have its correlated events declared explicitly.

#### Engine Safety Net

The engine automatically infers correlated events for 6 common Windows command patterns when `supplementary: auto` (the default) is set on a process event:

| Command Pattern | Auto-Inferred Event |
|----------------|---------------------|
| `net user <name> /add` | 4720 (account created) |
| `net user <name> /delete` | 4726 (account deleted) |
| `net group "<group>" <user> /add` | 4728 (group member added) |
| `schtasks /Create /TN "<name>"` | 4698 (scheduled task created) |
| `sc create <name> binPath=` | 4697 (service installed) |
| `wevtutil cl Security` | 1102 (log cleared) |

This safety net catches common cases, but should not be relied upon as the primary mechanism -- always declare correlated events explicitly. If the same event type is already in the `events` list, auto-inference skips it (no duplicates). Set `supplementary: none` to disable auto-inference entirely.

### Best Practices

1. **Always declare the primary action explicitly** -- don't rely on inference for the main event
2. **Declare correlated events for process commands** -- if a command creates an account, installs a service, clears logs, etc., add the corresponding event type to the `events` list
3. **Explicitly declare cross-system events** -- inference cannot generate events on other systems (e.g., DC Kerberos for domain logon, RDP logon on target)
4. **Explicitly declare events when field precision matters** -- auto-inference uses auto-generated values (random SIDs); declare explicitly if SIDs must match across steps
5. **Use explicit events for specialized detection types** -- CreateRemoteThread, LSASS access; inference doesn't detect these patterns

### Examples

**Password spray + lateral movement:**
```yaml
- time: "+30m"
  actor: attacker
  system: WS-01
  activity: "Password spray against domain accounts"
  events:
    - type: failed_logon
      source_ip: "185.220.101.34"
    - type: failed_logon
      source_ip: "185.220.101.34"
    - type: logon
      source_ip: "185.220.101.34"
      logon_type: 3
```

**Process with explicit correlated events:**
```yaml
- time: "+1h"
  actor: attacker
  system: DC-01
  activity: "Create backdoor domain account"
  events:
    - type: process
      process_name: "C:\\Windows\\System32\\net.exe"
      command_line: "net user svc-audit P@ss! /add /domain"
    - type: account_created
      target_username: "svc-audit"
```

**Service persistence with correlated audit event:**
```yaml
- time: "+1h15m"
  actor: attacker
  system: WEB-01
  activity: "Install malicious service for persistence"
  events:
    - type: process
      process_name: "C:\\Windows\\System32\\sc.exe"
      command_line: "sc create evilsvc binPath= C:\\Windows\\Temp\\payload.exe start= auto"
    - type: service_installed
      service_name: "evilsvc"
      service_file_name: "C:\\Windows\\Temp\\payload.exe"
```

**Explicit cross-system events:**
```yaml
- time: "+1h30m"
  actor: attacker
  system: WEB-01
  activity: "SSH lateral movement to web server"
  events:
    - type: ssh_session
      source_ip: "10.20.10.13"
```

## Output

```yaml
output:
  logs:
    - format: windows
    - format: zeek
    - format: ecar
  destination: ./output
  compression: false           # Optional (default: false)
```

Supported formats: `windows`, `zeek`, `ecar`, `syslog`, `bash_history`, `snort_alert`, `cisco_asa`, `web_access`, `proxy`.

## Backward Compatibility

Persona fields are optional with null defaults:
- `expanded_activities`, `work_hours_parsed`, `activity_intensity` default to null
- `work_hours_parsed` is auto-populated from the `work_hours` string if not explicitly provided

**Breaking change (Phase 8.4):** The `events` field on storyline entries is now required. The old `details` dict and `event_sequence` fields have been removed. All storyline entries must use the typed `events` list format.

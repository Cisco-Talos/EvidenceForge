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
  groups: [...]               # Optional
```

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
    primary_system: WS-01      # Optional: reference to system hostname
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
| `process_access` | Sysmon 10, eCAR PROCESS/OPEN | `target_process` | `granted_access` (default `0x1010`) |
| `dhcp_lease` | Zeek dhcp.log | | `mac_address`, `requested_ip` |
| `raw` | Any single format | `target_format`, `fields` | |

All event types also accept optional `technique` (MITRE ATT&CK ID) and `description` (human-readable detail) fields for GROUND_TRUTH.md enrichment.

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

Supported formats: `windows`, `zeek`, `ecar`, `syslog`, `bash_history`, `snort_alert`, `web_access`, `proxy_access`.

## Backward Compatibility

Persona fields are optional with null defaults:
- `expanded_activities`, `work_hours_parsed`, `activity_intensity` default to null
- `work_hours_parsed` is auto-populated from the `work_hours` string if not explicitly provided

**Breaking change (Phase 8.4):** The `events` field on storyline entries is now required. The old `details` dict and `event_sequence` fields have been removed. All storyline entries must use the typed `events` list format.

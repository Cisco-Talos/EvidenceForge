---
description: "Scenario Schema Reference"
---

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

`primary_system` is operationally important, not just descriptive. The compiled world model uses it to place the user's interactive activity, choose realistic remote-admin source hosts, and decide when server activity should be modeled as SSH/RDP/network access instead of a local console session.

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

`roles` and `services` materially affect realism. They feed the compiled world model that drives infrastructure discovery, proxy routing, legitimate lateral-movement patterns, and whether remote access should look like SSH, RDP, or generic network activity.

### Proxy Deployment

```yaml
proxy:
  mode: transparent              # Optional: transparent|explicit (default: transparent)
  listener_port: 8080            # Optional: explicit-mode proxy listener (default: 8080)
```

`environment.proxy` controls how systems with `roles: [forward_proxy]` appear in network evidence:

- `transparent` preserves direct-looking client-to-origin Zeek/IDS traffic while still generating proxy access logs.
- `explicit` models PAC/browser-configured proxy behavior by replacing the logical client-to-origin connection with two concrete legs: client-to-proxy on `listener_port`, then proxy-to-origin on the destination port. Sensor placement determines which leg each Zeek/IDS/firewall source sees. Denied proxy requests stop at the proxy and do not emit a proxy-to-origin leg.

If `proxy_access` is requested and `environment.proxy` is omitted, validation warns and defaults to `transparent`. If `mode: explicit` is set without `listener_port`, validation warns and defaults to `8080`.

### System Roles

The `roles` field declares a system's function in the network. The engine uses roles to generate both **outbound** traffic (connections the host initiates) and **inbound** traffic (connections the host receives):

- `web_server` — outbound: database queries, LDAP auth, API calls; inbound: HTTPS/HTTP from external clients and internal users
- `database` — outbound: replication, updates; inbound: SQL queries from web/app servers
- `mail_server` — outbound: SMTP relay, LDAP lookups; inbound: SMTP from internet, webmail from users
- `file_server` — outbound: Kerberos/LDAP auth; inbound: SMB file access from workstations. File-server roles also increase baseline SMB target selection beyond normal DC SYSVOL/GPO traffic.
- `domain_controller` — outbound: inter-DC replication; inbound: Kerberos/LDAP/DNS from all hosts
- `forward_proxy` — routes outbound HTTP/HTTPS traffic through this system; generates proxy access logs with CONNECT entries for HTTPS, cache hit/miss status, and full destination URLs
- `dns_server` — DNS resolution target

Inbound traffic is constrained by network topology: DMZ hosts receive substantial external traffic, while internal servers only receive connections from other internal systems. The firewall policy determines what gets permitted vs denied — denied connection attempts still produce firewall deny records and source-side sensor visibility.

For server and infrastructure hosts, pair `roles` with realistic `services` whenever possible. `roles` tell the engine what the host is for; `services` help the world model infer concrete protocols and destinations (for example, PostgreSQL vs MSSQL, web stack vs proxy stack, SSH-capable Linux admin targets, and so on).

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
      placement: span           # span mirrors segment traffic | tap observes uplink/boundary traffic
      log_formats: [zeek]       # Format groups or individual formats
```

`span` sensors can see traffic where either endpoint belongs to a monitored segment, including same-segment traffic. `tap` sensors do not see same-segment traffic. When a TAP monitors multiple internal segments, internal cross-segment traffic is visible only if both endpoint segments are monitored; external/boundary traffic remains visible when either side is monitored.

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
      nat_rules:
        - type: dynamic_pat
          src: [workstations, servers]
          mapped_ip: 45.83.220.1
        - type: static
          real_ip: 172.16.0.5
          mapped_ip: 45.83.220.5
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

#### Public Address Space

The `public_cidrs` field on `NetworkConfig` declares the org's public IP address blocks. External scan/probe traffic targets these ranges instead of internal IPs, and legitimate inbound connections use VIPs (static NAT `mapped_ip` values) as the wire-level destination.

```yaml
network:
  public_cidrs: ["45.83.220.0/28"]  # Optional — auto-derived from VIPs if omitted
  segments: [...]
  sensors: [...]
```

**Auto-derivation:** When `public_cidrs` is empty, VIPs from static NAT rules are grouped by /24 prefix to create scan target ranges. For example, VIPs `45.83.220.10` and `45.83.220.14` produce `["45.83.220.0/24"]`.

**Inbound traffic flow:** External clients connect to VIPs (public IPs). The NAT engine translates to real (internal) IPs per sensor — outside Zeek sees VIPs, inside Zeek sees real IPs, ASA shows both in Built/Teardown records.
- Rules are evaluated in order; first match wins (like real ACLs)
- Traffic not matching any rule is subject to `default_action`

**Interfaces**: Map segment names to ASA interface names (e.g., `inside`, `outside`, `dmz`). IPs not in any mapped segment resolve to `"outside"`.

**Threat detection**: The ASA emitter automatically tracks per-source-IP deny rates and fires 733100 alerts when both burst (default 10 drops/sec over 20s) and average (default 5 drops/sec over 60s) thresholds are exceeded. Set `threat_detection_rate: 0` to disable.

**NAT rules**: Define Network Address Translation behavior for the firewall. Each rule in the `nat_rules` list supports:
- `type`: `dynamic_pat` (many:1 with port translation) or `static` (1:1 IP mapping)
- `src`: segment name(s), IP, or CIDR. Accepts a string or list.
- `mapped_ip`: the post-NAT IP address
- `real_ip`: for static NAT, the specific internal IP being mapped

Dynamic PAT: all traffic from matching segments shares one external IP with port translation. Static NAT: bidirectional 1:1 mapping, enables inbound connections to DMZ servers via public IP. NAT only applies to permitted connections that cross segment boundaries; denied connections are not NATted.

### Database Service Routing

When a system has the `database` role, the engine determines the DB protocol from `services`:

- `services: [postgresql]` → PostgreSQL on port 5432
- `services: [mysql]` or `services: [mariadb]` → MySQL on port 3306
- `services: [mssql]` or `services: [sqlserver]` → MSSQL on port 1433

When `services` is empty, the engine infers from OS: **Linux → PostgreSQL**, **Windows → MSSQL**. Traffic generation only routes database connections to hosts running the matching DB engine — a PostgreSQL host never receives MSSQL traffic, even in mixed-DB environments.

### External Inbound Requirements

External inbound traffic requires the target host to be reachable from the internet:

- **Hosts with static NAT VIP** → External clients connect to the VIP; NAT translates per sensor
- **Hosts with a public IP** (non-RFC1918, e.g., cloud) → External clients connect directly
- **RFC1918 hosts without a VIP** → External inbound is silently skipped (unreachable)

If a system needs external inbound traffic, either configure a static NAT rule with `mapped_ip` or assign it a public IP address.

### Session Management

The engine manages user sessions with exact transport-type matching. When a storyline or baseline requests a session on a host, the engine:

1. Checks for an existing session with the **exact** `session_kind` (interactive, network, ssh, rdp)
2. If no match, creates a new session with the appropriate transport evidence (SSH syslog, RDP 4624 type 10, etc.)

Built-in accounts (SYSTEM, LOCAL SERVICE, NETWORK SERVICE) and service accounts always use local system sessions — they never fabricate remote logon evidence.

Sessions marked as `storyline_protected` (by storyline events that depend on them) are immune to baseline logoff, even if logoff was already planned for the same hour.

### Baseline Failed Logon Noise

The engine automatically generates realistic failed logon patterns without scenario configuration:

- **Password typos** (~5% of interactive logons): 1-2 failed attempts (4625) immediately before a successful logon (4624) for the same user. Simulates mistyped complex passwords.
- **Stale scheduled tasks**: Periodic failed batch logons (type 4) from plausible service accounts on deterministic hosts. Fires every 1-2 hours, representing forgotten tasks with expired credentials.
- **Management software sweeps**: 1-2 times per business day, a management tool tries a disabled credential across 5-15 servers in quick succession. All fail with "account disabled."

These patterns augment the explicit `stale_accounts` feature, which generates additional failures from accounts you define. Together they produce a realistic ratio of failed-to-successful authentication events.

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

### Browsing Intensity

The `browsing_intensity` field controls how much HTTP traffic a persona generates per browsing session. It affects proxy log depth (number of page loads and subresource cascades) for baseline web activity.

```yaml
personas:
  - name: developer
    browsing_intensity: normal    # Optional: light | normal | heavy (default: "normal")
```

| Value | Behavior |
|-------|----------|
| `light` | 1 page load, few subresources (CSS, 1-2 images) |
| `normal` | 1-2 page loads, typical subresource cascade |
| `heavy` | 2-4 page loads, full subresource cascades (JS, CSS, images, fonts, API calls) |

Available on persona definitions and as a per-user override on user entries. Per-user override takes precedence over the persona default:

```yaml
users:
  - username: marcus.chen
    persona: developer
    browsing_intensity: heavy    # Overrides developer persona's default
    primary_system: WS-DEV-01
```

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
  warmup: "8h"                     # Optional (default "8h"). Minimum 1 hour.
```

The `warmup` field controls a pre-generation phase that runs *before* `start` to pre-populate
internal state (DNS cache, process trees, active sessions, Kerberos tickets, Hawkes timing kernels).
Events generated during warm-up update state but are **not** written to output files. This makes
the first minutes of output look like a running system rather than a cold start. Minimum 1 hour;
default 8 hours covers a full day/night transition for maximum realism.

All `storyline` and `red_herrings` times should fall inside the configured `time_window`. For
example, if the final storyline step is scheduled at `+36h`, set `duration` longer than 36 hours
so baseline logs, proxy/firewall evidence, and attack traces cover the same collection horizon.
`eforge validate` warns when a storyline step falls outside the window.

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
| `logon` | 4624, target-host 4672 for elevated sessions, eCAR LOGIN | | `logon_type` (default 3), `source_ip` |
| `failed_logon` | 4625, eCAR LOGIN failure | | `source_ip`, `logon_type` (default 3) |
| `logoff` | 4634, eCAR LOGOUT | | |
| `connection` | Zeek conn, eCAR FLOW, + web_access/zeek_http when `service: http` | `dst_ip` | `dst_port` (default 443), `hostname` (domain for DNS/SSL SNI), `service`, `source_ip`, `method`, `uri`, `status_code`, `user_agent` |
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
| `port_scan` | ASA 106023 (bulk denies) | `target_ips` or `target_segment` | `source_ip`, `target_count`, `ports`, `protocol`, `scan_rate` |
| `beacon` | Zeek conn/proxy/ASA (periodic connections) | `dst_ip`, `interval`, one of `end_time`/`duration`/`count` | `action` (allow/deny), `hostname`, `service`, `protocol`, `source_ip`, `method`, `uri`, `user_agent`, `referrer`, `status_code`, `orig_bytes`, `resp_bytes`, `jitter` (default: 0.15) |
| `dns_query` | Zeek dns.log + conn.log, Sysmon 22 | `query` | `qtype`, `rcode`, `ttl`, `answer` (required for NOERROR), `source_ip` |
| `web_scan` | web_access + Zeek HTTP (bulk HTTP requests) | `dst_ip`, `rate`, one of `end_time`/`duration`/`count` | `preset` (nikto/dirb/gobuster/sqlmap/nmap_http), `paths`, `hostname`, `user_agent`, `jitter` (default: 0.4) |
| `credential_spray` | Windows 4625/4776 or syslog auth | `target_accounts`, `interval`, one of `end_time`/`duration`/`count` | `pattern` (spray/brute_force/stuffing), `source_ip`, `logon_type`, `success`, `jitter` (default: 0.5) |
| `dga_queries` | Zeek dns.log + conn.log (bulk DGA) | `interval`, one of `end_time`/`duration`/`count` | `length_range`, `charset`, `tld`, `seed`, `rcode_distribution`, `answer_ip`, `source_ip`, `jitter` (default: 0.3) |
| `dns_tunnel` | Zeek dns.log + conn.log (encoded exfil) | `base_domain`, `interval`, one of `end_time`/`duration`/`count` | `encoding` (base32/base64/hex), `qtype` (TXT/NULL/CNAME), `label_length`, `payload`, `payload_size`, `source_ip`, `jitter` (default: 0.25) |
| `explicit_credentials` | Windows 4648 (explicit credential usage) | `target_username` | `target_server`, `process_name`, `source_ip` |
| `workstation_lock` | Windows 4800 (workstation locked) | | |
| `workstation_unlock` | Windows 4801 + 4624 type 7 (unlock + re-auth) | | |
| `raw` | Any single format | `target_format`, `fields` | |

For `process` events, prefer full process image paths when you know them. Bare executable names are accepted and are normalized through the configured application/process catalog during generation. If a scenario needs a custom install path, add or update the relevant configuration overlay rather than putting an ad hoc path in one storyline event.

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
| `logon` (Kerberos auth, Windows, not on DC) | Kerberos TGT (4768) + TGS (4769) on DC | TGT 50-200ms before, TGS 20-100ms after TGT. Elevated-session 4672 is emitted with the target-host 4624. |
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

**Compiled world model:** Before generation starts, the engine compiles authoritative host and user capabilities from `primary_system`, `assigned_user`, `roles`, and `services`. That model is then used to place user activity, choose realistic SSH/RDP/network session types, and keep baseline/storyline session bootstrap behavior aligned.

**Network-level red herrings:** The suspicious noise generator includes network-layer patterns: high-entropy DNS queries (CDN subdomains, DoH providers), unusual outbound connections (cloud backup sync, dev tool endpoints), and scheduled vulnerability scan overlaps. Controlled by `baseline_activity.suspicious_noise` level.

**Entity lifecycle validation:** The engine validates that process injection events target existing PIDs and that event timestamps don't precede system boot times. Warnings are logged for impossible sequences.

**Process→network correlation:** Baseline processes that normally generate network traffic (browsers, Office, dev tools, DB clients) automatically emit corresponding connections (HTTPS, SQL, SSH) 50-500ms after process creation, with the process PID carried for cross-source correlation.

**Storyline process+connection pairing:** When a storyline process command line references a domain (e.g., `Invoke-WebRequest -Uri 'https://cdn-assets-update.com/...'`), pair it with a `connection` event that sets `hostname` to ensure the domain appears in DNS, SSL, HTTP, and proxy logs. The `hostname` field on `connection` and `beacon` events should be the client-facing DNS name the endpoint actually resolved and sent in HTTP Host, TLS SNI, or proxy CONNECT metadata. Avoid reverse-DNS/PTR artifacts or provider-generated infrastructure names unless the scenario intentionally models the client using that name. Omit `hostname` for raw-IP C2 (no DNS lookup expected). For realism-bound generated datasets, avoid using reserved documentation domains (`example.com`, `example.net`, `example.org`) as live public infrastructure; use a scenario-owned lab domain or realistic non-reserved domain when public resolver answers and certificates should appear. The validator will warn about unmatched domains.

**NTP time synchronization:** In AD environments, all domain-joined workstations sync NTP from the domain controller (W32Time service), not from external NIST servers. NTP stratum is stable per server — a DC serving as NTP always reports the same stratum value. External NTP servers are only used for non-domain environments.

**Multi-sensor timing realism:** When multiple Zeek sensors observe the same connection, each sensor's records have a deterministic propagation delay (100-500 microseconds) based on the sensor's position. Sensors farther from the packet source see events slightly later. Byte and packet counts are identical across sensors (both see the same packets on the wire), but timestamps and durations differ.

**Linux syslog depth:** Linux hosts generate 18 categories of syslog messages: SSH login/key exchange (70% key / 30% password), package management, systemd timer execution, logrotate detail, journald statistics, plus systemd lifecycle, cron, UFW, logind, and more. Distro-aware (Ubuntu vs RHEL) with appropriate daemon names and paths.

**Command diversification:** Baseline process commands are parameterized with varied project paths, document names, build configurations, and per-user file references instead of fixed strings.

**Realistic process trees:** Parent-child relationships are driven by `spawn_rules.yaml`, which defines valid parent processes for each child executable. CLI tools (dotnet.exe, git.exe, npm.exe, etc.) are parented from shells (cmd.exe, powershell.exe), GUI apps from explorer.exe, and system services from services.exe/svchost.exe. When a valid parent doesn't exist in the user's process history, the engine auto-creates the intermediate chain with realistic timing. Linux processes follow sshd→bash→command chains. Sysmon Event 1 `ParentCommandLine` is populated from the parent process's actual command line (no longer always "-").

**PID allocation:** Windows PIDs use a lognormal distribution for gap sizes (mu=1.2, sigma=0.8), producing mostly small gaps with an occasional heavy tail — simulating background process churn consuming PIDs between emitted events. Linux PIDs use a similar but tighter distribution (mu=0.5, sigma=0.6). No fixed choice-set fingerprint.

**Per-user bash history:** Baseline SSH sessions to Linux servers generate organic admin commands (ls, df -h, ps aux, systemctl status, etc.) for realistic admin users, creating per-user `<username>.bash_history` files on all Linux hosts. Storyline process events on Linux inject 0-3 organic noise commands around each attack command for realistic interleaving.

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

Both `mac_address` and `requested_ip` are optional — the engine auto-generates a MAC (using diversified OUI prefixes from `network_params.yaml`) from the system IP and uses the system's configured IP if omitted. DHCP events include NetworkContext for proper sensor routing. DHCP broadcast is link-local in the generator: it appears on SPAN-style Zeek sensors monitoring the client's segment and does not traverse unrelated TAP/firewall boundaries unless a separate relay/server transaction is modeled.

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

Fields: `source_ip` (override scan source; default: uses storyline system IP — useful for external attacker scans). `target_ips` (explicit list) or `target_segment` + `target_count` (sample from CIDR). `ports` (default: [22, 80, 443, 445, 3389]). `protocol` (tcp/udp/icmp). `scan_rate` (connections/second, default: 100).

Denied connections are only visible to sensors on the source side of the firewall. The firewall's `drop_mode` controls whether Zeek sees `S0` (silent drop) or `REJ` (RST response).

### Beacon Events

Use `beacon` for periodic connections — allowed (C2 callbacks through proxy) or denied (firewall-blocked beaconing). Replaces the former `blocked_c2` type.

```yaml
# Allowed beacon through proxy
- time: "+3h"
  actor: attacker
  system: workstation01
  activity: "C2 beacon to attacker infrastructure"
  events:
    - type: beacon
      dst_ip: "45.83.221.30"
      dst_port: 443
      hostname: "cdn-analytics.example.com"
      interval: "5m"
      duration: "7d"
      jitter: 0.2
      action: allow
      technique: "T1071.001 - Web Protocols"

# Denied beacon (equivalent to former blocked_c2)
- time: "+5h"
  actor: attacker
  system: DC-01
  activity: "Blocked C2 beaconing — firewall denies outbound from DC"
  events:
    - type: beacon
      dst_ip: "45.83.221.30"
      dst_port: 443
      interval: "30m"
      duration: "12h"
      jitter: 0.2
      action: deny
      technique: "T1071.001 - Web Protocols"
```

Timing fields: `start_time` (optional, defaults to parent event time), `interval` (required), one of `end_time`/`duration`/`count` (required), `jitter` (0.0-1.0, default: **0.15** — beacons are deliberately tight). Connection fields: all `connection` fields (dst_ip, dst_port, hostname, service, protocol, method, uri, user_agent, `referrer`, etc.). For `hostname`, use the client-facing DNS name used by the beacon, not a reverse-DNS/PTR artifact, unless that is intentionally part of the scenario. `action`: `allow` (default) or `deny`. Set `referrer` to pin the HTTP Referer header for a specific beacon URL (e.g., a phishing page that launched the download). In explicit proxy mode, HTTP/S beacons from hosts routed through a `forward_proxy` traverse the proxy; denied proxyable beacons stop at the proxy and emit proxy-denied CONNECT/GET evidence rather than direct client-to-origin network evidence.

### DNS Query Events

Use `dns_query` for standalone DNS lookups with full control over query parameters. Unlike the automatic DNS expansion on `connection` events, this type lets you specify exact query type, response code, TTL, and answer. Useful for DNS-based reconnaissance, cache poisoning indicators, or any scenario where the DNS query itself is the story.

```yaml
- time: "+1h"
  actor: marcus.chen
  system: WS-DEV-01
  activity: "DNS reconnaissance — query for mail server"
  events:
    - type: dns_query
      query: "mail.example.com"
      qtype: MX
      rcode: NOERROR
      answer: "10 smtp.example.com"
      technique: "T1018 - Remote System Discovery"
```

Fields:
- `query` (required): Domain name to query
- `qtype` (default: `A`): Query type — `A`, `AAAA`, `TXT`, `CNAME`, `MX`, `NULL`, `SRV`, `PTR`
- `rcode` (default: `NOERROR`): Response code — `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`
- `ttl` (optional): Response TTL (auto-generated if omitted)
- `answer` (required when `rcode=NOERROR`): Response value(s) — string or list of strings
- `source_ip` (optional): Querying host IP (default: storyline system IP)

### Web Scan Events

Use `web_scan` for automated web scanning attacks (Nikto, DirBuster, Gobuster, SQLMap, Nmap HTTP). Generates high-volume HTTP requests with scanner-realistic patterns, user agents, and status code distributions. Each request produces correlated web_access + Zeek HTTP + Zeek conn records.

```yaml
- time: "+3h"
  actor: SYSTEM
  system: WEB-01
  activity: "Nikto scan against web server from external attacker"
  events:
    - type: web_scan
      dst_ip: "10.10.20.10"
      dst_port: 80
      hostname: "portal.example.com"
      source_ip: "104.248.71.33"
      preset: nikto
      rate: 10                        # 10 requests/second
      duration: "15m"
      technique: "T1595.002 - Active Scanning: Vulnerability Scanning"
```

Fields:
- `dst_ip` (required): Target web server IP
- `dst_port` (default: 80): Target port
- `hostname` (optional): Target domain name
- `source_ip` (optional): Override scanner source IP
- `preset` (optional): Scanner preset — `nikto`, `dirb`, `gobuster`, `sqlmap`, `nmap_http`
- `paths` (optional): Custom URI path list — `[{uri: "/admin", method: "GET", status: 403}]`
- `user_agent` (optional): Override the preset's default user agent
- `status_codes` (optional): Override status code distribution (e.g., `{"404": 0.7, "200": 0.2, "403": 0.1}`)
- `rate` (required): Average requests per second. With `duration`/`end_time`, the engine applies deterministic per-campaign throughput drift so repeated scans with the same nominal rate do not produce identical request totals. With explicit `count`, the count remains exact.
- `duration` / `count` / `end_time`: Termination condition (exactly one required)
- `jitter` (default: **0.4**): Timing variation — wide variance reflects real-world latency jitter from target server response times

Either `preset` or `paths` (or both) must be specified.

### Credential Spray Events

Use `credential_spray` for bulk authentication attacks — password spraying, brute force, or credential stuffing. Generates realistic sequences of failed logon events (Windows 4625/4776 or Linux syslog auth failures) with an optional final successful logon.

```yaml
- time: "+2h"
  actor: SYSTEM
  system: DC-01
  activity: "Password spray against domain accounts"
  events:
    - type: credential_spray
      source_ip: "185.220.101.34"
      pattern: spray
      target_accounts: ["marcus.chen", "priya.patel", "sarah.oconnell", "diego.ramirez"]
      logon_type: 3
      interval: "2s"
      duration: "10m"
      success:
        account: "priya.patel"
        after: 8                      # Succeed after 8 failures
      technique: "T1110.003 - Brute Force: Password Spraying"
```

Fields:
- `target_accounts` (required): List of target usernames
- `source_ip` (optional): Attacker source IP
- `pattern` (default: `spray`): Attack pattern — `spray` (one password per account), `brute_force` (many passwords per account), `stuffing` (one-to-one credential pairs)
- `logon_type` (default: 3): Windows logon type for the attempts
- `success` (optional): Final successful logon — `{account: "username", after: N}` where `N` is number of failures before success
- `interval` (required): Time between attempts
- `duration` / `count` / `end_time`: Termination condition (exactly one required)
- `jitter` (default: **0.5**): Timing variation — high default reflects self-pacing behavior to evade lockout policies

### DGA Query Events

Use `dga_queries` for domain generation algorithm (DGA) traffic — algorithmically generated DNS lookups that mostly return NXDOMAIN. Used for botnet/DGA detection training.

```yaml
- time: "+4h"
  actor: SYSTEM
  system: WS-DEV-01
  activity: "DGA beaconing from infected workstation"
  events:
    - type: dga_queries
      interval: "500ms"
      duration: "2h"
      jitter: 0.3
      tld: ".com"
      length_range: [10, 15]
      seed: 42
      rcode_distribution:
        NXDOMAIN: 0.95
        NOERROR: 0.05
      answer_ip: "45.83.221.99"
      technique: "T1568.002 - Dynamic Resolution: Domain Generation Algorithms"
```

Fields:
- `length_range` (default: `[8, 15]`): Min/max domain label length (1-63)
- `charset` (default: lowercase alphanumeric): Character set for domain generation
- `tld` (default: `.com`): Top-level domain suffix
- `seed` (optional): Deterministic seed for reproducible domain sequences
- `rcode_distribution` (optional): Response code probabilities (must sum to ~1.0) — e.g., `{"NXDOMAIN": 0.95, "NOERROR": 0.05}`
- `answer_ip` (required when NOERROR > 0): IP address for successful resolutions
- `source_ip` (optional): Override querying host IP
- `interval` (required): Time between queries
- `duration` / `count` / `end_time`: Termination condition (exactly one required)
- `jitter` (default: **0.3**): Timing variation

### DNS Tunnel Events

Use `dns_tunnel` for data exfiltration via encoded DNS subdomain labels. Generates DNS queries with encoded payload chunks as subdomains (e.g., `aGVsbG8gd29ybGQ.tunnel.evil.com`). Useful for DNS exfiltration detection training.

```yaml
- time: "+6h"
  actor: marcus.chen
  system: WS-DEV-01
  activity: "DNS tunneling exfiltration of stolen credentials"
  events:
    - type: dns_tunnel
      base_domain: "ns1.cdn-analytics.net"
      encoding: base64
      qtype: TXT
      label_length: 30
      payload_size: 512
      interval: "2s"
      duration: "30m"
      jitter: 0.1
      technique: "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"
```

Fields:
- `base_domain` (required): Tunnel endpoint domain — encoded chunks become subdomains of this
- `encoding` (default: `hex`): Encoding scheme — `base32`, `base64`, `hex`
- `qtype` (default: `TXT`): DNS query type — `TXT`, `NULL`, `CNAME`
- `label_length` (default: 30): Max length of each encoded subdomain label (1-63)
- `payload` (optional): Fixed payload string to encode and exfiltrate
- `payload_size` (default: 256): Random payload size in bytes if no `payload` specified
- `source_ip` (optional): Override querying host IP
- `interval` (required): Time between queries
- `duration` / `count` / `end_time`: Termination condition (exactly one required)
- `jitter` (default: **0.25**): Timing variation

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
      source_ip: "104.248.71.33"
      method: "GET"
      uri: "/ehr/login.php?id=1%27%20OR%201=1--"
      status_code: 200
      user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)"
```

HTTP optional fields on `connection` events: `method` (GET/POST/etc.), `uri`, `status_code`, `user_agent`, `referrer`. When these are provided with `service: http`, the engine generates correlated web_access, zeek_http, and zeek_conn records from a single SecurityEvent. The `referrer` field defaults to `null` (auto-generated from the traffic context — search engine, same-origin, social, or blank); set it explicitly for phishing click scenarios or specific referrer chain modeling (e.g., `referrer: "https://evil.example.com/page"`). The same `referrer` field is available on `beacon` events.

**Byte and connection state overrides:** `orig_bytes` (originator payload bytes), `resp_bytes` (responder payload bytes), `conn_state` (Zeek connection outcome: SF, S0, REJ, etc.). When omitted, the engine auto-sizes bytes based on the event's `technique` and `description` fields (exfiltration -> large `orig_bytes`; C2 -> small bidirectional; download -> large `resp_bytes`), and defaults `conn_state` to SF. Set `conn_state` explicitly to model failed connections (e.g., `S0` for a dead C2 channel, `REJ` for a blocked exfil attempt).

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

Supported formats: `windows`, `zeek`, `ecar`, `syslog`, `bash_history`, `snort_alert`, `cisco_asa`, `web_access`, `proxy_access`.

`proxy_access` requires at least one system with `roles: [forward_proxy]`. If it is requested without a forward proxy system, validation warns because no proxy access log file will be generated. When proxy logs are requested, add `environment.proxy.mode` to make transparent vs explicit proxy semantics clear. Current proxy behavior assumes TLS interception, so HTTPS can include CONNECT plus inspected request rows; non-intercepting tunnel-only proxy behavior is deferred.

#### Format Filtering

The `output.logs` list can be scoped to only needed formats for faster generation with long time windows. For example, a 30-day baseline exercise that only needs Zeek conn.log can declare just `format: zeek_conn` instead of the full `zeek` group.

The `--formats` CLI flag provides runtime filtering without modifying the scenario YAML. It intersects with `output.logs` — only formats present in both are generated. Group names (`zeek`, `windows`) are expanded before intersection.

## Backward Compatibility

Persona fields are optional with null defaults:
- `expanded_activities`, `work_hours_parsed`, `activity_intensity` default to null
- `work_hours_parsed` is auto-populated from the `work_hours` string if not explicitly provided

**Breaking change (Phase 8.4):** The `events` field on storyline entries is now required. The old `details` dict and `event_sequence` fields have been removed. All storyline entries must use the typed `events` list format.

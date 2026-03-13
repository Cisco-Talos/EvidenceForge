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
```

## Personas

Personas define user behavior patterns for activity generation.

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
  duration: "8h"                   # Supports: "10h", "3d", "2h30m"
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

Storyline events define specific actions at specific times.

```yaml
storyline:
  - time: "+2h30m"             # Required: ISO 8601, relative offset, or seconds
    actor: john.doe            # Required: username, built-in account (SYSTEM/root), or service_account
    system: WS-01              # Required: system hostname
    activity: "lateral movement"  # Required: activity description
    details:                   # Optional: activity-specific details
      target_ip: "10.0.1.20"
      method: "pass-the-hash"
```

### Phase 2.4+ Optional Fields

```yaml
storyline:
  - time: "+2h30m"
    # ... Phase 1 fields above ...

    event_sequence:            # Phase 2.4+: Multi-step sub-events
      - sub_event_type: process
        delay_seconds: 5
        details:
          process_name: powershell.exe
      - sub_event_type: file
        delay_seconds: 10
        details:
          file_path: C:\temp\payload.exe

    duration: "30m"            # Phase 2.4+: Event duration
    success_probability: 0.8   # Phase 2.4+: 0.0-1.0
    retry_on_failure: true     # Phase 2.4+: Retry flag
```

**event_sequence** items must have:
- `sub_event_type` (required): Type of sub-event (e.g., process, file, network)
- `delay_seconds` (optional): Delay before this sub-event
- `details` (optional): Sub-event-specific details

## Output

```yaml
output:
  logs:
    - format: windows_event_security
    - format: zeek_conn
    - format: ecar
  destination: ./output
  compression: false           # Optional (default: false)
```

Supported formats: `windows_event_security`, `zeek_conn`, `ecar`, `syslog`, `bash_history`, `snort_alert`, `web_access`.

## Backward Compatibility

All Phase 2.4+ fields are optional with null defaults. Existing Phase 1 scenarios work without modification:
- `expanded_activities`, `work_hours_parsed`, `activity_intensity` default to null
- `event_sequence`, `duration`, `retry_on_failure`, `success_probability` default to null
- `work_hours_parsed` is auto-populated from the `work_hours` string if not explicitly provided

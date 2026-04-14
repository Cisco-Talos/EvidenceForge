# Format Definition Configuration Reference

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

Schema documentation for log format definition files in `src/evidenceforge/config/formats/`.

---

## Overview

Each format file defines the schema for one log output type. These are standalone files with no cross-file dependencies (except evaluation rules reference their field names). There are 22 format definitions covering:

| Category | Formats |
|----------|---------|
| Windows | `windows_event_security`, `windows_event_sysmon` |
| Zeek (Network) | `zeek_conn`, `zeek_dns`, `zeek_http`, `zeek_ssl`, `zeek_x509`, `zeek_files`, `zeek_dhcp`, `zeek_ntp`, `zeek_ocsp`, `zeek_pe`, `zeek_packet_filter`, `zeek_reporter`, `zeek_weird` |
| Other Network | `snort_alert`, `cisco_asa`, `proxy_access`, `web_access` |
| Host (Linux) | `syslog`, `bash_history` |
| EDR | `ecar` |

## Schema

```yaml
name: zeek_conn                              # Format identifier
version: "1.0"                               # Schema version
description: "Zeek conn.log format"          # Human-readable description
category: network                            # Category: network, host, edr

fields:
  - name: ts                                 # Field name in output
    type: timestamp                          # Data type
    required: true                           # Required in every record
    description: "Timestamp of connection"   # Human-readable description

  - name: uid
    type: string
    required: true
    description: "Unique connection ID"
    constraints:                             # Optional validation constraints
      pattern: "^[A-Za-z0-9]{17,19}$"

  - name: id.orig_p
    type: port
    required: true
    description: "Originator port"
    constraints:
      min: 0
      max: 65535
```

## Field Types

| Type | Description | Example |
|------|-------------|---------|
| `timestamp` | ISO 8601 or epoch timestamp | `1609459200.000000` |
| `string` | Free-text string | `"Cqt7c92LCc2q0m5Nj"` |
| `ip_address` | IPv4 or IPv6 address | `"192.168.1.100"` |
| `port` | Port number (0-65535) | `443` |
| `integer` | Whole number | `4624` |
| `float` | Decimal number | `0.003` |
| `boolean` | True/false | `true` |
| `enum` | One of a fixed set of values | `"tcp"` |

## Constraint Types

| Constraint | Applies To | Description |
|-----------|------------|-------------|
| `pattern` | string | Regex pattern the value must match |
| `min` / `max` | integer, float, port | Value range |
| `values` | enum | List of allowed values |
| `min_length` | string | Minimum string length |

## Conventions

- Format names use snake_case matching the output file prefix
- Fields are listed in the order they appear in the output
- The `required: true` fields must be present in every generated record
- Optional fields may be omitted or set to `"-"` (Zeek convention) when not applicable
- `constraints:` are used by the evaluation engine, not enforced during generation

## When to Modify Format Files

Format definitions rarely need modification. Common reasons:
- Adding support for a new Zeek log type → create a new format file
- Adding a field that the engine now generates → add field definition
- Correcting field constraints for evaluation accuracy → update constraints

After modifying, check `evaluation/co_occurrence.yaml` and `evaluation/distributions.yaml` for rules that reference the changed fields.

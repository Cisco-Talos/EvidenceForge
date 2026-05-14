# Config Validation Checks Reference

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

Checks for verifying config file integrity. Run via the config skill's validation operation ("validate config files", "check config", etc.) or automatically after edits (scoped to affected files).

Run `eforge info <field>` to get specific values (e.g., `eforge info paths.activity`, `eforge info overlay.exists`). Run `eforge info --fields` to see all available fields. Use `eforge info --json` if you need everything at once.

## YAML Health (run first — blocks all others)

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 1 | YAML parse errors | ERROR | File doesn't parse as valid YAML |
| 2 | Empty files | ERROR | YAML file exists but has no content |

## DNS Registry Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 3 | Duplicate domains | ERROR | Same domain listed more than once |
| 4 | Empty tags | ERROR | Domain entry with missing or empty `tags:` list |
| 5 | Empty IPs | ERROR | Domain entry with missing or empty `ips:` list |
| 6 | Invalid tags | WARNING | Tag not in the valid set (web, saas, cdn, email, git, background, windows, linux, internal, storage, dev, social) |
| 7 | Orphaned proxy templates | WARNING | Domain key in proxy_uri_templates that doesn't exist in dns_registry |
| 8 | Orphaned OCSP responders | WARNING | OCSP responder host in tls_realism that doesn't exist in dns_registry |
| 9 | Orphaned site maps | WARNING | Domain key or referenced subresource host in site_maps that doesn't exist in dns_registry |
| 10 | Invalid proxy template structure | ERROR | proxy_uri_templates entry has empty paths/methods, mismatched content type lists, or invalid referrer_policy |
| 11 | Browser-like infrastructure proxy templates | WARNING | OCSP/CRL/update domain_class uses browser paths/content types or emits referrers |
| 12 | Missing proxy templates | INFO | dns_registry domain with `web` or `saas` tag but no proxy_uri_templates entry |
| 13 | Missing site maps | INFO | dns_registry domain with `web` or `saas` tag but no site_maps entry |

## Traffic Profile Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 12 | Orphaned dns_tags | WARNING | `dns_tags:` value in traffic_profiles, process_network_map, or tls_realism profiles/overrides that no dns_registry domain uses |
| 13 | Orphaned persona_traffic keys | WARNING | Persona name in `persona_traffic:` with no matching persona file |
| 14 | Missing required fields | ERROR | Connection entry without `role`, `port`, or `weight` |

## Application Catalog Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 14 | Duplicate app IDs | ERROR | Same `id:` used more than once |
| 15 | Orphaned persona references | WARNING | Persona name in app `personas:` list with no matching persona file |
| 16 | Missing image paths | ERROR | App without `image_path` for its declared platform(s) |
| 17 | Bare filenames | WARNING | `image_path` that isn't fully qualified (no directory separator) |

## Process Chain

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 18 | Orphaned spawn rule children | WARNING | Exe basename in spawn_rules not in application_catalog or system_processes |
| 19 | Missing spawn rules | INFO | App in catalog not listed as a child anywhere in spawn_rules |
| 20 | Orphaned process_network_map | WARNING | Exe name in process_network_map not matching any catalog entry |

## Persona Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 21 | Filename/name mismatch | ERROR | Persona file where `name:` field doesn't match the filename (without .yaml) |
| 22 | Missing required fields | ERROR | Persona file missing any of: name, description, typical_activities, work_hours, application_usage, risk_profile, browsing_intensity |
| 23 | Invalid risk_profile | ERROR | Value not in {low, medium, high} |
| 24 | Invalid browsing_intensity | ERROR | Value not in {light, normal, heavy} |
| 25 | Phantom personas | WARNING | Persona name referenced in application_catalog or traffic_profiles but no persona file exists |

## Evaluation Rule Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 26 | Invalid field references | WARNING | co_occurrence or distribution rule referencing a field name not in the corresponding format definition |
| 27 | Invalid format references | ERROR | Rules under a format key that doesn't match any format file name |
| 28 | sysmon_filters.yaml structure | ERROR | Missing required sections (network_connect, image_loaded, etc.) or invalid types |
| 29 | edr_pools.yaml structure | ERROR | Missing required sections (file_paths_windows, registry_keys_hkcu, etc.) or empty lists |
| 30 | calltrace_patterns.yaml structure | ERROR | Patterns list empty, or pattern missing `modules`/`offset_ranges` fields |
| 31 | rsat_tools.yaml structure | ERROR | Tool missing required fields (`id`, `snap_in`, `command_line`, `target_ports`, `weight`), invalid weight, or target_ports missing `port`/`service` |
| 32 | traffic_rates.yaml structure | ERROR | Missing intensity level (low/medium/high), or level missing required traffic type keys (`user_activity`, `web`, `dns_interval`, `ntp`, `smb_interval`, `kerberos`, `ldap`, `persona_connections`), or values not `[lo, hi]` positive integer pairs with lo ≤ hi |
| 33 | process_access_patterns.yaml structure | ERROR | Baseline pair missing source/target PID keys, image paths, or positive weighted hex access masks |
| 34 | create_remote_thread_patterns.yaml structure | ERROR | Baseline pair missing source/target PID keys, image paths, or positive weight |
| 35 | smb_file_transfers.yaml structure | ERROR | Missing SMB file-analysis thresholds/probabilities, invalid probability ranges, empty MIME/analyzer lists, invalid filename templates, or non-positive weights |
| 36 | kerberos_realism.yaml structure | ERROR | Invalid Kerberos 4768 pre-auth/ticket/encryption distribution, unsupported hex values, PKINIT without certificate profile, non-PKINIT with certificate fields, excessive no-preauth/PKINIT/RC4 weights, or malformed certificate profile fields |
| 37 | web_session_profiles.yaml structure | ERROR | Invalid inbound web visitor class, missing User-Agent pool, malformed configured request, or invalid request-count range |
| 38 | auth_noise.yaml structure | ERROR | Invalid stale scheduled-credential account pool, host-count range, recurrence interval range, jitter range, skip probability, or backoff bounds |

## Scenario Validation: traffic_rates

When `eforge validate` checks a scenario with `baseline_activity.traffic_rates`:
- Keys must be from: `user_activity`, `web`, `dns_interval`, `ntp`, `smb_interval`, `kerberos`, `ldap`, `persona_connections`
- Integer values must be > 0
- List values must be `[lo, hi]` with both positive and lo ≤ hi
- String values must be `low`, `medium`, or `high` (preset name)

## Output Format

Report grouped by severity, then by file. End with summary: "N errors, N warnings, N info items across N files checked."

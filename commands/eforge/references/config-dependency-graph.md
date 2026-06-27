# Config File Dependency Graph

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

This document maps every cross-file dependency in the EvidenceForge config system. Use it to determine which files need coordinated edits when making any change.

## Project-Local Overlay

Users can customize configs without modifying the package by placing partial YAML files in `.eforge/config/` in their project root. The engine merges overlay entries with package defaults at load time. Run `eforge info overlay.exists` and `eforge info overlay.files` to check overlay status, or `eforge info --fields` to see all available queries.

When adding new entries via the config skill, they go in the overlay directory (not the package files) unless the user is a developer editing the source directly.

Scenario YAML can also declare `environment.network_identities` for
scenario-local host/IP ownership. Use that for one-off lab, partner, attacker,
or public-service identities that should travel with a scenario. Use config
overlays for reusable libraries shared by many scenarios.

## Table of Contents

1. [Dependency Matrix](#dependency-matrix)
2. [Operation Checklists](#operation-checklists)
3. [Tag and Name Registries](#tag-and-name-registries)
4. [Silent Failure Patterns](#silent-failure-patterns)

---

## Dependency Matrix

Each row is a file; columns show what it depends on and what depends on it.

### dns_registry.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| **depended on by** | `traffic_profiles.yaml` | `dns_tags:` field selects domains by tag |
| **depended on by** | `process_network_map.yaml` | `dns_tags:` field constrains app-specific destinations |
| **depended on by** | `proxy_uri_templates.yaml` | `domains:` section keys must match dns_registry domains |
| **depended on by** | `site_maps.yaml` | `domains:` section keys must match dns_registry domains |
| **depended on by** | Engine (runtime) | Builds FORWARD_DNS, REVERSE_DNS, and tag-based lookup tables |
| depends on | nothing | This is a root data source |

### traffic_profiles.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `dns_registry.yaml` | `dns_tags:` values must exist as tags on at least one domain |
| depends on | persona names | `persona_traffic:` keys must match persona filenames |
| depends on | system roles | `role_traffic:` keys define valid system roles |
| **depended on by** | Engine (runtime) | Drives all baseline network connection generation |

### traffic_rates.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone rate table |
| **depended on by** | Engine (runtime) | Drives all baseline traffic rate calculations (user activity, web top-level actions, DNS, SMB, Kerberos, LDAP, persona connections) |

### host_activity_profiles.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | scenario host metadata | Uses system type, roles, assigned users, primary systems, and user personas to resolve coarse activity multipliers |
| depends on | `traffic_rates.yaml` | Multiplies resolved baseline rates after global intensity and scenario `baseline_activity.traffic_rates` overrides are applied |
| **depended on by** | Engine (runtime) | Shapes host/persona/role baseline volume, endpoint noise, Linux/syslog shell activity, firewall deny bursts, IDS/ICMP rates, and encoded PowerShell artifact variation |
| validated by | `eforge validate-config` | Enforces known rate-family names, ordered positive bounds, core host types, firewall deny burst settings, and artifact variant pools |

### web_session_profiles.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `site_maps.yaml` | Human visitor sessions use site maps to expand top-level page loads into assets and same-origin API calls |
| depends on | `traffic_rates.yaml` | `web` rates count top-level visitor actions; subresources are dependent fanout |
| depends on | `timing_profiles.yaml` | Uses web session/navigation and asset/tool fanout timing relationships |
| **depended on by** | Engine (runtime) | Drives inbound `web_server` visitor classes, tool/API request shapes, status codes, and User-Agents |

### timing_profiles.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone timing relationship profile |
| **depended on by** | Engine (runtime) | Drives causal prerequisite offsets, source-latency offsets, web session/fanout timing, sensor observation timing, teardown margins, and Windows/Sysmon tied-timestamp collision spacing |
| validated by | `eforge validate-config` | Enforces valid relationship classes, before/after positions, non-negative timing windows, and coherent min/max bounds |

### kerberos_realism.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone Kerberos field-distribution profile |
| **depended on by** | Engine (runtime) | Drives Windows 4768 TGT PreAuthType, TicketOptions, TicketEncryptionType, and PKINIT certificate fields |
| validated by | `eforge validate-config` | Enforces coherent combinations: PKINIT requires a certificate profile, non-PKINIT must not emit certificate fields, and no-preauth/PKINIT/RC4 weights stay bounded |

### proxy_uri_templates.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `dns_registry.yaml` | Domain keys should exist in dns_registry |
| **depended on by** | Engine (runtime) | Provides realistic URI paths for proxy log generation |

### proxy_user_agents.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `dns_registry.yaml` | Package-manager and domain-override hostnames should exist in dns_registry when used as generated destinations |
| **depended on by** | Engine (runtime) | Selects workstation/server and domain-specific proxy User-Agent values for proxy log generation |

### site_maps.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `dns_registry.yaml` | Domain keys should exist in dns_registry |
| **depended on by** | Engine (runtime) | Drives browsing session depth and page structure |

### application_catalog.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | persona names | `personas:` list references persona filenames (without .yaml) |
| **depended on by** | `spawn_rules.yaml` | Child exe basenames should exist in catalog for correct image paths |
| **depended on by** | `process_network_map.yaml` | Exe basenames should match catalog entries |
| **depended on by** | Engine (runtime) | Drives all process creation events |

### spawn_rules.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `application_catalog.yaml` | Child exe basenames should exist in catalog or `system_processes.yaml` |
| depends on | `system_processes.yaml` | System process exe basenames used as parents/children |
| **depended on by** | Engine (runtime) | Drives parent-child process tree generation |

### process_network_map.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `application_catalog.yaml` | Exe basenames should match catalog entries |
| depends on | `dns_registry.yaml` | `dns_tags:` values must match domain tags |
| **depended on by** | Engine (runtime) | Correlates process events with network connections |

### personas/*.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| **depended on by** | `application_catalog.yaml` | Persona name appears in `personas:` lists |
| **depended on by** | `traffic_profiles.yaml` | Persona name used as key in `persona_traffic:` |
| **depended on by** | `bash_commands.yaml` | Persona name used as role key (for Linux users) |
| **depended on by** | Engine (runtime) | Drives per-user activity generation |
| depends on | nothing | Personas are leaf definitions (no YAML-level deps) |

### bash_commands.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | persona/role names | Role keys should match persona names or system roles |
| **depended on by** | Engine (runtime) | Drives bash_history log generation |

### system_processes.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| **depended on by** | `spawn_rules.yaml` | System processes used as parents |
| **depended on by** | Engine (runtime) | Drives background system process events |
| depends on | nothing | Standalone system process definitions |

### systemd_schedules.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone (uses distro/role filters but these are soft matches) |
| **depended on by** | Engine (runtime) | Drives periodic syslog events on Linux |

### extra_syslog_messages.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone (uses distro/role filters) |
| **depended on by** | Engine (runtime) | Adds diversity to syslog baseline |

### auth_noise.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone authentication-noise profile data |
| **depended on by** | Engine (runtime) | Drives stale scheduled-credential account pools, recurrence timing, jitter, skips, and backoff |

### endpoint_noise.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone endpoint background timing and registry-emission policy data |
| **depended on by** | Engine (runtime) | Drives Windows scheduled-process trigger windows, host drift, skips, and DHCP interface registry write policy |
| validated by | `eforge validate-config` | Enforces coherent timing bounds, probability ranges, and non-empty DHCP registry value lists |

### observation_profiles.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | scenario `observation_profile` | The scenario selects a named profile; the profile file owns source-level missingness/delay values |
| **depended on by** | Event dispatcher, GROUND_TRUTH.md, OBSERVATION_MANIFEST.json, `eforge eval` | Applies deterministic source-observation drops/delays after canonical state updates, reports source evidence status, and lets eval distinguish expected gaps from missing visible evidence |
| validated by | `eforge validate-config` and `eforge validate` | Config validation checks source-family names/ranges; scenario validation checks that the named profile exists |

### network_params.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone MAC OUI and public NTP server data |
| **depended on by** | Engine (runtime) | Generates realistic MAC addresses and fallback public NTP server metadata |

### tls_issuers.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone certificate authority data |
| **depended on by** | Engine (runtime) | Drives Zeek x509/SSL certificate generation |

### tls_realism.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | tls_issuers.yaml, dns_registry.yaml | Chain templates and subject-key profiles match issuer names/patterns selected from issuer config; OCSP responder hosts must exist in dns_registry; destination profiles can pull domains by DNS tag |
| **depended on by** | Engine (runtime) | Drives Zeek TLS SAN, x509 chain depth, issuer-compatible certificate signature algorithms, OCSP cache/status behavior, and profiled TLS SNI/destination selection |
| validated by | `eforge validate-config` | Enforces coherent chain profile structure, non-empty subject-key patterns, and RSA/ECDSA child signature compatibility |

### smb_file_transfers.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone SMB file-analysis tuning |
| **depended on by** | Engine (runtime) | Controls when SMB connections generate Zeek files.log rows and their filename/MIME/analyzer mix |

### sysmon_filters.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone (filter rules reference exe basenames but no hard deps) |
| **depended on by** | Engine (runtime) | Controls which Sysmon Events 3/7/11/12/13/22 are emitted |

### edr_pools.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone file path/registry/DLL pools |
| **depended on by** | Engine (runtime) | Drives probabilistic file create, registry modify, and DLL load events |

### calltrace_patterns.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone call chain template definitions |
| **depended on by** | Engine (runtime) | Drives Sysmon Event 10 CallTrace field generation |

### process_access_patterns.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone source/target process pairs and access-mask weights |
| **depended on by** | Engine (runtime) | Drives Sysmon Event 10 baseline ProcessAccess pairs and GrantedAccess diversity |

### create_remote_thread_patterns.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone source/target process pairs and weights |
| **depended on by** | Engine (runtime) | Drives Sysmon Event 8 baseline CreateRemoteThread pairs |

### formats/*.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | nothing | Standalone format schemas |
| **depended on by** | `evaluation/*.yaml` | Field names referenced in co-occurrence and distribution rules |
| **depended on by** | Engine (runtime) | Drives log record structure |

### evaluation/*.yaml
| Direction | File | Relationship |
|-----------|------|-------------|
| depends on | `formats/*.yaml` | References field names and EventID values defined in formats |
| **depended on by** | Evaluation engine | Drives data quality scoring |

---

## Operation Checklists

Use these checklists when performing each type of edit. Items marked with **[auto-fix]** can be stub-generated automatically; items marked with **[advise]** should be flagged to the user.

### Add a Domain

1. Add entry to `dns_registry.yaml` with `domain`, `ips` (list of 1-3), and `tags` (list)
2. If tags include `web` or `saas`:
   - **[auto-fix]** Add proxy_uri_templates entry with generic paths
   - **[auto-fix]** Add site_maps entry with minimal page structure
3. If the domain should appear in specific role/persona traffic:
   - **[advise]** Check that `dns_tags:` in relevant traffic_profiles entries include the domain's tags
4. Group the domain entry under the correct provider comment block

### Remove a Domain

1. Remove entry from `dns_registry.yaml`
2. Remove matching key from `proxy_uri_templates.yaml` (if present)
3. Remove matching key from `site_maps.yaml` (if present)
4. **[advise]** Check if any traffic_profiles entries used a tag that now has no domains

### Retag a Domain

1. Change `tags:` in `dns_registry.yaml`
2. If removing `web`/`saas` tag → proxy_uri_templates and site_maps entries may now be unreachable (harmless but stale)
3. If adding `web`/`saas` tag:
   - **[auto-fix]** Add proxy_uri_templates entry if missing
   - **[auto-fix]** Add site_maps entry if missing
4. **[advise]** Check dns_tags references in traffic_profiles for impact

### Add an Application

1. Add entry to `application_catalog.yaml` with all required fields
2. **[auto-fix]** Add exe basename as child of appropriate parent in `spawn_rules.yaml` (explorer.exe for user apps)
3. If app generates network traffic:
   - **[advise]** Add entry to `process_network_map.yaml`
4. If app spawns child processes:
   - **[auto-fix]** Add parent entry in `spawn_rules.yaml` with children list

### Create a Persona

1. Create `personas/{name}.yaml` with all required fields
2. **[auto-fix]** Add persona name to `personas:` lists in relevant `application_catalog.yaml` entries
3. If persona needs custom traffic:
   - **[advise]** Add `persona_traffic:` entry in `traffic_profiles.yaml`
4. If persona is Linux-oriented:
   - **[advise]** Consider adding role entry in `bash_commands.yaml`

### Modify a Persona

1. Edit `personas/{name}.yaml`
2. If renaming (rare):
   - Update `personas:` lists across `application_catalog.yaml`
   - Update `persona_traffic:` key in `traffic_profiles.yaml`
   - Update role key in `bash_commands.yaml` (if applicable)
   - Rename the YAML file itself

### Add Traffic Profile Entries

1. Add/modify entries in `traffic_profiles.yaml`
2. If using new `dns_tags:` values:
   - Verify tags exist on domains in `dns_registry.yaml`
3. If adding `persona_traffic:` for a new persona:
   - Verify persona file exists in `personas/`

### Modify Spawn Rules

1. Edit `spawn_rules.yaml`
2. Verify all child exe basenames exist in `application_catalog.yaml` or `system_processes.yaml`
3. Verify parent command_templates use correct fully-qualified paths

### Modify ProcessAccess Patterns

1. Edit `process_access_patterns.yaml`
2. Verify each `source_pid_key` and `target_pid_key` refers to a seeded Windows system process
3. Verify every `access_masks:` entry has a hex `mask` and positive `weight`
4. Edit `calltrace_patterns.yaml` separately if changing the Event 10 CallTrace shape

### Modify CreateRemoteThread Patterns

1. Edit `create_remote_thread_patterns.yaml`
2. Verify each `source_pid_key` and `target_pid_key` refers to a seeded Windows system process
3. Verify each `weight` is positive
4. Edit Sysmon Event 8 rendering logic only if changing StartModule/StartFunction selection semantics

### Modify Format Definitions

1. Edit `formats/{name}.yaml`
2. If adding/renaming/removing fields:
   - **[advise]** Check `evaluation/co_occurrence.yaml` for rules referencing changed fields
   - **[advise]** Check `evaluation/distributions.yaml` for distribution profiles referencing changed fields

### Modify Evaluation Rules

1. Edit `evaluation/{name}.yaml`
2. Verify all referenced field names exist in the corresponding format definition
3. Verify all EventID values are valid for the format

---

## Tag and Name Registries

### Valid DNS Tags
These are the tags used in `dns_registry.yaml` and referenced by `dns_tags:` in
`traffic_profiles.yaml` and `process_network_map.yaml`:

| Tag | Meaning | Example Domains |
|-----|---------|----------------|
| `web` | General web browsing targets | www.google.com, github.com |
| `saas` | SaaS application traffic | drive.google.com, app.slack.com |
| `cdn` | CDN/API endpoints (not directly browsed) | api.cloudflare.com, cdn.jsdelivr.net |
| `email` | Email server connections | outlook.office365.com |
| `git` | Source control services | github.com (also tagged web) |
| `background` | OS-level background HTTPS | telemetry, CRL, OCSP endpoints |
| `windows` | Windows-specific background traffic | windowsupdate.com, msftconnecttest.com |
| `linux` | Linux-specific background traffic | security.ubuntu.com, mirrors.centos.org |
| `internal` | Internal infrastructure | Internal DB, file shares (rarely in dns_registry) |
| `storage` | Cloud storage (exfiltration targets) | AWS S3, Azure Blob, Google Cloud Storage |
| `dev` | Developer tool API endpoints | api.github.com, registry.npmjs.org |
| `social` | Social media | linkedin.com, twitter.com |

### Valid Application Categories
Used in `application_catalog.yaml` `categories:` field:

| Category | Maps To |
|----------|---------|
| `user_app` | General user applications |
| `code` | Development tools (IDEs, editors) |
| `build` | Build/CI tools (Docker, compilers) |
| `query` | Data query tools (SQL clients, BI tools) |
| `browser` | Web browsers |
| `office` | Office suite applications |

### Valid Persona Risk Profiles
| Value | Meaning |
|-------|---------|
| `low` | Minimal system access, simple activity patterns |
| `medium` | Standard access, moderate activity diversity |
| `high` | Elevated access, diverse tools and admin activities |

### Valid Browsing Intensities
| Value | Meaning |
|-------|---------|
| `light` | Few browsing sessions, shallow page depth |
| `normal` | Moderate browsing with typical page depth |
| `heavy` | Frequent browsing, deep page hierarchies, many subresources |

---

## Silent Failure Patterns

These are situations where a missing cross-reference doesn't crash the engine but degrades output quality. The skill should proactively check for these.

| Symptom | Cause | Detection |
|---------|-------|-----------|
| Generic/unrealistic proxy log URIs | Domain in dns_registry but not in proxy_uri_templates | Grep dns_registry web/saas domains against proxy_uri_templates keys |
| Shallow single-page browsing sessions | Domain in dns_registry but not in site_maps | Grep dns_registry web/saas domains against site_maps keys |
| App processes with wrong image paths | Exe in spawn_rules but not in application_catalog | Grep spawn_rules children against application_catalog ids |
| Persona never spawns expected apps | Persona name missing from application_catalog `personas:` lists | Grep persona filename against application_catalog personas fields |
| Persona traffic falls back to generic [background] | No dns_tags on traffic_profiles entry, or dns_tags point to unused tags | Check dns_tags values against dns_registry tag usage |
| Missing process-network correlation | App generates traffic but has no process_network_map entry | Check network-capable apps against process_network_map keys and `dns_tags` |
| Stale proxy templates for removed domains | Domain removed from dns_registry but template remains | Grep proxy_uri_templates keys against dns_registry domains |

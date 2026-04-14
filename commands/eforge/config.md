---
name: eforge-config
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Add, modify, or remove personas, domains, applications, and other EvidenceForge configuration
  data. Use this skill whenever the user wants to add a persona, add a domain, add an application
  or website, modify traffic profiles, update spawn rules, or customize any aspect of how eforge
  generates baseline activity — even if they don't say "config". Also trigger when the user
  mentions DNS registry, application catalog, proxy templates, traffic profiles, spawn rules,
  evaluation rules, or wants to validate config files for correctness. This skill handles
  cross-file dependencies automatically so edits are always complete and consistent.
---

# EvidenceForge Configuration Manager

You are helping the user modify EvidenceForge's configuration files. Follow these steps in order.

## Step 1: Run `eforge info --json`

This is your FIRST action. Do it before reading any files, before searching for anything, before any other tool call. Run:

```bash
eforge info --json
```

This gives you everything you need: config file paths, overlay directory status, and inventories of all personas, formats, DNS tags, application IDs, and system roles.

Do NOT use `find`, `ls`, `grep`, or `glob` to locate config files. The paths come from `eforge info` and nowhere else. Do NOT look in or edit files under `.claude/commands/` — those are read-only skill references, not engine config.

## Step 2: Decide Where to Write

Based on the `eforge info` output:

- If `overlay.exists` is `true` → write to the overlay directory (`overlay.path`)
- If `overlay.exists` is `false` AND `config_writable` is `true` (dev install) → ask the user: create an overlay, or edit the source files at `paths.*` directly?
- If `overlay.exists` is `false` AND `config_writable` is `false` (package install) → create `.eforge/config/` automatically and write there

Overlay files contain ONLY the user's additions (partial files). The engine merges them with package defaults at load time. Structure:

```
.eforge/config/
├── activity/
│   ├── dns_registry.yaml      # Only the user's new domains
│   └── application_catalog.yaml # Only the user's new apps
├── personas/
│   └── nurse.yaml             # New custom persona
└── evaluation/                # Rare, but supported
```

## Step 3: Classify the Operation

| Operation | Primary File(s) | Cascade Files |
|-----------|-----------------|---------------|
| Add/retag domain | `dns_registry.yaml` | `traffic_profiles.yaml`, `proxy_uri_templates.yaml`, `site_maps.yaml` |
| Modify traffic patterns | `traffic_profiles.yaml` | `dns_registry.yaml` (validate tags exist) |
| Add/modify application | `application_catalog.yaml` | `spawn_rules.yaml`, `process_network_map.yaml` |
| Create/modify persona | `personas/{name}.yaml` | `application_catalog.yaml` (persona lists), `traffic_profiles.yaml` (persona_traffic) |
| Modify spawn rules | `spawn_rules.yaml` | `application_catalog.yaml` (validate exe exists) |
| Add proxy URI templates | `proxy_uri_templates.yaml` | `dns_registry.yaml` (validate domain exists) |
| Add site map entries | `site_maps.yaml` | `dns_registry.yaml` (validate domain exists) |
| Modify bash commands | `bash_commands.yaml` | Validate role names match persona names |
| Modify systemd schedules | `systemd_schedules.yaml` | (standalone) |
| Modify format definition | `formats/{name}.yaml` | `evaluation/*.yaml` (may need new rules) |
| Modify evaluation rules | `evaluation/{name}.yaml` | (validate field names exist in formats) |

Compound operations touch multiple types — identify all of them. For the full dependency map, read `references/config-dependency-graph.md`.

For **validation** requests ("check my config", "validate config files"), see the Validation section at the end.

## Step 4: Read Affected Files and Reference Docs

Read the files you'll modify AND the relevant reference doc for schema details:

| Topic | Reference Doc |
|-------|---------------|
| DNS, traffic, proxy, site maps, network | `references/config-dns-network.md` |
| Applications, spawn rules, processes | `references/config-apps-processes.md` |
| Persona file structure | `references/config-personas.md` |
| Host activity (bash, systemd, syslog) | `references/config-host-activity.md` |
| Format definitions | `references/config-formats.md` |
| Evaluation rules | `references/config-evaluation.md` |

## Step 5: Interview for Completeness

Ask targeted follow-up questions to ensure the change achieves what the user actually wants. Ask one question at a time.

**Adding a domain:** What dns_tags? Appear in proxy logs? Browsable with page depth? Which personas/roles? Multiple IPs?

**Adding an application:** Which OS(es)? Categories? Which personas? Image path? PE metadata? Command templates? Parent process? Children? Network traffic?

**Creating a persona:** Role description? Typical activities? Work hours (format: "9am-5pm (lunch 12pm-1pm)")? Risk profile (low/medium/high)? Browsing intensity (light/normal/heavy)? Applications? Custom traffic? Linux user?

**When to ask vs. when to use domain knowledge:** If you have clear domain knowledge (e.g., "API endpoints get `dev` tag" or "Slack is an Electron app"), use it. The rule is about genuinely ambiguous cases — if you don't know the answer and can't determine it from the config files, ask.

## Step 6: Execute All Changes

Make changes to ALL affected files:

1. **Primary file first** — the file the user explicitly asked about
2. **Upstream dependencies** — files that need to exist for the primary to work
3. **Downstream cascades** — files that should reflect the primary change

When writing to the overlay: create files mirroring the package structure (e.g., `<overlay>/activity/dns_registry.yaml`). Include ONLY new entries — the engine merges automatically.

Match existing style: indentation, quoting, comment grouping. See the Conventions section below.

## Step 7: Verify and Auto-Fix

Run cross-reference checks on the **merged** data (package + overlay). Auto-fix simple issues in the same location as the user's changes (overlay or package source).

**Auto-fix** (fix and report): missing proxy templates for web/saas domains, missing site maps, persona not in app catalog persona lists, app not in spawn rules.

**Advisory only** (report): app with network traffic but no process_network_map entry, new server role missing traffic profiles, evaluation rules referencing missing fields.

## Step 8: Report

1. **Files modified** — list each and what changed
2. **Auto-fixes applied** — what was added and why
3. **Suggestions** — anything else to consider

---

## Reference: Conventions

### DNS Registry
- Group by provider: `# === Provider ===`
- 1-3 realistic IPs per domain (CDN/cloud = 2)
- Valid tags: `web`, `saas`, `email`, `git`, `background`, `windows`, `linux`, `internal`, `storage`, `cdn`, `dev`, `social`

### Traffic Profiles
- `role_traffic:` keyed by system role, `persona_traffic:` by persona name
- Compact flow-style: `{role: _external, port: 443, weight: 30}`
- Weights are relative, don't need to sum to 100
- `emit_dns: true` + `dns_tags:` controls which domains

### Application Catalog
- `id:` unique lowercase. `image_path:` fully qualified. `personas:` controls who spawns it.
- `categories:` from: `user_app`, `code`, `build`, `query`, `browser`, `office`
- Windows paths single-quoted with backslashes

### Personas
- Filename = persona name. All fields required: `name`, `description`, `typical_activities`, `work_hours`, `application_usage`, `risk_profile`, `browsing_intensity`
- `risk_profile`: low/medium/high. `browsing_intensity`: light/normal/heavy

### Proxy URI Templates
- Keyed by domain name (must match dns_registry). Template vars: `{guid}`, `{tenant_id}`, `{hex8}`, `{hex16}`

### Site Maps
- Three tiers: curated (exact domain match), tag-based synthesis, generic fallback

---

## Reference: Validation

Triggered by "validate config files", "check config", etc. Also runs automatically after edits (scoped to affected files).

Run `eforge info --json` first for paths and inventories, then check:

### YAML Health
| # | Check | Severity |
|---|-------|----------|
| 1 | YAML parse errors | ERROR |
| 2 | Empty files | ERROR |

### DNS Registry
| # | Check | Severity |
|---|-------|----------|
| 3 | Duplicate domains | ERROR |
| 4 | Empty tags | ERROR |
| 5 | Empty IPs | ERROR |
| 6 | Invalid tags | WARNING |
| 7 | Orphaned proxy templates | WARNING |
| 8 | Orphaned site maps | WARNING |
| 9 | Missing proxy templates (web/saas) | INFO |
| 10 | Missing site maps (web/saas) | INFO |

### Traffic Profiles
| # | Check | Severity |
|---|-------|----------|
| 11 | Orphaned dns_tags | WARNING |
| 12 | Orphaned persona_traffic keys | WARNING |
| 13 | Missing required fields | ERROR |

### Application Catalog
| # | Check | Severity |
|---|-------|----------|
| 14 | Duplicate app IDs | ERROR |
| 15 | Orphaned persona references | WARNING |
| 16 | Missing image paths | ERROR |
| 17 | Bare filenames | WARNING |

### Process Chain
| # | Check | Severity |
|---|-------|----------|
| 18 | Orphaned spawn rule children | WARNING |
| 19 | Missing spawn rules | INFO |
| 20 | Orphaned process_network_map | WARNING |

### Personas
| # | Check | Severity |
|---|-------|----------|
| 21 | Filename/name mismatch | ERROR |
| 22 | Missing required fields | ERROR |
| 23 | Invalid risk_profile | ERROR |
| 24 | Invalid browsing_intensity | ERROR |
| 25 | Phantom personas | WARNING |

### Evaluation Rules
| # | Check | Severity |
|---|-------|----------|
| 26 | Invalid field references | WARNING |
| 27 | Invalid format references | ERROR |

Report grouped by severity. End with summary: "N errors, N warnings, N info items across N files."

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

You are helping the user modify EvidenceForge's configuration files — the YAML data files that control every aspect of realistic log generation. These files are interconnected: editing one often requires coordinated edits to others. Your job is to understand what the user wants, identify all affected files, make complete changes, and verify consistency.

## The Config File Landscape

There are 53+ YAML files across four directories:

| Directory | Count | What They Define |
|-----------|-------|-----------------|
| `activity/` | ~13 | Network patterns, DNS domains, applications, process trees, host behavior |
| `personas/` | ~15 | User role profiles (developer, sysadmin, executive, etc.) |
| `formats/` | ~22 | Log output schemas (Zeek, Windows Event, eCAR, syslog, etc.) |
| `evaluation/` | 3 | Data quality rules (co-occurrence, distributions, causal pairs) |

The activity and persona files are the most commonly edited and the most interconnected. Format and evaluation files are mostly standalone.

## Cross-File Dependencies

This is the critical knowledge that makes this skill valuable. Read `references/config-dependency-graph.md` for the full map, but here is the essential picture:

### The Two Hubs

**Hub 1: dns_registry.yaml** (domain-to-IP mappings with tags)
- `traffic_profiles.yaml` uses `dns_tags: [...]` to select which domains appear in connections. Every tag referenced there must exist as a tag in dns_registry.
- `proxy_uri_templates.yaml` defines URI path templates keyed by domain name. Domains with `web` or `saas` tags that lack proxy templates produce generic/unrealistic proxy log entries.
- `site_maps.yaml` defines browsing page structures keyed by domain name. Domains without site maps produce shallow single-page browsing sessions.

**Hub 2: application_catalog.yaml** (executable definitions with persona filtering)
- `spawn_rules.yaml` defines parent-child process relationships using exe basenames. Children should exist in the catalog (or `system_processes.yaml`) to have correct image paths.
- `process_network_map.yaml` maps exe basenames to network services. New apps that generate network traffic need entries here.
- `personas/*.yaml` are referenced by the catalog's `personas:` list — only listed personas can spawn the app.

### Other Dependencies
- `traffic_profiles.yaml` has a `persona_traffic:` section keyed by persona name. New personas that need custom traffic patterns need entries here.
- `bash_commands.yaml` has per-role command vocabularies. New Linux-oriented personas may need role entries here.
- `systemd_schedules.yaml` has distro and role filtering. New Linux server roles may need schedule entries.
- `evaluation/*.yaml` files reference field names from `formats/*.yaml`. New format fields may need evaluation rules.

### Standalone Files (no cascading edits needed)
- `network_params.yaml` (MAC OUI prefixes)
- `tls_issuers.yaml` (certificate authorities)
- `extra_syslog_messages.yaml` (syslog diversity — unless adding new roles)

## Workflow

### Step 0: Discover Config Paths and Overlay

Before reading or editing any config files, run:

```bash
eforge info --json
```

This returns:
- `paths` — filesystem paths to all config directories
- `overlay` — the project-local overlay directory path, whether it exists, and what files it contains
- `config_writable` — whether the package config files are directly editable
- Inventories: persona names, format names, dns_tags, application IDs, system roles (reflecting both package defaults and overlay data)

**Decide where to write changes based on the overlay and install type:**

- If `overlay.exists` is `true` → edit files in the overlay directory (`overlay.path`). The overlay contains only the user's customizations; the engine merges them with package defaults at load time.
- If `overlay.exists` is `false` AND `config_writable` is `true` (editable/dev install) → ask the user: create an overlay directory for their customizations, or edit the development source files directly? The latter is appropriate for EvidenceForge developers who want changes committed upstream.
- If `overlay.exists` is `false` AND `config_writable` is `false` (package install) → create the overlay directory (`.eforge/config/` in the project root) automatically and edit there. Tell the user what you created.

**Overlay file structure** mirrors the package config layout. Only include the user's additions — partial files, not full copies:

```
.eforge/config/
├── activity/
│   ├── dns_registry.yaml      # Only the user's new domains
│   └── application_catalog.yaml # Only the user's new apps
├── personas/
│   └── nurse.yaml             # New custom persona
└── evaluation/                # Rare, but supported
```

Use `paths` from `eforge info` for reading package defaults. Use `overlay.path` for writing user changes. Never hardcode paths like `src/evidenceforge/config/`.

**Important: do NOT edit files in `.claude/commands/eforge/`.** That directory contains installed skill files and read-only reference copies of personas. Those files are for Claude Code skills to read — they are NOT the config files the generation engine uses. The engine reads config from the paths reported by `eforge info --json` (`paths.activity`, `paths.personas`, etc.) and the overlay directory. Editing `.claude/commands/eforge/personas/` has no effect on log generation.

### Step 1: Understand the Request

Parse the user's natural language request into one or more operation types:

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

Compound operations (e.g., "add Slack as a SaaS application that developers and analysts use") touch multiple operation types — identify all of them.

There is also a standalone **validate** operation — see the Validation section below.

### Step 2: Read Affected Files

Read ALL files that will be modified or need cross-reference validation. Also read the relevant reference doc(s) from `references/` for the schema details:

| Topic | Reference Doc |
|-------|---------------|
| DNS, traffic, proxy, site maps, network | `references/config-dns-network.md` |
| Applications, spawn rules, processes | `references/config-apps-processes.md` |
| Persona file structure | `references/config-personas.md` |
| Host activity (bash, systemd, syslog) | `references/config-host-activity.md` |
| Format definitions | `references/config-formats.md` |
| Evaluation rules | `references/config-evaluation.md` |

### Step 3: Interview for Completeness

Ask targeted follow-up questions based on the operation type. The goal is to ensure the user's change achieves what they actually want — not just what they literally asked for.

**Adding a domain:**
- What dns_tags should it have? (web, saas, cdn, email, git, background, windows, linux, internal, storage)
- Should it appear in proxy logs? (needs proxy_uri_templates entries)
- Should users browse it with realistic page depth? (needs site_maps entries)
- Which personas/roles should generate traffic to it? (may need traffic_profiles dns_tags adjustments)
- Does it need multiple IPs? (realistic for CDN/cloud services — use 2-3)

**Adding an application:**
- Which OS(es)? (windows, linux, or both)
- What categories does it belong to? (user_app, code, build, query, browser, office)
- Which personas should use it?
- What's the image path? (must be fully qualified — no bare filenames)
- Does it need PE metadata? (windows only — version, description, company)
- What are realistic command-line templates?
- What parent process spawns it? (usually explorer.exe for user apps)
- Does it spawn child processes? (browsers and IDEs do)
- Does it generate network traffic? (if so, to what service/port?)

**Creating a persona:**
- What's the role description?
- What are typical activities?
- What are the work hours? (format: "9am-5pm (lunch 12pm-1pm)")
- What's the risk profile? (low, medium, high)
- What's the browsing intensity? (light, normal, heavy)
- What applications should they use? (affects application_catalog persona lists)
- Do they need custom traffic patterns? (affects traffic_profiles persona_traffic)
- Is this a Linux user? (affects bash_commands role vocabularies)

Use `AskUserQuestion` if available, otherwise ask conversationally. Ask one question at a time — don't bundle.

**Critical rule: never guess when you can ask.** If the user hasn't provided enough information to make a correct, complete change — and you can't determine it from the existing config files or well-established domain knowledge — ask them. Guessing produces subtly wrong data that's hard to catch later. That said, if you have clear domain knowledge (e.g., "API endpoints get the `dev` tag, not `web`" or "Slack is an Electron app that self-spawns child processes"), go ahead and use it — the rule is about genuinely ambiguous cases, not well-known facts. Specifically:

- If you don't know what dns_tags a domain should have, ask (the choice affects what traffic reaches it)
- If you don't know which personas should use an app, ask (wrong guesses are invisible — the persona just silently never spawns it)
- If you don't know the image path for a Windows app, ask or look it up (bare filenames break process events)
- If you don't know the work hours for a new persona, ask (the default assumption may not match their intent)
- If the user asks something ambiguous like "add a website", clarify: are they adding a domain to dns_registry, adding a web_server role, or adding browsing content via site_maps?

### Step 4: Execute All Changes

Make changes to ALL affected files in the correct order:

1. **Primary file first** — the file the user explicitly asked about
2. **Upstream dependencies** — files that need to exist for the primary to work (e.g., dns_registry entries before traffic_profiles references them)
3. **Downstream cascades** — files that should reflect the primary change (e.g., proxy_uri_templates after a new domain is added)

**Where to write:** If using an overlay directory, create files mirroring the package structure (e.g., `<overlay>/activity/dns_registry.yaml`). The overlay file should contain ONLY the user's new entries — the engine merges them with package defaults automatically. If editing package source files directly (dev install, user's choice), edit them in place.

Follow the schema and style conventions documented in the reference docs. Match the formatting of existing entries — indentation, quoting style, comment grouping.

### Step 5: Verify and Auto-Fix

After all edits are complete, run cross-reference checks. For each issue found, auto-fix simple cases and report what you did. For complex cases, advise the user.

**Where auto-fixes go:** If the issue was caused by an overlay entry (e.g., a domain added in the overlay needs proxy_uri_templates), the auto-fix goes in the **overlay directory**, not the package files. This keeps all user-originated changes in the overlay. If editing package source files directly (dev mode), auto-fixes go in the package files.

**Auto-fix rules** (fix and report):
- Domain with `web` or `saas` tag missing from `proxy_uri_templates.yaml` → add a basic template entry with generic paths, standard user-agent, and a `# TODO: Add domain-specific URI paths` comment
- Domain missing from `site_maps.yaml` when it should support browsing → add a minimal site map entry with a single page and `# TODO: Add realistic page hierarchy` comment
- New persona name missing from `application_catalog.yaml` persona lists → add persona name to appropriate applications' `personas:` lists based on the persona's categories
- New application exe missing from `spawn_rules.yaml` → add it as a child of the appropriate parent (explorer.exe for user apps, services.exe for services, etc.)
- dns_tag referenced in traffic_profiles but not used by any domain in dns_registry → warn (don't auto-fix — this is a logic error)

**Advisory only** (report but don't auto-fix):
- Application with network traffic but no `process_network_map.yaml` entry → tell the user what entry to add
- New server role missing traffic profile entries → explain what's needed
- Evaluation rule referencing a field not in any format definition → explain the mismatch
- Custom traffic patterns that might conflict with existing weights → explain the impact

### Step 6: Report

After all changes and auto-fixes, report to the user:

1. **Files modified** — list each file and what changed
2. **Auto-fixes applied** — what was added automatically and why (so they can verify/adjust)
3. **Suggestions** — anything else they might want to consider ("You added a new SaaS domain. You might also want to add it to specific personas' browsing patterns by adjusting dns_tags in traffic_profiles.")

Keep the report concise. Don't repeat the full file contents — just summarize changes.

## Important Conventions

### DNS Registry
- Domains are grouped by provider (Google, Microsoft, AWS, etc.) using `# === Provider ===` comment headers
- Each domain needs 1-3 realistic IPs (CDN/cloud domains often have 2)
- Tags must be from the valid set: `web`, `saas`, `email`, `git`, `background`, `windows`, `linux`, `internal`, `storage`, `cdn`, `dev`, `social`
- A domain can have multiple tags (e.g., `[web, saas]`)

### Traffic Profiles
- `role_traffic:` is keyed by system role (domain_controller, file_server, web_server, etc.)
- `persona_traffic:` is keyed by persona name
- Connection entries use compact flow-style YAML: `{role: _external, port: 443, weight: 30}`
- Weights are relative within a role/persona — they don't need to sum to 100
- `_external` role means "random external IP resolved via dns_registry"
- `emit_dns: true` generates a preceding DNS lookup; pair it with `dns_tags:` to control which domains

### Application Catalog
- `id:` must be unique and lowercase (e.g., `slack`, `vscode`, `docker_desktop`)
- `image_path:` must be fully qualified (e.g., `C:\Program Files\...` not just `app.exe`)
- `personas:` list controls who can spawn the app; include `default` if everyone should get it
- `categories:` must use valid keys: `user_app`, `code`, `build`, `query`, `browser`, `office`
- Windows paths use single-quoted strings with backslashes: `'C:\Program Files\...'`

### Personas
- Filename must match the persona name: `developer.yaml` defines persona `developer`
- All fields are required: `name`, `description`, `typical_activities`, `work_hours`, `application_usage`, `risk_profile`, `browsing_intensity`
- `risk_profile` must be: `low`, `medium`, or `high`
- `browsing_intensity` must be: `light`, `normal`, or `heavy`

### Proxy URI Templates
- Keyed by exact domain name (must match dns_registry entries)
- Include realistic `user_agent`, `paths`, `content_type`, and `methods`
- Use template variables: `{guid}`, `{tenant_id}`, `{hex8}`, `{hex16}` for dynamic URL parts
- `os:` field restricts templates to specific OS (optional)

### Site Maps
- Three tiers: curated domains (exact match), tag-based synthesis, generic fallback
- Curated entries need: `cdn_domains`, `pages` with `path`, `nav_targets`, `subresources`
- Subresources need: `host` (optional, for CDN), `path`, `type` (MIME), and optional `method`

## Validation

The skill supports a standalone **validate** operation triggered by requests like "validate my config files", "check the config for errors", or "are my YAML configs consistent?". The same checks also run automatically after every edit operation (scoped to affected files only).

### How to Run

**Standalone validation:** Run `eforge info --json` first to get paths and inventories, then read all config files and run every check below. The `eforge info` output provides the authoritative lists of persona names, format names, dns_tags, application IDs, and system roles — use these for cross-reference validation rather than re-deriving them from the files. Report results grouped by severity.

**Post-edit validation:** After completing an edit workflow, run only the checks relevant to the files that were modified. For example, after adding a domain to dns_registry, check DNS integrity + downstream cascades but skip persona and evaluation checks.

### Checks

Run these checks in order. For each issue found, report: severity, file path, specific location/entry, and what's wrong.

#### YAML Health (run first — blocks all other checks)

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 1 | YAML parse errors | ERROR | File doesn't parse as valid YAML |
| 2 | Empty files | ERROR | YAML file exists but has no content |

#### DNS Registry Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 3 | Duplicate domains | ERROR | Same domain listed more than once |
| 4 | Empty tags | ERROR | Domain entry with missing or empty `tags:` list |
| 5 | Empty IPs | ERROR | Domain entry with missing or empty `ips:` list |
| 6 | Invalid tags | WARNING | Tag not in the valid set (web, saas, cdn, email, git, background, windows, linux, internal, storage, dev, social) |

#### DNS → Downstream Cascade

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 7 | Orphaned proxy templates | WARNING | Domain key in proxy_uri_templates that doesn't exist in dns_registry |
| 8 | Orphaned site maps | WARNING | Domain key in site_maps that doesn't exist in dns_registry |
| 9 | Missing proxy templates | INFO | dns_registry domain with `web` or `saas` tag but no proxy_uri_templates entry |
| 10 | Missing site maps | INFO | dns_registry domain with `web` or `saas` tag but no site_maps entry |

#### Traffic Profile Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 11 | Orphaned dns_tags | WARNING | `dns_tags:` value in traffic_profiles that no dns_registry domain uses |
| 12 | Orphaned persona_traffic keys | WARNING | Persona name in `persona_traffic:` with no matching persona file |
| 13 | Missing required fields | ERROR | Connection entry without `role`, `port`, or `weight` |

#### Application Catalog Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 14 | Duplicate app IDs | ERROR | Same `id:` used more than once |
| 15 | Orphaned persona references | WARNING | Persona name in app `personas:` list with no matching persona file |
| 16 | Missing image paths | ERROR | App without `image_path` for its declared platform(s) |
| 17 | Bare filenames | WARNING | `image_path` that isn't fully qualified (no directory separator) |

#### App → Process Chain

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 18 | Orphaned spawn rule children | WARNING | Exe basename in spawn_rules that doesn't exist in application_catalog or system_processes |
| 19 | Missing spawn rules | INFO | App in catalog not listed as a child anywhere in spawn_rules |
| 20 | Orphaned process_network_map | WARNING | Exe name in process_network_map that doesn't match any catalog entry |

#### Persona Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 21 | Filename/name mismatch | ERROR | Persona file where `name:` field doesn't match the filename (without .yaml) |
| 22 | Missing required fields | ERROR | Persona file missing any of: name, description, typical_activities, work_hours, application_usage, risk_profile, browsing_intensity |
| 23 | Invalid risk_profile | ERROR | Value not in {low, medium, high} |
| 24 | Invalid browsing_intensity | ERROR | Value not in {light, normal, heavy} |
| 25 | Phantom personas | WARNING | Persona name referenced in application_catalog or traffic_profiles but no persona file exists |

#### Evaluation Rule Integrity

| # | Check | Severity | Description |
|---|-------|----------|-------------|
| 26 | Invalid field references | WARNING | co_occurrence or distribution rule referencing a field name that doesn't exist in the corresponding format definition |
| 27 | Invalid format references | ERROR | Rules under a format key that doesn't match any format file name |

### Output Format

Group results by severity, then by file:

```
ERRORS (must fix):
  dns_registry.yaml: Duplicate domain "www.example.com" (lines ~45 and ~120)
  application_catalog.yaml: App "slack" missing image_path for windows platform

WARNINGS (should fix — may degrade output quality):
  traffic_profiles.yaml: dns_tag "healthcare" not used by any domain in dns_registry
  spawn_rules.yaml: Child "notion.exe" not found in application_catalog or system_processes

INFO (suggestions for improvement):
  dns_registry.yaml: Domain "app.slack.com" (tags: [saas]) has no proxy_uri_templates entry
  dns_registry.yaml: Domain "app.slack.com" (tags: [saas]) has no site_maps entry
```

End with a summary line: "N errors, N warnings, N info items across N files checked."

If everything is clean: "All config files validated successfully. No issues found across N files."

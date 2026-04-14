---
name: eforge-config
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Add, modify, or remove EvidenceForge personas, DNS domains, applications, traffic profiles,
  spawn rules, and other configuration data that controls how eforge generates realistic baseline
  activity. Use this skill when the user wants to add a persona, add a domain or website, add an
  application, change browsing intensity, update traffic weights, add bash commands, customize
  proxy URI templates, or validate config file integrity — even if they don't say "config".
  This is for changing the underlying data library, not for creating scenarios (use eforge:scenario
  for that) or running generation (use eforge:generate). Trigger on phrases like "add a persona",
  "new domain", "new application", "check my config", "dns registry", "application catalog".
---

# EvidenceForge Configuration Manager

Before doing anything else, run these commands to establish where to read and write:

```bash
eforge info config_writable
eforge info overlay.exists
eforge info overlay.path
eforge info paths.activity
eforge info paths.personas
```

Do not read files. Do not search. Do not explore. Run the commands above first.

The `eforge info` command has three modes — do not mix them:
- `eforge info <field>` — get one value (e.g., `eforge info personas`, `eforge info paths.activity`)
- `eforge info --fields` — list all available field names (no other arguments)
- `eforge info --json` — get everything as JSON (no other arguments)

**Where to READ** (package defaults): use the paths from `eforge info paths.*`.

**Where to WRITE** (user changes):
- `config_writable` is `False` → WRITE to the overlay directory from `eforge info overlay.path` (create it if `overlay.exists` is False)
- `config_writable` is `True` (dev install) → ask the user: overlay or edit source files directly?

When writing to the overlay, files are partial — they contain ONLY the user's new or changed entries. The engine merges them with package defaults automatically. Mirror the package directory structure: `activity/`, `personas/`, etc.

**Rules:**
- Do NOT use `find`, `ls`, `grep`, or `glob` to locate config files — use `eforge info`
- Do NOT read or edit files under `.claude/commands/` (those are read-only skill copies)
- Do NOT edit files under `paths.*` when `config_writable` is `False` — those are inside the installed Python package

## Step 2: Classify the Operation

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

For **validation** requests ("check my config", "validate config files"), read `references/config-validation.md`.

## Step 3: Read Affected Files and Reference Docs

Read package default files from `paths.*` (READ path) to understand existing content. Also read the relevant reference doc for field schemas and conventions:

| Topic | Reference Doc |
|-------|---------------|
| DNS, traffic, proxy, site maps, network | `references/config-dns-network.md` |
| Applications, spawn rules, processes | `references/config-apps-processes.md` |
| Persona file structure | `references/config-personas.md` |
| Host activity (bash, systemd, syslog) | `references/config-host-activity.md` |
| Format definitions | `references/config-formats.md` |
| Evaluation rules | `references/config-evaluation.md` |
| Cross-file dependencies | `references/config-dependency-graph.md` |
| Validation checks | `references/config-validation.md` |

## Step 4: Interview for Completeness

Ask targeted follow-up questions to ensure the change achieves what the user actually wants. Ask one question at a time.

**Adding a domain:** What dns_tags? Appear in proxy logs? Browsable with page depth? Which personas/roles? Multiple IPs?

**Adding an application:** Which OS(es)? Categories? Which personas? Image path? PE metadata? Command templates? Parent process? Children? Network traffic?

**Creating a persona:** Role description? Typical activities? Work hours (format: "9am-5pm (lunch 12pm-1pm)")? Risk profile (low/medium/high)? Browsing intensity (light/normal/heavy)? Applications? Custom traffic? Linux user?

If you have clear domain knowledge (e.g., "API endpoints get `dev` tag"), use it. Only ask about genuinely ambiguous decisions.

## Step 5: Execute All Changes

Write ALL changes to the WRITE path established in Step 1 — the overlay directory, NOT the package files (unless the user explicitly chose source editing in a dev install).

For overlay files: create them mirroring the package structure (e.g., `<overlay>/activity/application_catalog.yaml`). Include ONLY the new/changed entries — the engine merges with package defaults automatically. You do not need to copy existing entries from the package.

Order of changes:
1. **Primary file first** — the file the user explicitly asked about
2. **Upstream dependencies** — files that need to exist for the primary to work
3. **Downstream cascades** — files that should reflect the primary change

Match existing style from the package files (indentation, quoting, comment grouping).

## Step 6: Verify and Auto-Fix

Run cross-reference checks on the **merged** data (package + overlay). Write auto-fixes to the same WRITE path as the user's changes.

**Auto-fix** (fix and report): missing proxy templates for web/saas domains, missing site maps, persona not in app catalog persona lists, app not in spawn rules.

**Advisory only** (report): app with network traffic but no process_network_map entry, new server role missing traffic profiles, evaluation rules referencing missing fields.

## Step 7: Report

1. **Files modified** — list each and what changed
2. **Auto-fixes applied** — what was added and why
3. **Suggestions** — anything else to consider

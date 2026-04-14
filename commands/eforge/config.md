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

Overlay files contain ONLY the user's additions (partial files). The engine merges them with package defaults at load time. Structure mirrors the package layout: `activity/`, `personas/`, `evaluation/`, `formats/`.

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

For **validation** requests ("check my config", "validate config files"), read `references/config-validation.md` for the 27-check procedure.

## Step 4: Read Affected Files and Reference Docs

Read the files you'll modify AND the relevant reference doc for field schemas and conventions:

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

These references contain the field schemas, valid values, formatting conventions, and examples you need. Read the relevant one before making changes.

## Step 5: Interview for Completeness

Ask targeted follow-up questions to ensure the change achieves what the user actually wants. Ask one question at a time.

**Adding a domain:** What dns_tags? Appear in proxy logs? Browsable with page depth? Which personas/roles? Multiple IPs?

**Adding an application:** Which OS(es)? Categories? Which personas? Image path? PE metadata? Command templates? Parent process? Children? Network traffic?

**Creating a persona:** Role description? Typical activities? Work hours (format: "9am-5pm (lunch 12pm-1pm)")? Risk profile (low/medium/high)? Browsing intensity (light/normal/heavy)? Applications? Custom traffic? Linux user?

**When to ask vs. when to use domain knowledge:** If you have clear domain knowledge (e.g., "API endpoints get `dev` tag" or "Slack is an Electron app"), use it. Only ask about genuinely ambiguous decisions the user needs to make.

## Step 6: Execute All Changes

Make changes to ALL affected files:

1. **Primary file first** — the file the user explicitly asked about
2. **Upstream dependencies** — files that need to exist for the primary to work
3. **Downstream cascades** — files that should reflect the primary change

When writing to the overlay: create files mirroring the package structure. Include ONLY new entries — the engine merges automatically.

Match existing style in the package files (indentation, quoting, comment grouping). The reference docs have examples.

## Step 7: Verify and Auto-Fix

Run cross-reference checks on the **merged** data (package + overlay). Auto-fix simple issues in the same location as the user's changes (overlay or package source).

**Auto-fix** (fix and report): missing proxy templates for web/saas domains, missing site maps, persona not in app catalog persona lists, app not in spawn rules.

**Advisory only** (report): app with network traffic but no process_network_map entry, new server role missing traffic profiles, evaluation rules referencing missing fields.

## Step 8: Report

1. **Files modified** — list each and what changed
2. **Auto-fixes applied** — what was added and why
3. **Suggestions** — anything else to consider

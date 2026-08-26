---
description: "Core authored-scenario contract and safe editing workflow"
---

# Scenario Core

Use this reference for every authored-scenario create, update, or repair. Load another scenario
reference only for the section being changed.

**Contents:** [Documents](#authored-documents) · [Includes](#includes) ·
[Safe mutation](#safe-mutation) · [Runtime discovery](#runtime-discovery)

## Authored documents

- New scenarios use `scenario_version: "2.0"`, even when they are monolithic and select no packs.
- Existing Scenario 1.0 documents use `version: "1.0"`. Preserve that version unless the user asks
  to migrate; never place both version keys in one document.
- A generated document starts with `kind: evidenceforge.resolved-scenario`. It is authoritative
  generation input, not an editable authoring format. Find the authored source instead.
- Unknown fields and duplicate mapping keys fail. Read the focused environment, run, or event
  reference for the exact structure being changed.

Scenario 2.0 changes only the authored envelope. Its ordinary scenario fields remain at the root:

```yaml
scenario_version: "2.0"
name: exercise-name
description: "What the exercise models"
environment: {}
time_window: {}
baseline_activity: {}
storyline: []
output: {}
```

The placeholders above are not a valid complete scenario. `environment`, `time_window`,
`baseline_activity`, and `output` need their required concrete fields after all includes and packs
are composed.

Use exactly one of `time_window.end` or `time_window.duration`. Warmup defaults to `8h` and, when
supplied, must be at least one hour. These are the smallest ordinary run sections:

```yaml
time_window:
  start: "2026-08-17T13:00:00Z"
  duration: "8h"
  warmup: "8h"
baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: medium
  suspicious_noise: high
storyline: []
red_herrings: []
output:
  logs: [{format: windows}]
  destination: "./output"
  compression: false
```

`storyline` and `red_herrings` may be empty. `environment`, time window, baseline activity, and
output must be concrete in the effective scenario even when an organization pack contributes some
of them.

## Includes

Use `includes` only to split disjoint authored fields for the same exercise. Paths resolve relative
to the YAML file that declares them. The include graph is composed once; duplicate fields are
errors, and lists are neither concatenated nor overlaid.

```yaml
includes:
  - includes/environment.yaml
  - includes/storyline.yaml
```

Each included file uses its ordinary top-level wrapper, such as `environment:` or `storyline:`.
Nested includes are allowed and remain relative to their own declaring file.

Before editing, inspect the root and complete include graph. Change the one authored file that
declares the field or list. Do not flatten includes, shadow an included field in the root, or move
unrelated content merely to make an edit convenient.

Keep a small root as a navigation surface when useful. A practical split is environment, baseline,
storyline, and red herrings, but preserve an existing layout unless restructuring is requested.

## Safe mutation

1. Resolve one absolute scenario root and use the current working directory as project context.
2. Read before writing; preserve comments, ordering, style, schema version, and unrelated content.
3. Validate references before inventing replacements: actors are modeled users, service accounts,
   or appropriate built-in identities such as `SYSTEM` and `root`; systems are modeled hostnames.
4. Make the smallest coherent patch in the declaring authored file.
5. Treat adjacent generated artifacts as stale after any authored or project-config change.
6. Validate the authored root, not an individual include fragment.

Never edit `RESOLVED_SCENARIO.yaml`, `GENERATION_MANIFEST.json`, `GROUND_TRUTH.*`, collection,
storage, observation, or artifact manifests, generated data, or completion markers. Never delete or
overwrite generated output unless the user explicitly requests the owning generate workflow.

## Runtime discovery

Run `eforge info <field> --json` before choosing configured
names.
Useful fields include `personas`, `formats`, `system_roles`, `dns_tags`, `application_ids`, and
`identity_pools`. Project `.eforge/config` can change these inventories, so installed defaults are
not a reliable substitute for inspection.

Validate after every material edit. Fix errors and actionable warnings at their owning authored
field; do not weaken containment, safety, resource, or authorization checks.

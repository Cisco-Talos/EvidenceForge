---
description: "Consume existing packs from an authored Scenario 2.0 document"
---

# Scenario Pack Consumption

Use this reference to select an existing pack. Pack discovery and lifecycle operations belong to
`/eforge pack`; catalog or model authoring belongs to `/eforge industry-pack` or
`/eforge organization-pack`. Do not load the pack-authoring contract merely to consume a pack.

Packs are optional. A Scenario 1.0 document or monolithic Scenario 2.0 document needs no
`composition`, pack scan, missing-pack warning, or migration.

## Exact selection

Select direct industry packs:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      name: healthcare
      version: "1.0.0"
```

Or select one organization, which brings its exactly pinned industry dependencies:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: project
    name: northstar-health
    version: "1.0.0"
```

Direct industries and an organization are mutually exclusive. Every persisted reference requires
an explicit `source`, `name`, and semantic `version`; there is no implicit latest version. Source
is `package`, `project`, or `path`. A path reference additionally requires `path`:

```yaml
- source: path
  path: ../packs/custom-healthcare
  name: custom-healthcare
  version: "1.0.0"
```

The path is relative to the YAML file that declares it, including an include. Manifest identity
must match the reference. Pack catalog exports use their qualified public identities; do not use
ambiguous shorthand for pack exports.

## What still belongs in the scenario

Industry packs contribute reusable catalogs, not a concrete organization. A scenario selecting
direct industries must still author a complete concrete `environment` and `baseline_activity`, as
well as its time window, storyline, red herrings, and output.

An organization pack may contribute partial concrete environment and baseline fragments. The
effective compiled result must still satisfy all required scenario fields; scenario-local fields
are appropriate for exercise-specific additions and overrides.

Project `.eforge/config` remains a separate project-wide configuration layer. It is not a pack and
must not be copied into scenario YAML. Effective precedence is packaged defaults, direct industry
packs, organization pack, project config, then scenario-local fields.

## Inspect before authoring against exports

Use an exact CLI reference such as `package:industry:healthcare@1.0.0`:

```bash
eforge pack list --project-root <absolute-project-root> --json
eforge pack show <exact-ref> --project-root <absolute-project-root> --json
eforge resolve <scenario> --project-root <absolute-project-root> \
  --explain-composition --json
```

Inspect identities, compatibility, dependencies, digest, exports, merges, and field origins. Do
not guess qualified IDs. Use non-writing explanation mode during iteration; write an authoritative
resolved document only when the user requests the artifact.

Ordinary explanation JSON stays compact. Only when the task needs pack-contributed concrete model
fields, add `--include-effective-scenario` and inspect its stable `effective_scenario` object. This
is required before writing an effective `ENVIRONMENT.md`; it does not write a temporary artifact.

The resolved document is generated and non-editable. It is the correct source for the effective
environment and briefing, but authored changes must go back to the declaring scenario/include,
pack, or project-config owner.

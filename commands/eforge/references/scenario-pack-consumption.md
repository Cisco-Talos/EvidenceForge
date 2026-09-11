---
description: "Consume existing packs from an authored Scenario 2.0 document"
---

# Scenario Pack Consumption

Use this reference to select an existing pack. Pack discovery and lifecycle operations belong to
`/eforge pack`; catalog or model authoring belongs to `/eforge industry-pack` or
`/eforge organization-pack`. Do not load the pack-authoring contract merely to consume a pack.

Packs are optional. Scenario 1.0 and monolithic Scenario 2.0 need no composition or pack scan.

## Contents

- [Context decision](#pre-authoring-context-decision) · [Selection](#exact-selection)
- [Ownership](#what-still-belongs-in-the-scenario) · [Inspection](#inspect-before-authoring-against-exports)

## Pre-authoring context decision

Every new scenario needs explicit industry and organization decisions. Packs are optional;
silently assuming generic or inventing an organization is not. Do not repeat decisions already
supplied by the prompt or a referenced file.

Industry context is a named industry, an installed industry pack, or generic/industry-neutral. A
named organization pack supplies its pinned industry. Otherwise list packs from the current working
directory and, when industry is missing, ask one question offering available industries, another
industry, or generic.

Organization context must use one of these paths:

- a compatible organization pack;
- a guided scenario-local organization;
- reusable organization-pack authoring; or
- sufficient details already provided in the prompt or an explicitly referenced file.

“Sufficient details already provided” requires an organization identity or archetype, scale,
naming/domain posture, and the major users, systems, services, and topology needed by the narrative.
Explicit delegation such as “you decide” also permits reasonable inference. A bare adjective such
as “large enterprise” or an industry selection alone is not sufficient.

After an industry choice, offer only organization packs whose pinned dependency matches it. If none
exists or the user declines them, ask whether to guide a scenario-local organization or author a
reusable organization pack unless sufficient details were already provided. For guided work, ask
one material question at a time, then present a concise organization summary for confirmation.

Do not write scenario artifacts until both decisions and any required confirmation are complete.
Do not repeat these checkpoints for an established existing scenario.

## Exact selection

Select direct industry packs:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      publisher: evidenceforge
      name: healthcare
      version: "1.0.0"
```

Or select one organization, which brings its exact locked industry dependencies:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: project
    publisher: example-publisher
    name: northstar-health
    version: "1.0.0"
```

Direct industries and an organization are mutually exclusive. Every persisted reference requires
an explicit `source`, `publisher`, `name`, and semantic `version`; there is no implicit latest version. Source
is `package`, `project`, or `path`. A path reference additionally requires `path`:

```yaml
- source: path
  path: ../packs/custom-healthcare
  publisher: example-publisher
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

`pack show` calls the six reusable catalogs `exports`. Those lists do not include an organization
pack's `environment` or `baseline_activity` model fragments. Empty catalog exports therefore do
not mean that an organization pack lacks users, systems, domain, topology, storage, or baseline
content. Never infer that those fields belong in the scenario until effective composition proves
they are absent.

Stable organization `deployment_overrides` and `observation_overrides` remain reusable exact-target
defaults. Scenario-local patches for the same case-insensitive `system` or `source_instance` merge
field by field; omitted fields inherit and explicit empty lists replace lower-layer values.

Project `.eforge/config` remains a separate project-wide configuration layer. It is not a pack and
must not be copied into scenario YAML. Effective precedence is packaged defaults, direct industry
packs, organization pack, project config, then scenario-local fields.

## Inspect before authoring against exports

Use an exact CLI reference such as `package:evidenceforge:industry:healthcare@1.0.0`:

```bash
eforge pack list --json
eforge pack show <exact-ref> --json
eforge resolve <scenario> --explain-composition --json
```

Inspect identities, compatibility, dependencies, digest, exports, merges, and field origins. Do
not guess qualified IDs. Use non-writing explanation mode during iteration; write an authoritative
resolved document only when the user requests the artifact.

The selected root does not need a `.eforge` directory to use installed `package` packs; project
pack and config layers are simply absent. Treat a package pack's reported filesystem `location` as
diagnostic metadata and do not traverse it during scenario authoring. Follow
`/eforge:references:project-context` rather than searching for another root.

Ordinary explanation JSON stays compact. Only when the task needs pack-contributed concrete model
fields, add `--include-effective-scenario` and inspect its stable `effective_scenario` object. This
is required before writing an effective `ENVIRONMENT.md`; it does not write a temporary artifact.
For a self-contained organization, begin with a thin wrapper containing the exact composition
reference plus scenario identity, time, and output, then resolve before adding any local
environment fields.

The resolved document is generated and non-editable. It is the correct source for the effective
environment and briefing, but authored changes must go back to the declaring scenario/include,
pack, or project-config owner.

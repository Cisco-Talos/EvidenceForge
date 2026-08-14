---
name: eforge-organization-pack
description: >
  Create, extend, tailor, or repair reusable EvidenceForge organization packs through chat. Use
  this skill when the user wants a fictional or modeled organization's exact industry dependencies,
  organization-specific catalogs, reusable users, systems, groups, topology, services, email
  environment, SMB environment, or baseline activity; wants to fork a sample organization; or
  wants to author, validate, or version organization-pack content. Do not use it for storylines,
  time windows, output settings, OOB policy, evaluation policy, or project config overlays.
---

# EvidenceForge Organization Pack Author

Author reusable organization context on top of exactly pinned industry packs. Default to a
self-contained environment and baseline that a small Scenario 2.0 wrapper can consume directly.

## Establish context

1. Resolve one concrete absolute project root and pass it through every CLI call.
2. Use `eforge` directly; in a source checkout where it is unavailable, retry with
   `uv run eforge`.
3. Read `/eforge:references:pack-reference` completely for pack fields and lifecycle rules.
4. Read `/eforge:references:scenario-reference` for the exact `environment` and
   `baseline_activity` fields needed by this organization.
5. Discover candidate dependencies and bases:

```bash
eforge pack list --project-root <absolute-project-root> --json
eforge pack show <exact-industry-or-organization-ref> \
  --project-root <absolute-project-root> --json
eforge info pack_builtin_application_ids
eforge info pack_builtin_dns_tags
```

Do not infer an implicit latest version or inspect package directories as a substitute for the CLI.

## Interview one decision at a time

Determine:

1. The organization boundary and whether all names must be newly fictionalized.
2. The exact industry source, name, and version dependencies.
3. Whether to initialize a blank pack or fork the closest organization sample.
4. Whether the pack must stand alone or intentionally depends on a named consumer scenario.
5. Which reusable users, systems, groups, services, network segments, sensors, email topology,
   storage topology, and baseline activity belong to the organization.
6. Which organization-specific personas, processes, applications, destinations, traffic, or
   storage vocabulary cannot be reused from an industry dependency.

Ask only questions whose answers change the model. Prefer qualified dependency exports over
duplicating them.

## Initialize or fork

Use `0.1.0` for an explicitly identified draft and `1.0.0` for the first complete pack when the
user supplies no version. Edit only a confirmed unshared draft in place. Fork any shared,
referenced, or complete pack: patch for compatible corrections, minor for compatible additions,
major for incompatible changes.

```bash
eforge pack init organization <name> --version <version> \
  --project-root <absolute-project-root> --json

eforge pack copy <exact-organization-ref-or-path> --name <name> --version <version> \
  --project-root <absolute-project-root> --json
```

Never edit a packaged pack or overwrite an existing project version. After a renamed copy, confirm
that local self-references use the new namespace while dependency references are unchanged.
`pack copy` performs a technical namespace fork, not an organization rebrand: prose, domains,
hostnames, usernames, email addresses, share names, and other modeled identity remain unchanged.
Ask whether the user wants a namespace-only tailored copy or a full fictional rebrand. For a full
rebrand, inventory and deliberately update every organization-facing identity while preserving
dependency namespaces; never apply an unreviewed global string replacement.

## Pin dependencies first

Declare every industry dependency with exact `source`, `type: industry`, `name`, and `version`; add
`path` only for `source: path`. Validate and inspect each dependency before referencing its exports.
An organization may depend on industries; an industry may not depend on another industry.

Use qualified references such as `healthcare:clinical-coordinator`. Never copy a dependency export
into the organization merely to avoid qualification.

## Author organization content

Keep all six fixed catalog files and both model files, including empty root mappings. Work in this
order:

1. Pin and validate dependencies.
2. Add only organization-specific catalog exports.
3. Author the partial or complete `environment` fragment.
4. Author the partial or complete `baseline_activity` fragment.
5. Reconcile users, personas, systems, groups, roles, services, segments, sensors, email routes,
   storage shares/mappings, and catalog references across the effective composed model.

Apply the same generation-effective catalog chain as an industry pack: applications own persona
audiences, process references, and named destination/service connections; traffic references those
connections and uses structured cadence; low-level outbound remains only for processless/system
activity.

Default to self-contained content. If the user explicitly requests a partial organization pack:

- Identify the representative consumer scenario by path or create a temporary one.
- Document which required model pieces the consumer supplies.
- Resolve and validate that exact consumer before claiming the pack is usable.
- Report the pack as partial, not standalone.

Do not add storyline events, red herrings, time windows, output targets, collection settings,
credentials, safety, OOB authorization, resource policy, evaluation rules, or runtime policy.
Do not place `ENVIRONMENT.md` in a pack. A temporary harness does not need one. If a consumer
scenario will be retained, hand it to the scenario skill after resolution; that skill must use its
`ENVIRONMENT.md` template to create the attack-free analyst briefing from the effective resolved
environment.

Do not set `environment.email.corpus` in an organization pack. Pack-owned corpus-path provenance is
not part of the current public contract. Keep any corpus path scenario-owned until that asset model
is explicitly added.

Use fictional entities, reserved domains, and reserved public/private address ranges. Add no
executable hooks or arbitrary assets.

## Validate continuously

After each coherent edit:

```bash
eforge pack validate <project:organization:name@version> \
  --project-root <absolute-project-root> --json
```

Treat structural validation as necessary but not sufficient: partial model fragments can be valid
only in a consumer context. Fix every schema, dependency, reference, collision, containment, or
runtime-semantic error before continuing.

At handoff, inspect identity, dependencies, and exports:

```bash
eforge pack show <project:organization:name@version> \
  --project-root <absolute-project-root> --json
```

## Prove the effective organization

Create or select a Scenario 2.0 consumer outside the pack root. A self-contained organization
harness normally needs only the exact composition reference, scenario name/description, fixed seed,
time window, and output. A partial organization harness must supply every deliberately omitted
environment or baseline requirement.

Use a fresh temporary resolved filename for each proof attempt because authoritative resolved
documents are never silently overwritten. Choose each cadence proof window after expected
interactive-session bootstrap—normally at least ten local minutes after login—and keep it open
long enough for startup pacing and the authored pattern.

Run:

```bash
eforge resolve <consumer-scenario.yaml> --output <temporary-resolved.yaml> \
  --project-root <absolute-project-root> --explain-composition --json
eforge validate <consumer-scenario.yaml> --project-root <absolute-project-root> --show-storage
eforge generate <consumer-scenario.yaml> --output <absolute-temporary-output> \
  --project-root <absolute-project-root> --seed 42 --force
```

Inspect the composition explanation for exact dependencies, origins, replacements, and qualified
references. Inspect generated records for representative users, systems, applications,
destinations, cadence, email behavior, and SMB behavior that the pack claims to provide.
Always pass an absolute temporary `--output`. If the claimed proof requires Zeek, IDS, or firewall
records, confirm the effective organization has a compatible observing sensor before generation.
Selecting a format enables its emitter but does not guarantee a file in a short probabilistic run.
To prove SMTP or bash output, use a calibrated longer window or a deterministic scenario-local
email or Linux process event.

Do not leave temporary resolved or generated output inside the pack. Preserve a consumer scenario
only when the user requests an example or regression fixture.

## Report

Return the exact organization reference, exact industry dependencies, version rationale, standalone
or partial status, files and exports authored, final digest, validation result, consumer-harness
result, and representative runtime evidence observed. State what remains scenario-owned.

---
name: eforge-industry-pack
description: >
  Create, extend, tailor, or repair reusable EvidenceForge industry packs through chat. Use this
  skill when the user wants sector-specific personas, processes, applications, destinations,
  traffic cadence, or SMB storage vocabulary for finance, healthcare, technology, or another
  industry; wants to turn repeated scenario content into an industry pack; or wants to author or
  version an industry-pack catalog. Do not use it for a concrete organization's users, systems,
  topology, baseline model, storyline, output, or project config overlay.
---

# EvidenceForge Industry Pack Author

Author reusable sector vocabulary that changes deterministic generation behavior. Industry packs
contain all six fixed catalogs and no concrete environment or baseline model.

## Establish context

1. Resolve one concrete absolute project root and pass it through every CLI call.
2. Use `eforge` directly; in a source checkout where it is unavailable, retry with
   `uv run eforge`.
3. Read `/eforge:references:pack-reference` completely before editing a catalog. It is the
   authoritative field, reference, validation, and harness contract.
4. Read `/eforge:references:scenario-reference` before building a consumer harness that needs
   exact environment, topology, sensor, output, or storage fields.
5. Discover existing packs and built-in process profiles before proposing names:

```bash
eforge pack list --project-root <absolute-project-root> --json
eforge info pack_builtin_application_ids
eforge info pack_builtin_dns_tags
```

Inspect any candidate base pack with `pack show --json`. Do not scan package directories to
reconstruct inventory.

## Interview one decision at a time

Determine:

1. The industry boundary and workflows the pack should represent.
2. Whether to start from an empty skeleton or fork the closest existing pack.
3. Whether this is an unshared draft or a complete/shared version.
4. Which personas need distinct work patterns.
5. Which built-in or custom process profiles those personas use.
6. Which applications connect to which named destination services.
7. Whether traffic is weighted, periodic, burst-oriented, or a deliberate mixture.
8. Which bounded SMB directory, subject, and file-type vocabulary is useful.

Ask only about choices that materially affect the model. Infer ordinary sector details, then state
those assumptions before writing.

## Initialize or fork

Use `0.1.0` for an explicitly identified draft and `1.0.0` for the first complete pack when the
user supplies no version. An unshared draft may be edited in place. Fork any shared, referenced, or
complete pack to a new SemVer: patch for compatible corrections, minor for compatible additions,
major for incompatible changes.

```bash
eforge pack init industry <name> --version <version> \
  --project-root <absolute-project-root> --json

eforge pack copy <exact-industry-ref-or-path> --name <name> --version <version> \
  --project-root <absolute-project-root> --json
```

Never edit a packaged pack or overwrite an existing project version.

## Author the catalogs

Keep every fixed file and root key, even when empty. Work in dependency order:

1. Define personas and destinations.
2. Select stable built-in processes or define realistic custom platform processes.
3. Define applications with authoritative persona audiences, process references, and named
   destination/service connections.
4. Define traffic entries that reference applications and their named connections; use low-level
   outbound traffic only for activity without an application process.
5. Define structured weighted, periodic, or burst cadence where the default weekday behavior is
   insufficient.
6. Add bounded storage vocabulary only when the industry commonly produces shared-file activity.

Use local IDs inside the pack; the loader qualifies them as `<pack-name>:<local-id>`. Reference an
export from another pack only where the contract explicitly permits it. Industry packs cannot
declare dependencies on other industry packs.

Make process/application/traffic content a closed, generation-effective chain:

- Every custom process must be eligible on a modeled platform and have realistic executable paths
  and command templates.
- Every application audience must resolve to a persona.
- Every application process reference must resolve to a built-in or local process profile.
- Every application connection must resolve to an exact destination and typed service.
- Every application traffic reference must name an application connection.
- Keep document terms scoped to the process templates that consume them.

Do not add concrete users, systems, groups, topology, services, storage servers/shares/mappings,
email topology, storyline events, red herrings, time windows, output targets, credentials, safety,
OOB authorization, resource policy, evaluation rules, runtime policy, or model files.

Use fictional names, `.example` or `.invalid` domains, RFC-reserved public addresses, and private
addresses where appropriate. A pack is untrusted inert YAML: add no hooks or arbitrary assets.

## Validate continuously

After each coherent edit:

```bash
eforge pack validate <project:industry:name@version> \
  --project-root <absolute-project-root> --json
```

Repair every schema, reference, compatibility, collision, containment, or runtime-semantic error
before continuing. Do not dismiss a field because it serializes: prove it participates in the
catalog chain.

At handoff, inspect identity and exports:

```bash
eforge pack show <project:industry:name@version> \
  --project-root <absolute-project-root> --json
```

## Prove composition and runtime behavior

Create a temporary Scenario 2.0 consumer outside the pack root. Select the exact project industry
reference and provide a small scenario-local environment with at least one user of a pack persona
and a compatible system. Include a fixed seed, a one-hour window with warmup, low baseline
intensity, and only the formats needed to observe the authored behavior. Choose a local date and
hour that overlap every cadence behavior the harness is intended to prove. Start narrow cadence
windows after expected interactive-session bootstrap—normally at least ten local minutes after
login—and leave enough time for startup pacing.

Then run:

```bash
eforge resolve <temporary-scenario.yaml> --output <temporary-resolved.yaml> \
  --project-root <absolute-project-root> --explain-composition --json
eforge validate <temporary-scenario.yaml> --project-root <absolute-project-root>
eforge generate <temporary-scenario.yaml> --output <absolute-temporary-output> \
  --project-root <absolute-project-root> --seed 42 --force
```

Use a fresh temporary resolved filename for each attempt; an existing authoritative resolved
document is not overwritten when its identity differs.

Verify from the composition explanation and generated records that the qualified persona, selected
process, application, exact destination/service, and intended cadence appear. If storage was
authored, add a scenario-local storage server/share using the qualified preset and validate with
`--show-storage`.

The standard industry harness uses host and eCAR output. If the user needs Zeek, IDS, or firewall
proof, use the scenario reference to add compatible topology plus a sensor that observes the modeled
path; requesting a network format alone does not create sensor visibility. Always pass an absolute
temporary `--output` so verification never depends on scenario-relative destination behavior.

Do not leave temporary resolved or generated output in the pack. Preserve a consumer scenario only
when the user requests an example or regression fixture.

## Report

Return the exact reference, version rationale, files and exports authored, final digest, validation
result, consumer-harness result, and specific runtime evidence observed. Identify any intentionally
empty catalog and why it remains empty.

# Scenario 2.0 and composable packs

Scenario 2.0 can compose reusable industry or organization data while preserving monolithic
authoring. Packs are optional: Scenario 1.0 and Scenario 2.0 without `composition` do not discover
packs and do not warn about their absence.

Use packs for reusable, versioned context. Keep an exercise's time window, storyline, red
herrings, output, collection choices, and other run-specific fields in its scenario. The complete
pack field and validation contract is in the
[Pack Authoring Reference](../../commands/eforge/references/pack-reference.md).

## Choose the right authoring layer

| Layer | Use it for | Do not use it for |
|---|---|---|
| Industry pack | Reusable sector personas, processes, applications, destinations, traffic, and SMB storage vocabulary | Concrete users, hosts, topology, or one exercise |
| Organization pack | Exactly pinned industries, organization-specific catalogs, concrete environment, and baseline activity | Storylines, time/output settings, or runtime policy |
| Scenario | Exercise identity, seed, time, output, storyline, red herrings, and scenario-local additions/overrides | Content that should be shared and independently versioned |
| `.eforge/config` overlay | Project-wide tuning of EvidenceForge's internal configuration families | A portable public pack contract or scenario selection |

Packs cannot set safety, OOB authorization, credentials, resource policy, evaluation rules, output
policy, or engine runtime policy.

## Scenario forms

A monolithic Scenario 2.0 file replaces the legacy top-level `version` field with
`scenario_version` and otherwise uses the canonical scenario fields:

```yaml
scenario_version: "2.0"
name: monolithic-example
description: "No packs are required."
environment: ...
time_window: ...
baseline_activity: ...
output: ...
```

Select direct industry packs:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      name: healthcare
      version: "1.0.0"
name: healthcare-example
# Supply the concrete environment, time window, output, and optional storyline here.
```

Or select one organization pack, which brings its exactly pinned industry dependencies:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: package
    name: northstar-health
    version: "1.0.0"
name: northstar-baseline
time_window: ...
output: ...
```

Direct industries and an organization are mutually exclusive. Persisted references always contain
an exact source, name, and `X.Y.Z` version; EvidenceForge never selects an implicit latest version.
`source` is `package`, `project`, or `path`. A path reference also contains `path`:

```yaml
source: path
path: ../packs/custom-healthcare
name: custom-healthcare
version: "1.0.0"
```

The path is relative to the YAML file that declares the reference, including when composition came
from an include. The referenced manifest name and version must match the persisted values.

## Repositories and project roots

EvidenceForge resolves whole packs from three sources:

```text
package  <installed-config-root>/packs/<type>/<name>/<version>/
project  <project-root>/.eforge/packs/<type>/<name>/<version>/
path     an explicitly named external directory
```

Installed package packs are read-only. Project packs are editable. A path pack is used only when a
scenario or command explicitly names it. There is no implicit user-global pack registry.

For scenario compilation, the project root is selected in this order:

1. Explicit `--project-root`.
2. Nearest ancestor of the root scenario containing `.eforge`.
3. The root scenario's directory.

Compilation never falls back to the process working directory. For pack-management commands that
do not have a scenario, the order is explicit `--project-root`, the nearest `.eforge` ancestor of
the working directory, then the working directory. Chat-driven workflows resolve one absolute
project root and pass it explicitly to every applicable command.

## Fixed pack contract

Every pack contains `pack.yaml` and all six catalog files, including unused catalogs:

```text
pack.yaml
catalogs/persona_catalog.yaml       # persona_catalog
catalogs/process_catalog.yaml       # process_catalog
catalogs/application_catalog.yaml   # application_catalog
catalogs/destination_catalog.yaml   # destination_catalog
catalogs/traffic_catalog.yaml       # traffic_catalog
catalogs/storage_catalog.yaml       # storage_catalog
```

Organization packs additionally contain:

```text
model/environment.yaml              # environment
model/baseline_activity.yaml        # baseline_activity
```

Each unused catalog remains present with an empty predictable root, such as
`application_catalog: {}`. This lets authors and tools predict every available filename and root
key across all packs.

A pack manifest identifies its public contract and compatibility:

```yaml
pack_schema_version: "1.0"
type: industry
name: healthcare
version: "1.0.0"
requires_evidenceforge: ">=2.0.0,<3.0.0"
description: "Reusable fictional healthcare behavior and vocabulary."
industry_dependencies: []
```

Only organization packs may declare `industry_dependencies`. Every dependency pins its exact
source, `type: industry`, name, and version. Industry packs cannot depend on other industries.

Pack-local IDs become public qualified IDs in the form `<pack-name>:<local-id>`. For example,
`healthcare` local persona `clinical-coordinator` becomes
`healthcare:clinical-coordinator`. Inside the same pack, references may use local IDs; an
organization must use qualified references to dependency exports. Built-in and scenario-local
names retain their existing shorthand for monolithic compatibility.

## Catalogs and runtime behavior

The catalogs are a stable public API rather than copies of internal configuration files:

| Catalog | Defines | Generation effect |
|---|---|---|
| Persona | Reusable behavioral roles | Work hours, risk, intensity, and application eligibility |
| Process | Built-in/custom executable profiles and scoped document terms | Process images, commands, metadata, and selection |
| Application | Persona audience, process profiles, and named connections | Exact eligible process and connection graph |
| Destination | Synthetic endpoints, tags, and typed services | DNS ownership and destination IP/port/protocol |
| Traffic | Application activity, structured cadence, and low-level outbound traffic | Deterministic baseline timing and network activity |
| Storage | Bounded directory, subject, and file-type vocabulary | SMB share population and activity presets |

Persona entries use the canonical persona shape. The other five catalogs use a stable
`description` plus typed `data` envelope. Unknown keys are rejected.

Application-owned traffic forms a closed graph:

```text
traffic audience -> application -> process profile
                               -> named connection -> destination -> typed service
```

Validation rejects unresolved or orphaned graph elements. At runtime, application traffic uses
only the referenced application's eligible processes and the exact named destination/service; it
does not guess a process from a port or select a destination through a broad tag.
Every named application connection must have a traffic consumer; otherwise validation rejects it
as inert.

Traffic supports `weighted`, `periodic`, and `burst` cadence in the scenario's local timezone.
Cadence changes deterministic generation timing; it is not documentation-only. Low-level
`outbound` entries are reserved for legitimate processless/system traffic. Discover the stable,
packaged-only inventories allowed by the public schema with:

```bash
eforge info pack_builtin_application_ids
eforge info pack_builtin_dns_tags
```

Pack process document terms are scoped to their process profile and do not enter global command
pools. An industry storage entry supplies vocabulary, not a concrete server/share; a scenario or
organization selects its qualified preset while owning storage topology, access, population, and
activity. Storage vocabulary stays provider-neutral and contains bounded SMB-relative directory,
subject, extension, and MIME components—not Windows drives, Linux mounts, backing filesystems,
Samba audit policy, or client-process profiles.

An organization may own the concrete cross-platform SMB environment: Windows or Linux server
systems, OS-native volume mounts and backing filesystems, share-advertised filesystem labels,
access/audit settings, Windows drive or Linux mount mappings, and the services that grant Linux
baseline client/server capability. It must not copy internal `smb_profiles.yaml` into a pack or
depend on a project-only profile override. Those profiles are engine/project policy; the public organization
model selects stable modes such as `cifs_mount` or `smbclient` through canonical scenario fields.

Organization `environment` and `baseline_activity` files are typed partial canonical fragments.
A reusable organization should normally be self-contained enough for a thin Scenario 2.0 wrapper.
An intentionally partial organization must name and pass a representative consumer scenario before
it can be claimed usable.

## Composition and precedence

Effective generation data is applied in this order:

1. Installed EvidenceForge defaults.
2. Direct industry packs for additive exports.
3. The organization pack.
4. Project `.eforge/config` overlays under their established per-family merge rules.
5. Scenario-local model fields and authored overrides.

Packs are peers, not arbitrary recursive overlays. Industry order does not resolve incompatible
definitions: export collisions and incompatible identities fail with source and pack provenance.
An organization's exactly pinned dependencies are resolved before its own catalogs/model. The
compiled scenario records selected identities and digests, authored `field_origins`, qualified
`catalog_field_origins`, `organization_model_origins`, and concrete `merge_decisions`. Origin paths
are portable and retain the exact included YAML file that declared each value.

## Author packs through chat

Install the bundled agent skills, then use the matching workflow:

```bash
uv run eforge install-skills
```

- `/eforge pack` (Claude Code) or `eforge-pack` (ChatGPT/Codex) lists, compares, inspects,
  initializes, copies, versions, validates, and diagnoses packs.
- `/eforge industry-pack` or `eforge-industry-pack` authors reusable industry catalogs and proves
  them with a small consumer scenario.
- `/eforge organization-pack` or `eforge-organization-pack` authors concrete organizations,
  dependencies, and organization-only catalogs and proves their effective environment.
- `/eforge scenario` or `eforge-scenario` selects exact packs, chooses the monolithic/composed
  boundary, and authors the exercise-specific wrapper.
- `/eforge config` or `eforge-config` manages internal `.eforge/config` overlays, not packs.

The authoring skills use JSON command output for decisions, validate after coherent edits, resolve
a representative consumer with composition provenance, and run fixed-seed generation to verify
that pack fields affect evidence rather than merely serialize.

## CLI lifecycle

Use exact CLI references in the form `source:type:name@version`:

```bash
eforge pack list --project-root /absolute/project --json
eforge pack show package:industry:healthcare@1.0.0 \
  --project-root /absolute/project --json
eforge pack validate package:organization:northstar-health@1.0.0 \
  --project-root /absolute/project --json

# Create every canonical file under .eforge/packs; never overwrite.
eforge pack init industry custom-healthcare --version 0.1.0 \
  --project-root /absolute/project --json

# Create an editable project-local fork with non-semantic copy provenance.
eforge pack copy package:industry:healthcare@1.0.0 \
  --name tailored-healthcare --version 1.0.0 \
  --project-root /absolute/project --json

# Compile without generation and explain exact selection, origins, and precedence.
eforge resolve scenario.yaml --output resolved.yaml \
  --project-root /absolute/project --explain-composition --json
```

`pack init` and `pack copy` publish atomically and refuse unsafe identities, traversal, symlinked
ancestry, or an existing destination. A renamed copy rewrites typed semantic self-references but
does not rewrite prose or dependency namespaces. There is no public pack-delete command.

Use a draft-aware version policy:

- Default a clearly identified new draft to `0.1.0` and a first complete pack to `1.0.0`.
- Edit in place only when an existing version is confirmed unshared, unreferenced, and still a
  draft.
- Copy a shared, referenced, or complete pack to a new exact version before editing.
- Use patch for compatible corrections, minor for compatible additions, and major for removals,
  renames, or incompatible behavior changes.

Validation covers fixed files and schemas, exact identity/compatibility/dependencies, include
containment and budgets, export collisions, catalog graph semantics, typed organization fragments,
and forbidden files. Structural validation alone cannot prove a partial organization; resolve,
validate, generate, and inspect its representative consumer.

## Included examples

EvidenceForge ships these ordinary, validated package packs:

- `package:industry:finance@1.0.0`
- `package:industry:healthcare@1.0.0`
- `package:industry:technology@1.0.0`
- `package:organization:northstar-health@1.0.0`

`northstar-health` pins the healthcare industry and demonstrates a concrete mixed environment,
email activity, and SMB-backed storage. The samples use the same public schemas and runtime paths
as custom packs; they are not special-cased built-ins.

## Includes, safety, and portability

Pack YAML may use bounded includes contained within its pack root. Included mappings must be
disjoint; includes compose fields rather than overriding them. Unknown YAML, duplicate keys,
traversal, symlink escape, cyclic/excessive includes, identity mismatch, incompatible versions,
unreachable semantic YAML, and export collisions fail validation.

Permitted non-semantic companions are `README.md`, `LICENSE`/`LICENSE.md`, and
`COPY_PROVENANCE.md`. They do not affect the pack digest. Executable hooks, scripts, binaries,
templates, corpora, and arbitrary assets are forbidden. Use fictional entities, reserved domains,
and reserved/private address ranges; never place secrets or live operator endpoints in reusable
packs.

## Authoritative generated bundles

Successful generation writes `RESOLVED_SCENARIO.yaml` and writes
`GENERATION_MANIFEST.json` last. The resolved document contains the canonical runtime scenario,
pack identities/digests, portable source provenance, embedded YAML/corpora, and immutable effective
configuration. Loading it bypasses authored includes, pack repositories, project discovery,
installed YAML reads, and ambient caches. It is generated and non-editable.

The generation manifest records runtime/build identity, effective seed/formats/target, permitted
overrides, selected pack digests, the resolved-file hash, and every bundle-file hash. Existing
domain sidecars remain; the manifest is the authoritative run identity.

When composed storage is present, `STORAGE_MANIFEST.json` schema v2 is the authoritative compiled
storage view. It retains pack-qualified presets while separating server platform, backing and
SMB-advertised filesystems, Windows drive and Linux mount presentations, credential identity, and
resolved storyline targets. It is metadata-only and does not make a pack responsible for runtime
credentials or file payloads.

New bundles evaluate without an authored scenario:

```bash
eforge eval OUTPUT
```

`eforge eval OUTPUT --scenario scenario.yaml` recompiles the authored input with the manifest's
effective seed/options and fails on a digest mismatch. `--allow-scenario-mismatch` permits the
comparison mismatch, but evaluation still uses the bundle's resolved scenario. Legacy bundles
still require `--scenario`.

Literal OOB hosts always require a fresh matching `--oob-host` on validate, resolve, or generate.
Neither a pack nor a previously resolved document grants that authorization.

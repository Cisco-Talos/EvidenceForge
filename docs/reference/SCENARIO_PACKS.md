# Scenario 2.0 and composable packs

Scenario 2.0 can compose reusable industry or organization data while preserving the existing
monolithic authoring model. Packs are optional: a Scenario 1.0 file or a Scenario 2.0 file without
`composition` does not discover packs and does not warn about their absence.

## Scenario forms

A monolithic Scenario 2.0 file replaces the legacy top-level `version` field with
`scenario_version` and otherwise uses the same canonical scenario fields:

```yaml
scenario_version: "2.0"
name: monolithic-example
description: No packs are required
environment: ...
time_window: ...
baseline_activity: ...
output: ...
```

Select direct industry packs in declared order:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      name: healthcare
      version: "1.0.0"
name: healthcare-example
# Scenario-local environment, time window, output, and optional storyline follow.
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

Direct industries and an organization are mutually exclusive. Persisted references always name an
exact source, name, and semantic version; there is no implicit latest-version lookup. `source` is
`package`, `project`, or `path`. A path reference also includes `path`, and that path is relative to
the YAML file that declares it—even when the composition field is in an include.

## Repositories and precedence

EvidenceForge resolves whole packs from:

- Installed read-only data: `src/evidenceforge/config/packs/<type>/<name>/<version>/`.
- Project-local editable data: `<project-root>/.eforge/packs/<type>/<name>/<version>/`.
- An explicit scenario or CLI path.

There is no implicit user-global pack registry. Scenario project-root selection is, in order:
explicit `--project-root`, the nearest ancestor of the root scenario containing `.eforge`, then the
root scenario directory. Compilation never uses the process working directory as a fallback.

Effective generation data is applied in this order:

1. Installed EvidenceForge defaults.
2. Direct industry packs (additive exports; peer collisions are errors).
3. The organization pack.
4. Project `.eforge/config` overlays, retaining their existing per-file merge rules.
5. Scenario-local model fields and authored overrides.

Packs are part of the data-driven configuration layer, but they are not arbitrary config overlays.
Public pack schemas are stable adapters; internal config filenames are not pack API. Evaluation,
safety, resource, runtime, output, credential, storyline, and OOB policy remain engine/scenario
owned and cannot be changed by packs.

## Fixed pack contract

Each pack has `pack.yaml` and all six catalog files, including empty catalogs:

```text
pack.yaml
catalogs/persona_catalog.yaml       # persona_catalog
catalogs/process_catalog.yaml       # process_catalog
catalogs/application_catalog.yaml   # application_catalog
catalogs/destination_catalog.yaml   # destination_catalog
catalogs/traffic_catalog.yaml       # traffic_catalog
catalogs/storage_catalog.yaml       # storage_catalog
```

Organization packs additionally have:

```text
model/environment.yaml              # environment
model/baseline_activity.yaml        # baseline_activity
```

Catalog exports are referenced as `<pack-name>:<local-name>`, for example
`healthcare:clinical_coordinator` or `healthcare:clinical-department`. This makes ownership
predictable and prevents accidental cross-pack shorthand. Built-in and scenario-local names retain
their existing shorthand for monolithic compatibility.

Pack YAML may use bounded includes contained within its pack root. Unknown YAML, missing canonical
files, duplicate keys, traversal, symlink escapes, incompatible versions, identity mismatches, and
export collisions fail validation. README, license, and `COPY_PROVENANCE.md` files are non-semantic;
executable hooks and unconstrained assets are not allowed.

## CLI workflow

```bash
eforge pack list --json
eforge pack show package:industry:healthcare@1.0.0 --json
eforge pack validate package:organization:northstar-health@1.0.0 --json

# Complete project-local skeleton; never overwrites an existing pack.
eforge pack init industry custom-healthcare --version 1.0.0

# Editable project-local fork with non-semantic copy provenance.
eforge pack copy package:industry:healthcare@1.0.0 \
  --name tailored-healthcare --version 1.0.0

# Compile without generation and explain origins/precedence.
eforge resolve scenario.yaml --output RESOLVED_SCENARIO.yaml --explain-composition --json
```

`eforge info pack_roots` reports repository locations and `eforge info packs` reports exact
available references. `pack init` and `pack copy` are foundations for authoring; dedicated
industry/organization pack-authoring skills are a separate follow-on feature.

## Authoritative generated bundles

Successful generation writes `RESOLVED_SCENARIO.yaml` and writes
`GENERATION_MANIFEST.json` last. The resolved document contains the canonical runtime scenario,
pack identities/digests, source provenance, embedded YAML/corpora, and the immutable effective
configuration. Loading it bypasses authored includes, pack repositories, project discovery,
installed YAML reads, and ambient caches. It is generated and non-editable.

The generation manifest records runtime/build identity, effective seed/formats/target, permitted
overrides, selected pack digests, the resolved-file hash, and every bundle-file hash. Existing
domain sidecars remain; the manifest is the authoritative run identity.

New bundles evaluate without an authored scenario:

```bash
eforge eval OUTPUT
```

`eforge eval OUTPUT --scenario scenario.yaml` recompiles the authored input with the manifest's
effective seed/formats and fails on a digest mismatch. `--allow-scenario-mismatch` permits the
comparison mismatch but evaluation still uses the bundle's resolved scenario. Legacy bundles still
require `--scenario`.

Literal OOB hosts always require a fresh matching `--oob-host` on validate, resolve, or generate.
Neither a pack nor a previously resolved document grants that authorization.

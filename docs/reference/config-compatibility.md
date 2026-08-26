# Configuration Compatibility and Migration

EvidenceForge normalizes supported legacy configuration at the model or cached loader boundary.
Generation consumes only the normalized form; emitters do not reinterpret legacy fields. Each
legacy entry or authored use emits an `EvidenceForgeDeprecationWarning` with its exact replacement
and states that the legacy shape will be removed in a future release.

Warnings are intentionally visible. Update automation and tests to current syntax instead of
suppressing them globally. Cached configuration loaders warn only on the first load of one legacy
document in a process.

## Supported migrations

| Family | Supported legacy input | Current replacement | Compatibility semantics |
|---|---|---|---|
| Sensor timing | `clock_skew_us` | `clock_offset_us` | The `{min, max}` range is renamed unchanged. |
| Sensor timing | `path_delay_us` | `route_delay_us` | The `{min, max}` range is renamed unchanged. |
| Proxy auth | `auth_policy.mode: legacy` | `auth_policy.mode: realistic` plus explicit non-human settings when required | Legacy mode remains typed and retains its prior attribution behavior; no probabilities are synthesized. |
| Observation profiles | An unversioned `profiles:` document | `schema_version: 2` with the same named profiles | Profile fields and source behavior are unchanged. |
| Applications | An unversioned catalog, a platform without `deployment`, or a managed descriptor without `kind` | Version 2 catalog and explicit `deployment.kind` | Missing deployment becomes `legacy_static`; a descriptor with release fields becomes `managed`. |
| Installed software | `{name, publisher, version}` | Explicit product/release/build/architecture/scope fields | Display output is unchanged; compatibility derives a stable name-based product ID, `build: version`, `architectures: [neutral]`, and `scope: machine`. |

These are the complete supported aliases. EvidenceForge does not guess near-miss field names.
Supplying a legacy and current timing field with different values, or only part of the current
installed-software identity, fails validation instead of choosing one silently.

## Observation profiles

Add the document version without changing profile content:

```yaml
schema_version: 2
profiles:
  complete:
    description: Perfect source coverage.
    default:
      missingness: 0.0
      delay_ms: {min_ms: 0, max_ms: 0}
    sources: {}
```

Project overlays should also declare `schema_version: 2` before their partial `profiles:` mapping.

## Application deployment descriptors

Version 2 makes the catalog's deployment intent explicit:

```yaml
schema_version: 2
default_deployment:
  kind: legacy_static

applications:
  - id: contoso-chat
    display_name: Contoso Chat
    platforms:
      windows:
        image_path: 'C:\Program Files\Contoso\Chat\chat.exe'
        deployment:
          kind: managed
          product_id: contoso-chat
          version: "4.2.1"
          build: "4210"
          architectures: [x64]
          scope: machine
          variant: stable
          fleet_prevalence: 1.0
        pe_metadata:
          file_version: "4.2.1"
          description: Contoso Chat
          product: Contoso Chat
          company: Contoso Ltd.
          original_filename: chat.exe
        command_templates:
          - '"C:\Program Files\Contoso\Chat\chat.exe"'
    categories: [user_app]
    personas: [sales]
```

Use `kind: managed` only when product, release, placement, and Windows PE metadata are known.
Content identity is release/build/architecture based and does not include host, user, or install
path. Use `kind: legacy_static` when the catalog intentionally preserves the historical static
process definition until authoritative deployment metadata is available.

## Installed software descriptors

Current `edr_pools.yaml` entries separate the stable product from its installed release:

```yaml
installed_software_products:
  - product_id: contoso-endpoint-agent
    name: Contoso Endpoint Agent
    publisher: Contoso Ltd.
    version: "8.4.2"
    build: "8420"
    architectures: [x64, arm64]
    scope: machine
```

The generated uninstall-key `DisplayName`, `Publisher`, and `DisplayVersion` remain sourced from
`name`, `publisher`, and `version`. The additional fields provide stable internal identity and
placement truth.

## Validation

After migrating package or project configuration, run from the intended project working directory:

```bash
eforge validate-config
```

Then validate representative scenarios from the same directory. A clean current configuration
emits no compatibility warnings.

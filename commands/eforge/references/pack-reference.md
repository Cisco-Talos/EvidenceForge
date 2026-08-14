# EvidenceForge Pack Authoring Reference

> This is the field and operational reference for `/eforge pack`,
> `/eforge industry-pack`, and `/eforge organization-pack`. Invoke the matching skill for
> lifecycle or authoring work instead of using this document as a standalone workflow.

Packs are optional, deterministic, data-only inputs for Scenario 2.0. They contribute reusable
generation data through a fixed public schema without exposing EvidenceForge's internal config
filenames.

## Table of contents

- [Core invariants](#core-invariants)
- [Repositories and project roots](#repositories-and-project-roots)
- [Exact references](#exact-references)
- [Fixed pack layout](#fixed-pack-layout)
- [Manifest schema](#manifest-schema)
- [Identity and namespace rules](#identity-and-namespace-rules)
- [Catalog overview](#catalog-overview)
- [Persona catalog](#persona-catalog)
- [Process catalog](#process-catalog)
- [Application catalog](#application-catalog)
- [Destination catalog](#destination-catalog)
- [Traffic catalog](#traffic-catalog)
- [Structured cadence](#structured-cadence)
- [Low-level outbound traffic](#low-level-outbound-traffic)
- [Storage catalog](#storage-catalog)
- [Organization model fragments](#organization-model-fragments)
- [Includes and permitted files](#includes-and-permitted-files)
- [Composition and precedence](#composition-and-precedence)
- [Drafts and semantic versioning](#drafts-and-semantic-versioning)
- [CLI JSON contracts](#cli-json-contracts)
- [Validation sequence](#validation-sequence)
- [Industry consumer harness](#industry-consumer-harness)
- [Organization consumer harness](#organization-consumer-harness)
- [Safety and portability](#safety-and-portability)
- [Failure diagnosis](#failure-diagnosis)

## Core invariants

- Scenario 1.0 and monolithic Scenario 2.0 require no packs and produce no missing-pack warnings.
- Packs are inert YAML. They cannot run code, add hooks, or grant permissions.
- A pack is selected as one whole unit. Catalog subcomponents are not independently selectable.
- Every pack has the same six catalog filenames and root keys, including empty catalogs.
- Only organization packs have model fragments and industry dependencies.
- Persisted references always contain an exact source, name, and version.
- Pack-local IDs become qualified public IDs: `<pack-name>:<local-id>`.
- Industry peer collisions fail. Ordering never silently resolves incompatible exports.
- Pack data must be effective at runtime. Do not add generation-looking fields that merely survive
  validation or provenance serialization.
- Pack content cannot change output, evaluation, safety, OOB authorization, credentials, resource
  policy, or engine runtime policy.

## Repositories and project roots

EvidenceForge resolves packs from three explicit sources:

```text
package  <installed-config-root>/packs/<type>/<name>/<version>/
project  <project-root>/.eforge/packs/<type>/<name>/<version>/
path     an explicit directory named by the scenario or CLI
```

`package` is installed and read-only. `project` is the editable project repository. `path` is for
an explicitly named external directory. There is no implicit user-global pack registry.

For scenario compilation, project-root selection is:

1. Explicit `--project-root`.
2. Nearest ancestor of the root scenario containing `.eforge`.
3. The root scenario's directory.

For pack-management commands without a scenario, selection is:

1. Explicit `--project-root`.
2. Nearest `.eforge` ancestor of the working directory.
3. The working directory.

Skills must resolve one concrete absolute project root and pass it explicitly. A project-root
choice must not change because a later command runs from another directory.

Inspect repositories with:

```bash
eforge info pack_roots
eforge pack list --project-root <absolute-project-root> --json
```

## Exact references

### Persisted scenario reference

```yaml
source: package
name: healthcare
version: "1.0.0"
```

`source` is `package`, `project`, or `path`. A path reference also requires `path`:

```yaml
source: path
path: ../packs/custom-healthcare
name: custom-healthcare
version: "1.0.0"
```

The path is relative to the YAML file that declares the reference, including when that field came
from an include. The manifest name/version must match the persisted values.

### CLI reference

Use this exact form for package and project repositories:

```text
source:type:name@version
```

Examples:

```text
package:industry:healthcare@1.0.0
project:organization:northstar-health@1.1.0
```

CLI commands that accept a path may receive a pack directory or its `pack.yaml`. Prefer a concrete
absolute path in chat-driven operations. Never abbreviate a persisted version or select an implicit
latest version.

### Scenario composition

Select direct industries:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: package
      name: healthcare
      version: "1.0.0"
```

Or select one organization, which brings its pinned industries:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: project
    name: northstar-health
    version: "1.1.0"
```

Direct industries and an organization are mutually exclusive.

## Fixed pack layout

Every pack contains:

```text
pack.yaml
catalogs/persona_catalog.yaml
catalogs/process_catalog.yaml
catalogs/application_catalog.yaml
catalogs/destination_catalog.yaml
catalogs/traffic_catalog.yaml
catalogs/storage_catalog.yaml
```

Organization packs additionally contain:

```text
model/environment.yaml
model/baseline_activity.yaml
```

Each catalog file must exist and contain exactly its predictable root key:

```yaml
persona_catalog: {}
process_catalog: {}
application_catalog: {}
destination_catalog: {}
traffic_catalog: {}
storage_catalog: {}
```

Empty catalogs are meaningful and valid. Do not delete an unused canonical file.

## Manifest schema

Industry manifest:

```yaml
pack_schema_version: "1.0"
type: industry
name: healthcare
version: "1.0.0"
requires_evidenceforge: ">=2.0.0,<3.0.0"
description: "Reusable fictional healthcare behavior and vocabulary."
industry_dependencies: []
```

Organization manifest:

```yaml
pack_schema_version: "1.0"
type: organization
name: northstar-health
version: "1.0.0"
requires_evidenceforge: ">=2.0.0,<3.0.0"
description: "Fictional regional healthcare organization."
industry_dependencies:
  - source: package
    type: industry
    name: healthcare
    version: "1.0.0"
```

Rules:

- `pack_schema_version` is exactly `"1.0"`.
- `type` is `industry` or `organization`.
- `name` uses lower-case letters, digits, and hyphens and must match its directory identity.
- `version` is exact `X.Y.Z` SemVer without leading zeroes and must match its directory identity.
- `requires_evidenceforge` uses comma-separated exact comparisons such as
  `>=2.0.0,<3.0.0`.
- `description` explains the reusable scope, not one exercise.
- Industry packs must have no dependencies.
- Only organization packs may list industry dependencies.
- Every dependency pins source, type, name, and version. Add `path` only when `source: path`.
- Dependencies cannot be cyclic, missing, incompatible, ambiguous, or silently substituted.

## Identity and namespace rules

Use stable local IDs in catalog mappings. IDs must match
`^[a-z0-9][a-z0-9_-]*$`: lower-case letters and digits, followed by lower-case letters, digits,
hyphens, or underscores. A local ID cannot contain `:`, because colon separates the pack namespace.
Do not change an established valid ID only for style.

When `healthcare` exports local `clinical-coordinator`, its public identity is:

```text
healthcare:clinical-coordinator
```

Inside the same pack, local references may use `clinical-coordinator`; loading qualifies them.
Organization references to an industry dependency must be qualified, for example
`healthcare:clinical-coordinator`. A built-in process ID such as `chrome` is intentionally
unqualified in a process profile's `builtins` list.

Scenarios use qualified pack exports:

```yaml
persona: healthcare:clinical-coordinator
preset: healthcare:clinical-department
```

Built-in and scenario-local shorthand remains valid for monolithic compatibility. Do not use
ambiguous shorthand to refer to a pack export.

## Catalog overview

| Catalog | Owns | Runtime effect |
|---|---|---|
| Persona | Reusable behavioral roles | Work hours, risk, intensity, and application eligibility |
| Process | Built-in/custom executable profiles and scoped document terms | Process images, commands, metadata, selection |
| Application | Persona audience, process profiles, named connections | Exact eligible process and connection graph |
| Destination | Synthetic endpoints, tags, typed services | DNS ownership and destination IP/port/protocol |
| Traffic | Application activity, cadence, low-level connections | Deterministic baseline timing and network activity |
| Storage | Bounded directory/subject/file vocabulary | SMB share population and activity presets |

Process, application, destination, traffic, and storage entries use a common envelope:

```yaml
<catalog-root>:
  <local-id>:
    description: "Human-readable reusable purpose."
    data: {}
```

Persona entries use the canonical Persona shape directly, as shown below. Unknown keys are
rejected by the public catalog models. Preserve the `description` + `data` envelope for the other
five catalogs even when a data model is small.

## Persona catalog

```yaml
persona_catalog:
  clinical-coordinator:
    name: clinical-coordinator
    description: "Coordinates scheduling, records, and care-team communication."
    typical_activities:
      - "Review schedules"
      - "Update clinical documentation"
    work_hours: "7am-4pm (lunch 12pm-1pm)"
    application_usage: ["Clinical portal", "Email"]
    risk_profile: medium
    browsing_intensity: normal
```

The mapping key and `name` must match before qualification.

Fields:

- `name`: local persona ID.
- `description`: concise role description.
- `typical_activities`: behavioral documentation used by authoring and ground truth.
- `work_hours`: accepted EvidenceForge work-hours description.
- `application_usage`: human-facing description; application-catalog `personas` is authoritative
  for process eligibility.
- `risk_profile`: `low`, `medium`, or `high`.
- `browsing_intensity`: `light`, `normal`, or `heavy`.
- `expanded_activities`, `work_hours_parsed`, and `activity_intensity`: optional canonical Persona
  fields. Prefer ordinary fields unless a tested scenario needs explicit advanced behavior.

Do not define a persona without assigning it to at least one application unless processless
activity is deliberate.

## Process catalog

A process entry groups stable built-ins and/or custom executable definitions used together by one
business workflow.

```yaml
process_catalog:
  clinical-workstation:
    description: "Clinical workstation executable profile."
    data:
      builtins: [chrome, outlook]
      custom:
        - id: clinical-client
          display_name: "Fictional Clinical Client"
          platforms:
            windows:
              image_path: 'C:\Program Files\Example Clinical\ClinicalClient.exe'
              pe_metadata:
                file_version: "4.2.0.0"
                description: "Example Clinical Client"
                product: "Example Clinical Suite"
                company: "Example Clinical Software"
                original_filename: "ClinicalClient.exe"
              command_templates:
                - '"C:\Program Files\Example Clinical\ClinicalClient.exe" --open "{document_path}"'
              children:
                - '"C:\Program Files\Example Clinical\ClinicalRenderer.exe" --type=renderer'
              loaded_modules:
                - path: 'C:\Program Files\Example Clinical\ClinicalCore.dll'
                  signed: true
                  signature: "Example Clinical Software"
                  signature_status: Valid
                  load_phase: startup
                  startup_probability: 1.0
          categories: [user_app, office]
          system_types: [workstation]
          selection_weight: 8
          singleton_per_session: true
      document_terms: [care-plan, referral-summary, shift-roster]
```

At least one of `builtins` or `custom` is required.

### Built-in processes

`builtins` contains stable application IDs reported by:

```bash
eforge info pack_builtin_application_ids
```

This inventory comes from packaged defaults only. Overlay application IDs are internal project
config and are not portable pack built-ins.

Do not use an executable basename such as `chrome.exe` or a display label such as `Google Chrome`
when the stable ID is `chrome`.

### Custom process fields

- `id`: stable custom process ID, unique across the owning pack.
- `display_name`: human-readable application/process name.
- `platforms`: one or both of `windows` and `linux`.
- `image_path`: fully qualified, OS-native executable path. Bare filenames are invalid.
- `command_templates`: non-empty realistic commands for that platform.
- `pe_metadata`: Windows PE identity containing `file_version`, `description`, `product`,
  `company`, and `original_filename`.
- `children`: optional platform-native child command templates.
- `loaded_modules`: optional Windows-only module definitions.
- `categories`: one or more of `user_app`, `browser`, `office`, `code`, `build`, `query`.
- `system_types`: optional scenario system types eligible for the process.
- `selection_weight`: positive relative selection weight; default is 10.
- `singleton_per_session`: whether overlapping copies are suppressed in one user session; default
  is false.

Linux platforms cannot contain Windows PE metadata or loaded modules. OS-specific values must not
cross platform boundaries.

Custom categories must include at least one schedulable category: `user_app`, `code`, `build`, or
`query`. `browser` and `office` may refine behavior but cannot make an otherwise inert process
schedulable.

### Loaded module fields

- `path`: required fully qualified Windows module path.
- `signed`: boolean, default true.
- `signature`: optional native signer label.
- `signature_status`: optional source-native status such as `Valid`.
- `pe_metadata`: optional five-field PE identity described above.
- `load_phase`: optional `startup` or `runtime`.
- `startup_probability`: number from 0 through 1, default 1.

Known third-party module families require matching native signer and complete PE identity.

### Scoped document terms

`document_terms` is a pool of unique 1–64-character filename stems. Each term starts with a letter
or digit and may otherwise use letters, digits, spaces, underscores, or hyphens. The pool is scoped
to processes selected through this process profile. It can fill `{document_term}`,
`{document_name}`, `{doc_path}`, `{document_path}`, `{spreadsheet_path}`, and `{pdf_path}` in
built-in and custom commands. EvidenceForge derives safe extensions and paths for the specific
placeholder.

Terms never enter global command pools and cannot leak into another pack or process profile. Use
synthetic business nouns, not sensitive real document names.

## Application catalog

Applications connect personas to process profiles and named destination services.

```yaml
application_catalog:
  clinical-portal:
    description: "Browser and client access to fictional clinical services."
    data:
      personas: [clinical-coordinator]
      processes: [clinical-workstation]
      connections:
        records-api:
          destination: clinical-services
          service: secure-web
        mail-relay:
          destination: clinical-services
          service: smtp-submit
```

Fields:

- `personas`: persona references allowed to use the application. This is authoritative for
  baseline process eligibility.
- `processes`: process-profile references from `process_catalog`, not executable basenames or
  custom-process IDs.
- `connections`: mapping of local connection ID to an exact destination reference and one service
  local to that destination.

An application may own multiple named connections. Traffic references the connection ID in the
context of its application, so connection IDs only need to be unique within that application.

Every persona, process profile, destination, and service reference must resolve. Do not encode a
protocol list without an exact destination; the destination service owns protocol and port.

Every named application connection must be referenced by at least one traffic binding. Unused
connections are rejected because their destination/service data cannot affect generation.

Every process profile must be referenced by at least one application. Orphan process exports are
rejected because they cannot affect generation.

## Destination catalog

```yaml
destination_catalog:
  clinical-services:
    description: "Fictional hosted clinical service family."
    data:
      tags: [healthcare, saas]
      endpoints:
        - domain: records.healthcare.example
          ips: [198.51.100.80, "2001:db8:42::80"]
      services:
        secure-web:
          protocol: https
        smtp-submit:
          protocol: smtp
          port: 587
```

Fields:

- `tags`: stable DNS-selection tags. Pack-defined tags are added to effective DNS configuration.
- `endpoints`: non-empty list of `{domain, ips}` objects.
- `domain`: bare valid hostname without scheme, port, path, query, or wildcard.
- `ips`: non-empty list of valid IPv4 or IPv6 address strings.
- `services`: mapping of local service ID to `protocol` plus optional port override.

Supported protocols and defaults:

| Protocol | Transport | Default port |
|---|---:|---:|
| `http` | TCP | 80 |
| `https` | TCP | 443 |
| `ssh` | TCP | 22 |
| `smb` | TCP | 445 |
| `smtp` | TCP | 25 |
| `mssql` | TCP | 1433 |
| `mysql` | TCP | 3306 |
| `postgresql` | TCP | 5432 |

Use `port` only for a deliberate non-default listener. The typed protocol still controls semantic
generation; a port override does not turn HTTPS into an arbitrary TCP label.

Within one effective composition, domains and endpoint identities must not collide incompatibly.
Use `.example`, `.invalid`, or another reserved namespace for reusable external services.

Built-in DNS tags retain their existing unqualified identity. Other destination tags are local at
authoring time and become `<pack-name>:<tag>` in effective configuration. Use the same local tag in
same-pack low-level traffic; EvidenceForge applies the namespace consistently.

Every destination must be reachable from an application connection or a low-level traffic DNS tag.
Orphan destination exports are rejected because no runtime activity can select them.

## Traffic catalog

Traffic entries schedule application connections and, when necessary, low-level processless
connections.

```yaml
traffic_catalog:
  clinical-shift:
    description: "Clinical portal use around shift transitions."
    data:
      audience: [clinical-coordinator]
      applications:
        - application: clinical-portal
          connection: records-api
          weight: 20
      cadence:
        pattern: burst
        days: [mon, tue, wed, thu, fri]
        windows:
          - {start: "06:45", end: "08:15"}
          - {start: "14:30", end: "16:00"}
        burst_count: [2, 5]
        jitter_minutes: 10
      outbound: []
```

Fields:

- `audience`: persona references eligible for the traffic entry.
- `applications`: weighted application-connection references.
- `application`: application-catalog reference.
- `connection`: a named connection owned by that application.
- `weight`: positive relative selection weight.
- `cadence`: optional structured schedule described below.
- `outbound`: optional low-level traffic described separately.

`audience` must be non-empty, and each traffic entry must contain at least one application binding
or low-level outbound connection. Duplicate application/connection pairs are rejected.

An application activity uses only the referenced application's eligible processes and exact named
destination/service. It does not select a domain by a broad tag or guess a process from its port.

The traffic audience and application audience must be compatible. A traffic entry with no eligible
persona session produces no activity; do not broaden eligibility merely to silence that result.

## Structured cadence

Omitting `cadence` preserves the existing default: weighted stochastic persona traffic on weekdays
from 07:00 through 20:00 in scenario-local time.

All explicit cadence variants accept:

- `pattern`: `weighted`, `periodic`, or `burst`.
- `days`: optional list from `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`; default weekdays.
- `windows`: optional list of `{start: "HH:MM", end: "HH:MM"}`; default 07:00–20:00.

Windows use the scenario's local timezone. A cross-midnight window is supported and belongs to its
starting day. Window start and end must differ.

### Weighted cadence

```yaml
cadence:
  pattern: weighted
  days: [mon, tue, wed, thu, fri]
  windows:
    - {start: "08:00", end: "18:00"}
```

Weighted cadence uses existing persona intensity counts and deterministic weighted stochastic
placement inside eligible windows. It does not accept `jitter_minutes`, `interval_minutes`, or
`burst_count`.

### Periodic cadence

```yaml
cadence:
  pattern: periodic
  days: [mon, tue, wed, thu, fri]
  windows:
    - {start: "07:00", end: "19:00"}
  interval_minutes: 60
  jitter_minutes: 10
```

- `interval_minutes` is required and ranges from 5 through 1440.
- `jitter_minutes` is an integer at least 0 and defaults to 0.
- Twice the jitter cannot exceed the interval.
- Anchors are deterministic per eligible user and remain inside permitted windows.

### Burst cadence

```yaml
cadence:
  pattern: burst
  windows:
    - {start: "08:45", end: "09:15"}
  burst_count: [2, 4]
  jitter_minutes: 5
```

- `burst_count` is a two-integer `[minimum, maximum]` range with positive values and minimum no
  greater than maximum; neither bound may exceed 50.
- `jitter_minutes` is an integer at least 0 and defaults to 0.
- Jitter cannot exceed half the shortest configured window.
- Each eligible window receives a deterministic per-user count in the authored range.

All variants still require an active eligible session and remain subject to generation workload
limits. Cadence controls runtime timing, not just provenance or documentation.

## Low-level outbound traffic

Use `outbound` only for legitimate system/processless traffic that should not be attributed to an
application process.

Discover the packaged-only built-in DNS tags accepted here with:

```bash
eforge info pack_builtin_dns_tags
```

```yaml
outbound:
  - role: _external
    port: 123
    proto: udp
    service: ntp
    weight: 2
    os: windows
    emit_dns: false
    dns_tags: []
```

Fields:

- `role`: destination system role; `_external` selects external traffic behavior.
- `port`: 1 through 65535.
- `proto`: `tcp` or `udp`; default `tcp`.
- `service`: optional source-native service hint.
- `weight`: positive selection weight; default 1.
- `os`: optional `windows` or `linux` source restriction.
- `emit_dns`: whether to emit prerequisite DNS; default false.
- `dns_tags`: DNS registry tags used only when DNS selection is requested.

Prefer application entries for browser, office, database, SSH client, SMB client, SMTP client, and
other process-owned traffic. Do not duplicate one logical connection in both `applications` and
`outbound`.

## Storage catalog

```yaml
storage_catalog:
  clinical-department:
    description: "Bounded clinical department share vocabulary."
    data:
      directories: [Care Coordination, Scheduling, Policies, Referrals]
      subjects: [care-plan, shift-roster, referral-summary]
      files:
        - extension: .docx
          mime: application/vnd.openxmlformats-officedocument.wordprocessingml.document
          weight: 4
        - extension: .pdf
          mime: application/pdf
          weight: 3
```

Fields:

- `directories`: non-empty bounded relative directory-name vocabulary.
- `subjects`: non-empty synthetic filename-subject vocabulary.
- `files`: non-empty weighted file-type list.
- `extension`: dot-prefixed alphanumeric extension.
- `mime`: valid MIME label matching the extension.
- `weight`: positive selection weight.

An industry storage entry is vocabulary, not a concrete server or share. A scenario or
organization environment selects it as a qualified storage `preset` while owning server, volume,
share, access, mapping, population, and activity settings. Keep storage vocabulary
provider-neutral: directory and subject values are bounded SMB-relative components, not Windows
drives, Linux mountpoints, backing filesystems, Samba audit policy, or internal client/server
profiles.

## Organization model fragments

Organization packs add two fixed roots:

```yaml
# model/environment.yaml
environment:
  description: "Fictional regional care provider."
  timezone:
    default: America/Chicago
  domain: northstarhealth.example
  users: []
  systems: []
```

```yaml
# model/baseline_activity.yaml
baseline_activity:
  description: "Normal organization activity."
  intensity: low
  variation: medium
  suspicious_noise: low
```

These are typed partial canonical `environment` and `baseline_activity` fragments. Use the exact
scenario schema reference loaded by the organization-pack authoring workflow for nested fields.

A self-contained organization should normally provide the users, systems, groups, services,
topology, sensors, email topology, storage topology, and baseline settings necessary for its stated
behavior. A Scenario 2.0 wrapper then supplies scenario identity, seed, time, output, and optional
exercise-specific behavior.

For cross-platform SMB, the organization environment owns concrete Windows or Linux storage
servers, OS-native volume mounts and backing filesystems, optional SMB-advertised filesystem labels,
share audit/access policy, Windows drive and/or Linux mount mappings, and Linux client/server service
markers. Do not place internal `smb_profiles.yaml` data in a pack or rely on a project overlay for a
portable capability claim. Use canonical scenario modes (`auto`, `windows_native`, `cifs_mount`, or
`smbclient`) and validate a representative client/server matrix instead.

A deliberately partial organization is valid only with a named representative consumer scenario.
That consumer must supply the missing effective model and pass resolve, validation, and generation
tests. Report the pack as partial rather than standalone.

Never put these fields in an organization pack:

- `storyline` or `red_herrings`
- `time_window` or generation seed
- `output`, target, or collection overrides
- literal credentials or OOB authorization
- safety, evaluation, resource, or runtime policy

Do not set `environment.email.corpus` in a pack. Pack-owned corpus path provenance is not part of
the current public contract. Keep the corpus and its declaring path in the consumer scenario.

Do not put `ENVIRONMENT.md` in a pack. Temporary validation harnesses do not need it. For a retained
consumer, route to the scenario skill and use its `ENVIRONMENT.md` template to generate the
attack-free analyst briefing from the resolved effective environment.

## Includes and permitted files

Pack semantic YAML may use top-level `includes` or singular `include`:

```yaml
includes:
  - fragments/clinical-processes.yaml

process_catalog: {}
```

Include paths resolve relative to the YAML file that declares them and must remain within the pack
root. Included mappings must be disjoint; includes are composition, not last-wins overrides.
Circular includes, duplicate YAML keys, conflicting fields, traversal, symlink escape, excessive
depth/file count/bytes/nodes, and files outside the pack root fail.

All semantic YAML must be reachable from `pack.yaml`, a fixed catalog, or an organization model
file. Unreferenced `.yaml` or `.yml` files fail validation.

Permitted non-semantic companions are:

- `README.md`
- `LICENSE` or `LICENSE.md`
- `COPY_PROVENANCE.md`

They do not affect resolution or digest. Do not add scripts, binaries, templates, corpora, arbitrary
assets, or executable hooks.

## Composition and precedence

Effective generation data applies in this order:

1. Packaged EvidenceForge defaults.
2. Directly selected industry packs for additive exports.
3. The selected organization pack.
4. Project `.eforge/config` overlays under their established internal merge rules.
5. Scenario-local model fields and authored overrides.

Packs are not arbitrary recursive overlays. Each public catalog has an explicit adapter and merge
contract. Export collisions and incompatible definitions fail with provenance rather than relying
on ordering.

Industry packs are peers. Organization dependencies are resolved exactly. A compiled scenario
records portable selected identities, digests, authored `field_origins`, qualified
`catalog_field_origins`, `organization_model_origins`, concrete `merge_decisions`, and effective
configuration. Included pack fields retain the exact declaring YAML path.

Inspect them with:

```bash
eforge resolve <scenario.yaml> --output <resolved.yaml> \
  --project-root <absolute-project-root> --explain-composition --json
```

The generated authoritative resolved document no longer depends on original packs, includes,
project config, working directory, or ambient caches. Do not edit that generated document.

## Drafts and semantic versioning

Use a draft-aware policy:

- Default an explicitly identified new draft to `0.1.0`.
- Default the first declared complete pack to `1.0.0`.
- Permit in-place edits only when the user confirms the version is unshared, unreferenced, and
  still a draft.
- Once a version is shared, referenced, or complete, copy it to a new exact version before editing.
- Use patch for compatible corrections, minor for compatible additions, and major for incompatible
  removals, renames, or behavior changes.

A tailored copy with a different name starts a new identity (`0.1.0` while explicitly draft or
`1.0.0` when complete). A new version of the same identity keeps `--name` unchanged and advances
the version, such as `1.0.0` to `1.1.0` for compatible additions.

Changing an export ID, removing an export, changing an application's connection identity, changing
a destination service incompatibly, or materially changing expected cadence normally requires a
major version. Adding a new independent export normally permits a minor version. Fixing metadata or
a clearly unintended compatible value normally permits a patch.

Never overwrite an existing destination and never mutate a packaged version.

## CLI JSON contracts

Use JSON for agent-driven decisions. Parse fields; do not scrape Rich text.

### List

```bash
eforge pack list --project-root <root> --json
```

Success:

```json
{"packs": [{"source": "package", "type": "industry", "name": "healthcare", "version": "1.0.0", "digest": "...", "location": "...", "exports": {}}]}
```

Failure, exit 1:

```json
{"packs": [], "error": "..."}
```

### Show

```bash
eforge pack show <ref-or-path> --project-root <root> --json
```

Success is the raw pack metadata payload with `source`, `type`, `name`, `version`, `description`,
`requires_evidenceforge`, `digest`, `location`, `industry_dependencies`, and sorted `exports`.

Failure, exit 1:

```json
{"valid": false, "error": "..."}
```

### Validate

```bash
eforge pack validate <ref-or-path> --project-root <root> --json
```

Success:

```json
{"valid": true, "pack": {}, "dependencies": []}
```

Failure, exit 2:

```json
{"valid": false, "error": "..."}
```

### Initialize

```bash
eforge pack init <industry|organization> <name> --version <version> \
  --project-root <root> --json
```

Success:

```json
{"created": true, "pack": {}}
```

Failure, exit 1:

```json
{"created": false, "error": "..."}
```

### Copy

```bash
eforge pack copy <ref-or-path> --name <new-name> --version <new-version> \
  --project-root <root> --json
```

Success:

```json
{"copied": true, "source_pack": {}, "pack": {}}
```

Failure, exit 1:

```json
{"copied": false, "error": "..."}
```

All JSON modes write JSON only to standard output for expected success and failure. Lifecycle
commands validate identity before constructing paths, reject absolute/traversal names and unsafe
SemVer, reject symlinked ancestry, refuse overwrite, stage and publish atomically, roll back on
failure, and reload the published pack. A renamed copy rewrites typed semantic self-references only;
it does not rewrite prose or dependency namespaces.

For an organization, distinguish a namespace-only fork from a full fictional rebrand. `pack copy`
does not rewrite organization-facing prose, domains, hostnames, usernames, email addresses, share
labels, or similar modeled identity. A full rebrand must inventory and deliberately update those
fields while leaving dependency namespaces intact; never use an unreviewed global replacement.

## Validation sequence

Use this order:

1. Run `pack list --json` and resolve the intended identity.
2. Run `pack show --json` for a base or dependency.
3. Run `pack init` or `pack copy --json` when creating a version.
4. Edit one coherent catalog dependency layer.
5. Run `pack validate --json` immediately.
6. Repeat edit/validate until every catalog is complete.
7. Run `pack show --json` and record exact identity, exports, and digest.
8. Resolve a representative Scenario 2.0 with `--explain-composition --json`.
9. Run normal scenario validation.
10. Run fixed-seed generation and inspect evidence for runtime effects.

Pack validation checks:

- safe YAML and duplicate keys
- fixed files/root keys and unknown fields
- manifest/directory/reference identity
- EvidenceForge compatibility
- include containment and cumulative budgets
- no symlinks, traversal, orphan YAML, hooks, or arbitrary assets
- dependency existence, type, exact identity, and cycles
- export namespaces and collisions
- persona/application/process/destination/service/traffic references
- stable built-in process IDs and custom platform definitions
- domain/IP/tag and protocol/port consistency
- cadence variant, range, window, interval, and jitter rules
- storage vocabulary shape
- typed organization environment/baseline fragments

Structural validation alone cannot prove a partial organization model. Always compile its named
consumer.

## Industry consumer harness

Use a temporary scenario outside the pack root. Adapt the qualified persona and output location:

```yaml
scenario_version: "2.0"
composition:
  industries:
    - source: project
      name: custom-healthcare
      version: "0.1.0"
generation_seed: 42
name: custom-healthcare-pack-smoke
description: "Temporary consumer for industry-pack verification."
environment:
  description: "Fictional pack smoke-test environment."
  timezone:
    default: America/Chicago
  users:
    - username: alex.morgan
      full_name: "Alex Morgan"
      email: alex.morgan@smoke.example
      persona: custom-healthcare:clinical-coordinator
      primary_system: SMOKE-WS-01
  systems:
    - hostname: SMOKE-WS-01
      ip: 10.77.10.21
      os: Windows 11
      type: workstation
      assigned_user: alex.morgan
      roles: [workstation]
baseline_activity:
  description: "Low-volume deterministic pack verification."
  intensity: low
  variation: low
  suspicious_noise: low
time_window:
  start: "2026-08-14T13:00:00Z"
  duration: "1h"
  warmup: "1h"
output:
  logs:
    - format: windows
    - format: ecar
  destination: ./temporary-pack-smoke-output
  compression: false
```

Resolve with explicit project root and composition explanation. Confirm the selected pack digest,
qualified persona origin, application/process graph, destination/service, and cadence. Generate and
inspect process and flow records rather than treating presence in `RESOLVED_SCENARIO.yaml` as proof
of runtime behavior. Set the scenario's local date and hour so they overlap each authored cadence
that the harness is intended to prove.
Put narrow cadence windows after expected interactive-session bootstrap—normally at least ten
local minutes after login—and leave time for startup pacing. Use a fresh resolved-output filename
for each attempt because a differing authoritative document is not overwritten.

Use a fixed command boundary for the runtime proof:

```bash
eforge generate <temporary-scenario.yaml> --output <absolute-temporary-output> \
  --project-root <absolute-project-root> --seed 42 --force
```

The standard harness requests host and eCAR records and therefore needs no network sensor. If the
user requests Zeek, IDS, or firewall proof, add compatible topology and a sensor that observes the
modeled path using the scenario reference; an output format alone does not establish visibility.

For a storage export, add a compatible server, OS-native volume, share, access/audit policy, and
mapping that uses the qualified `preset`; give Linux clients and Samba servers explicit service
markers, then run scenario validation with `--show-storage`. Exercise the provider combination the
pack claims rather than assuming a Windows-only consumer proves Linux portability.

## Organization consumer harness

A self-contained organization pack normally needs only a thin scenario:

```yaml
scenario_version: "2.0"
composition:
  organization:
    source: project
    name: northstar-health-custom
    version: "0.1.0"
generation_seed: 42
name: northstar-health-custom-smoke
description: "Temporary organization-pack consumer."
time_window:
  start: "2026-08-14T14:00:00Z"
  duration: "1h"
  warmup: "1h"
output:
  logs:
    - format: windows
    - format: zeek
    - format: ecar
    - format: syslog
  destination: ./temporary-pack-smoke-output
  compression: false
```

Schedule cadence assertions after the expected user session has started, normally at least ten
local minutes after login. Use a fresh temporary resolved filename for each attempt rather than
trying to overwrite a differing authoritative artifact.

Resolve, validate with `--show-storage` when applicable, and generate. Inspect representative user,
system, application, network, email, and SMB records claimed by the pack.

For SMB consumers, inspect `STORAGE_MANIFEST.json` schema v2 as well as logs. Confirm server
platform, backing versus SMB-advertised filesystem, drive/mount presentation, credential mode, and
resolved target paths. Windows Security and Samba syslog are platform-selective; requesting both
formats does not mean both should render for one server operation.

Generate with an explicit absolute output root and fixed seed:

```bash
eforge generate <consumer-scenario.yaml> --output <absolute-temporary-output> \
  --project-root <absolute-project-root> --seed 42 --force
```

Before claiming Zeek, IDS, or firewall evidence, verify that the effective organization contains a
compatible sensor with visibility of the relevant modeled path.

Selecting an output format enables its emitter but does not guarantee a file in a short
probabilistic run. When a smoke test must prove SMTP or bash output, use a calibrated longer window
or a deterministic scenario-local email or Linux process event.

For a partial organization, the harness must explicitly supply every missing environment or
baseline requirement. Record the consumer path as part of the pack's authoring handoff. Do not use
a manually repaired resolved document as a substitute for a valid authored consumer.

## Safety and portability

- Use fictional organizations and people unless the user explicitly owns and authorizes modeled
  identifying data.
- Use `.example`, `.invalid`, `.test`, RFC 5737 IPv4 (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), RFC 3849 IPv6 (`2001:db8::/32`), or appropriate private ranges.
- Never place real-looking secrets, API keys, tokens, passwords, or live campaign indicators in a
  reusable pack.
- Never place a literal operator OOB endpoint in a pack. A fresh matching CLI `--oob-host` remains
  required for each validate, resolve, or generate invocation that needs it.
- Never add absolute machine-specific semantic paths except OS-native executable and modeled
  filesystem paths. External pack references and authoring paths must remain deliberate and
  portable.
- Do not store the resolved author's absolute filesystem paths in semantic metadata.
- Do not edit packaged packs, authoritative resolved scenarios, or generated installer copies.
- Do not treat a pack digest as authorization or executable trust. It provides reproducible
  identity and tamper detection only.

## Failure diagnosis

### Pack not found

- Confirm project root.
- Confirm source/type/name/version.
- Run `pack list --json`.
- For `source: path`, resolve the path from the declaring YAML, not the shell directory.
- Do not substitute another version.

### Identity mismatch

- Match manifest name/version/type to the reference and repository directory.
- Use `pack copy` to create a new identity; do not hand-rename only the directory.

### Missing or unknown catalog field

- Confirm all fixed filenames and root keys.
- Compare against the exact entry envelope and catalog schema in this reference.
- Remove prototype fields such as process executable-name lists, application protocol-only lists,
  destination-level scalar service, or free-form cadence strings. These were never a shipped
  runtime contract and are rejected because they were inert or ambiguous.

### Unresolved application graph

- Resolve the traffic audience persona.
- Resolve the traffic application.
- Resolve its process profile.
- Resolve the named connection.
- Resolve that connection's destination and destination-local service.
- Check OS and system-type eligibility for at least one process.

### Cadence error or no activity

- Check the discriminated variant fields.
- Check day/window timezone and cross-midnight ownership.
- Check interval/jitter or burst-count/jitter bounds.
- Check for an active eligible persona session inside the window.
- Check workload limits and selected output formats.

### Dependency or collision error

- Validate each exact dependency separately.
- Qualify dependency exports.
- Remove undeclared cross-industry references.
- Do not reorder industry peers to hide a collision; rename or reconcile the conflicting export.

### Organization validates but cannot generate

- Determine whether it is intentionally partial.
- Resolve the named representative consumer.
- Supply missing required environment/baseline fields in that consumer or complete the pack.
- Report partial status explicitly.

### Digest mismatch

- Treat a packaged mismatch as tampering or a broken distribution.
- For project/path packs, inspect semantic YAML changes and revalidate.
- Non-semantic README/license/provenance changes do not change the digest.
- Never alter a digest index or resolved artifact merely to make a mismatch disappear.

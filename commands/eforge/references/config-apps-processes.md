# Application, process, and endpoint overlays

Read only the section matching the requested family. Inspect the packaged YAML and existing overlay
before editing; several files that look alike have different merge behavior.

## Contents

- [Applications](#applications)
- [Deployment and release identity](#deployment-and-release-identity)
- [Process relationships](#process-relationships)
- [System and endpoint telemetry](#system-and-endpoint-telemetry)
- [Installed software identity](#installed-software-identity)
- [RSAT](#rsat)

## Applications

`application_catalog.yaml` contains an `applications` list keyed by `id`. Matching IDs deep-merge;
lists append unless the entry uses `_replace: true`. New IDs append.

The effective catalog uses schema version 2. Every new platform entry must carry an explicit typed
`deployment`; do not rely on boundary normalization to invent release identity.

```yaml
applications:
  - id: ehr_client
    display_name: EHR Client
    platforms:
      windows:
        image_path: 'C:\Program Files\Example\EHR\ehr.exe'
        deployment:
          kind: managed
          product_id: example-ehr-client
          version: "4.2.0.0"
          build: "4.2.117"
          architectures: [x64]
          scope: machine
          variant: stable
          fleet_prevalence: 0.65
        pe_metadata:
          file_version: "4.2.0.0"
          description: "Example EHR Client"
          product: "Example EHR Suite"
          company: "Example Clinical Software"
          original_filename: "ehr.exe"
        command_templates:
          - '"C:\Program Files\Example\EHR\ehr.exe" --open {internal_url}'
        command_parameter_pools:
          internal_url: [https://ehr.example.test/]
        children: []
        loaded_modules:
          - path: 'C:\Program Files\Example\EHR\ehrcore.dll'
            release_policy: owner_release
            signature: "Example Clinical Software"
            pe_metadata:
              file_version: "4.2.0.0"
              description: "Example EHR Core"
              product: "Example EHR Suite"
              company: "Example Clinical Software"
              original_filename: "ehrcore.dll"
    categories: [user_app]
    personas: [nurse]
    system_types: [workstation]
    selection_weight: 10
    singleton_per_session: true
```

Application entry fields:

- Required: `id`, `display_name`, `platforms`, `categories`, `personas`.
- Optional selection fields: `system_types`, positive `selection_weight`, `compatibility_group`,
  `compatibility_option`, and `singleton_per_session`.
- Each new platform requires `image_path` plus a typed `deployment`, and may define `pe_metadata`,
  `command_templates`, scoped `command_parameter_pools`, `children`, and `loaded_modules`.
- A loaded module declares a `release_policy` and may define signer/PE identity, `load_phase`
  (`startup` or `runtime`), and `startup_probability` from 0 to 1. Known third-party modules require
  native signer and complete PE metadata.

`personas` controls eligibility; a persona's `application_usage` list is descriptive only. Ask for
exact persona access rather than deriving it from title or risk.

## Deployment and release identity

Choose the deployment discriminator from the identity actually known at the catalog boundary:

- `kind: managed` owns an exact `product_id`, `version`, `build`, architecture set, install `scope`,
  optional `variant`, and `fleet_prevalence`. On Windows, `pe_metadata.file_version` must equal the
  managed version.
- `kind: catalog` derives a current catalog release through `release_policy: pe_metadata` or binds
  an OS-owned image through `release_policy: host_build`. A Windows `host_build` descriptor requires
  the owning OS `product_id`.

Architectures are exact eligibility, not display text. A deployment or module that is incompatible
with the scenario host's `architecture` is not compiled onto that host. Machine-scoped paths cannot
contain `{username}`; user-scoped placement is compiled separately for each eligible principal.

Module release policy is independent from load timing:

- `owner_release` shares the owning application or service release.
- `pe_metadata` owns a distinct versioned module product and requires `product_id` plus complete PE
  metadata.
- `host_build` binds an OS module to the exact scenario host build.

Binary release identity excludes hostname, username, and installation path. Installation identity,
application profile, local artifact version, file content, and source observation identity remain
separate. Fix cross-source hash or version mismatches at deployment/content compilation; do not
rewrite an emitter-facing catalog pool to hide them.

## Process relationships

### `spawn_rules.yaml`

Deep-merges `windows` and `linux` parent mappings. A parent may define command templates, lifetime,
spawn delay, max children, and child executable names. Parent and child names must resolve through
application or system-process catalogs. Adding an application does not imply a parent; ask unless the
user selected one.

### `process_network_map.yaml`

Appends `mappings`. Each mapping associates an executable with a network service/port behavior used
for process-to-network correlation. Add one only when the application actually owns that traffic.
Avoid duplicate executables because runtime indexing is last-wins.

### `system_processes.yaml`

Deep-merges `scheduled_tasks`, `system_services`, `system_binaries`, `common_loaded_modules`, and
`process_loaded_modules`. Use this file for OS/service processes, not user applications. Preserve
source-native image paths, parent symbols, host-role eligibility, rarity, cooldown, and lifecycle.

### `service_process_profiles.yaml`

Deep-merges `families`. Each family defines one resident OS-native service manager and named workers
that must reuse that manager across generation entry paths. Manager and worker entries require a
stable `key`, source-native `image`, `command_line`, `username`, and `parent_key`; worker
`parent_key` values must be `manager`. Use this family only for durable master/worker ancestry such
as Postfix or IIS, not for interactive invocations of the same executable.

### ProcessAccess and CreateRemoteThread

- `process_access_patterns.yaml`: `baseline_pairs` append; each pair owns plausible source/target
  process identity and granted-access choices.
- `create_remote_thread_patterns.yaml`: `baseline_pairs` and start-location lists append;
  `baseline_noise`, `start_locations`, and `target_overrides` otherwise retain their specialized
  merge behavior. Source/target images must exist in seeded process state.
- `calltrace_patterns.yaml`: every supplied top-level `patterns` or `source_families` section replaces
  the entire packaged section. Copy the complete section before changing it.

## System and endpoint telemetry

### `sysmon_filters.yaml`

Every supplied event section (`network_connect`, `image_loaded`, `file_create`, `registry_event`, or
`dns_query`) replaces that whole packaged section. Omitted sections remain defaults. A valid filter
can still erase useful coverage, so compare the effective section before writing.

### `edr_pools.yaml`

Every supplied top-level section replaces that section in full. Supported sections include:

- `linux_service_users` and `group_policy_extension_guids`
- `file_side_effect_profiles`, `file_ownership_rules`, and `registry_ownership_rules`
- `installed_software_products`
- `file_paths_windows`, `file_paths_linux`, and `runmru_commands`
- `registry_keys_hkcu` and `registry_keys_hklm` (three strings per entry)
- `dll_pool`

Use `{user}`, `{rand}`, `{hex}`, and other placeholders already supported by the surrounding pool.
Keep Windows paths in Windows sections and Linux paths in Linux sections. Process-aware side effects
belong in `file_side_effect_profiles`; do not put package-manager state, `/proc/<pid>`, protected
event logs, or another owner's artifacts into generic churn pools.

## Installed software identity

`installed_software_products` is source-native inventory metadata, not an executable release or an
application placement rule. Every new row uses the complete typed identity:

```yaml
installed_software_products:
  - product_id: example-ehr-client
    name: "Example EHR Client"
    publisher: "Example Clinical Software"
    version: "4.2.0"
    build: "4.2.117"
    architectures: [x64]
    scope: machine
```

Keep `product_id` stable across display-name changes. `version` and `build` are distinct release
dimensions, `architectures` is non-empty and unique, and `scope` is `machine` or `user`. Do not use
an installed-software row to imply that an application executable, service, task, or module was
deployed; those facts come from their typed deployment owners.

## RSAT

`rsat_tools.yaml` contains `tools` keyed by `id`. Matching tools merge; new IDs append. Each complete
tool requires `id`, `snap_in`, `command_line`, non-empty `target_ports` entries (`port`, `service`),
and positive `weight`; `display_name` and `loaded_modules` add source-native detail.

```yaml
tools:
  - id: aduc
    weight: 20
```

Use `_replace: true` when a matching tool's list must replace rather than extend.

## Verification

Check referenced personas, executables, parent/child relationships, modules, services, and unique
keys. Apply only exact dependencies selected by the user; application access, parentage, traffic,
and module visibility are semantic choices. Run
`eforge validate-config --json` in a fresh process after every mutation.

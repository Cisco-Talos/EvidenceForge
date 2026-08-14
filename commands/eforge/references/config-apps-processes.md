# Application, process, and endpoint overlays

Read only the section matching the requested family. Inspect the packaged YAML and existing overlay
before editing; several files that look alike have different merge behavior.

## Contents

- [Applications](#applications)
- [Process relationships](#process-relationships)
- [System and endpoint telemetry](#system-and-endpoint-telemetry)
- [RSAT](#rsat)

## Applications

`application_catalog.yaml` contains an `applications` list keyed by `id`. Matching IDs deep-merge;
lists append unless the entry uses `_replace: true`. New IDs append.

```yaml
applications:
  - id: ehr_client
    display_name: EHR Client
    platforms:
      windows:
        image_path: 'C:\Program Files\Example\EHR\ehr.exe'
        command_templates:
          - '"C:\Program Files\Example\EHR\ehr.exe" --open {internal_url}'
        command_parameter_pools:
          internal_url: [https://ehr.example.test/]
        children: []
        loaded_modules: []
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
- Each platform requires `image_path` and may define `pe_metadata`, `command_templates`, scoped
  `command_parameter_pools`, `children`, and `loaded_modules`.
- A loaded module may define signer/PE identity, `load_phase` (`startup` or `runtime`), and
  `startup_probability` from 0 to 1. Known third-party modules require native signer and complete PE
  metadata.

`personas` controls eligibility; a persona's `application_usage` list is descriptive only. Ask for
exact persona access rather than deriving it from title or risk.

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
`eforge validate-config --project-root <root> --json` in a fresh process after every mutation.

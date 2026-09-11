---
description: "Exact Scenario 2.0 deployment and source-observation override schemas"
---

# Scenario Deployment and Observation Overrides

Read this reference only when a Scenario 2.0 exercise must override compiled deployment or source
collection for exact instances. Ordinary scenarios should use configured profiles and omit both
lists. These structures replace selected fields; they are not wildcard selectors or append-only
patches.

## Deployment overrides

Each `environment.deployment_overrides` entry requires exact `system` plus at least one of
`applications`, `services`, `tasks`, `modules`, `cohorts`, or `user_applications`. Every patch field
is optional; an explicit empty list removes inherited values, while omission inherits them.
System targets are unique and must resolve to `environment.systems`.

`user_applications` entries require exactly `user` and `applications`; user targets are unique,
must resolve, and their application list is a complete replacement.

```yaml
environment:
  deployment_overrides:
    - system: WS-DEV-01
      applications: [chrome, vscode]
      services: []
      tasks: []
      modules: []
      cohorts: [engineering]
      user_applications:
        - user: marcus.chen
          applications: [chrome, vscode]
```

Application/cohort IDs allow letters, digits, `.`, `_`, `:`, and `-`. Service, task, and module
names may use source-native text but cannot contain wildcard selectors.

## Observation overrides

Each `environment.observation_overrides` entry requires exact `source_instance` and at least one
actual patch field. Optional `system` and `family` are identity guards, not selectors. Supported
patch fields are `enabled`, `capabilities`, `missingness`, `format_missingness`, `optional_fields`,
`windows`, and `batching`.

`source_instance` uses exact `<family>:<owner>[:<local-name>]` identity and is normalized to lower
case. Entries must be unique and must resolve against the compiled collection registry.
`family` is one of `windows_security`, `sysmon`, `ecar`, `syslog`, `bash_history`, `zeek`, `proxy`,
`web`, `asa`, or `ids`.

```yaml
environment:
  observation_overrides:
    - source_instance: sysmon:ws-dev-01
      system: WS-DEV-01
      family: sysmon
      enabled: true
      capabilities: [process, network, file]
      missingness: 0.02
      format_missingness:
        windows_event_sysmon: 0.01
      optional_fields: [CommandLine, Hashes]
      windows:
        - start: "2026-08-25T13:00:00Z"
          end: "2026-08-25T21:00:00Z"
      batching:
        enabled: true
        interval_us: 250000
        max_records: 500
```

`missingness` and each format probability are 0–1. Capability names and format names come from
the fixed authored schema; an empty capability list removes all capabilities. `optional_fields`
contains unique exact source-native names and may be empty.

Each `windows` entry supports optional timezone-aware `start` and `end`; start is inclusive, end
exclusive, and supplied endpoints must be ordered. Windows are sorted and cannot overlap. An
explicit empty list means no active collection interval.

`batching` supports exactly `enabled` (default `false`), nonnegative `interval_us`, and nonnegative
`max_records`. Enabled batching requires a positive interval.

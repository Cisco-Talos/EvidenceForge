---
description: "Exact endpoint, authentication, account, and raw storyline event schemas"
---

# Scenario Endpoint and Authentication Events

Read this reference when authoring any event type listed below. Every event accepts optional
`technique` and `description`; `type` selects the exact schema, and unknown fields are rejected.
Use typed events for modeled behavior. Reserve `raw` for source-native evidence that has no typed
contract.

**Contents:** process and session events · account and Windows state changes · process access ·
explicit credentials · workstation state · raw escape hatch

## `process`

Fields: `type`, required `process_name`, optional `command_line`, `process_ref`, `parent_ref`,
`supplementary`, `technique`, and `description`. `command_line` defaults to the process name at
generation time. Use unique `process_ref` values only when later children need exact lineage;
`parent_ref` names an earlier durable reference. `supplementary` is `auto` (default) or `none`.

```yaml
- type: process
  process_name: /usr/bin/curl
  command_line: curl -fsS https://updates.example/status
  process_ref: status-check
  supplementary: auto
```

## `logon`

Fields: `type`, `logon_type` (default `3`), optional `source_ip`, `technique`, and `description`.
Use `ssh_session` or `rdp_session` for modeled remote interactive sessions. Type 9 models Windows
NewCredentials token cloning; it is not an inbound authentication attempt.

## `failed_logon`

Fields: `type`, optional `source_ip`, `logon_type` (default `3`), optional `target_username`,
`technique`, and `description`. When `target_username` is absent, the storyline actor is the
target. Type 9 is invalid because it has no remote authentication target.

## `logoff`

Fields: `type`, optional `technique`, and optional `description`. It closes the compatible owned
session; do not duplicate closure evidence already owned by an SSH or RDP bundle.

## `account_created`

Fields: `type`, required `target_username`, optional `target_sid`, `technique`, and `description`.
When omitted, `target_sid` is derived from the modeled Windows domain identity.

## `account_deleted`

Fields: `type`, required `target_username`, optional `target_sid`, `technique`, and `description`.

## `group_member_added`

Fields: `type`, required `group_name`, required `member_name`, `scope`, `technique`, and
`description`. `scope` is `global` (default), `local`, or `universal`.

## `service_installed`

Fields: `type`, required `service_name`, required `service_file_name`, `service_account`,
`technique`, and `description`. `service_account` defaults to `LocalSystem`. Use a Windows-native
binary path and route remote installation through the bundle-owned service-control behavior.

## `scheduled_task_created`

Fields: `type`, required `task_name`, optional `task_content`, `technique`, and `description`.

## `log_cleared`

Fields: `type`, optional `technique`, and optional `description`.

## `create_remote_thread`

Fields: `type`, required `target_process`, optional `technique`, and optional `description`. This
models the remote-thread occurrence; pair it with a separate `process_access` event only when that
access is independently part of the narrative.

## `process_access`

Fields: `type`, `target_process`, `access_mask`, `technique`, and `description`.
`target_process` defaults to `lsass.exe`; `access_mask` defaults to `0x1010`.

## `explicit_credentials`

Fields: `type`, required `target_username`, optional `target_server`, `process_name`, `source_ip`,
`technique`, and `description`. Use this for Windows 4648 semantics such as RunAs or delegated
credentials. A materialized `runas.exe /netonly` caller owns the correlated Type 9 session.

## `workstation_lock`

Fields: `type`, optional `technique`, and optional `description`.

## `workstation_unlock`

Fields: `type`, optional `technique`, and optional `description`.

## `raw`

Fields: `type`, required `target_format`, `fields` (default `{}`), optional `technique`, and
optional `description`. `fields` is an arbitrary source-native mapping. Use this escape hatch only
when no typed event owns the intended occurrence; raw rendered rows must not trigger correlated
sibling evidence.

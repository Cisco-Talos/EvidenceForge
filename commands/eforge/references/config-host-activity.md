# Host activity, authentication, observation, and timing overlays

Read only the matching section. Inspect packaged YAML and the existing overlay before editing; use
validation as the schema authority.

## Contents

- [Linux activity](#linux-activity)
- [SMB client and server profiles](#smb-client-and-server-profiles)
- [Authentication and endpoint noise](#authentication-and-endpoint-noise)
- [Volume and distribution](#volume-and-distribution)
- [Observation and timing](#observation-and-timing)
- [Safety fixture families](#safety-fixture-families)

## Linux activity

### `bash_commands.yaml`

Deep-merges shared command roles and behavior models: `common`, persona/shared roles,
`storyline_friction`, `workflow_model`, `workflows`, `typo_model`, `package_manager_model`,
`keyboard_adjacency`, and `params`.

Runtime maps personas to reusable roles—for example, developers can use `dba`/`webadmin` and
security analysts can use `security`. Do not add duplicate persona-named pools.

Keep baseline commands inert and legitimate; use packaged placeholders and OS-native paths.
Probabilities must be 0-1 and count/range bounds ordered.

### `systemd_schedules.yaml`

`schedules` append. Each has a unique service identity, type/frequency/hour/jitter/distro, and
optional role/service/probability/cron fields. Avoid fixed fleet-wide cadence.

### `extra_syslog_messages.yaml`

`programs` append with program, templates, parameter profiles, host filters, rarity, and window
limits. Canonical activity bundles—not ambient messages—own lifecycle evidence.

## SMB client and server profiles

### `smb_profiles.yaml`

Deep-merges reusable SMB provider defaults and source-native process morphology. Scenario or
organization YAML—not this file—owns storage topology, share access and selected audit profile,
mappings, credential mode/principal, and explicit `smb_activity.client_access` intent.

The strict `schema_version: 1` document has six mapping roots:

- `advertised_filesystem_defaults` keeps the wire label separate from an ext4/XFS backing volume;
  `samba_audit` maps failures and every canonical operation to a VFS label and eligible tier.
- `client_defaults`/`client_profiles` cover Explorer, GVFS texture, direct `smbclient`, and mounted
  CIFS; `server_defaults`/`server_profiles` cover LanmanServer and Samba identities.

Client profiles declare OS, access/path modes, process/kernel/none transport attribution, aliases,
system types, weight, optional protocol auth options, and shared or per-operation process metadata.
Processes use an OS-native absolute image, command template, username, lifecycle, and optional
credential source/operand mode. `remote` uses the wire path; `upload`/`download` use remote plus local
operands; `rename` uses remote source/destination; mounted `transfer` requires native
`{source_path}` and `{destination_path}`. Allowed template fields are `server`, `share`, `path`,
`client_path`, `local_path`, `source_path`, `destination_path`, `username`, `smb_principal`,
`auth_options`, `operation`, and `client_ip`; traversal, conversions, and format specs are invalid.

Mounted CIFS uses kernel transport plus an explicit operation actor; `mount.cifs` does not own later
I/O. Direct `smbclient` is operation/process-owned, Explorer is resident, and GVFS is background
texture only. Samba uses a service listener plus a per-transport `smbd` worker. Audit `minimal` is
lifecycle-only; operation/failure tiers permit only monotonic `standard`/`high` mappings.

An overlay supplies only changed nested fields:

```yaml
# .eforge/config/activity/smb_profiles.yaml
client_profiles:
  linux_cifs_mount:
    weight: 55.0
```

List fields extend, so add only unique aliases/system types; `_replace` does not replace a partial
profile list. Run `eforge validate-config` after every change.

## Authentication and endpoint noise

### `kerberos_realism.yaml`

Deep-merges `tgt_success`, `tgt_failure`, `certificate_profiles`, and `transport_profiles`. PKINIT
requires a certificate; non-PKINIT entries forbid one. Keep ticket/encryption weights valid.

### `windows_auth_realism.yaml`

Deep-merges `workstation_lock`, `group_policy_refresh`, `failed_logon`, and `special_privileges`.
Keep failures local where appropriate, paths non-empty, probabilities 0-1, and timing ordered.

### `auth_noise.yaml`

Deep-merges stale scheduled-credential and service-account delegation. Use recurrence, jitter,
skipping, and backoff for irregular low-volume failures rather than exact cadence.

### `endpoint_noise.yaml`

Deep-merges `windows_scheduled_processes`, `registry_noise`, `ecar_flow_identity`, and
`ecar_file_churn`. These generation knobs do not replace application or EDR pool ownership.

## Volume and distribution

### `traffic_rates.yaml`

Deep-merges the `low`, `medium`, and `high` intensity tables. Each supported traffic family uses an
ordered, non-negative range and enforced upper bound. Change only the intended leaf.

### `host_activity_profiles.yaml`

Deep-merges `rate_families`, host/role/persona profiles, `artifact_variants`, and `firewall_deny` for
coarse volume/distribution—not authorization or topology. Keep multipliers/ranges bounded.

## Observation and timing

### `observation_profiles.yaml`

Deep-merges named `profiles`; `complete` must remain. Source-level missingness/delay stays coherent
for each local process/session/same-UID lifecycle group. Scenarios select `observation_profile`.

Do not embed evaluator rules here. Evaluation policy remains engine-owned.

### `timing_profiles.yaml`

Deep-merges:

- `relationships`: causal prerequisites, source latency, human workflow, and teardown.
- `endpoint_clock`: shared host clock profiles for endpoint-resident sources.
- `network_sensor_observation` and `firewall_observation`: appliance clock/path/capture policy.
- `windows_startup_modules`, `windows_event_time`, and `sysmon_event_envelope`: source-native
  projection timing.

Keep ranges ordered/non-negative. Fix bad ordering in the owning planner, not one emitter.

## Safety fixture families

`secret_families.yaml` and `payload_families.yaml` merge synthetic fixtures by `name`; markers and
reserved-host allowlists extend. They cannot authorize live credentials/hosts, payloads, or OOB.

- Keep a poison marker inside every high-entropy secret token.
- Keep `{marker}` in every adversarial `value_template`; marked forged lines must remain marked on
  both halves.
- Use reserved/test hosts accepted by the packaged safety schema.
- Never weaken default markers or allowlists to make validation pass.

## Verification

Treat cadence, rate, role, missingness, or safety changes as semantic. Run `eforge validate-config
--project-root <root> --json` fresh after every edit; validate affected scenarios with that root.

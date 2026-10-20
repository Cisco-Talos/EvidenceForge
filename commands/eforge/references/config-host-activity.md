# Host activity, authentication, observation, and timing overlays

Inspect the matching packaged YAML and existing overlay before editing; validation is the schema authority.

## Contents

- [Linux activity](#linux-activity)
- [Mac native logging profile](#mac-native-logging-profile)
- [Mac filesystem and execution metadata](#modeled-mac-filesystem-and-execution-metadata)
- [SMB client and server profiles](#smb-client-and-server-profiles)
- [Authentication and endpoint noise](#authentication-and-endpoint-noise)
- [Volume and distribution](#volume-and-distribution)
- [Observation and timing](#observation-and-timing)
- [Safety fixture families](#safety-fixture-families)

## Linux activity

### `bash_commands.yaml`

Deep-merges command roles and models: `common`, persona/shared roles, `storyline_friction`, `workflow_model`, `workflows`, `typo_model`, `package_manager_model`, `keyboard_adjacency`, and `params`.

Runtime maps personas to reusable roles, including developer → `dba`/`webadmin` and security analyst → `security`. Do not duplicate pools under persona names. Keep baseline commands inert and legitimate; use packaged placeholders and OS-native paths. Probabilities must be 0-1 and count/range bounds ordered.

### `systemd_schedules.yaml`

`schedules` append. Each has a unique service identity, type/frequency/hour/jitter/distro, and optional role/service/probability/cron fields. Avoid fixed fleet-wide cadence.

### `extra_syslog_messages.yaml`

`programs` append with program, templates, parameter profiles, host filters, rarity, and window limits. Canonical activity bundles own lifecycle evidence.

## SMB client and server profiles

### `smb_profiles.yaml`

Deep-merges reusable SMB provider defaults and source-native process morphology. Scenario or organization YAML owns storage topology, share access and selected audit profile, mappings, credential mode/principal, and explicit `smb_activity.client_access` intent.

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

Mounted CIFS uses kernel transport plus an explicit operation actor; `mount.cifs` does not own later I/O. Direct `smbclient` is operation/process-owned, Explorer is resident, and GVFS is background texture only.
Samba uses a service listener plus a per-transport `smbd` worker. Audit `minimal` is lifecycle-only; operation/failure tiers permit only monotonic `standard`/`high` mappings.

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
--json` fresh after every edit; validate affected scenarios from the same working directory.

## Mac native source profiles

`macos_unified_log_profiles.yaml` deep-merges through existing activity overlays and immutable effective configuration. The packaged `macos26-workspace-entry-v1` profile contains the modeled Mach timebase and one static loginwindow callsite/message. Offsets and timing are synthetic profile choices; do not calibrate them from personal logs. Existing timing relationships `macos.workspace_request` and `source.macos_unified_log` own canonical gap and source delay. Collection uses the existing source family and observation policies. `macos_endpoint_security_profiles.yaml` selects only the modeled macOS 26 arm64 workstation fork/v10 profile, literal privileged `/usr/bin/eslogger fork` activation, and the same explicit clock policy. Its frozen source identity, exact collector execution and finite complete modeled inventory remain bound to checkpointed counters; restored legacy unknown profiles cannot acquire new defaults. This is internal initialization policy: ES is still unregistered, missing required metadata stays unavailable, and changing this file cannot admit exec/exit or close native reference gates. No collector flag or top-level scenario block is added.

## Modeled Mac filesystem and execution metadata

`macos_installed_files.yaml` uses the existing deep-mapping activity overlay and frozen effective-config snapshot. Its `modeled-macos-installed-v1` policy produces metadata when native preparation or a supported Mac launch requests the engine's installed-file owner. Logical sizes follow a bounded log-normal model and remain equal for identical binary content across hosts and workload seeds. Each host owns a separate modeled volume and distinct single-link file objects. Machine files use the resolved local root account; user files require their exact local owner. Unknown accounts remain unavailable.

The profile explicitly selects dense block allocation, permissions, flags, generation and pre-window timestamp ranges. These are synthetic model choices, not discovered file sizes, installed inventories, APFS compression or native calibration. No generator-host file is inspected. Preserve range ordering, a size median within the logical-size range, positive sigma and allocation units divisible by 512. Older frozen inputs without this packaged profile keep native stat unavailable instead of reading newer defaults. Other OS paths do not request these Mac owners. Provisioning alone admits no native source or event family.

`macos_execution_metadata.yaml` deep-merges the explicit `modeled-macos-execution-v1` launch policy. `terminal` bounds host-local devfs slots, device IDs, inode allocation, permissions and block size; exact session credentials own UID/GID. Root jobs/boot select absent terminals, local login allocates a character device, and fork/exec reuse session ownership. `user_environment`/`root_environment` are ordered assignments with only `{username}`, `{home}` and `{shell}` placeholders. Directory inode/size/allocation/age fields provision known roots and resolved homes on the installed volume; arbitrary paths stay unknown. `cpu_subtype` explicitly selects a modeled native arm64 slice; it is not inferred from host architecture. `first_pipe_id` starts the transactional host-local pipe namespace. Complete descriptor extents belong to canonical descriptor operations; legacy unknown tables cannot become empty observations. Slot/pipe/inode consumption rolls back on failure and survives checkpoint recovery. These are synthetic model choices, not APFS measurements. Older frozen inputs without this policy remain unknown; no host filesystem or environment is read. This policy does not enable ES output or close native reference gates.

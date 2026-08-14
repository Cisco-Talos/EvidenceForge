# Host activity, authentication, observation, and timing overlays

Read only the section matching the requested family. Inspect the packaged YAML and existing overlay
before editing; use validation as the schema authority.

## Contents

- [Linux activity](#linux-activity)
- [Authentication and endpoint noise](#authentication-and-endpoint-noise)
- [Volume and distribution](#volume-and-distribution)
- [Observation and timing](#observation-and-timing)
- [Safety fixture families](#safety-fixture-families)

## Linux activity

### `bash_commands.yaml`

Deep-merges all supplied branches. The file contains shared command roles as well as behavior
models: `common`, persona/shared roles, `storyline_friction`, `workflow_model`, `workflows`,
`typo_model`, `package_manager_model`, `keyboard_adjacency`, and `params`.

Role keys do not all equal persona names. Runtime intentionally maps personas to reusable roles—for
example, developer activity can use `dba` or `webadmin`, and security analysts can use `security`.
Match existing role/mapping conventions instead of adding duplicate persona-named pools.

Keep command vocabulary inert and legitimate for baseline noise. Use OS-native paths and supported
placeholders from the packaged file. Probability values must be 0-1 and count/range bounds ordered.

### `systemd_schedules.yaml`

`schedules` append. Each entry has a unique service identity plus type/frequency/hour/jitter/distro
and optional role, service, probability, or cron fields. Avoid duplicate service identities and
fixed fleet-wide cadence.

### `extra_syslog_messages.yaml`

`programs` append. Entries own program name, message templates, optional atomic parameter profiles,
distro/role/system filters, rarity, and per-window limits. Do not use ambient messages for lifecycle
evidence that belongs to a canonical activity bundle.

## Authentication and endpoint noise

### `kerberos_realism.yaml`

Deep-merges `tgt_success`, `tgt_failure`, `certificate_profiles`, and `transport_profiles`. Preserve
coherent pre-auth/certificate combinations: PKINIT requires a certificate profile; non-PKINIT
entries must not carry certificate fields. Keep weighted ticket/encryption values within validator
bounds.

### `windows_auth_realism.yaml`

Deep-merges `workstation_lock`, `group_policy_refresh`, `failed_logon`, and `special_privileges`.
Keep local failures workstation-local, network validation paths non-empty, probabilities 0-1, ports
positive, privilege names source-native, and timing ranges ordered.

### `auth_noise.yaml`

Deep-merges stale scheduled-credential and service-account-delegation behavior. Account pools,
recurrence, jitter, skipping, and backoff should create irregular low-volume failures rather than
exact modulo cadence.

### `endpoint_noise.yaml`

Deep-merges `windows_scheduled_processes`, `registry_noise`, `ecar_flow_identity`, and
`ecar_file_churn`. These are generation/attribution knobs, not a substitute for application or EDR
pool ownership.

## Volume and distribution

### `traffic_rates.yaml`

Deep-merges the `low`, `medium`, and `high` intensity tables. Each supported traffic family uses an
ordered, non-negative range and enforced upper bound. Change only the intended leaf.

### `host_activity_profiles.yaml`

Deep-merges `rate_families`, `host_types`, `role_profiles`, `persona_profiles`,
`artifact_variants`, and `firewall_deny`. Use these for coarse volume/distribution differences, not
for authorization or concrete topology. Multipliers and probability/range fields must remain
bounded and internally coherent.

## Observation and timing

### `observation_profiles.yaml`

Deep-merges named profiles below `profiles`. The `complete` profile must remain available. Missingness
and delay are source-level collection behavior; decisions must remain coherent for a source-local
process/session/same-UID lifecycle group. A scenario selects a named `observation_profile`.

Do not embed evaluator rules here. Evaluation policy remains engine-owned.

### `timing_profiles.yaml`

Deep-merges:

- `relationships`: causal prerequisites, source latency, human workflow, and teardown.
- `endpoint_clock`: shared host clock profiles for endpoint-resident sources.
- `network_sensor_observation` and `firewall_observation`: appliance clock/path/capture policy.
- `windows_startup_modules`, `windows_event_time`, and `sysmon_event_envelope`: source-native
  projection timing.

All ranges must be ordered and non-negative where required. Do not compensate for bad event ordering
by moving one emitter's timestamp; fix the owning relationship or planner.

## Safety fixture families

`secret_families.yaml` and `payload_families.yaml` support intentionally synthetic test artifacts.
Families merge by `name`; safety markers and reserved-host allowlists extend. They cannot authorize
real-looking credentials, live hosts, executable payloads, or OOB behavior.

- Keep a poison marker inside every high-entropy secret token.
- Keep `{marker}` in every adversarial `value_template`; marked forged lines must remain marked on
  both halves.
- Use reserved/test hosts accepted by the packaged safety schema.
- Never weaken default markers or allowlists to make validation pass.

## Verification

Treat new cadence, rate, role mapping, missingness, or safety policy as semantic and ask before
writing. Run `eforge validate-config --project-root <root> --json` in a fresh process after every
mutation. If a scenario selects a changed observation profile, validate that scenario with the same
project root.

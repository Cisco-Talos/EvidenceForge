# Host Activity Configuration Reference

> **This is a reference document for the /eforge:config skill.** If you are trying to add, modify, or remove config entries, invoke /eforge:config instead of using this reference directly. This file contains schema details that the config skill reads during execution.
>
> To discover config file paths, run `eforge info <field>` (e.g., `eforge info paths.activity`). Run `eforge info --fields` to see all available fields.

Schema documentation for host-level activity config files. User customizations go in the project-local overlay at `.eforge/config/activity/` — partial files that merge with package defaults. See `config-dependency-graph.md` for details.

## Table of Contents

1. [bash_commands.yaml](#bash_commandsyaml)
2. [systemd_schedules.yaml](#systemd_schedulesyaml)
3. [extra_syslog_messages.yaml](#extra_syslog_messagesyaml)
4. [kerberos_realism.yaml](#kerberos_realismyaml)
5. [windows_auth_realism.yaml](#windows_auth_realismyaml)
6. [auth_noise.yaml](#auth-noise-auth_noiseyaml)
7. [endpoint_noise.yaml](#endpoint-noise-endpoint_noiseyaml)
8. [timing_profiles.yaml](#timing_profilesyaml)
9. [Domain Controller Baseline Activity](#domain-controller-baseline-activity)

---

## bash_commands.yaml

Per-role bash command vocabularies for realistic `bash_history` log generation. The generator picks commands based on user persona and server role.

### Structure

```yaml
common:                              # Commands available to ALL roles
  - "ls -la"
  - "ps aux | grep {service}"

sysadmin:                            # Role-specific commands
  - "systemctl status {service}"
  - "tail -{n} /var/log/auth.log"

developer:
  - "git status"
  - "docker ps"

typo_model:                          # Optional typo/noise controls
  max_rate: 0.08
  short_history_threshold: 8
  short_history_max_typos: 1
  correction_probability: 0.85
```

### Placeholder Tokens

These are resolved at generation time from a built-in params dictionary:

| Token | Expands To |
|-------|------------|
| `{service}` | Random system service name (e.g., `sshd`, `nginx`, `postgresql`) |
| `{n}` | Random integer (typically 5-50) |
| `{ip}` | Random IP address from scenario |
| `{file}` | Random file path |
| `{user}` | Random username from scenario |
| `{port}` | Random port number |

### Conventions

- `common:` section provides baseline commands for all Linux users
- Role keys must match persona names (e.g., `sysadmin`, `developer`, `analyst`)
- `typo_model:` caps typo density so short bash histories do not look artificially noisy
- Run `eforge validate-config` after changing `typo_model`; rates must be between 0 and 1, and count thresholds must be non-negative integers
- A user gets commands from `common` + their persona's role section
- Commands should be realistic — look at actual bash history for reference
- Include common typos and abbreviated commands for realism (`ll`, `cd -`)

### Adding a New Role

1. Add a new key under the root level matching the persona name
2. Include 10-30 role-specific commands
3. Use `{placeholder}` tokens for dynamic content

---

## systemd_schedules.yaml

Real-world systemd timer and cron job schedules. These generate periodic syslog events on Linux hosts at realistic intervals.

### Structure

```yaml
schedules:
  # Systemd timer example
  - service: logrotate
    type: systemd_timer
    frequency: daily
    typical_hour: 6
    jitter_minutes: 30
    distro: all
    process_path: "/usr/sbin/logrotate"
    start_message: "Starting logrotate.service - Rotate log files."
    finish_message: "Finished logrotate.service - Rotate log files."
    timer_message: "logrotate.timer: Triggering logrotate.service..."
    detail_messages:
      debian:
        - "rotating /var/log/syslog"
      rhel:
        - "rotating /var/log/messages"

  # Cron job example
  - service: certbot_renew
    type: cron
    frequency: daily
    typical_hour: 3
    jitter_minutes: 60
    distro: all
    role: web_server
    cron_user: root
    cron_commands:
      debian: "/usr/bin/certbot renew --quiet --deploy-hook 'systemctl reload nginx'"
      rhel: "/usr/bin/certbot renew --quiet --deploy-hook 'systemctl reload httpd'"
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service` | string | yes | Service/timer name |
| `type` | string | yes | `systemd_timer` or `cron` |
| `frequency` | string | yes | `daily`, `weekly`, or `30min` |
| `typical_hour` | int | yes | UTC hour (0-23) when task normally runs |
| `typical_day` | string | weekly only | Day of week (`monday`-`sunday`) |
| `jitter_minutes` | int | yes | Max jitter offset (per-host deterministic) |
| `distro` | string | yes | `all`, `debian`, or `rhel` |
| `role` | string | no | Host role filter (e.g., `web_server`) |
| `process_path` | string | no | Path to service binary for process create events |

**Systemd timer additional fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `start_message` | string | yes | Syslog message when service starts |
| `finish_message` | string | yes | Syslog message when service finishes |
| `timer_message` | string | no | Timer trigger message (logged by systemd PID 1) |
| `detail_messages` | object | no | Distro-keyed lists of detail messages |

**Cron additional fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `cron_user` | string | yes | User running the cron job |
| `cron_commands` | object | yes | Distro-keyed command strings |

---

## extra_syslog_messages.yaml

Additional syslog program messages for baseline diversity. These supplement the main syslog generation with daemon and system program messages.

### Structure

```yaml
programs:
  - app: NetworkManager              # Syslog app_name
    messages:                         # List of message templates
      - "<info> [{}] device (ens160): state change: ip-config -> activated"
    distro: ubuntu                    # Optional: restrict to distro
    roles: [web_server]              # Optional: restrict to host roles (any match)
    transient: true                   # Optional: true if process forks per invocation
    weight: 5                         # Optional: relative selection weight (default 10)
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `app` | string | yes | Syslog program/app name |
| `messages` | list[string] | yes | Message templates (`{}` filled at generation time) |
| `distro` | string | no | Restrict to `ubuntu` (excluded on RHEL-like) |
| `roles` | list[string] | no | Required host roles (any match includes the entry) |
| `transient` | bool | no | If `true`, uses random PID per invocation |
| `weight` | integer | no | Relative selection weight; lower values make rare messages less frequent |

---

## kerberos_realism.yaml

Data-driven Kerberos field distributions for Windows Security authentication events. The generator uses this file for successful 4768 TGT requests and failed 4771 pre-authentication events.

### Structure

```yaml
tgt_success:
  pre_auth_types:
    encrypted_timestamp:
      value: 2
      weight: 96
      certificate_required: false
    pkinit:
      value: 15
      weight: 3
      certificate_required: true
      certificate_profile: enterprise_user
    none_or_legacy:
      value: 0
      weight: 1
      certificate_required: false
  ticket_options:
    forwardable_renewable_canonicalize:
      value: "0x40810010"
      weight: 60
  encryption_types:
    aes256:
      value: "0x12"
      weight: 70

tgt_failure:
  pre_auth_types:
    encrypted_timestamp:
      value: 2
      weight: 95
    none_or_legacy:
      value: 0
      weight: 5
  ticket_options:
    forwardable_renewable_canonicalize:
      value: "0x40810010"
      weight: 80

certificate_profiles:
  enterprise_user:
    issuer_names:
      - "CN=Acme Enterprise Issuing CA, O=Acme Corp, C=US"
    serial_hex_bytes: 16
    thumbprint_hex_chars: 40
```

### Conventions

- `PreAuthType: 2` is the normal encrypted timestamp case and should dominate default profiles.
- `PreAuthType: 15` models PKINIT/certificate pre-auth and must reference a certificate profile so 4768 cert fields are populated.
- `PreAuthType: 0` is rare legacy/no-preauth behavior.
- Supported encryption types are `0x12` (AES-256), `0x11` (AES-128), and `0x17` (RC4-HMAC).
- Failed 4771 events should usually use `PreAuthType: 2`; `eforge validate-config` rejects failure profiles where no-preauth exceeds 10%.
- Run `eforge validate-config` after changes; it rejects invalid PKINIT/certificate combinations and excessively high no-preauth, PKINIT, or RC4 weights.

---

## Windows Auth Realism (`windows_auth_realism.yaml`)

Controls Windows Security authentication realism knobs that are too operationally specific for scenario YAML.

```yaml
workstation_lock:
  min_unlock_gap_seconds: 127

failed_logon:
  local_interactive:
    logon_process_name: User32
    authentication_package_name: Negotiate
    process_name: "C:\\Windows\\System32\\winlogon.exe"
  network:
    validation_path_weights:
      ntlm_only:
        emit_4776: true
        emit_4771: false
        weight: 55
    logon_process_weights:
      ntlm:
        logon_process_name: NtLmSsp
        authentication_package_name: NTLM
        lm_package_name: NTLM V2
        weight: 70
    emit_network_connection_probability: 1.0
    network_ports:
      smb:
        port: 445
        weight: 85
  special_privileges:
    emission_probabilities:
      service_account: 0.35
      domain_admin: 0.55
      workstation_admin: 0.50
    profiles:
      domain_admin:
        privileges: [SeSecurityPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege]
        weight: 1
```

The lock/unlock gap applies when a generated 4801 unlock would otherwise occur too soon after the previous 4800 lock for the same user, host, and LogonID. Overlays can increase or decrease the value, but `eforge validate-config` requires at least 60 seconds.

Failed-logon profiles control source-native Windows 4625 fields and DC-side validation evidence. Local interactive failures should remain workstation-local (`User32`/`Negotiate` with no source IP); network failures choose weighted NTLM/Negotiate profiles, a weighted validation path (`4776`, `4771`, or both), and companion network ports for sensor-visible failed-auth attempts. Remote auth companion connections must be established or reset after payload, never SYN-only. Special-privilege emission probabilities control how often each account class gets a companion 4672, and profiles control the `PrivilegeList` for service accounts, domain admins, workstation admins, and UAC-elevated users. Run `eforge validate-config` after overlay changes; probabilities must be between 0 and 1, weights/ports must be positive, validation paths must emit at least one DC-side event, and privilege names must use `Se*Privilege` names.

---

## Auth Noise (`auth_noise.yaml`)

Controls baseline authentication noise that is not scenario-authored, especially stale scheduled credentials.

```yaml
scheduled_stale_credentials:
  account_base_names: [svc_backup, svc_monitor, svc_report, svc_deploy, svc_scan]
  host_count_min: 1
  host_count_max: 2
  interval_ranges:
    - min_minutes: 55
      max_minutes: 95
      weight: 30
    - min_minutes: 105
      max_minutes: 155
      weight: 45
  first_occurrence_seconds_min: 0
  first_occurrence_seconds_max: 2700
  jitter_seconds_min: -420
  jitter_seconds_max: 780
  skip_probability: 0.16
  backoff_probability: 0.10
  backoff_seconds_min: 900
  backoff_seconds_max: 3600
```

`account_base_names` should be plausible disabled service or automation principals; the engine still avoids collisions with scenario users and service accounts. Interval ranges, jitter, skip probability, and backoff probability produce deterministic but non-modulo recurrence so stale scheduled-task failures do not land on exact hourly or two-hour cadences. Run `eforge validate-config` after overlay changes; ranges must be ordered, weights must be positive, and probabilities must be between 0 and 0.95.

---

## Endpoint Noise (`endpoint_noise.yaml`)

Controls endpoint background timing and registry-emission policies that are too source-specific for scenario YAML. Use it to tune routine Windows scheduled-process spacing and whether DHCP interface registry values appear as ambient Sysmon/EDR noise.

```yaml
windows_scheduled_processes:
  count_min: 2
  count_max: 5
  trigger_window_start_seconds: 90
  trigger_window_end_seconds: 3510
  slot_spacing_seconds: 300
  host_phase_window_seconds: 900
  jitter_seconds_min: -42
  jitter_seconds_max: 73
  skip_probability: 0.08

registry_noise:
  dhcp_interface_values:
    value_names: [DhcpIPAddress, DhcpNameServer]
    require_dhcp_state: true
    emit_on_lease_events: true
    suppress_system_types: [server, domain_controller]
    suppress_roles: [domain_controller, dns_server, file_server, web_server]
```

`windows_scheduled_processes` replaces hour-end clamping with profile-driven trigger windows, per-host phase offsets, jitter, and skips. Keep `trigger_window_end_seconds` comfortably below 3599 to avoid synthetic `xx:59:59` clusters.

`registry_noise.dhcp_interface_values` reserves DHCP interface registry writes for actual DHCP lease/reconfigure activity. Static infrastructure roles should stay in `suppress_system_types` or `suppress_roles` so they do not repeatedly rewrite DHCP values as ambient registry noise. Run `eforge validate-config` after overlay changes; it rejects inverted ranges, empty value-name lists, and invalid probabilities.

---

## timing_profiles.yaml

Data-driven timing windows for causal relationships, source-native latency, teardown margins, and Windows/Sysmon same-timestamp collision spacing. Use this when tuning realism of correlated event gaps without changing scenario YAML.

### Structure

```yaml
relationships:
  network.dns_before_tcp:
    class: causal_prerequisite
    position: before
    min_ms: 20
    max_ms: 1500
  source.zeek_ssl_analyzer:
    class: same_observation
    position: after
    min_ms: 5
    max_ms: 80
  source.zeek_conn_start:
    class: same_observation
    position: after
    min_ms: 0
    max_ms: 850
  network.tls_completed_min_duration:
    class: same_observation
    position: after
    min_ms: 800
    max_ms: 2500
  web.session_navigation:
    class: human_workflow
    position: after
    min_ms: 3000
    max_ms: 30000
  web.asset_stylesheet_script_after_page:
    class: burst_fanout
    position: after
    min_ms: 50
    max_ms: 200
  web.tool_request_gap:
    class: burst_fanout
    position: after
    min_ms: 120
    max_ms: 1500

network_sensor_observation:
  default_profile: well_synced
  profiles:
    well_synced:
      clock_skew_us:
        min: -1500
        max: 1500
      path_delay_us:
        min: 50
        max: 2000

windows_event_time:
  collision_spacing:
    near_zero_until: 25
    near_gap_min_us: 50
    near_gap_max_us: 500
    large_gap_min_ms: 1000
    large_gap_max_ms: 4000
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `relationships.<name>.class` | string | yes | Relationship class such as `same_observation`, `source_latency`, `causal_prerequisite`, `human_workflow`, `periodic`, or `teardown` |
| `relationships.<name>.position` | string | yes | `before` or `after` relative to the trigger event |
| `relationships.<name>.min_ms` | int | yes | Minimum offset in milliseconds |
| `relationships.<name>.max_ms` | int | yes | Maximum offset in milliseconds; must be `>= min_ms` |
| `windows_event_time.collision_spacing.near_zero_until` | int | yes | Same-host tied-event collisions that can remain near-zero before larger spacing begins |
| `windows_event_time.collision_spacing.near_gap_min_us` / `near_gap_max_us` | int | yes | Microsecond spacing for small tied clusters |
| `windows_event_time.collision_spacing.large_gap_min_ms` / `large_gap_max_ms` | int | yes | Millisecond spacing for large tied clusters that would otherwise compress into synthetic-looking bursts |
| `network_sensor_observation.default_profile` | string | yes | Sensor timing profile used for multi-sensor Zeek observation offsets |
| `network_sensor_observation.profiles.<name>.clock_skew_us` | mapping | yes | `{min, max}` per-sensor clock skew in microseconds |
| `network_sensor_observation.profiles.<name>.path_delay_us` | mapping | yes | `{min, max}` per-flow tap/capture delay in microseconds |

### Conventions

- Treat `same_observation` and small tied clusters as eligible for near-zero gaps.
- Keep source-native analyzer offsets inside the owning event lifetime. For example, Zeek
  `ssl.log` and `x509.log` timestamps should occur after conn start but before conn end for
  the same UID.
- Use seconds or minutes for human or bulk workflow relationships; do not force everything into microseconds.
- Web session timing uses `web.session_navigation` for user-driven page-to-page actions and `web.asset_*_after_page` / `web.tool_request_gap` for render fanout and tool/API bursts.
- Keep the default `network_sensor_observation` profile in low milliseconds for well-synced Zeek fleets; use overlays only when modeling known sensor clock drift or queued/remote capture paths.
- Run `eforge validate-config` after overlay changes; it rejects invalid relationship classes, positions, negative windows, and inverted min/max ranges.

---

## Domain Controller Baseline Activity

Domain controllers receive admin-only baseline activity — no user desktop sessions, browsers, Office apps, or user profile artifacts. This is controlled by two mechanisms:

1. **`system_types` in application_catalog.yaml**: User-facing apps have `system_types: [workstation]`, preventing them from appearing on DCs. DC admin tools (dcdiag, repadmin, etc.) have `system_types: [domain_controller]`. See `config-apps-processes.md` for details.

2. **RSAT sessions from `rsat_tools.yaml`**: The baseline generates correlated cross-host admin sessions where mmc.exe and snap-in DLL loads appear on the admin's workstation, while LDAP/RPC connections and type 3 logons appear on the DC. See the `rsat_tools.yaml` section in `config-apps-processes.md` for the schema.

No scenario YAML configuration is needed. RSAT sessions are auto-generated when the environment contains domain controllers and admin personas (sysadmin/help_desk).

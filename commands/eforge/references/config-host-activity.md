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
5. [Domain Controller Baseline Activity](#domain-controller-baseline-activity)

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
      - "<info> [{}] device (ens160): state change: activated -> activated"
    distro: ubuntu                    # Optional: restrict to distro
    roles: [web_server]              # Optional: restrict to host roles (any match)
    transient: true                   # Optional: true if process forks per invocation
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `app` | string | yes | Syslog program/app name |
| `messages` | list[string] | yes | Message templates (`{}` filled at generation time) |
| `distro` | string | no | Restrict to `ubuntu` (excluded on RHEL-like) |
| `roles` | list[string] | no | Required host roles (any match includes the entry) |
| `transient` | bool | no | If `true`, uses random PID per invocation |

---

## kerberos_realism.yaml

Data-driven Kerberos field distributions for Windows Security authentication events. The generator uses this file for successful 4768 TGT requests.

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
- Run `eforge validate-config` after changes; it rejects invalid PKINIT/certificate combinations and excessively high no-preauth, PKINIT, or RC4 weights.

---

## Domain Controller Baseline Activity

Domain controllers receive admin-only baseline activity — no user desktop sessions, browsers, Office apps, or user profile artifacts. This is controlled by two mechanisms:

1. **`system_types` in application_catalog.yaml**: User-facing apps have `system_types: [workstation]`, preventing them from appearing on DCs. DC admin tools (dcdiag, repadmin, etc.) have `system_types: [domain_controller]`. See `config-apps-processes.md` for details.

2. **RSAT sessions from `rsat_tools.yaml`**: The baseline generates correlated cross-host admin sessions where mmc.exe and snap-in DLL loads appear on the admin's workstation, while LDAP/RPC connections and type 3 logons appear on the DC. See the `rsat_tools.yaml` section in `config-apps-processes.md` for the schema.

No scenario YAML configuration is needed. RSAT sessions are auto-generated when the environment contains domain controllers and admin personas (sysadmin/help_desk).

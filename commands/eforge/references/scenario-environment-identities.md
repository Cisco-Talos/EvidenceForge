---
description: "Exact scenario people, systems, groups, platform identities, and network identities"
---

# Scenario Environment Identities

Read this reference whenever `environment.users`, `systems`, accounts, groups, platform identity,
or `network_identities` changes. These are authored structures; use `eforge info` only to discover
project-dependent persona or role names.

**Contents:** [Users and systems](#users-and-systems) · [Personas and timezone](#personas-and-timezone)
· [Accounts and groups](#accounts-and-groups) · [Platform identity](#platform-identity-overrides)
· [Network identities](#network-identities)

## Users and systems

Each `users` entry supports required `username`, `full_name`, and `email`, plus `groups` (default
`[]`), `enabled` (default `true`), optional `persona`, optional `primary_system`, and optional
`browsing_intensity: light|normal|heavy`. Usernames allow letters, digits, `.`, `_`, `$`, and `-`.
Every active user that should generate ordinary activity needs a resolvable `primary_system`.

Each `systems` entry supports required `hostname`, `ip`, `os`, and
`type: workstation|server|domain_controller`; optional `os_build` (1–128 characters),
`architecture: x86|x64|arm64`, `assigned_user`; and lists `services`, `roles`, and
`public_hostnames` (all default `[]`). IPs must be IPv4 or IPv6. Public hostnames describe
internet-facing names for modeled defender-controlled services; external systems themselves
belong in `network_identities`.

```yaml
environment:
  description: "Corporate environment"
  domain: corp.invalid
  users:
    - username: marcus.chen
      full_name: "Marcus Chen"
      email: marcus.chen@corp.invalid
      persona: developer
      primary_system: WS-DEV-01
      enabled: true
  systems:
    - hostname: WS-DEV-01
      ip: "10.0.1.10"
      os: "Windows 11"
      os_build: "10.0.22631.3880"
      architecture: x64
      type: workstation
      assigned_user: marcus.chen
      roles: [workstation]
      services: []
```

The optional `domain` field under `environment` is an Active Directory FQDN. When absent, domain behavior may be
inferred from the modeled topology and user email domains.

The required environment `description` is human context for the modeled organization and belongs
in the attack-free briefing; it does not generate activity.

## Personas and timezone

Top-level inline `personas` entries require `name` and `description`. Optional fields are
`typical_activities` (default `[]`), `work_hours` (default `9am-5pm`), `application_usage`
(default `[]`), `risk_profile: low|medium|high` (default medium),
`browsing_intensity: light|normal|heavy` (default normal), plus advanced `expanded_activities`,
`work_hours_parsed`, and `activity_intensity`. Prefer a configured persona name unless the exercise
needs scenario-local behavior.

The `timezone` object under `environment` supports `default` (default `UTC`) and optional
`systems`, a mapping of
first-match hostname glob patterns to valid IANA timezone names. Timezones control local scheduling
and evaluator context; emitted evidence timestamps remain UTC.

## Accounts and groups

`service_accounts` is a list of additional principal names accepted as storyline actors.
`stale_accounts` entries have exactly `username`, `last_active`, and `reason`; they are not active
users and generate background failed-authentication texture. A stale username cannot collide with
an active user or service account.

`groups` entries support `name`, optional `description`, `members` (default `[]`), and optional
`permissions`. Members must resolve to modeled users. Keep group membership consistent with each
user's `groups` list.

## Platform identity overrides

Most scenarios should omit `identity` and use deterministic defaults. The exact optional shape is:

```yaml
environment:
  identity:
    windows_default_scope: auto       # auto | domain | local
    linux_default_scope: directory    # directory | local
    windows_account_control:
      legacy.asrep: [DONT_REQUIRE_PREAUTH]
    users:
      marcus.chen:
        windows:
          scope: domain               # auto | domain | local | disabled
          account_name: mchen
          sid: S-1-5-21-100-200-300-1105
        linux:
          scope: directory            # auto | directory | local | disabled
          account_name: mchen
          uid: 2528
          gid: 2528
          home: /home/mchen
          shell: /bin/bash
```

`identity` supports only `windows_default_scope`, `linux_default_scope`,
`windows_account_control`, and `users`. A Windows override supports `scope`, `account_name`, and
`sid`; a Linux override supports `scope`, `account_name`, `uid`, `gid`, `home`, and `shell`.
UID/GID values are 0–60,000 and explicit identifiers must be unique in their platform namespace.
Only accounts explicitly carrying `DONT_REQUIRE_PREAUTH` may receive successful AS-REP behavior
without preauthentication.

## Network identities

`network_identities` is a list. Each entry supports exactly `id`, `hosts`, `ips`, `tags`, and
`dns`. `id` is required; `hosts`, `ips`, and `tags` default to `[]`; `dns` defaults to `true`.
Every entry must contain at least one host or IP. Hosts are bare hostnames without a scheme, port,
path, or whitespace; IP values must parse as IPv4 or IPv6. IDs and normalized hosts are unique.

```yaml
environment:
  network_identities:
    - id: partner_portal
      hosts: [partner.example.com]
      ips: ["203.0.113.60"]
      tags: [web, partner]
      dns: true
```

Identity references are authoritative for authored traffic. Resolution checks the scenario
identity first, then project DNS configuration, then deterministic fallback. An IP-only event
stays IP-only unless it also supplies a hostname or identity.

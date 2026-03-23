# EvidenceForge

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

## What It Does

EvidenceForge creates multi-format security log datasets from YAML scenario definitions. You describe an environment (users, systems, network topology) and a storyline (attack events), and EvidenceForge generates temporally consistent logs across all formats simultaneously — complete with cross-referenced LogonIDs, PIDs, timestamps, and UIDs.

Every attack scenario includes a `GROUND_TRUTH.md` file documenting exactly what happened, when, and where — making the datasets immediately usable for threat hunting training.

- **20+ log formats** — Windows Security (30 event IDs), Sysmon, 13 Zeek log types, eCAR, syslog, bash history, Snort, web access
- **Cross-log consistency** — Shared LogonIDs, PIDs, timestamps, and UIDs across all formats
- **OS-aware generation** — Windows systems produce Windows Event + Sysmon logs; Linux systems produce syslog + bash history
- **Network visibility modeling** — Define sensor placement (SPAN/TAP), direction, and monitored segments to control which connections appear in network logs
- **Ground truth documentation** — Every attack scenario generates a GROUND_TRUTH.md with narrative, timeline, and IOCs
- **Parallel generation** — Threaded emitters write all formats simultaneously with temporal consistency
- **Scenario validation** — Cross-reference checking, uniqueness constraints, and network topology validation
- **Data quality evaluation** — 5-dimension scoring framework (23 sub-scores) with acceptance criteria
- **Multi-timezone support** — Pattern-based timezone overrides per system hostname

## Quick Start

```bash
# Install
uv sync

# Generate logs from a scenario
uv run eforge generate tests/fixtures/scenarios/attack.yaml -o ./output

# Generate the retail store FTP attack scenario (24-hour, 20+ users, network topology)
uv run eforge generate tests/fixtures/scenarios/retail-store-ftp-attack.yaml -o ./output
```

Output is organized per-host and per-sensor:
- `<host.domain>/windows_event_security.xml` — Windows Security events (30 event IDs: logon, process, Kerberos, account management, etc.)
- `<host.domain>/windows_event_sysmon.xml` — Sysmon events (process creation with hashes, remote thread injection)
- `<sensor>/conn.json`, `dns.json`, `ssl.json`, `http.json`, ... — Zeek network logs (13 log types, NDJSON)
- `ecar.json` — eCAR EDR/XDR telemetry (NDJSON)
- `syslog.log` — Linux syslog (BSD format authentication and system logs)
- `<host.domain>/bash_history/<user>.bash_history` — Per-user bash command history
- `snort_alert.log` — Snort/Suricata IDS alerts
- `web_access.log` — Apache/Nginx combined access logs
- `GROUND_TRUTH.md` — Attack narrative, timeline, and IOCs

## Supported Log Formats

| Format | Category | Description |
|--------|----------|-------------|
| Windows Security Events | Host | 30 event IDs: authentication (4624/4625/4634/4648/4672), process (4688/4689), Kerberos (4768/4769/4770/4771/4776), persistence (4697/4698-4701), account mgmt (4720/4723/4724/4726/4738), group membership (4728/4729/4732/4733/4756/4757), firewall (5156), defense evasion (1102) |
| Windows Sysmon | Host | Process creation with hashes (Event 1), remote thread injection (Event 8) |
| Zeek (13 log types) | Network | conn, dns, http, ssl, files, x509, dhcp, ntp, weird, pe, ocsp, packet_filter, reporter |
| eCAR | Host | MITRE CAR-based EDR/XDR telemetry (PROCESS, FILE, FLOW, REGISTRY, MODULE, USER_SESSION) |
| Syslog | Host | Linux authentication and system logs (BSD format) |
| Bash History | Host | Per-user timestamped command history |
| Snort Alert | Network | IDS alert format (fast alert) |
| Web Access | Network | Apache/Nginx combined log format |

See [Evidence Formats Reference](docs/EVIDENCE_FORMATS.md) for detailed field documentation, output paths, and known limitations.

## Key Features

### OS-Aware Generation
Systems generate logs appropriate to their OS. Windows systems produce Windows Event logs; Linux systems produce syslog and bash history. eCAR provides an optional EDR/XDR layer across all platforms.

### Network Visibility Modeling
Define network segments and sensor placement to control which connections appear in network logs. Supports:
- **SPAN ports** — see all traffic including intra-segment (desktop-to-desktop)
- **Inline TAPs** — only see traffic crossing segment boundaries
- **Directional sensors** — inbound, outbound, or bidirectional monitoring
- **Format-aware emission** — different sensors produce different log formats (Zeek vs Snort)

```yaml
environment:
  network:
    segments:
      - name: workstations
        cidr: "10.10.10.0/24"
      - name: servers
        cidr: "10.10.30.0/24"
    sensors:
      - name: core-switch
        type: network
        placement: span
        monitoring_segments: [workstations, servers]
        direction: bidirectional
        log_formats: [zeek_conn]
      - name: perimeter-ids
        type: ids
        placement: tap
        monitoring_segments: [servers]
        direction: inbound
        log_formats: [snort_alert]
```

### Cross-Log Consistency
Events share consistent identifiers across all formats — a logon generates a Windows 4624 event, an eCAR USER_SESSION event, and a syslog auth entry, all with matching timestamps and correlated IDs.

### Parallel Generation
Threaded emitters write all 7 log formats simultaneously with hour-level barriers for temporal consistency and bounded queues for backpressure.

### Scenario Validation
```bash
uv run eforge validate scenario.yaml
```
Validates cross-references (users, systems, personas, storyline actors), uniqueness constraints, network topology, and schema compliance with clear error messages.

## Scenario Structure

Scenarios are YAML files describing:

```yaml
version: "1.0"
name: my-scenario
description: "Description of the scenario"

environment:
  description: "Corporate office network"
  timezone:
    default: "America/New_York"
  users: [...]
  systems: [...]
  network: [...]    # Optional: segments and sensors

personas: [...]     # User behavior patterns

time_window:
  start: "2024-01-15T08:00:00Z"
  duration: "8h"

baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: low

storyline:          # Optional: attack events
  - time: "+2h"
    actor: attacker
    system: TARGET-01
    activity: "Lateral movement via pass-the-hash"

output:
  logs: [{format: windows_event_security}, {format: zeek_conn}]
  destination: ./output
```

See [docs/scenario-reference.md](docs/scenario-reference.md) for complete schema documentation.

## Example Scenarios

| Scenario | Users | Duration | Description |
|----------|-------|----------|-------------|
| [minimal.yaml](tests/fixtures/scenarios/minimal.yaml) | 1 | 1 hour | Minimal baseline-only scenario |
| [attack.yaml](tests/fixtures/scenarios/attack.yaml) | 2 | 4 hours | Lateral movement + exfiltration |
| [retail-store-ftp-attack.yaml](tests/fixtures/scenarios/retail-store-ftp-attack.yaml) | 20+ | 24 hours | Retail store with FTP RCE attack, network topology |

## Development

```bash
# Install dependencies
uv sync

# Run tests
uv run pytest tests/ -v

# Run specific test suite
uv run pytest tests/unit/test_network_visibility.py -v
```

### Tech Stack
- Python 3.12+ with uv
- Pydantic v2 for schema validation
- Jinja2 for log format templates
- Typer + Rich for CLI
- pytest (930+ tests)

### Architecture

```
src/evidenceforge/
  cli/            # Typer CLI commands
  formats/        # YAML format definitions + Jinja2 templates
  generation/     # Engine, activity generator, emitters, state manager
  models/         # Pydantic models (scenario, config, state)
  validation/     # Cross-reference and schema validation
  utils/          # Time parsing, file I/O, config loading
```

## Documentation

- [Evidence Formats Reference](docs/EVIDENCE_FORMATS.md) — All log types, output paths, field details, and known limitations
- [Scenario Reference](docs/scenario-reference.md) — Complete YAML schema documentation
- [PRD](docs/PRD.md) — Product requirements and specifications
- [Research Report](docs/synthetic-log-generation-research.md) — Analysis of existing tools
- [AGENTS.md](AGENTS.md) — Coding conventions for AI agents

## License

[License TBD]

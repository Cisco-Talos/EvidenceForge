# EvidenceForge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/cisco-foundation-ai/EvidenceForge/actions/workflows/ci.yml/badge.svg)](https://github.com/cisco-foundation-ai/EvidenceForge/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

## What Makes EvidenceForge Different

Most synthetic log generators produce isolated, single-format data that experienced analysts identify as fake within seconds. EvidenceForge takes a fundamentally different approach:

- **Consistency by construction.** A canonical `SecurityEvent` model feeds all log formats from a single source of truth. Two emitters cannot disagree about a port number, timestamp, or LogonID because there is only one value — on the event object. This eliminates the cross-source inconsistencies that are the #1 tell of synthetic data.

- **Deterministic engine, LLM-assisted authoring.** Scenario creation uses Claude Code Skills for interactive, research-backed attack planning. Log generation is fully deterministic — no LLM calls, no API costs, reproducible output every time.

- **Network visibility modeling.** Define sensor placement (SPAN/TAP), monitored segments, and direction. EvidenceForge determines which connections each sensor can see and only emits network logs where they'd realistically appear.

- **20+ correlated log formats.** Windows Security (30 event IDs), Sysmon, 13 Zeek log types, eCAR EDR/XDR, syslog, bash history, Snort IDS, web access, and proxy logs — all from the same event pipeline.

- **Built-in quality evaluation.** A 5-dimension scoring framework (23 sub-scores) measures parsability, cross-source consistency, noise realism, temporal patterns, and signal integrity. Know exactly how good your data is before using it.

## Quick Start

```bash
# Install
git clone https://github.com/cisco-foundation-ai/EvidenceForge.git
cd EvidenceForge
uv sync

# Install Claude Code skills (recommended workflow)
uv run eforge install-skills

# Create a scenario interactively (requires Claude Code)
# /eforge scenario

# Or generate from an existing scenario
uv run eforge generate scenarios/retail-store-ftp-attack.yaml -o ./output

# Validate a scenario file
uv run eforge validate scenarios/retail-store-ftp-attack.yaml

# Evaluate generated data quality
uv run eforge eval scenarios/retail-store-ftp-attack.yaml ./output
```

## Claude Code Skills (Recommended)

EvidenceForge includes Claude Code Skills for interactive, guided workflows. These are the preferred way to use EvidenceForge.

| Skill | Description |
|-------|-------------|
| `/eforge scenario` | Guided scenario creation through a structured interview. Researches TTPs via MITRE ATT&CK, builds environment/network/personas, outputs validated YAML + student context document. |
| `/eforge generate` | Validates the scenario, runs the generation engine, monitors output, and diagnoses errors. |
| `/eforge validate` | Checks a scenario for schema correctness and cross-reference integrity. Fixes simple issues, escalates structural problems. |
| `/eforge evaluate` | Runs the data quality evaluation, interprets scores, reviews records for realism, and suggests improvements. |

Install skills with `uv run eforge install-skills` (project scope) or `uv run eforge install-skills --global`.

## CLI Reference

For scripted or non-interactive use:

| Command | Description |
|---------|-------------|
| `eforge generate <scenario.yaml> -o <dir>` | Generate logs from a scenario file |
| `eforge validate <scenario.yaml>` | Validate scenario schema and cross-references |
| `eforge eval <scenario.yaml> <output_dir>` | Evaluate data quality (5 dimensions, 23 sub-scores) |
| `eforge install-skills [--global]` | Install Claude Code skills |
| `eforge version` | Show version |

Common flags: `--verbose` / `--debug` for logging, `--output` / `-o` for output directory.

## What It Does

EvidenceForge creates multi-format security log datasets from YAML scenario definitions. You describe an environment (users, systems, network topology) and a storyline (attack events), and EvidenceForge generates temporally consistent logs across all formats simultaneously — complete with cross-referenced LogonIDs, PIDs, timestamps, and UIDs.

Every attack scenario includes a `GROUND_TRUTH.md` file documenting exactly what happened, when, and where — making the datasets immediately usable for threat hunting training.

### Key Capabilities

- **Cross-log consistency** — Shared LogonIDs, PIDs, timestamps, and Zeek UIDs across all formats
- **OS-aware generation** — Windows systems produce Windows Event + Sysmon logs; Linux systems produce syslog + bash history
- **Network visibility modeling** — Define sensor placement (SPAN/TAP), direction, and monitored segments
- **Ground truth documentation** — Every attack scenario generates a GROUND_TRUTH.md with narrative, timeline, and IOCs
- **Parallel generation** — Threaded emitters write all formats simultaneously with temporal consistency
- **Scenario validation** — Cross-reference checking, uniqueness constraints, and network topology validation
- **Data quality evaluation** — 5-dimension scoring framework (23 sub-scores) with acceptance criteria
- **Multi-timezone support** — Pattern-based timezone overrides per system hostname

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

See [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) for detailed field documentation, output paths, and known limitations.

## Scenario Structure

Scenarios are YAML files describing an environment, personas, time window, and optional attack storyline:

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
  network:             # Optional: segments and sensors
    segments: [...]
    sensors: [...]

personas: [...]        # User behavior patterns

time_window:
  start: "2024-01-15T08:00:00Z"
  duration: "8h"

baseline_activity:
  description: "Normal office activity"
  intensity: medium
  variation: low

storyline:             # Optional: attack events
  - time: "+2h"
    actor: attacker
    system: TARGET-01
    activity: "Lateral movement via pass-the-hash"
    events:
      - type: process
        process_name: "C:\\Windows\\System32\\cmd.exe"
        command_line: "cmd.exe /c whoami"

output:
  logs: [{format: windows_event_security}, {format: zeek}]
  destination: ./output
```

See [Scenario Reference](docs/reference/scenario-reference.md) for complete schema documentation.

## Example Scenarios

| Scenario | Users | Duration | Description |
|----------|-------|----------|-------------|
| [minimal.yaml](tests/fixtures/scenarios/minimal.yaml) | 1 | 1 hour | Minimal baseline-only scenario |
| [attack.yaml](tests/fixtures/scenarios/attack.yaml) | 2 | 4 hours | Lateral movement + exfiltration |
| [retail-store-ftp-attack.yaml](tests/fixtures/scenarios/retail-store-ftp-attack.yaml) | 20+ | 24 hours | Retail store with FTP RCE attack, full network topology |

## Data Quality Evaluation

EvidenceForge includes a built-in evaluation framework that scores generated data across 5 dimensions:

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| Record Fidelity | 15% | Parsability, field co-occurrence, population statistics |
| Cross-Source Consistency | 20% | Source correctness, trace coverage, cross-format agreement |
| Noise Realism | 25% | Volume adequacy, diversity, plausibility, anomaly absence |
| Temporal Realism | 20% | Work-hour distribution, burstiness, causal ordering, timing |
| Signal Integrity | 20% | Event presence, indicator accuracy, pivot linkability |

**Acceptance criteria** (hard pass/fail): Parsability >= 98%, Source Correctness >= 95%, Causal Ordering >= 99%, Event Presence >= 90%.

```bash
uv run eforge eval scenario.yaml ./output
```

## Architecture

```
Scenario YAML
    |
    v
Validation (Pydantic schema + cross-reference checks)
    |
    v
GenerationEngine (hour-by-hour orchestration)
    |
    v
ActivityGenerator (builds SecurityEvents with composable contexts)
    |
    v
EventDispatcher (routes to StateManager + matching emitters)
    |
    +---> WindowsEventEmitter ---> Security.evtx (XML)
    +---> SysmonEmitter ---------> Sysmon.evtx (XML)
    +---> ZeekEmitter(s) --------> conn/dns/http/ssl/... (NDJSON)
    +---> EcarEmitter -----------> ecar.json (NDJSON)
    +---> SyslogEmitter ---------> syslog.log
    +---> BashHistoryEmitter ----> per-user bash history
    +---> SnortEmitter ----------> snort_alert.log
    +---> WebEmitter ------------> web_access.log
```

See [Architecture Documentation](docs/ARCHITECTURE.md) for the full deep dive including the SecurityEvent model, state management, and emitter system.

## Development

```bash
# Install dependencies
uv sync

# Run tests (950+ tests)
uv run pytest tests/ -v

# Run specific test suite
uv run pytest tests/unit/test_network_visibility.py -v

# Lint and format
uv run ruff check src/ tests/
uv run ruff format src/ tests/
```

### Tech Stack

- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- Pydantic v2 for schema validation
- Jinja2 for log format templates
- Typer + Rich for CLI
- pytest (950+ tests)

## Documentation

- [Scenario Reference](docs/reference/scenario-reference.md) — Complete YAML schema documentation
- [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) — All log types, field details, known limitations
- [Architecture](docs/ARCHITECTURE.md) — How the generation engine works
- [Contributing](CONTRIBUTING.md) — How to contribute to EvidenceForge
- [AGENTS.md](AGENTS.md) — Coding conventions for AI agents

### Design Documents

- [PRD](docs/design/PRD.md) — Product requirements and specifications
- [Event Model Design](docs/design/event-model-prd.md) — Canonical SecurityEvent architecture
- [Data Quality Design](docs/design/data-quality-prd.md) — Evaluation framework design
- [Research Report](docs/design/synthetic-log-generation-research.md) — Analysis of existing tools

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, sending pull requests, and setting up a development environment.

## License

[MIT License](LICENSE) - Copyright (c) 2025 Cisco Systems, Inc.

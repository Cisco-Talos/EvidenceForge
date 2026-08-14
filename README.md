# EvidenceForge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Cisco-Talos/EvidenceForge/actions/workflows/ci.yml/badge.svg)](https://github.com/Cisco-Talos/EvidenceForge/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

For background on the project and why we built it, read our announcement:
[Introducing EvidenceForge: synthetic security logs that don't look (as) fake](https://blog.talosintelligence.com/introducing-evidenceforge-synthetic-security-logs-that-dont-look-as-fake).

## What Makes EvidenceForge Different

Most synthetic log generators produce isolated, single-format data that experienced analysts identify as fake within seconds. EvidenceForge takes a fundamentally different approach:

- **Consistency by construction.** Canonical events and immutable plans own shared connection,
  identity, lifecycle, and protocol facts for migrated action families; emitters perform only
  source-native projection. Dispatch rejects unknown or incomplete canonical occurrences. Some
  mutable compatibility views remain during the approved migration, and the explicit `raw` path
  is outside cross-source consistency guarantees.

- **Causal event ordering.** Events respect real-world dependencies — DNS queries precede connections, Kerberos TGT/TGS precede domain logons, audit events follow administrative commands. A composable rule engine auto-generates prerequisites with realistic timing offsets, so the data tells a coherent causal story across log sources.

- **Self-exciting temporal dynamics.** User activity follows a Hawkes process — events trigger bursts that taper off naturally, matching real human work patterns. System traffic uses periodic intervals with jitter. Day-of-week variation models Monday login storms, Friday early departures, and near-zero weekends. Most generators use uniform random timing that experienced analysts spot instantly.

- **20+ correlated log formats.** Windows Security (30 event IDs), Sysmon, 13 Zeek log types, eCAR EDR/XDR, syslog, bash history, Snort IDS, web access, and proxy logs — all from the same event pipeline.

- **Network visibility modeling.** Define sensor placement (SPAN/TAP), monitored segments, and direction. EvidenceForge determines which connections each sensor can see and only emits network logs where they'd realistically appear.

- **Deterministic engine, skill-assisted authoring.** Scenario creation uses AI agent skills for interactive, research-backed attack planning. Log generation is fully deterministic — no LLM calls, no API costs, reproducible output every time.

- **Built-in quality evaluation.** A 4-pillar scoring framework (22 sub-scores) measures
  parseability, plausibility, causality, and timing, with additional concern-oriented views for
  source schema, canonical invariants, scenario completeness, and distribution realism.

## Quick Start

```bash
# Install
git clone https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge
uv sync

# Install project-local skills for all supported agents
uv run eforge install-skills

# Or select one agent or install user-wide
uv run eforge install-skills --agent chatgpt
uv run eforge install-skills --global

# Create a scenario interactively
# /eforge scenario

# Or generate from an existing scenario
uv run eforge generate scenarios/branch-office-example/scenario.yaml -o ./output

# Validate a scenario file
uv run eforge validate scenarios/branch-office-example/scenario.yaml

# Evaluate a new authoritative bundle (legacy bundles still need --scenario)
uv run eforge eval ./output
```

## Agent Skills (Recommended)

EvidenceForge includes agent skills for interactive, guided workflows. These are the preferred way to use EvidenceForge.

| Skill | Description |
|-------|-------------|
| `/eforge scenario` | Guided scenario creation through a structured interview. Researches TTPs via MITRE ATT&CK, builds environment/network/personas, outputs validated YAML + student context document. |
| `/eforge pack` | Discovers, compares, inspects, validates, initializes, and copies industry or organization packs. |
| `/eforge industry-pack` | Authors reusable industry catalogs with exact references, qualified exports, validation, and composition smoke tests. |
| `/eforge organization-pack` | Authors concrete organization environments and baselines with pinned industry dependencies, validation, and composition smoke tests. |
| `/eforge generate` | Validates the scenario, runs the generation engine, monitors output, and diagnoses errors. |
| `/eforge validate` | Checks a scenario for schema correctness and cross-reference integrity. Fixes simple issues, escalates structural problems. |
| `/eforge evaluate` | Runs the data quality evaluation, interprets scores, reviews records for realism, and suggests improvements. |
| `/eforge config` | Add, modify, or remove personas, domains, applications, and other configuration data. Handles cross-file dependencies automatically. See [Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md). |

The table shows Claude Code command names. In ChatGPT and Codex, use the corresponding
`eforge-scenario`, `eforge-pack`, `eforge-industry-pack`, `eforge-organization-pack`,
`eforge-generate`, `eforge-validate`, `eforge-evaluate`, and `eforge-config` skills.

`uv run eforge install-skills` installs project-local skills for both Claude Code
and ChatGPT. Claude commands go under `.claude/commands/`; ChatGPT skills go
under `.agents/skills/`. Add `--global` to install both user-wide under
`~/.claude/commands/` and `~/.agents/skills/`, or select one with `--agent
claude` or `--agent chatgpt`. The legacy name `--agent codex` remains an alias
for `--agent chatgpt` and uses the same destinations.

## CLI Reference

For scripted or non-interactive use:

| Command | Description |
|---------|-------------|
| `eforge generate <scenario.yaml> -o <dir> [--seed N]` | Forecast machine resources, then generate logs; `--seed` overrides the scenario seed |
| `eforge validate <scenario.yaml>` | Validate schema and cross-references, and always print a machine-aware memory and disk forecast |
| `eforge resolve <scenario.yaml> -o <resolved.yaml> [--explain-composition]` | Compile an authoritative, self-contained scenario without generating logs |
| `eforge pack list\|show\|validate\|init\|copy` | Discover, inspect, validate, or create project-local industry/organization packs |
| `eforge eval <output_dir> [-s <scenario.yaml>] [--allow-large-evaluation]` | Evaluate quality; new bundles use their adjacent resolved scenario, while legacy bundles require `--scenario` |
| `eforge info [field]` | Show installation info, config paths, and data inventories. Pass a dot-path field for a specific value (e.g., `eforge info personas`). Use `--fields` to list available fields, `--json` for machine output. |
| `eforge validate-config` | Validate config files for cross-reference integrity. Use `--json` for machine output. |
| `eforge install-skills [--agent all\|claude\|chatgpt\|codex] [--global]` | Install project-local or user-wide agent skills; defaults to all agents (`codex` aliases `chatgpt`) |
| `eforge version` | Show version |

Useful command flags: `generate` accepts `--verbose` / `--debug` for logging,
`--output` / `-o` for output directory overrides, `--force` / `-f` to overwrite
existing output without prompting, and `--target default|sof-elk|splunk` to choose the
generated file layout. The `default` target is SIEM-neutral; `sof-elk` emits
target-specific variants such as Snare Windows events and year-partitioned
RFC3164 syslog for parser validation, and `splunk` emits Splunk-friendly
Windows XML event streams. `eval` uses `--scenario` / `-s` and
`--format text|json`; `info` and `validate-config` support `--json` for machine
output.

All commands accept `--help` and `-h` for usage information.

## Customizing Configuration

EvidenceForge ships with 50+ YAML config files controlling DNS domains, applications, personas, traffic profiles, and more. You can customize these using a project-local overlay at `.eforge/config/` — your changes survive package upgrades and merge automatically with built-in defaults.

The recommended approach is the agent skill (`/eforge config` in Claude Code or `eforge-config` in
ChatGPT/Codex):

```
/eforge config add a nurse persona for a healthcare scenario
```

For details on the overlay system, manual editing, and cross-file dependencies, see **[Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md)**.

## Scenario 2.0 packs

Scenario 2.0 optionally composes exact, whole industry or organization packs from installed data,
project-local `.eforge/packs`, or an explicit path. Packs have the same six predictable catalogs,
including required empty catalogs; organization packs can also contribute a concrete environment
and baseline. Existing Scenario 1.0 files and monolithic Scenario 2.0 files require no packs and do
not scan for or warn about them.

EvidenceForge ships `finance`, `healthcare`, and `technology` industry examples plus the fictional
`northstar-health` organization example. Start with the `/eforge pack` (Claude Code) or
`eforge-pack` (ChatGPT/Codex) skill, or run `eforge pack list --json`. See
[Scenario 2.0 and composable packs](docs/reference/SCENARIO_PACKS.md) for the composition and
lifecycle guide and the [Pack Authoring Reference](commands/eforge/references/pack-reference.md)
for exact catalog fields, cadence, validation, and consumer-harness workflows.

## What It Does

EvidenceForge creates multi-format security log datasets from YAML scenario definitions. You describe an environment (users, systems, network topology) and a storyline (attack events), and EvidenceForge generates temporally consistent logs across all formats simultaneously — complete with cross-referenced LogonIDs, PIDs, timestamps, and UIDs.

Every generated scenario includes a `GROUND_TRUTH.md` file. Attack scenarios document exactly what happened, when, and where, while baseline-only scenarios explicitly document that no malicious events were generated.

### Key Capabilities

- **Cross-log consistency** — Shared LogonIDs, PIDs, timestamps, and Zeek UIDs across all formats
- **Causal expansion engine** — Auto-generates prerequisite events (DNS, Kerberos, audit events) with composable rules
- **Realistic baseline noise** — 26 lateral movement patterns, process→network correlation, network-level red herrings, and 18 Linux syslog categories create noise that analysts must work through
- **OS-aware generation** — Windows systems produce Windows Event + Sysmon logs; Linux systems produce syslog + bash history
- **Network visibility modeling** — Define sensor placement (SPAN/TAP), direction, and monitored segments
- **Ground truth documentation** — Every run generates a GROUND_TRUTH.md; attack scenarios include narrative, timeline, and IOCs
- **Parallel generation** — Threaded emitters write all formats simultaneously with temporal consistency
- **Scenario validation** — Cross-reference checking, uniqueness constraints, and network topology validation
- **Data quality evaluation** — 4-pillar scoring framework (22 sub-scores), concern-oriented
  diagnostic categories, non-vacuous applicability, and acceptance criteria
- **Multi-timezone support** — Pattern-based timezone overrides per system hostname

## Supported Log Formats

| Format | Category | Description |
|--------|----------|-------------|
| Windows Security Events | Host | 30 event IDs: authentication (4624/4625/4634/4648/4672), process (4688/4689), Kerberos (4768/4769/4770/4771/4776), persistence (4697/4698-4701), account mgmt (4720/4723/4724/4726/4738), group membership (4728/4729/4732/4733/4756/4757), firewall (5156), defense evasion (1102) |
| Windows Sysmon | Host | Process create (Event 1), terminate (Event 5), remote thread injection (Event 8), process access (Event 10) |
| Zeek (13 log types) | Network | conn, dns, http, ssl, files, x509, dhcp, ntp, weird, pe, ocsp, packet_filter, reporter |
| eCAR | Host | EDR/XDR telemetry in MITRE CAR-based format (PROCESS, FILE, FLOW, REGISTRY, MODULE, THREAD, USER_SESSION, SERVICE) |
| Syslog | Host | Linux authentication and system logs (BSD format) |
| Bash History | Host | Per-user timestamped command history |
| Snort Alert | Network | IDS alert format (fast alert) |
| Web Access | Network | Apache/Nginx combined log format |
| HTTP Proxy | Host | Forward proxy access log (W3C Extended format, CONNECT entries, cache status, proxy action hints) |

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
| [branch-office-example](scenarios/branch-office-example/scenario.yaml) | 5 | 6 hours | Beginner branch office scenario with Windows, Zeek, eCAR, syslog, bash history, Snort, ASA, web, and proxy logs |
| [minimal.yaml](tests/fixtures/scenarios/minimal.yaml) | 1 | 1 hour | Minimal baseline-only scenario |
| [attack.yaml](tests/fixtures/scenarios/attack.yaml) | 2 | 4 hours | Lateral movement + exfiltration |
| [retail-store-ftp-attack.yaml](tests/fixtures/scenarios/retail-store-ftp-attack.yaml) | 20+ | 24 hours | Retail store with FTP RCE attack, full network topology |

## Data Quality Evaluation

EvidenceForge includes a built-in evaluation framework that scores generated data across 4 pillars:

| Pillar | Weight | What it measures |
|--------|--------|-----------------|
| Parseability | 30% | Spec conformance, format constraints |
| Plausibility | 25% | Value/OS correctness, co-occurrence, distributions, user diversity, anomaly rate |
| Causality | 25% | Causal ordering, event presence, indicator accuracy, pivot linkability |
| Timing | 20% | Attack-chain timing, burstiness, diurnal patterns, volume adequacy |

**Two-tier acceptance**: applicable hard gates must pass, while aspirational targets remain
informational. Gates cover source conformance, value and field consistency, exact IDS integrity,
causal/scenario reconciliation, and linkability. The authoritative thresholds are configurable in
`src/evidenceforge/config/evaluation/thresholds.yaml`.

The compatibility pillars remain the weighted public score. The report also groups the same
applicable measures by review concern: source/schema fidelity, canonical cross-source invariants,
declared-scenario completeness, and distribution realism. Required measures with no applicable
denominator are reported as unavailable instead of receiving a vacuous perfect score.

By default, evaluation accepts at most 512 MiB of input, 10,000 files, and 500,000 parsed records.
Use `--allow-large-evaluation` only for a trusted corpus after reviewing available memory. The
override does not relax file or parser safety checks.

```bash
uv run eforge eval ./output -s scenario.yaml
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
WorldModel / WorldPlanner (compile host roles, user placement, session bootstrap)
    |
    v
ActivityGenerator (builds canonical occurrences with composable contexts)
    |
    v
EventDispatcher (routes to StateManager + matching emitters)
    |
    +---> WindowsEventEmitter ---> default XML / sof-elk Snare / splunk XML stream
    +---> SysmonEmitter ---------> default XML / sof-elk Snare / splunk XML stream
    +---> ZeekEmitter(s) --------> sensor/conn,dns,http,ssl,... (NDJSON)
    +---> EcarEmitter -----------> ecar.json (NDJSON)
    +---> SyslogEmitter ---------> default+splunk RFC5424 / sof-elk RFC3164 year layout
    +---> BashHistoryEmitter ----> per-user bash history
    +---> SnortEmitter ----------> snort_alert.log
    +---> CiscoAsaEmitter -------> default+splunk flat / sof-elk year layout
    +---> WebEmitter ------------> web_access.log
    +---> ProxyEmitter ----------> proxy_access.log
```

Generation records the selected output target in `OUTPUT_TARGET.txt` and
emitters apply it only where file shape differs.

`WorldModel` compiles authoritative host and user capabilities from scenario fields like `primary_system`, `roles`, `services`, and workstation assignments. `WorldPlanner` then chooses realistic interactive, network, SSH, and RDP session paths before `ActivityGenerator` emits the correlated evidence.

See [Architecture Documentation](docs/ARCHITECTURE.md) for the full deep dive including the world-model layer, CanonicalOccurrence model, state management, and emitter system.

## Development

```bash
# Install dependencies and development tools
uv sync --all-extras

# Run tests without coverage instrumentation (skips slow by default)
uv run pytest --no-cov

# Run slow comprehensive workload tests without coverage instrumentation
uv run pytest --include-slow -m slow --no-cov --durations=20

# Run optional third-party parser validation tests.
# Requires Docker Compose v2 or Podman Compose.
uv run pytest --include-external-parsers -m external_parser --no-cov

# Run the release coverage gate before a dev -> main PR
uv run pytest --cov=evidenceforge --cov-report=term-missing --cov-report=xml --cov-fail-under=70

# Do not combine slow tests with coverage during release validation.
# Slow tests are run with --no-cov; coverage is measured on the default non-slow suite.

# Run specific test suite
uv run pytest tests/unit/test_network_visibility.py -v

# Lint and format
uv run ruff check .
uv run ruff format --check .
```

See [External Parser Validation](docs/external-parser-validation/README.md)
for the third-party parser validation quickstart, external-parser harness architecture,
full-dataset runner command, and failure report details.

### Tech Stack

- Python 3.11+ with [uv](https://docs.astral.sh/uv/)
- Pydantic v2 for schema validation
- Jinja2 for log format templates
- Typer + Rich for CLI
- pytest (3700+ tests)

## Documentation

- [Scenario Reference](docs/reference/scenario-reference.md) — Complete YAML schema documentation
- [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) — All log types, field details, known limitations
- [Architecture](docs/ARCHITECTURE.md) — How the generation engine works
- [Contributing](CONTRIBUTING.md) — How to contribute to EvidenceForge
- [AGENTS.md](AGENTS.md) — Coding conventions for AI agents

### Design Documents

- [PRD](docs/design/PRD.md) — Product requirements and specifications
- [Event Model Design](docs/design/event-model-prd.md) — Canonical occurrence architecture
- [Data Quality Design](docs/design/data-quality-prd.md) — Evaluation framework design
- [Research Report](docs/design/synthetic-log-generation-research.md) — Analysis of existing tools

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, sending pull requests, and setting up a development environment.

## Acknowledgements

SOF-ELK® is a registered trademark of Lewes Technology Consulting, LLC. Used with permission.

## License

[MIT License](LICENSE) - Copyright (c) 2026 Cisco Systems, Inc.

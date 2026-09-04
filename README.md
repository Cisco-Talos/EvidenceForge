# EvidenceForge

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logos/evidenceforge-fullcolor-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/logos/evidenceforge-fullcolor-light.png">
    <img alt="EvidenceForge logo" src="docs/logos/evidenceforge-fullcolor-light.png" width="400">
  </picture>
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/Cisco-Talos/EvidenceForge/actions/workflows/ci.yml/badge.svg)](https://github.com/Cisco-Talos/EvidenceForge/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

For background on the project and why we built it, read our announcement:
[Introducing EvidenceForge: synthetic security logs that don't look (as) fake](https://blog.talosintelligence.com/introducing-evidenceforge-synthetic-security-logs-that-dont-look-as-fake).

## What It Does

EvidenceForge creates multi-format security log datasets from YAML scenario definitions. You
describe an environment—users, systems, network topology, and normal activity—and an optional
attack storyline. EvidenceForge then generates temporally consistent evidence across all selected
formats, complete with cross-referenced identities, sessions, processes, timestamps, and network
connections.

Every generated bundle includes human-readable `GROUND_TRUTH.md` and machine-readable
`GROUND_TRUTH.json` answer keys. Attack scenarios document what happened, when, and where, while
baseline-only scenarios explicitly state that no malicious events were generated.

### Key Capabilities

- **Guided scenario authoring** — Agent skills turn exercise ideas into validated scenario
  definitions, environment briefings, reusable packs, and configuration changes.
- **Multi-source evidence generation** — Produce Windows, Linux, EDR, network, IDS, firewall, web,
  proxy, and email evidence from one scenario.
- **Baseline and storyline modeling** — Combine ordinary user and system activity, benign red
  herrings, and typed attack events in the same dataset.
- **Repeatable generation at scale** — Deterministic seeds, resource forecasts, progress reporting,
  and resumable checkpoints support complex simulations and huge datasets.
- **Validation and quality measurement** — Catch schema, cross-reference, topology, and capacity
  problems before generation, then evaluate the resulting evidence across four quality pillars.
- **Reusable environment modeling** — Split scenarios with YAML includes, compose versioned
  industry or organization packs, and apply project-local configuration overlays.

## What Makes EvidenceForge Different

Most synthetic log generators create independent rows or replay isolated templates. EvidenceForge
models activities first, then renders the evidence those activities would leave across different
systems and sensors.

- **Correlated evidence, not independent rows.** A logon, process, file operation, or connection
  retains the same identities and relationships everywhere it is observed, enabling realistic
  pivots between endpoint, identity, network, and application sources.
- **Causal activity, not keyword matching.** DNS lookups precede connections, Kerberos tickets
  precede domain logons, and lifecycle endings follow their beginnings. Required supporting
  evidence is generated automatically instead of being hand-authored as disconnected events.
- **Behavioral and temporal realism.** Bursty user activity, periodic system traffic with jitter,
  day-of-week variation, role-aware services, and benign anomalies create the texture analysts
  expect from real environments.
- **Observation-aware output.** Sensor placement, network direction, collection profiles, source
  clocks, and coherent visibility gaps determine what each source can actually observe.
- **Source-native evidence.** Each output uses the identities, fields, ordering, and lifecycle
  conventions of the source it represents rather than projecting one generic event schema into
  every format.
- **Creative authoring, deterministic rendering.** Agent skills help research and design scenarios,
  while the generation engine makes no LLM calls. The same scenario, seed, formats, and version
  reproduce the same dataset without API costs or model variability.

## What's New in 2.0

- **More realistic correlated evidence:** SSH, RDP, SMB, Windows authentication, Sysmon, Zeek,
  Snort, eCAR, and Linux system logs now agree more closely on identities, timing, processes,
  network sessions, and lifecycle boundaries. Investigations encounter fewer cross-source
  contradictions and more source-native behavior.

- **Cross-platform SMB2/3 activity:** Generate realistic file-share activity across Windows and
  Linux clients and Windows or Samba servers. Authentication, file operations, network traffic,
  endpoint telemetry, and Samba audit events remain correlated across the resulting log sources.

- **Resumable long-running generation:** EvidenceForge creates automatic recovery checkpoints
  during generation, so large or multi-week runs can be safely interrupted and resumed without
  starting over. New status and suspension commands make these runs easier to inspect and control.

- **Easier scenario authoring:** Focused `eforge schema` commands provide exact field definitions
  and working minimal examples for individual scenario objects and event types. Validation errors
  are grouped around the object that needs attention and point directly to the relevant schema
  contract.

- **Modular, reusable scenarios:** Split large scenarios into nested YAML includes, then compose
  them with versioned industry and organization packs containing reusable environments, personas,
  applications, and activity models. Packs can be validated, shared as portable `.efpack`
  archives, and reproduced with their exact dependencies.

[See the complete changelog](CHANGELOG.md) for detailed release history.

## Supported Log Formats

| Format | Description |
|--------|-------------|
| Windows Security Events | 30 event IDs covering authentication, process activity, Kerberos, persistence, account and group management, permitted connections, and log clearing |
| Windows Sysmon | Events 1, 3, 5, 7, 8, 10, 11, 12, 13, and 22 for process, network, module, injection, file, registry, and DNS activity |
| Zeek (16 log types) | conn, dhcp, dns, files, http, ntp, ocsp, packet_filter, pe, reporter, smb_files, smb_mapping, smtp, ssl, weird, and x509 |
| eCAR | Simulated EDR/XDR telemetry for processes, files, flows, registry, modules, threads, user sessions, and services |
| Linux syslog | Authentication, session, service, package, scheduler, maintenance, firewall, Samba, and other role-aware system activity |
| Bash history | Per-user timestamped command history |
| Snort/Suricata alerts | Fast-format IDS alerts with sensor-aware filtering and correlation to network evidence |
| Cisco ASA | Connection, teardown, deny, NAT, and threat-detection syslog from modeled firewall control points |
| Web access | Apache/Nginx combined text or Splunk-compatible JSON, depending on the output target |
| HTTP proxy | Extended Apache/Nginx combined text, SOF-ELK®-compatible combined text, or Splunk-compatible JSON, depending on the output target |

The default target uses SIEM-neutral output. `--target sof-elk` produces layouts and source-native
variants suitable for SOF-ELK, including Snare Windows events and year-partitioned RFC3164
syslog. `--target splunk` produces Splunk-friendly Windows event streams and JSON variants for web
and proxy access logs. Formats whose representation does not need to change remain identical
across targets.

See the [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) for field-level details and
the [Output Target Ingest Guides](docs/output-targets/README.md) for target-specific ingestion and
parser support.

## Quick Start

```bash
# Install EvidenceForge from the source checkout
git clone https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge
uv sync

# Install skills. You can choose either project- or user-level skills, or both

# Install the project-local skills for Claude Code and ChatGPT/Codex
# (for the current directory/project only)
uv run eforge install-skills

# Install the user-level skills for Claude Code and ChatGPT/Codex
# (for all user projects)
uv run eforge install-skills --global
```

In Claude Code, create a new exercise or try the bundled branch-office scenario:

```text
/eforge scenario
/eforge generate scenarios/branch-office-example/scenario.yaml to ./output
/eforge evaluate ./output
```

In ChatGPT or Codex, use the corresponding `eforge-scenario`, `eforge-generate`, and
`eforge-evaluate` skills.

Checkpoint-enabled runs can be inspected, stopped safely after the current simulated hour, and
resumed from another terminal:

```bash
uv run eforge checkpoint status ./output
uv run eforge checkpoint suspend ./output
uv run eforge generate --output ./output --resume
```

## Agent Skills (Recommended)

EvidenceForge provides skills for the creative and interactive parts of the workflow. They guide
scenario and pack authoring, invoke the deterministic CLI when appropriate, interpret results,
and help repair problems without adding LLM calls to generation itself.

| Workflow | Claude Code | ChatGPT/Codex | Purpose |
|----------|-------------|---------------|---------|
| Scenario authoring | `/eforge scenario` | `eforge-scenario` | Create or revise a validated exercise and its environment briefing |
| Scenario validation | `/eforge validate` | `eforge-validate` | Explain validation failures and repair authored scenarios when requested |
| Log generation | `/eforge generate` | `eforge-generate` | Generate, monitor, verify, and troubleshoot an existing scenario |
| Quality evaluation | `/eforge evaluate` | `eforge-evaluate` | Score generated evidence, interpret results, and review realism |
| Pack discovery and lifecycle | `/eforge pack` | `eforge-pack` | Find, inspect, validate, initialize, and copy reusable packs |
| Industry-pack authoring | `/eforge industry-pack` | `eforge-industry-pack` | Create reusable sector-specific personas, applications, traffic, and storage vocabulary |
| Organization-pack authoring | `/eforge organization-pack` | `eforge-organization-pack` | Create reusable users, systems, topology, services, and baseline activity |
| Pack releases | `/eforge pack-release` | `eforge-pack-release` | Build, inspect, import, hydrate, and verify portable `.efpack` releases |
| Configuration | `/eforge config` | `eforge-config` | Inspect or tailor project-local personas, applications, traffic, and other generator data |

By default, `uv run eforge install-skills` installs both integrations for the current project under
`.claude/commands/eforge/` and `.agents/skills/eforge-*`. Use `--global` for user-wide installation,
or select one integration with `--agent claude` or `--agent chatgpt`; `--agent codex` remains an
alias for `--agent chatgpt`.

## CLI Reference

For scripted or non-interactive use:

| Command | Description |
|---------|-------------|
| `eforge generate <scenario.yaml> -o <dir> [--seed N]` | Forecast resources, then generate logs with 24-hour checkpoints; `--seed` overrides the scenario seed |
| `eforge checkpoint status <bundle-root> [--verbose\|--json]` | Thoroughly inspect recovery health, compatibility, cursor, and managed storage without resuming |
| `eforge checkpoint suspend <bundle-root>` | Ask an active checkpoint-enabled generator to stop safely after its current simulated hour |
| `eforge validate <scenario.yaml>` | Validate schema and cross-references, and always print a machine-aware memory and disk forecast |
| `eforge resolve <scenario.yaml> -o <resolved.yaml> [--explain-composition]` | Compile an authoritative, self-contained scenario without generating logs |
| `eforge pack <command>` | Discover, author, lock, validate, package, inspect, import, or hydrate industry and organization packs |
| `eforge eval <output_dir> [-s <scenario.yaml>] [--allow-large-evaluation]` | Evaluate quality; new bundles use their adjacent resolved scenario, while legacy bundles require `--scenario` |
| `eforge info [field]` | Show installation info, config paths, and data inventories. Pass a dot-path field for a specific value (e.g., `eforge info personas`). Use `--fields` to list available fields, `--json` for machine output. |
| `eforge schema <selector> [--json]` | Show one focused installed-version authored-scenario contract, such as `environment.network_identities` or `event.email_read`. |
| `eforge validate-config` | Validate config files for cross-reference integrity. Use `--json` for machine output. |
| `eforge install-skills [--agent all\|claude\|chatgpt\|codex] [--global]` | Install project-local or user-wide agent skills; defaults to all agents (`codex` aliases `chatgpt`) |
| `eforge version` | Show version |

Useful `generate` flags include `--verbose` / `--debug`, `--formats` / `-F`,
`--target default|sof-elk|splunk`, `--resume`, `--overwrite`, and `--checkpoint-hours N`. The
default checkpoint cadence is 24 simulated hours; `0` disables new checkpoints. `validate` accepts
the same checkpoint-cadence option so its resource forecast reflects the intended run.

See [Generation Checkpoints and Resume](docs/reference/GENERATION_CHECKPOINTS.md) for recovery and
filesystem-safety details, and the [Output Target Ingest Guides](docs/output-targets/README.md) for
target-specific layouts and parser support.

All commands accept `--help` and `-h` for usage information.

## Customizing Configuration

EvidenceForge uses a large data-driven configuration catalog for DNS, applications, personas,
traffic profiles, source behavior, timing, and more. Customize it through a project-local overlay
at `.eforge/config/`; project changes remain separate from the installed defaults and survive
package upgrades.

The recommended approach is the agent skill (`/eforge config` in Claude Code or `eforge-config` in
ChatGPT/Codex):

```text
/eforge config add a nurse persona for a healthcare scenario
```

For the overlay workflow, manual editing, and cross-file dependencies, see
[Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md).

## Reusable Industry and Organization Packs

Scenarios can compose exact-version industry or organization packs while still supporting
monolithic authoring. Industry packs provide reusable sector-specific behavior and vocabulary;
organization packs can provide a concrete environment and baseline activity. The skills are the
recommended way to discover, select, author, and release packs.

Bundled industry packs:

- `finance` v1.0.0
- `healthcare` v1.0.0
- `technology` v1.0.0

Bundled fictional organization packs:

- `metrolink-specialty-care` v1.0.0
- `northstar-health` v1.0.0 and v1.1.0; v1.1.0 adds cross-platform SMB storage

Use `/eforge pack` or `eforge-pack` to inspect the available inventory. For the underlying
composition and lifecycle contract, see
[Reusable scenario packs](docs/reference/SCENARIO_PACKS.md).

## Data Quality Evaluation

EvidenceForge can evaluate a generated bundle across four complementary quality pillars:

| Pillar | Weight | What it measures |
|--------|--------|-----------------|
| Parseability | 30% | Source conformance and format constraints |
| Plausibility | 25% | Values, cross-source agreement, distributions, diversity, and anomaly rates |
| Causality | 25% | Event presence, ordering, authored-intent reconciliation, and investigative pivots |
| Timing | 20% | Attack-chain timing, burstiness, regularity, diurnal patterns, and event rates |

Applicable hard gates must pass; aspirational targets show where quality can improve without
turning every shortfall into a failure. Measures that do not apply to a dataset are reported as
unavailable rather than receiving an automatic perfect score.

```bash
uv run eforge eval ./output
```

## Development

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

See [Contributing](CONTRIBUTING.md) for the complete development workflow, extended test tiers,
coverage gate, coding conventions, and external-parser validation requirements.

## Documentation

- [Scenario Reference](docs/reference/scenario-reference.md) — Scenario fields, includes, typed
  events, and validation rules
- [Evidence Formats Reference](docs/reference/EVIDENCE_FORMATS.md) — Output layout, log types,
  field details, and known limitations
- [Reusable Scenario Packs](docs/reference/SCENARIO_PACKS.md) — Industry and organization pack
  composition and lifecycle
- [Customizing Configuration](docs/reference/CUSTOMIZING_CONFIG.md) — Project-local configuration
  overlays and data catalogs
- [Generation Checkpoints and Resume](docs/reference/GENERATION_CHECKPOINTS.md) — Safe suspension,
  recovery, status, storage, and filesystem behavior
- [Output Target Ingest Guides](docs/output-targets/README.md) — Default, SOF-ELK, and Splunk
  layouts, parsing, and ingestion
- [Adversarial Payload Testing](docs/reference/adversarial_payload.md) — Safe synthetic payload and
  callback-testing workflow
- [Credential Spillage Modeling](docs/reference/spillage.md) — Synthetic credential leakage and
  evidence-surface behavior
- [Configuration Compatibility](docs/reference/config-compatibility.md) — Legacy configuration
  normalization and compatibility rules
- [External Parser Validation](docs/external-parser-validation/README.md) — SOF-ELK and Splunk
  validation harnesses
- [Architecture](docs/ARCHITECTURE.md) — Generation architecture and ownership contracts
- [Changelog](CHANGELOG.md) — Release history
- [Contributing](CONTRIBUTING.md), [Security](SECURITY.md), and
  [Code of Conduct](CODE_OF_CONDUCT.md) — Project contribution and security policies
- [Agent Development Conventions](AGENTS.md) — Repository conventions for coding agents

## Contributing

Before opening a pull request, please open an issue describing the problem or proposed change and
wait for the approach to be discussed with the maintainers. This helps avoid work on changes that
do not fit the project direction; pull requests submitted without prior agreement may be closed.
Once an approach is agreed, follow [CONTRIBUTING.md](CONTRIBUTING.md) for development, testing, and
submission requirements.

## Acknowledgements

SOF-ELK® is a registered trademark of Lewes Technology Consulting, LLC. Used with permission.

## License

[MIT License](LICENSE) - Copyright (c) 2026 Cisco Systems, Inc.

# EvidenceForge

Generate realistic synthetic security logs for cybersecurity threat hunting training and research.

## Overview

EvidenceForge is a system for creating realistic synthetic security logs using a unique two-phase architecture:

**Phase 1 - Scenario Creation:** Conversational CLI interface accepts natural language descriptions of environments and activities. An LLM researches TTPs, expands descriptions into detailed execution plans, and outputs structured scenario files.

**Phase 2 - Log Generation:** Deterministic generation engine executes the scenario plan without LLM calls, producing large-scale, temporally consistent datasets across multiple log formats with coordinated cross-references.

### Key Features (MVP)

- **Natural language scenario creation** - Describe what you want, the LLM handles the details
- **Multiple log formats** - Windows Event Logs, Zeek, Snort/Suricata, Linux syslogs, W3C web logs
- **Cross-log consistency** - Events reference matching LogonIDs, PIDs, timestamps, etc.
- **Realistic baseline activity** - Pre-built persona library for normal user behavior
- **Flexible attack scenarios** - Support multiple threat actors (APT29, SCATTERED SPIDER, insider threats)
- **Scalable generation** - Handle datasets from classroom exercises to multi-day simulations (millions of events)
- **Reproducible scenarios** - Save scenario files for reuse and variation

### Why EvidenceForge?

Existing synthetic log tools focus on single formats or require deep technical expertise. EvidenceForge bridges the gap:

- **No production data risks** - Generate training data without privacy/security concerns
- **Ground truth included** - Know exactly what's malicious for training threat hunters
- **Flexible specification** - From high-level ("50-person financial company") to explicit (exact users, IPs, timelines)
- **Research-backed** - LLM researches MITRE ATT&CK TTPs for realistic attack patterns

## Status

🚧 **In Development** - Currently in requirements and planning phase. See [docs/PRD.md](docs/PRD.md) for complete specifications.

## Project Structure

```
├── AGENTS.md                           # AI coding agent instructions
├── docs/
│   ├── PRD.md                          # Product Requirements Document
│   └── synthetic-log-generation-research.md  # Research on existing tools
└── README.md                           # This file
```

## Planned Architecture

**Tech Stack:**
- Python 3.11+ with uv for package management
- Pydantic v2 for data validation
- AWS Bedrock for LLM integration (Claude Sonnet 4.6)
- Typer for CLI, Rich for progress reporting
- pytest for testing (95%+ coverage target)

**CLI Commands:**
```bash
# Initialize configuration
forge init

# Create scenario interactively
forge new

# Validate scenario
forge validate scenario.yaml

# Generate logs
forge generate scenario.yaml

# Evaluate output quality
forge evaluate output/
```

## Development Phases

**Phase 1: Core Generation** (2-3 weeks)
- Basic scenario schema and generation
- 2-3 log formats (Windows Event, Zeek, syslog)
- Manual state tracking, small datasets

**Phase 2: Scalability** (2-3 weeks)
- Parallel generation across formats
- All 5 MVP log formats
- Medium to large datasets (100K+ events)

**Phase 3: Robustness - MVP Release** (3-4 weeks)
- Checkpointing and resume capability
- Comprehensive error handling
- 95%+ test coverage
- Complete documentation and examples

**Total MVP Timeline:** 7-10 weeks

## Documentation

- **[PRD](docs/PRD.md)** - Complete product requirements and technical specifications
- **[Research Report](docs/synthetic-log-generation-research.md)** - Analysis of 40+ existing log generation tools
- **[AGENTS.md](AGENTS.md)** - Coding conventions and architecture patterns for AI agents

## Contributing

This project uses AI coding agents for development. See [AGENTS.md](AGENTS.md) for:
- Code style and standards
- Architecture patterns
- Testing requirements
- Implementation workflow

## License

[License TBD]

## Contact

[Contact info TBD]

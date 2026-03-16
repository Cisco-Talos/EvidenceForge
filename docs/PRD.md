# PRD: EvidenceForge

> **Naming conventions:** "EvidenceForge" is the product name, `evidenceforge` is the Python package name, `eforge` is the CLI command name.

## 1. Overview

EvidenceForge is a system for generating realistic synthetic security logs for cybersecurity threat hunting training and research. The system uses a two-phase architecture:

**Phase 1 - Scenario Creation (Skill-assisted):** Claude Code skills (`/eforge scenario`) guide users through an interactive interview to build structured scenario YAML files. The skill uses a hybrid interview flow -- structured questions first for core requirements, then free-form conversation to fill gaps and refine details. Users can also hand-author or edit scenario YAML directly.

**Phase 2 - Log Generation (Deterministic):** The `eforge generate` CLI command executes the scenario plan without any LLM calls, producing large-scale, temporally consistent datasets across multiple log formats (Windows Event Logs, Zeek, ECAR, Syslog, Bash History, Snort, web logs) with coordinated cross-references (matching LogonIDs, PIDs, session data, connection IDs, etc.).

This architecture combines the flexibility and domain expertise of LLM-assisted authoring with the speed, cost-efficiency, and reproducibility of deterministic generation.

Unlike existing tools that focus solely on attack simulation or use purely programmatic generation, this system:
- Generates coordinated multi-source logs (not single format)
- Supports both baseline "normal" activity and injected attack scenarios
- Maintains realistic temporal patterns and behavioral variation via persona-based activity distribution
- Provides ground truth about malicious activities for threat hunting exercises
- Models network topology and sensor placement for realistic traffic visibility

The tool addresses the need for realistic, large-volume training datasets without the privacy/security concerns of production data.

## 2. Goals & Non-Goals

### Goals (MVP)
- Generate realistic synthetic logs for 7 formats: Windows Event Security, Zeek conn, ECAR, Syslog, Bash History, Snort alerts, W3C web access
- Claude Code skills for scenario creation (`/eforge scenario`) and generation troubleshooting (`/eforge generate`)
- Skill installer command (`eforge install-skills`) for project-level or global installation
- Pre-built persona library for common organizational roles
- Maintain cross-log consistency (events reference same LogonIDs, PIDs, timestamps, connection IDs)
- Support arbitrary time windows from hours to weeks
- Handle datasets from small (classroom exercises) to large (multi-day, 500+ users)
- Parallel generation at emitter level (different log formats simultaneously) with incremental writing
- Progress reporting during generation with per-hour and per-storyline-event tracking
- Schema validation for scenario files (Pydantic-based)
- Cross-reference validation (users, systems, personas, groups referenced correctly)
- Evaluation framework with concrete metrics (format compliance, consistency, statistical properties)
- Ground truth documentation (GROUND_TRUTH.md) for scenarios with malicious activity
- Network topology and sensor placement modeling for traffic visibility
- Persona-based temporal activity distribution with configurable work hours, intensity, and risk profiles
- Comprehensive test coverage (95%+) with pytest
- Flexible timezone handling (UTC internal, configurable per-system/format for output)

### Non-Goals (Future Enhancements)
- Bit-perfect reproducibility via seed (save scenario file for reuse instead)
- Subjective "does this feel real?" evaluation beyond concrete metrics
- Config file inheritance/templating
- Built-in LLM client for semantic validation (deferred; use Claude Code skills for now)
- Checkpointing and resume for long-running generation jobs
- Support for LLM backends beyond Claude Code skills (Bedrock client, OpenAI, Ollama)
- PyPI package distribution (MVP is git clone + local install)
- Pre-built binaries or container images
- Streaming output to SIEM/data lakes
- OT/ICS environment simulation
- Mobile device logs
- Cloud provider logs (CloudTrail, Azure Activity, GCP Audit)
- Time-slice or user-level parallelization (MVP parallelizes at emitter level only)
- Large dataset optimization (100M+ events, memory-mapped writes)

## 3. Target Users

**Primary Users:**
- **Security Researchers**: Need realistic datasets for developing detection algorithms and threat hunting techniques
- **Threat Hunters**: Require practice datasets with known ground truth for training and skill development
- **Security Educators**: Must create reproducible scenarios for classroom exercises and labs
- **SOC Trainers**: Need varied, realistic datasets for analyst training programs
- **Detection Engineers**: Require test data for validating detection rules and SIEM configurations

**User Context:**
- All users are expected to have Claude Code installed (skills are the primary scenario authoring interface)
- Mix of technical proficiency (from educators who may not code to researchers who do)
- Need for both quick scenario generation via skills and detailed customization via YAML editing
- Often simulating specific real-world environments or generic representative environments
- May need same scenario run multiple times with variations
- Can use `/eforge scenario` skill for guided creation or hand-author YAML for precise control

## 4. Functional Requirements

### 4.1 Core Workflows

#### Workflow 1: Initialize New Project
```bash
eforge init [--force]
```
1. System copies `config.example.yaml` to `config.yaml` in the current directory
2. Includes documented parameters for output paths and logging
3. User can customize for their environment

#### Workflow 2: Scenario Creation via Skill
```
/eforge scenario
```
1. Claude Code skill starts a hybrid interview flow
2. **Structured phase** -- asks targeted questions about:
   - Environment (size, type of organization, systems, users)
   - Network topology and sensor placement
   - Baseline activity patterns (reference pre-built personas or define custom)
   - Specific attack scenarios or activities to inject
   - Time windows and output requirements
3. **Free-form phase** -- identifies gaps in the scenario and asks open-ended questions:
   - Refine persona behaviors
   - Add detail to attack storylines
   - Clarify network visibility requirements
4. User can specify at any level of detail:
   - High-level: "50-person financial services company" (skill fills in details)
   - Mixed: 10 specific users, generate 40 more with personas
   - Detailed: Exact usernames, hostnames, IPs, file paths, timezones
5. Skill generates complete scenario YAML file conforming to the schema in Section 4.2
6. Saves to disk for review/editing/reuse
7. No LLM calls needed during generation phase

#### Workflow 3: Install Skills
```bash
eforge install-skills [--project | --global]
```
1. Copies skill files from the repo's `commands/eforge/` directory
2. `--project` (default): Installs to `.claude/commands/` in the current project
3. `--global`: Installs to `~/.claude/commands/`
4. Reports which skills were installed and their slash-command triggers

#### Workflow 4: Validate Scenario
```bash
eforge validate SCENARIO_FILE
```
1. Schema validation: Check YAML structure, data types, required fields via Pydantic models
2. Cross-reference validation: Verify internal consistency
   - Referenced users exist in environment
   - Referenced systems exist in environment
   - Referenced personas are defined
   - Group members reference valid users
   - Storyline actors reference valid users
   - Time sequences are within the defined window
3. Report all validation issues with field paths, descriptions, and suggestions
4. Return exit code 0 on success, exit code 2 on schema failure

#### Workflow 5: Generate Logs
```bash
eforge generate SCENARIO_FILE [--output DIR] [--verbose] [--debug]
```
1. Load and validate scenario file (schema + cross-reference validation)
2. Load format definitions for requested log types
3. Initialize generation state (users, systems, sessions, processes, connections)
4. Start parallel emitters (one per log format, shared read-only state access)
5. Generate baseline activity:
   - Execute persona-based activity patterns for all users
   - Apply realistic temporal distributions throughout time window
   - StateManager tracks all sessions, processes, connections
6. Layer storyline activities on top of baseline:
   - Execute detailed event sequences at specified times
   - Suppress baseline for affected users during storyline (+/-5 min window)
7. Each emitter writes coordinated logs with consistent cross-references
8. Convert timestamps from UTC to system/format-specific timezones as configured
9. Write to organized directory structure with incremental flushing (10K event buffer)
10. Show progress with Rich progress bars (per-hour baseline, per-event storyline)
11. Log details to `generation.log` in output directory
12. Generate GROUND_TRUTH.md when malicious/suspicious activities are present

#### Workflow 6: Evaluate Output
```bash
eforge evaluate OUTPUT_DIR [--report REPORT_FILE] [--verbose]
```
1. Load generated logs
2. Run validation checks:
   - Format compliance (syntactically valid against format definitions)
   - Consistency (cross-references resolve correctly)
   - Statistical properties (distributions, timing patterns)
   - Completeness (no orphaned references)
3. If GROUND_TRUTH.md exists, validate that all documented IOCs are present in logs
4. Generate report with scores and specific findings
5. Optional: Save report for comparison across runs

### 4.2 Data Model

#### Scenario File Schema

Primary file: `scenario-name.yaml`

```yaml
version: string              # Schema version, e.g., "1.0"
                             # If schema version is not "1.0", reject with error:
                             # "Unsupported schema version. This tool supports version 1.0."
name: string                 # Human-readable scenario name
description: string          # Multi-line natural language description

environment:
  description: string        # Natural language environment description

  timezone:
    default: string          # Default timezone for all systems (e.g., "UTC", "America/New_York")
    systems:                 # Per-system overrides (optional)
      pattern: string        # e.g., "WS-NYC-*": "America/New_York"

  # Note: The /eforge scenario skill handles auto-generating users/systems from
  # high-level descriptions (e.g., "50-person financial services company").
  # The final scenario YAML only contains explicit users and systems lists.

  users:
    - username: string
      full_name: string
      email: string
      persona: string        # Optional: Reference to persona definition; if omitted, user generates no activity
      primary_system: string # Optional: Reference to system hostname
      groups: list[string]   # List of group names
      enabled: boolean       # If false, user exists in environment but generates no activity

  systems:
    - hostname: string
      ip: string             # Single IP address (multi-NIC out of scope for MVP)
      os: string
      type: string           # workstation|server|domain_controller
      assigned_user: string  # Optional, for workstations
      services: list[string] # Optional: Service names like "IIS", "SSH", "SQL Server" (not ports)
                             # If omitted, auto-populated from OS type:
                             #   Windows: ["dns-client", "ntp-client", "smb", "windows-update"]
                             #   Linux: ["dns-client", "ntp-client", "syslog"]
                             # Server roles auto-detected from hostname hints (e.g., "dc-*" → add "active-directory")
                             # Explicit values override auto-population entirely (no merge)

  groups:
    - name: string
      description: string
      members: list[string]  # Usernames
      permissions: list[string]

  network:
    segments:
      - name: string           # Segment identifier (e.g., "workstations", "servers", "dmz")
        cidr: string           # CIDR notation (e.g., "10.0.10.0/24")
        description: string    # Human-readable description
        systems: list[string]  # Optional: Hostnames in this segment (inferred from system IPs if omitted)

    sensors:
      - type: string           # network|ids|firewall (determines which log formats this sensor generates)
        name: string           # Sensor identifier
        monitoring_segments: list[string]  # Segment names this sensor monitors
        direction: string      # inbound|outbound|bidirectional (what traffic is visible)
        log_formats: list[string]  # Which formats this sensor generates (e.g., ["zeek_conn", "snort_alert"])
        description: string    # Optional description

    # Note: Network topology defines which connections are observable by sensors.
    # Only traffic visible to configured sensors generates network log entries.

personas:
  - name: string
    description: string      # Natural language behavior description
    typical_activities: list[string]  # High-level activities
    work_hours: string       # e.g., "8am-6pm with variation"
    application_usage: list[string]
    risk_profile: string     # low|medium|high (affects activity intensity/variation)

    expanded_activities:     # Detailed activity patterns with frequencies
      - activity: string     # Concrete activity
        frequency: float     # Events per hour
        processes: list[string]
        network_targets: list[string]
        file_patterns: list[string]

time_window:
  start: datetime            # ISO 8601 format in UTC (YYYY-MM-DDTHH:MM:SSZ or +00:00)
  end: datetime              # Either end (ISO 8601 UTC)...
  # OR
  duration: string           # ...or duration (exact time span: "10h", "3d", "2h30m")
  # Exactly one of end or duration must be specified

baseline_activity:
  description: string        # Natural language description
  intensity: string          # low|medium|high -> events/user/hour: low=5, medium=15, high=40
  variation: string          # low|medium|high -> timing stddev: low=+/-10%, medium=+/-25%, high=+/-50%
  # Note: Persona risk_profile modifies intensity (low=-5, high=+10 events/hour)

storyline:
  - time: string             # Time formats:
                             #   - ISO 8601 timestamp (must be within window)
                             #   - Relative offset: "+2h30m" or "+2h" or "+150m"
                             #   - Offset in seconds: "+7200"
    actor: string            # Actor specification:
                             #   - Specific username: "bwilliams"
                             #   - Threat actor: "APT29", "SCATTERED SPIDER", "Red Team Alpha"
                             #   - Generic: "attacker"
                             #   - Note: Multiple distinct actors supported in same scenario
    system: string           # Target system hostname
    activity: string         # Natural language activity description
    details: dict            # Flexible activity-specific details:
      # Common examples (not exhaustive):
      source_ip: string      # For external attackers (e.g., details.source_ip)
      url: string            # For web activities
      file: string           # For file operations
      binary: string         # For process execution
      command: string        # For command execution
      target_system: string  # For lateral movement
      stolen_creds: string   # For credential usage

    event_sequence: list     # Detailed event sequence with specific log artifacts
      - event_type: string
        log_sources: list[string]  # Which log formats show this event
        fields: dict         # Specific field values for each log source

output:
  logs:
    - format: string         # windows_event_security|zeek_conn|ecar|syslog|bash_history|snort_alert|web_access
      variant: string        # Optional: Security|System|conn|http|auth|access
      timezone: string       # "system" (use system's timezone) or explicit "UTC"/"America/New_York"
      options: dict          # Format-specific options

  destination: string        # Output directory path
  compression: boolean       # Compress output files (gzip)
  # Format-specific options (output format, headers, etc.) are future enhancements.
```

#### Format Definition Schema

**Format Definitions** (`src/evidenceforge/formats/definitions/{format_name}.yaml`)
```yaml
format:
  name: string
  description: string
  category: string           # windows|linux|network|web|application

common_fields:
  - name: string
    type: string             # See Type System below
    required: boolean
    range: list[integer]     # For numeric types (min, max)
    enum: list[any]          # Allowed values (mutually exclusive with range)
    pattern: string          # Regex pattern for validation
    default: any

# Type System for Format Definitions:
# - datetime: ISO 8601 timestamp, rendered per format (epoch, ISO, custom)
# - integer: 64-bit signed integer
# - float: IEEE 754 double-precision floating point
# - string: UTF-8 string
# - ip_address: IPv4 or IPv6 address
# - ipv4: IPv4 address specifically
# - ipv6: IPv6 address specifically
# - hex_string: Hexadecimal string (e.g., "0xC000006D")
# - boolean: true/false
# - port: Integer 1-65535
# - mac_address: MAC address (colon or hyphen separated)
# - hostname: DNS hostname (RFC 1123)
# - fqdn: Fully qualified domain name
# - email: Email address
# - url: URL (http/https)
# - uuid: UUID v4
# - base64: Base64-encoded string

# Format-Specific Precision Requirements:
# - Zeek timestamps: Epoch float with exactly 6 decimal places (microsecond precision)
#   Format: f"{timestamp:.6f}" to preserve trailing zeros during JSON serialization
# - Windows Event timestamps: ISO 8601 with millisecond precision (YYYY-MM-DDTHH:MM:SS.sssZ)
# - Syslog timestamps: RFC 3339 format with timezone offset

variants:                    # For formats with subtypes (channels, log types)
  - name: string
    description: string
    fields: list[field]      # Same structure as common_fields
    validators:
      - rule: object         # JSON Logic expression (see http://jsonlogic.com)
        error: string        # Error message if validation fails

output_template: string      # Jinja2 template for rendering final log format
                             # Available context: all field values as variables, timestamp(), hex(), escape()

# Validator examples using JSON Logic:
# Success status can't have failure reason:
# {"and": [{"==": [{"var": "Status"}, "0x0"]}, {"!=": [{"var": "FailureReason"}, null]}]}
#
# Network logon requires IP address:
# {"and": [{"in": [{"var": "LogonType"}, [3, 10]]}, {"==": [{"var": "IpAddress"}, "-"]}]}
```

#### Internal State Model (Runtime)

The generator maintains these state structures during execution:

```python
@dataclass
class ActiveSession:
    logon_id: str
    username: str
    system: str
    logon_type: int
    start_time: datetime
    source_ip: str

@dataclass
class RunningProcess:
    pid: int
    parent_pid: int
    image: str
    command_line: str
    username: str
    system: str
    start_time: datetime
    integrity_level: str

@dataclass
class OpenConnection:
    conn_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    state: str
    start_time: datetime
    bytes_sent: int
    bytes_received: int

@dataclass
class GeneratorState:
    active_sessions: dict[str, ActiveSession]
    running_processes: dict[int, RunningProcess]
    open_connections: dict[str, OpenConnection]
    dns_cache: dict[str, str]
    current_time: datetime
    user_states: dict[str, UserState]  # Current activity per user
```

#### Output Files

**Directory Structure**

Generated logs are written to a timestamped output directory:
```
output/
  scenario-name-YYYYMMDD-HHMMSS/
    generation.log              # Detailed generation log
    GROUND_TRUTH.md            # Attack ground truth (if malicious activity present)
    windows_events.xml         # Windows Event Logs
    zeek_conn.log              # Zeek connection logs
    ecar.json                  # ECAR events
    syslog.log                 # Linux syslogs
    bash_history.log           # Bash history entries
    snort_alerts.log           # Snort/Suricata alerts
    web_access.log             # Web/proxy logs
```

**GROUND_TRUTH.md Format**

When a scenario includes malicious or suspicious activities (not baseline-only scenarios), the generator creates a GROUND_TRUTH.md file documenting the attack for training and evaluation purposes.

```markdown
# Ground Truth: [Scenario Name]

Generated: YYYY-MM-DD HH:MM:SS UTC
Time Window: [start] to [end]

## Attack Summary

[Narrative description of the malicious/suspicious activities. Excludes benign baseline
activity. Describes the attack from initial access through objectives, including
techniques used, systems compromised, data accessed, etc.]

## Timeline

Chronological sequence of key malicious events. Each entry includes:
- Timestamp (ISO 8601 format)
- Optional record ID (EventRecordID, UID, line number) if applicable
- Human-readable description with relevant context

Format:
YYYY-MM-DDTHH:MM:SS.ssssssZ [RecordID: 12345] - Description with IOCs

Example:
2024-01-15T10:23:45.123456Z [EventRecordID: 12345] - Initial access: Threat actor logged in to WIN-TEST-01 as CORP\jdoe from source IP 203.0.113.50
2024-01-15T10:24:12.789012Z - C2 communication: Outbound connection from 192.168.1.100 to C2 server 198.51.100.45:443
2024-01-15T10:25:03.456789Z [EventRecordID: 12389] - Credential dumping: Process mimikatz.exe (PID 4532) executed by CORP\jdoe

## Indicators of Compromise (IOCs)

Atomic indicators that can be searched for in the logs to identify malicious activity.
Grouped by type for easy reference.

### Network Indicators
- Attacker IP addresses: 203.0.113.50, 198.51.100.45
- C2 domains: evil-c2.example.com, malware-download.net
- C2 IP:Port combinations: 198.51.100.45:443, 198.51.100.45:8080

### User Accounts
- Compromised accounts: CORP\jdoe, CORP\admin-backup
- Created accounts: CORP\backdoor-admin

### Host Indicators
- Compromised systems: WIN-TEST-01, WIN-TEST-05, DC-01
- Malicious processes: mimikatz.exe, nc.exe, evil-payload.exe
- Process IDs: 4532 (mimikatz.exe), 5123 (nc.exe)
- File paths: C:\Temp\mimikatz.exe, C:\Users\jdoe\Downloads\payload.exe
- Command lines: "mimikatz.exe privilege::debug sekurlsa::logonpasswords"

### Other Indicators
- [Additional categories as relevant: registry keys, scheduled tasks, services, etc.]
```

**Purpose:**
- Provides ground truth for threat hunting training exercises
- Enables validation that detection rules capture the malicious activity
- Documents the attack narrative for educational purposes
- Lists atomic IOCs for direct searching in SIEM/analysis tools

**Generation:**
- Created automatically during log generation when storyline contains malicious activities
- Not generated for baseline-only scenarios (no malicious activity)
- IOCs extracted from actual generated events (guaranteed to be present in logs)
- Timeline includes only key events (not every single malicious log entry)

### 4.3 CLI Interface

**Command: init**
```
eforge init [--force]

Options:
  --force    Overwrite existing config.yaml if it exists

Creates config.yaml from config.example.yaml in the current directory.
Non-interactive: Simply copies the example config with all options documented.
```

**Command: install-skills**
```
eforge install-skills [--project | --global]

Options:
  --project    Install skills to .claude/commands/ in the current project (default)
  --global     Install skills to ~/.claude/commands/

Copies EvidenceForge skill files to the appropriate Claude Code skills location.
Skill files are bundled as package data and loaded via importlib.resources at runtime.

Skills installed:
  /eforge scenario  - Guided scenario creation
  /eforge generate  - Generation with troubleshooting
```

**Command: validate**
```
eforge validate SCENARIO_FILE

Arguments:
  SCENARIO_FILE    Path to scenario YAML file

Validates scenario file for schema correctness and cross-reference integrity.
Exit codes: 0 = success, 1 = YAML parse error, 2 = schema/cross-reference error.

Checks performed:
  - YAML parsing and Pydantic schema validation
  - All referenced users exist in environment.users
  - All referenced systems exist in environment.systems
  - All referenced personas are defined in personas section
  - Group members reference valid users
  - Storyline actors reference valid users or external actors
  - Storyline times fall within the defined time window
  - Network segment and sensor references are valid
```

**Command: generate**
```
eforge generate SCENARIO_FILE [--output DIR] [--verbose] [--debug]

Arguments:
  SCENARIO_FILE    Path to scenario YAML file

Options:
  --output, -o     Override output directory from scenario file
  --verbose, -v    Enable INFO level logging
  --debug, -d      Enable DEBUG level logging

Generates logs according to scenario specification.
No LLM calls during generation (purely deterministic).
Shows progress bars and writes detailed logs to output directory.
Performs schema + cross-reference validation before generation starts.
```

**Command: evaluate**
```
eforge evaluate OUTPUT_DIR [--report REPORT_FILE] [--verbose]

Arguments:
  OUTPUT_DIR       Path to generated log directory

Options:
  --report         Path to write evaluation report (default: OUTPUT_DIR/evaluation.json)
  --verbose        Include detailed findings in report

Evaluates generated logs for concrete metrics:
  - Format compliance: Events parse successfully against format definitions
  - Consistency: Cross-references resolve (LogonIDs, PIDs, connection IDs)
  - Statistical properties: Event type distributions, timing patterns
  - Completeness: No orphaned references
  - Ground truth validation: If GROUND_TRUTH.md exists, verify all documented IOCs are present

Report is informational only (no pass/fail thresholds for MVP).
Outputs JSON report with scores and specific findings.
```

**Evaluation Report Schema (minimal)**

The evaluation report is a JSON file with the following top-level structure. The exact sub-structure of each section will be refined during implementation.

```json
{
  "format_compliance": { "...": "per-format parse/validation results" },
  "cross_ref_consistency": { "...": "orphaned references, mismatched IDs" },
  "ground_truth": { "...": "IOC presence verification (if GROUND_TRUTH.md exists)" },
  "summary": { "total_checks": 0, "passed": 0, "failed": 0, "warnings": 0 }
}
```

**Command: version**
```
eforge version

Shows version information.
```

### 4.4 Skills Architecture

EvidenceForge uses Claude Code skills as the primary scenario authoring interface. Skills are Markdown files that provide Claude Code with domain-specific instructions, enabling it to guide users through complex scenario creation without requiring a built-in LLM client.

#### Skill Files

Skills live in `commands/eforge/` in the repository and are installed via `eforge install-skills`.

**`/eforge scenario`** -- Guided scenario creation skill

Responsibilities:
- Interview users about their scenario requirements using a hybrid flow
- Structured phase: targeted questions about environment, users, systems, network, personas, storyline, time window, output formats
- Free-form phase: identify gaps, refine details, ask follow-up questions
- Reference the pre-built persona library and suggest appropriate personas
- Generate valid scenario YAML conforming to the schema
- Validate the generated YAML against known constraints before saving
- Save the file and suggest next steps (`eforge validate`, `eforge generate`)

**`/eforge generate`** -- Generation with troubleshooting skill

Responsibilities:
- Run `eforge generate` on a scenario file
- If generation fails, analyze the error output
- Suggest fixes for common issues (schema errors, missing references, invalid time windows)
- Optionally edit the scenario file to fix issues and retry
- Report summary of generated output on success

#### Skill Design Principles

1. **Hybrid interview flow**: Start with structured questions to gather core requirements quickly, then switch to free-form conversation for gap-filling and refinement
2. **Progressive disclosure**: Ask simple questions first, offer advanced options only when relevant
3. **Persona-aware**: Reference the pre-built persona library to reduce authoring effort
4. **Schema-aware**: Skills know the exact scenario YAML schema and generate conforming output
5. **Idempotent suggestions**: Skills suggest CLI commands the user can verify and run

#### Installation Model

```
# Install to current project (default)
eforge install-skills --project
# Creates .claude/commands/eforge-scenario.md
# Creates .claude/commands/eforge-generate.md

# Install globally for all projects
eforge install-skills --global
# Creates ~/.claude/commands/eforge-scenario.md
# Creates ~/.claude/commands/eforge-generate.md
```

Skills are plain Markdown files and can be version-controlled, customized, or extended by users.

## 5. Non-Functional Requirements

### Performance
- **Small datasets** (1 hour, 50 users, ~10K events): < 15 seconds generation time
- **Medium datasets** (8 hours, 100 users, ~100K events): < 30 seconds generation time (current benchmark: ~14 seconds)
- **Large datasets** (8 hours, 500 users, ~1M events): < 30 minutes generation time
- Memory usage: < 2GB regardless of output size (soft target, not enforced)
  - Streaming writes with 10K event buffer per emitter
  - State grows with active sessions/processes but typically < 100MB for large scenarios
  - No automatic state pruning (realistic incompleteness is acceptable)
- Parallel generation at emitter level: Different log formats write simultaneously
  - Shared StateManager with thread-safe read access
  - Each emitter runs in separate thread

### Scalability
- Support up to 1000 users and 2000 systems in a single environment
- Handle time windows up to 30 days
- Generate up to 100M events in a single run

### Reliability
- **Input validation**: Schema + cross-reference validation before generation starts (fail fast)
- **Atomic writes**: Use temp files + rename for log files
- **Resource exhaustion**: Check disk space before starting (require 2x estimated output size), fail if insufficient

### Security
- Never log AWS credentials or other secrets
- Support AWS credential chain (no credentials in config files)
- Environment variable interpolation for sensitive values
- .env file support with search from current directory up to home
- Format definition validation: Constrained DSL only, no arbitrary code execution from untrusted format files

### Usability
- Progress reporting with Rich progress bars for long-running jobs
- Clear, actionable error messages with field paths and suggestions
- Examples and templates included
- Comprehensive documentation
- Skills provide guided authoring for users who prefer not to write YAML manually

### Maintainability
- 95%+ test coverage across all components
- Type hints throughout codebase
- Pydantic models for all data structures
- Clear separation of concerns (skill-assisted authoring / validation / generation / evaluation)
- Format definitions as data, not code

## 6. Technical Architecture

### 6.1 Tech Stack

**Core:**
- Python 3.11+ (for latest type hint features)
- uv for package management and script/tool support
- Pydantic v2 for data validation and schema management

**CLI & Output:**
- Typer for CLI framework
- Rich for progress bars and console formatting
- Jinja2 for log format templates
- PyYAML for configuration parsing
- pytz for timezone handling

**Skills:**
- Claude Code skills (Markdown files in `commands/eforge/`)
- Installed via `eforge install-skills` command
- No runtime dependency on Claude Code for generation (skills are authoring-time only)

**Testing:**
- pytest for test framework
- pytest-cov for coverage reporting
- pytest-mock for mocking
- pytest-benchmark for performance tests
- Separate markers for @pytest.mark.live (requires API) and @pytest.mark.slow (large datasets)

**Format Support:**
- Standard library json/csv for text formats
- Custom parsers/writers for Zeek, Syslog, ECAR, Bash History, etc.
- json-logic-qubit for format definition validation rules

### 6.2 Project Structure

```
evidenceforge/
+-- README.md
+-- AGENTS.md                    # AI coding agent instructions
+-- LICENSE
+-- pyproject.toml               # uv project config (entry point: eforge)
+-- config.example.yaml          # Example configuration
+-- .env.example                 # Example environment variables
|
+-- commands/                      # Claude Code skills (source, installed via eforge install-skills)
|   +-- eforge/
|       +-- scenario.md          # /eforge scenario skill
|       +-- generate.md          # /eforge generate skill
|
+-- personas/                    # Pre-built persona library
|   +-- developer.yaml
|   +-- accountant.yaml
|   +-- executive.yaml
|   +-- help_desk.yaml
|   +-- security_analyst.yaml
|   +-- ...                      # 10-15 common personas
|
+-- src/
|   +-- evidenceforge/
|       +-- __init__.py
|       +-- __main__.py          # CLI entry point
|       +-- py.typed             # PEP 561 marker
|       |
|       +-- cli/
|       |   +-- __init__.py
|       |   +-- commands.py      # CLI command implementations (init, generate, validate, evaluate, install-skills, version)
|       |
|       +-- models/
|       |   +-- __init__.py
|       |   +-- config.py        # Pydantic models for config
|       |   +-- scenario.py      # Pydantic models for scenario
|       |   +-- exceptions.py    # Custom exception types
|       |   +-- state.py         # Runtime state models
|       |
|       +-- validation/
|       |   +-- __init__.py
|       |   +-- schema.py        # Schema + cross-reference validation
|       |
|       +-- generation/
|       |   +-- __init__.py
|       |   +-- engine.py        # Main generation orchestrator
|       |   +-- state_manager.py # State tracking (sessions, processes, connections)
|       |   +-- activity.py      # Persona-based activity generation with temporal distribution
|       |   +-- ground_truth.py  # GROUND_TRUTH.md generation
|       |   +-- network_visibility.py  # TAP/SPAN sensor modeling
|       |   +-- emitters/
|       |       +-- __init__.py
|       |       +-- base.py      # Base emitter interface
|       |       +-- windows.py   # Windows Event Security emitter
|       |       +-- zeek.py      # Zeek conn.log emitter
|       |       +-- ecar.py      # ECAR event emitter
|       |       +-- syslog.py    # Syslog emitter
|       |       +-- bash_history.py  # Bash history emitter
|       |       +-- snort.py     # Snort alert emitter
|       |       +-- web.py       # Web access log emitter
|       |
|       +-- formats/
|       |   +-- __init__.py
|       |   +-- format_def.py    # Pydantic models for format definitions
|       |   +-- loader.py        # Format definition loader
|       |   +-- validator.py     # Format constraint validator (JSON Logic DSL)
|       |   +-- definitions/
|       |       +-- windows_event_security.yaml
|       |       +-- zeek_conn.yaml
|       |       +-- ecar.yaml
|       |       +-- syslog.yaml
|       |       +-- bash_history.yaml
|       |       +-- snort_alert.yaml
|       |       +-- web_access.yaml
|       |
|       +-- llm/                 # Created when LLM integration is needed (future)
|       |   +-- __init__.py
|       |
|       +-- evaluation/
|       |   +-- __init__.py
|       |   +-- evaluator.py     # Main evaluation logic
|       |   +-- metrics.py       # Concrete metrics (format, consistency, stats)
|       |   +-- report.py        # Report generation
|       |
|       +-- utils/
|           +-- __init__.py
|           +-- config.py        # Config loading with env var interpolation
|           +-- files.py         # File I/O utilities
|           +-- ids.py           # ID generation utilities
|           +-- logging.py       # Logging setup
|           +-- time.py          # Time/duration parsing utilities
|
+-- tests/
|   +-- __init__.py
|   +-- conftest.py              # Shared fixtures
|   +-- unit/                    # Fast unit tests (526+ tests)
|   |   +-- test_models.py
|   |   +-- test_validation.py
|   |   +-- test_state_manager.py
|   |   +-- test_engine.py
|   |   +-- test_emitters.py
|   |   +-- test_activity.py
|   |   +-- test_persona_activity.py
|   |   +-- test_network_visibility.py
|   |   +-- test_ground_truth.py
|   |   +-- test_format_def.py
|   |   +-- test_format_loader.py
|   |   +-- test_format_validator.py
|   |   +-- test_time_parsing.py
|   |   +-- test_timezone_handling.py
|   |   +-- test_cli.py
|   |   +-- test_utils.py
|   |   +-- ...
|   +-- integration/             # Multi-component tests
|   |   +-- test_format_definitions.py
|   |   +-- test_parallel_generation.py
|   |   +-- test_scenario_timezone.py
|   |   +-- test_medium_dataset.py
|   |   +-- ...
|   +-- live/                    # Tests requiring external APIs
|   +-- fixtures/                # Test fixture data
|
+-- docs/
|   +-- PRD.md                   # This document
|   +-- ...
|
+-- examples/
    +-- simple-baseline/         # Simple baseline activity scenario
    +-- ransomware-attack/       # Ransomware scenario
    +-- credential-stuffing/     # Credential attack scenario
    +-- insider-threat/          # Insider threat scenario
```

### 6.3 Configuration & Secrets

**Configuration Hierarchy** (later overrides earlier):
1. Default values in code
2. System-wide config (if exists): `~/.config/evidence-forge/config.yaml`
3. .env file (if exists): Search from current working directory upward to home directory, stop at first found (don't merge multiple)
4. Project config: `./config.yaml`
5. Command-line arguments

**Secrets Handling:**
- **AWS credentials**: Use standard boto3 credential chain (never in config files)
  1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
  2. AWS credentials file (~/.aws/credentials) using specified profile
  3. IAM role (if running on EC2/ECS)
  4. AWS SSO
- **Other secrets**: Support environment variable interpolation in config: `${VAR_NAME}`
- **.env file search**: Walk from CWD upward, max search depth is home directory
- **Security**: Never log secrets or include in error messages, stack traces, or debug output

## 7. Error Handling & Edge Cases

### Input Validation Errors

**Exit Code Table:**

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Input Error | Malformed YAML or file I/O error |
| 2 | Schema Validation | Pydantic validation or cross-reference failure |
| 20 | Resource Exhaustion | Insufficient disk space or memory |
| 21 | Generation Error | Invalid state or unrecoverable generation failure |
| 22 | Format Error | Format definition loading or validation error |
| 130 | SIGINT | User interrupted (Ctrl+C) |

**Malformed YAML:**
- Detect during parsing
- Show line number and syntax error
- Suggest common fixes (indentation, quotes, etc.)
- Exit code: 1

**Schema Violations:**
- Validate against Pydantic models
- Show field path and expected type/constraint
- List all violations (don't stop at first)
- Exit code: 2

**Cross-Reference Errors:**
- Present issues with field paths, descriptions, and suggestions
- Distinguish errors (block generation) from warnings (proceed with caution)
- Exit code: 2 if errors present

### Generation Failures

**Resource exhaustion:**
- Memory: Stream writes, don't buffer all output
- Disk: Check available space before starting, fail fast if insufficient
- Exit code: 20

**Invalid state:**
- Detect impossible states (e.g., PID reuse collision)
- Log detailed state information
- Attempt recovery (assign new PID)
- If unrecoverable: fail with detailed error
- Exit code: 21

**Format definition errors:**
- Validate format definitions on load
- Show which format and which rule failed
- Fail before generation starts
- Exit code: 22

### Edge Cases

**Empty time window:**
- If start == end: Error
- If duration <= 0: Error

**No users or systems defined:**
- Require at least 1 user and 1 system
- Error with suggestion to add users/systems

**Conflicting specifications:**
- Duplicate usernames or hostnames: Error (must be unique)
- Storyline references non-existent user/system: Error with suggestion

**Activity before window start or after end:**
- Clamp to window boundaries with warning
- Log original vs adjusted time

**User activity on unassigned system:**
- If user has primary_system: Warn but allow
- If system doesn't exist: Error

**Process tree inconsistencies:**
- Parent PID doesn't exist: Use reasonable default (explorer.exe, init)
- Circular parent references: Error

**Network impossibilities:**
- Connection where src_ip == dst_ip: Skip with warning (network sensors cannot observe localhost traffic)
- Connection involving localhost addresses (127.0.0.0/8): Skip with warning (never traverses network)
- Connection involving link-local addresses (169.254.0.0/16): Skip with warning (auto-config, not routed)
- Connection involving multicast/reserved addresses (224.0.0.0/4): Skip with warning
- Connection to private IP from external actor: Warn (might be VPN/proxy, but allow)
- Response bytes > 0 for failed connection: Adjust to 0, warn
- Connection not visible to configured sensors: Skip based on network topology and sensor placement

**Logon without logoff:**
- Within time window: Acceptable and common (user still logged in, forgot to log off, system crash)
- At end of window: ~85% of sessions close properly, ~15% incomplete (realistic messiness)
- Storyline can specify incomplete sessions for attacker behavior

**Time travel:**
- Event A references Event B that happens later: Error
- Process termination before creation: Error
- All timestamps validated during generation

**Duplicate identifiers:**
- Two users with same username: Error (must be unique)
- Two systems with same hostname: Error (must be unique)
- PID reuse within same system: Track PIDs per-system, allocate incrementally, reuse only after explicit termination

**Timezone handling:**
- All internal timestamps UTC
- Convert to system/format timezone during output
- If system timezone not configured: Use environment.timezone.default
- Support pattern matching for multi-location environments (WS-NYC-*, WS-LON-*)
- Invalid timezone name: Error with suggestion

**Connection to private IP from external actor:**
- Allow but warn: "External actor accessing private IP -- consider modeling VPN/proxy/compromised perimeter"
- User should explicitly model network topology to represent VPN/proxy/perimeter devices

## 8. Testing Strategy

### Test Levels

**Unit Tests** (target: 95% coverage, currently 526+ tests passing)
- All Pydantic models: validation, serialization
- State manager: session/process/connection tracking (including thread safety)
- Format validators: constraint DSL evaluation
- Emitters: log format generation (including thread safety)
- Activity generation: persona-based temporal distribution
- Network visibility: sensor placement and traffic filtering
- Ground truth generation
- Time utilities: parsing, duration calculation, timezone handling
- Config loading: env var interpolation, .env file discovery
- CLI commands: argument parsing, error handling

**Integration Tests** (target: 90% coverage)
- Scenario file loading, validation, and generation end-to-end
- Format definition loading, validation, and application
- Parallel generation across multiple emitters
- Timezone handling through full pipeline
- Medium dataset generation (100 users, 8 hours)

**End-to-End Tests** (run manually or in release pipeline)
- Complete workflow: init, generate, evaluate
- Multiple dataset sizes and configurations
- Verify output structure, format compliance, consistency
- Performance benchmarks (time to generate, memory usage)

### Test Data

**Fixtures:**

Required scenario files:
1. **minimal**: 1 user, 1 system, 1 hour, baseline only
2. **small-realistic**: 20 users, 10 systems, 8 hours, baseline only
3. **attack-single**: 50 users, ransomware scenario
4. **attack-multi**: 100 users, credential stuffing + lateral movement
5. **large-scale**: 100 users, 24 hours, multiple log formats

**Property Tests:**
- All timestamps within specified window
- All LogonIDs referenced have corresponding 4624 events
- All PIDs referenced have corresponding process creation events
- No orphaned connections (all have start events)

### Testing Tools

**Framework:** pytest with plugins
- pytest-cov for coverage
- pytest-mock for mocking
- pytest-benchmark for performance tests

**Coverage Requirements:**
- Overall: 95%+
- Core generation engine: 95%+
- Format definitions & validators: 90%+
- CLI interface: 85%+
- Exclude: `__main__.py`, type stubs, test fixtures

## 9. MVP Scope & Future Considerations

### MVP Deliverables

1. **Three Claude Code skills**
   - `/eforge scenario`: Guided scenario creation with hybrid interview flow, ENVIRONMENT.md generation, 10-tactic ATT&CK kill chain template
   - `/eforge generate`: Generation execution with pre-flight validation, error diagnosis, ENVIRONMENT.md copying
   - `/eforge validate`: Schema and cross-reference validation with auto-fix for simple issues
   - Developed using /skill-creator with 2 iterations, 30/30 eval assertions passing

2. **Pre-built persona library** (15 personas)
   - Persona files use the exact same YAML schema as the Persona model in scenario files
   - Complete set: developer, executive, analyst, sysadmin, help_desk, security_analyst, accountant, sales, hr, marketing, data_analyst, receptionist, intern, project_manager, legal_counsel
   - Each with realistic activity patterns, work hours, and risk profiles

3. **`eforge install-skills` command**
   - Installs skills, personas, and reference docs to `.claude/commands/` (project) or `~/.claude/commands/` (global)
   - Bundled as package data via `importlib.resources` + hatch force-include
   - Handles updates: overwrites changed files, removes stale files

4. **Documentation**
   - This PRD
   - Scenario authoring reference (`docs/scenario-reference.md`)
   - README with skill-based workflow

5. **Core generation engine** (implemented in Phases 1-2)
   - 7 log formats with emitters
   - Persona-based temporal activity distribution
   - Network visibility with TAP/SPAN sensor modeling
   - Parallel emitter-level generation
   - Progress reporting
   - Ground truth generation
   - Schema + cross-reference validation
   - 542+ tests passing

### Post-MVP: Evaluation Framework ✅ COMPLETE (Phase 4)

- `eforge evaluate` command with 5 quality dimensions, 23 sub-scores, acceptance criteria
- `/eforge evaluate` skill for qualitative LLM review
- Full details in `docs/data-quality-prd.md`

### Post-MVP: Data Realism Improvements (Phase 5)

Phase 4 evaluation revealed that while signal integrity is excellent (100/100), the background noise is too shallow and uniform for the data to pass casual inspection by an experienced analyst. Phase 5 addresses these generator-level limitations in 5 incremental sub-phases.

**Problem statement:** An experienced threat hunter would identify the data as synthetic within minutes due to: uniform Zeek conn_states, zero UDP/ICMP traffic, only 11 destination IPs, only 2 Windows Event IDs in baseline, metronomic timing, and statistically interchangeable users.

**Target outcome:** Overall eval score ≥ 85, all hard acceptance criteria pass, no "instant tells" on qualitative review.

#### 5.1 Record Fidelity Quick Wins
- **SID generation**: Populate `SubjectUserSid`/`TargetUserSid` with realistic Windows SIDs (`S-1-5-21-{domain}-{rid}`). Per-domain base SID at engine init, per-user RID mapping, well-known SIDs for system accounts.
- **Session lifecycle**: Baseline activity generates logoff events (Windows 4634, eCAR USER_SESSION/LOGOUT). Sessions have realistic lifetimes with probabilistic termination.
- **Zeek conn_state diversity**: Replace hardcoded `SF`/`ShADadfF` with probabilistic selection (SF 85%, S0 5%, REJ 2%, RSTO 3%, etc.) with history strings and byte counts consistent with state.
- **Process path expansion**: Expand from 14 to 50+ unique process paths including OS backbone (svchost, lsass, explorer, csrss) and common applications (browsers, Office, Teams). Per-persona weighting.

#### 5.2 Event Type Diversity
- **Additional Windows Event IDs**: 4625 (failed logon), 4672 (special privileges), 4689 (process termination), 4648 (explicit credential logon), 5156 (firewall allow). Update format definition, templates, and validation.
- **Failed logon generation**: 5-15% of logon attempts fail with realistic reasons (bad password, locked account, expired password).
- **eCAR object type expansion**: Generate FILE/CREATE, FILE/MODIFY, REGISTRY/MODIFY, FLOW/CONNECT, MODULE/LOAD events alongside existing USER_SESSION and PROCESS types.
- **Process termination**: Pair 4689 with 4688, track running processes, terminate after realistic durations.

#### 5.3 Protocol & Network Diversity
- **UDP traffic**: DNS queries (UDP 53) preceding TCP connections, NTP sync (UDP 123), DHCP (UDP 67/68), mDNS/LLMNR, QUIC (UDP 443).
- **ICMP traffic**: Periodic pings between same-segment systems, ICMP unreachable for failed connections.
- **Service registry**: Internal consistency model — tracks which internal IPs run which services (ports). Declared systems + auto-generated infrastructure. Connection success/failure consistent with whether port is open on the target.
- **External IP expansion**: Grow from ~9 to 50+ fixed IPs per category plus random generation for CDN/cloud long-tail. Target hundreds of unique destinations per scenario.
- **Zeek dns.log format**: New format definition for DNS query/response logging.

#### 5.4 Background Traffic & System Activity
- **System model enhancement**: Optional inline `services` field on System (e.g., `services: ["dns-client", "ntp-client", "smb"]`). Auto-populated from OS type if not specified. Hybrid approach: auto-generate defaults, allow scenario overrides. No separate records for host and services — all in one System definition.
- **System traffic loop**: New generation pass per hour for OS-appropriate system traffic (DNS lookups, NTP sync, Windows Update, SMB browsing). Target ~20-30% of total output.
- **System process trees**: Generate OS-appropriate boot processes at scenario start (Windows: System→smss→csrss→wininit→services→svchost; Linux: init/systemd→cron, sshd, rsyslogd).
- **Scheduled tasks**: Periodic system activities (Windows Defender scans, logrotate, package update checks) at regular intervals with slight jitter.

#### 5.5 Temporal Realism
- **Soft work-hour ramp**: Replace binary on/off with sigmoid curve. Gradual morning ramp (10%→100% over ~1 hour), soft lunch dip (50% not 0%), evening tail (20% for 1-2 hours post-end), occasional late-night activity (1-3% probability).
- **Activity clusters**: Replace uniform event distribution with burst model. Each "activity" becomes a cluster of 3-15 correlated events over 5-30 seconds (e.g., logon→process spawns→connections). Inter-cluster gaps follow exponential distribution (2-15 minutes).
- **Per-user work hour jitter**: Randomize each user's start/end/lunch ±30min from persona defaults. Applied once at init, consistent throughout scenario.
- **Per-persona behavioral differentiation**: Distinct cluster templates per persona type. Developers: long sustained coding sessions. Executives: short frequent email/calendar bursts. Analysts: medium DB-heavy clusters.

### Current Implementation Status

| Component | Status |
|-----------|--------|
| CLI (`eforge init`, `eforge generate`, `eforge validate`, `eforge version`, `eforge install-skills`) | Complete |
| Scenario Pydantic models | Complete |
| 7 format definitions (YAML) | Complete |
| 7 emitters (Windows, Zeek, ECAR, Syslog, Bash History, Snort, Web) | Complete |
| State manager (sessions, processes, connections) | Complete |
| Persona-based activity generation | Complete |
| Network visibility / sensor modeling | Complete |
| Ground truth generation | Complete |
| Schema + cross-reference validation | Complete |
| Parallel emitter-level generation | Complete |
| Progress reporting (Rich) | Complete |
| Timezone handling | Complete |
| OS-aware activity generation (Windows + Linux) | Complete |
| `eforge validate` command | Complete |
| `eforge install-skills` command | Complete |
| Skills (`/eforge scenario`, `/eforge generate`, `/eforge validate`) | Complete |
| Persona library files (15 personas) | Complete |
| `eforge evaluate` command | Complete (Phase 4) |
| Evaluation framework (5 dimensions, 23 sub-scores) | Complete (Phase 4) |
| `/eforge evaluate` skill | Complete (Phase 4) |
| Data realism improvements (SIDs, event diversity, protocol mix, timing) | Phase 5 (planned) |

### Future Enhancements

**Short-term (post-MVP):**
- Checkpointing and resume for long-running generation jobs
- Large dataset optimization (100M+ events, memory-mapped writes)
- Config file inheritance/templating
- Additional log formats (cloud providers, databases)
- PyPI package distribution

**Medium-term:**
- Poisson/Hawkes process timing model (upgrade from Phase 5.5 activity clusters to self-exciting point process for statistically rigorous inter-arrival distributions)
- Web UI for scenario creation
- Streaming output to SIEM/data lakes
- Log format auto-detection from samples

**Long-term:**
- OT/ICS environment simulation
- Real-time log streaming mode (not batch generation)
- Collaborative scenario editing
- Scenario marketplace (share/download scenarios)
- Integration with attack frameworks (CALDERA, Atomic Red Team)
- Cloud provider logs (CloudTrail, Azure Activity, GCP Audit)

### Architectural Decisions Preserving Future Features

**Must NOT block:**
1. **LLM client integration**: `llm/` package created when LLM integration is needed (future); Bedrock/OpenAI client plugs in here
2. **Real-time streaming**: State manager and emitters designed to work event-by-event, not requiring full dataset in memory
3. **New log formats**: Format engine is data-driven, adding formats requires only a new YAML definition and emitter class
4. **Web UI**: Business logic separated from CLI, can wrap with API layer
5. **Distributed generation**: State can be partitioned (per-user, per-system)

**Abstractions to maintain:**

```python
# Log Emitter base class (uniform interface for all formats)
class LogEmitter(ABC):
    @abstractmethod
    def emit_event(self, event: Event, state: StateManager) -> None: ...

    @abstractmethod
    def flush(self) -> None: ...

# State Manager (encapsulates all runtime state)
class StateManager:
    # Thread-safe state access; only StateManager can mutate state
    def create_session(self, ...) -> str: ...  # Returns LogonID
    def get_active_sessions(self) -> dict[str, ActiveSession]: ...
    def create_process(self, ...) -> int: ...  # Returns PID
    # etc.

# Format Definition (declarative, loaded from YAML)
@dataclass
class FormatDefinition:
    name: str
    common_fields: list[FieldDefinition]
    variants: list[VariantDefinition]
    output_template: str
```

- Scenario schema versioning (enable backward compatibility)

### Known Limitations

**MVP will NOT:**
- Generate bit-perfect binary EVTX files (XML output by default)
- Support binary log formats (Snort uses fast alert format, not pcap)
- Perform network traffic capture simulation (packet-level)
- Simulate actual malware execution (this is synthetic, not sandboxing)
- Generate logs for systems without format definitions
- Guarantee detection rule triggering (depends on SIEM/tool configuration)
- Provide bit-perfect reproducibility (save and reuse scenario files)
- Checkpoint and resume interrupted generation jobs

**Performance bounds (MVP):**
- Max 1000 users (technical limit, not enforced)
- Max 30-day time windows (technical limit, not enforced)
- Single machine execution (no distributed generation)
- Emitter-level parallelization only (not user-level or time-slice)

### Success Metrics

**MVP is successful if:**
1. Can generate realistic 8-hour dataset for 100 users in < 30 seconds
2. Generated logs pass format validation for all 7 formats
3. Cross-log consistency checks pass (no orphaned references)
4. `/eforge scenario` skill can produce valid scenarios for common use cases
5. 95%+ test coverage achieved
6. 3+ external users successfully generate custom scenarios
7. Generated logs successfully imported into Splunk/ELK without errors

**Quality bar:**
- Security researcher can use generated data for detection rule development
- Threat hunter cannot immediately distinguish synthetic from real logs (structural examination)
- Educator can create reproducible lab exercises with specific ground truth
- Generated datasets exhibit realistic temporal patterns and user behaviors

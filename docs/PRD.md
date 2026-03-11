# PRD: EvidenceForge

## 1. Overview

This project creates a system for generating realistic synthetic security logs for cybersecurity threat hunting training and research. The system uses a two-phase hybrid architecture:

**Phase 1 - Scenario Creation (LLM-intensive):** Conversational interface accepts natural language descriptions of computing environments and activities. LLM researches TTPs, expands high-level descriptions into detailed execution plans, and outputs structured scenario files.

**Phase 2 - Log Generation (Deterministic):** Generation engine executes the detailed scenario plan without LLM calls, producing large-scale, temporally consistent datasets across multiple log formats (Windows Event Logs, Zeek, Syslog, web logs, etc.) with coordinated cross-references (matching LogonIDs, PIDs, session data, etc.).

This architecture combines the flexibility and realism of LLM understanding with the speed, cost-efficiency, and reproducibility of deterministic generation.

Unlike existing tools that focus solely on attack simulation or use purely programmatic generation, this system:
- Accepts natural language input (not just code/YAML)
- Generates coordinated multi-source logs (not single format)
- Supports both baseline "normal" activity and injected attack scenarios
- Maintains realistic temporal patterns and behavioral variation
- Provides ground truth about malicious activities for threat hunting exercises

The tool addresses the need for realistic, large-volume training datasets without the privacy/security concerns of production data.

## 2. Goals & Non-Goals

### Goals (MVP)
- Generate realistic synthetic logs for 5 initial formats: Windows Event Logs, Zeek, Snort/Suricata, Linux syslogs, W3C web/proxy logs
- Conversational interface for scenario specification that outputs structured configuration files
- LLM expands high-level descriptions during conversation into detailed execution plans (no LLM calls during generation)
- Support both high-level environment descriptions (LLM fills in details) and explicit specifications (users define exact systems, users, IPs)
- Maintain cross-log consistency (events reference same LogonIDs, PIDs, timestamps, etc.)
- Support arbitrary time windows from hours to weeks
- Handle datasets from small (classroom exercises) to huge (multi-day, 500+ users)
- Parallel generation at emitter level (different log formats simultaneously) with incremental writing for performance
- Progress reporting during generation
- Checkpointing for long-running generation jobs
- Schema validation and LLM-based semantic validation with interactive repair
- Optional realism evaluation with concrete metrics
- Ground truth documentation (GROUND_TRUTH.md) for scenarios with malicious activity: attack narrative, timeline, atomic IOCs
- Comprehensive test coverage (95%+) with pytest
- Ship with pre-built persona library to reduce LLM usage
- Flexible timezone handling (UTC internal, configurable per-system/format for output)

### Non-Goals (Future Enhancements)
- Bit-perfect reproducibility via seed (LLM expansion during conversation is non-deterministic; save scenario file for reuse)
- Subjective "does this feel real?" evaluation beyond concrete metrics
- Config file inheritance/templating
- Support for LLM backends beyond AWS Bedrock (OpenAI, Ollama, Anthropic native, Gemini)
- PyPI package distribution (MVP is git clone + local install)
- Pre-built binaries or container images
- Streaming output to SIEM/data lakes
- OT/ICS environment simulation
- Mobile device logs
- Cloud provider logs (CloudTrail, Azure Activity, GCP Audit)
- Time-slice or user-level parallelization (MVP parallelizes at emitter level only)

## 3. Target Users

**Primary Users:**
- **Security Researchers**: Need realistic datasets for developing detection algorithms and threat hunting techniques
- **Threat Hunters**: Require practice datasets with known ground truth for training and skill development
- **Security Educators**: Must create reproducible scenarios for classroom exercises and labs
- **SOC Trainers**: Need varied, realistic datasets for analyst training programs
- **Detection Engineers**: Require test data for validating detection rules and SIEM configurations

**User Context:**
- Mix of technical proficiency (from educators who may not code to researchers who do)
- Need for both quick scenario generation and detailed customization
- Often simulating specific real-world environments or generic representative environments
- May need same scenario run multiple times with variations

## 4. Functional Requirements

### 4.1 Core Workflows

#### Workflow 1: Initialize New Project
```bash
log-generator init [--output CONFIG_FILE]
```
1. System creates example configuration file with documented parameters
2. Includes example models, AWS settings, output paths
3. User can customize for their environment

#### Workflow 2: Interactive Scenario Creation
```bash
log-generator new [--config CONFIG_FILE]
```
1. System starts conversational interface
2. Asks clarifying questions about:
   - Environment (size, type of organization, systems, users)
   - Baseline activity patterns (or select from pre-built persona library)
   - Specific attack scenarios or activities to inject
   - Time windows
   - Output requirements
3. User can specify at any level of detail:
   - High-level: "50-person financial services company"
   - Mixed: 10 specific users, generate 40 more
   - Detailed: Exact usernames, hostnames, IPs, file paths, timezones
4. LLM performs research as needed:
   - MITRE ATT&CK TTPs for attack scenarios
   - Typical behavior patterns for custom personas
   - Log artifact details for specific techniques
   - Common tooling and related techniques
   - 30-second timeout per research query
5. LLM expands high-level descriptions into detailed execution plans:
   - Personas → concrete activity sequences with frequencies
   - Storyline activities → detailed event sequences with specific log artifacts
   - Attack scenarios → full kill chain with appropriate techniques
6. System generates complete scenario YAML file + research markdown file
7. Saves to disk for review/editing/reuse
8. No further LLM calls needed during generation phase

#### Workflow 3: Validate Scenario
```bash
log-generator validate SCENARIO_FILE
```
1. Schema validation: Check YAML structure, data types, required fields
2. LLM semantic validation: Check logical consistency
   - Referenced users exist in environment
   - Activities make sense for specified environment
   - Time sequences are logical
   - Attack scenarios are technically sound
3. If issues found:
   - Present issues to user
   - Offer interactive repair (re-enter conversation mode)
   - Suggest auto-fixes where appropriate
4. Report validation status

#### Workflow 4: Generate Logs
```bash
log-generator generate SCENARIO_FILE [--output DIR] [--resume]
```
1. Load and validate scenario file (schema validation only, no LLM)
2. Load format definitions for requested log types
3. Load research markdown if exists (context for generation)
4. Initialize generation state (users, systems, sessions, processes, connections)
5. Start parallel emitters (one per log format, shared read-only state access)
6. Generate baseline activity:
   - Execute expanded persona activity patterns for all users
   - Apply realistic temporal distributions throughout time window
   - StateManager tracks all sessions, processes, connections (no automatic cleanup)
7. Layer storyline activities on top of baseline:
   - Execute detailed event sequences at specified times
   - Suppress baseline for affected users during storyline (±5 min window to avoid conflicts)
   - LLM-defined behavior controls completeness (some sessions/processes may not close cleanly)
8. Each emitter writes coordinated logs with consistent cross-references (LogonIDs, PIDs, timestamps)
9. Convert timestamps from UTC to system/format-specific timezones as configured
10. Write to organized directory structure with incremental flushing (10K event buffer)
11. Show progress bar with ETA (based on moving average of last 10% progress)
12. Log details to generation.log in output directory
13. Create checkpoint files every 5 minutes (or 100K events) for resume capability
14. Generate GROUND_TRUTH.md file when malicious/suspicious activities are present:
   - Attack narrative summary (malicious activities only, excludes benign baseline)
   - Timeline of key malicious events with timestamps and optional record IDs
   - Atomic IOCs grouped by type (IP addresses, usernames, hostnames, processes, file paths, command lines, etc.)

#### Workflow 5: Evaluate Output
```bash
log-generator evaluate OUTPUT_DIR
```
1. Load generated logs
2. Run validation checks:
   - Format compliance (syntactically valid)
   - Consistency (cross-references resolve correctly)
   - Statistical properties (distributions, timing patterns)
   - Completeness (no orphaned references)
3. If GROUND_TRUTH.md exists, validate that all documented IOCs are present in logs
4. Generate report with scores and specific findings
5. Optional: Save report for comparison across runs

### 4.2 Data Model

#### Configuration File Schema

**Main Configuration** (`config.yaml` or `.env`)
```yaml
aws:
  profile: string (supports ${AWS_PROFILE})
  region: string (supports ${AWS_REGION})

bedrock:
  model_primary: string      # Default: anthropic.claude-sonnet-4-6-v1:0
  model_research: string     # For TTP research, default: sonnet-4-6
  model_generation: string   # For bulk generation, default: haiku-4-5

output:
  base_directory: string     # Where to write generated datasets

logging:
  level: string              # debug|info|warning|error
  console_level: string      # warning|error (what shows on console)
```

**Scenario File Schema** (output of conversational interface)

Primary file: `scenario-name.yaml`
Companion file: `scenario-name-research.md` (LLM research findings)

```yaml
version: string              # Schema version, e.g., "1.0"
name: string                 # Human-readable scenario name
description: string          # Multi-line natural language description

environment:
  description: string        # Natural language environment description

  timezone:
    default: string          # Default timezone for all systems (e.g., "UTC", "America/New_York")
    systems:                 # Per-system overrides (optional)
      pattern: string        # e.g., "WS-NYC-*": "America/New_York"

  # Option 1: Generated (LLM fills in details)
  generate:
    organization_type: string
    size: integer
    user_count: integer
    workstation_count: integer
    server_count: integer

  # Option 2: Explicit (user-defined)
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
      type: string           # workstation|server|domain_controller|network_device|...
      assigned_user: string  # Optional, for workstations
      services: list[string] # Service names like "IIS", "SSH", "SQL Server" (not ports)

  groups:
    - name: string
      description: string
      members: list[string]  # Usernames
      permissions: list[string]

  file_shares:
    - path: string
      permissions: list[string]  # Group names

personas:
  # Note: LLM expands high-level persona descriptions into detailed activity patterns
  # during conversation phase. Can reference pre-built personas or define custom.
  - name: string
    description: string      # Natural language behavior description
    typical_activities: list[string]  # High-level activities that LLM expands
    work_hours: string       # e.g., "8am-6pm with variation" (LLM interprets as distribution)
    application_usage: list[string]
    risk_profile: string     # low|medium|high (affects activity intensity/variation)

    # LLM-expanded fields (added during conversation):
    expanded_activities:     # Detailed activity patterns with frequencies, processes, etc.
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
  intensity: string          # low|medium|high → events/user/hour: low=5, medium=15, high=40
  variation: string          # low|medium|high → timing stddev: low=±10%, medium=±25%, high=±50%
  # Note: Persona risk_profile modifies intensity (low=-5, high=+10 events/hour)

storyline:
  # Note: LLM expands natural language activities into detailed event sequences during conversation
  - time: string             # Time formats:
                             #   - ISO 8601 timestamp (must be within window)
                             #   - Relative offset: "+2h30m" or "+2h" or "+150m"
                             #   - Offset in seconds: "+7200"
    actor: string            # Actor specification (LLM interprets during expansion):
                             #   - Specific username: "bwilliams"
                             #   - Threat actor: "APT29", "SCATTERED SPIDER", "Red Team Alpha"
                             #   - Generic: "attacker" (LLM determines external vs internal)
                             #   - Note: Multiple distinct actors supported in same scenario
    source_ip: string        # Optional, for external actors
    system: string           # Target system hostname (specific or ANY_SYSTEM_OF_TYPE:workstation)
    activity: string         # Natural language activity description (LLM expands to detailed events)
    details: dict            # Flexible activity-specific details (LLM validates appropriateness):
      # Common examples (not exhaustive):
      url: string            # For web activities
      file: string           # For file operations
      binary: string         # For process execution
      command: string        # For command execution
      target_system: string  # For lateral movement
      stolen_creds: string   # For credential usage
      # Any other relevant fields as needed

    # LLM-expanded fields (added during conversation):
    event_sequence: list     # Detailed event sequence with specific log artifacts
      - event_type: string
        log_sources: list[string]  # Which log formats show this event
        fields: dict         # Specific field values for each log source

output:
  logs:
    - format: string         # windows_event|zeek|syslog|snort|web
      variant: string        # Optional: Security|System|conn|http|auth|access
      timezone: string       # "system" (use system's timezone) or explicit "UTC"/"America/New_York"
      options: dict          # Format-specific options

  destination: string        # Output directory path
  compression: boolean       # Compress output files (gzip)
  format_options:            # Complete options for all MVP formats
    windows_event:
      output_format: string  # xml|evtx|json (default: xml, binary evtx optional)
    zeek:
      include_header: boolean  # TSV header row (default: true)
    syslog:
      format: string         # rfc3164|rfc5424 (default: rfc5424)
    snort:
      format: string         # unified2|fast|full (default: fast)
    web:
      format: string         # w3c|combined|common (default: w3c)
```

#### Format Definition Schema

**Format Definitions** (`formats/{format_name}.yaml`)
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
#
# Reference: JSON Logic provides complete formal specification, unambiguous for AI generation
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
    checkpoint_data: dict  # For resume capability
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
    syslog.log                 # Linux syslogs
    snort_alerts.log           # Snort/Suricata alerts
    web_access.log             # Web/proxy logs
    .checkpoints/              # Resume checkpoints (deleted on success)
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
log-generator init [--output CONFIG_FILE]

Options:
  --output    Path to write config file (default: ./config.yaml)

Creates example configuration file with AWS settings, model selections,
and other parameters documented inline.

Non-interactive: Simply writes heavily-commented config file with:
- All options documented
- Defaults set
- AWS profile/region set to ${AWS_PROFILE}, ${AWS_REGION} placeholders
- Links to documentation for more details
```

**Command: new**
```
log-generator new [--config CONFIG_FILE]

Options:
  --config    Path to config file (default: ./config.yaml)

Starts interactive conversational interface for scenario creation.
Outputs scenario YAML file based on user responses.
```

**Command: validate**
```
log-generator validate SCENARIO_FILE [--config CONFIG_FILE]

Arguments:
  SCENARIO_FILE    Path to scenario YAML file

Options:
  --config         Path to config file (default: ./config.yaml)
  --fix            Automatically fix issues where possible
  --interactive    Enter conversation mode to fix issues interactively

Validates scenario file for schema and semantic correctness.
Returns exit code 0 on success, non-zero on failure.
```

**Command: generate**
```
log-generator generate SCENARIO_FILE [--config CONFIG_FILE] [--output DIR] [--resume]

Arguments:
  SCENARIO_FILE    Path to scenario YAML file

Options:
  --config         Path to config file (default: ./config.yaml)
  --output         Override output directory from scenario file
  --resume         Resume from last checkpoint if generation was interrupted

Generates logs according to scenario specification.
No LLM calls during generation (all expansion happened during 'new' command).
Shows progress bar and writes detailed logs to output directory.
Performs schema validation only (no LLM semantic validation).
```

**Command: evaluate**
```
log-generator evaluate OUTPUT_DIR [--config CONFIG_FILE] [--report REPORT_FILE]

Arguments:
  OUTPUT_DIR       Path to generated log directory

Options:
  --config         Path to config file (default: ./config.yaml)
  --report         Path to write evaluation report (default: OUTPUT_DIR/evaluation.json)
  --verbose        Include detailed findings in report

Evaluates generated logs for concrete metrics:
  - Format compliance: 100% of events parse successfully against format definitions
  - Consistency: 100% of cross-references resolve (LogonIDs, PIDs, connection IDs)
  - Statistical properties: Event type distributions, logon/logoff balance (within 5%)
  - Completeness: No orphaned references
  - Ground truth validation: If GROUND_TRUTH.md exists, verify all documented IOCs are present in logs

Report is informational only (no pass/fail thresholds for MVP).
Outputs JSON report with scores and specific findings.
```

## 5. Non-Functional Requirements

### Performance
- **Small datasets** (1 hour, 50 users, ~10K events): < 1 minute generation time
- **Large datasets** (8 hours, 500 users, ~1M events): < 30 minutes generation time
- **Huge datasets** (7 days, 500 users, ~20M events): < 4 hours generation time
- Memory usage: < 2GB regardless of output size (soft target, not enforced)
  - Streaming writes with 10K event buffer per emitter
  - State grows with active sessions/processes but typically < 100MB for huge scenarios
  - No automatic state pruning (realistic incompleteness is acceptable)
- Parallel generation at emitter level: Different log formats write simultaneously
  - Shared StateManager with thread-safe read access
  - Each emitter runs in separate thread
  - Time-slice and user-level parallelization out of MVP scope

### Scalability
- Support up to 1000 users and 2000 systems in a single environment
- Handle time windows up to 30 days
- Generate up to 100M events in a single run
- Checkpoint every 5 minutes during generation for resume capability

### Reliability
- **LLM API retry logic** (conversation and validation phases only, not generation):
  - Retry per-request with exponential backoff: 2s, 4s, 8s (±25% jitter)
  - Retry on: 429 (rate limit), 500, 502, 503, network errors
  - Don't retry on: 400 (bad request), 401 (unauthorized), 403 (forbidden)
  - Max 3 attempts per request
  - Log retries at INFO level
  - After 3 failures: Fail fast with clear error message indicating operation and remediation
- **Checkpointing** (generation phase):
  - Save state every 5 minutes OR 100K events (whichever comes first)
  - Checkpoint contains: current time in window, StateManager snapshot, event counts per format, progress metrics
  - Checkpoints auto-deleted on successful completion, retained on failure
  - Support --resume flag to continue from last checkpoint
  - Checkpoints versioned with schema version for forward compatibility
- **Input validation**: Schema validation before generation starts (fail fast)
- **Atomic writes**: Use temp files + rename for log files
- **Resource exhaustion**: Check disk space before starting (require 2x estimated output size), fail if insufficient

### Security
- Never log AWS credentials or other secrets
- Support AWS credential chain (no credentials in config files)
- Environment variable interpolation for sensitive values
- .env file support with search from current directory up to home
- Format definition validation: Constrained DSL only, no arbitrary code execution from untrusted format files

### Usability
- Progress reporting with ETA for long-running jobs
- Clear, actionable error messages
- Interactive validation repair when issues found
- Examples and templates included
- Comprehensive documentation

### Maintainability
- 95%+ test coverage across all components
- Type hints throughout codebase
- Pydantic models for all data structures
- Clear separation of concerns (conversation / validation / generation)
- Format definitions as data, not code

## 6. Technical Architecture

### 6.1 Tech Stack

**Core:**
- Python 3.11+ (for latest type hint features)
- uv for package management and script/tool support
- Pydantic v2 for data validation and schema management

**LLM Integration:**
- boto3 for AWS Bedrock access
- Primary model: anthropic.claude-sonnet-4-6-v1:0
- Research model: anthropic.claude-sonnet-4-6-v1:0
- Generation model: anthropic.claude-haiku-4-5-v1:0 (cost optimization)

**CLI & Output:**
- Typer for CLI framework (modern, excellent Pydantic integration)
- Rich for progress bars and console formatting
- Jinja2 for log format templates
- PyYAML for configuration parsing
- pytz for timezone handling

**Testing:**
- pytest for test framework
- pytest-asyncio for async tests
- pytest-cov for coverage reporting
- pytest-mock for mocking
- Separate markers for @pytest.mark.live (requires LLM API) vs unit tests

**Format Support:**
- python-evtx (try first) or XML fallback for Windows Event Log (binary EVTX optional)
- Standard library json/csv for text formats
- Custom parsers/writers for Zeek, Syslog, etc.
- json-logic-py for format definition validation

### 6.2 Project Structure

```
log-generator/
├── README.md
├── AGENTS.md                    # AI coding agent instructions
├── LICENSE
├── pyproject.toml               # uv project config
├── config.example.yaml          # Example configuration
├── .env.example                 # Example environment variables
│
├── personas/                    # Pre-built persona library (reduce LLM usage)
│   ├── developer.yaml
│   ├── accountant.yaml
│   ├── executive.yaml
│   ├── help_desk.yaml
│   ├── security_analyst.yaml
│   └── ...                      # 10-15 common personas
│
├── src/
│   └── log_generator/
│       ├── __init__.py
│       ├── __main__.py          # CLI entry point
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   ├── commands.py      # CLI command implementations
│       │   └── conversation.py  # Interactive conversation interface
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── config.py        # Pydantic models for config
│       │   ├── scenario.py      # Pydantic models for scenario
│       │   ├── format_def.py    # Pydantic models for format definitions
│       │   └── state.py         # Runtime state models
│       │
│       ├── validation/
│       │   ├── __init__.py
│       │   ├── schema.py        # Schema validation
│       │   ├── semantic.py      # LLM-based semantic validation
│       │   └── repair.py        # Interactive repair logic
│       │
│       ├── generation/
│       │   ├── __init__.py
│       │   ├── engine.py        # Main generation orchestrator
│       │   ├── state_manager.py # State tracking (sessions, processes, etc.)
│       │   ├── persona.py       # Persona-based activity generation
│       │   ├── activity.py      # Activity script execution
│       │   ├── checkpoint.py    # Checkpoint/resume logic
│       │   └── emitters/
│       │       ├── __init__.py
│       │       ├── base.py      # Base emitter interface
│       │       ├── windows.py   # Windows Event Log emitter
│       │       ├── zeek.py      # Zeek log emitter
│       │       ├── syslog.py    # Syslog emitter
│       │       ├── snort.py     # Snort/Suricata emitter
│       │       └── web.py       # Web/proxy log emitter
│       │
│       ├── formats/
│       │   ├── __init__.py
│       │   ├── loader.py        # Format definition loader
│       │   ├── validator.py     # Format constraint validator (DSL)
│       │   └── definitions/
│       │       ├── windows_event.yaml
│       │       ├── zeek.yaml
│       │       ├── syslog.yaml
│       │       ├── snort.yaml
│       │       └── web.yaml
│       │
│       ├── llm/
│       │   ├── __init__.py
│       │   ├── client.py        # Bedrock client wrapper
│       │   ├── prompts.py       # System prompts for various tasks
│       │   ├── research.py      # TTP research logic
│       │   └── retry.py         # Retry logic with backoff
│       │
│       ├── evaluation/
│       │   ├── __init__.py
│       │   ├── evaluator.py     # Main evaluation logic
│       │   ├── metrics.py       # Concrete metrics (format, consistency, stats)
│       │   └── report.py        # Report generation
│       │
│       └── utils/
│           ├── __init__.py
│           ├── config.py        # Config loading with env var interpolation
│           ├── logging.py       # Logging setup
│           ├── time.py          # Time/duration parsing utilities
│           └── files.py         # File I/O utilities
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Shared fixtures
│   ├── unit/                    # Fast unit tests
│   │   ├── test_models.py
│   │   ├── test_validation.py
│   │   ├── test_state_manager.py
│   │   └── ...
│   ├── integration/             # Multi-component tests
│   │   ├── test_scenario_creation.py
│   │   ├── test_generation_small.py
│   │   └── ...
│   ├── live/                    # Tests requiring LLM API (marked @pytest.mark.live)
│   │   ├── test_conversation.py
│   │   ├── test_semantic_validation.py
│   │   └── test_research.py
│   └── fixtures/
│       ├── scenarios/           # Example scenario files
│       ├── configs/             # Example configs
│       └── sample_logs/         # Real log samples for validation
│
├── docs/
│   ├── installation.md
│   ├── quickstart.md
│   ├── user-guide.md
│   ├── scenario-reference.md
│   ├── format-definitions.md
│   └── architecture.md
│
└── examples/
    ├── simple-baseline/         # Simple baseline activity scenario
    ├── ransomware-attack/       # Ransomware scenario
    ├── credential-stuffing/     # Credential attack scenario
    └── insider-threat/          # Insider threat scenario
```

### 6.3 Configuration & Secrets

**Configuration Hierarchy** (later overrides earlier):
1. Default values in code
2. System-wide config (if exists): `~/.config/log-generator/config.yaml`
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
  - Example: `bedrock.model_primary: "${MODEL_PRIMARY}"`
- **.env file search**: Walk from CWD upward, max search depth is home directory (don't search above)
- **Security**: Never log secrets or include in error messages, stack traces, or debug output

**Required Configuration Items:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| aws.profile | string | "default" | AWS profile name, supports ${AWS_PROFILE} |
| aws.region | string | "us-east-1" | AWS region, supports ${AWS_REGION} |
| bedrock.model_primary | string | "anthropic.claude-sonnet-4-6-v1:0" | Main model for conversation and validation |
| bedrock.model_research | string | "anthropic.claude-sonnet-4-6-v1:0" | Model for TTP research |
| bedrock.model_generation | string | "anthropic.claude-haiku-4-5-v1:0" | Model for bulk generation tasks |
| output.base_directory | string | "./output" | Base directory for generated datasets |
| logging.level | string | "info" | Log level for file: debug/info/warning/error |
| logging.console_level | string | "warning" | Log level for console: warning/error |

## 7. UI/UX

This is a CLI tool, so traditional UI/UX doesn't apply. However, interaction design matters:

### Conversational Interface

**Design Principles:**
- One question at a time (never multi-part questions)
- Acknowledge user's answers before proceeding
- Offer recommendations when user is unsure
- Explain technical concepts if user asks
- Follow tangents (often reveal important requirements)
- Summarize and confirm before finalizing scenario

**Interaction Model:**
- Linear conversation (no backtracking in MVP - users edit YAML for corrections)
- LLM detects completeness when all required fields can be populated
- User says "done" or LLM asks "Is there anything else?" to conclude
- Three example conversation flows should be documented covering:
  1. Simple baseline-only scenario (minimal user input)
  2. Attack scenario with research and expansion
  3. Complex multi-actor scenario with explicit environment specs

**Implementation Notes:**
- System prompts guide LLM behavior (one question at a time, acknowledgment, etc.)
- Few-shot examples demonstrate desired interaction patterns
- Conversation state tracked for context
- Research results referenced in later questions

### Progress Reporting
```
Generating logs for scenario: ransomware-healthcare
Time window: 2026-01-15 08:00:00 to 2026-01-15 18:00:00 (10 hours)
Environment: 120 users, 95 workstations, 12 servers

[████████████████████--------] 65% | 6h 32m / 10h | ETA: 8m 15s

Writing: Windows Security Events (23,451 events)
         Sysmon (8,932 events)
         Zeek conn.log (127,834 connections)

Last activity: User jsmith browsing to internal portal (14:32:15)
```

### Error Messages
**Bad:**
```
Error: Validation failed
```

**Good:**
```
Validation Error: Invalid scenario file

Issue 1: Referenced user not found
  Line 42: storyline[0].actor = "bwilliams"
  Problem: User "bwilliams" is not defined in environment.users

  Suggestions:
    1. Add bwilliams to environment.users section
    2. Change actor to "ANY_USER_FROM:accountant"
    3. Run 'log-generator validate --interactive' to fix issues

Issue 2: Invalid time format
  Line 15: time_window.start = "2026-1-15"
  Problem: Must use ISO 8601 format
  Expected: "2026-01-15T08:00:00"

Run with --fix to automatically correct fixable issues.
```

## 8. Error Handling & Edge Cases

### Input Validation Errors

**Exit Code Table:**

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Input Error | Malformed YAML or file I/O error |
| 2 | Schema Validation | Pydantic validation failure (type/constraint violations) |
| 3 | Semantic Validation | LLM-detected logical inconsistencies |
| 10 | LLM API Failure | Persistent LLM API errors (auth, quota, region) |
| 11 | LLM Timeout | LLM operation exceeded timeout |
| 20 | Resource Exhaustion | Insufficient disk space or memory |
| 21 | Generation Error | Invalid state or unrecoverable generation failure |
| 22 | Format Error | Format definition loading or validation error |
| 130 | SIGINT | User interrupted (Ctrl+C) |

Note: Warnings do not affect exit code.

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

**Semantic Inconsistencies:**
- LLM validates logical consistency (conversation phase only)
- Present issues with context and suggestions
- Offer interactive repair (Option A: ask clarifying questions with suggestions from LLM auto-fixes)
- Exit code: 3

### LLM API Failures

**Transient errors** (rate limits, network issues):
- Retry with exponential backoff: 2s, 4s, 8s
- Log retry attempts at debug level
- After 3 failures: Escalate to persistent error handling

**Persistent errors** (auth failures, quota exhausted):
- Stop immediately with clear error message
- Indicate which operation failed (conversation, validation, research)
- Suggest remediation (check credentials, quota, region)
- Exit code: 10

**Context window exceeded:**
- For conversation: Summarize and continue
- For validation: Break into chunks
- For generation: Should not happen (deterministic, not LLM-based)

### Generation Failures

**Resource exhaustion:**
- Memory: Stream writes, don't buffer all output
- Disk: Check available space before starting, fail fast if insufficient
- Exit code: 20

**Invalid state:**
- Detect impossible states (e.g., PID reuse collision)
- Log detailed state information
- Attempt recovery (assign new PID)
- If unrecoverable: Checkpoint and fail with detailed error
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
- If environment.generate not specified and no explicit users: Error
- Require at least 1 user and 1 system

**Conflicting specifications:**
- Both environment.generate and environment.users specified: Use explicit (users), ignore generate
- Warn user about ignored section

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
- Connection to private IP from external actor: Warn (might be VPN/proxy)
- Response bytes > 0 for failed connection: Adjust to 0, warn

**Logon without logoff:**
- Within time window: Acceptable and common (user still logged in, forgot to log off, system crash)
- At end of window: LLM decides during expansion whether to close sessions cleanly or leave incomplete
- Default behavior: ~85% of sessions close properly, ~15% incomplete (realistic messiness)
- Storyline can specify incomplete sessions for attacker behavior

**Time travel:**
- Event A references Event B that happens later: Error
- Process termination before creation: Error
- All timestamps validated during generation

**Duplicate identifiers:**
- Two users with same username: Error (must be unique)
- Two systems with same hostname: Error (must be unique)
- PID reuse within same system: Track PIDs per-system, allocate incrementally, reuse only after explicit termination
- If PID pool exhausted (unlikely < 32K processes): Error with suggestion to shorten scenario

**Timezone handling:**
- All internal timestamps UTC
- Convert to system/format timezone during output
- If system timezone not configured: Use environment.timezone.default
- Support pattern matching for multi-location environments (WS-NYC-*, WS-LON-*)
- Invalid timezone name: Error with suggestion

**Connection to private IP from external actor:**
- Allow but warn: "External actor accessing private IP - consider modeling VPN/proxy/compromised perimeter"
- Don't auto-create NAT infrastructure
- User should explicitly model network topology if needed (or note as future enhancement)

## 9. Testing Strategy

### Test Levels

**Unit Tests** (target: 95% coverage)
- All Pydantic models: validation, serialization
- State manager: session/process/connection tracking
- Format validators: constraint DSL evaluation
- Emitters: log format generation (mocked output)
- Time utilities: parsing, duration calculation
- Config loading: env var interpolation, .env file discovery

**Integration Tests** (target: 90% coverage)
- Conversation → scenario file generation (mocked LLM)
- Scenario file → validation → report
- Small scenario end-to-end generation (< 1000 events, deterministic)
- Format definition loading → validation → application
- Checkpoint → resume workflow

**Live Tests** (marked with @pytest.mark.live, not run by default)
- Actual LLM conversation workflows
- Real semantic validation with Bedrock
- TTP research queries
- Full scenario with all LLM calls
- Run manually or in nightly CI builds with API budget

**End-to-End Tests** (run manually or in release pipeline)
- Complete workflow: init → new → validate → generate → evaluate
- Medium dataset: 8 hours, 100 users, all 5 log formats
- Verify output structure, format compliance, consistency
- Performance benchmarks (time to generate, memory usage)

### Test Data

**Fixtures:**

Required scenario files (5):
1. **minimal**: 1 user, 1 system, 1 hour, baseline only
2. **small-realistic**: 20 users, 10 systems, 8 hours, baseline only
3. **attack-single**: 50 users, ransomware scenario
4. **attack-multi**: 100 users, credential stuffing + lateral movement
5. **large-scale**: 100 users, 24 hours, multiple log formats

Sample log files:
- Use synthetic logs generated with early implementation
- Manually validate for correctness
- Commit as test fixtures for regression testing
- 10-20 examples per format (not 100+ - too large)

Mock LLM responses:
- Record actual LLM responses for common scenarios
- Use for unit/integration tests to avoid API costs

**Property Tests:**
- All timestamps within specified window
- All LogonIDs referenced have corresponding 4624 events
- All PIDs referenced have corresponding process creation events
- No orphaned connections (all have start events)

**Regression Tests:**
- Commit validation criteria for scenarios
- Assert structure, key metrics, sample events match expected patterns
- Don't commit full output (too large), just validation rules

### Testing Tools

**Framework:** pytest with plugins
- pytest-cov for coverage
- pytest-asyncio for async tests
- pytest-mock for mocking
- pytest-benchmark for performance tests

**Mocking Strategy:**
- Mock LLM API calls in unit/integration tests (use recorded responses)
- Mock file I/O in unit tests, use temp directories in integration tests
- Mock time/randomness for deterministic tests

**Coverage Requirements:**
- Overall: 95%+
- Core generation engine: 95%+
- Format definitions & validators: 90%+
- CLI/conversation interface: 85%+
- Exclude: `__main__.py`, type stubs, test fixtures

**CI/CD Integration:**
- Run unit + integration tests on every PR
- Enforce coverage thresholds (fail if below target)
- Run live tests nightly with API budget limits
- Run E2E tests before releases

## 10. MVP Scope & Future Considerations

### MVP Phase Breakdown

**Phase 1: Core Generation**
- Basic scenario schema (simplified)
- Single-threaded generation
- Manual state tracking
- 2-3 log formats (Windows Event, Zeek conn, syslog)
- Small datasets only (< 10K events)
- No checkpointing
- Target: Prove the concept works

**Phase 2: Scalability**
- Parallel generation (multiple log types simultaneously)
- Incremental file writing (streaming)
- Progress reporting
- All 5 MVP log formats
- Medium datasets (100K+ events)
- Target: Handle real-world dataset sizes

**Phase 3: Robustness (MVP Release)**
- Checkpointing and resume
- Full error handling and retry logic
- Comprehensive test coverage (95%+)
- Complete documentation (installation, user guide, format definitions, architecture)
- Example scenarios (5 required fixtures + 5-10 additional examples)
- Pre-built persona library (10-15 personas)
- Large dataset support (millions of events)
- Timezone handling
- Target: Production-ready tool

**Timeline Estimate:**
- Phase 1: 2-3 weeks
- Phase 2: 2-3 weeks
- Phase 3: 3-4 weeks
- Total MVP: 7-10 weeks

Note: Phase 3 is the MVP release. Phases 1-2 are internal milestones.

### Future Enhancements

**Short-term (post-MVP):**
- Subjective realism evaluation (LLM-based "does this feel real?")
- Config file inheritance/templating
- PyPI package distribution
- Additional log formats (cloud providers, mobile, databases)
- Performance optimizations (Rust extensions, better parallelization)

**Medium-term:**
- Alternative LLM backends (OpenAI, Ollama, Anthropic native, Gemini)
- Web UI for scenario creation
- Streaming output to SIEM/data lakes
- Log format auto-detection from samples
- Machine learning-based realism scoring

**Long-term:**
- OT/ICS environment simulation
- Real-time log streaming mode (not batch generation)
- Collaborative scenario editing
- Scenario marketplace (share/download scenarios)
- Integration with attack frameworks (CALDERA, Atomic Red Team)

### Architectural Decisions Preserving Future Features

**Must NOT block:**
1. **Additional LLM backends**: Keep LLM client abstracted behind interface, config specifies backend type
2. **Real-time streaming**: State manager and emitters designed to work event-by-event, not requiring full dataset in memory
3. **New log formats**: Format engine is data-driven, adding formats doesn't require code changes
4. **Web UI**: Business logic separated from CLI, can wrap with API layer
5. **Distributed generation**: State can be partitioned (per-user, per-system), enable future map-reduce style parallelization

**Abstractions to maintain:**

Key interfaces to preserve future extensibility:

```python
# LLM Client abstraction (currently Bedrock, future: OpenAI, Ollama, etc.)
class LLMClient(Protocol):
    def chat(self, messages: list[Message]) -> str: ...
    def complete(self, prompt: str) -> str: ...

# Log Emitter base class (uniform interface for all formats)
class LogEmitter(ABC):
    @abstractmethod
    def emit_event(self, event: Event, state: StateManager) -> None: ...

    @abstractmethod
    def flush(self) -> None: ...

# State Manager (encapsulates all runtime state)
class StateManager:
    # Only StateManager can mutate state, emitters read-only
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

**Configuration extensibility:**
- Use nested dicts for format-specific options
- Allow unknown keys (don't fail on new config options from future versions)
- Version scenario file schema explicitly

### Known Limitations

**MVP will NOT:**
- Generate bit-perfect binary EVTX files (XML output by default, binary EVTX optional if python-evtx works)
- Support binary log formats beyond EVTX (Snort will be unified2 or fast alert format, not pcap)
- Perform network traffic capture simulation (packet-level)
- Simulate actual malware execution (this is synthetic, not sandboxing)
- Generate logs for systems we don't have format definitions for
- Guarantee detection rule triggering (depends on SIEM/tool configuration)
- Provide bit-perfect reproducibility (LLM expansion is non-deterministic; save and reuse scenario files)
- Auto-generate complete network topology (external->internal connections flagged with warning)

**Performance bounds (MVP):**
- Max 1000 users (technical limit, not enforced)
- Max 30-day time windows (technical limit, not enforced)
- Single machine execution (no distributed generation)
- Sequential persona activity generation (persona templates applied one at a time)

### Success Metrics

**MVP is successful if:**
1. Can generate realistic 8-hour dataset for 100 users in < 30 minutes
2. Generated logs pass format validation for all 5 MVP formats
3. Cross-log consistency checks pass (no orphaned references)
4. At least 10 example scenarios included and documented
5. 95%+ test coverage achieved
6. 3+ external users successfully generate custom scenarios
7. Generated logs successfully imported into Splunk/ELK without errors

**Quality bar:**
- Security researcher can use generated data for detection rule development
- Threat hunter cannot immediately distinguish synthetic from real logs (structural examination)
- Educator can create reproducible lab exercises with specific ground truth
- Generated datasets exhibit realistic temporal patterns and user behaviors

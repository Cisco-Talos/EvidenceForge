# AGENTS.md - EvidenceForge

This document provides AI coding agents with everything needed to write consistent, idiomatic code for the EvidenceForge project.

## Project Overview

EvidenceForge generates realistic synthetic security logs for cybersecurity threat hunting training and research. The system uses a two-phase hybrid architecture:

**Phase 1 - Scenario Creation (Skill-assisted):** Claude Code Skills guide users through scenario creation via structured interviews. Skills research TTPs via MITRE ATT&CK, expand high-level descriptions into detailed execution plans, and output structured YAML scenario files with companion research markdown.

**Phase 2 - Log Generation (Deterministic):** Generation engine executes the detailed scenario plan WITHOUT any LLM calls, producing large-scale, temporally consistent datasets across multiple log formats (Windows Event Logs, Zeek, Syslog, Snort/Suricata, web logs) with coordinated cross-references (matching LogonIDs, PIDs, session data).

This architecture combines LLM flexibility/realism with deterministic speed, cost-efficiency, and reproducibility.

**Key Principle:** The `eforge` CLI is a deterministic tool. Creative/interactive work happens through Claude Code Skills, not built-in LLM calls. Phase 2 is a deterministic renderer that executes the plan. Never call LLMs during generation.

## 🔴 MANDATORY: Implementation State Tracking

**CRITICAL: Read this section first before doing ANY work on this project.**

This project uses `TODO.md` as the **persistent implementation plan and progress tracker**. This is NOT optional.

### Required Workflow for Every Session

1. **START OF SESSION (BEFORE ANY WORK):**
   - **ALWAYS read `TODO.md` first** to understand:
     - What phase/milestone the project is in
     - What's been completed
     - What's in progress
     - What's next to work on
   - If `TODO.md` doesn't exist, create it with the initial implementation plan based on the PRD

2. **BEFORE STARTING ANY TASK:**
   - Update the task status to `- [ ] **IN PROGRESS**` in `TODO.md`
   - This marks your claim on the work and provides visibility

3. **WHEN COMPLETING TASKS:**
   - **IMMEDIATELY** update `TODO.md` to mark the task as `- [x]` completed
   - Do NOT batch updates - update as soon as each item is done
   - Add notes if the implementation deviated from the plan

4. **WHEN ADDING NEW TASKS:**
   - Add them to `TODO.md` in the appropriate phase/section
   - Use `- [ ]` for pending tasks

### TODO.md Format

Use markdown checkboxes organized by phase/feature:

```markdown
# EvidenceForge Implementation Plan

## Phase 1: Core Generation (Target: 2-3 weeks)

### Setup & Foundation
- [x] Initialize project structure with uv
- [x] Create Pydantic models for configuration
- [ ] **IN PROGRESS** Create Pydantic models for scenario schema
- [ ] Set up pytest infrastructure with fixtures

### State Management
- [ ] Implement StateManager class
- [ ] Add session tracking (ActiveSession)
- [ ] Add process tracking (RunningProcess)
...
```

### Why This Matters

- **Recovery:** If a session is interrupted, the next agent (or you in a new session) can pick up exactly where work left off
- **Visibility:** Always know what's done, what's in progress, what's next
- **Planning:** Break down PRD requirements into concrete, trackable work items
- **History:** Keep completed items checked off to show progress

**Never delete completed tasks** - they show the project's progress and help with debugging/context.

## Tech Stack

**Core:**
- Python 3.11+ (required for latest type hint features including `Self`, `TypedDict` improvements)
- uv for package management, virtual environments, and script running
- Pydantic v2 for all data validation and schema management

**LLM Integration (deferred):**
- Built-in LLM client via boto3/Bedrock is deferred to future phases
- Scenario creation is handled by Claude Code Skills (external to the codebase)
- The `llm/` directory is a placeholder; model IDs kept as reference for future use:
  - Primary model: `anthropic.claude-sonnet-4-6-v1:0` (conversation & validation)
  - Research model: `anthropic.claude-sonnet-4-6-v1:0` (TTP research)
  - Generation model: `anthropic.claude-haiku-4-5-v1:0` (cost optimization for bulk tasks)

**CLI & Output:**
- Typer for CLI framework (excellent Pydantic integration)
- Rich for progress bars, tables, and console formatting
- Jinja2 for log format templates
- PyYAML for configuration/scenario parsing
- pytz for timezone handling (UTC internal, configurable output)

**Testing:**
- pytest with pytest-cov, pytest-asyncio, pytest-mock, pytest-benchmark
- Separate test markers: `@pytest.mark.live` for tests requiring LLM API (not run by default)
- Target coverage: 95%+ overall, 95%+ for core generation engine

**Format Support:**
- python-evtx (try first) or XML fallback for Windows Event Logs
- json-logic-py for format definition validation rules
- Standard library json/csv for text formats

## Project Structure

```
log-generator/
├── pyproject.toml               # uv project config
├── README.md
├── AGENTS.md                    # This file
├── LICENSE
├── config.example.yaml          # Example configuration
├── .env.example                 # Example environment variables
│
├── skills/
│   └── eforge/                  # Claude Code Skills for scenario creation
│       ├── scenario.md          # /eforge scenario - guided scenario creation
│       └── generate.md          # /eforge generate - generation workflow
│
├── personas/                    # Pre-built persona library
│   └── ...                      # Persona YAML files (developer, accountant, etc.)
│
├── src/
│   └── log_generator/
│       ├── __init__.py
│       ├── __main__.py          # CLI entry point
│       │
│       ├── cli/
│       │   ├── __init__.py
│       │   └── commands.py      # Typer CLI command implementations
│       │
│       ├── models/
│       │   ├── __init__.py
│       │   ├── config.py        # Pydantic models for config.yaml
│       │   ├── scenario.py      # Pydantic models for scenario files
│       │   ├── format_def.py    # Pydantic models for format definitions
│       │   └── state.py         # Runtime state models (dataclasses)
│       │
│       ├── validation/
│       │   ├── __init__.py
│       │   └── schema.py        # Pydantic-based schema validation
│       │
│       ├── generation/
│       │   ├── __init__.py
│       │   ├── engine.py        # Main generation orchestrator (includes persona logic)
│       │   ├── state_manager.py # State tracking (sessions, processes, connections)
│       │   ├── activity.py      # Activity script execution (includes persona behavior)
│       │   ├── network_visibility.py  # Network visibility/perspective logic
│       │   └── emitters/
│       │       ├── __init__.py
│       │       ├── base.py          # Base emitter ABC
│       │       ├── bash_history.py  # Bash history emitter
│       │       ├── ecar.py          # ECAR emitter
│       │       ├── snort.py         # Snort/Suricata emitter
│       │       ├── syslog.py        # Syslog emitter
│       │       ├── web.py           # Web/proxy log emitter
│       │       ├── windows.py       # Windows Event Log emitter
│       │       └── zeek.py          # Zeek log emitter
│       │
│       ├── formats/
│       │   ├── __init__.py
│       │   ├── loader.py        # Format definition loader
│       │   ├── validator.py     # Format constraint validator (JSON Logic DSL)
│       │   └── definitions/
│       │       ├── windows_event.yaml
│       │       ├── zeek.yaml
│       │       ├── syslog.yaml
│       │       ├── snort.yaml
│       │       └── web.yaml
│       │
│       ├── llm/                 # Placeholder for future built-in LLM integration
│       │   └── __init__.py
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
│   ├── conftest.py              # Shared pytest fixtures
│   ├── unit/                    # Fast unit tests
│   │   ├── test_models.py
│   │   ├── test_validation.py
│   │   ├── test_state_manager.py
│   │   └── ...
│   ├── integration/             # Multi-component tests
│   │   ├── test_scenario_creation.py
│   │   ├── test_generation_small.py
│   │   └── ...
│   ├── live/                    # Tests requiring LLM API (@pytest.mark.live)
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

## Dependency Management

**Adding Dependencies:**
```bash
# Add runtime dependency
uv add package-name

# Add dev dependency
uv add --dev package-name

# Add with version constraint
uv add "package-name>=1.0,<2.0"
```

**Running Commands:**
```bash
# Run tests
uv run pytest

# Run the CLI
uv run python -m log_generator --help

# Run with specific Python version
uv run --python 3.11 pytest
```

**Important:** Never use `pip` directly. Always use `uv` for dependency management. The `pyproject.toml` is the source of truth.

## Code Style & Standards

### General Principles

1. **Type hints everywhere** - All functions, methods, and variables must have type hints
2. **Pydantic for data** - Use Pydantic models for any structured data (configs, scenarios, API responses)
3. **Explicit over implicit** - Prefer clarity over cleverness
4. **Fail fast** - Validate inputs early, fail with clear error messages
5. **No magic** - Avoid metaclasses, dynamic imports, or other "clever" patterns unless absolutely necessary

### PEP 8 Compliance

- Line length: 100 characters (not 79)
- Indentation: 4 spaces
- Use double quotes for strings (except to avoid escaping)
- Import order: stdlib, third-party, local (use `isort` with black profile)

### Type Hints

**Required:**
```python
from typing import Any
from collections.abc import Sequence
from pathlib import Path

# Function signatures - always include return type
def process_scenario(scenario_path: Path, config: Config) -> ScenarioResult:
    ...

# Class attributes with defaults
class GenerationConfig:
    base_directory: Path = Path("./output")
    compression: bool = False

# Variables when type isn't obvious
user_map: dict[str, User] = {}
events: list[Event] = []
```

**Use modern type hints (Python 3.11+):**
```python
# Good: Use built-in types
def get_users() -> list[User]:
    ...

def map_ids(ids: list[int]) -> dict[int, str]:
    ...

# Bad: Don't use typing.List, typing.Dict (deprecated)
from typing import List, Dict
def get_users() -> List[User]:  # Wrong
    ...
```

**Use `None` for optional returns, not `Optional`:**
```python
# Good
def find_user(username: str) -> User | None:
    ...

# Bad
from typing import Optional
def find_user(username: str) -> Optional[User]:  # Verbose
    ...
```

### Docstrings

Use Google-style docstrings for all public functions, classes, and modules:

```python
def generate_logs(scenario: Scenario, output_dir: Path) -> GenerationResult:
    """Generate synthetic logs from a scenario specification.

    This function orchestrates the entire log generation process without
    making any LLM API calls. All creative decisions must have been made
    during the scenario creation phase.

    Args:
        scenario: Validated scenario specification
        output_dir: Directory to write generated logs

    Returns:
        GenerationResult containing event counts, timing, and paths

    Raises:
        ValidationError: If scenario fails schema validation
        InsufficientDiskSpaceError: If output_dir lacks required space
        GenerationError: If unrecoverable error occurs during generation

    Example:
        >>> scenario = load_scenario("attack.yaml")
        >>> result = generate_logs(scenario, Path("./output"))
        >>> print(f"Generated {result.total_events} events")
    """
```

**Docstring rules:**
- Public API (functions/classes used by other modules): Required
- Private functions (starting with `_`): Optional but encouraged for complex logic
- Test functions: Optional (test name should be self-documenting)
- One-line docstrings for simple utilities are acceptable

### Error Handling

**Always use specific exception types:**
```python
# Good
class ValidationError(Exception):
    """Raised when validation fails."""

class InsufficientDiskSpaceError(Exception):
    """Raised when output directory lacks required disk space."""

raise ValidationError(f"User '{username}' not found in environment.users")

# Bad
raise Exception("validation failed")  # Too generic
```

**Define custom exceptions in appropriate modules:**
- `models/scenario.py` - Scenario-specific exceptions
- `generation/engine.py` - Generation exceptions
- `validation/schema.py` - Validation exceptions

**Exception hierarchy:**
```python
class EvidenceForgeError(Exception):
    """Base exception for all EvidenceForge errors."""

class ValidationError(EvidenceForgeError):
    """Base validation error."""

class SchemaValidationError(ValidationError):
    """Schema validation failed."""

class SemanticValidationError(ValidationError):
    """Semantic validation failed."""
```

### Logging

**Use Python's logging module, configured in `utils/logging.py`:**
```python
import logging

logger = logging.getLogger(__name__)

# Levels:
logger.debug("Detailed state: %s", state)  # File only (not console)
logger.info("Starting generation for %d users", user_count)  # File only
logger.warning("User activity on unassigned system: %s", hostname)  # Console + file
logger.error("Failed to load format definition: %s", error)  # Console + file
```

**Logging rules:**
- Never log secrets (AWS credentials, API keys)
- Never log full exception tracebacks in error messages to users (log to file only)
- Use `%s` formatting, not f-strings (lazy evaluation)
- Log retries at DEBUG level, final failure at ERROR level
- Log progress milestones at INFO level

**Console vs File:**
- Console: `warning` and `error` only (configurable via `logging.console_level`)
- File: All levels based on `logging.level` config (default: `info`)
- File location: `{output_dir}/generation.log` for generate command

### Pydantic Models

**All structured data uses Pydantic v2:**
```python
from pydantic import BaseModel, Field, field_validator
from pathlib import Path
from datetime import datetime

class ScenarioConfig(BaseModel):
    """Configuration for scenario generation."""

    name: str = Field(..., min_length=1, description="Scenario name")
    description: str
    time_window: TimeWindow
    environment: Environment

    # Custom validation
    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.replace("-", "").replace("_", "").isalnum():
            raise ValueError("Name must contain only alphanumeric, dash, underscore")
        return v

    # Configuration
    model_config = {
        "frozen": False,  # Allow mutation if needed for state tracking
        "extra": "forbid",  # Reject unknown fields
        "validate_assignment": True,  # Validate on field assignment
    }
```

**Pydantic rules:**
- Use `Field()` for descriptions and constraints
- Use `field_validator` for complex validation logic
- Set `extra="forbid"` to catch typos/unknown fields
- Use `frozen=True` for immutable configs
- Provide clear error messages in validators

### Path Handling

**Always use `pathlib.Path`, never string paths:**
```python
from pathlib import Path

# Good
def load_scenario(scenario_path: Path) -> Scenario:
    if not scenario_path.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_path}")

    with scenario_path.open("r") as f:
        data = yaml.safe_load(f)
    return Scenario(**data)

# Bad
def load_scenario(scenario_path: str) -> Scenario:  # String path
    if not os.path.exists(scenario_path):  # os.path instead of Path
        ...
```

**Path rules:**
- Function parameters: Use `Path` type hint
- Path operations: Use Path methods (`.exists()`, `.mkdir()`, `.read_text()`)
- Resolve paths early: `path = Path(user_input).resolve()` at boundaries
- Check paths before operations: Fail fast with clear messages

## Configuration & Secrets

### Configuration Hierarchy

Loaded in this order (later overrides earlier):
1. Default values in code
2. System-wide config: `~/.config/log-generator/config.yaml` (if exists)
3. `.env` file (if exists, search from CWD upward to home, stop at first found)
4. Project config: `./config.yaml`
5. Command-line arguments

### Environment Variable Interpolation

Config files support `${VAR_NAME}` syntax:
```yaml
aws:
  profile: ${AWS_PROFILE}  # Replaced with env var value
  region: ${AWS_REGION}

bedrock:
  model_primary: ${MODEL_PRIMARY:-anthropic.claude-sonnet-4-6-v1:0}  # With default
```

**Implementation in `utils/config.py`:**
```python
import os
import re

def interpolate_env_vars(value: str) -> str:
    """Replace ${VAR_NAME} and ${VAR_NAME:-default} with env var values."""
    pattern = r'\$\{([^}:]+)(?::-(.[^}]*))?\}'

    def replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(2)
        return os.environ.get(var_name, default or "")

    return re.sub(pattern, replace, value)
```

### Secrets Handling

**AWS Credentials:**
- NEVER store in config files
- Use boto3 credential chain (env vars → `~/.aws/credentials` → IAM role)
- Config specifies profile name only: `aws.profile: "default"`

**Logging:**
- Never log credential values
- Never include secrets in error messages or tracebacks
- Redact in debug output: `logger.debug("Config: %s", redact_secrets(config))`

**Implementation pattern:**
```python
REDACTED = "***REDACTED***"

def redact_secrets(obj: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive fields for safe logging."""
    sensitive_keys = {"password", "secret", "key", "token", "credential"}

    result = {}
    for k, v in obj.items():
        if any(sensitive in k.lower() for sensitive in sensitive_keys):
            result[k] = REDACTED
        elif isinstance(v, dict):
            result[k] = redact_secrets(v)
        else:
            result[k] = v
    return result
```

## Key Architecture Patterns

### LLM Client Abstraction (Future)

The LLM client abstraction is planned for future built-in LLM integration. Currently, scenario creation is handled by Claude Code Skills (external to the codebase). The patterns below are kept as reference for when the `llm/` module is implemented.

The LLM client will be abstracted behind a Protocol to support future backends (OpenAI, Ollama, etc.):

```python
from typing import Protocol

class LLMClient(Protocol):
    """Protocol for LLM client implementations."""

    def chat(self, messages: list[dict[str, str]], **kwargs) -> str:
        """Send chat messages and return response."""
        ...

    def complete(self, prompt: str, **kwargs) -> str:
        """Complete a prompt and return response."""
        ...
```

**Current implementation (Bedrock):**
```python
import boto3
from typing import Any

class BedrockClient:
    """AWS Bedrock LLM client implementation."""

    def __init__(self, model_id: str, region: str, profile: str | None = None):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.client = session.client("bedrock-runtime")
        self.model_id = model_id

    def chat(self, messages: list[dict[str, str]], **kwargs) -> str:
        """Send chat messages to Bedrock."""
        # Bedrock-specific implementation
        ...
```

**Usage pattern (future):**
```python
# Example for future built-in LLM integration
llm = BedrockClient(
    model_id=config.bedrock.model_primary,
    region=config.aws.region,
    profile=config.aws.profile
)

response = llm.chat(messages=[
    {"role": "system", "content": system_prompt},
    {"role": "user", "content": user_input}
])
```

**Critical:** Never call LLM during generation phase. Scenario creation is currently handled by Claude Code Skills, not built-in LLM calls.

### Retry Logic with Backoff

**LLM API calls must use exponential backoff:**
```python
import time
import random
from typing import TypeVar, Callable

T = TypeVar("T")

class RetryableError(Exception):
    """Errors that should trigger retry."""

def retry_with_backoff(
    func: Callable[..., T],
    max_attempts: int = 3,
    base_delay: float = 2.0,
    jitter: float = 0.25
) -> T:
    """Retry function with exponential backoff.

    Args:
        func: Function to retry
        max_attempts: Maximum retry attempts (default: 3)
        base_delay: Initial delay in seconds (default: 2.0)
        jitter: Random jitter as fraction of delay (default: 0.25)

    Returns:
        Function result

    Raises:
        Last exception if all retries exhausted
    """
    for attempt in range(max_attempts):
        try:
            return func()
        except RetryableError as e:
            if attempt == max_attempts - 1:
                raise

            # Calculate delay: 2s, 4s, 8s with ±25% jitter
            delay = base_delay * (2 ** attempt)
            jitter_amount = delay * jitter * (random.random() * 2 - 1)
            sleep_time = delay + jitter_amount

            logger.info("Retry %d/%d after error: %s (sleeping %.1fs)",
                       attempt + 1, max_attempts, e, sleep_time)
            time.sleep(sleep_time)

    raise RuntimeError("Retry logic error")  # Should never reach here
```

**Retryable errors:**
- 429 (rate limit)
- 500, 502, 503 (server errors)
- Network errors (connection timeout, DNS failure)

**Non-retryable errors:**
- 400 (bad request - our fault)
- 401 (unauthorized - credential issue)
- 403 (forbidden - permission issue)
- 404 (not found - wrong endpoint)

### State Management

The `StateManager` is the single source of truth for runtime state during generation:

```python
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ActiveSession:
    """An active logon session."""
    logon_id: str
    username: str
    system: str
    logon_type: int
    start_time: datetime
    source_ip: str

@dataclass
class RunningProcess:
    """A running process."""
    pid: int
    parent_pid: int
    image: str
    command_line: str
    username: str
    system: str
    start_time: datetime
    integrity_level: str

class StateManager:
    """Manages all runtime state during generation.

    Thread-safe for read access (multiple emitters reading state).
    Write access is single-threaded (only orchestrator mutates state).
    """

    def __init__(self):
        self._sessions: dict[str, ActiveSession] = {}
        self._processes: dict[str, dict[int, RunningProcess]] = {}  # system -> pid -> process
        self._connections: dict[str, OpenConnection] = {}
        self._dns_cache: dict[str, str] = {}
        self._next_pid: dict[str, int] = {}  # system -> next PID

    def create_session(
        self,
        username: str,
        system: str,
        logon_type: int,
        start_time: datetime,
        source_ip: str = "-"
    ) -> str:
        """Create new logon session and return LogonID."""
        logon_id = self._generate_logon_id()
        session = ActiveSession(
            logon_id=logon_id,
            username=username,
            system=system,
            logon_type=logon_type,
            start_time=start_time,
            source_ip=source_ip
        )
        self._sessions[logon_id] = session
        logger.debug("Created session %s for %s on %s", logon_id, username, system)
        return logon_id

    def get_active_sessions(self, system: str | None = None) -> dict[str, ActiveSession]:
        """Get all active sessions, optionally filtered by system."""
        if system is None:
            return self._sessions.copy()
        return {
            lid: s for lid, s in self._sessions.items()
            if s.system == system
        }

    def create_process(
        self,
        system: str,
        image: str,
        command_line: str,
        username: str,
        parent_pid: int,
        start_time: datetime,
        integrity_level: str = "Medium"
    ) -> int:
        """Create new process and return PID."""
        if system not in self._processes:
            self._processes[system] = {}
            self._next_pid[system] = 4  # Start from PID 4 (System=4, realistic)

        pid = self._next_pid[system]
        self._next_pid[system] += 1

        process = RunningProcess(
            pid=pid,
            parent_pid=parent_pid,
            image=image,
            command_line=command_line,
            username=username,
            system=system,
            start_time=start_time,
            integrity_level=integrity_level
        )
        self._processes[system][pid] = process
        logger.debug("Created process PID=%d (%s) on %s", pid, image, system)
        return pid

    # Similar methods for connections, DNS cache, etc.
```

**State rules:**
- StateManager is the ONLY place to track sessions, processes, connections
- Emitters READ state (to get LogonIDs, PIDs for events)
- Orchestrator WRITES state (creates sessions/processes as scenario executes)
- No automatic cleanup (realistic incompleteness is acceptable per PRD)
- Thread-safe for reads, single-threaded for writes

### Log Emitters

All log format emitters inherit from `LogEmitter` ABC:

```python
from abc import ABC, abstractmethod
from pathlib import Path

class LogEmitter(ABC):
    """Base class for all log format emitters."""

    def __init__(self, output_path: Path, state_manager: StateManager):
        self.output_path = output_path
        self.state_manager = state_manager
        self._buffer: list[str] = []
        self._buffer_size = 10_000  # Flush every 10K events

    @abstractmethod
    def emit_event(self, event: Event) -> None:
        """Emit a single event to the log.

        Args:
            event: Event to emit (type depends on emitter)
        """
        pass

    @abstractmethod
    def flush(self) -> None:
        """Flush buffered events to disk."""
        pass

    def _write_buffered(self, line: str) -> None:
        """Add line to buffer, flush if needed."""
        self._buffer.append(line)
        if len(self._buffer) >= self._buffer_size:
            self.flush()
```

**Example emitter (Zeek conn.log):**
```python
from datetime import datetime

class ZeekConnEmitter(LogEmitter):
    """Zeek connection log emitter."""

    def emit_event(self, event: ConnectionEvent) -> None:
        """Emit a Zeek conn.log line."""
        # Get connection state from StateManager
        conn = self.state_manager.get_connection(event.conn_id)

        # Format as TSV
        line = "\t".join([
            str(event.timestamp.timestamp()),  # ts
            conn.conn_id,  # uid
            conn.src_ip,  # id.orig_h
            str(conn.src_port),  # id.orig_p
            conn.dst_ip,  # id.resp_h
            str(conn.dst_port),  # id.resp_p
            conn.protocol,  # proto
            "-",  # service (can be "-" if unknown)
            str(conn.duration),  # duration
            str(conn.bytes_sent),  # orig_bytes
            str(conn.bytes_received),  # resp_bytes
            conn.state,  # conn_state
            # ... additional fields
        ])

        self._write_buffered(line)

    def flush(self) -> None:
        """Write buffer to disk."""
        if not self._buffer:
            return

        with self.output_path.open("a") as f:
            f.write("\n".join(self._buffer) + "\n")

        logger.debug("Flushed %d events to %s", len(self._buffer), self.output_path)
        self._buffer.clear()
```

**Emitter rules:**
- Read state from StateManager, never mutate it
- Buffer writes (10K events), use atomic flush
- Use Jinja2 templates from format definitions for rendering
- Handle timezone conversion (UTC → system/format timezone)
- Each emitter runs in separate thread, writes to separate file

### Format Definitions

Format definitions are YAML files, not code. This enables adding formats without code changes:

```yaml
# formats/definitions/windows_event.yaml
format:
  name: windows_event
  description: Windows Event Log
  category: windows

common_fields:
  - name: TimeCreated
    type: datetime
    required: true
  - name: EventID
    type: integer
    required: true
    range: [1, 65535]
  - name: Computer
    type: hostname
    required: true

variants:
  - name: Security
    description: Security channel events
    fields:
      - name: LogonID
        type: hex_string
        required: false
        pattern: "^0x[0-9A-Fa-f]+$"
      - name: TargetUserName
        type: string
        required: false
      # ... more fields

    validators:
      - rule:
          # JSON Logic: Success status (0x0) can't have FailureReason
          and:
            - "==": [{"var": "Status"}, "0x0"]
            - "!=": [{"var": "FailureReason"}, null]
        error: "Successful logon cannot have FailureReason"

output_template: |
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>{{ EventID }}</EventID>
      <Computer>{{ Computer }}</Computer>
      <TimeCreated SystemTime="{{ TimeCreated.isoformat() }}" />
    </System>
    <EventData>
      {% if LogonID %}<Data Name="LogonID">{{ LogonID }}</Data>{% endif %}
      {% if TargetUserName %}<Data Name="TargetUserName">{{ TargetUserName }}</Data>{% endif %}
    </EventData>
  </Event>
```

**Format loader in `formats/loader.py`:**
```python
import yaml
from pathlib import Path
from pydantic import BaseModel

class FormatDefinition(BaseModel):
    """Parsed format definition."""
    name: str
    description: str
    category: str
    common_fields: list[FieldDefinition]
    variants: list[VariantDefinition]
    output_template: str

def load_format(format_name: str) -> FormatDefinition:
    """Load format definition from YAML file."""
    format_path = Path(__file__).parent / "definitions" / f"{format_name}.yaml"

    if not format_path.exists():
        raise ValueError(f"Unknown format: {format_name}")

    with format_path.open("r") as f:
        data = yaml.safe_load(f)

    return FormatDefinition(**data)
```

### Timezone Handling

**Internal representation: Always UTC**
```python
from datetime import datetime, timezone

# Parse user input (assume UTC if no timezone)
def parse_timestamp(ts_str: str) -> datetime:
    """Parse ISO 8601 timestamp to UTC datetime."""
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# Store internally
scenario.time_window.start = parse_timestamp("2026-01-15T08:00:00Z")
```

**Output conversion: System/format timezone**
```python
import pytz

def convert_to_output_timezone(dt: datetime, system: str, config: ScenarioConfig) -> datetime:
    """Convert UTC datetime to output timezone for system."""
    # Get timezone for this system
    tz_name = get_system_timezone(system, config)
    tz = pytz.timezone(tz_name)
    return dt.astimezone(tz)

def get_system_timezone(system: str, config: ScenarioConfig) -> str:
    """Get timezone for a system, checking pattern overrides."""
    # Check per-system overrides
    if config.environment.timezone.systems:
        for pattern, tz_name in config.environment.timezone.systems.items():
            if fnmatch.fnmatch(system, pattern):
                return tz_name

    # Fall back to default
    return config.environment.timezone.default
```

**Timezone rules:**
- Store all datetimes in UTC internally (use `datetime.timezone.utc`)
- Convert to output timezone only when rendering logs
- Support per-system timezone overrides with pattern matching
- Default timezone from `environment.timezone.default`

## CLI Design Patterns

### Typer Conventions

```python
import typer
from pathlib import Path
from typing import Annotated

app = typer.Typer(
    name="log-generator",
    help="Generate realistic synthetic security logs",
    add_completion=False  # Disable shell completion for MVP
)

@app.command()
def init(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path to write config file")
    ] = Path("./config.yaml")
) -> None:
    """Initialize a new project with example configuration."""
    try:
        create_example_config(output)
        typer.echo(f"Created example config: {output}")
        typer.echo("Edit the file to configure AWS credentials and models.")
    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)

@app.command()
def generate(
    scenario_file: Annotated[
        Path,
        typer.Argument(help="Path to scenario YAML file")
    ],
    config: Annotated[
        Path,
        typer.Option("--config", "-c", help="Path to config file")
    ] = Path("./config.yaml"),
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Override output directory")
    ] = None,
    resume: Annotated[
        bool,
        typer.Option("--resume", help="Resume from last checkpoint")
    ] = False
) -> None:
    """Generate logs from a scenario file."""
    try:
        # Load and validate
        cfg = load_config(config)
        scenario = load_scenario(scenario_file)

        # Run generation
        result = run_generation(scenario, cfg, output, resume)

        typer.echo(f"✓ Generated {result.total_events} events")
        typer.echo(f"  Output: {result.output_dir}")

    except ValidationError as e:
        typer.echo(f"Validation Error: {e}", err=True)
        raise typer.Exit(code=2)
    except GenerationError as e:
        typer.echo(f"Generation Error: {e}", err=True)
        raise typer.Exit(code=21)
    except KeyboardInterrupt:
        typer.echo("\nInterrupted by user", err=True)
        raise typer.Exit(code=130)
```

### Exit Codes

**Standard exit codes (must follow PRD spec):**

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Input Error | Malformed YAML or file I/O error |
| 2 | Schema Validation | Pydantic validation failure |
| 3 | Semantic Validation | LLM-detected logical inconsistencies |
| 10 | LLM API Failure | Persistent LLM API errors |
| 11 | LLM Timeout | LLM operation exceeded timeout |
| 20 | Resource Exhaustion | Insufficient disk space or memory |
| 21 | Generation Error | Invalid state or unrecoverable generation failure |
| 22 | Format Error | Format definition loading/validation error |
| 130 | SIGINT | User interrupted (Ctrl+C) |

**Implementation:**
```python
class ExitCode:
    """Standard exit codes for CLI."""
    SUCCESS = 0
    INPUT_ERROR = 1
    SCHEMA_VALIDATION = 2
    SEMANTIC_VALIDATION = 3
    LLM_API_FAILURE = 10
    LLM_TIMEOUT = 11
    RESOURCE_EXHAUSTION = 20
    GENERATION_ERROR = 21
    FORMAT_ERROR = 22
    SIGINT = 130

# Usage in CLI
try:
    validate_scenario(scenario)
except SchemaValidationError:
    raise typer.Exit(code=ExitCode.SCHEMA_VALIDATION)
```

### Progress Reporting

Use Rich for progress bars:
```python
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

def generate_with_progress(scenario: Scenario) -> GenerationResult:
    """Generate logs with progress bar."""
    total_duration = (scenario.time_window.end - scenario.time_window.start).total_seconds()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task(
            f"Generating {scenario.name}",
            total=total_duration
        )

        # Generation loop
        for current_time in time_range(scenario.time_window.start, scenario.time_window.end):
            # ... generate events at current_time

            elapsed = (current_time - scenario.time_window.start).total_seconds()
            progress.update(task, completed=elapsed)

    return result
```

## Testing Requirements

### Test Organization

```
tests/
├── unit/           # Fast, isolated tests (no I/O, no network)
├── integration/    # Multi-component tests (file I/O OK, no network)
├── live/           # Tests requiring LLM API (marked @pytest.mark.live)
└── fixtures/       # Shared test data
```

### Coverage Targets

- Overall: 95%+
- Core generation engine: 95%+
- Format definitions & validators: 90%+
- CLI/conversation interface: 85%+
- Exclude: `__main__.py`, type stubs, test fixtures

### Pytest Conventions

**Test file naming:** `test_<module_name>.py`
**Test function naming:** `test_<function>_<scenario>_<expected_result>`

```python
import pytest
from pathlib import Path
from log_generator.models.scenario import Scenario, ValidationError

def test_scenario_load_valid_file_returns_scenario(tmp_path: Path):
    """Test that loading a valid scenario file returns a Scenario object."""
    # Arrange
    scenario_file = tmp_path / "test.yaml"
    scenario_file.write_text("""
version: "1.0"
name: "test-scenario"
description: "Test scenario"
# ... minimal valid scenario
""")

    # Act
    scenario = Scenario.load(scenario_file)

    # Assert
    assert scenario.name == "test-scenario"
    assert scenario.version == "1.0"

def test_scenario_load_invalid_yaml_raises_validation_error(tmp_path: Path):
    """Test that loading invalid YAML raises ValidationError."""
    # Arrange
    scenario_file = tmp_path / "bad.yaml"
    scenario_file.write_text("invalid: yaml: content:")

    # Act & Assert
    with pytest.raises(ValidationError):
        Scenario.load(scenario_file)

@pytest.mark.live
def test_conversation_creates_valid_scenario():
    """Test full conversation flow creates valid scenario (requires LLM API)."""
    # This test makes real LLM API calls
    # Only run with: pytest -m live
    ...
```

### Fixtures

**Common fixtures in `tests/conftest.py`:**
```python
import pytest
from pathlib import Path
from log_generator.models.config import Config
from log_generator.models.scenario import Scenario

@pytest.fixture
def tmp_output_dir(tmp_path: Path) -> Path:
    """Create temporary output directory."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir

@pytest.fixture
def minimal_scenario() -> Scenario:
    """Return minimal valid scenario for testing."""
    return Scenario(
        version="1.0",
        name="minimal",
        description="Minimal test scenario",
        environment=Environment(
            users=[User(username="testuser", full_name="Test User")],
            systems=[System(hostname="test-ws-01", ip="10.0.0.10", os="Windows 10")]
        ),
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, 8, 0, 0, tzinfo=timezone.utc),
            duration="1h"
        ),
        # ... minimal required fields
    )

@pytest.fixture
def mock_llm_client(monkeypatch):
    """Mock LLM client to avoid API calls in tests."""
    class MockLLMClient:
        def chat(self, messages, **kwargs):
            return "Mock LLM response"

    client = MockLLMClient()
    monkeypatch.setattr("log_generator.llm.client.BedrockClient", lambda *args, **kwargs: client)
    return client
```

### Mocking Strategy

**Mock LLM API calls:**
```python
@pytest.fixture
def mock_bedrock_response(monkeypatch):
    """Mock Bedrock API response."""
    def mock_invoke_model(*args, **kwargs):
        return {
            "body": json.dumps({
                "content": [{"text": "Mocked LLM response"}]
            }).encode()
        }

    monkeypatch.setattr("boto3.Session.client", lambda *args, **kwargs: type("MockClient", (), {
        "invoke_model": mock_invoke_model
    })())
```

**Mock time for deterministic tests:**
```python
from unittest.mock import patch
from datetime import datetime

def test_event_timestamp_uses_current_time():
    """Test that events use current time."""
    fixed_time = datetime(2026, 1, 1, 12, 0, 0)

    with patch("log_generator.generation.engine.datetime") as mock_datetime:
        mock_datetime.now.return_value = fixed_time
        mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

        event = create_event()
        assert event.timestamp == fixed_time
```

**Use `tmp_path` for file I/O:**
```python
def test_generate_writes_output_files(tmp_path: Path, minimal_scenario: Scenario):
    """Test that generation writes output files."""
    output_dir = tmp_path / "output"

    result = generate_logs(minimal_scenario, output_dir)

    assert (output_dir / "windows_security.xml").exists()
    assert (output_dir / "zeek_conn.log").exists()
```

### Property-Based Tests

Use Hypothesis for property-based testing where appropriate:
```python
from hypothesis import given, strategies as st

@given(st.integers(min_value=1, max_value=1000))
def test_state_manager_creates_unique_pids(user_count: int):
    """Test that StateManager never creates duplicate PIDs on same system."""
    state = StateManager()
    pids = set()

    for _ in range(user_count):
        pid = state.create_process(
            system="test-host",
            image="test.exe",
            command_line="test.exe",
            username="testuser",
            parent_pid=4,
            start_time=datetime.now(timezone.utc)
        )
        assert pid not in pids, f"Duplicate PID: {pid}"
        pids.add(pid)
```

## Skills

Claude Code Skills handle the interactive, creative aspects of scenario creation -- work that was originally planned as a built-in conversational CLI.

**Location:** `skills/eforge/` directory

**Installation:**
```bash
# Install skills for the current project
eforge install-skills --project

# Install skills globally
eforge install-skills --global
```

**MVP Skills:**
- `/eforge scenario` -- Guided scenario creation through a structured interview, producing a validated YAML scenario file
- `/eforge generate` -- Generation workflow that validates a scenario and runs the deterministic engine

**Key design points:**
- Skills are markdown prompt files (`.md`), not Python code
- They run inside Claude Code, not inside the `eforge` CLI process
- Skills follow a hybrid interview pattern: structured questions first (environment, users, systems), then free-form refinement
- Skills reference the scenario schema from `docs/scenario-reference.md`

### Adding a New Skill

1. Create `skills/eforge/{name}.md` with the skill prompt
2. Follow the hybrid interview pattern: structured questions first, then free-form elaboration
3. Reference the scenario schema from `docs/scenario-reference.md` to ensure output validity
4. Test interactively by running the skill in Claude Code
5. Update the `install-skills` command if needed to include the new skill

## Common Pitfalls

### DO NOT

1. **Call LLMs during generation** - All creative/LLM work happens via Claude Code Skills before generation
   ```python
   # WRONG
   def generate_event(event_type: str) -> Event:
       details = llm.chat([{"role": "user", "content": f"Generate {event_type}"}])  # NO!
       return parse_details(details)

   # CORRECT
   def generate_event(event_spec: EventSpec) -> Event:
       # event_spec was created by LLM during scenario creation
       return Event.from_spec(event_spec)
   ```

2. **Use string paths instead of Path objects**
   ```python
   # WRONG
   def load_file(path: str):
       with open(path) as f:  # Use Path
           ...

   # CORRECT
   def load_file(path: Path):
       with path.open() as f:
           ...
   ```

3. **Store non-UTC datetimes internally**
   ```python
   # WRONG
   event.timestamp = datetime.now()  # No timezone

   # CORRECT
   event.timestamp = datetime.now(timezone.utc)
   ```

4. **Mutate StateManager from emitters**
   ```python
   # WRONG
   class WindowsEmitter:
       def emit_logon(self, user: str):
           logon_id = self.state.create_session(...)  # Emitter mutating state!

   # CORRECT
   class GenerationEngine:
       def execute_logon(self, user: str):
           logon_id = self.state.create_session(...)  # Orchestrator mutates
           self.windows_emitter.emit_logon(logon_id)  # Emitter uses existing state
   ```

5. **Catch generic exceptions**
   ```python
   # WRONG
   try:
       do_something()
   except Exception:  # Too broad
       pass

   # CORRECT
   try:
       do_something()
   except SpecificError as e:
       logger.error("Failed: %s", e)
       raise
   ```

6. **Log secrets**
   ```python
   # WRONG
   logger.debug("AWS config: %s", boto3_session.get_credentials())

   # CORRECT
   logger.debug("AWS config: region=%s, profile=%s", region, profile)
   ```

7. **Use mutable default arguments**
   ```python
   # WRONG
   def add_user(users: list[User] = []):  # Shared mutable default!
       users.append(User())
       return users

   # CORRECT
   def add_user(users: list[User] | None = None) -> list[User]:
       if users is None:
           users = []
       users.append(User())
       return users
   ```

8. **Forget to flush emitter buffers**
   ```python
   # WRONG
   class LogEmitter:
       def emit_event(self, event: Event):
           self._buffer.append(event)
           # Forgot to flush!

   # CORRECT
   class LogEmitter:
       def emit_event(self, event: Event):
           self._buffer.append(event)
           if len(self._buffer) >= self._buffer_size:
               self.flush()

       def close(self):
           self.flush()  # Final flush on close
   ```

### DO

1. **Validate early, fail fast**
   ```python
   def generate_logs(scenario: Scenario):
       # Validate before starting expensive work
       validate_schema(scenario)
       check_disk_space(scenario.output.destination)
       check_format_definitions(scenario.output.logs)

       # Now do the work
       ...
   ```

2. **Use context managers for resources**
   ```python
   # File I/O
   with output_path.open("w") as f:
       f.write(data)

   # Progress bars
   with Progress() as progress:
       task = progress.add_task("Working...", total=100)
       ...

   # Emitters
   with emitter_manager.open_emitters(formats) as emitters:
       for event in events:
           emitters[event.format].emit(event)
   ```

3. **Provide actionable error messages**
   ```python
   # WRONG
   raise ValueError("Invalid input")

   # CORRECT
   raise ValidationError(
       f"User '{username}' not found in environment.users. "
       f"Add user to scenario or use ANY_USER_FROM:persona pattern."
   )
   ```

4. **Use type hints for complex structures**
   ```python
   # WRONG
   def process_events(events):
       ...

   # CORRECT
   def process_events(events: list[Event]) -> dict[str, list[Event]]:
       """Group events by system.

       Args:
           events: List of events to process

       Returns:
           Dictionary mapping system hostname to events on that system
       """
       ...
   ```

5. **Write deterministic tests**
   ```python
   # Seed randomness
   random.seed(42)

   # Mock time
   with patch("datetime.datetime") as mock_dt:
       mock_dt.now.return_value = fixed_time
       ...

   # Use fixed test data
   scenario = load_fixture("minimal_scenario.yaml")
   ```

## Reference

**Key PRD Sections:**
- Full PRD: `/Users/dabianco/projects/SURGe/data-gen-test/docs/PRD.md`
- Architecture: Section 6 (Tech Stack, Project Structure, Configuration)
- Data Models: Section 4.2 (Configuration, Scenario, Format Definition schemas)
- CLI Interface: Section 4.3 (Command specs, options, behavior)
- Error Handling: Section 8 (Exit codes, validation errors, LLM failures)
- Testing Strategy: Section 9 (Test levels, fixtures, coverage targets)

**Getting Started:**
```bash
# Install dependencies
uv sync

# Run tests
uv run pytest

# Run CLI
uv run python -m log_generator --help
```

**Questions?** Refer to PRD first, then make engineering decisions that align with project goals. Document decisions in code comments or update this file.

# AGENTS.md - EvidenceForge

This document provides AI coding agents with everything needed to write consistent, idiomatic code for the EvidenceForge project.

## Project Overview

EvidenceForge generates realistic synthetic security logs for cybersecurity threat hunting training and research. The system uses a two-phase hybrid architecture:

**Phase 1 - Scenario Creation (Skill-assisted):** Claude Code Skills guide users through scenario creation via structured interviews. Skills research TTPs via MITRE ATT&CK, expand high-level descriptions into detailed execution plans, and output structured YAML scenario files with companion research markdown.

**Phase 2 - Log Generation (Deterministic):** Generation engine executes the detailed scenario plan WITHOUT any LLM calls, producing large-scale, temporally consistent datasets across multiple log formats (Windows Event Logs, Zeek, Syslog, Snort/Suricata, web logs) with coordinated cross-references (matching LogonIDs, PIDs, session data).

This architecture combines LLM flexibility/realism with deterministic speed, cost-efficiency, and reproducibility.

**Key Principle:** The `eforge` CLI is a deterministic tool. Creative/interactive work happens through Claude Code Skills, not built-in LLM calls. Phase 2 is a deterministic renderer that executes the plan. Never call LLMs during generation. LLM integration is not built-in; scenario creation uses Claude Code Skills.

**Storyline Events (Phase 8.4):** Storyline entries use typed `events` lists, not free-text keyword matching. Each event has a `type` field (`process`, `logon`, `connection`, `ssh_session`, etc.) with per-type validated fields. The `activity` field is documentation only (for GROUND_TRUTH.md). Process events auto-generate supplementary Windows audit events (4720, 4697, etc.) from command-line patterns unless `supplementary: none` is set. See `docs/reference/scenario-reference.md` for the full event type reference.

## MANDATORY: Implementation State Tracking

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

### Changelog Workflow

When a phase is fully complete, collapse its tasks in `TODO.md` to a 2-3 line summary and move the detailed task history to `CHANGELOG.md`. This keeps `TODO.md` focused on active/future work while preserving the full development record.

## Tech Stack

**Core:**
- Python 3.11+ (required for latest type hint features including `Self`, `TypedDict` improvements)
- uv for package management, virtual environments, and script running
- Pydantic v2 for all data validation and schema management

**CLI & Output:**
- Typer for CLI framework (excellent Pydantic integration)
- Rich for progress bars, tables, and console formatting
- Jinja2 for log format templates
- PyYAML for configuration/scenario parsing
- pytz for timezone handling (UTC internal, configurable output)

**Testing:**
- pytest with pytest-cov, pytest-asyncio, pytest-mock, pytest-benchmark
- Separate test markers: `@pytest.mark.slow` for large dataset tests (not run by default)
- Target coverage: 95%+ overall, 95%+ for core generation engine

**Format Support:**
- json-logic-qubit for format definition validation rules
- Standard library json/csv for text formats
- XML output via string templates (no python-evtx dependency)

## Dependency Management

Use `uv` for all dependency management (never `pip`). `pyproject.toml` is the source of truth.

## Code Style & Standards

### General Principles
- **Type hints everywhere** — all functions, methods, and variables must have type hints
- **Pydantic for data** — use Pydantic models for any structured data (configs, scenarios, API responses)
- **Explicit over implicit** — prefer clarity over cleverness
- **Fail fast** — validate inputs early, fail with clear error messages
- **No magic** — avoid metaclasses, dynamic imports, or other "clever" patterns unless absolutely necessary

### Commits
- **Conventional Commits** — prefix every commit message with a type: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`. See [CONTRIBUTING.md](/CONTRIBUTING.md#commit-messages) for details and examples.

### Linting
- **Before committing:** always run `uv run ruff check .` and `uv run ruff format --check .` and fix any errors. A `pre-commit` hook enforces this, but verify manually when in doubt.
- Ruff configuration is in `pyproject.toml` — do not add `# noqa` comments without justification.

### Formatting
- Line length: 100 characters
- Indentation: 4 spaces
- Double quotes for strings (except to avoid escaping)
- Import order: stdlib, third-party, local (enforced by ruff's `I` rules)

### Type Hints
- Use modern Python 3.11+ built-in types: `list[User]`, `dict[int, str]` — not `typing.List`, `typing.Dict`
- Use `X | None` — not `Optional[X]`
- Always include return types on function signatures
- Annotate variables when the type isn't obvious from the assignment

### Docstrings
- Google-style docstrings for public functions/classes. Test functions: name is the doc.

### Error Handling
- Define specific custom exceptions inheriting from `EvidenceForgeError` base
- Place exceptions in appropriate modules (`models/scenario.py`, `generation/engine.py`, `validation/schema.py`)
- Provide actionable error messages: say what's wrong and how to fix it
- Never catch bare `Exception` — always use specific types

### Logging
- Use `logging.getLogger(__name__)` in every module
- Use `%s` formatting, not f-strings (lazy evaluation)
- Console output: `warning` and `error` only (configurable via `logging.console_level`)
- File output: all levels based on `logging.level` config (default: `info`); file location: `{output_dir}/generation.log`
- Never log secrets, credentials, or full exception tracebacks to users
- Log retries at DEBUG, final failure at ERROR, progress milestones at INFO

### Pydantic Models
- Use `Field()` for descriptions and constraints
- Use `field_validator` for complex validation
- Set `extra="forbid"` to catch typos/unknown fields
- Use `frozen=True` for immutable configs
- Provide clear error messages in validators

### Path Handling
- Always use `pathlib.Path`, never string paths. Resolve paths early at boundaries.

## Key Architecture Patterns

### Canonical Event Model

The generation engine uses a canonical event model — an intermediate representation between activity generation and log rendering. ActivityGenerator builds `SecurityEvent` objects carrying composable context dataclasses (`HostContext`, `AuthContext`, `ProcessContext`, `NetworkContext`, `DnsContext`, `FileContext`, `RegistryContext`, `IdsContext`, `SyslogContext`). An `EventDispatcher` routes each event to `StateManager.apply()` and to matching emitters based on `can_handle()` and network visibility.

**Core principle: consistency by construction, not by coordination.** Two emitters cannot disagree about a port number because there is only one port number — on the event object.

**Two-phase build + dispatch:** (1) Allocate IDs from StateManager (`create_session()`, `create_process()`, `open_connection()`), (2) build a complete `SecurityEvent` with those IDs, (3) dispatch to emitters. `StateManager.apply()` records state from a fully-constructed event — it does NOT allocate IDs. `RawLogEntry` exists solely for the user-facing `raw` event type in scenario YAML. All internal engine code uses canonical SecurityEvent dispatch exclusively — including baseline IDS alerts, web access, syslog daemon messages, DHCP leases, anomaly records, anonymous logons, and sensor startup.

Full design details: `docs/design/event-model-prd.md`. Key types: `src/evidenceforge/events/`.

### State Management

`StateManager` (`src/evidenceforge/generation/state_manager.py`) is the single source of truth for runtime state:
- **ActivityGenerator writes state** — allocates IDs via `create_session()`, `create_process()`, `open_connection()` before building SecurityEvents
- **Emitters only read state** — to get LogonIDs, PIDs for rendered events; never mutate StateManager
- **`apply(event)`** records state from a fully-constructed SecurityEvent — handles teardown (logoff, process termination) and updates (connection bytes); does NOT allocate IDs
- Events are transient (GC'd after dispatch); StateManager owns durable state
- Thread-safe for reads, single-threaded for writes

### Log Emitters

All emitters inherit from `LogEmitter` ABC (`src/evidenceforge/generation/emitters/base.py`):
- Each emitter declares `_supported_types` and implements `can_handle(event)` for dispatcher self-selection
- `emit()` receives `SecurityEvent` objects, builds a field dict via `_render_{event_type}()`, passes to Jinja2 template
- `emit_raw()` is the escape hatch for `RawLogEntry`
- Buffer writes (10K events), use atomic flush, always flush on close
- Handle timezone conversion (UTC → system/format timezone)
- OS-specific emitters check `event.host.os_category` in `can_handle()`
- Each emitter runs in separate thread, writes to separate file

### Format Definitions

Format definitions are YAML files in `src/evidenceforge/formats/definitions/`, not code. Each defines fields, variants, JSON Logic validators, and Jinja2 output templates. Loaded via `formats/loader.py`. Adding a new format requires only a new YAML file.

### Timezone Handling
- Store all datetimes in UTC internally (`datetime.timezone.utc`)
- Convert to output timezone only when rendering logs
- Support per-system timezone overrides with pattern matching
- Default timezone from `environment.timezone.default`

### Event & Schema Change Checklist

When adding or significantly modifying event types, emitters, or the event schema, update ALL of the following:

1. **Documentation** — `docs/reference/EVIDENCE_FORMATS.md`, `docs/reference/scenario-reference.md`, `README.md`
2. **Architecture & design docs** — `docs/ARCHITECTURE.md` (emitter tree, event type list), `docs/design/event-model-prd.md` (supported types tables)
3. **Skills** — `commands/eforge/scenario.md` (event type list + examples), other skills as relevant
4. **Validation** — `src/evidenceforge/validation/schema.py` (event type sets, OS-gating)
5. **Evaluation** — `src/evidenceforge/evaluation/dimensions/` (signal_integrity, noise_realism), `src/evidenceforge/evaluation/rules/` (co_occurrence.yaml, causal_pairs.yaml)
6. **Coverage test prompt** — `scenarios/COVERAGE-TEST-PROMPT.md` (event type count, storyline steps, format-specific verification sections)

## CLI Design Patterns

- Use Typer with `Annotated` type hints for all options/arguments
- Use Rich for progress bars (SpinnerColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn)
- Handle `KeyboardInterrupt` → exit code 130

**Exit codes (per PRD spec):**

| Code | Category | Description |
|------|----------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Input Error | Malformed YAML or file I/O error |
| 2 | Schema Validation | Pydantic validation failure |
| 21 | Generation Error | Invalid state or unrecoverable generation failure |
| 22 | Format Error | Format definition loading/validation error |
| 130 | SIGINT | User interrupted (Ctrl+C) |

## Testing Requirements

**Organization:** `tests/unit/` (fast, no I/O), `tests/integration/` (file I/O OK), `tests/fixtures/` (shared data)

**Coverage targets:** 95%+ overall, 95%+ core engine, 90%+ formats, 85%+ CLI. Exclude: `__main__.py`, type stubs, test fixtures.

**Conventions:**
- Test naming: `test_<function>_<scenario>_<expected_result>`
- Use Arrange/Act/Assert pattern
- Use `tmp_path` for all file I/O in tests
- No LLM calls during generation — all tests are deterministic
- Write deterministic tests: seed randomness, mock time, use fixed test data
- Use Hypothesis for property-based testing where appropriate (e.g., unique PIDs)
- Never use mutable default arguments

## Skills

Claude Code Skills handle the interactive, creative aspects of scenario creation.

**Location:** `commands/eforge/` directory

**Skills:**
- `/eforge scenario` — Guided scenario creation through a structured interview, producing a validated YAML scenario file
- `/eforge generate` — Generation workflow that validates a scenario and runs the deterministic engine
- `/eforge validate` — Validate a scenario file for schema correctness and cross-reference integrity
- `/eforge evaluate` — Run data quality evaluation on generated output

Skills are markdown prompt files (`.md`), not Python code. They run inside Claude Code, not inside the `eforge` CLI process. They follow a hybrid interview pattern (structured questions first, then free-form refinement) and reference `docs/reference/scenario-reference.md` for schema validity.

**Important:** When modifying the scenario schema (adding/removing/changing fields in Pydantic models or `docs/reference/scenario-reference.md`), always update the corresponding skills in `commands/eforge/` to reflect the changes — especially `scenario.md` (YAML templates and validation rules) and `validate.md` (error handling guidance).

### Adding a New Skill
1. Create `commands/eforge/{name}.md` with the skill prompt
2. Follow the hybrid interview pattern
3. Reference `docs/reference/scenario-reference.md` for output validity
4. Test interactively in Claude Code
5. Update `install-skills` command if needed

## Reference

**Key docs:**
- Full PRD: `docs/design/PRD.md`
- Event model design: `docs/design/event-model-prd.md`
- Scenario schema: `docs/reference/scenario-reference.md`
- Evidence formats: `docs/reference/EVIDENCE_FORMATS.md`
- Data quality: `docs/design/data-quality-prd.md`
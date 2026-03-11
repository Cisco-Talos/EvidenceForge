# EvidenceForge Implementation Plan

**Status:** Phase 1 - Core Generation (Proof of Concept)
**Started:** 2026-03-11
**Target MVP Completion:** 7-10 weeks from start

---

## Phase 1: Core Generation (2-3 weeks)

**Goal:** Prove the concept works with basic functionality, simplified schema, 2-3 log formats, small datasets (<10K events).

### 1.1 Project Setup & Infrastructure

- [ ] Initialize uv project with pyproject.toml
- [ ] Set up src/log_generator/ package structure
- [ ] Create tests/ directory structure (unit/, integration/, live/, fixtures/)
- [ ] Set up pytest with pytest.ini and coverage configuration
- [ ] Create .env.example with AWS_PROFILE, AWS_REGION placeholders
- [ ] Create config.example.yaml with documented parameters
- [ ] Add LICENSE file (TBD)
- [ ] Set up GitHub Actions for CI (unit + integration tests only)

### 1.2 Core Data Models (Pydantic)

- [ ] `models/config.py` - Config models (AWS, Bedrock, output, logging)
- [ ] `models/scenario.py` - Simplified scenario schema (Phase 1 subset)
  - [ ] Basic TimeWindow, Environment, User, System models
  - [ ] Simple persona structure (no LLM expansion yet)
  - [ ] Basic storyline structure
- [ ] `models/state.py` - Runtime state dataclasses (ActiveSession, RunningProcess, OpenConnection)
- [ ] Custom exception hierarchy (EvidenceForgeError, ValidationError, etc.)

### 1.3 Configuration & Utilities

- [ ] `utils/config.py` - Config loader with env var interpolation (${VAR_NAME})
- [ ] `utils/logging.py` - Logging setup (console vs file, level filtering)
- [ ] `utils/time.py` - Time parsing utilities (ISO 8601, duration strings)
- [ ] `utils/files.py` - File I/O utilities, path validation
- [ ] Test: Config loading from multiple sources (defaults, .env, config.yaml, CLI)

### 1.4 State Management

- [ ] `generation/state_manager.py` - StateManager class
  - [ ] Session creation and tracking (LogonID generation)
  - [ ] Process creation and tracking (PID allocation per system)
  - [ ] Connection tracking
  - [ ] DNS cache
  - [ ] Thread-safe reads, single-threaded writes
- [ ] Test: Unique PID generation per system
- [ ] Test: Session/process lifecycle

### 1.5 Format Definitions (2 formats for Phase 1)

- [ ] `formats/format_def.py` - Pydantic models for format definitions
- [ ] `formats/loader.py` - YAML format definition loader
- [ ] `formats/validator.py` - JSON Logic validator integration (json-logic-py)
- [ ] `formats/definitions/windows_event.yaml` - Windows Event Log format (Security variant)
- [ ] `formats/definitions/zeek.yaml` - Zeek conn.log format
- [ ] Test: Format definition loading and validation

### 1.6 Log Emitters (2 formats for Phase 1)

- [ ] `generation/emitters/base.py` - LogEmitter ABC with buffering (10K events)
- [ ] `generation/emitters/windows.py` - Windows Event Log emitter (XML output)
  - [ ] EventID 4624 (logon), 4634 (logoff), 4688 (process creation)
- [ ] `generation/emitters/zeek.py` - Zeek conn.log emitter (TSV output)
- [ ] Test: Buffer flushing at 10K threshold
- [ ] Test: Event formatting matches format definitions

### 1.7 Generation Engine (Simplified)

- [ ] `generation/engine.py` - Main generation orchestrator (single-threaded for Phase 1)
  - [ ] Load scenario and validate schema
  - [ ] Initialize StateManager
  - [ ] Simple time iteration loop (hour-by-hour)
  - [ ] Basic baseline activity generation (fixed patterns, no LLM)
  - [ ] Simple storyline execution
  - [ ] Coordinate emitters for cross-log consistency
- [ ] `generation/activity.py` - Activity execution logic
- [ ] Test: Small scenario end-to-end (<1000 events)
- [ ] Test: Cross-log consistency (LogonIDs, PIDs match)

### 1.8 CLI Framework (Basic Commands)

- [ ] `cli/commands.py` - Typer app setup with command structure
- [ ] `__main__.py` - CLI entry point
- [ ] Command: `forge init` - Write config.example.yaml to config.yaml
- [ ] Command: `forge generate` - Generate logs from simplified scenario file
  - [ ] Accept scenario file path
  - [ ] Accept --config, --output flags
  - [ ] Schema validation only (no LLM)
  - [ ] Call generation engine
  - [ ] Exit codes: 0 (success), 1 (input error), 2 (schema validation), 21 (generation error), 130 (SIGINT)
- [ ] Test: CLI argument parsing
- [ ] Test: Exit codes for error conditions

### 1.9 Validation (Schema Only for Phase 1)

- [ ] `validation/schema.py` - Pydantic-based schema validation
- [ ] Clear error messages with field paths
- [ ] Test: Invalid YAML detection
- [ ] Test: Missing required fields
- [ ] Test: Type violations

### 1.10 Phase 1 Testing & Documentation

- [ ] Unit tests for all core modules (target: 90%+ coverage for Phase 1 code)
- [ ] Integration test: Complete flow with minimal scenario
- [ ] Create test fixture: `fixtures/scenarios/minimal.yaml` (1 user, 1 system, 1 hour)
- [ ] Create test fixture: `fixtures/scenarios/small-realistic.yaml` (20 users, 10 systems, 8 hours)
- [ ] Manual testing: Generate logs and verify format compliance
- [ ] Update README with Phase 1 status and basic usage

**Phase 1 Milestone:** Can generate small, consistent datasets across 2 log formats with schema validation.

---

## Phase 2: Scalability (2-3 weeks)

**Goal:** Handle real-world dataset sizes with parallel generation, all 5 MVP formats, medium datasets (100K+ events).

### 2.1 Parallel Generation

- [ ] Refactor StateManager for thread-safe concurrent reads
- [ ] Implement emitter threading (one thread per log format)
- [ ] Shared read-only state access for all emitters
- [ ] Incremental file writing with atomic flushes
- [ ] Test: Parallel emitter execution with state consistency
- [ ] Test: No data races or deadlocks

### 2.2 Additional Log Formats (3 more)

- [ ] `formats/definitions/syslog.yaml` - Linux syslog format (RFC 5424)
- [ ] `formats/definitions/snort.yaml` - Snort/Suricata alert format (fast alert)
- [ ] `formats/definitions/web.yaml` - W3C web log format
- [ ] `generation/emitters/syslog.py` - Syslog emitter
- [ ] `generation/emitters/snort.py` - Snort emitter
- [ ] `generation/emitters/web.py` - Web log emitter
- [ ] Test: All 5 formats generate valid output
- [ ] Test: Cross-format consistency across all 5 formats

### 2.3 Progress Reporting

- [ ] Integrate Rich library for progress bars
- [ ] `cli/commands.py` - Add progress bar to generate command
  - [ ] Show time window progress (elapsed / total)
  - [ ] Show event counts per format
  - [ ] Show ETA based on moving average
- [ ] Test: Progress updates correctly during generation

### 2.4 Enhanced Scenario Schema

- [ ] Expand `models/scenario.py` with full MVP schema
  - [ ] Timezone configuration (default + per-system patterns)
  - [ ] Persona structure with expanded_activities (prepare for LLM expansion)
  - [ ] Storyline with event_sequence (prepare for LLM expansion)
  - [ ] Complete environment specification
- [ ] Timezone handling in utilities
- [ ] Test: Timezone conversions (UTC internal → system timezone output)

### 2.5 Persona-Based Activity Generation

- [ ] `generation/persona.py` - Persona activity pattern execution
  - [ ] Load persona definitions (from scenario)
  - [ ] Generate baseline activity for all users
  - [ ] Realistic temporal distributions (work hours, lunch breaks)
  - [ ] Activity variation (high/medium/low risk profiles)
- [ ] Test: Persona activity patterns match definitions
- [ ] Test: Temporal distributions look realistic

### 2.6 LLM Integration (Bedrock Client)

- [ ] `llm/client.py` - BedrockClient implementation
  - [ ] Chat and complete methods
  - [ ] Boto3 session management with profile/region
  - [ ] Basic error handling
- [ ] `llm/retry.py` - Exponential backoff retry logic
  - [ ] Retry on 429, 500, 502, 503, network errors
  - [ ] Don't retry on 400, 401, 403, 404
  - [ ] 2s, 4s, 8s delays with ±25% jitter
  - [ ] Max 3 attempts
- [ ] Test: Retry logic with mocked failures
- [ ] Test: Non-retryable errors fail immediately

### 2.7 Medium Dataset Support

- [ ] Optimize StateManager for 100K+ events
- [ ] Memory profiling to ensure <2GB usage
- [ ] Test: 8-hour, 100-user scenario (target: ~100K events, <10 min generation time)
- [ ] Test: Memory usage stays under 2GB

### 2.8 Phase 2 Testing & Scenarios

- [ ] Integration test: 8-hour scenario with all 5 formats
- [ ] Create test fixture: `fixtures/scenarios/medium-dataset.yaml` (100 users, 8 hours)
- [ ] Performance benchmarks (time, memory) for medium datasets
- [ ] Unit test coverage: maintain 95%+ overall
- [ ] Update README with Phase 2 capabilities

**Phase 2 Milestone:** Can generate medium-scale datasets (100K+ events) across all 5 MVP formats in parallel with good performance.

---

## Phase 3: Robustness - MVP Release (3-4 weeks)

**Goal:** Production-ready tool with checkpointing, full error handling, 95%+ test coverage, complete documentation, examples.

### 3.1 Conversational Interface (LLM-Driven)

- [ ] `cli/conversation.py` - Interactive scenario creation
- [ ] `llm/prompts.py` - System prompts for conversation, validation, research
- [ ] `llm/research.py` - MITRE ATT&CK TTP research (30s timeout per query)
- [ ] Command: `forge new` - Interactive scenario creation
  - [ ] One question at a time
  - [ ] LLM expands high-level descriptions into detailed execution plans
  - [ ] Save scenario YAML + research markdown companion file
- [ ] Test: Conversation flow with mocked LLM
- [ ] Live test: Full conversation with real Bedrock API

### 3.2 Semantic Validation & Repair

- [ ] `validation/semantic.py` - LLM-based semantic validation
  - [ ] Check logical consistency (users exist, timelines make sense)
  - [ ] Identify issues with context and suggestions
- [ ] `validation/repair.py` - Interactive repair workflow
- [ ] Command: `forge validate` - Validate scenario file
  - [ ] Schema validation (Pydantic)
  - [ ] Semantic validation (LLM)
  - [ ] --fix flag for auto-repair
  - [ ] --interactive flag for guided repair
- [ ] Test: Semantic validation catches logical errors
- [ ] Test: Interactive repair flow

### 3.3 Checkpointing & Resume

- [ ] `generation/checkpoint.py` - Checkpoint/resume logic
  - [ ] Save state every 5 minutes OR 100K events
  - [ ] Checkpoint format: current time, StateManager snapshot, event counts, progress metrics
  - [ ] Versioned checkpoint schema
- [ ] Update `forge generate` command with --resume flag
- [ ] Auto-delete checkpoints on successful completion
- [ ] Retain checkpoints on failure
- [ ] Test: Resume from checkpoint continues correctly
- [ ] Test: Checkpoint cleanup

### 3.4 Evaluation Framework

- [ ] `evaluation/metrics.py` - Concrete metrics
  - [ ] Format compliance (100% parse rate)
  - [ ] Cross-reference consistency (100% resolution)
  - [ ] Statistical properties (event distributions, logon/logoff balance within 5%)
  - [ ] Completeness (no orphaned references)
- [ ] `evaluation/evaluator.py` - Main evaluation logic
- [ ] `evaluation/report.py` - JSON report generation
- [ ] Command: `forge evaluate` - Evaluate generated logs
  - [ ] Load logs from output directory
  - [ ] Run all metrics
  - [ ] Generate report (JSON)
  - [ ] --verbose flag for detailed findings
- [ ] Test: Metrics calculation
- [ ] Test: Report generation

### 3.5 Pre-Built Persona Library

- [ ] Create `personas/` directory
- [ ] 10-15 common personas in YAML format:
  - [ ] `developer.yaml` - Software developer
  - [ ] `accountant.yaml` - Finance/accounting
  - [ ] `executive.yaml` - C-level executive
  - [ ] `help_desk.yaml` - IT support
  - [ ] `security_analyst.yaml` - SOC analyst
  - [ ] `sales.yaml` - Sales representative
  - [ ] `hr.yaml` - Human resources
  - [ ] `marketing.yaml` - Marketing
  - [ ] `data_analyst.yaml` - Data analyst
  - [ ] `sysadmin.yaml` - System administrator
  - [ ] Additional 5 personas based on common enterprise roles
- [ ] Update conversation logic to reference persona library

### 3.6 Comprehensive Error Handling

- [ ] Disk space check before generation (require 2x estimated output size)
- [ ] Graceful handling of Ctrl+C (SIGINT) with checkpoint
- [ ] Resource exhaustion detection (disk, memory)
- [ ] All error messages actionable and clear
- [ ] Test: Insufficient disk space fails fast
- [ ] Test: SIGINT creates checkpoint and exits cleanly
- [ ] Test: All exit codes correct for error types

### 3.7 Complete Test Suite

- [ ] 95%+ test coverage overall
- [ ] 95%+ coverage for core generation engine
- [ ] 90%+ coverage for format definitions & validators
- [ ] 85%+ coverage for CLI/conversation interface
- [ ] Property-based tests with Hypothesis (PID uniqueness, timestamp ordering)
- [ ] Live tests marked with @pytest.mark.live (conversation, semantic validation, research)
- [ ] Test fixtures for all 5 required scenarios:
  - [ ] `minimal.yaml` (1 user, 1 system, 1 hour, baseline only)
  - [ ] `small-realistic.yaml` (20 users, 10 systems, 8 hours, baseline only)
  - [ ] `attack-single.yaml` (50 users, ransomware scenario)
  - [ ] `attack-multi.yaml` (100 users, credential stuffing + lateral movement)
  - [ ] `large-scale.yaml` (100 users, 24 hours, multiple formats)
- [ ] Sample log files for validation (10-20 examples per format)

### 3.8 Example Scenarios

- [ ] `examples/simple-baseline/` - Simple baseline activity scenario
  - [ ] scenario.yaml
  - [ ] README.md explaining the scenario
- [ ] `examples/ransomware-attack/` - Ransomware scenario
  - [ ] scenario.yaml
  - [ ] scenario-research.md
  - [ ] README.md
- [ ] `examples/credential-stuffing/` - Credential attack scenario
  - [ ] scenario.yaml
  - [ ] scenario-research.md
  - [ ] README.md
- [ ] `examples/insider-threat/` - Insider threat scenario
  - [ ] scenario.yaml
  - [ ] scenario-research.md
  - [ ] README.md
- [ ] Additional 5-10 examples covering common training scenarios

### 3.9 Complete Documentation

- [ ] `docs/installation.md` - Installation guide (uv, AWS credentials, requirements)
- [ ] `docs/quickstart.md` - Quick start guide (init, new, generate, evaluate)
- [ ] `docs/user-guide.md` - Comprehensive user guide
  - [ ] Scenario creation (conversational and manual)
  - [ ] Configuration options
  - [ ] Command reference
  - [ ] Common workflows
- [ ] `docs/scenario-reference.md` - Complete scenario file schema reference
- [ ] `docs/format-definitions.md` - Format definition system documentation
- [ ] `docs/architecture.md` - Technical architecture overview
- [ ] Update README.md with complete feature list and getting started
- [ ] Contributing guide (reference AGENTS.md)

### 3.10 Large Dataset Support & Optimization

- [ ] Test: 7-day, 500-user scenario (target: ~20M events, <4 hours)
- [ ] Memory optimization to stay <2GB for large scenarios
- [ ] Performance profiling and bottleneck identification
- [ ] Optimize hot paths if needed

### 3.11 MVP Release Preparation

- [ ] Run all tests (unit, integration, live)
- [ ] Verify 95%+ test coverage achieved
- [ ] Manual testing: All CLI commands with various scenarios
- [ ] Manual testing: Generate logs and import into Splunk/ELK
- [ ] Verify all 7 MVP success metrics:
  - [ ] 8-hour, 100-user dataset in <30 minutes
  - [ ] All 5 formats pass validation
  - [ ] Cross-log consistency checks pass
  - [ ] 10+ example scenarios included
  - [ ] 95%+ test coverage achieved
  - [ ] Test with 3+ external users (internal team first)
  - [ ] Logs import into Splunk/ELK without errors
- [ ] Create release notes for MVP v1.0
- [ ] Tag release: v1.0.0

**Phase 3 Milestone:** Production-ready MVP with full feature set, comprehensive testing, and complete documentation.

---

## Post-MVP Enhancements (Future)

**Not part of MVP, but tracked here for future reference:**

### Short-term (Post-MVP)
- [ ] Subjective realism evaluation (LLM-based)
- [ ] Config file inheritance/templating
- [ ] PyPI package distribution
- [ ] Additional log formats (CloudTrail, Azure Activity, GCP Audit, database logs)
- [ ] Performance optimizations (Rust extensions, better parallelization)

### Medium-term
- [ ] Alternative LLM backends (OpenAI, Ollama, Anthropic native, Gemini)
- [ ] Web UI for scenario creation
- [ ] Streaming output to SIEM/data lakes
- [ ] Log format auto-detection from samples
- [ ] Machine learning-based realism scoring

### Long-term
- [ ] OT/ICS environment simulation
- [ ] Real-time log streaming mode
- [ ] Collaborative scenario editing
- [ ] Scenario marketplace
- [ ] Integration with attack frameworks (CALDERA, Atomic Red Team)

---

## Notes

- **Phase focus:** Start with Phase 1, complete each phase fully before moving to next
- **Testing:** Write tests alongside implementation, not after
- **Documentation:** Update docs incrementally, not all at end
- **Code review:** All major features should be reviewed before marking complete
- **Git workflow:** Commit frequently with clear messages, push to main or feature branches
- **Dependencies:** Add via `uv add`, never use `pip` directly
- **AGENTS.md compliance:** Follow all patterns and conventions specified in AGENTS.md

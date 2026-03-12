# EvidenceForge Implementation Plan

**Status:** Phase 2 - Scalability ✅ COMPLETE. Ready for Phase 3.
**Started:** 2026-03-11
**Last Updated:** 2026-03-12 (Phase 2 complete)
**Target MVP Completion:** 7-10 weeks from start

**Recent Completions:**
- ✅ Phase 2.1: Parallel Generation with Threaded Emitters
- ✅ Phase 2.2: 5 New Log Formats (eCAR, syslog, bash_history, snort_alert, web_access)
- ✅ Phase 2.3: Progress Reporting
- ✅ Phase 2.4: Enhanced Scenario Schema (work hours parsing, model expansion, timezone tests, validation, docs)
- ✅ Phase 2.5: Network Visibility Architecture (sensor placement, TAP vs SPAN, direction filtering)
- ✅ Phase 2.6: Persona-Based Activity Generation (work hours, peak hours, risk profiles, activity intensity)
- ✅ Phase 2.8+2.9: Medium Dataset Support (100-user 8h in ~14s, memory <500MB, 526 tests)
- ✅ Phase 2.10: OS-Aware Activity Generation (Windows + Linux support)

---

## Phase 1: Core Generation ✅ COMPLETE

**Goal:** Prove the concept works with basic functionality, simplified schema, 2-3 log formats, small datasets (<10K events).

### 1.1 Project Setup & Infrastructure

- [x] Initialize uv project with pyproject.toml
- [x] Set up src/log_generator/ package structure
- [x] Create tests/ directory structure (unit/, integration/, live/, fixtures/)
- [x] Set up pytest with pytest.ini and coverage configuration
- [x] Create .env.example with AWS_PROFILE, AWS_REGION placeholders
- [x] Create config.example.yaml with documented parameters
- [x] Add LICENSE file (TBD)
- [x] Set up GitHub Actions for CI (unit + integration tests only)

### 1.2 Core Data Models (Pydantic)

- [x] `models/config.py` - Config models (AWS, Bedrock, output, logging)
- [x] `models/scenario.py` - Simplified scenario schema (Phase 1 subset)
  - [x] Basic TimeWindow, Environment, User, System models
  - [x] Simple persona structure (no LLM expansion yet)
  - [x] Basic storyline structure
- [x] `models/state.py` - Runtime state dataclasses (ActiveSession, RunningProcess, OpenConnection)
- [x] Custom exception hierarchy (EvidenceForgeError, ValidationError, etc.)

### 1.3 Configuration & Utilities

- [x] `utils/config.py` - Config loader with env var interpolation (${VAR_NAME})
- [x] `utils/logging.py` - Logging setup (console vs file, level filtering)
- [x] `utils/time.py` - Time parsing utilities (ISO 8601, duration strings)
- [x] `utils/files.py` - File I/O utilities, path validation
- [x] Test: Config loading from multiple sources (defaults, .env, config.yaml, CLI)

### 1.4 State Management

- [x] `generation/state_manager.py` - StateManager class
  - [x] Session creation and tracking (LogonID generation)
  - [x] Process creation and tracking (PID allocation per system)
  - [x] Connection tracking
  - [x] DNS cache
  - [x] Thread-safe reads, single-threaded writes
- [x] Test: Unique PID generation per system
- [x] Test: Session/process lifecycle

### 1.5 Format Definitions (2 formats for Phase 1)

- [x] `formats/format_def.py` - Pydantic models for format definitions
- [x] `formats/loader.py` - YAML format definition loader
- [x] `formats/validator.py` - JSON Logic validator integration (json-logic-py)
- [x] `formats/definitions/windows_event_security.yaml` - Windows Event Log format (Security variant)
- [x] `formats/definitions/zeek_conn.yaml` - Zeek conn.log format (JSON/NDJSON output)
- [x] Test: Format definition loading and validation
- [x] Added FLOAT field type for Zeek duration field
- [x] Created test_zeek_format_accuracy.py to validate against real-world Zeek logs

### 1.6 Log Emitters (2 formats for Phase 1)

- [x] `generation/emitters/base.py` - LogEmitter ABC with buffering (10K events)
- [x] `generation/emitters/windows.py` - Windows Event Log emitter (XML output)
  - [x] EventID 4624 (logon), 4634 (logoff), 4688 (process creation)
- [x] `generation/emitters/zeek.py` - Zeek conn.log emitter (JSON/NDJSON output)
- [x] Test: Buffer flushing at 10K threshold
- [x] Test: Event formatting matches format definitions
- [x] Created `utils/ids.py` with generate_zeek_uid() for 18-character UIDs
- [x] Validated format accuracy against real-world Zeek conn.log examples

### 1.7 Generation Engine (Simplified)

- [x] `generation/engine.py` - Main generation orchestrator (single-threaded for Phase 1)
  - [x] Load scenario and validate schema
  - [x] Initialize StateManager
  - [x] Simple time iteration loop (hour-by-hour)
  - [x] Basic baseline activity generation (fixed patterns, no LLM)
  - [x] Simple storyline execution with keyword matching
  - [x] Coordinate emitters for cross-log consistency
  - [x] Generate GROUND_TRUTH.md when malicious activities present
- [x] `generation/activity.py` - Activity execution logic
  - [x] generate_logon() - creates session, emits Windows 4624
  - [x] generate_logoff() - ends session, emits Windows 4634
  - [x] generate_process() - creates process, emits Windows 4688
  - [x] generate_connection() - opens connection, emits Zeek conn.log
  - [x] Fixed baseline patterns (developer, executive, analyst)
- [x] `generation/ground_truth.py` - Ground truth documentation generator
  - [x] Extract attack narrative from storyline
  - [x] Build timeline of key malicious events with timestamps and record IDs
  - [x] Collect atomic IOCs (IPs, usernames, hostnames, processes, file paths, command lines)
  - [x] Write formatted GROUND_TRUTH.md
- [x] Test: Small scenario end-to-end (<1000 events) - smoke test passed
- [x] Created test fixtures: minimal.yaml, baseline-only.yaml, attack.yaml
- [ ] Test: Full unit tests for engine, activity, ground truth modules (deferred to Phase 2)
- [ ] Test: Integration tests with cross-log consistency checks (deferred to Phase 2)

### 1.8 CLI Framework (Basic Commands)

- [x] `cli/commands.py` - Typer app setup with command structure
- [x] `__main__.py` - CLI entry point
- [x] Command: `forge init` - Write config.example.yaml to config.yaml
- [x] Command: `forge generate` - Generate logs from simplified scenario file
  - [x] Accept scenario file path
  - [x] Accept --config, --output flags
  - [x] Schema validation only (no LLM)
  - [x] Call generation engine
  - [x] Exit codes: 0 (success), 1 (input error), 2 (schema validation), 21 (generation error), 130 (SIGINT)
- [x] Test: CLI argument parsing
- [x] Test: Exit codes for error conditions

### 1.9 Validation (Schema Only for Phase 1)

- [x] `validation/schema.py` - Pydantic-based schema validation
- [x] Clear error messages with field paths
- [x] Test: Invalid YAML detection
- [x] Test: Missing required fields
- [x] Test: Type violations
- [x] Cross-reference validation (personas, systems, users)
- [x] Uniqueness validation (usernames, hostnames, IPs)
- [x] CLI integration with Rich formatting
- [x] 14 test cases with 100% coverage

### 1.10 Phase 1 Testing & Documentation ✅ COMPLETE

- [x] Unit tests for CLI module (test_cli.py exists)
- [x] Unit tests for engine module (test_engine.py exists)
- [x] Unit tests for activity module (test_activity.py + test_activity_threading.py exist)
- [x] Unit tests for ground_truth module (test_ground_truth.py exists)
- [x] Integration tests: Complete flow with all scenarios (test_parallel_generation.py, test_format_definitions.py)
- [x] Test fixture exists: `tests/fixtures/scenarios/minimal.yaml`
- [x] Test fixture exists: `tests/fixtures/scenarios/baseline-only.yaml`
- [x] Test fixture exists: `tests/fixtures/scenarios/attack.yaml`
- [x] Test fixture exists: `tests/fixtures/scenarios/retail-store-ftp-attack.yaml`
- [ ] Create test fixture: `tests/fixtures/scenarios/small-realistic.yaml` (20 users, 10 systems, 8 hours) - DEFERRED
- [x] Manual testing: Generate logs and verify format compliance (done throughout Phase 1 & 2)
- [ ] Update README with Phase 1 status and basic usage - NEEDS UPDATE (still says "in planning")

### 1.11 Document Windows-Only Limitation ✅ OBSOLETE (Multi-OS support added in Phase 2.10)

**This section is obsolete** - Phase 1 was Windows-only but Phase 2.10 added multi-OS support:
- [x] Multi-OS support implemented in Phase 2.10
- [x] Windows systems generate Windows Event logs
- [x] Linux systems generate syslog + bash_history
- [x] eCAR provides optional unified EDR/XDR layer across all OSes

**Documentation tasks moved to Phase 2.10 section:**
- [ ] Update README.md to document current multi-OS support
- [ ] Update PRD.md with Phase 2.10 multi-OS architecture

**Phase 1 Milestone:** ✅ Can generate small, consistent datasets across 2 log formats with schema validation. ~~Known limitation: Windows-only log generation~~ **Updated:** Multi-OS support added in Phase 2.10.

---

## Phase 2: Scalability (2-3 weeks)

**Goal:** Handle real-world dataset sizes with parallel generation, all 5 MVP formats, medium datasets (100K+ events).

### 2.1 Parallel Generation ✅ COMPLETE

- [x] Refactor StateManager for thread-safe concurrent reads
- [x] Implement emitter threading (one thread per log format)
- [x] Shared read-only state access for all emitters
- [x] Incremental file writing with atomic flushes
- [x] Test: Parallel emitter execution with state consistency
- [x] Test: No data races or deadlocks
- [x] Hour-level barriers for temporal consistency
- [x] Bounded queues with backpressure (50K events)
- [x] Background threads consume queues and render events

### 2.2 Additional Log Formats ✅ COMPLETE

**Goal:** Add 5 new log formats for MVP (7 total formats)

- [x] `formats/definitions/ecar.yaml` - Extended Cyber Analytics Repository (MITRE CAR-based EDR/XDR)
  - [x] NDJSON format with object/action model
  - [x] Support PROCESS, FILE, FLOW, USER_SESSION, REGISTRY objects
  - [x] UUID generation for event IDs and object IDs
  - [x] Fixed JSON escaping for Windows paths
- [x] `formats/definitions/syslog.yaml` - Linux syslog format (RFC 5424)
  - [x] Support authentication logs (authpriv facility)
  - [x] Facility/severity mapping
- [x] `formats/definitions/bash_history.yaml` - Bash command history format
  - [x] Timestamped command history
  - [x] Per-user history files
- [x] `formats/definitions/snort_alert.yaml` - Snort/Suricata alert format (fast alert)
  - [x] SID, classification, priority fields
  - [x] Protocol and network tuple support
- [x] `formats/definitions/web_access.yaml` - W3C web log format
  - [x] Apache/Nginx combined log format
  - [x] Client IP, method, path, status, user agent support
- [x] `generation/emitters/ecar.py` - eCAR emitter
- [x] `generation/emitters/syslog.py` - Syslog emitter
- [x] `generation/emitters/bash_history.py` - Bash history emitter
- [x] `generation/emitters/snort.py` - Snort emitter
- [x] `generation/emitters/web.py` - Web log emitter
- [x] Engine initialization for all 7 formats with threaded emitters
- [x] Test: All format definitions load successfully
- [x] Test: All emitters generate valid output

**Note:** Total formats: Windows Event Security (Phase 1), Zeek conn.log (Phase 1), eCAR, syslog, bash_history, snort_alert, web_access = 7 formats

### 2.3 Progress Reporting ✅ COMPLETE

- [x] Integrate Rich library for progress bars
- [x] `cli/commands.py` - Add progress bar to generate command
  - [x] Show time window progress (elapsed / total)
  - [x] Show event counts per format
  - [x] Show ETA based on moving average
- [x] Test: Progress updates correctly during generation

### 2.4 Enhanced Scenario Schema ✅ COMPLETE

**Goal:** Add optional schema fields for LLM expansion (Phase 3.1) and persona generation (Phase 2.6)

- [x] Add `parse_work_hours()` utility to `utils/time.py`
  - [x] Parse "9am-5pm" format to hour ranges
  - [x] Support lunch breaks: "9am-5pm (lunch 12pm-1pm)"
  - [x] Support half-hours: "8:30am-5:30pm"
  - [x] Calculate peak hours (mid-morning, mid-afternoon)
  - [x] Add 10+ test cases in `tests/unit/test_time_parsing.py` (17 tests, all passing)
- [x] Expand Persona model in `models/scenario.py` (optional fields, backward compatible)
  - [x] Timezone configuration (default + per-system patterns) - Already exists!
  - [x] Add optional `expanded_activities` field (for Phase 3.1 LLM to populate)
  - [x] Add optional `work_hours_parsed` field (auto-populated from work_hours)
  - [x] Add optional `activity_intensity` field (per-activity overrides)
  - [x] Add `@model_validator` to auto-populate work_hours_parsed
- [x] Expand StorylineEvent model in `models/scenario.py` (optional fields, backward compatible)
  - [x] Add optional `event_sequence` field (sub-events for complex attacks)
  - [x] Add optional `duration` field (event duration like "30m")
  - [x] Add optional `retry_on_failure` field
  - [x] Add optional `success_probability` field (0.0-1.0)
- [x] Add timezone tests
  - [x] Create `tests/unit/test_timezone_handling.py` (14 tests: pattern matching, DST, conversions)
  - [x] Create `tests/integration/test_scenario_timezone.py` (4 tests: multi-timezone scenarios)
  - [x] Test UTC → local timezone conversions
  - [x] Test pattern-based timezone overrides
  - [x] Test work hours parsing
- [x] Update validation in `validation/schema.py`
  - [x] Validate expanded_activities structure if present
  - [x] Validate event_sequence structure if present
  - [x] 6 new validation tests added to `tests/unit/test_validation.py`
- [x] Documentation
  - [x] Create `docs/scenario-reference.md` with full schema reference
  - [x] Document optional fields for Phase 3.1 LLM expansion
  - [x] Document backward compatibility guarantees
- [x] Verification
  - [x] Test backward compatibility with existing scenarios (minimal.yaml, attack.yaml)
  - [x] Verify work_hours_parsed auto-population works
  - [x] All 105 Phase 2.4 tests pass

### 2.5 Network Visibility Architecture ✅ COMPLETE

- [x] Model network topology and sensor placement in scenario schema
  - [x] `NetworkSegment` model: name, CIDR, description, systems list
  - [x] `NetworkSensor` model: type, name, monitoring_segments, direction, placement (span|tap), log_formats
  - [x] `NetworkConfig` model: segments + sensors, added as optional field on `Environment`
- [x] Implement `NetworkVisibilityEngine` in `generation/network_visibility.py`
  - [x] IP-to-segment mapping (explicit systems list or CIDR auto-inference)
  - [x] Direction filtering: inbound, outbound, bidirectional
  - [x] Placement filtering: SPAN (sees intra-segment) vs TAP (cross-segment only)
  - [x] Format-aware emission: union of log_formats from all observing sensors
  - [x] Backward compatible: no network config = all connections visible
- [x] Integrate into `generation/activity.py` connection logic
  - [x] Visibility check before connection emission
  - [x] Format-aware emitter selection (replaces hardcoded Zeek emission)
- [x] Wire up in `generation/engine.py`
- [x] Cross-reference validation in `validation/schema.py`
  - [x] Segment systems reference existing hostnames
  - [x] Sensor segments reference existing segments
  - [x] System IP vs segment CIDR mismatch warnings
- [x] 25 unit tests in `tests/unit/test_network_visibility.py`
- [x] 5 validation tests in `tests/unit/test_validation.py`
- [x] Updated `retail-store-ftp-attack.yaml` with network topology (3 segments, 2 sensors)

### 2.6 Persona-Based Activity Generation ✅ COMPLETE

- [x] Resolve user.persona string to Persona object in engine (`_get_user_persona()`)
- [x] Work hours modulation: zero events outside work hours, 150% during peak hours
- [x] Lunch break support: zero events during lunch
- [x] Risk profile scaling: low=0.7x, medium=1.0x, high=1.3x intensity
- [x] Dynamic activity patterns from `activity_intensity` overrides
- [x] Backward compatible: no persona = uniform activity at all hours
- [x] 13 tests in `tests/unit/test_persona_activity.py`

### 2.7 LLM Integration (Bedrock Client) — DEFERRED TO PHASE 3

**Moved to Phase 3.1** - LLM client and retry logic are only needed for the conversational interface. Will be implemented alongside Phase 3.1 (Conversational Interface).

### 2.8+2.9 Medium Dataset Support & Phase 2 Completion ✅ COMPLETE

- [x] Create test fixture: `fixtures/scenarios/medium-dataset.yaml` (100 users, 20 systems, 8 hours)
- [x] Performance test: 100 users x 8 hours completes in ~14 seconds
- [x] Memory test: peak memory under 500MB (validated with tracemalloc)
- [x] Integration tests: 8 slow-marked tests for event counts, JSON validity, file sizes
- [x] StateManager handles 100K+ events without optimization needed (O(1) dicts)
- [x] 526 total tests (518 fast + 8 slow), 88.7% coverage

### 2.10 OS-Aware Activity Generation ✅ COMPLETE

**Goal:** Enable generation of OS-specific logs based on system.os field (addresses Phase 1 limitation)

- [x] Create OS detection helper `_get_os_category()` in `generation/activity.py`
  - [x] Pattern matching for OS strings (Windows, Linux, Ubuntu, CentOS, Debian, RHEL)
  - [x] Returns "windows", "linux", or "unknown"
- [x] Refactor `generation/activity.py` for OS branching
  - [x] `generate_logon()` - detect OS and emit native logs (Windows Event 4624 OR syslog auth)
  - [x] `generate_process()` - detect OS and emit native logs (Windows Event 4688 OR skip for Linux)
  - [x] Optional eCAR emission - check if 'ecar' in emitters before emitting
  - [x] Linux-specific process templates (PROCESS_TEMPLATES_LINUX)
  - [x] Maintain existing ActivityGenerator API (no breaking changes)
- [x] Create OS-specific activity patterns
  - [x] Windows: paths (C:\Windows\...), event IDs (4624, 4688, etc.)
  - [x] Linux: paths (/usr/bin/..., /bin/...), syslog facilities
  - [x] Bash command generation for Linux systems
- [x] Multi-format emission strategy
  - [x] Native OS logs: Windows Event Security (Windows) OR syslog (Linux) - ALWAYS present
  - [x] eCAR: Optional EDR/XDR layer - check if enabled before emitting
  - [x] Network: Zeek, Snort - OS-agnostic
  - [x] Bash history: Linux only - always present for Linux systems
- [x] Engine initializes all 7 formats regardless of OS (activity.py decides what to emit)
- [x] Test: Windows system generates Windows Event logs + optional eCAR
- [x] Test: Linux system generates syslog + bash_history + optional eCAR
- [x] Test: OS detection works correctly (Windows 10, Linux Ubuntu, CentOS, Debian, RHEL)
- [x] Test: Multi-format emission produces expected outputs
- [x] Update README.md to document current multi-OS support (status, formats, capabilities)
- [ ] Update PRD.md with Phase 2.10 multi-OS architecture and design decisions

**Architecture Note:** Native logs (Windows Event Security, syslog) are ALWAYS present per OS type. eCAR is OPTIONAL and may be present on all, some, or no systems (EDR/XDR is not universally deployed).

**Phase 2 Status: ✅ COMPLETE**
- ✅ All phases complete: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.8+2.9, 2.10
- 🔀 Deferred: 2.7 (LLM Integration) → folded into Phase 3.1

**Phase 2 Milestone:** Can generate datasets across 7 formats in parallel with threaded emitters. 100-user 8-hour scenarios complete in ~14 seconds. Persona-based temporal distributions, network visibility with TAP/SPAN sensors, OS-aware log routing, and cross-log consistency. 526 tests passing.

**Phase 2 Milestone (Partial):** Can generate datasets across 7 formats (Windows Event Security, Zeek, eCAR, syslog, bash_history, snort_alert, web_access) in parallel with threaded emitters. Windows and Linux systems generate appropriate OS-specific logs. Native logs (Windows Event/syslog) always present; eCAR optional EDR/XDR layer.

---

## Phase 3: Robustness - MVP Release (3-4 weeks)

**Goal:** Production-ready tool with checkpointing, full error handling, 95%+ test coverage, complete documentation, examples.

### 3.1 Conversational Interface & LLM Integration

**Includes LLM client work deferred from Phase 2.7.**

- [ ] `llm/client.py` - BedrockClient implementation (from Phase 2.7)
  - [ ] Chat and complete methods
  - [ ] Boto3 session management with profile/region
  - [ ] Basic error handling
- [ ] `llm/retry.py` - Exponential backoff retry logic (from Phase 2.7)
  - [ ] Retry on 429, 500, 502, 503, network errors
  - [ ] Don't retry on 400, 401, 403, 404
  - [ ] 2s, 4s, 8s delays with ±25% jitter, max 3 attempts
- [ ] `cli/conversation.py` - Interactive scenario creation
- [ ] `llm/prompts.py` - System prompts for conversation, validation, research
- [ ] `llm/research.py` - MITRE ATT&CK TTP research (30s timeout per query)
- [ ] Command: `forge new` - Interactive scenario creation
  - [ ] One question at a time
  - [ ] LLM expands high-level descriptions into detailed execution plans
  - [ ] Save scenario YAML + research markdown companion file
- [ ] Test: Retry logic with mocked failures
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
  - [ ] Ground truth validation (if GROUND_TRUTH.md exists, verify all IOCs present)
- [ ] `evaluation/evaluator.py` - Main evaluation logic
- [ ] `evaluation/report.py` - JSON report generation
- [ ] Command: `forge evaluate` - Evaluate generated logs
  - [ ] Load logs from output directory
  - [ ] Run all metrics
  - [ ] Validate GROUND_TRUTH.md IOCs if present
  - [ ] Generate report (JSON)
  - [ ] --verbose flag for detailed findings
- [ ] Test: Metrics calculation
- [ ] Test: Report generation
- [ ] Test: Ground truth IOC validation

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
- [ ] Additional network diagram formats (Graphviz/DOT, draw.io exports, network discovery tool outputs)
- [ ] Network diagram ingestion: auto-infer sensor placement (span vs tap) from diagram topology
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

# EvidenceForge Implementation Plan

**Status:** Phase 7 - Canonical Event Model ✅ COMPLETE (7.1-7.4); Phase 6 ongoing (44 original + 16 new from improvement loop, 46 resolved)
**Started:** 2026-03-11
**Last Updated:** 2026-03-19 (Phase 7 complete: all emission through EventDispatcher, 761 tests passing)
**Target MVP Completion:** 7-10 weeks from start

**Recent Completions:**
- ✅ Phase 3.1: Claude Code Skills + Install Command (scenario, generate, validate skills; eforge install-skills)
- ✅ Phase 3.2: Pre-Built Persona Library (15 personas)
- ✅ Phase 3.3: Documentation (scenario reference, README, skill usage)
- ✅ Phase 3.4: MVP Release Preparation

---

## Phase 1: Core Generation ✅ COMPLETE

**Goal:** Prove the concept works with basic functionality, simplified schema, 2-3 log formats, small datasets (<10K events).

### 1.1 Project Setup & Infrastructure

- [x] Initialize uv project with pyproject.toml
- [x] Set up src/evidenceforge/ package structure
- [x] Create tests/ directory structure (unit/, integration/, live/, fixtures/)
- [x] Set up pytest with pytest.ini and coverage configuration
- [x] ~~Create .env.example with AWS_PROFILE, AWS_REGION placeholders~~ REMOVED (no Bedrock integration)
- [x] ~~Create config.example.yaml with documented parameters~~ REMOVED (no config.yaml needed)
- [x] Add LICENSE file (TBD)
- [x] Set up GitHub Actions for CI (unit + integration tests only)

### 1.2 Core Data Models (Pydantic)

- [x] ~~`models/config.py` - Config models (AWS, Bedrock, output, logging)~~ REMOVED
- [x] `models/scenario.py` - Simplified scenario schema (Phase 1 subset)
  - [x] Basic TimeWindow, Environment, User, System models
  - [x] Simple persona structure (no LLM expansion yet)
  - [x] Basic storyline structure
- [x] `models/state.py` - Runtime state dataclasses (ActiveSession, RunningProcess, OpenConnection)
- [x] Custom exception hierarchy (EvidenceForgeError, ValidationError, etc.)

### 1.3 Configuration & Utilities

- [x] ~~`utils/config.py` - Config loader with env var interpolation~~ REMOVED
- [x] `utils/logging.py` - Logging utilities (redact_secrets)
- [x] `utils/time.py` - Time parsing utilities (ISO 8601, duration strings)
- [x] `utils/files.py` - File I/O utilities, path validation
- [x] ~~Test: Config loading from multiple sources~~ REMOVED

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
- [x] ~~Command: `eforge init`~~ REMOVED (no config.yaml needed)
- [x] Command: `eforge generate` - Generate logs from simplified scenario file
  - [x] Accept scenario file path
  - [x] Accept --output flag
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

### 2.7 LLM Integration (Bedrock Client) — ✅ OBSOLETE

**Replaced by Claude Code Skills.** Phase 3 adopted a skills-based architecture where all LLM-driven work (scenario creation, validation, evaluation review) happens through Claude Code skills rather than a built-in Bedrock client. No code-level LLM calls are needed.

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
- ✅ Obsolete: 2.7 (LLM Integration) → replaced by Claude Code Skills architecture

**Phase 2 Milestone:** Can generate datasets across 7 formats in parallel with threaded emitters. 100-user 8-hour scenarios complete in ~14 seconds. Persona-based temporal distributions, network visibility with TAP/SPAN sensors, OS-aware log routing, and cross-log consistency. 526 tests passing.

**Phase 2 Milestone (Partial):** Can generate datasets across 7 formats (Windows Event Security, Zeek, eCAR, syslog, bash_history, snort_alert, web_access) in parallel with threaded emitters. Windows and Linux systems generate appropriate OS-specific logs. Native logs (Windows Event/syslog) always present; eCAR optional EDR/XDR layer.

---

## Phase 3: MVP Release (Skill-Based Architecture) ✅ COMPLETE

**Goal:** Ship skills for scenario creation, persona library, install command, and documentation. Core generation engine already complete from Phase 2.

**Architecture shift:** Interactive/creative work (scenario creation) happens through Claude Code Skills, not a built-in LLM conversation engine. The `eforge` CLI stays focused on deterministic operations (generate, validate, evaluate).

### 3.1 Claude Code Skills + Install Command

- [x] Create `commands/eforge/scenario.md` — `/eforge scenario` skill
  - [x] Hybrid interview flow: structured questions first, then free-form gap-filling
  - [x] Environment, network, personas, attacks, time window, output formats
  - [x] References persona library and scenario schema
  - [x] Generates valid scenario YAML, validates before saving
  - [x] Generates ENVIRONMENT.md student context document alongside scenario
  - [x] 10-tactic MITRE ATT&CK kill chain template
  - [x] Base64/encoded content must be generated via Bash, never fabricated
  - [x] Use `/skill-creator` to develop skill prompt content (2 iterations, 30/30 assertions)
- [x] Create `commands/eforge/generate.md` — `/eforge generate` skill
  - [x] Runs `eforge generate` on scenario file
  - [x] Runs `eforge validate` as pre-flight check
  - [x] Monitors output, diagnoses errors
  - [x] Suggests fixes for common issues, escalates structural problems to `/eforge scenario`
  - [x] Copies ENVIRONMENT.md to output directory alongside GROUND_TRUTH.md
- [x] Create `commands/eforge/validate.md` — `/eforge validate` skill
  - [x] Runs `eforge validate` and interprets output
  - [x] Fixes simple issues directly, escalates structural problems to `/eforge scenario`
- [x] Add `eforge install-skills` CLI command to `cli/commands.py`
  - [x] `--project` flag: copies to `.claude/commands/` (default)
  - [x] `--global` flag: copies to `~/.claude/commands/`
  - [x] Skills bundled as package data via `importlib.resources` + hatch force-include
  - [x] Updates existing installations: overwrites changed files, removes stale files
  - [x] Bundles skills, personas, and scenario-reference.md
- [x] Test: install-skills copies files correctly (12 tests)

### 3.2 Pre-Built Persona Library ✅ COMPLETE

- [x] Create `personas/` directory with 15 YAML persona files
  - [x] Uses same schema as Persona model in scenario files
  - [x] developer, executive, analyst, sysadmin, help_desk, security_analyst
  - [x] accountant, sales, hr, marketing, data_analyst
  - [x] receptionist, intern, project_manager, legal_counsel
  - [x] Each with realistic work_hours, typical_activities, risk_profile
- [x] Skills reference persona library when creating scenarios
- [x] Personas bundled with `eforge install-skills` command

### 3.3 Documentation

- [ ] Update `docs/scenario-reference.md` (already exists, may need refresh)
- [ ] Create skill usage guide
- [ ] Update README with skill-based workflow
- [ ] Update TODO with Phase 3 completion status

### 3.4 MVP Release Preparation

- [ ] Run all tests
- [ ] Manual testing: skills + generate workflow
- [ ] Verify success metrics (see PRD Section 9)
- [ ] Tag release: v1.0.0

**Phase 3 Milestone:** ✅ Skills-based scenario creation (3 skills), persona library (15 personas), install command, and documentation. Core generation engine already complete from Phase 2. 542+ tests passing.

---

## Phase 4: Data Quality Evaluation Framework (Post-MVP)

**Goal:** Add `eforge eval` command that scores generated datasets across 5 quality dimensions with 23 sub-scores. Focused on threat hunting realism. All scoring is deterministic/statistical (no LLM required). Optional LLM spot-check layer for qualitative review.

**PRD:** See `docs/data-quality-prd.md` for full rationale, scoring formulas, and design decisions.

**Scoring model:** 5 dimensions roll up to an overall 0-100 score. Each dimension has weighted sub-scores. Acceptance criteria are a separate pass/fail layer on top of scores.

### 4.1 Report Framework & CLI Command ✅ COMPLETE

- [x] Create `src/evidenceforge/evaluation/` package structure
- [x] `evaluation/engine.py` — Orchestrator with progress callbacks, acceptance criteria
- [x] `evaluation/report.py` — Rich text + JSON report formatting
- [x] `evaluation/models.py` — QualityReport, DimensionScore, SubScore, AcceptanceCriterion
- [x] Add `eforge eval` CLI command with Rich progress bars
- [x] 7 log parsers: XML (Windows), NDJSON (Zeek, eCAR), regex (syslog, snort, web, bash_history)
- [x] Tests: 50 tests for parsers, models, CLI, report

### 4.2 Dimension 1 — Record-Level Fidelity (weight: 0.15) ✅ COMPLETE

- [x] `evaluation/dimensions/record_fidelity.py`
- [x] Tier A: Parsability (reuses formats/validator.py)
- [x] Tier B: Co-occurrence rules (YAML rule sets, 5-10 per format)
- [x] Tier C: Population statistics (Jensen-Shannon divergence, hand-rolled)
- [x] Tests: known-good/bad fixtures

### 4.3 Dimension 5 — Signal Integrity (weight: 0.20) ✅ COMPLETE

- [x] `evaluation/dimensions/signal_integrity.py`
- [x] Event Presence, Indicator Accuracy, Pivot Linkability, Storyline Temporal Integrity
- [x] Storyline resolution (ISO + relative offsets), keyword-based activity matching
- [x] Tests: 17 tests covering all sub-scores

### 4.4 Dimension 4 — Temporal Realism (weight: 0.15) ✅ COMPLETE

- [x] `evaluation/dimensions/temporal.py`
- [x] Work Hour Distribution, Human Burstiness (CV), System Process Regularity (autocorrelation)
- [x] Causal Ordering with `evaluation/rules/causal_pairs.yaml` (4 pair types)
- [x] Timing Plausibility (command rate + transfer speed checks)
- [x] Tests: 17 tests

### 4.5 Dimension 2 — Cross-Source Coherence (weight: 0.25) ✅ COMPLETE

- [x] `evaluation/dimensions/cross_source.py`
- [x] `evaluation/visibility.py` — OS→format mapping + NetworkVisibilityEngine reuse
- [x] Source Correctness, Storyline Trace Coverage, Cross-Source Field Agreement
- [x] Baseline Coherence (Sampled + Aggregate)
- [x] Tests: 11 tests

### 4.6 Dimension 3 — Background Noise Realism (weight: 0.25) ✅ COMPLETE

- [x] `evaluation/dimensions/noise_realism.py`
- [x] `evaluation/anomaly.py` — statistical anomaly detector (work hours, failed ops, rare processes, unexpected ports)
- [x] Volume Adequacy, User Behavioral Diversity (cosine similarity), Activity Plausibility
- [x] Organic Anomaly Rate (1-5% target)
- [x] Tests: 13 tests

### 4.7 Evaluate Skill (`/eforge evaluate`) ✅ COMPLETE

- [x] Create `commands/eforge/evaluate.md` — runs `eforge eval`, interprets results, provides qualitative LLM review
- [x] Replaces the originally planned Bedrock-based LLM spot-check layer
- [x] Qualitative review (record realism, narrative coherence, hunting feasibility) handled conversationally by the skill

### 4.8 Integration & Acceptance Criteria ✅ COMPLETE

- [x] Acceptance criteria engine: hard requirements (reject) + quality targets (flag)
  - [x] Hard: Dim1 Tier A >= 98%, Dim2 Source Correctness >= 95%, Dim4 Causal Ordering >= 99%, Dim5 Event Presence >= 90%
- [x] Integration test: `eforge generate` + `eforge eval` pipeline verified on retail-store-ftp-attack
- [x] 653+ tests passing, all 5 dimensions scoring

### 4.9 Scenario Skill Update

- [ ] Update `commands/eforge/scenario.md` to check sensor coverage during authoring
- [ ] Flag when storyline events may not be discoverable given declared topology

**Phase 4 Status:** ✅ COMPLETE. All 5 scoring dimensions (23 sub-scores), acceptance criteria, `/eforge evaluate` skill. 653+ tests.

**Baseline scores on retail-store-ftp-attack (24K records, 4 sources):**
- Overall: 78/100
- Dim 1 (Record Fidelity): 68 — empty SIDs, distribution skew
- Dim 2 (Cross-Source): 100 — correct OS mapping, field agreement
- Dim 3 (Noise Realism): 50 — volume too low, users too similar
- Dim 4 (Temporal): 67 — work hours too concentrated, burstiness low
- Dim 5 (Signal Integrity): 100 — all storyline events found with correct indicators

**Evaluation on ironforge-source-theft (80K records, 3 sources):**
- Overall: 76/100 | Acceptance: FAIL (parsability 59.3% < 98%)
- Dim 1 (Record Fidelity): 69 — empty SID fields sole cause of parsability failure
- Dim 2 (Cross-Source): 94 — strong agreement, minor storyline trace gaps in Windows
- Dim 3 (Noise Realism): 52 — volume ratio 4,179:1 vs 10,000:1 target, 87% user pairwise similarity
- Dim 4 (Temporal): 60 — perfect causal ordering but uniform timing, no burstiness
- Dim 5 (Signal Integrity): 100 — all 19 attack events present, linkable, correctly timed
- Qualitative assessment: "An experienced threat hunter would spot this as synthetic within minutes"

**Key qualitative tells identified:**
1. All Zeek connections SF/ShADadfF (no failed connections, resets, timeouts)
2. Zero UDP/ICMP (no DNS, NTP, DHCP, mDNS)
3. Only 11 destination IPs across 14,799 connections
4. Only 2 Windows Event IDs (4624, 4688) — no logoffs, failures, privilege events
5. Only 12 unique process paths — no system backbone processes (svchost, lsass, explorer)
6. Only 2 eCAR object types (USER_SESSION, PROCESS) — no file/registry/network
7. Metronomic inter-event timing, hard rectangular work-hour profile
8. Users statistically interchangeable regardless of persona

---

## Phase 5: Data Realism Improvements

**Goal:** Address generator-level limitations identified by Phase 4 evaluation and qualitative review. Make generated data indistinguishable from real data at casual inspection. Organized in 5 sub-phases, each independently shippable.

**Target outcome:** Overall eval score ≥ 85, parsability ≥ 98% (PASS), qualitative review finds no "instant tells."

### 5.1 Record Fidelity Quick Wins

**Goal:** Fix the hard acceptance failure (parsability) and the most obvious per-record tells. Smallest changes, biggest eval score impact.

- [x] **Fix empty SID fields in Windows events**
  - Generate realistic SIDs: `S-1-5-21-{domain_sub_authorities}-{user_rid}`
  - Assign per-domain base SID at engine init (e.g., `S-1-5-21-3623811015-3361044348-30300820`)
  - Map each user to a unique RID (starting at 1001, incrementing)
  - Well-known SIDs for system accounts: `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE), `S-1-5-20` (NETWORK SERVICE)
  - Populate `SubjectUserSid` and `TargetUserSid` in all Windows event data dicts in `activity.py`
  - Files: `activity.py`, `engine.py` (SID registry initialization)
- [x] **Add logoff generation to baseline activity**
  - Track active sessions per user; probabilistically end sessions (e.g., 30% chance per hour after first hour)
  - Emit Windows 4634 (logoff) and eCAR USER_SESSION/LOGOUT
  - Ensure logon→activity→logoff ordering within each session
  - Files: `activity.py` (`execute_baseline_activity`), `engine.py` (`_generate_baseline`)
- [x] **Vary Zeek conn_state and history strings**
  - Replace hardcoded `SF`/`ShADadfF` with probabilistic selection
  - Connection states: SF (85%), S0 (5%), S1 (3%), REJ (2%), RSTO (3%), RSTR (1%), OTH (1%)
  - Generate history strings that match conn_state (e.g., S0→`S`, REJ→`Sr`, RSTO→`ShADaR`)
  - Adjust orig_bytes/resp_bytes to be consistent (e.g., S0 = 0 resp_bytes)
  - Files: `activity.py` (`generate_connection`)
- [x] **Expand process template pools**
  - Windows: add system backbone (svchost.exe, lsass.exe, explorer.exe, services.exe, csrss.exe, RuntimeBroker.exe, SearchIndexer.exe) + user apps (chrome.exe, firefox.exe, outlook.exe, teams.exe, OneDrive.exe)
  - Linux: add system processes (systemd, cron, sshd, rsyslogd, NetworkManager) + user apps (firefox, thunderbird, git, docker, python3)
  - Per-persona weighting: developers see more compilers/editors, executives see more Office/browser
  - Files: `activity.py` (PROCESS_TEMPLATES, PROCESS_TEMPLATES_LINUX)
- [x] Test: Parsability score ≥ 98% (SIDs valid format)
- [x] Test: Logoff events present in output, paired with logons
- [x] Test: conn_state distribution is varied (not 100% SF)
- [x] Test: Process path count > 30 unique paths

### 5.2 Event Type Diversity

**Goal:** Expand the vocabulary of events generated. Address "only 2 Event IDs" and "only 2 eCAR object types."

- [x] **Add Windows Event IDs to format definition and emitters**
  - 4625: Failed logon (account does not exist, bad password, account locked)
  - 4672: Special privileges assigned to new logon (admin logons)
  - 4689: Process termination (pair with 4688)
  - 4648: Explicit credential logon (RunAs, scheduled tasks)
  - 5156: Windows Filtering Platform connection allowed (host firewall)
  - Update `windows_event_security.yaml` schema, Jinja2 templates, and validation rules
  - Files: `formats/definitions/windows_event_security.yaml`, `generation/emitters/windows.py`
- [x] **Generate failed logons in baseline**
  - 5-15% of logon attempts fail (configurable via persona risk_profile)
  - Failure reasons: bad password (most common), account locked, expired password
  - Emit Windows 4625 + eCAR USER_SESSION/LOGON_FAILURE
  - Files: `activity.py` (`generate_logon` or new `generate_failed_logon`)
- [x] **Add eCAR object type diversity**
  - FILE/CREATE, FILE/MODIFY, FILE/DELETE — generated alongside process activity
  - REGISTRY/MODIFY — Windows system processes and app installs
  - FLOW/CONNECT — parallel to Zeek connections for eCAR-equipped hosts
  - MODULE/LOAD — DLL loads for Windows processes
  - Files: `activity.py` (new methods), `generation/emitters/ecar.py`
- [x] **Add process termination events**
  - Pair 4689 with 4688: terminate processes after realistic duration (seconds to hours)
  - Track running processes in StateManager, probabilistically terminate
  - Files: `activity.py`, `state_manager.py`
- [x] Test: ≥ 6 unique Windows Event IDs in output
- [x] Test: ≥ 5 unique eCAR object types in output
- [x] Test: Failed logon rate between 5-15% of total logon events
- [x] Test: Process termination events present, paired with creation

### 5.3 Protocol & Network Diversity

**Goal:** Eliminate the "zero UDP/ICMP" and "only 11 IPs" tells. Add realistic network protocol mix.

- [x] **Add UDP traffic generation**
  - DNS queries (UDP 53): `_emit_dns_lookup()` emits both Zeek conn.log UDP/53 and dns.log records before every user TCP connection
  - NTP sync (UDP 123): periodic per-system in `_generate_system_traffic()` (Phase 5.4)
  - Deferred: DHCP, mDNS/LLMNR, QUIC
- [x] **Add ICMP traffic generation**
  - 1-3 ICMP echo pings per hour between systems on same subnet
  - Added to `_generate_system_traffic()` in engine.py
- [ ] **Implement service registry for internal IP consistency** — DEFERRED
- [x] **Expand external destination IP pools**
  - EXTERNAL_IPS expanded from 9 to 50+ IPs across 5 categories (web, email, git, db, saas)
  - Added REVERSE_DNS mapping (IP → hostname) for DNS query generation
  - Added `_generate_random_external_ip()` for CDN/cloud long-tail destinations (30% chance per connection)
  - Added `_generate_random_hostname()` for plausible CDN hostnames
- [x] **Add Zeek dns.log format definition** (new format, 8th format total)
  - `formats/definitions/zeek_dns.yaml` — 18 fields matching real Zeek dns.log
  - `generation/emitters/zeek_dns.py` — NDJSON emitter with JSON compaction
  - `evaluation/parsers/zeek_dns.py` — eval parser for dns.log records
  - Eval rules: qtype_name distribution + rcode_name distribution + co-occurrence rules
- [x] **Cross-record consistency**: DNS answers match subsequent TCP connection dst_ip, same source IP, temporal ordering
- [x] Test: UDP traffic present (proto=udp in Zeek output)
- [x] Test: DNS queries emitted for TCP connection destinations
- [x] Test: dns.log format loads, emitter produces valid NDJSON, parser reads correctly
- [ ] Test: ≥ 100 unique destination IPs in medium dataset — DEFERRED (needs integration test)
- [ ] Test: Internal IP service consistency — DEFERRED (service registry not implemented)

### 5.4 Background Traffic & System Activity

**Goal:** Generate OS-appropriate system/service traffic independent of user activity. Eliminate the "all traffic is user-initiated" tell.

- [x] **Add optional `services` field to System model (inline)**
  - `System.services: list[str]` already existed; auto-populate defaults in engine if empty
  - Windows workstation: `["dns-client", "ntp-client", "smb-client"]`, Linux: `["dns-client", "ntp-client", "syslog"]`
  - Auto-detect DC/DNS/NTP from hostname hints, override infra IPs
  - Files: `engine.py` (`_build_service_defaults`, `_detect_infrastructure_ips`)
- [x] **Add system traffic generation loop in engine**
  - New `_generate_system_traffic()` method called per-hour in `_generate_baseline`
  - Generates: DNS lookups (UDP/53, 2-6/hr), NTP sync (UDP/123, ~1/hr), SMB browsing (TCP/445, 1-3/hr Windows)
  - Scheduled tasks: svchost/cron child processes with realistic command lines
  - Files: `engine.py` (`_generate_system_traffic`)
- [x] **Pre-seed system process trees (no log output)**
  - Windows: System(4) → smss → csrss, wininit → services (8 svchost groups), lsass, MsMpEng, SearchIndexer, dwm, RuntimeBroker (19 processes)
  - Linux: systemd → journald, udevd, rsyslogd (syslog user), NetworkManager, dbus (messagebus user), logind, sshd, cron/crond, 2x agetty (11 processes)
  - Distro-aware: Ubuntu vs RHEL/CentOS paths and daemon names
  - Silent seeding (StateManager only, no events) — systems already booted before scenario window
  - Files: `engine.py` (`_seed_system_process_trees`, `_seed_windows_process_tree`, `_seed_linux_process_tree`)
- [x] **Add scheduled task / cron simulation**
  - Windows: svchost Schedule, taskhostw, usoclient as children of services.exe svchost
  - Linux: logrotate, apt-get update, apt-check as children of cron
  - Integrated into `_generate_system_traffic` per-hour loop
- [x] **New `generate_system_process` method in activity.py**
  - Emits Windows 4688, syslog, and eCAR for system-initiated processes
  - Uses SYSTEM SID (S-1-5-18) / root, no user session required
- [x] Test: System process tree seeded correctly (hierarchy, SIDs, users)
- [x] Test: DNS/NTP UDP connections emitted via generate_connection
- [x] Test: Scheduled tasks are children of correct parent PIDs
- [x] Test: Infrastructure IP detection from scenario systems

### 5.5 Temporal Realism

**Goal:** Replace uniform event distribution with realistic human timing patterns. Address "metronomic spacing" and "hard rectangular work hours."

- [x] **Soft ramp-up/ramp-down for work hours**
  - Replace binary on/off with sigmoid curve: 10% activity at work_start-1h, ramp to 100% by work_start+1h
  - Soft lunch dip (50% reduction, not 0%)
  - Evening tail: 20% activity for 1-2 hours after work_end
  - Occasional late-night activity (1-3% probability per user per night)
  - Files: `engine.py` (`_calculate_events_for_hour`)
- [x] **Activity cluster model**
  - Replace `_distribute_events_in_hour()` uniform distribution with cluster generation
  - Each "activity" becomes a burst of 3-15 correlated events over 5-30 seconds
  - Cluster types per persona: developer (editor→compile→test→git), executive (email→calendar→browser), analyst (query→export→review)
  - Inter-cluster gaps: 2-15 minutes (exponential distribution)
  - Files: `engine.py` (`_distribute_events_in_hour` → `_generate_activity_clusters`), `activity.py` (cluster templates)
- [x] **Per-user work hour jitter**
  - Randomize each user's actual start/end/lunch times ±30min from persona defaults
  - Applied once at engine init, consistent throughout scenario
  - Early arrivals, late starters, short/long lunches
  - Files: `engine.py` (init), `engine.py` (`_calculate_events_for_hour`)
- [x] **Per-persona behavioral differentiation**
  - Developers: longer clusters (sustained coding sessions), more process events, fewer web connections
  - Executives: short frequent clusters (meetings → quick email checks), more web/email, fewer processes
  - Analysts: medium clusters with heavy DB/query activity
  - Each persona type gets distinct cluster templates and inter-cluster timing
  - Files: `activity.py` (persona-specific cluster definitions)
- [x] Test: Events cluster with sub-second intra-cluster timing
- [x] Test: Inter-cluster gaps follow non-uniform distribution
- [x] Test: Work hour profile shows gradual ramp (not step function)
- [x] Test: Per-user timing varies (different arrival times)
- [x] Test: Human burstiness CV > 1.0 (eval dimension)

**Phase 5 Milestone:** Generated data passes qualitative review — no instant tells. Eval score ≥ 85, all hard acceptance criteria pass. Background noise has protocol diversity (TCP+UDP+ICMP), event type depth (≥ 6 Windows Event IDs, ≥ 5 eCAR objects), realistic timing patterns, and hundreds of unique destination IPs.

---

## Phase 6: Expert-Identified Realism Fixes

**Goal:** Address all findings from blind expert panel review (REALISM_ASSESSMENT-2.md). Four domain experts (threat hunter, detection engineer, Windows sysadmin, Linux/network admin) identified the data as synthetic within seconds. This phase fixes the specific tells, organized by severity. Cross-references are to finding numbers in the assessment.

**Source:** `../DataGenTest/scenarios/insider-exfiltration/REALISM_ASSESSMENT-2.md`
**Baseline:** Run 8 (overall eval score 82, 6 of 44 original findings resolved)

### 6.0 Fixes Already Implemented (Run 8)

- [x] **LogonType diversity** — Types 2,3,4,5,7,8,9,10,11 with weighted distribution by system type (#1 original, N1 new)
- [x] **PID multiples of 4** — OS-aware allocation: Windows multiples of 4 from realistic range, Linux sequential (#2 partial)
- [x] **UDP/TCP history separation** — UDP uses Dd/D/DdDd, ICMP uses OTH, protocol-aware conn_state (#3)
- [x] **NXDOMAIN responses** — ~20% of DNS lookups emit NXDOMAIN for suffix search failures, WPAD probes (#4)
- [x] **Syslog volume and diversity** — 12-80 events/hr per Linux server, 10 programs, kernel format, systemd PID 1 (#5)
- [x] **SYSTEM domain** — NT AUTHORITY for SYSTEM account (#14 original)
- [x] **explorer.exe in process tree** — winlogon → userinit → explorer.exe chain seeded (#2 partial)
- [x] **Dynamic ParentProcessName** — looked up from StateManager instead of hardcoded (#2 partial)

### 6.1 P0: Critical (Instant Giveaways)

- [x] **Fix DNS query type semantics** (Assessment #1)
  - AAAA queries return IPv6 addresses, PTR uses `in-addr.arpa`, removed CNAME as qtype
  - Added SRV queries (qtype 33) for AD service discovery
  - Added MX queries; new distribution: 65% A, 20% AAAA, 8% PTR, 5% SRV, 2% MX
  - Files: `activity.py` (`_emit_dns_lookup`, `_IPV6_MAP`, `_AD_SRV_QUERIES`)
- [x] **Fix parent PID — realistic process trees with depth** (Assessment #2)
  - Added `_select_parent_pid()` with dynamic parent selection from process history
  - Windows: shells from explorer, commands from shells, apps can spawn children
  - Linux: commands from bash (spawned from sshd), process tree depth tracked
  - Storyline processes also get correct parents
  - Files: `activity.py` (`_select_parent_pid`, `_record_user_process`), `engine.py`
- [x] **Fix duplicate fields in 4624 XML template** (Assessment #3)
  - Removed 5 duplicate Data elements (TargetUserName, TargetDomainName, TargetLogonId, LogonType, LogonGuid)
  - Files: `formats/definitions/windows_event_security.yaml`
- [x] **Add Kerberos/LDAP/DB traffic to Zeek** (Assessment #4)
  - Kerberos (port 88): 4-8/hr from Windows machines to DC
  - LDAP (port 389): 2-5/hr from Windows machines to DC
  - Database: scenario-driven detection from system `services` list (mssql/mysql/postgres)
  - `connection_db` activity uses scenario DB servers when available
  - Files: `engine.py` (`_generate_system_traffic`, `_detect_infrastructure_ips`), `activity.py`
- [x] **Correlate Zeek UIDs across all log types** (Assessment #5)
  - Zeek UID now stored on `OpenConnection` in StateManager, generated at `open_connection()` time
  - All Zeek log types for same connection share the UID automatically
  - Future-proof: http.log, files.log, smtp.log will use same pattern
  - Files: `models/state.py`, `state_manager.py`, `activity.py`

### 6.2 P1: Major (Would Fool Casual Observers, Not Experts)

- [x] **Add missing Windows Event IDs** (Assessment #6, #8)
  - Added 4768/4769 (Kerberos TGT/service tickets), 4776 (NTLM validation)
  - Added 5156 (WFP connection allowed), 4648 (explicit creds) — YAML templates + generation functions
  - Updated eval distribution profiles, co-occurrence rules, and WINDOWS_VARIANT_MAP
  - Future: 5140/5145 (share access), 4720-4740 (account management), 4103/4104 (PowerShell)
- [x] **Add machine account ($) activity** (Assessment #7)
  - `generate_machine_account_logon()` emits 4624 type 3 with HOSTNAME$ on DC
  - 2-6 machine account auth cycles per Windows system per hour in `_generate_system_traffic()`
- [x] **Set `local_resp: true` for internal servers** (Assessment #9)
  - `_is_private_ip()` helper using `ipaddress.ip_address().is_private`
  - Both `local_orig` and `local_resp` now dynamically set based on IP
- [x] **Fix Zeek packet/byte IP+TCP overhead** (Assessment #10)
  - TCP: random 52-72 bytes (IP+TCP+options), UDP: 28 bytes (IP+UDP)
- [x] **Per-computer EventRecordIDs** (Assessment #11)
  - `_event_record_counters: dict[str, int]` with per-host lazy init at random offset (1000-50000)
  - Deterministic seed from hostname for reproducibility
- [x] **Fix LogonType distribution** (Assessment #12, N1)
  - Servers/DCs: Type 3 at 70%, workstations: Type 3 at 55%
  - Type 5 restricted to service accounts ($ suffix or svc prefix)
- [x] **Massively increase DC event volume** (Assessment #13, N2)
  - DC-side Kerberos generation: 3-8 TGT+service ticket cycles per client per DC per hour
  - 10% NTLM fallback via 4776 events
- [x] **Break mechanical traffic pattern** (Assessment #14, N3)
  - Shuffled activity order, 15% idle periods, 20% burst mode (2-4x repeats)
  - Per-activity jitter (0-55s) within timeslots
- [x] **Route SMTP through internal Exchange** (Assessment #15)
  - Exchange detection via hostname ('exch'/'mail') in `_detect_infrastructure_ips()`
  - Email routes to Exchange IP:25 when detected, falls back to external on 587
- [x] **Route DNS through documented DCs** (Assessment #16)
  - `infra['dns']` now `list[str]` supporting multiple DCs
  - DNS queries randomly distributed across detected DC IPs

### 6.3 P2: Moderate (Polish & Realism)

- [x] **Add jitter to storyline timestamps** (Assessment #17)
  - ±30s random jitter + random microseconds; causal ordering enforced
- [x] **Realistic LogonIDs** (Assessment #18)
  - Random 32-bit hex values (0x10000-0xFFFFFFFF), well-known values excluded
- [x] **Populate real base64 in encoded commands** (Assessment #19)
  - 10 realistic decoded PowerShell commands, proper UTF-16LE base64 encoding
- [x] **Use realistic public IPs for exfiltration** (Assessment #20)
  - Real cloud/hosting IPs (DigitalOcean, Linode, Vultr ranges) replace RFC 5737
- [x] **Add Kerberos auth package + LogonGuids** (Assessment #21)
  - Type 3: 70% Kerberos/20% NTLM/10% Negotiate; non-null GUID when Kerberos
- [x] **Fix internal DNS IPs and DB ports** (Assessment #22)
  - DB connections require scenario-detected servers; no fallback to hardcoded 10.0.100.x
- [x] **Fix Zeek `ts` type consistency** (Assessment #23)
  - Both emitters output float (bare number in JSON), not string
- [x] **Interleave scenario events chronologically** (Assessment #24)
  - Storyline events injected into baseline hour loop; remaining executed after
  - Pre-parsed event times by hour; `_execute_single_storyline_event()` for interleaving
- [x] **Add FQDN to Computer names** (Assessment #25)
  - Optional `Environment.domain` field; auto-inferred from user emails
  - All Windows event Computer fields: `hostname.domain`; dynamic NetBIOS domain
- [x] **Add RID gaps and computer account SIDs** (Assessment #26)
  - Random 1-5 gaps between user RIDs; well-known RIDs (500-502); computer SIDs
- [x] **Use SSH source IPs from documented subnets** (Assessment #27)
  - SSH sources from scenario system IPs, not hardcoded 10.0.x.x
- [x] **Sort syslog chronologically** (Assessment #28)
  - SyslogEmitter sorts buffer by timestamp prefix before flush
- [x] **Limit systemd-timesyncd message** (Assessment #29)
  - "for the first time" only once per system; subsequent messages varied
- [x] **Diversify Zeek history strings** (Assessment #30)
  - 21 TCP + 8 UDP patterns (was 7+4); retransmission markers, varied FIN ordering
- [x] **Correlate eCAR/Zeek source ports** (Assessment #31)
  - src_port passed from generate_connection() to _emit_ecar_flow_event()
- [x] **Add SERVFAIL responses** (Assessment #32)
  - 0.2% SERVFAIL; multi-answer DNS (2-5 IPs) for external A records

### 6.4 P3: Minor (Nice-to-Have Improvements)

- [x] **Fix eCAR DNS FLOW protocol to UDP** (Assessment #33, Improvement Loop Iter 2)
  - eCAR now uses `"udp"` for DNS (port 53) and NTP (port 123) connections
  - Files: `activity.py` (`_emit_ecar_flow_event`)
- [ ] **Add process attribution to eCAR FLOWs** (Assessment #34)
  - `pid: -1` on all FLOW events; real EDR tracks socket-to-process mapping
  - Files: `activity.py` (`_emit_ecar_flow_event`)
- [ ] **Reduce eCAR LOGIN frequency** (Assessment #35)
  - LOGIN events paired with every activity burst; users generate new LOGIN every 1-2 seconds
  - Files: `activity.py` (`execute_baseline_activity`)
- [ ] **Vary filenames in eCAR file operations** (Assessment #36)
  - Cycles through 5 generic filenames: spreadsheet.xlsx, presentation.pptx, notes.txt, etc.
  - Files: `activity.py` (_ECAR_FILE_PATHS_WIN, _ECAR_FILE_PATHS_LINUX)
- [ ] **Decrement DNS TTLs for cached responses** (Assessment #37)
  - Always round values; cached responses should show decremented TTLs
  - Files: `activity.py` (`_emit_dns_lookup`)
- [ ] **Fix 4625 event Version to 0** (Assessment #38)
  - Uses Version 2 instead of standard Version 0 for 4625
  - Files: `formats/definitions/windows_event_security.yaml`
- [ ] **Vary command-line arguments** (Assessment #39)
  - Same exact PowerShell/sqlcmd commands repeated dozens of times
  - Files: `activity.py` (PROCESS_TEMPLATES)
- [ ] **Add PID interleaving for CRON** (Assessment #40, N6)
  - CRON PIDs too sequential (1660, 1661, 1662...); needs interleaving from other processes
  - Files: `engine.py` (syslog CRON generation)
- [ ] **Include resp_ip_bytes: 0 on zero-packet records** (Assessment #41)
  - Some records missing resp_ip_bytes instead of having it set to 0
  - Files: `activity.py` (`generate_connection`)
- [ ] **Multiple answers for popular DNS domains** (Assessment #42)
  - Every query returns single answer; CDN domains return multiple A records
  - Files: `activity.py` (`_emit_dns_lookup`)
- [x] **Add `<Events>` root XML wrapper** (Assessment #43, Improvement Loop Iter 2)
  - XML declaration + `<Events>` root + `</Events>` footer via header/footer templates
  - Files: `emitters/base.py`, `formats/format_def.py`, `formats/definitions/windows_event_security.yaml`
- [ ] **Set AA flag for internal DNS** (Assessment #44)
  - Internal zone queries (corp.local) show AA: false; should be authoritative
  - Files: `activity.py` (`_emit_dns_lookup`)

### 6.5 Improvement Loop Findings (2026-03-18)

**Source:** Automated improvement loop with 4-expert blind panel on `insider-exfiltration` scenario.
**Baseline:** Eval 75.4/100 → **Final: 90.6/100** across 5 iterations.

#### Resolved in improvement loop:
- [x] **Zeek UID source port mismatch** (P0, Iter 2)
  - conn.log and dns.log had different `id.orig_p` for same UID
  - Fix: pass `src_port` through `generate_connection()` to dns.log emission
  - Files: `activity.py` (`generate_connection`, `_emit_dns_lookup`)
- [x] **TCP orig_pkts inconsistent with history** (P0, Iter 2)
  - `orig_pkts: 1` with `history: "ShADadfF"` (implies 4+ orig packets)
  - Fix: derive TCP packet counts from history field characters
  - Files: `activity.py` (`generate_connection`)
- [x] **External CDN hostnames resolve to internal IPs** (P0, Iter 3)
  - `cdn-3986.cloudfront.net` → `10.10.100.16` (impossible in reality)
  - Fix: internal IPs get internal hostnames (`srv-01.corp.local` pattern)
  - Files: `activity.py` (`_emit_dns_lookup`, `_generate_internal_hostname`)
- [x] **Fabricated CDN/cloud hostnames** (P0, Iter 3)
  - `server-68-352.compute.amazonaws.com`, `cdn-NNNN.cloudfront.net` — wrong format
  - Fix: realistic formats (ec2-x-x-x-x, d{hash}.cloudfront.net, e{id}.dscb.akamaiedge.net)
  - Files: `activity.py` (`_generate_random_hostname`)
- [x] **Reserved domains in DNS** (P1, Iter 3)
  - `api.example.com`, `blog.example.com`, `cdn.example.com`, `www.example.com`
  - Fix: replaced with real service domains in REVERSE_DNS map
  - Files: `activity.py` (REVERSE_DNS)
- [x] **Same IPv6 for all AAAA queries** (P1, Iter 3)
  - 87% of AAAA responses used `2607:f8b0:` (Google prefix) regardless of provider
  - Fix: diverse prefixes per provider (Azure, Akamai, AWS, Cloudflare, Fastly)
  - Files: `activity.py` (`_ipv4_to_fake_ipv6`)
- [x] **4625 SID contradiction with SubStatus** (P0, Iter 4)
  - SubStatus `0xc0000064` (user not found) paired with valid domain SID
  - Fix: NULL SID `S-1-0-0` for unknown-user failures; varied SubStatus types
  - Files: `activity.py` (`generate_failed_logon`)
- [x] **4768:4769 TGT/TGS 1:1 ratio** (P0, Iter 4)
  - Exact same count (90,344 each) — statistically impossible
  - Fix: 2-5 TGS per TGT; TGS targets member servers (60%) not just DCs
  - Files: `engine.py` (`_generate_system_traffic`)
- [x] **Zero ICMP traffic** (P0, Iter 5)
  - 250K conn.log entries with no ICMP at all
  - Fix: servers ping each other 0-1 times per hour
  - Files: `engine.py` (`_generate_system_traffic`)
- [x] **NXDOMAIN `NonExistentSite` literal** (P2, Iter 2)
  - Placeholder string used as AD site name
  - Fix: replaced with `Default-First-Site-Name`
  - Files: `activity.py` (`_emit_dns_lookup`)

#### Eval scoring fixes (Iter 1):
- [x] **FQDN hostname normalization** — eval VisibilityModel and all dimension scorers
  now handle both bare and FQDN hostnames (Source Correctness: 1→100)
- [x] **PreAuthType integer coercion** — Windows parser now coerces to int (Parsability: 92→99.5)
- [x] **Timezone-aware work hours** — eval compares in scenario timezone, not UTC
- [x] **AD ports in common ports list** — Kerberos (88), LDAP (389) no longer flagged as anomalous
- [x] **Deep off-hours anomaly detection** — only midnight-5am flagged, not all off-hours

#### Remaining tells (not yet addressed):

**P0 — Instant Giveaways:**
- [ ] **RFC 5737 documentation IP (203.0.113.50) for exfiltration target**
  - TEST-NET-3 range instantly recognizable; also has `local_resp: true`
  - Fix: use realistic cloud storage IPs; fix `_is_private_ip()` for exfil destinations
  - Files: `activity.py` (storyline connection handling), scenario YAML
- [ ] **No DNS resolution for exfiltration/storyline targets**
  - Connections to 203.0.113.50 (pCloud) have no corresponding DNS queries
  - Fix: emit DNS lookup before each storyline network connection
  - Files: `engine.py` (storyline execution), `activity.py`
- [ ] **Kernel uptime counters non-monotonic in syslog**
  - Values jump randomly (1061731 → 516344 → 460933) instead of increasing
  - Fix: track per-host uptime state in StateManager, increment monotonically
  - Files: `engine.py` (syslog generation), `state_manager.py`
- [ ] **EventRecordID timestamps go backward within same computer**
  - Higher RecordID has earlier timestamp (events shuffled then sequentially numbered)
  - Fix: sort events by timestamp before assigning EventRecordIDs per computer
  - Files: `emitters/windows.py` or `engine.py` (event ordering)
- [ ] **No SSH/RDP connections in Zeek despite syslog SSH sessions**
  - Syslog shows active sshd but conn.log has zero port 22/3389 traffic
  - Fix: generate Zeek conn.log entries for SSH connections to Linux hosts
  - Files: `engine.py` (`_generate_system_traffic`)

**P1 — Expert-Level Tells:**
- [ ] **No LogonType 5 (Service) events**
  - Zero events; real Windows servers constantly generate type 5 for services
  - Fix: emit 4624 type 5 for service accounts (svc*, $-suffix) in system traffic
  - Files: `engine.py` (`_generate_system_traffic`), `activity.py`
- [ ] **No ANONYMOUS LOGON (S-1-5-7) events**
  - Real environments have frequent anonymous logons from network discovery
  - Fix: emit periodic 4624 type 3 with ANONYMOUS LOGON on servers/DCs
  - Files: `engine.py` (`_generate_system_traffic`)
- [ ] **LmPackageName always "-" even for NTLM authentications**
  - Should be "NTLM V2" when AuthenticationPackageName is "NTLM"
  - Files: `activity.py` (`generate_logon`, `generate_failed_logon`)
- [ ] **Zeek history "SS" is invalid**
  - Repeated SYN is still "S" in real Zeek; "SS" never appears
  - Fix: remove "SS" from `_TCP_CONN_ENTRIES` history patterns
  - Files: `activity.py` (`_TCP_CONN_ENTRIES`)
- [ ] **Service distribution unrealistic** (too much Kerberos/LDAP, too little HTTPS)
  - Real enterprises have HTTPS as dominant protocol
  - Fix: increase baseline HTTPS connections, reduce Kerberos frequency
  - Files: `engine.py` (`_generate_system_traffic`)
- [ ] **No 4770 TGT Renewal events**
  - TGTs expire every ~10 hours; 3-day window should have renewals
  - Fix: emit 4770 events periodically on DCs
  - Files: `activity.py` (new `generate_kerberos_renewal`), `engine.py`
- [ ] **4672 Special Privileges ratio too low** (9% vs expected ~30%+)
  - Every admin/service/machine account logon should generate paired 4672
  - Fix: emit 4672 for machine accounts, service accounts, admin logons
  - Files: `activity.py` (`generate_logon`, `generate_machine_account_logon`)

**P2 — Polish Issues:**
- [ ] **Events grouped by computer, not chronologically interleaved**
  - Windows XML has all EXEC-WS-01 events, then all EXEC-WS-02, etc.
  - Fix: sort events globally by timestamp before writing
  - Files: `emitters/windows.py` or `engine.py`
- [ ] **Syslog only from 2 hosts** (DMZ-WEB-01, SRV-LOG-01)
  - 118-system environment should have more syslog sources
  - Fix: emit syslog for all Linux systems, or add forwarding from Windows
  - Files: `engine.py` (syslog target selection)
- [ ] **No TXT DNS queries** (SPF/DKIM/DMARC checks)
  - Fix: add periodic TXT lookups for email-related domains
  - Files: `activity.py` (`_emit_dns_lookup`)
- [ ] **Audit serial numbers non-monotonic in syslog**
  - Jump erratically instead of incrementing per boot
  - Fix: track per-host audit serial in StateManager
  - Files: `engine.py`, `state_manager.py`
- [ ] **DNS-then-service paired pattern too uniform**
  - Every connection preceded by DNS with 10-50ms gap; needs caching, concurrency
  - Fix: skip DNS for cached domains, add temporal jitter
  - Files: `activity.py` (`_emit_dns_lookup`)
- [ ] **Ground truth mislabels file servers as "C2 Servers"**
  - Internal SMB servers listed under "C2 Server" IOC category
  - Fix: use correct labels in ground truth generation
  - Files: `ground_truth.py`

### 6.6 Phase 7 Eval Expert Panel Findings (2026-03-19)

**Source:** 4-expert blind panel A/B comparison on `baseline-test` scenario (old pre-Phase-7 vs new post-Phase-7 data).
**Eval scores:** Old 82.3/100 → New 83.7/100 (+1.4). Tells: 36 → 30 (-6).
**Resolved by Phase 7:** 6 tells fixed (lsass PID sharing, PowerShell on Linux, UDP history "DdA", UDP conn_state OTH, missing logoffs, missing service/anonymous logons).

#### New findings (not previously tracked):

**P0 — Instant Giveaways:**
- [ ] **Fabricated PTR records return forward lookup names** (Expert Panel #EP1)
  - `140.82.121.4.in-addr.arpa` → `api.github.com`; real rDNS is `lb-140-82-121-4-iad.github.com`
  - Fix: use realistic rDNS patterns (CDN edge names, cloud instance names)
  - Files: `activity.py` (REVERSE_DNS map, `_emit_dns_lookup`)
- [ ] **Cross-provider DNS: Google hostnames resolve to AWS IPs** (Expert Panel #EP2)
  - `105-10-37-226.bc.googleusercontent.com` → `54.230.26.104` (CloudFront IP)
  - Fix: ensure generated hostname provider matches the IP provider
  - Files: `activity.py` (`_generate_random_hostname`)
- [ ] **`service:"https"` on port 80 connections** (Expert Panel #EP3)
  - Generator applies scenario service label; Zeek would detect HTTP on port 80
  - Fix: port-based service override (80→http, 443→https, 22→ssh)
  - Files: `activity.py` (`generate_connection` or `execute_baseline_activity`)

**P1 — Expert-Level Tells:**
- [ ] **Every user gets SeDebugPrivilege on 4672** (Expert Panel #EP4)
  - 4672 privilege list is identical for all users; only admins should have SeDebugPrivilege
  - Fix: persona-aware privilege lists (admin vs standard user)
  - Files: `emitters/windows.py` (`_render_logon` 4672 section)
- [ ] **No Zeek http.log, ssl.log, or files.log** (Expert Panel #EP5)
  - Only conn.log + dns.log implemented; analysts expect protocol-specific logs
  - Fix: implement http.log and ssl.log emitters (major feature)
  - Files: new emitters needed
- [ ] **No syslog auth.log entries for storyline SSH lateral movement** (Expert Panel #EP6)
  - SSH to WEB-01/FILES-01 visible in Zeek but no corresponding syslog auth messages
  - Fix: emit syslog auth entries for storyline SSH connections
  - Files: `engine.py` (storyline execution), `activity.py`
- [ ] **SYSTEM process (mimikatz) with explorer.exe parent** (Expert Panel #EP7)
  - Credential dump as SYSTEM should have implant/cmd.exe parent, not explorer
  - Fix: storyline processes use correct parent chain from attack sequence
  - Files: `engine.py` (storyline process creation parent selection)
- [ ] **DC EventRecordID offset too low** (~11K) (Expert Panel #EP8)
  - Production DCs have 100K+ events; starting at 11K implies fresh install
  - Fix: increase DC initial offset to 50K-200K range
  - Files: `emitters/windows.py` (RecordID counter initialization)
- [ ] **eCAR ICMP flows use `protocol:"tcp"` instead of `"icmp"`** (Expert Panel #EP9)
  - ICMP has no ports; eCAR should use protocol:"icmp" or omit ICMP FLOWs
  - Files: `activity.py` (`_emit_ecar_flow_event`)

**P2 — Polish Issues:**
- [ ] **Zeek duration has 16+ decimal places** (Expert Panel #EP10)
  - Real Zeek uses microsecond precision (6 decimal places max)
  - Fix: round duration to 6 decimal places
  - Files: `activity.py` (`generate_connection`) or `emitters/zeek.py`
- [ ] **Mechanically regular Kerberos ticket timing** (Expert Panel #EP11)
  - TGT/TGS at even ~7-10min intervals; real Kerberos is bursty around user activity
  - Fix: cluster Kerberos around user activity windows, add jitter
  - Files: `engine.py` (`_generate_system_traffic` Kerberos section)
- [ ] **DNS query set too curated — no Windows telemetry noise** (Expert Panel #EP12)
  - Missing: settings-win.data.microsoft.com, ocsp.digicert.com, *.windowsupdate.com
  - Fix: add Windows telemetry/OCSP/CRL noise domains to DNS query pool
  - Files: `activity.py` (`_emit_dns_lookup` or new background DNS method)
- [ ] **NTP server mismatch: Zeek shows NIST, syslog shows Ubuntu pool** (Expert Panel #EP13)
  - Cross-source inconsistency between network and host logs
  - Fix: use same NTP server IPs in both Zeek conn and syslog timesyncd
  - Files: `engine.py` (`_generate_system_traffic` NTP section)
- [ ] **UFW BLOCK entries don't appear in Zeek conn.log** (Expert Panel #EP14)
  - Blocked SYN packets should appear as S0/REJ in Zeek if sensor is on same segment
  - Fix: emit corresponding Zeek conn records for UFW-blocked connections
  - Files: `engine.py` (syslog UFW generation)
- [ ] **Zeek `missed_bytes` always 0** (Expert Panel #EP15)
  - Real captures have some packet loss; ~1-5% of long connections should have missed_bytes > 0
  - Fix: probabilistic missed_bytes for long-duration connections
  - Files: `activity.py` (`generate_connection`)
- [ ] **Round `.0` timestamps on SSH/ICMP Zeek connections** (Expert Panel #EP16)
  - Storyline/system connections land on exact seconds; real pcap has fractional precision
  - Fix: add microsecond jitter to all Zeek timestamps
  - Files: `engine.py` (storyline/system traffic timestamp generation)

**P3 — Nitpicks:**
- [ ] **No 4778/4779 (RDP reconnect/disconnect) events** (Expert Panel #EP17)
  - LogonType 10 (RDP) events present but no corresponding session events
  - Fix: emit 4778/4779 pairs for RDP logons
  - Files: `activity.py` or `engine.py`

**Phase 6 Milestone:** Expert panel re-review finds no P0 instant giveaways. P1 findings reduced by 50%+. Eval score ≥ 90.

---

## Phase 7: Canonical Event Model

**Goal:** Replace manual per-emitter field coordination with a canonical `SecurityEvent` intermediate representation. Eliminates cross-format consistency bugs by construction — two emitters cannot disagree about shared fields because there is only one source of truth.

**PRD:** See `docs/event-model-prd.md` for full design, data model, and rationale.

**Architecture:** Two-phase build + dispatcher. ActivityGenerator allocates IDs from StateManager first, builds complete SecurityEvent second, dispatches to EventDispatcher which routes to StateManager.apply() + matching emitters.

### 7.1 Foundation (events package + dispatcher + base emitter changes) ✅ COMPLETE

- [x] Create `src/evidenceforge/events/__init__.py` — re-exports SecurityEvent, RawLogEntry, all context types
- [x] Create `src/evidenceforge/events/contexts.py` — all context dataclasses (`HostContext`, `AuthContext`, `ProcessContext`, `NetworkContext`, `DnsContext`, `FileContext`, `RegistryContext`, `IdsContext`)
- [x] Create `src/evidenceforge/events/base.py` — `SecurityEvent` and `RawLogEntry` dataclasses
- [x] Create `src/evidenceforge/events/dispatcher.py` — `EventDispatcher` with `NetworkVisibilityEngine` integration via existing `get_log_formats_for_connection()` API
- [x] Add `apply(event)` to `state_manager.py` — records state from fully-constructed SecurityEvent (teardown/updates only, no ID allocation)
- [x] Add `can_handle()`, `emit()`, `emit_raw()` to `emitters/base.py` (non-abstract defaults for backward compat)
- [x] Implement `_supported_types` on all 8 emitter subclasses (windows, zeek, zeek_dns, ecar, syslog, bash_history, snort, web)
- [x] Update `engine.py` — create `EventDispatcher`, pass to `ActivityGenerator`
- [x] Update `ActivityGenerator.__init__()` — accept `dispatcher: EventDispatcher` (optional for backward compat with tests)
- [x] Add `_build_host_context(system)` helper to ActivityGenerator
- [x] Write `tests/unit/test_events.py` — 11 tests: event/context construction, defaults, slots enforcement
- [x] Write `tests/unit/test_dispatcher.py` — 18 tests: routing, visibility filtering, state_manager.apply(), raw escape hatch, emit/emit_raw defaults, _build_host_context
- [x] Run all existing tests — 793 passed, zero regressions

### 7.2 Migrate Activity Types (one at a time, one commit each)

Migrate each `generate_*` method: refactor to two-phase build + dispatch, implement emitter `_render_{event_type}()` methods, retire corresponding `_emit_ecar_*` helper. Run tests after each.

- [x] **7.2.1** `generate_logon()` — Windows + syslog + eCAR (3 formats)
  - [x] Refactor to build SecurityEvent with HostContext + AuthContext
  - [x] Implement `WindowsEventEmitter._render_logon()`, `SyslogEmitter._render_logon()`, `EcarEmitter._render_logon()`
  - [x] Auto-create EventDispatcher when not provided (backward compat)
  - [x] Add fqdn/netbios_domain to HostContext, auth fields to AuthContext
  - [x] Run tests — 756 passed, zero regressions
- [x] **7.2.4** `generate_logoff()` — Windows + syslog + eCAR (3 formats)
  - [x] Refactor to build SecurityEvent with HostContext + AuthContext
  - [x] Implement `_render_logoff()` on all 3 emitters
  - [x] StateManager.apply() handles end_session (no double-call)
  - [x] Run tests — 757 passed
- [x] **7.2.5** `generate_failed_logon()` — Windows + syslog + eCAR (3 formats)
  - [x] Refactor with AuthContext (result="failure", failure_substatus populated)
  - [x] Add failure_status/failure_substatus to AuthContext
  - [x] Implement `_render_failed_logon()` on all 3 emitters
  - [x] Run tests — 756 passed
- [x] **7.2.3** `generate_process()` — Windows + eCAR (2 formats; Linux skips native log)
  - [x] Refactor to build SecurityEvent with ProcessContext
  - [x] Implement `_render_process_create()` on Windows + eCAR emitters
  - [x] eCAR file/module/registry helpers remain via emit_event (probabilistic diversity)
  - [x] Run tests — 756 passed
- [x] **7.2.6** `generate_process_termination()` — Windows + eCAR (2 formats)
  - [x] Refactor with ProcessContext; StateManager.apply() handles end_process
  - [x] Implement `_render_process_terminate()` on Windows + eCAR emitters
  - [x] Run tests — 756 passed
- [x] **7.2.8** `generate_system_process()` — Windows + syslog + eCAR (3 formats)
  - [x] Refactor with event_type="system_process_create"
  - [x] Windows: 4688 with NT AUTHORITY domain; Syslog: daemon/cron message; eCAR: reuses process_create
  - [x] Run tests — 756 passed
- [x] **7.2.2** `generate_connection()` — Zeek conn (1 format via dispatch; eCAR FLOW still via helper)
  - [x] Refactor to build SecurityEvent with NetworkContext
  - [x] Add orig_ip_bytes, resp_ip_bytes, ip_proto, missed_bytes to NetworkContext
  - [x] Implement ZeekEmitter.emit() for "connection" type
  - [x] Conn state/history/packet derivation stays in activity.py (connection semantics)
  - [x] eCAR FLOW/CONNECT remains via _emit_ecar_flow_event helper
  - [x] Run tests — 756 passed
- [x] **7.2.7** `generate_bash_command()` — bash_history (1 format)
  - [x] Add ShellContext (command, exit_code) to contexts.py
  - [x] Add can_handle/emit to BashHistoryEmitter (Linux-only filter)
  - [x] Run tests — 763 passed
- [x] **7.2.9** `generate_machine_account_logon()` — Windows (1 format)
  - [x] Add _build_dc_host_context helper for raw DC hostname strings
  - [x] Implement _render_machine_logon on WindowsEmitter (4624 type 3)
  - [x] Run tests — 763 passed
- [x] **7.2.10** `generate_kerberos_tgt()` — Windows (1 format)
  - [x] Add KerberosContext dataclass for 4768/4769 fields
  - [x] Implement _render_kerberos_tgt on WindowsEmitter (4768)
  - [x] Run tests — 763 passed
- [x] **7.2.11** `generate_kerberos_service_ticket()` — Windows (1 format)
  - [x] Implement _render_kerberos_service on WindowsEmitter (4769)
  - [x] Run tests — 763 passed
- [x] **7.2.12** `generate_ntlm_validation()` — Windows (1 format)
  - [x] Implement _render_ntlm_validation on WindowsEmitter (4776)
  - [x] Uses AuthContext (not KerberosContext — it's NTLM)
  - [x] Run tests — 763 passed

### 7.3 Cleanup ✅ COMPLETE

- [x] Remove orphaned `_emit_ecar_logon()` and `_emit_ecar_process()` (dead code from 7.2)
- [x] Convert 4 active eCAR helpers to `dispatch_raw()` (file, registry, flow, module)
- [x] Replace `ActivityGenerator.network_visibility` → `self._network_visibility` / `dispatcher.visibility_engine`
- [x] Replace `self.emitters` eCAR guards → `self.dispatcher.emitters`
- [x] Verify all tests pass — 761 passing

### 7.4 Remaining Emissions ✅ COMPLETE

- [x] Migrate DNS lookups (`_emit_dns_lookup`) to dispatch_raw — 3 zeek_dns call sites
- [x] Remove `ActivityGenerator.emitters` dict entirely — all emission via dispatcher
- [x] Migrate engine.py `_generate_system_traffic` direct emissions to dispatch_raw — 9 call sites (2 Windows, 7 syslog)
- [ ] Update `docs/PRD.md` Post-MVP section with Phase 7 status
- [ ] Final eval comparison: `eforge evaluate` before vs. after on `retail-store-ftp-attack.yaml`

**Phase 7 Milestone:** ✅ All event emission goes through EventDispatcher. 12 activity types use canonical SecurityEvent dispatch; eCAR diversity helpers, DNS lookups, and engine system traffic use dispatch_raw (RawLogEntry). Zero direct `self.emitters[]` bracket access in activity.py. 761+ tests passing, zero regressions.

---

## Post-MVP Enhancements (Future)

**Not part of MVP, but tracked here for future reference.**

### Short-term (Post-MVP)
- [ ] ~~Bedrock LLM client for semantic validation~~ → Handled by `/eforge validate` skill
- [ ] Checkpointing and resume for long-running generation
- [ ] Additional skills: create-persona, create-log-format, create-network, analyze-output
- [ ] Example scenario collection (ransomware, credential stuffing, insider threat)
- [ ] ~~Subjective realism evaluation (LLM-based)~~ → Handled by `/eforge evaluate` skill
- [ ] Config file inheritance/templating
- [ ] PyPI package distribution
- [ ] Additional log formats (CloudTrail, Azure Activity, GCP Audit, database logs)
- [ ] Network diagram ingestion: auto-infer sensor placement (span vs tap) from diagram topology
- [ ] ~~Per-user work hours jitter~~ → Moved to Phase 5.5
- [ ] Performance optimizations (Rust extensions, better parallelization)
- [ ] Full user directory export as separate CSV file for large scenarios (ENVIRONMENT.md enhancement)
- [ ] Authentication and naming convention documentation in ENVIRONMENT.md
- [ ] Separate student/instructor output packages (GROUND_TRUTH.md in instructor-only directory)
- [ ] Poisson/Hawkes process timing model: replace Phase 5.5 activity clusters with self-exciting point process for statistically rigorous inter-arrival times (CV naturally 1-3)

### Medium-term
- [ ] ~~Alternative LLM backends (OpenAI, Ollama, Anthropic native, Gemini)~~ → No code-level LLM calls; skills use whatever model the user's Claude Code runs
- [ ] Web UI for scenario creation
- [ ] Streaming output to SIEM/data lakes
- [ ] Log format auto-detection from samples
- [ ] ~~Machine learning-based realism scoring~~ → Superseded by Phase 4 statistical scoring approach

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

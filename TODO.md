# EvidenceForge Implementation Plan

**Status:** Phase 4 - Data Quality Evaluation ✅ SCORING COMPLETE (5/5 dimensions). LLM spot-check deferred.
**Started:** 2026-03-11
**Last Updated:** 2026-03-16 (Phase 4 eval framework complete: 5 dimensions, 23 sub-scores, 653+ tests)
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

- [ ] **Fix empty SID fields in Windows events**
  - Generate realistic SIDs: `S-1-5-21-{domain_sub_authorities}-{user_rid}`
  - Assign per-domain base SID at engine init (e.g., `S-1-5-21-3623811015-3361044348-30300820`)
  - Map each user to a unique RID (starting at 1001, incrementing)
  - Well-known SIDs for system accounts: `S-1-5-18` (SYSTEM), `S-1-5-19` (LOCAL SERVICE), `S-1-5-20` (NETWORK SERVICE)
  - Populate `SubjectUserSid` and `TargetUserSid` in all Windows event data dicts in `activity.py`
  - Files: `activity.py`, `engine.py` (SID registry initialization)
- [ ] **Add logoff generation to baseline activity**
  - Track active sessions per user; probabilistically end sessions (e.g., 30% chance per hour after first hour)
  - Emit Windows 4634 (logoff) and eCAR USER_SESSION/LOGOUT
  - Ensure logon→activity→logoff ordering within each session
  - Files: `activity.py` (`execute_baseline_activity`), `engine.py` (`_generate_baseline`)
- [ ] **Vary Zeek conn_state and history strings**
  - Replace hardcoded `SF`/`ShADadfF` with probabilistic selection
  - Connection states: SF (85%), S0 (5%), S1 (3%), REJ (2%), RSTO (3%), RSTR (1%), OTH (1%)
  - Generate history strings that match conn_state (e.g., S0→`S`, REJ→`Sr`, RSTO→`ShADaR`)
  - Adjust orig_bytes/resp_bytes to be consistent (e.g., S0 = 0 resp_bytes)
  - Files: `activity.py` (`generate_connection`)
- [ ] **Expand process template pools**
  - Windows: add system backbone (svchost.exe, lsass.exe, explorer.exe, services.exe, csrss.exe, RuntimeBroker.exe, SearchIndexer.exe) + user apps (chrome.exe, firefox.exe, outlook.exe, teams.exe, OneDrive.exe)
  - Linux: add system processes (systemd, cron, sshd, rsyslogd, NetworkManager) + user apps (firefox, thunderbird, git, docker, python3)
  - Per-persona weighting: developers see more compilers/editors, executives see more Office/browser
  - Files: `activity.py` (PROCESS_TEMPLATES, PROCESS_TEMPLATES_LINUX)
- [ ] Test: Parsability score ≥ 98% (SIDs valid format)
- [ ] Test: Logoff events present in output, paired with logons
- [ ] Test: conn_state distribution is varied (not 100% SF)
- [ ] Test: Process path count > 30 unique paths

### 5.2 Event Type Diversity

**Goal:** Expand the vocabulary of events generated. Address "only 2 Event IDs" and "only 2 eCAR object types."

- [ ] **Add Windows Event IDs to format definition and emitters**
  - 4625: Failed logon (account does not exist, bad password, account locked)
  - 4672: Special privileges assigned to new logon (admin logons)
  - 4689: Process termination (pair with 4688)
  - 4648: Explicit credential logon (RunAs, scheduled tasks)
  - 5156: Windows Filtering Platform connection allowed (host firewall)
  - Update `windows_event_security.yaml` schema, Jinja2 templates, and validation rules
  - Files: `formats/definitions/windows_event_security.yaml`, `generation/emitters/windows.py`
- [ ] **Generate failed logons in baseline**
  - 5-15% of logon attempts fail (configurable via persona risk_profile)
  - Failure reasons: bad password (most common), account locked, expired password
  - Emit Windows 4625 + eCAR USER_SESSION/LOGON_FAILURE
  - Files: `activity.py` (`generate_logon` or new `generate_failed_logon`)
- [ ] **Add eCAR object type diversity**
  - FILE/CREATE, FILE/MODIFY, FILE/DELETE — generated alongside process activity
  - REGISTRY/MODIFY — Windows system processes and app installs
  - FLOW/CONNECT — parallel to Zeek connections for eCAR-equipped hosts
  - MODULE/LOAD — DLL loads for Windows processes
  - Files: `activity.py` (new methods), `generation/emitters/ecar.py`
- [ ] **Add process termination events**
  - Pair 4689 with 4688: terminate processes after realistic duration (seconds to hours)
  - Track running processes in StateManager, probabilistically terminate
  - Files: `activity.py`, `state_manager.py`
- [ ] Test: ≥ 6 unique Windows Event IDs in output
- [ ] Test: ≥ 5 unique eCAR object types in output
- [ ] Test: Failed logon rate between 5-15% of total logon events
- [ ] Test: Process termination events present, paired with creation

### 5.3 Protocol & Network Diversity

**Goal:** Eliminate the "zero UDP/ICMP" and "only 11 IPs" tells. Add realistic network protocol mix.

- [ ] **Add UDP traffic generation**
  - DNS queries (UDP 53): every TCP connection preceded by a DNS lookup; add `generate_dns_query()` that emits Zeek dns.log-style conn records
  - NTP sync (UDP 123): periodic per-system (every 5-15 minutes to 1-3 NTP servers)
  - DHCP (UDP 67/68): at session start for dynamic-IP systems
  - mDNS/LLMNR (UDP 5353/5355): periodic local name resolution
  - QUIC (UDP 443): percentage of HTTPS traffic uses QUIC
  - Files: `activity.py` (new methods), `engine.py` (system traffic loop)
- [ ] **Add ICMP traffic generation**
  - Periodic ping (ICMP echo) between systems on same segment
  - Occasional ICMP unreachable for failed connections
  - Files: `activity.py` (`generate_icmp`)
- [ ] **Implement service registry for internal IP consistency**
  - At engine init, build a registry of which internal IPs run which services (ports)
  - Sources: declared systems + auto-generated infrastructure IPs (DNS server, mail server, DC, file server, NTP server)
  - All connections to internal IPs check the registry; connection success/failure is consistent with whether the port is open
  - Files: new `generation/service_registry.py`, `engine.py` (initialization)
- [ ] **Expand external destination IP pools**
  - Grow to ~50+ IPs per category with realistic assignments (CDN ranges, cloud provider ranges, SaaS IPs)
  - Add random IP generation for long-tail destinations (simulate CDN edge nodes, ad networks, analytics)
  - Total unique destination IPs per scenario should be hundreds, not 11
  - Files: `activity.py` (EXTERNAL_IPS → larger pools + generator)
- [ ] **Add Zeek dns.log format definition** (new format)
  - Query name, query type, response code, answers
  - Files: new `formats/definitions/zeek_dns.yaml`, new `generation/emitters/zeek_dns.py`
- [ ] Test: UDP traffic present (proto=udp in Zeek output)
- [ ] Test: DNS queries present for TCP connection destinations
- [ ] Test: ≥ 100 unique destination IPs in medium dataset
- [ ] Test: Internal IP service consistency (no successful connections to closed ports)

### 5.4 Background Traffic & System Activity

**Goal:** Generate OS-appropriate system/service traffic independent of user activity. Eliminate the "all traffic is user-initiated" tell.

- [ ] **Add optional `services` field to System model (inline)**
  - Extend `System` in `models/scenario.py` with optional `services: list[str]` field (e.g., `["dns", "ntp", "http", "smb"]`)
  - Auto-populate defaults based on OS if not specified: Windows gets `["dns-client", "ntp-client", "smb", "windows-update"]`, Linux gets `["dns-client", "ntp-client", "syslog"]`
  - Servers auto-detect from role/hostname hints (e.g., hostname contains "dc" or "dns" → add `dns-server`)
  - Files: `models/scenario.py`, `validation/schema.py`
- [ ] **Add system traffic generation loop in engine**
  - New `_generate_system_traffic()` method called per-hour alongside user activity
  - Generates: DNS lookups, NTP sync, Windows Update checks, SMB browsing, DHCP renewals
  - System processes: svchost.exe spawns, scheduled tasks, service startups
  - Volume: system traffic should be ~20-30% of total traffic
  - Files: `engine.py` (`_generate_baseline` calls new system traffic method)
- [ ] **Generate system process trees**
  - Windows: System(4) → smss.exe → csrss.exe, wininit.exe → services.exe → svchost.exe (multiple instances)
  - Linux: init/systemd → cron, sshd, rsyslogd, NetworkManager
  - Generate at scenario start time, persist through time window
  - Files: `activity.py` (new `generate_system_boot_processes`)
- [ ] **Add scheduled task / cron simulation**
  - Windows: periodic svchost activity, Windows Defender scans, Update checks
  - Linux: cron jobs (logrotate, package updates, monitoring scripts)
  - Regular intervals with slight jitter (±5% of period)
  - Files: `engine.py` or `activity.py`
- [ ] Test: System-generated events present without user activity
- [ ] Test: System processes appear at scenario start
- [ ] Test: DNS/NTP traffic at regular intervals
- [ ] Test: System traffic is ~20-30% of total output

### 5.5 Temporal Realism

**Goal:** Replace uniform event distribution with realistic human timing patterns. Address "metronomic spacing" and "hard rectangular work hours."

- [ ] **Soft ramp-up/ramp-down for work hours**
  - Replace binary on/off with sigmoid curve: 10% activity at work_start-1h, ramp to 100% by work_start+1h
  - Soft lunch dip (50% reduction, not 0%)
  - Evening tail: 20% activity for 1-2 hours after work_end
  - Occasional late-night activity (1-3% probability per user per night)
  - Files: `engine.py` (`_calculate_events_for_hour`)
- [ ] **Activity cluster model**
  - Replace `_distribute_events_in_hour()` uniform distribution with cluster generation
  - Each "activity" becomes a burst of 3-15 correlated events over 5-30 seconds
  - Cluster types per persona: developer (editor→compile→test→git), executive (email→calendar→browser), analyst (query→export→review)
  - Inter-cluster gaps: 2-15 minutes (exponential distribution)
  - Files: `engine.py` (`_distribute_events_in_hour` → `_generate_activity_clusters`), `activity.py` (cluster templates)
- [ ] **Per-user work hour jitter**
  - Randomize each user's actual start/end/lunch times ±30min from persona defaults
  - Applied once at engine init, consistent throughout scenario
  - Early arrivals, late starters, short/long lunches
  - Files: `engine.py` (init), `engine.py` (`_calculate_events_for_hour`)
- [ ] **Per-persona behavioral differentiation**
  - Developers: longer clusters (sustained coding sessions), more process events, fewer web connections
  - Executives: short frequent clusters (meetings → quick email checks), more web/email, fewer processes
  - Analysts: medium clusters with heavy DB/query activity
  - Each persona type gets distinct cluster templates and inter-cluster timing
  - Files: `activity.py` (persona-specific cluster definitions)
- [ ] Test: Events cluster with sub-second intra-cluster timing
- [ ] Test: Inter-cluster gaps follow non-uniform distribution
- [ ] Test: Work hour profile shows gradual ramp (not step function)
- [ ] Test: Per-user timing varies (different arrival times)
- [ ] Test: Human burstiness CV > 1.0 (eval dimension)

**Phase 5 Milestone:** Generated data passes qualitative review — no instant tells. Eval score ≥ 85, all hard acceptance criteria pass. Background noise has protocol diversity (TCP+UDP+ICMP), event type depth (≥ 6 Windows Event IDs, ≥ 5 eCAR objects), realistic timing patterns, and hundreds of unique destination IPs.

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

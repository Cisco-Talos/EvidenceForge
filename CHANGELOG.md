# EvidenceForge Development Changelog

Detailed development history for the EvidenceForge project. Transferred from TODO.md during release preparation. For active and planned work, see [TODO.md](TODO.md).

---

## Phase 1: Core Generation (COMPLETE)

**Goal:** Prove the concept with basic functionality, simplified schema, 2-3 log formats, small datasets (<10K events).

### 1.1 Project Setup & Infrastructure
- [x] Initialize uv project with pyproject.toml
- [x] Set up src/evidenceforge/ package structure
- [x] Create tests/ directory structure (unit/, integration/, live/, fixtures/)
- [x] Set up pytest with coverage configuration
- [x] ~~Create .env.example with AWS_PROFILE, AWS_REGION placeholders~~ REMOVED (no Bedrock integration)
- [x] ~~Create config.example.yaml with documented parameters~~ REMOVED (no config.yaml needed)
- [x] Add LICENSE file (MIT)
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

### 1.4 State Management
- [x] `generation/state_manager.py` - StateManager class
  - [x] Session creation and tracking (LogonID generation)
  - [x] Process creation and tracking (PID allocation per system)
  - [x] Connection tracking
  - [x] DNS cache
  - [x] Thread-safe reads, single-threaded writes
- [x] Test: Unique PID generation per system
- [x] Test: Session/process lifecycle

### 1.5 Format Definitions (2 formats)
- [x] `formats/format_def.py` - Pydantic models for format definitions
- [x] `formats/loader.py` - YAML format definition loader
- [x] `formats/validator.py` - JSON Logic validator integration
- [x] `formats/definitions/windows_event_security.yaml`
- [x] `formats/definitions/zeek_conn.yaml`
- [x] FLOAT field type for Zeek duration field
- [x] test_zeek_format_accuracy.py for real-world validation

### 1.6 Log Emitters (2 formats)
- [x] `generation/emitters/base.py` - LogEmitter ABC with buffering (10K events)
- [x] `generation/emitters/windows.py` - Windows Event Log emitter (XML)
- [x] `generation/emitters/zeek.py` - Zeek conn.log emitter (NDJSON)
- [x] `utils/ids.py` with generate_zeek_uid() for 18-character UIDs

### 1.7 Generation Engine
- [x] `generation/engine.py` - Main generation orchestrator
- [x] `generation/activity.py` - Activity execution logic
- [x] `generation/ground_truth.py` - Ground truth documentation generator
- [x] CLI entry point with Typer + Rich progress bars

### 1.8 Scenario Validation
- [x] `validation/schema.py` - Cross-reference validation
- [x] Pydantic model validation with clear error messages
- [x] 93 tests passing at Phase 1 completion

---

## Phase 2: Scalability (COMPLETE)

**Goal:** Handle real-world dataset sizes with parallel generation, 7 MVP formats, medium datasets (100K+ events).

### 2.1 Parallel Generation
- [x] Thread-safe StateManager with RLock
- [x] Emitter threading (one thread per log format)
- [x] Hour-level barriers for temporal consistency
- [x] Bounded queues with backpressure (50K events)

### 2.2 Additional Log Formats (5 new, 7 total)
- [x] eCAR (MITRE CAR-based EDR/XDR, NDJSON)
- [x] Syslog (Linux, RFC 5424/BSD format)
- [x] Bash history (per-user timestamped)
- [x] Snort/Suricata IDS alerts
- [x] Web access logs (Apache/Nginx combined)

### 2.3 Cross-Log Consistency
- [x] Windows Event IDs 4624, 4634, 4688, 4689
- [x] Zeek conn.log with consistent UIDs
- [x] eCAR PROCESS, FILE, FLOW, USER_SESSION
- [x] Syslog auth.info for SSH/PAM events

### 2.4 Persona-Based Temporal Distribution
- [x] Work hours parsing with ramp-up/ramp-down
- [x] Per-persona activity probability weights
- [x] Configurable work_hours string format

### 2.5 Network Visibility Modeling
- [x] NetworkSegment and NetworkSensor models
- [x] SPAN (all traffic) vs TAP (boundary only) placement
- [x] Directional sensors (inbound, outbound, bidirectional)
- [x] Format-aware emission (Zeek vs Snort per sensor)

### 2.6 Storyline Enhancements
- [x] Failed logon events (4625)
- [x] Account creation (4720)
- [x] Service installation (4697)
- [x] Log clearing (1102)
- [x] Supplementary event inference from command-line patterns

### 2.7 LLM Integration — OBSOLETE
- ~~Bedrock LLM client~~ → Replaced by Claude Code Skills architecture

### 2.8-2.9 Evaluation Framework (moved to Phase 4)

### 2.10 Multi-OS Support
- [x] OS detection from system OS string
- [x] Windows: Security Events + Sysmon + optional eCAR
- [x] Linux: syslog + bash_history + optional eCAR
- [x] OS-aware activity generation

**Phase 2 Milestone:** 7 formats in parallel, 100-user 8-hour scenarios in ~14 seconds. 526 tests passing.

---

## Phase 3: MVP Release (COMPLETE)

**Goal:** Ship skills for scenario creation, persona library, install command, and documentation.

### 3.1 Claude Code Skills + Install Command
- [x] `/eforge scenario` — Guided scenario creation with hybrid interview flow
- [x] `/eforge generate` — Generation workflow with pre-flight validation
- [x] `/eforge validate` — Schema and cross-reference validation
- [x] `eforge install-skills` CLI command (project + global scope)
- [x] Skills bundled as package data via importlib.resources + hatch force-include
- [x] 10-tactic MITRE ATT&CK kill chain template
- [x] ENVIRONMENT.md student context document generation

### 3.2 Pre-Built Persona Library
- [x] 15 personas: developer, executive, analyst, sysadmin, help_desk, hr, legal_counsel, marketing, sales, intern, receptionist, accountant, data_analyst, project_manager, security_analyst
- [x] Realistic work hours, activity patterns, risk profiles

### 3.3 Documentation
- [x] Scenario reference documentation (full YAML schema)
- [x] README with quick start and feature overview
- [x] Evidence formats reference
- [x] AGENTS.md coding conventions

---

## Phase 4: Data Quality Evaluation (COMPLETE)

**Goal:** Add `eforge eval` command scoring datasets across 5 quality dimensions with 23 sub-scores.

### 4.1 Report Framework & CLI
- [x] `evaluation/engine.py` — Orchestrator with progress callbacks
- [x] `evaluation/report.py` — Rich text + JSON report formatting
- [x] `evaluation/models.py` — QualityReport, DimensionScore, SubScore
- [x] `eforge eval` CLI command with Rich progress bars
- [x] 7 log parsers: XML, NDJSON, regex

### 4.2 Record-Level Fidelity (weight: 0.15)
- [x] Parsability, co-occurrence rules, population statistics (JSD)

### 4.3 Signal Integrity (weight: 0.20)
- [x] Event presence, indicator accuracy, pivot linkability, storyline temporal integrity

### 4.4 Cross-Source Consistency (weight: 0.20)
- [x] Source correctness, trace coverage, cross-format agreement

### 4.5 Temporal Realism (weight: 0.20)
- [x] Work-hour distribution, burstiness, causal ordering (YAML rule-based)

### 4.6 Noise Realism (weight: 0.25)
- [x] Volume adequacy, diversity, plausibility, statistical anomaly detection

---

## Phase 5: Data Realism Improvements (COMPLETE)

**Goal:** Fix generator-level tells to make data indistinguishable from real data at casual inspection.

### 5.1 Record Fidelity Quick Wins
- [x] Realistic SID generation (S-1-5-21-{domain}-{user_rid})
- [x] Logoff generation for baseline sessions
- [x] Varied Zeek conn_state/history strings
- [x] Expanded process template pools (OS-aware)

### 5.2 Failed Logons & Process Termination
- [x] Background failed logon noise (wrong password, expired account, lockout)
- [x] Process termination events (4689) matching 4688 lifecycle
- [x] eCAR PROCESS/TERMINATE events

### 5.3 Protocol & Destination Diversity
- [x] UDP traffic (DNS, NTP, SNMP, Syslog)
- [x] ICMP traffic (echo request/reply, unreachable)
- [x] 50+ destination IP pool with CDN/cloud diversity
- [x] Reverse DNS patterns per cloud provider

### 5.4 System Traffic Generation
- [x] Kerberos (port 88) to Domain Controllers
- [x] LDAP (port 389) to Domain Controllers
- [x] Database traffic (scenario-driven port/service detection)
- [x] NTP synchronization, SSH keepalive, ICMP health checks

### 5.5 Work-Hour Realism & Timing
- [x] Activity clustering (sub-second intra-cluster, non-uniform gaps)
- [x] Per-persona cluster templates
- [x] Work-hour ramp-up/ramp-down (not step function)
- [x] Human burstiness (CV > 1.0)

---

## Phase 6: Expert-Identified Realism Fixes (IN PROGRESS)

**Goal:** Address blind expert panel findings. 5 improvement loops completed, 60 resolved.

### 6.0 Pre-existing Fixes
- [x] LogonType diversity (Types 2,3,4,5,7,8,9,10,11)
- [x] PID multiples of 4 (Windows) / sequential (Linux)
- [x] UDP/TCP history separation
- [x] NXDOMAIN responses (~20% of DNS lookups)
- [x] Syslog volume and diversity (12-80 events/hr, 10 programs)
- [x] SYSTEM domain (NT AUTHORITY)
- [x] explorer.exe in process tree (winlogon → userinit → explorer)

### 6.1 P0: Critical Fixes
- [x] DNS query type semantics (AAAA→IPv6, PTR→in-addr.arpa, SRV for AD)
- [x] Realistic process trees with depth (_select_parent_pid)
- [x] Duplicate fields in 4624 XML template
- [x] Kerberos/LDAP/DB traffic in Zeek
- [x] Zeek UID correlation across all log types

### 6.2 P1: Major Fixes
- [x] Missing Windows Event IDs (4768/4769/4770/4771/4776, 4697/4698-4701, 4720-4738, 5156, 1102)
- [x] Sysmon Event 1 (process creation) and Event 8 (remote thread injection)
- [x] HTTP proxy log emitter (Squid/PAC3 format)
- [x] Zeek HTTP/SSL/files/x509 log emitters (13 log types total)

### 6.3-6.4 P2/P3: Moderate and Minor Fixes
- [x] Zeek DNS fan-out from connection events
- [x] DHCP lease events
- [x] NTP synchronization logs
- [x] Weird.log and packet_filter.log
- [x] Reporter.log and PE analysis logs

### 6.5 Improvement Loop 1 (2026-03-18)
- [x] Work-hour timezone conversion fix
- [x] Failed logon target_username fix
- [x] Proxy log emitter improvements
- [x] 16 new issues identified, multiple resolved

### 6.6 Phase 7 Eval Expert Panel (2026-03-19)
- [x] Multiple expert-identified issues resolved through canonical event model

### 6.7 Improvement Loop 2 (2026-03-20, arch-firm-ssh-bruteforce)
- [x] 11 new issues identified, evaluation score 75/100

### 6.8 Improvement Loop 3 (2026-03-20, healthcare-supply-chain)
- [x] Evaluation score improved to 78/100

### 6.9-6.10 Improvement Loops 4-5 (2026-03-23, healthcare-supply-chain)
- [x] 4-expert panel evaluations, score improved to 80/100
- ~30 remaining issues tracked in TODO.md

---

## Phase 7: Canonical Event Model (COMPLETE)

**Goal:** Replace manual per-emitter coordination with SecurityEvent intermediate representation.

### 7.1 Foundation
- [x] SecurityEvent and RawLogEntry dataclasses
- [x] 8+ composable context dataclasses (Host, Auth, Process, Network, DNS, File, Registry, IDS)
- [x] EventDispatcher with NetworkVisibilityEngine integration
- [x] StateManager.apply() for event-driven state changes
- [x] can_handle()/emit()/emit_raw() on LogEmitter base class

### 7.2 Activity Type Migration
- [x] generate_logon() — Windows + syslog + eCAR
- [x] generate_logoff() — Windows + syslog + eCAR
- [x] generate_failed_logon() — Windows + syslog + eCAR
- [x] generate_process() — Windows + eCAR
- [x] generate_process_termination() — Windows + eCAR
- [x] generate_system_process() — Windows + syslog + eCAR
- [x] generate_connection() — Zeek conn
- [x] generate_bash_command() — bash_history
- [x] generate_machine_account_logon() — Windows
- [x] generate_kerberos_tgt() — Windows (4768)
- [x] generate_kerberos_service_ticket() — Windows (4769)
- [x] generate_ntlm_validation() — Windows (4776)

### 7.3 Cleanup
- [x] Removed orphaned eCAR helpers
- [x] Converted remaining helpers to dispatch_raw()
- [x] Removed ActivityGenerator.emitters dict (all via dispatcher)

### 7.4 Remaining Emissions
- [x] Migrated DNS lookups to dispatch_raw
- [x] Migrated engine.py system traffic to dispatch_raw
- [x] Final eval: 82.3 → 83.7, expert panel 36 → 30 tells

**Phase 7 Milestone:** All event emission through EventDispatcher. 12 activity types use canonical dispatch; diversity helpers and system traffic use dispatch_raw. 761+ tests, zero regressions.

---

## Phase 8: Cross-Source Correlation (PLANNED)

Planned but not yet started. See TODO.md for details on eCAR FLOW migration, FILE/REGISTRY/MODULE migration, syslog system message migration, and typed event declarations.

### 8.4 Typed Event Declarations (COMPLETE)
- [x] Per-event-type Pydantic models for storyline events
- [x] `events` list field on storyline entries
- [x] `supplementary` field (auto/none)
- [x] Load-time validation via `eforge validate`
- [x] Existing scenarios migrated
- [x] Keyword matcher removed

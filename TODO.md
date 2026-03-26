# EvidenceForge Implementation Plan

**Status:** Phase 7 (Canonical Event Model) COMPLETE; Phase 6 ongoing (improvement loops); Phase 8 planned
**Started:** 2026-03-11
**Last Updated:** 2026-03-25

See [CHANGELOG.md](CHANGELOG.md) for detailed development history of completed phases.

---

## Phase 1: Core Generation — COMPLETE

Proved the concept with basic functionality: Pydantic scenario models, StateManager, 2 log formats (Windows Event Security, Zeek conn.log), hour-by-hour generation engine, ground truth documentation. 93 tests.

## Phase 2: Scalability — COMPLETE

Scaled to real-world datasets: parallel threaded emitters, 7 log formats (added eCAR, syslog, bash history, Snort, web access), persona-based temporal distribution, network visibility modeling (SPAN/TAP sensors), multi-OS support (Windows + Linux). 526 tests, 100-user 8-hour scenarios in ~14 seconds.

## Phase 3: MVP Release — COMPLETE

Shipped skill-based architecture: 4 Claude Code Skills (/eforge scenario, generate, validate, evaluate), 15 pre-built personas, eforge install-skills CLI command, scenario reference documentation. Skills handle interactive/creative work; CLI stays deterministic.

## Phase 4: Data Quality Evaluation — COMPLETE

Added `eforge eval` command: 5 scoring dimensions (Record Fidelity, Cross-Source Consistency, Noise Realism, Temporal Realism, Signal Integrity) with 23 sub-scores, 17 log parsers, acceptance criteria pass/fail layer. All deterministic/statistical, no LLM required.

## Phase 5: Data Realism Improvements — COMPLETE

Fixed generator-level tells across 5 sub-phases: SID generation, conn_state diversity, process template pools, failed logon events, process termination, eCAR object diversity, protocol diversity (UDP/ICMP/NTP/SSH), system traffic generation (Kerberos/LDAP/DB), work-hour ramp/clustering, human burstiness patterns. Eval score target >= 85.

## Phase 7: Canonical Event Model — COMPLETE

Replaced manual per-emitter field coordination with SecurityEvent intermediate representation. Two-phase build + dispatch architecture: ActivityGenerator builds SecurityEvent with composable contexts (Host, Auth, Process, Network, DNS, File, Registry, IDS), EventDispatcher routes to StateManager + matching emitters. Migrated logon, logoff, process, connection, DNS, failed logon, and process termination event types. 950+ tests.

---

## Phase 6: Expert-Identified Realism Fixes — IN PROGRESS

**Goal:** Address findings from blind expert panel review. Four domain experts (threat hunter, detection engineer, Windows sysadmin, Linux/network admin) identified synthetic tells. Fix organized by severity.

**Progress:** 5 improvement loops completed, 60 issues resolved, ~30 remaining.

### Remaining P0/P1 Issues

- [ ] **No TXT DNS queries** (SPF/DKIM/DMARC checks)
- [ ] **DNS query set too curated — no Windows telemetry noise** (Expert Panel #EP12)
- [ ] **NTP server mismatch: Zeek shows NIST, syslog shows Ubuntu pool** (Expert Panel #EP13)
- [ ] **UFW BLOCK entries don't appear in Zeek conn.log** (Expert Panel #EP14)
- [ ] **No 4778/4779 (RDP reconnect/disconnect) events** (Expert Panel #EP17)
- [ ] **Volume Adequacy 0/100 — noise:signal ratio ~730:1 vs 5000:1 target**
- [ ] **Storyline Trace Coverage stuck at 50% (14/28 expected format-traces)**
- [ ] **Parsability stuck at ~95% (5% records fail structure validation)**
- [ ] **No SSH protocol negotiation messages in syslog**
- [ ] **Limited syslog program variety (9 programs vs 30+ real)**
- [ ] **Bash history still too sparse for SSH session duration**
- [ ] **DLL file as NewProcessName in 4688 event**
- [ ] **OTH/"Cc" Zeek conn_state over-represented** (Network Engineer)
- [ ] **DNS TTL distribution too uniform** (Network Engineer)
- [ ] **HTTP connections without preceding DNS queries** (Network Engineer)
- [ ] **TLSv13 ratio too low for 2024 timeframe** (Network Engineer)
- [ ] **Limited eCAR object diversity on Linux** (Linux Admin)
- [ ] **explorer.exe parent for RDP sessions** (Threat Hunter)
- [ ] **All Linux processes share same ppid** (Linux Admin)
- [ ] **Per-host syslog has only 1-3 programs** (Linux Admin)
- [ ] **Missing 4672 (special privileges) on DC-01**
- [ ] **Low 4689:4688 process termination ratio** (57% vs 80-90% expected)
- [ ] **Missing eCAR USER_SESSION events on server-side of RDP lateral movement**
- [ ] **Inconsistent Zeek sensor coverage for SSH pivot**
- [ ] **Only 1-2 RDP connections in Zeek over 6 hours**
- [ ] **No SSL certificate subject/issuer data in Zeek ssl.log**
- [ ] **Logrotate runs every 15 minutes** (should be daily at ~6:25am)
- [ ] **Only 4 User-Agents across HTTP requests** (need 10-15 for 5 workstations)
- [ ] **100% HTTP 200 status codes** (need 301/302/404/500 mix)
- [ ] **Only 52 SMB connections over 6 hours** (need 200-400 for Windows file server)
- [ ] **60 DNS UIDs (7%) missing from conn.log**
- [ ] **EventRecordID gaps too regular** (need more irregular gap sizes 5-20)
- [ ] **Vary filenames in eCAR file operations** (Assessment #36)

### Remaining Improvement Loop 5 Issues (healthcare-supply-chain)

- [ ] **4769 TargetUserName double-realm format** (DFIR P1)
- [ ] **4648 SubjectLogonId is SYSTEM (0x3e7) for domain user** (DFIR P1)
- [ ] **TLS version/cipher suite mismatch** (Network P0, Threat Hunter P0)
- [ ] **services.exe PID changes within single boot session** (DFIR P0)
- [ ] **No 4672 (Special Privileges) on Domain Controller** (DFIR P0, Detection Eng)
- [ ] **Centralized syslog timestamps not chronologically sorted** (Network P0)
- [ ] **100% HTTP 200 status codes** (Network P0)
- [ ] **User-Agent OS mismatch with source hosts** (Network P0)
- [ ] **RDP lateral movement completely invisible** (Detection Eng P0, Threat Hunter P1)
- [ ] **No DC Kerberos events for compromised user** (Threat Hunter P1, Detection Eng P0)
- [ ] **EMR-DB-01 LogonID discontinuity — process chain orphaned from logon** (Threat Hunter P1)
- [ ] **KeyLength always 0 for NTLM logons** (DFIR P1)
- [ ] **No LSASS access events (4656/4663) for credential dumping** (Detection Eng P0)
- [ ] **No eCAR FILE events on attack hosts** (Detection Eng P1)
- [ ] **DNS queries use corp.local instead of scenario domain** (Network P1)
- [ ] **SSL SNI values are fabricated reverse-DNS/cdn-provider.net names** (Network P1)
- [ ] **Process tree has no RadView parent for supply chain attack** (Threat Hunter P1)
- [ ] **Credential dump chain implausible** (Threat Hunter P1, Detection Eng P1)
- [ ] **Service-inappropriate logs on MAIL-01/FILE-SRV-01** (Network P1)
- [ ] **HTTP MIME type mismatches with URI** (Network P1)
- [ ] **Exfiltration Zeek connections show 0 bytes transferred** (Detection Eng P2)
- [ ] **No 4698 (Scheduled Task Created) for schtasks.exe /Create** (Detection Eng P2)
- [ ] **No port 135 (RPC/EPMAP) traffic in Zeek** (Network P2)
- [ ] **Dual SSH syslog entries with mismatched PIDs/ports** (Threat Hunter P2)

---

## Phase 8: Cross-Source Correlation — PLANNED

**Goal:** Eliminate systemic cross-source correlation gaps caused by `RawLogEntry` bypass of the canonical event model. Background noise events should correlate across log formats the same way storyline events do.

### 8.1 Migrate eCAR FLOW to canonical SecurityEvent dispatch

- [ ] Add `"connection"` to `EcarEmitter._supported_types`
- [ ] Implement `EcarEmitter._render_connection()` from `SecurityEvent.network`
- [ ] Remove `_emit_ecar_flow_event()` helper
- [ ] Verify eCAR FLOW records carry Zeek UID for analyst pivoting

### 8.2 Migrate eCAR FILE/REGISTRY/MODULE to SecurityEvent dispatch

- [ ] **Phase A:** Add file_create, file_modify, registry_modify, module_load event types
- [ ] **Phase B:** Implement Windows 4663 + Sysmon 11/12/13 renderers for cross-source correlation

### 8.3 Migrate syslog system messages to SecurityEvent where applicable

- [ ] CRON executions: correlate with eCAR PROCESS
- [ ] Kernel UFW BLOCK: correlate with Zeek conn.log
- [ ] systemd service start/stop: evaluate eCAR PROCESS correlation

### 8.4 Replace keyword matching with typed event declarations — COMPLETE

Typed `events` list on storyline entries with per-type Pydantic models, supplementary inference, load-time validation. See `docs/reference/scenario-reference.md` for event type reference.

---

## Post-MVP Enhancements (Future)

### Immediate-term (priority fixes)
- [ ] The `eforge validate` command correctly finds defined personas when run as an installed tool, but is unable to find them when run in dev mode (`uv run eforge validate [...]`).
- [ ] **Extend canonical event model to baseline activity for cross-source coherence.** Currently, baseline noise events are generated independently per format (RawLogEntry), so a svchost process on WS-01 doesn't produce a correlated Zeek conn record. Storyline events use SecurityEvent dispatch (Phase 7) which handles this. Baseline activity should use the same SecurityEvent dispatch path so background noise correlates across Windows/Zeek/eCAR/syslog — this is the primary blocker for Baseline Coherence (Sampled) eval scores (currently ~43/100).

### Short-term
- [ ] Story line events are too perfect. Have the threat actor(s) fumble and make mistakes (e.g., use the wrong commands, make typos and correct them, enumerate systems/accounts/files, perform local recon, try attack paths that lead to dead ends, etc)
- [ ] Vastly expand options available for 'canned' data such as syslog messages, snort alerts, and other items (first discover what other items apply)
- [ ] `snort_alert` typed event spec for IDS signature declarations
- [ ] HTTP proxy server support (Squid, Blue Coat, Zscaler)
- [ ] Checkpointing and resume for long-running generation
- [ ] Additional skills: create-persona, create-log-format, create-network, analyze-output
- [ ] Example scenario collection (ransomware, credential stuffing, insider threat)
- [ ] Config file inheritance/templating
- [ ] Subset sensor format support (e.g., `log_formats: [zeek, -zeek_dns]`)
- [ ] PyPI package distribution
- [ ] Additional log formats (CloudTrail, Azure Activity, GCP Audit, database logs)
- [ ] Network diagram ingestion for auto-inferred sensor placement
- [ ] Performance optimizations (Rust extensions, better parallelization)
- [ ] Full user directory export as separate CSV
- [ ] Separate student/instructor output packages
- [ ] Poisson/Hawkes process timing model

### Medium-term
- [ ] Web UI for scenario creation
- [ ] Streaming output to SIEM/data lakes
- [ ] Log format auto-detection from samples

### Long-term
- [ ] OT/ICS environment simulation
- [ ] Real-time log streaming mode
- [ ] Collaborative scenario editing
- [ ] Scenario marketplace
- [ ] Integration with attack frameworks (CALDERA, Atomic Red Team)

---

## Notes

- **Testing:** Write tests alongside implementation, not after
- **Documentation:** Update docs incrementally, not all at end
- **Dependencies:** Add via `uv add`, never use `pip` directly
- **Changelog:** When completing a phase, move detailed task history to [CHANGELOG.md](CHANGELOG.md)

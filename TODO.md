# EvidenceForge Implementation Plan

**Status:** Phase 8.5 (Dual src/dst HostContext) COMPLETE; Pre-MVP quality fixes ongoing
**Started:** 2026-03-11
**Last Updated:** 2026-03-27

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

## Pre-MVP: Consolidated Quality Fixes — IN PROGRESS

**Goal:** Fix all expert-identified issues that would cause an analyst to reject the data. Consolidated from 6 blind expert panel improvement loops (Threat Hunter, DFIR, Network Eng, Detection Eng) plus infrastructure issues. Work top to bottom.

### Recently Resolved

- [x] SubjectLogonId hardcoded to SYSTEM (0x3e7) on 4720/4728/4697/4698/1102
- [x] 4728 MemberSid doesn't match 4720 TargetSid across storyline events
- [x] 4648 SubjectLogonId is SYSTEM (0x3e7) for domain user
- [x] Missing Snort IDS baseline alerts for single-system segments
- [x] Sysmon 8 TargetProcessId hardcoded to 4 (System kernel PID)
- [x] Network logon (type 3) processes parented by explorer.exe instead of services/svchost
- [x] 4698 TaskContent empty when not specified in scenario
- [x] System Process Regularity eval penalized realistic variance (CV scoring)
- [x] Volume Adequacy eval targets miscalibrated for storyline-based signal counting
- [x] Slow tests (medium dataset, parallel generation) excluded from default `uv run pytest`; run explicitly with `-m slow`

### Tier 0: Infrastructure

- [x] **`uv.lock` not committed** — gitignored, so CI `setup-uv@v4` cache fails. Remove from `.gitignore` and commit.
- [x] **`eforge validate` can't find personas in dev mode** — works when installed (`eforge validate`) but not via `uv run eforge validate`. Blocks dev workflow.
- [x] **511 ruff lint errors + 102 formatting issues** — CI lint job fails immediately. Auto-fix + suppress false positives (B008 for Typer, N806 for lookup tables, B904 for typer.Exit).
- [x] **Coverage threshold mismatch (local 70% vs CI 90%)** — pyproject.toml `fail_under` doesn't match CI's `--cov-fail-under=90`. Devs pass locally, fail in CI.
- [x] **CI runs tests 3 times** — 3 separate pytest invocations (unit, integration, both again for coverage). Consolidate to single run.
- [x] **No pre-commit hooks** — ruff issues only caught in CI. Add pre-commit framework with ruff check + format hooks.

### Tier 1: Foundational Correctness

Data is *wrong* — a hunter hits dead ends. Fix these first; several unblock Tier 2 work.

- [x] **LogonIDs leak across hosts** — remote processes on DC/file server use the originating-host LogonID instead of the destination host's 4624 TargetLogonId. Breaks every pivot-based hunting workflow.
- [x] **services.exe PID changes within single boot session** — process tree references a parent PID that was replaced mid-scenario. Child processes become orphaned.
- [x] **Extend canonical event model to baseline activity** — added SyslogContext, WeirdContext, extended DhcpContext. Syslog emitter renders from SyslogContext exclusively. All internal `generate_raw()` calls eliminated (was 12, now 0). `generate_raw()` exists solely for user-facing `raw` event type in scenario YAML.
- [x] **Migrate eCAR FLOW to SecurityEvent dispatch** — already complete: `"connection"` in `_supported_types`, `_render_connection()` implemented, all connections dispatch through SecurityEvent. `pid:-1` for system traffic is correct behavior.
- [x] **No 4625 on DC for password spray** — sprays against domain accounts should produce 4625/4776 on the DC, not just the originating workstation. DC-focused Sigma/Splunk rules won't fire.
- [x] **Ground truth Zeek UIDs missing from logs** — UIDs listed in GROUND_TRUTH.md IOC section don't exist in any sensor's conn.json. Answer key references evidence that isn't there.

### Tier 2: Huntability & Detection

Data is structurally correct but the hunt doesn't work — key attack steps are undetectable or trivially obvious.

- [x] **RDP lateral movement invisible + zero RDP noise** — added background IT admin RDP connections (1-3/hour) to Windows servers/DCs in baseline. Storyline RDP sessions already produce Zeek conn records via generate_rdp_session().
- [x] **No DC Kerberos events for compromised user** — generate_logon() now emits 4768 (TGT) + 4769 (service ticket) on the DC for Kerberos-authenticated domain logons, with realistic timing offsets.
- [x] **No LSASS access events (Sysmon 10)** — added Sysmon Event 10 (ProcessAccess) emitter, format template, and generate_process_access() method. Auto-emits alongside create_remote_thread when target is lsass.exe.
- [x] **No 4672 (Special Privileges) on Domain Controller** — new `special_privileges` event type emits standalone 4672 on DC during Kerberos authentication for elevated users.
- [x] **Storyline events too perfect** — /eforge scenario skill now interviews about attacker sophistication and generates fumbles (mistakes) and dead ends (abandoned paths) appropriate to the chosen level.
- [x] **C2/exfiltration SNI values are auto-generated CDN names** — replaced `host-x-x-x-x.cdn-provider.net` fallback with 30 plausible SaaS/analytics/CDN domains.
- [x] **Proxy log issues** — CONNECT entries now use domain names from REVERSE_DNS or plausible random hostnames instead of raw IPs.
- [x] **Zeek http.log doesn't reflect storyline HTTP activity** — storyline HttpContext host field now uses domain names; skill guidance added to always specify method/uri for HTTP exfiltration events.
- [x] **Vastly expand canned data** — syslog: 6→20 programs (added NetworkManager, dbus-daemon, rsyslogd, sudo, dhclient, polkitd, etc.); User-Agents: 5→15 (added Opera, IE11, curl, wget, older versions); Snort SIDs: 8→30 (added scanning, web attacks, protocol anomalies, policy violations).
- [x] **Baseline connections missing initiating process PIDs** — all `generate_connection()` calls in baseline default to `pid=-1`, so eCAR FLOW records can't be correlated to the originating system process. Pass realistic PIDs from `_system_pids` (e.g., svchost for DNS/NTP/SMB, lsass for Kerberos/LDAP, sshd for SSH). Add `systemd-resolved` to Linux process tree in `emitter_setup.py`. Pass `_last_storyline_pid` in storyline connection handler. Update scenario-reference.md and EVIDENCE_FORMATS.md to document FLOW pid behavior. Update `/eforge generate` and `/eforge scenario` skill references to reflect pid correlation. Add tests for baseline PID propagation and storyline PID passthrough.

### Dual src/dst HostContext (Phase 8.5)

- [x] **Replace SecurityEvent.host with src_host/dst_host** — Network events now carry both source and destination host contexts. Single-host events use src_host (process, file, shell) or dst_host (logon, account mgmt, Kerberos). Connection events populate both when both endpoints are internal. eCAR emitter emits OUTBOUND FLOW on src_host and INBOUND FLOW on dst_host. All emitters, StateManager, ActivityGenerator (46 constructors), and 10 test files updated. No backward-compat property — clean cut.
- [x] **Fix phantom OUTBOUND eCAR records** — Pre-existing bug in baseline.py: SSH inbound connections, UFW blocks, and ICMP pings passed `source_system=system` (the destination) to `generate_connection()`. With dual-host, this created ~1,660 phantom OUTBOUND records on destination hosts. Removed incorrect `source_system` from 4 calls.
- [x] **Fix storyline connection source_system** — storyline.py passed `source_system=system` (the storyline target) instead of resolving from `source_ip`. Now resolves via `_ip_to_system`.
- [x] **Fix baseline SSH syslog source_ip** — Interactive logons on Linux defaulted to own IP or 127.0.0.1. Now picks realistic remote IP from environment for SSH-style logon types.
- [x] **Add direction field to eCAR format definition** — FLOW/CONNECT records now carry INBOUND/OUTBOUND direction in properties.

### Tier 3: Realism Polish

Data works but experienced analysts spot tells. Grouped by format for efficient fix passes.

**DNS:**
- [ ] No TXT queries (SPF/DKIM/DMARC checks)
- [ ] No Windows telemetry noise in query set
- [ ] TTL distribution too uniform
- [ ] HTTP connections without preceding DNS queries
- [ ] Queries default to corp.local instead of scenario domain

**TLS/SSL:**
- [ ] TLSv13 ratio too low for 2024 timeframe
- [ ] TLS version/cipher suite mismatches
- [ ] x509 Let's Encrypt certs show 280+ day validity (should be 90)
- [ ] No SSL certificate subject/issuer data in ssl.log

**Syslog:**
- [ ] NTP server mismatch (Zeek shows NIST, syslog shows Ubuntu pool)
- [ ] No SSH protocol negotiation messages
- [ ] Logrotate runs every 15 minutes (should be daily)
- [ ] Centralized syslog timestamps not chronologically sorted
- [ ] Dual SSH syslog entries with mismatched PIDs/ports

**Windows Events:**
- [ ] DLL file as NewProcessName in 4688
- [ ] Low 4689:4688 process termination ratio (57% vs 80-90%)
- [ ] EventRecordID gaps too regular
- [ ] 4769 TargetUserName double-realm format
- [ ] KeyLength always 0 for NTLM logons
- [ ] 4648 targets localhost instead of DC for domain commands
- [ ] 4728 MemberName is "-" (should be DN of added member)
- [ ] No 4778/4779 (RDP reconnect/disconnect)
- [ ] Process creation timestamp can precede its authorizing logon
- [ ] Missing 4634 logoff events for network logon sessions

**Process Trees:**
- [ ] explorer.exe parent for RDP sessions (should be per-session userinit→explorer)
- [ ] All Linux user processes share same ppid
- [ ] Human Burstiness at 54/100 — events too uniformly distributed, need more clustering/idle

**Zeek:**
- [ ] OTH/"Cc" conn_state over-represented
- [ ] SMB volume too low for Windows file server environments
- [ ] DNS UIDs missing from conn.log (~7%)
- [ ] UFW BLOCK entries don't appear in conn.log
- [ ] weird.json TCP-specific types attributed to UDP sources
- [ ] Exfiltration connections show 0 bytes transferred
- [ ] No port 135 (RPC/EPMAP) traffic
- [ ] Inconsistent sensor coverage for SSH pivot

**HTTP/Proxy:**
- [ ] User-Agent OS mismatch with source hosts
- [ ] 100% HTTP 200 status codes (need 301/302/404/500 mix)
- [ ] HTTP MIME type mismatches with URI
- [ ] Proxy format doesn't match standard Squid or Bluecoat output
- [ ] DHCP shows full discovery instead of renewals in mid-scenario windows

**eCAR:**
- [x] Limited object diversity on Linux — expanded _EDR_FILE_PATHS_LINUX from 5 to 20 entries (logs, caches, config files, /proc, package manager)
- [x] No FILE events on attack hosts — storyline processes now pass ensure_file_event=True, guaranteeing a FILE/CREATE for the process image
- [x] No USER_SESSION events for server-side RDP lateral movement — generate_rdp_session() calls generate_logon() on target, which dispatches USER_SESSION/LOGIN to eCAR with EdrContext
- [x] Vary filenames in file operations — expanded _EDR_FILE_PATHS_WIN from 7 to 21 entries, _EDR_FILE_PATHS_LINUX from 5 to 20 entries

**Other:**
- [ ] Bash history too sparse for SSH session duration
- [ ] Baseline generates IPs outside defined network segments
- [ ] Parsability at ~95% (5% records fail structure validation)

### Tier 4: Eval Fixes

- [ ] Storyline Trace Coverage hostname normalization bug (traces exist but bare vs FQDN mismatch)
- [ ] Ground truth File IOCs section truncated in GROUND_TRUTH.md output

### Cross-Source Correlation (depends on Tier 1 baseline migration)

Once baseline activity uses SecurityEvent dispatch, these become straightforward:

- [x] Migrate eCAR FILE/REGISTRY/MODULE to SecurityEvent dispatch (enables 4663 + Sysmon 11/12/13 correlation) — completed in Phase 8.2; probabilistic EDR events dispatch via SecurityEvent with EdrContext
- [x] Migrate syslog system messages: CRON↔eCAR PROCESS, UFW BLOCK↔Zeek conn, systemd↔eCAR PROCESS — CRON and UFW were already working; systemd now uses paired generate_system_process/generate_system_process_termination lifecycle
- [ ] Sysmon Event 3 (Network), 11 (FileCreate), 13 (Registry) emission

---

## Post-MVP Enhancements (Future)

### Short-term
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
- [ ] **D3FEND Defensive Response Modeling** — Extend storyline events with environmental response: when an attack step fires, security controls react (account lockout on brute force, EDR quarantine on suspicious process, firewall deny on lateral movement). Driven by a defense profile in scenario YAML defining deployed controls (EDR, DLP, lockout policy, firewall rules). Some attacks succeed, some get partially blocked, some get detected but not prevented. Creates more realistic training (analysts see attacks that don't go unopposed) and more correlation opportunities ("trace from EDR alert back to initial access").
- [ ] **ML-Informed Baseline Profiles** — Optional offline pipeline: feed in sanitized real logs, extract statistical profiles, output persona definitions matching actual observed patterns. Covers temporal distributions (hourly activity curves, night shifts), process/application mix (top 50 processes, PowerShell:cmd ratio), network patterns (DNS volume, port distributions, internal/external ratios), and authentication patterns (failed login frequency, Kerberos:NTLM ratios). Ships as `eforge learn` CLI command producing persona YAML. Closes the gap between structurally correct synthetic data and data that "feels" real to experienced analysts.

### Long-term
- [ ] OT/ICS environment simulation
- [ ] Real-time log streaming mode
- [ ] Collaborative scenario editing
- [ ] Scenario marketplace
- [ ] Integration with attack frameworks (CALDERA, Atomic Red Team)
- [ ] **High-Performance Generation Mode** — Parallelize generation for enterprise-scale scenarios (200+ users, 7+ days, CI pipelines). Two approaches: (1) parallelize across emitters — EventDispatcher fans out to 20+ emitters concurrently (lower risk, emitters don't share state); (2) parallelize across time windows — process hours in parallel batches with StateManager coordination (higher complexity, bigger payoff). Even approach #1 removes the proportional scaling ceiling for large scenarios.

---

## Notes

- **Testing:** Write tests alongside implementation, not after
- **Documentation:** Update docs incrementally, not all at end
- **Dependencies:** Add via `uv add`, never use `pip` directly
- **Changelog:** When completing a phase, move detailed task history to [CHANGELOG.md](CHANGELOG.md)

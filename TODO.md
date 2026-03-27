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
- [ ] Limited object diversity on Linux
- [ ] No FILE events on attack hosts
- [ ] No USER_SESSION events for server-side RDP lateral movement
- [ ] Vary filenames in file operations

**Other:**
- [ ] Bash history too sparse for SSH session duration
- [ ] Baseline generates IPs outside defined network segments
- [ ] Parsability at ~95% (5% records fail structure validation)

### Tier 4: Eval Fixes

- [ ] Storyline Trace Coverage hostname normalization bug (traces exist but bare vs FQDN mismatch)
- [ ] Ground truth File IOCs section truncated in GROUND_TRUTH.md output

### Cross-Source Correlation (depends on Tier 1 baseline migration)

Once baseline activity uses SecurityEvent dispatch, these become straightforward:

- [ ] Migrate eCAR FILE/REGISTRY/MODULE to SecurityEvent dispatch (enables 4663 + Sysmon 11/12/13 correlation)
- [ ] Migrate syslog system messages: CRON↔eCAR PROCESS, UFW BLOCK↔Zeek conn, systemd↔eCAR PROCESS
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

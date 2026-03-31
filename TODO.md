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

Data works but experienced analysts spot tells. Grouped by format for efficient fix passes. Items marked with ✓ were fixed in the blind expert panel improvement loop (2026-03-27).

**Snort/IDS:**
- [x] ✓ Snort protocol field randomly assigned (no binding to SID/rule) — restructured `_FP_SIGS` to protocol-keyed dict with per-signature port and direction
- [x] ✓ Snort flow directions inverted for outbound rules — signatures tagged "in"/"out", src/dst swapped for outbound alerts
- [x] ✓ ICMP connections carry TCP/UDP ports — force src_port=0, dst_port=0 for ICMP in generate_connection()

**Sysmon:**
- [x] ✓ Sysmon Execution ProcessID rotates every event — stable per-host PID via hostname hash
- [x] ✓ PE metadata fields (FileVersion/Company/etc.) always "-" — lookup table of 17 common Windows binaries; fixed Windows path parsing on non-Windows OS
- [x] ✓ Sysmon TargetImage bare "lsass.exe" — resolve bare filenames to full System32 paths in Events 8/10
- [x] ✓ Sysmon ProcessGuid inconsistent for same PID — truncate timestamp to second precision for stable GUIDs
- [x] ✓ Sysmon Event 5 (ProcessTerminate), Event 8 baseline noise, Event 10 baseline noise — added to baseline + eCAR THREAD/REMOTE_CREATE and PROCESS/OPEN correlation
- [ ] Sysmon Event 3 (NetworkConnect), 11 (FileCreate), 12/13 (Registry), 22 (DNSQuery) not yet implemented
- [ ] ParentCommandLine always "-"

**Zeek:**
- [x] ✓ Cross-sensor UIDs byte-identical — deterministic per-sensor UID derivation (SHA-256 of uid+sensor) preserving intra-sensor cross-log correlation
- [x] ✓ x509 certificate serial numbers all 5 bytes — generate 128-bit (16-byte) serials matching real CA practice
- [x] ✓ NTP Zeek ref_time/org_time/rec_time/xmt_time all 0.0 — populate with realistic values relative to event timestamp
- [ ] OTH/"Cc" conn_state over-represented; SF at 88% (real: 55-75%); missing SH/S2/S3 states
- [ ] SMB volume too low for Windows file server environments
- [ ] DNS UIDs missing from conn.log (~7%)
- [ ] UFW BLOCK entries don't appear in conn.log
- [ ] weird.json TCP-specific types attributed to UDP sources
- [ ] Exfiltration connections show 0 bytes transferred
- [ ] No port 135 (RPC/EPMAP) traffic
- [ ] Inconsistent sensor coverage for SSH pivot

**DNS:**
- [ ] DNS IP pool reuse: 15+ unrelated SaaS domains resolve to same IP (need per-domain IP assignment)
- [ ] DNS AAAA records: unrelated services share IPv6 prefix (cross-provider)
- [ ] CloudFront distributions resolve to Microsoft IP ranges (cross-provider)
- [ ] No TXT queries (SPF/DKIM/DMARC checks)
- [ ] No Windows telemetry noise in query set
- [ ] TTL distribution too uniform
- [ ] Queries default to corp.local instead of scenario domain
- [ ] MX records for CDN domains that shouldn't have mail exchangers

**TLS/SSL:**
- [ ] TLSv13 ratio too low for 2024 timeframe
- [ ] TLS version/cipher suite mismatches
- [ ] x509 Let's Encrypt certs show 280+ day validity (should be 90)
- [ ] No SSL certificate subject/issuer data in ssl.log

**Syslog:**
- [x] ✓ DHCP messages contain integers instead of IP addresses — use system.ip
- [x] ✓ Persistent daemon PIDs randomized per message — map to sys_pids for known daemons; hash-derived stable PIDs for others
- [x] ✓ CentOS hosts run Ubuntu daemons (snapd, systemd-timesyncd, debian-sa1, user ubuntu, APT) — filter by is_rhel_like
- [x] ✓ dhclient shares PID with NetworkManager — isolated PID derivation per daemon
- [x] ✓ NetworkManager internal timestamps non-monotonic — use kernel uptime counter
- [x] ✓ Googlebot user-agent on internal hosts — split UA pool; bots only from external IPs
- [x] ✓ AppArmor mysqld audit on all hosts — only on DB-role hosts, skip RHEL
- [x] ✓ phpsessionclean on non-PHP hosts — only on web_server/forward_proxy role
- [x] ✓ Transient process (sudo) gets stable PID — sudo/cron children now get random PIDs
- [x] ✓ systemd-logind session IDs random — sequential per-host counter from boot
- [ ] Session IDs appear out-of-order (assigned in generation order, not chronological)
- [ ] NTP server mismatch (Zeek shows NIST, syslog shows Ubuntu pool)
- [ ] No SSH protocol negotiation messages
- [ ] Logrotate/cron.daily fire too frequently (should be daily, not multiple times per hour)
- [ ] Centralized syslog timestamps not chronologically sorted
- [ ] Dual SSH syslog entries with mismatched PIDs/ports

**Windows Events:**
- [x] ✓ IpAddress "::ffff:-" malformed — handle "-" string in _ipv6_mapped()
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
- [ ] Only AES-256 Kerberos encryption; no RC4/AES-128 mix
- [ ] Only 2 unique TicketOptions values; zero 4771 pre-auth failures
- [ ] File server has no domain user logon events
- [ ] NETWORK SERVICE TargetDomainName shows domain instead of "NT AUTHORITY"

**Process Trees:**
- [ ] explorer.exe parent for RDP sessions (should be per-session userinit→explorer)
- [ ] All Linux user processes share same ppid
- [ ] Human Burstiness at 65/100 — events too uniformly distributed, need more clustering/idle

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

## Data Realism — IN PROGRESS

**Goal:** Address structural realism gaps identified by adversarial review. These are issues where the generated data is technically correct but experienced analysts or ML models would identify it as synthetic due to missing real-world patterns. Prioritized by impact on analyst training, then implementation complexity.

**Completed so far:** Causal expansion engine (#1), day-of-week variation (#6), stale account enrichment (#9), legitimate lateral movement (#11, 26 patterns), command pool diversification (#12). Sensor timestamp skew (#10) dropped — tight NTP is best practice.

### Temporal Realism

- [x] **Causal event ordering** — CausalExpansionEngine with 4 composable rules (DnsBeforeConnection, KerberosBeforeLogon, ProcessAccessAfterRemoteThread, SupplementaryAuditEvents). Validator warns on redundant manual prerequisites. Evaluator scores DNS→connection and Kerberos→logon causal pairs.
- [ ] **Hawkes/bursty temporal model** — Replace flat Poisson arrivals with clustered, self-similar traffic patterns. Real networks exhibit heavy-tailed inter-arrival times from backup jobs, patch cycles, login storms, etc. Current uniform jitter within each hour is a major synthetic tell.
- [x] **Day-of-week variation** — Monday 1.15x login storms, Friday 0.85x early departures, Saturday/Sunday 0.05-0.08x near-zero. Non-IT personas skipped on weekends.
- ~~**Sensor timestamp skew**~~ — Dropped: tight NTP is best practice in production environments.

### Baseline Depth

- [ ] **Process → network correlation** — Link process creation to corresponding network activity. A `chrome.exe` should generate HTTP/DNS traffic; `git.exe` should connect to GitHub. Currently process and network events are generated independently.
- [ ] **Linux baseline activity** — Add cron jobs, systemd service restarts, package manager activity, log rotation, NFS mounts. Currently Linux hosts get storyline commands but minimal baseline noise, making any Linux activity immediately suspicious.
- [x] **Legitimate lateral movement** — 26 patterns: backup agents, monitoring, AD replication, app→DB, config management, DNS zone transfers, NFS, Docker registry, syslog relay, etc. Conditional on environment topology and system roles.
- [x] **Stale account enrichment** — Kerberos pre-auth failures (4771, 0x12), scheduled task failures (batch logon type 4), service startup failures (type 5, first hour), plus existing failed network logons.

### Red Herring Sophistication

- [ ] **Network-level red herrings** — Add suspicious-but-benign DNS patterns (high-entropy subdomain queries to CDNs, DNS-over-HTTPS to known providers), unusual-but-legitimate connections (dev VPN to unfamiliar cloud region, CI/CD pulling from new registry). Current red herrings are almost entirely OS-level.
- [ ] **Expand suspicious ambient noise types** — Add: large outbound transfers (backup/cloud sync), process injection false positives (AV/EDR memory scanning), scheduled vulnerability scan overlap, automated software update bursts. Currently 4 pattern types.

### Entity Consistency

- [ ] **Entity lifecycle validation** — Track system uptime so events can't precede boot time. Validate that Process Access (Sysmon 10) targets existing PIDs. Prevent file operations on nonexistent paths. Currently no lifecycle constraints beyond session/PID tracking.

### Format Expansion

- [ ] **Cloud/SaaS log formats** — Azure AD sign-in logs, AWS CloudTrail, GCP audit logs, M365 audit logs. Most modern SOCs are hybrid; on-prem-only formats limit training relevance.
- [x] **Static command pool diversification** — All process template categories parameterized with {placeholder} syntax. New _GENERAL_PARAMS pool (project paths, doc names, build configs, git branches, internal URLs). Per-user affinity via {username} substitution.

---

## Post-MVP Enhancements (Future)

### Short-term
- [ ] **Configurable work-week schedules** — Allow scenario authors to shift the typical workday (e.g., Tues–Sunday for retail/healthcare), define shift workers with non-standard hours, or specify per-persona day-of-week overrides
- [ ] `snort_alert` typed event spec for IDS signature declarations
- [ ] HTTP proxy server support (Squid, Blue Coat, Zscaler)
- [ ] Checkpointing and resume for long-running generation
- [ ] Additional skills: create-persona, create-log-format, create-network, analyze-output
- [ ] Example scenario collection (ransomware, credential stuffing, insider threat)
- [ ] Config file inheritance/templating
- [ ] Subset sensor format support (e.g., `log_formats: [zeek, -zeek_dns]`)
- [ ] PyPI package distribution
- [ ] Network diagram ingestion for auto-inferred sensor placement
- [ ] Performance optimizations (Rust extensions, better parallelization)
- [ ] Full user directory export as separate CSV
- [ ] Separate student/instructor output packages

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

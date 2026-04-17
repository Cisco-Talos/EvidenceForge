# EvidenceForge Implementation Plan

**Status:** Phase 8.5 (Dual src/dst HostContext) COMPLETE; Pre-MVP quality fixes ongoing
**Started:** 2026-03-11
**Last Updated:** 2026-04-08

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

### World Model Refactor

- [x] Open the draft PR from `world-model` into `dev`
Compiled `WorldModel` / `WorldPlanner` behavior is now the shared planning layer for persona placement, host capabilities, proxy/infrastructure routing, and interactive/network/SSH/RDP session bootstrap across baseline and storyline generation.
Runtime ownership state was expanded to track exact session/process/connection provenance, the remaining `hash()`-based realism-critical derivations were replaced with `_stable_seed(...)`, and the contributor/docs/skill guidance was updated to match the new contract.
Verification is complete: dedicated `tests/unit/test_world_model.py` coverage was added and `uv run pytest -v --include-slow` passed (`1483 passed`).

### Recently Resolved

- [x] Fix `_find_user_session` mixed tz-aware/naive `start_time` comparison crash (Aardvark finding)
- [x] Baseline inbound profile traffic no longer depends on outbound role traffic for business-hour gating (fixed UnboundLocalError when outbound profile is empty).
- [x] Security: validate blocked_c2 interval/duration are > 0 to prevent zero-interval infinite loop DoS
- [x] Harden temporal evaluator `exclude_ports` parsing against malformed `zeek_conn.id.resp_p` values (prevent eval crash on non-numeric ports)
- [x] Evaluator grace period for causal ordering (logon→process rule skips events within logon_grace_period from scenario start)
- [x] Evaluator event type detection from typed EventSpec fields (replaces fragile keyword matching) + 9 new record matchers
- [x] Evaluator per-sub-event indicator accuracy (fixes last-writer-wins IP merge for compound storyline steps) + tighter eCAR FLOW matching
- [x] Evaluator format group trace coverage (host-local vs network groups instead of checking all formats)
- [x] Evaluator anomaly rate: red herring events count as anomalies + 2 new suspicious patterns (temp_dir_execution, unusual_powershell) + doubled noise intensity
- [x] Evaluator burstiness: raised minimum event threshold to 30 for reliable CV estimates + tuned Hawkes alpha/beta ratios
- [x] Evaluator causal pair tolerance field (DNS→TCP allows 3% direct-IP connections) + expanded eCAR exclude_accounts for Linux daemons
- [x] ZeekDhcpEmitter missing can_handle() — DHCP events never reached emitter
- [x] Windows emitter cross-host OS filtering — can_handle() now uses _get_host() for consistent host selection
- [x] Per-system session check for baseline + suspicious noise — logon emitted on target system, not reused from wrong system
- [x] Context-aware logon types — interactive (type 2) for workstations, network/RDP (type 3/10) for servers
- [x] DNS before baseline system traffic — SMB/Kerberos/LDAP/DB connections emit DNS via causal expansion with 2% direct-IP skip
- [x] System IP→FQDN registration — scenario system hostnames registered in REVERSE_DNS at setup time
- [x] Red herring typing cadence — compound red herring steps now use typing cadence like storyline events
- [x] primary_system required for all users — scenario skill, reference, and validation updated; coverage test prompt updated
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

- [x] Security: validate `environment.timezone.systems` overrides at schema load to prevent runtime `UnknownTimeZoneError` crashes during timezone conversion.
- [x] Security: threaded emitter worker exceptions can deadlock `barrier_flush()` (`Queue.join()` wait forever when worker dies).
- [x] Security: blocked symlinked `eforge` install target in `install-skills` to prevent arbitrary overwrite/deletion and stale-file cleanup outside target.
- [x] Security: cap firewall deny baseline amplification (`deny_ratio`/hourly deny volume) to prevent scenario-driven local DoS — `NetworkSensor.deny_ratio` now enforces `<= 50.0`.
- [x] Security: prevent IPv6 scenario DoS in DNS AAAA fallback (`_ipv4_to_fake_ipv6` no longer evaluates for IPv6 destination IPs; AAAA uses mapped IPv6 or preserves IPv6 literal).
- [x] Security: bounded/pruned ActivityGenerator DNS cache (60s prune cadence, 600s TTL-horizon eviction, 50k hard cap) to prevent unbounded memory growth from unique `(src_ip, hostname)` keys.

- [x] **`uv.lock` not committed** — gitignored, so CI `setup-uv@v4` cache fails. Remove from `.gitignore` and commit.
- [x] **`eforge validate` can't find personas in dev mode** — works when installed (`eforge validate`) but not via `uv run eforge validate`. Blocks dev workflow.
- [x] **511 ruff lint errors + 102 formatting issues** — CI lint job fails immediately. Auto-fix + suppress false positives (B008 for Typer, N806 for lookup tables, B904 for typer.Exit).
- [x] **Coverage threshold mismatch (local 70% vs CI 90%)** — pyproject.toml `fail_under` doesn't match CI's `--cov-fail-under=90`. Devs pass locally, fail in CI.
- [x] **CI runs tests 3 times** — 3 separate pytest invocations (unit, integration, both again for coverage). Consolidate to single run.
- [x] **No pre-commit hooks** — ruff issues only caught in CI. Add pre-commit framework with ruff check + format hooks.
- [x] Security: sandboxed Jinja template rendering for YAML-defined format templates (SandboxedEnvironment + StrictUndefined) to block SSTI/code execution while preserving safe field interpolation.
- [x] Security: bound baseline failed-logon synthetic service account selection loops to prevent scenario-controlled infinite loops/DoS.
- [x] Security: guard persona `activity_intensity` normalization against all-zero values to prevent divide-by-zero DoS during generation (all-zero overrides now safely map to floor probability instead of crashing).
- [x] **Re-generation appends to existing output** — CLI now checks for existing `data/`, `GROUND_TRUTH.md`, and `ENVIRONMENT.md` before generation. Prompts user to confirm overwrite or abort. `--force` / `-f` flag skips prompt for automation/AI use.

### Tier 1: Foundational Correctness

Data is *wrong* — a hunter hits dead ends. Fix these first; several unblock Tier 2 work.

- [x] Stale account usernames with `$` no longer crash baseline generation when converted to `User` objects (aligned `User` username/email validation with stale account pattern)
- [x] Harden provider-aware DNS hostname generation against invalid/IPv6 storyline `dst_ip` values to prevent generation-time crashes (invalid/non-IPv4 inputs now fall back to `generic` provider safely).
- [x] **LogonIDs leak across hosts** — remote processes on DC/file server use the originating-host LogonID instead of the destination host's 4624 TargetLogonId. Breaks every pivot-based hunting workflow.
- [x] **services.exe PID changes within single boot session** — process tree references a parent PID that was replaced mid-scenario. Child processes become orphaned.
- [x] **Extend canonical event model to baseline activity** — added SyslogContext, WeirdContext, extended DhcpContext. Syslog emitter renders from SyslogContext exclusively. All internal `generate_raw()` calls eliminated (was 12, now 0). `generate_raw()` exists solely for user-facing `raw` event type in scenario YAML.
- [x] **Migrate eCAR FLOW to SecurityEvent dispatch** — already complete: `"connection"` in `_supported_types`, `_render_connection()` implemented, all connections dispatch through SecurityEvent. `pid:-1` for system traffic is correct behavior.
- [x] **No 4625 on DC for password spray** — sprays against domain accounts should produce 4625/4776 on the DC, not just the originating workstation. DC-focused Sigma/Splunk rules won't fire.
- [x] **Ground truth Zeek UIDs missing from logs** — UIDs listed in GROUND_TRUTH.md IOC section don't exist in any sensor's conn.json. Answer key references evidence that isn't there.
- [x] Raw storyline events path traversal hardening — sanitized host routing keys for host-multiplexed emitters and Windows per-host writers so raw event fields cannot escape output directory; unsafe keys now fall back to flat-file output.

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

Data works but experienced analysts spot tells. Grouped by format for efficient fix passes. Items marked with ✓ were fixed in the blind expert panel improvement loop (2026-03-27). Items marked with ✓² were fixed in the improve/apt-healthcare-coverage loop (2026-04-02, 5 iterations, 4-expert blind panel: network forensics, host/EDR, detection engineer, threat hunter; all at 92% SYNTHETIC confidence).

**Snort/IDS:**
- [x] ✓ Snort protocol field randomly assigned (no binding to SID/rule) — restructured `_FP_SIGS` to protocol-keyed dict with per-signature port and direction
- [x] ✓ Snort flow directions inverted for outbound rules — signatures tagged "in"/"out", src/dst swapped for outbound alerts
- [x] ✓ ICMP connections carry TCP/UDP ports — force src_port=0, dst_port=0 for ICMP in generate_connection()
- [x] ✓² Snort baseline volume too low (1-3/hour) — increased to 5-15/hour per sensor; experts still consider 73/day low vs thousands in real environments
- [x] ✓² Snort alert timestamps not chronologically sorted — enabled _sort_before_flush on SnortEmitter
- [ ] Snort SID revisions all `:1:1` — should vary to match real ET ruleset update patterns
- [x] ~~Snort baseline scan IPs absent from Zeek conn~~ — no longer reproduces; prior visibility fixes (denied traffic visibility, external deny scoping) resolved this
- [ ] Snort alert volume still 10-100x too low for real perimeter IDS (experts expect thousands/day)
- [x] No ET POLICY, ET INFO, ET DNS categories in baseline — added ET POLICY (curl UA, Basic Auth, SSLv3, APT, PE download), ET INFO (Let's Encrypt, Discord, Telegram, IP lookup, TLS failure, STUN), ET DNS (.top/.cloud TLDs) in baseline.py

**Sysmon:**
- [x] ✓ Sysmon Execution ProcessID rotates every event — stable per-host PID via hostname hash
- [x] ✓ PE metadata fields (FileVersion/Company/etc.) always "-" — lookup table of 17 common Windows binaries; fixed Windows path parsing on non-Windows OS
- [x] ✓ Sysmon TargetImage bare "lsass.exe" — resolve bare filenames to full System32 paths in Events 8/10
- [x] ✓ Sysmon ProcessGuid inconsistent for same PID — truncate timestamp to second precision for stable GUIDs
- [x] ✓ Sysmon Event 5 (ProcessTerminate), Event 8 baseline noise, Event 10 baseline noise — added to baseline + eCAR THREAD/REMOTE_CREATE and PROCESS/OPEN correlation
- [x] ✓² Lsass ProcessAccess GrantedAccess hardcoded to 0x1010 for Mimikatz — changed to 0x1FFFFF (PROCESS_ALL_ACCESS) in causal expansion rule
- [x] ✓² Benign lsass accessors limited to MsMpEng + svchost — added csrss.exe, svchost (netsvcs), services.exe as additional baseline lsass accessors
- [x] **P1** Sysmon Event 3 (NetworkConnect), 7 (ImageLoaded), 11 (FileCreate), 12/13 (Registry), 22 (DNSQuery) — implemented with data-driven filtering via sysmon_filters.yaml (SwiftOnSecurity/Olaf Hartong style). Event 3 include-filters LOLBins + suspicious ports; Event 7 excludes Microsoft-signed System32 DLLs; Event 11 include-filters executable extensions + suspicious paths; Events 12/13 include-filter persistence/tampering keys; Event 22 logs all DNS. User-configurable via .eforge/config/ overlay with per-event enabled toggle.
- [x] ✓³ ParentCommandLine always "-" — added parent_command_line to ProcessContext; populated via _lookup_parent_command_line() from StateManager
- [x] Event 7 DLL load profiles per process — `loaded_modules` field on application_catalog.yaml (user apps) and system_processes.yaml (OS processes), using same schema. Unified loader in dll_load_profiles.py collects from both. Common OS loader chain applied to all processes; unprofilesd processes fall back to common-only.
- [ ] GrantedAccess diversity limited to 3-4 values (0x1000/0x1010/0x1410/0x1FFFFF) — real environments show 10-20+ distinct masks from AV, EDR, WMI, etc.
- [x] CallTrace offsets limited to 2 patterns — moved to calltrace_patterns.yaml with 8 distinct call chains (ntdll, KERNELBASE, kernel32, RPCRT4, wbemcomn, combase, advapi32, sechost)
- [x] Sysmon EventRecordIDs perfectly sequential (no gaps) — gaps widened to 1-7 with 15% chance of 8-50
- [ ] Event 8 StartModule/StartFunction always empty for benign pairs
- [ ] **P1** Event 3 process-to-destination mismatch — user app sampling (Teams, Outlook, etc.) pairs process images with random baseline destinations (e.g., Teams→old.reddit.com). The process_network_map needs per-app destination domain constraints so each app only connects to plausible hosts (Teams→Microsoft domains, Outlook→O365, etc.).
- [ ] **P1** Event 7 (ImageLoaded) volume too thin — only 3-7 DLL load events per host per 6 hours. Real Sysmon with SwiftOnSecurity config logs hundreds. Baseline needs a standalone DLL load generator similar to the registry event generator.
- [ ] **P2** Registry TargetObject path diversity — baseline registry pool has ~30 unique paths that cycle. Real Sysmon sees hundreds of distinct paths from COM registration, GPO processing, software updates. Need larger pool or dynamic path generation.

**Zeek:**
- [x] ✓ Cross-sensor UIDs byte-identical — deterministic per-sensor UID derivation (SHA-256 of uid+sensor) preserving intra-sensor cross-log correlation
- [x] ✓ x509 certificate serial numbers all 5 bytes — generate 128-bit (16-byte) serials matching real CA practice
- [x] ✓ NTP Zeek ref_time/org_time/rec_time/xmt_time all 0.0 — populate with realistic values relative to event timestamp
- [x] OTH/"Cc" conn_state over-represented; SF at 88% (real: 55-75%); missing SH/S2/S3 states — rebalanced TCP distribution: SF 82%→62%, added S2/S3 half-closed states, increased S0/REJ/RSTO/RSTR
- [ ] SSL ssl_history limited to 2 values (CsiI, CsijI) — need 10-20+ patterns including resumed sessions, failed handshakes
- [x] Zeek conn history too uniform (ShADadfF dominant) — 26 distinct history patterns in TCP_CONN_STATE_DISTRIBUTION including RST-based terminations, retransmissions, partial closes
- [ ] SMB volume too low for Windows file server environments
- [x] ~~DNS UIDs missing from conn.log (~7%)~~ — no longer reproduces (0/6487 orphans on apt-healthcare-breach); prior visibility fixes resolved this
- [x] UFW BLOCK entries don't appear in conn.log — UFW BLOCK dispatches via SecurityEvent, emits Zeek conn with conn_state='REJ'
- [x] weird.json TCP-specific types attributed to UDP sources — split into protocol-specific pools; UDP gets DNS/checksum/length anomalies at 0.5% rate vs TCP's 3%
- [x] Exfiltration connections show 0 bytes transferred — auto-size by technique/description heuristic; added orig_bytes/resp_bytes/conn_state to ConnectionEventSpec; storyline defaults to SF
- [ ] No port 135 (RPC/EPMAP) traffic
- [ ] Inconsistent sensor coverage for SSH pivot

**DNS:**
- [x] DNS IP pool reuse: 15+ unrelated SaaS domains resolve to same IP — switched to domain-first selection for baseline web/SaaS; FORWARD_DNS maps domain→IP; fixed 93.184.216.34 mapping (was Reuters, now example.com)
- [ ] DNS AAAA records: unrelated services share IPv6 prefix (cross-provider)
- [ ] CloudFront distributions resolve to Microsoft IP ranges (cross-provider)
- [ ] No TXT queries (SPF/DKIM/DMARC checks)
- [ ] No Windows telemetry noise in query set
- [x] TTL distribution too uniform — Phase 6.0: varied TTLs with cache-aging jitter
- [ ] Queries default to corp.local instead of scenario domain
- [ ] MX records for CDN domains that shouldn't have mail exchangers

**TLS/SSL:**
- [ ] TLSv13 ratio too low for 2024 timeframe
- [ ] TLS version/cipher suite mismatches
- [x] x509 Let's Encrypt certs show 280+ day validity (should be 90) — tls_issuers.yaml with per-issuer validity (LE=90d, DigiCert=397d, etc.); issuer-aware key type selection
- [x] No SSL certificate subject/issuer data in ssl.log — zeek_x509.yaml includes subject/issuer fields; generation uses tls_issuers.yaml

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
- [x] Centralized syslog timestamps not chronologically sorted — _sort_flat_file = True in syslog.py; sorting in host_base.py
- [ ] Dual SSH syslog entries with mismatched PIDs/ports

**Windows Events:**
- [x] ✓ IpAddress "::ffff:-" malformed — handle "-" string in _ipv6_mapped()
- [ ] DLL file as NewProcessName in 4688
- [x] Low 4689:4688 process termination ratio (57% vs 80-90%) — raised termination probability from 0.5 to 0.85
- [ ] EventRecordID gaps too regular
- [ ] 4769 TargetUserName double-realm format
- [ ] KeyLength always 0 for NTLM logons
- [ ] 4648 targets localhost instead of DC for domain commands
- [ ] 4728 MemberName is "-" (should be DN of added member)
- [ ] No 4778/4779 (RDP reconnect/disconnect)
- [x] Process creation timestamp can precede its authorizing logon
- [x] Missing 4634 logoff events for network logon sessions — paired logoffs for type 3 machine account logons on DCs (1-30s delay); baseline type 3/5 already had logoff pairing
- [ ] Only AES-256 Kerberos encryption; no RC4/AES-128 mix
- [x] Only 2 unique TicketOptions values; zero 4771 pre-auth failures — randomized TicketOptions per event type; boosted stale 4771 probability to 15%; added active-user typo 4771 at 2%/hour
- [x] File server has no domain user logon events — type 3 logon+logoff pairs for SMB access in baseline traffic profiles and storyline causal expansion
- [x] NETWORK SERVICE TargetDomainName shows domain instead of "NT AUTHORITY" — _subject_domain() helper in windows.py returns "NT AUTHORITY" for SYSTEM/NETWORK SERVICE/LOCAL SERVICE
- [ ] Event 4672 LogonId 0x3e7 for domain users — SYSTEM-only logon ID (0x3e7) assigned to regular domain users (e.g., james.washington, aisha.johnson) in Special Privileges events

**Process Trees:**
- [x] ✓³ explorer.exe parent for everything — spawn_rules.yaml now defines valid parent-child relationships; _resolve_parent() auto-creates intermediate chains (shells for CLI tools, services.exe for system processes, sshd→bash for Linux)
- [x] ✓³ PID allocation monotonic with uniform stride (~4) — replaced choice list with lognormal distribution (Windows mu=1.2 sigma=0.8; Linux mu=0.5 sigma=0.6); PID wraparound skips allocated PIDs
- [x] explorer.exe parent for RDP sessions (should be per-session userinit→explorer) — per-session smss→winlogon→userinit→explorer chain for type 10 logons
- [x] All Linux user processes share same ppid — per-SSH-session sshd fork + bash login shell; session_shell_pid on ActiveSession
- [x] Human Burstiness at 56/100 — retuned Hawkes params (alpha_beta_ratio 0.80→0.60, beta 0.04→0.06), tightened bias clamps (0.95→0.75), narrowed Gaussians
- [ ] Mimikatz at Medium integrity would succeed in scenario but fail in reality — generator doesn't model integrity levels

**HTTP/Proxy:**
- [x] ✓² Proxy user-agent pool limited to 2 agents — expanded to 8 diverse agents (Chrome/Firefox/Edge/Opera/IE11)
- [x] ✓² Proxy/SSL hostname uses CDN reverse-DNS PTR records instead of domain names — now prefers dns.query from DnsContext; partial fix (first connections per host still use PTR when no DNS context exists)
- [x] ✓² Proxy URL paths all root "/" only — added pool of 18 realistic URI paths
- [x] User-Agent OS mismatch with source hosts — os field on proxy_uri_templates.yaml; OS-aware filtering in pick_proxy_uri(); OS-aware baseline web UA pool
- [x] 100% HTTP 200 status codes — _get_http_status() in network.py returns 200 (70%), 304 (8%), 301 (10%), 302 (5%), 404 (4%), 403 (2%), 500 (1%)
- [x] HTTP MIME type mismatches with URI — _URI_MIME_MAP in baseline.py and generator.py pairs URIs to correct MIME types
- [ ] Proxy format doesn't match standard Squid or Bluecoat output
- [ ] Proxy lacks authenticated usernames (all "-") — healthcare proxies typically show NTLM/Kerberos auth
- [x] Proxy URL paths randomly paired with hostnames (e.g., download.windowsupdate.com/search?q=...) — site map data layer with 12 curated domains + 8 tag-based synthesis templates; browsing session generator selects paths from site-specific page definitions
- [x] Proxy lacks session depth — browsing session model generates landing page + subresource cascade (CSS/JS/images/fonts/favicon/API) + navigation to additional pages with referrer chains; persona-driven intensity (light/normal/heavy); cross-domain CDN fan-out; CONNECT tunnel deduplication with 5-min timeout
- [x] Proxy user-agent mismatch — removed system UAs (Windows-Update-Agent, Microsoft-CryptoAPI) from general _PROXY_UAS_WINDOWS pool; restricted workstation role traffic dns_tags to [background, windows]; added dns_tags to all persona profiles; retagged CDN/API domains in dns_registry
- [x] Web access log referrer headers — tightened web_access emitter can_handle() to require dst_host (destination is a scenario system); prevents outbound HTTPS connections from creating entries on source workstation
- [x] DHCP shows full discovery instead of renewals in mid-scenario windows — initial leases emitted during warm-up (suppressed); periodic REQUEST/ACK renewals at T/2 in _generate_system_traffic()

**Cisco ASA:**
- [x] Security: bound threat-detection deny timestamp tracking window to prevent unbounded memory/CPU growth
- [ ] ASA Built/Teardown counts perfectly balanced — real logs have orphans from log rotation boundaries
- [ ] ASA message type diversity limited to 106023/302013-16/305011-12 — missing 111008, 113004, 733100, 106001, 725001, 304001
- [ ] ASA deny baseline uniformly spaced (3-7s) — real scans arrive in bursty patterns
- [ ] ASA deny events use `[0x0, 0x0]` hash values uniformly
- [ ] NAT mapped_ip 45.33.32.1 is scanme.nmap.org — recognizable IP used as scenario PAT address

**eCAR:**
- [x] Limited object diversity on Linux — expanded _EDR_FILE_PATHS_LINUX from 5 to 20 entries (logs, caches, config files, /proc, package manager)
- [x] No FILE events on attack hosts — storyline processes now pass ensure_file_event=True, guaranteeing a FILE/CREATE for the process image
- [x] No USER_SESSION events for server-side RDP lateral movement — generate_rdp_session() calls generate_logon() on target, which dispatches USER_SESSION/LOGIN to eCAR with EdrContext
- [x] Vary filenames in file operations — expanded _EDR_FILE_PATHS_WIN from 7 to 21 entries, _EDR_FILE_PATHS_LINUX from 5 to 20 entries
- [ ] Template variable leak — literal `{psql_db}` appearing in eCAR output; unsubstituted template variable in process command line or file path

**Cross-Source / General:**
- [ ] Cross-source correlation too perfect — every attack action appears in exactly the expected formats with no gaps
- [x] Cross-sensor timestamp precision identical to 15+ decimal places — microsecond jitter added in snort.py, windows.py, and storyline.py
- [ ] **P2** Per-host-type event rate multiplier — Domain controllers generate ~50 events/hr but real DCs running AD/DNS/DFS/GPO produce thousands/hr. `system.type` is used for routing but never for volume scaling. Need `event_rate_multiplier` on System model (or implicit per-type defaults) applied in `_calculate_events_for_hour()` and `_generate_system_traffic()`. DCs should be 3-5x workstation baseline; file servers and web servers similarly elevated.
- [ ] Encoded PowerShell baseline noise identical across hosts (same Get-Service blob) — needs per-host variation
- [ ] Workstation connection counts suspiciously uniform (808-1068 range) — Hawkes process variance too narrow
- [ ] Uniform log file sets across all hosts (every workstation has identical format coverage)
- [x] DNS IP pool reuse causes cross-provider resolution (CloudFront→Microsoft IPs, etc.) — domain-first selection ensures consistent domain→IP mapping via FORWARD_DNS
- [ ] AWS region mismatch between DNS PTR and SSL SNI for same IP

**Other:**
- [x] ✓³ Bash history only for root on compromised hosts — baseline SSH sessions now generate per-user bash history for admins on all Linux servers (34 files vs 3); organic noise commands interleaved via generate_bash_command_with_noise()
- [x] Bash history still lacks typos, repeated commands, tab-completion artifacts — bash_commands.yaml with per-role command vocabularies (sysadmin/dba/webadmin/developer/security), template parameterization, 5% typo rate; per-server RBAC user rosters via _get_server_ssh_users()
- [x] Baseline generates IPs outside defined network segments — external IP generator excludes org CIDRs; diagnostic validator warns on out-of-segment internal IPs
- [ ] Parsability at ~95% (5% records fail structure validation)

### Tier 4: Eval Fixes

- [x] Harden temporal causal-account exclusion against non-string SubjectUserName/principal values to prevent evaluator exceptions on malformed logs
- [ ] Storyline Trace Coverage hostname normalization bug (traces exist but bare vs FQDN mismatch)
- [ ] Ground truth File IOCs section truncated in GROUND_TRUTH.md output

### Cross-Source Correlation (depends on Tier 1 baseline migration)

Once baseline activity uses SecurityEvent dispatch, these become straightforward:

- [x] Migrate eCAR FILE/REGISTRY/MODULE to SecurityEvent dispatch (enables 4663 + Sysmon 11/12/13 correlation) — completed in Phase 8.2; probabilistic EDR events dispatch via SecurityEvent with EdrContext
- [x] Migrate syslog system messages: CRON↔eCAR PROCESS, UFW BLOCK↔Zeek conn, systemd↔eCAR PROCESS — CRON and UFW were already working; systemd now uses paired generate_system_process/generate_system_process_termination lifecycle
- [x] Sysmon Event 3 (Network), 11 (FileCreate), 13 (Registry) emission — implemented alongside Sysmon P1

---

## Data Realism — COMPLETE

**Goal:** Address structural realism gaps identified by adversarial review. These are issues where the generated data is technically correct but experienced analysts or ML models would identify it as synthetic due to missing real-world patterns. Prioritized by impact on analyst training, then implementation complexity.

**Completed:** All items except #13 (Cloud/SaaS formats, deferred to post-MVP). Sensor timestamp skew (#10) dropped — tight NTP is best practice.

### Temporal Realism

- [x] **Causal event ordering** — CausalExpansionEngine with 4 composable rules (DnsBeforeConnection, KerberosBeforeLogon, ProcessAccessAfterRemoteThread, SupplementaryAuditEvents). Validator warns on redundant manual prerequisites. Evaluator scores DNS→connection and Kerberos→logon causal pairs.
- [x] **Hawkes/bursty temporal model** — Replaced cluster model with Hawkes self-exciting process (Lewis-Shedler thinning). Parameters derived from persona risk_profile. Cross-hour state continuity. Storyline multi-event steps use typing cadence. System traffic uses periodic+jitter. Lateral movement uses hash-based periodic offsets.
- [x] **Day-of-week variation** — Monday 1.15x login storms, Friday 0.85x early departures, Saturday/Sunday 0.05-0.08x near-zero. Non-IT personas skipped on weekends.
- ~~**Sensor timestamp skew**~~ — Dropped: tight NTP is best practice in production environments.

### Baseline Depth

- [x] **Process → network correlation** — Baseline processes now emit correlated connections via _PROCESS_NETWORK_MAP (browsers→HTTPS, Office→cloud, DB clients→SQL, dev tools→registries). 60% emission probability with process PID for eCAR FLOW correlation.
- [x] **Linux baseline activity** — SSH login/key exchange messages (70% key / 30% password), package management (apt-daily/dnf-automatic), systemd timer execution (fstrim/logrotate/tmpfiles), logrotate file detail, journald runtime statistics. 18 syslog categories total.
- [x] **Legitimate lateral movement** — 26 patterns: backup agents, monitoring, AD replication, app→DB, config management, DNS zone transfers, NFS, Docker registry, syslog relay, etc. Conditional on environment topology and system roles.
- [x] **Stale account enrichment** — Kerberos pre-auth failures (4771, 0x12), scheduled task failures (batch logon type 4), service startup failures (type 5, first hour), plus existing failed network logons.

### Red Herring Sophistication

- [x] **Network-level red herrings** — 3 new patterns: suspicious DNS (high-entropy CDN subdomains, DoH providers), unusual outbound (cloud regions, dev tools, large backup sync), scheduled vulnerability scan overlap. 7 total patterns now.
- [x] **Expand suspicious ambient noise types** — Covered by network-level red herrings above (large outbound transfers, scan overlap).

### Entity Consistency

- [x] **Entity lifecycle validation** — StateManager tracks per-system boot times (register_boot_time at process tree seeding). validate_target_pid() checks PID existence for Sysmon 8/10 events. Warnings logged for impossible sequences.

### Format Expansion

- [x] **Static command pool diversification** — All process template categories parameterized with {placeholder} syntax. New _GENERAL_PARAMS pool (project paths, doc names, build configs, git branches, internal URLs). Per-user affinity via {username} substitution.

### State Pre-Population

- [x] **Warm-up period** — Configurable `warmup` field on `time_window` (default `"8h"`). Runs baseline generation before `start` to pre-populate DNS cache, process trees, active sessions, Kerberos tickets, Hawkes timing kernels, and event counters. Events during warm-up update internal state but are not written to output files, eliminating cold-start artifacts (logon bursts, universal DNS cache misses, orphaned process parents).

---

## Post-MVP Enhancements (Future)

### Short-term
- [ ] **Configurable work-week schedules** — Allow scenario authors to shift the typical workday (e.g., Tues–Sunday for retail/healthcare), define shift workers with non-standard hours, or specify per-persona day-of-week overrides
- [ ] **Storyline cadence field** — `cadence: human|automated|periodic(interval, jitter)` on storyline steps for malware beacons, AI-driven attacks, and automated exfiltration with appropriate timing (currently all steps use human typing cadence by default)
- [ ] **Cloud/SaaS log formats** — Azure AD sign-in logs, AWS CloudTrail, GCP audit logs, M365 audit logs. Most modern SOCs are hybrid; on-prem-only formats limit training relevance
- [ ] `snort_alert` typed event spec for IDS signature declarations
- [ ] HTTP proxy server support (Squid, Blue Coat, Zscaler)
- [ ] Checkpointing and resume for long-running generation
- [ ] Additional skills: create-persona, create-log-format, create-network, analyze-output
- [ ] Example scenario collection (ransomware, credential stuffing, insider threat)
- [ ] Config file inheritance/templating
- [ ] Overlay `_replace: true` recursive propagation — currently `_replace` only affects top-level list fields within a keyed entry; nested lists (e.g., `platforms.windows.command_templates`) still extend. Low impact: replacing entire app definitions with nested platform configs is rare.
- [ ] Overlay `_delete: true` for removing built-in entries — users cannot suppress stock domains/apps/personas from generation. Deferred until a real use case surfaces.
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

## Field Test Gaps (FOR668/FOR669 Exercise Data)

Gaps identified by comparing exercise data requirements against current engine capabilities. Full per-exercise analysis and recommendations in [scenarios/EXERCISE_DATA_REQUIREMENTS.md](scenarios/EXERCISE_DATA_REQUIREMENTS.md).

### Cluster 1: Configurable Bulk Event Framework + DNS Independence

Highest impact — unblocks or improves 10 exercises across all 5 days. These are all variations of "generate N events matching a pattern over a time window." A single YAML-configurable bulk event primitive with type-specific parameter sets covers all of them. DNS independence is part of this because DNS beaconing and DGA are primary use cases driving the framework.

- [x] General repeating/bulk event primitive (`_PeriodicEventBase` + `_iter_periodic_ticks()` shared engine)
- [x] Built-in type: beacon — any protocol (HTTP/S, SSH, DNS, NTP, arbitrary), permitted or blocked
- [x] Built-in type: web_scan — directory enumeration, vuln probing, URI lists, status code distribution (5 presets with overlay support)
- [x] Built-in type: credential_spray — bulk failed_logon with spray/brute_force/stuffing patterns, optional success
- [x] Built-in type: dga_queries — domain generation parameters (length, TLD, charset, count, rcode distribution, deterministic seed)
- [x] Standalone dns_query event type (query, qtype, rcode, ttl) — DNS records independent of TCP connections
- [x] DNS TTL control field on dns_query events
- [x] Replaced `blocked_c2` with beacon `action: deny` (blocked_c2 removed)
- [x] Built-in type: dns_tunnel — encoded subdomain exfiltration (base32/base64/hex, TXT/NULL/CNAME, payload chunking)
- [ ] DGA algorithm presets (known malware families — Conficker, Suppobox, etc.)
- [ ] Dictionary-based DGA (word combination domains)
- [ ] active_hours / active_days on periodic types
- [ ] Connection to non-listening host (conn_state=REJ/S0 without firewall deny)

**Exercises:** 1.1 (web_scan), 1.1b (beacon), 1.3 (injection payload volume), 3.3 (beacon), 4.1 (dns_query, dga), 4.2 (dns_query, dga), 5.1 (credential_spray)

### Cluster 2: Format Filtering

High breadth, low cost — makes multi-week generation practical for 5 exercises without deep optimization.

- [ ] `--formats` CLI filter (e.g., `--formats zeek_conn,zeek_dns` or `--formats proxy_access`)
- [ ] Skip emitters that don't match the filter

**Exercises:** 3.1, 3.2, 3.3, 5.1, 5.2 (all need 2-4 week windows)

### Cluster 3: Temporal Baseline Phases

Single-exercise blocker, but broadly useful for any multi-week scenario.

- [ ] `phases` section in scenario YAML with per-phase baseline intensity/parameters
- [ ] Support different baseline behavior across time ranges (e.g., "3x outbound from host X starting day 15")

**Exercises:** 3.2 (gradual behavioral shifts)

### Cluster 4: Windows Auth Enrichment

Same area of codebase — baseline engine Windows auth generation, persona work schedules.

- [ ] Broader baseline 4648 generation (RunAs, service account delegation, SCCM/GPO, helpdesk remote)
- [ ] Event IDs 4800/4801 (workstation lock/unlock)

**Exercises:** 5.1 (4800/4801), 5.2 (4648 breadth)

### Cluster 5: Labeled Data Export

Standalone post-processing. Defer until Day 4 exercises are functional (Cluster 1).

- [ ] `--export-labels` flag mapping storyline events to output records with technique/storyline ID

**Exercises:** 4.2 (MLTK labeled training data)

---

## Notes

- **Testing:** Write tests alongside implementation, not after
- **Documentation:** Update docs incrementally, not all at end
- **Dependencies:** Add via `uv add`, never use `pip` directly
- **Changelog:** When completing a phase, move detailed task history to [CHANGELOG.md](CHANGELOG.md)

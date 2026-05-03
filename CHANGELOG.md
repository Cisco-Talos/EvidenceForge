# EvidenceForge Development Changelog

Detailed development history for the EvidenceForge project. Transferred from TODO.md during release preparation. For active and planned work, see [TODO.md](TODO.md).

---

## v0.6.0 (2026-05-03)

This release packages the dev branch since `main` into a pre-MVP quality and Codex workflow release. Because the branch includes feature commits, the version moves from `0.5.0` to `0.6.0` under the pre-1.0 semver policy.

**Codex skill installation and assessment workflow**

- Added `eforge install-skills --agent codex` support alongside the existing Claude Code install path, with valid Codex `SKILL.md` frontmatter, conservative stale cleanup, and preservation of user-managed `eforge-*` skills such as `eforge-assess` (`9974b20`, `e63e6cb`).
- Imported and refined the independent `eforge-assess` Codex skill workflow for validate/generate/evaluate/blind-review loops, including bounded-window reviewer guidance, commit-before-next-loop discipline, and pytest-before-commit guidance (`aea8428`, `9df7349`).

**Evaluation and scenario guidance**

- Migrated evaluation to the four-pillar scoring model and fixed targeted evaluator issues around event presence, parseability, cross-source agreement, timing bounds, and short-scenario handling (`1a62403`, `5b138d7`, `891d9ba`).
- Tightened scenario and skill reference guidance so generated scenarios use source-native fields and current schema expectations without duplicating large reference content in command prompts (`124881c`, `f92d087`, `8a10345`).

**Endpoint, auth, and process causality**

- Fixed high-severity lifecycle and ordering defects across Windows Security, Sysmon, eCAR, Linux syslog, and storyline-derived process activity, including post-termination telemetry, process follow-on timing, singleton/system process handling, and log clear subject/token context (`cc00d6a`, `4d42461`, `3405c4d`, `b7fa175`, `5057517`, `605ebc5`, `6125e6d`, `bbb128a`, `37ffaef`, `0b5a676`, `946719c`, `101755c`).
- Improved endpoint identity realism for explicit credentials, SYSTEM/NT AUTHORITY rendering, LogonID/PID provenance, DNS Client process attribution, and cross-host eCAR actor ownership (`a1dc4e9`, `afcc63a`, `cfd16d7`, `028cca6`, `cc5eed2`).

**Network, proxy, TLS, and firewall realism**

- Preserved network timing invariants and source-native visibility across Zeek, Cisco ASA, proxy, web access, and storyline flows, including HTTP lifetime bounds, ASA connection IDs, DNS transaction accounting, denied CONNECT accounting, explicit proxy byte accounting, and NAT/source rendering (`442f41e`, `f13982d`, `7e2b829`, `3a382a0`, `5c995ba`, `fa1a7bd`, `a42ff57`, `e2714c5`).
- Improved TLS/certificate realism and scanner/DNS behavior by avoiding public-CA chains for raw IP TLS, keeping TLS success/failure state coherent across sources, reducing repeated certificate/hash artifacts, and diversifying DNS tunnel labels and web scan cadence (`36b0aa0`, `5aa3a7b`, `6b3a299`, `a5a8af2`).

**Validation**

- Fixed the CLI `eforge version` command to report the package `__version__` instead of the stale hardcoded `0.1.0`, and added unit coverage for the command.
- Full slow-inclusive suite passed before release prep: `uv run pytest -v --include-slow` with 2669 passed, 23 skipped, and 80.54% coverage.

## v0.5.3 (2026-04-30)

Five pre-existing evaluation false-positives eliminated. No generator behavior changes.

**Evaluator bug fixes**

- **Windows 4800/4801**: Added `workstation_locked` and `workstation_unlocked` entries to `WINDOWS_VARIANT_MAP` in `parseability.py`. Records for those EventIDs were evaluated against the base variant (missing required fields) rather than the correct variant, producing spurious "Unknown field" warnings and spec-conformance failures.
- **eCAR field declarations**: Declared six previously-emitted-but-undeclared optional base fields in `ecar.yaml`: `outcome`, `status_code`, `sub_status` (USER_SESSION/LOGIN) and `target_pid`, `target_process_uuid`, `target_image_path` (PROCESS/OPEN). Eliminated 6× "Unknown field in ecar" warnings per eval run.
- **eCAR rename**: THREAD/REMOTE_CREATE fields `tgt_pid` / `tgt_pid_uuid` renamed to `target_pid` / `target_process_uuid` to match the OpTC eCAR spec and the naming used by PROCESS events. Updated emitter, YAML, co_occurrence config, tests, and docs.
- **Host Log Profile deduplication**: `_build_host_log_profile` in `causality.py` now normalizes `VisibilityModel._os_map` keys via `resolve_hostname` before deduplication. Each host now appears exactly once (bare form) instead of appearing as both `WS-01` and `WS-01.corp.example.com`.
- **Diurnal pattern skip on short scenarios**: `_score_diurnal_pattern` returns a skipped `SubScore` (score=None) when the event span is <24 h or covers only one weekday — conditions under which JSD is not meaningful. The Timing pillar aggregator renormalizes weights across the remaining active sub-scores. Previously this produced a hard-zero score on typical single-day scenarios.
- **proxy_access ↔ zeek_http**: Added `condition_a/b: method_not: CONNECT` to exclude CONNECT tunnel rows from the pair. Proxy emits two rows per HTTPS request (CONNECT + inner); the pivot previously matched them against a single zeek_http row, causing status_code false-failures. Extended `_matches_condition` in `plausibility.py` to support `<field>_not` inequality checks.
- **zeek_ssl ↔ zeek_x509**: Added `condition_b: host_cert: true` to restrict the `server_name ∈ san.dns` agreement check to leaf certificates. Intermediate and root CA certs correctly have empty `san.dns` — the evaluator rule was incorrectly flagging them as failures.

**New / updated tests**

- `test_eval_record_fidelity.py`: `TestWindowsVariantMapCoverage` — all mapped variant names exist in the format YAML; 4800/4801 explicitly covered.
- `test_eval_cross_source_pairs.py`: `TestMatchesCondition` extended with three `_not` cases; `TestProxyZeekHttpConnectExclusion` (2 tests); `TestZeekSslX509IntermediateCAExclusion` (2 tests).
- `test_eval_timing_bounds.py`: `test_short_scenario_span_is_skipped` asserts `skipped=True, score=None` (was: `score=100`).
- `test_ecar_thread_process_access.py`, `test_ecar_spec_compliance.py`: updated assertions for `target_pid`/`target_process_uuid` rename.

---

## v0.5.2 (2026-04-30)

Completion of the 4-pillar evaluation restructure: rewritten field agreement scorer, strict-mode validators, two new timing sub-scores, Zeek schema fixes, and extended rule coverage.

**Signal integrity fixes (Phase A)**

- `event_presence` improved from 69.05 → 85.71 on apt-healthcare-breach dataset (acceptance_passed now True).
- Fixed FQDN hostname indexing: records with FQDN Computer fields (e.g., `WS-DEV-02.meridianhcs.com`) are now indexed under both FQDN and bare hostname keys. Eliminated the primary cause of missed storyline traces.
- Added `_DURATION_EVENT_TYPES` (beacon, dns_tunnel, dga_queries, web_scan): extended forward search window to `min(interval_seconds, 3600)` for duration-based events. Beacons with 10-minute intervals no longer require trace at exact `time:` offset.
- Added `logoff` and `raw` matchers in `_record_matches`. Both had fallthrough-to-False behavior; now logoff matches 4634/4647 on Windows, session-closed on syslog.
- Documented 6 remaining generator gaps (rogue DHCP, DC-01 C2 beacons without NAT, standalone DNS): categorized as (c) scenario topology gaps, not eval bugs.

**Cross-source field agreement (Phase C)**

- Replaced the no-op `_timestamps_agree` implementation with real pivot-key joins.
- New `src/evidenceforge/config/evaluation/cross_source_pairs.yaml` with 5 defined pairs: Windows 4688 ↔ eCAR PROCESS/CREATE (same PID+hostname+60s window), zeek_conn ↔ Cisco ASA flow (4-tuple match), web_access ↔ zeek_http and proxy_access ↔ zeek_http (client+URI+10s bucket), zeek_ssl ↔ zeek_x509 (cert_chain_fuids list → x509 id, server_name ∈ san.dns).
- Supports: multi-field pivots, `list_contains` pivot (ssl fuids), `require_hostname_match`, `time_window_seconds`, normalizers (`lower`, `path_basename_ci`, `cn_from_dn`), numeric tolerance, `b_is_list` for list-valued fields, nested properties access (`b_nested`).
- `field_agreement` score on apt-healthcare-breach: 93% (real disagreements: proxy vs Zeek HTTP status codes diverge because proxy records upstream status; these are genuine generator behavior differences).

**Parseability strict mode (Phase D)**

- New `validate_strict(format_name, raw, fields)` in `src/evidenceforge/formats/validator.py`. Dispatches to per-format checks when a format appears in `STRICT_FORMATS`.
- syslog: accepts BSD format (Mon DD HH:MM:SS HOSTNAME) and RFC 5424 with PRI (`<N>`); validates PRI ≤ 191 when present.
- zeek_*: each raw line must be valid JSON and a top-level object.
- windows_event_security / windows_event_sysmon: XML must be well-formed with root `<Event>` and `<System>` child.
- eCAR: JSON must be valid; `object` and `action` fields must be in the known enum sets.
- Strict mode runs only when `record.raw` is non-empty and the format is in `STRICT_FORMATS`; results merged into the Parsability sub-score.

**Zeek schema fixes (Phase B)**

- Fixed `zeek_files.yaml`: `tx_hosts`, `rx_hosts`, `conn_uids`, `analyzers` changed from `type: string` to `type: list`. These fields are emitted as JSON arrays; the validator was rejecting them with false positives, causing 15,395 spec_conformance failures.
- Fixed `zeek_http.yaml`: `tags` changed from `type: string` to `type: list`.
- Fixed `zeek_pe.yaml`: `section_names` changed from `type: string` to `type: list`.
- `spec_conformance` on apt-healthcare-breach: 99.22% → 100% after fixes.

**Evaluation rule extensions (Phase E)**

- `co_occurrence.yaml`: added impossible-combo rules — `zeek_conn` SF+TCP cannot have `duration=0`; `zeek_http` CONNECT must have `response_body_len=0`; `zeek_ssl` established connections must have `server_name`.
- `co_occurrence.yaml`: added new sections for `zeek_http` and `zeek_ssl`.
- `co_occurrence.yaml`: added `equals` check type (alongside existing `not_equal`, `in`, `present`, `min_length`). Fixed `min_value`/`max_value` to work as standalone checks (not just combined).
- `distributions.yaml`: added `zeek_http` (method, status_code) and `zeek_ssl` (version, established) reference distributions.

**New timing sub-scores (Phase F)**

- `diurnal_pattern` replaces `work_hours` as the active scoring sub-score (work_hours demoted to weight=0 informational). Scores 2D hour×weekday distribution via Jensen-Shannon divergence vs persona reference profile. Penalizes artificially uniform distributions (JSD < 0.01 treated as robotic). Requires ≥30 events per user.
- `attack_chain_timing`: checks elapsed time between consecutive storyline events against bounds from new `src/evidenceforge/config/evaluation/timing_bounds.yaml`. Default bounds 5s–2h; per-action-type overrides (lateral movement, exfiltration, recon, credential, persistence, C2, beacon, deploy, escalation). Activity matching: case-insensitive substring on step activity field.
- Temporal Realism sub-score weights updated: diurnal 0.20, burstiness 0.20, system_regularity 0.15, causal_ordering 0.20, timing_plausibility 0.15, attack_chain_timing 0.10 (sum=1.0).

**New tests (Phase G)**

- `tests/unit/test_eval_cross_source_pairs.py` (29 tests): pivot helpers, normalizers, values_agree, score_pair, integration with empty records.
- `tests/unit/test_eval_strict_parsers.py` (29 tests): all four format-specific strict validators, STRICT_FORMATS set.
- `tests/unit/test_eval_timing_bounds.py` (15 tests): attack_chain_timing (bounds loading, keyword matching, in/out-of-bounds), diurnal_pattern (work-hours clustering, uniform distribution penalty, insufficient-event fallback).
- Updated `test_eval_temporal.py` end-to-end test to expect 7 sub-scores.
- Total: 252 unit tests (was 173).

**Docs (Phase G.5)**

- `commands/eforge/references/config-evaluation.md`: removed "planned" markers from timing_bounds and cross_source_pairs sections; added full schema documentation for both.
- `commands/eforge/evaluate.md`: updated Cross-Source Field Agreement, Diurnal Pattern, and Attack-Chain Timing descriptions; added improvements-table rows for low field_agreement and low attack-chain timing.
- `docs/reference/CUSTOMIZING_CONFIG.md`: added eval config section documenting the six YAML files and how to tune them per-project.

**Score changes on apt-healthcare-breach (1.02M records, 14h, 17 users, 42 storyline events)**

| Sub-score | Before | After |
|-----------|--------|-------|
| event_presence | 69.05 (FAIL) | 85.71 (PASS) |
| spec_conformance | 99.22 | 100.00 |
| field_agreement | 100 (no-op) | 93.00 (real) |
| population_statistics | 78.58 | 81.14 |
| diurnal_pattern | — (new) | 100.00 |
| attack_chain_timing | — (new) | 90.24 |
| Overall | 87.63 | 94.13 |
| acceptance_passed | False | **True** |

---

## v0.5.1 (2026-04-30)

Evaluation framework restructure: 5 dimensions → 4 pillars (Parseability, Plausibility, Causality, Timing).

**Framework restructure**

- Replaced the 5-dimension / 23-sub-score model with 4 pillars (20 sub-scores). All existing sub-scores are re-homed, not dropped. Two baseline-coherence sub-scores (D2.4, D2.5) are demoted to a supplementary "Host Log Profile" diagnostic (informational, not scored). One old sub-score (`work_hours`) is replaced by the planned `diurnal_pattern`.
- Two-tier acceptance model: every sub-score now has a **minimum** (hard gate — dataset fails if missed) and an **aspirational** target (informational stretch goal). Thresholds stored in `src/evidenceforge/config/evaluation/thresholds.yaml` for tuning without code changes.
- Pillar weights: Parseability 0.30, Plausibility 0.25, Causality 0.25, Timing 0.20.
- Hard gates: `spec_conformance ≥ 95`, `value_plausibility ≥ 95`, `causal_ordering ≥ 90`, `event_presence ≥ 85`.

**Engine changes**

- `DimensionScore` renamed to `PillarScore`; `DimensionScore` kept as a backward-compat alias.
- `QualityReport.dimensions` kept as a property alias for `pillars`.
- `AcceptanceCriterion` gains `pillar` (string), `aspirational`, and `meets_aspirational` fields.
- `QualityReport` gains `aspirational_met` / `aspirational_total` counts.
- Engine reads thresholds from YAML; acceptance criteria are no longer hard-coded.
- Pillar-level `supplementary` dicts merged into `QualityReport.supplementary`.
- Transition-period machinery: `_LEGACY_SUB_SCORE_LOCATIONS` maps new sub-score keys to old dimension numbers/keys so thresholds.yaml can use new vocabulary while legacy scorers still run.

**Sub-score fixes**

- `CrossSourceScorer`: D2.4 (`baseline_sampled`) and D2.5 (`baseline_aggregate`) zeroed to `weight=0` (not scored); S1/S2/S3 re-weighted to 1/3 each. Emits `host_log_profile` diagnostic in `supplementary`.
- `NoiseRealismScorer` / `anomaly.py`: red herring events no longer inflate the organic anomaly rate. Red herrings are pre-declared storyline injections — they are not background anomalies.
- `TemporalScorer`: fixed pre-existing timezone-naive/aware comparison bug in causal ordering check.

**Report**

- Pillar-oriented text report replaces the old dimension table.
- Shows minimum (PASS/FAIL) and aspirational (met/missed) side-by-side for each gated sub-score.
- Summary line: "Aspirational targets: N/M (P%)".
- Host Log Profile supplementary section shows per-host expected vs. present formats (only when missing formats exist or `--verbose`).

**CLI**

- Added `--real-parsers` flag (no-op, reserved): prints "real parser backend not yet implemented" and exits cleanly. Reserves the interface for a future strict-parser evaluation backend.

---

## v0.5.0 (2026-04-29)

Version bump only; no code changes. Releases a known-good snapshot after the v0.4.3 correlated-timing review.

---

## v0.4.3 (2026-04-29)

Cross-source correlated timing hardening and Windows auth timing polish, driven by an adversarial timing-review cycle.

**Correlated timing** — introduced data-driven timing profiles (`src/evidenceforge/config/activity/timing_profiles.yaml`) as the source of truth for all inter-event offsets and stabilized cross-source timing correlation.

- Causal prerequisites (`network.dns_before_tcp`, `auth.kerberos_before_logon`, `process.remote_thread_lsass_access`) now consult a YAML profile instead of hard-coded constants; source-native latency, teardown margins, Zeek analyzer offsets, TLS duration floors, and Windows/Sysmon collision-spacing knobs are all configurable (47ec365, 7fb35c8).
- Stale evidence suppression: teardown events (SSH close, FLOW terminate) only emit for sessions/processes with a matching open event (f764425, 2ff89c4).
- Timing alignment across edges: EDR DNS↔SSH, SSH↔DNS↔proxy, IDS↔Zeek DNS alerts, process teardown↔Sysmon 5↔Security 4689↔eCAR PROCESS/TERMINATE (05e72a3, f831dc1, c2e7d7b, 7e1f9a1).
- Correlated lifecycle edge cases: source-offset margin before logoff, lifecycle guards for cross-source timing, cross-source network timestamp offsets (cc89170, 38266e4, e156d9b).
- Loop timing review follow-up findings resolved (ebe6bbf).
- Proxy context honors the canonical HTTP status code end-to-end rather than rewriting the origin response on the client-leg (3a887c3).

**Windows auth timing & rendering polish**

- Stabilized process parent chains during auth-adjacent activity (ac69865).
- Auth rendering/coherence fixes across 4624/4625/4634/4648 and pairing with target-host 4672 for elevated sessions (270eec3, 2467428, b467e6e).
- Timing realism for auth event sequences including DC machine-account logons (4b8779a).
- Windows logon token shape derived from auth context (d553709).

---

## v0.4.2 (2026-04-29)

Windows EDR and emitter field provenance hardening from a dedicated blind review.

- Field provenance alignment across emitters: WFP connection process image preserved, WFP/DNS provenance cleaned, emitter field consistency verified via blind review (ee32f4f, 980e500, c4203ee, 8432cc9).
- Windows process EDR cross-source realism polished across Sysmon 1/5/8/10, Security 4688/4689, and eCAR PROCESS/CREATE/TERMINATE/OPEN (d7bdf56, f794877, e4c5e5e).
- Consolidated approved open-PR updates (1b180a3).
- CI tuned: fast unit gate runs on dev; slow integration tests skipped on dev and re-enabled per PR (a976a44, b8409da).

---

## v0.4.1 (2026-04-28)

Windows authentication realism round 1.

- Data-driven Kerberos pre-auth realism: 4771/4776 validation paths, stale-account failure profiles (5fe6ca2).
- Improved Windows auth event realism across 4624/4625/4634/4648 rendering (df5a921).

---

## v0.4.0 (2026-04-28)

Web proxy path modeling and TLS/Zeek network realism — the biggest single feature release of the hardening campaign.

**Explicit proxy path modeling**

- `environment.proxy.mode` (transparent | explicit) controls whether proxy-routed HTTP/HTTPS keeps direct client→origin network evidence or splits into client→proxy and proxy→origin legs (9908cb6, 685bd81).
- DENIED proxy requests stop at the proxy leg and do not produce proxy→origin Zeek/IDS/firewall transactions (848de7d).
- Explicit proxy CONNECT tunnels reused across subsequent requests; explicit proxy DNS routed through the proxy; post-CONNECT TLS emits SSL evidence reliably (3d576db, 1e87a5b, 3e01f32, 1ddb932).
- External-hostname beacons correctly route through the proxy when explicit mode is in effect (c145b4a).
- Proxy user agents moved to data-driven YAML (`proxy_user_agents.yaml`) for diversity (c71d43e).
- Proxy/HTTP content realism: separated CONNECT timestamps, Apache-style response content, correlated web_access ↔ zeek_http ↔ zeek_conn (d6ec7cc, 8da9050, 62bb6cb, 3ac0d9c, edf7f9b).
- HTTP proxy NAT realism improved (685bd81).
- Prevent future session reuse on edge cases (bf4026f).
- Broader HTTP and proxy realism improvements (cd8f9f3).

**TLS & X.509 realism**

- Destination-aware certificate profiles (d0f433c).
- Issuer-matched validity periods and issuer overrides aligned (359ed67).
- OCSP evidence linked through zeek_files (a98f7b0, 20713f0).
- Chain-depth realism from `tls_realism.yaml` (a9fcf77, 575f3c0).

**Zeek network realism**

- Improved Zeek DNS support, SMB file observations, analyzer protocol semantics, and TLS-related conn records (6cb1f88, 00ed3c8, e0bcba3, e50d3c1, d988269, eff613f).
- Zeek outputs are sorted on close for deterministic ordering (757ddb9).
- Network blind-eval findings addressed (372c49a).

**Sysmon**

- Sysmon realism signals improved (e73cb85).

**Other**

- Warn on malformed overlay presets rather than silently ignoring (06e7839).
- Evidence formats reference inaccuracies fixed (3102cc4).

---

## v0.3.0 (2026-04-22)

The MVP-plus release. Introduced the bulk/periodic event framework, workstation lock/unlock, explicit credentials (4648), DC admin-only baseline with RSAT correlation, network segmentation hardening, CLI filtering, and broad web-log realism improvements.

**Bulk event framework**

- Phase A: shared `_PeriodicEventBase` timing engine, `beacon`, `dns_query` (59b856d).
- Phase B: `web_scan`, `credential_spray` (6696428).
- Phase C: `dga_queries`, `dns_tunnel` (eb18af4).
- `ProcessAccessEventSpec` added to the `EventSpec` discriminated union so `process_access` can be declared directly as well as auto-generated by `create_remote_thread` → lsass causal expansion (c9c6017).
- Per-event-type jitter defaults: `beacon` 0.15, `web_scan` 0.4, `credential_spray` 0.5, `dga_queries` 0.3, `dns_tunnel` 0.25.
- `credential_spray` success fires at exact attempt count (b287d62).
- `web_scan_presets` registered in `eforge info` and `validate-config` (eff2e1a).
- Multiple adversarial-review rounds for the bulk-event framework (bec232d, aa63ad9, 511b5ae, fb7faed).
- Security hardening: bounded `dns_tunnel` payload size, capped `traffic_rates` overrides, hardened `web_scan` preset overlay against malformed types, explicit credential process PID for 4648 (3323d85, 7559f8c, 65af981, b3c1e9c).

**Workstation lock/unlock & explicit credentials**

- `workstation_lock` / `workstation_unlock` (4800/4801) baseline + storyline with persona-variance lock frequency and cross-hour lock persistence (223959d, 4ca4268, e55b4c6).
- `explicit_credentials` (4648) storyline handler; broader baseline 4648 patterns for scheduled-task and RunAs activity (2ab8c9e, 1154520).
- Cluster 4 tests + docs for Windows auth enrichment (229c7fa).

**DC admin-only baseline & RSAT correlation**

- Domain controllers receive admin-only baseline activity: no user desktop artifacts, type 3 logons from RSAT sessions on admin workstations (mmc.exe runs on the workstation, not the DC), type 10 RDP for direct admin access (4382147, 9cdc464).
- Correlated RSAT sessions produce cross-host events: mmc.exe + DLL loads on the workstation, LDAP/RPC to DC, type 3 logon on DC — all within seconds (e1e08d9).
- OS-aware domain filtering prevents Linux hosts from visiting Windows-only domains (9e32911).

**Network segmentation & firewall**

- `NetworkSegment.exposure` required; `external_ratio` for segments with `exposure: both` (0e72bd7).
- Top-level `NetworkConfig.public_cidrs` for the org's own public address blocks (separate from NAT-inferred ranges).
- `NetworkSensor.drop_mode` (drop|reject) controls denied-connection conn_state (S0 vs REJ).
- `NetworkSensor.threat_detection_rate` drives ASA 733100 threat-detection alerts when deny bursts exceed the configured threshold.
- `intensity` scales all background traffic via configurable `traffic_rates.yaml` (46236c0).
- PAT port overflow, SF missing duration, and syslog None hostname fixes (75de469).

**CLI & config**

- `--formats` CLI filter for targeted log generation; individual format names accepted in `output.logs` (e71163d, c1ba151).
- EDR overlay pool validation with fallback to defaults (9535939).
- Transactional `--force` overwrite with rollback on failure; preserved rollback dir on failed restore for manual recovery (1e8647e, d96c721, 0c85126).
- Moved CallTrace patterns and EDR pools to YAML with overlay support (9396719, e835405).
- Document `sysmon_filters`, `edr_pools`, `calltrace_patterns` configs (1346563).
- Normalize naive datetimes in emitter sort and session bootstrap (2f4a856).
- Remove redundant runtime cap in `_resolve_traffic_rate` (05a8842).
- DNS multi-answer IPs use correct provider, IPv6 prefixes from YAML (980e24f).
- `dns_registry` + `proxy_uri_templates` for new curated `site_maps` domains (7f3656b).

**Web log realism improvements** — root-cause fixes for three structural realism gaps identified during adversarial evaluation of the `vdf-web-scanning` scenario (0f1e79b):

- *Referer header centralization* (root cause: 5 of 6 `HttpContext` construction sites dropped the field): extracted `pick_referrer()` and `pick_scan_referrer()` into `src/evidenceforge/generation/activity/referrer.py`. Baseline web-server traffic now generates realistic Referer distributions (~55% blank, ~20% search engine, ~20% same-origin, ~5% social/news; bot UAs always blank). Auto-generated HTTP connections and both storyline HTTP event types now populate Referer. Per-scanner Referer behavior is declarative in `web_scan_presets.yaml` via `send_referrer` field, grounded in verified upstream source behavior: Nikto sends same-origin Referer on ~30% of requests (partial-crawl mode); gobuster/sqlmap/dirb/nmap_http send none. Scenario authors can pin `referrer` on `connection` and `beacon` event specs for phishing-click and drive-by scenarios.
- *Scanner UA token substitution*: added `src/evidenceforge/utils/ua_template.py` with `render_ua()` supporting scanner-scoped tokens (`@NIKTO_TESTID@`, etc.). Nikto UA updated from static `(Test:map_codes)` to `(Test:@NIKTO_TESTID@)` — now generates a unique 6-digit test ID per request, matching real Nikto behavior.
- *Per-event-type jitter defaults*: each concrete `_PeriodicEventBase` subclass now carries an event-appropriate jitter default instead of the uniform 0.2 (see bulk event framework above). Scenario authors can still override per-event; existing YAML that omits `jitter` now gets a more realistic default.

**Data realism fixes from expert panel** (P0/P1 batches)

- P0 fixes: user-profile apps on DCs, formulaic HTTP, SF orig_bytes (727dbb8).
- P1 fixes: task XML, SSH fingerprints, IDS SIDs, journald, SSH ordering (8333dbf).
- Two additional iteration rounds (8c6bb87, 217490d).
- 6 more P0/P1 realism fixes (1486928).
- `test+docs` for realism fixes (33723dd).
- 4800/4801 and other missing EventIDs added to eval distribution allowlist (5e22243).

**Validation & security**

- JSON Logic truthiness for field constraints enforced (ddeb1ef).
- Windows eval XML parser hardened against entity expansion DoS (a92ebbe).
- Linux `process_query` placeholder expansion resolved (791c12c).
- `attacker` user renamed to a plausible contractor account (ce58db5).

**Test & CI**

- Repaired 4 broken tests (activity_gen fixture, thread safety assertions, Zeek DNS interface, inbound traffic role) (98d7813).
- Tests: `test_referrer.py`, `test_ua_template.py`, `test_scan_referrer.py` (185 new assertions) added for web log realism. Full suite at v0.3.0 release: 2083 passed.

---

## Pre-MVP Quality Fixes

### World Model Refactor (2026-04-08)

- Added a compiled `WorldModel` / `WorldPlanner` layer above the canonical event model to unify user placement, host capability inference, infrastructure discovery, proxy routing, and shared session bootstrap across baseline and storyline paths.
- Centralized interactive/network/SSH/RDP session planning so planner-owned sessions are allocated in `StateManager` before `ActivityGenerator` emits correlated host and network evidence, eliminating duplicated remote-session logic and brittle mock-only assumptions.
- Extended runtime ownership state to carry session/process/connection provenance (`logon_id`, `session_kind`, `source_port`, `transport_pid`, initiating PID, close time, source host metadata) and aligned process-first connection attribution with the new layer.
- Completed a realism cleanup sweep replacing remaining `hash()`-based derivation in critical generation paths with `_stable_seed(...)`.
- Added dedicated unit coverage in `tests/unit/test_world_model.py` and reran full verification with `uv run pytest -v --include-slow` (`1483 passed`).

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

# EvidenceForge Implementation Plan

**Status:** Phase 8.5 (Dual src/dst HostContext) COMPLETE; Pre-MVP quality fixes ongoing
**Started:** 2026-03-11
**Last Updated:** 2026-04-29

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

- [x] Remediate Windows singleton PID path traversal telemetry suppression — canonicalize Windows singleton paths with ntpath before seeded PID reuse and cover traversal variants with a unit test.

**Goal:** Fix all expert-identified issues that would cause an analyst to reject the data. Consolidated from 6 blind expert panel improvement loops (Threat Hunter, DFIR, Network Eng, Detection Eng) plus infrastructure issues. Work top to bottom.

### Security Fixes

- [x] Fix Cisco ASA connection ID normalization to avoid repeated full-file rewrites during emitter barrier flushes by deferring whole-file normalization to final close.
- [x] Fix causal-ordering scoring so diagnostic sample caps do not hide additional violations — diagnostic failure samples remain capped at 10, but every non-allow_missing_prior inversion now contributes to causal-ordering totals; covered by a regression test with 20 inversions plus 5 valid pairs.

### Skill Installer Agent Support

- [x] Fix Codex skill installer symlink clobber vulnerability by validating/writing nested destination files safely.
- [x] Fix RDP user coercion session/ground-truth desynchronization vulnerability and malformed fallback user crash — aligned preallocated RDP session usernames with coerced Windows credentials, records RDP ground truth from canonical session identity, and sanitizes fallback email domains.
- [x] Add dual-agent `eforge install-skills` workflow — default to Claude project installs, add explicit `--agent claude|codex`, keep Claude project/global behavior, add Codex user-level `~/.codex/skills/` installs, reject invalid Codex/global combinations, and cover installer safety/stale-cleanup behavior with tests.
- [x] Reduce Codex skill reference duplication — bundle only the references each Codex skill needs and rely on installer stale cleanup to prune no-longer-needed reference files from prior installs.
- [x] Import existing Claude `/eforge assess` command as a Codex skill without modifying the source skill.
- [x] Fix official Codex skill installs so generated `SKILL.md` frontmatter is valid and user-managed `eforge-*` skills are preserved.
- [x] Create, validate, generate, evaluate, and blind-assess the iteration-test scenario from `scenarios/ITERATION-TEST-PROMPT.md`.
- [x] Run three additional iteration-test assessment loops, fixing prior-loop P0/P1 root causes, committing each pass, regenerating/evaluating as needed, and preserving blind-review artifacts.
- [x] **P0** Loop 3 blind-review follow-up / up-to-10 assessment loop — completed the requested up-to-10 loop run. Final loop eval passed at 94/100 and rendered probes found zero DNS response-accounting contradictions, zero Sysmon parent-create-after-visible-parent-termination cases, and zero eCAR post-termination references. Blind reviewers still scored synthetic across all four roles (avg synthetic confidence 79.5/100, avg realism 71/100). Top remaining root-cause finding: Sysmon Event 5 can carry an EventData `UtcTime` earlier than later Event 7 module-load telemetry for the same ProcessGuid, even when XML System `TimeCreated` ordering looks normalized. Next fixes should also address all-zero Sysmon `TerminalSessionId`, SYSTEM subject-domain rendering, IP CN-only public-CA X.509 records, DNS tunnel/web scan regularity, and source-specific collection imperfection profiles.
- [x] Harden web scan preset `max_effective_rate` validation to prevent overlay-driven generation crashes or hangs.
- [ ] **IN PROGRESS** **P0** Loop 10 continuation / second up-to-10 assessment run — ignore "source coverage too perfect" style findings for now because source-specific missingness/coverage variance is already deferred to the imperfect-observation/profile TODO items. Active fixes should prioritize concrete source-native contradictions from loop 10: Sysmon Event 5 EventData `UtcTime` before later same-ProcessGuid telemetry, all-zero Sysmon `TerminalSessionId`, SYSTEM subject-domain rendering, public-CA IP CN-only X.509 records, DNS PID disagreement, DNS tunnel regularity, and web scan regularity. Continue up to 10 loops with the same early exits: average synthetic confidence <= 60%, no P0/P1/P2 findings remain after excluding deferred source-coverage findings, or scores appear to worsen / hit diminishing returns.
  Loop 20 fix pass: stabilized repeated Zeek certificate hashes, ordered Zeek certificate file rows after SSL analyzer rows, suppressed static ASA NAT xlate churn, ordered same-second systemd lifecycle syslog rows, and added SCP receiver-side Linux/file artifacts. Verified with full `uv run pytest -v`, Ruff, and `eforge validate-config`.
  Loop 21 fix pass: preserved caller-pinned successful TLS handshakes, carried explicit POST body sizes through proxy egress, emitted visible early DHCP renewals for storyline-DHCP hosts, aligned DNS FLOW PID inference with the DNS Client service, localized SCP receiver-side eCAR actor IDs, and normalized remote-thread target image paths. Local loop scenario NAT now includes the DMZ so proxy egress renders with mapped public sources. Verified with full `uv run pytest -v`, Ruff, and `eforge validate-config`.

### P1 Syslog BSD Timestamp Year Inference

- [ ] **P1** Syslog emitter uses BSD format (`%b %d %H:%M:%S`) with no year in the output template (`syslog.yaml` line 61). The parser substitutes `datetime.now().year` at parse time, so evaluating scenario data in a different calendar year than it was generated stamps all syslog events with the wrong year. This inflates the observed event span for the diurnal-pattern short-scenario guard and any other evaluator logic that computes spans across formats. Fix: switch the syslog emitter template to ISO 8601 (`%Y-%m-%dT%H:%M:%SZ`) and remove the BSD branch from the parser (keeping it only as a fallback for real-world log ingestion). Existing `_SYSLOG_MONTHS`, `_SYSLOG_TS_RE`, and `_syslog_sort_key` in the emitter can be removed once the template is ISO. Scenarios regenerated after this fix will parse cleanly at any future date.

### P0 Cross-Source Timing Audit

<<<<<<< ours
- [x] Security hardening: bounded `workstation_lock.min_unlock_gap_seconds` with schema upper-bound validation and runtime clamping to prevent `timedelta` overflow from malicious local overlays.

=======
- [x] **P1** Security fix: prevent quadratic behavior in Linux `systemd-logind` session ID allocation for warm-up/pre-boot and same-second event bursts.
>>>>>>> theirs
- [ ] **IN PROGRESS** **P0** Comprehensive correlated-event timing audit — after the current 78% synthetic blind-review fixes, perform a full audit similar to the emitter field-provenance audit, but focused on timing relationships between correlated events. Inventory all generated event clusters that are expected to correlate across Security/Sysmon/eCAR/Zeek/proxy/ASA/syslog/baseline/storyline outputs; identify where timestamps are source-native exact, realistically offset, impossible, or accidentally reordered; verify same-source ordering invariants such as process-create before process follow-on artifacts; verify cross-source offsets such as DNS before TCP, proxy client leg before proxy egress, firewall deny before absent downstream evidence, process create before WFP/Sysmon network evidence, auth before process, module/file/registry after process, and teardown after build/start; then implement root-cause fixes with tests and generated-output probes.
- [ ] **P0** Timing-audit baseline blind review follow-up — broad data-only baseline review of `/private/tmp/eforge-timing-baseline-output/data` scored **92% synthetic**. Critical findings: visible 4634 logoff followed by later same-host/same-LogonID process/lock/unlock activity; Sysmon Event 3/7/follow-on records preceding a later visible Event 1 for the same ProcessGuid. High findings: uniform 4624 `ElevatedToken=%%1842`; anonymous Type 3 logons use unrealistic domain/source/elevation fields. Medium findings: exact cross-source network timestamp reuse between Windows 5156, Zeek conn, and eCAR FLOW; proxy inspected HTTP paths remain domain-class inconsistent for update/vendor hosts.
- [x] **P0** Same-session lifecycle ordering guard — fixed baseline scheduling so planned logoffs are known before user activity, user activity/lock-unlock events skip inactive sessions, activity updates session last-use time, and Windows Security rendering has a narrow 4634-after-dependent backstop. Generated-output probe on `/private/tmp/eforge-timing-loop3-output/data` found zero same-host/same-LogonID 4688/4801 events after visible 4634 logoff.
- [x] **P0** Process follow-on timestamp guard — fixed process-dependent generation for module loads, registry noise, process access, and remote-thread evidence to clamp after process start and carry process start metadata where needed; added a Sysmon render-time ProcessGuid ordering backstop. Generated-output probe on `/private/tmp/eforge-timing-loop3-output/data` found zero Sysmon follow-on records before their Event 1 for the same ProcessGuid.
- [x] **P1** Cross-source network timestamp profile — Windows Security 5156, Sysmon Event 3, and eCAR FLOW now use data-driven `source.*` timing profiles so host audit/EDR telemetry renders after the canonical wire event instead of tying Zeek conn timestamps exactly. Generated-output probe on `/private/tmp/eforge-timing-loop12-output/data` found 20,892 Zeek/eCAR common tuples with zero exact or millisecond timestamp matches.
- [x] **P2** Proxy domain-class path/content profile completion — inspected proxy GET rows can still pair vendor/update user agents and hosts with generic browser paths such as `/login` or `/favicon.ico`. Current domain-class path selection and non-browser site-map exclusions cover the generated timing scenario; probe on `/private/tmp/eforge-timing-loop17-output/data` found zero infra/update/cert proxy GET rows with browser-generic paths, favicons, CSS, or webp assets.
- [ ] **P3** Time-window-aware blind-eval prompt/library — keep the bounded-window guidance in every reviewer prompt and codify it in the local eval helper/script once one exists, so reviewers do not treat missing pre-window initiators as impossible while still flagging visible initiators that occur after dependent events.
- [x] **P0** Sysmon transitive parent-create ordering guard — `_shift_process_creates_after_visible_parent()` now iterates until stable so cascading parent shifts in multi-level ProcessGuid chains cannot leave a child Event 1 before its shifted visible parent Event 1; added focused unit coverage for three-level chains.
- [ ] **P0** Follow-up timing blind review findings — follow-up data-only review of `/private/tmp/eforge-timing-loop3-output/data` scored **96% synthetic**. Critical: visible Sysmon Event 5 process termination followed by later Event 3/Event 7 telemetry for the same ProcessGuid. High: SSH syslog lifecycle entries for the same sshd PID/source tuple sorted as `Accepted` before `Connection from`; Linux `systemd-logind` session IDs mixed huge epoch-derived IDs with small sequential IDs. Medium: some accepted SSH logins lacked nearby visible session-open messages, likely same root as syslog second-level ordering.
- [x] **P1** Harden IDS DNS template validation/rendering against unsafe format fields — enforce that `dns_query_templates` only allow the `token` replacement field with sane format syntax/width and reject malformed or resource-exhausting templates in both config validation and runtime rendering.
- [x] **P0** Harden timing profile overlay parsing in generation path — enforced safe integer parsing and range clamps for `relationships.*` and `windows_event_time.collision_spacing` so malformed `.eforge/config/activity/timing_profiles.yaml` values cannot crash generation or produce pathological timing offsets; added focused unit coverage for invalid-type and extreme-value overlays.
- [x] **P0** Sysmon process-termination lifecycle guard — fixed Sysmon rendering so Event 5 process termination cannot appear before later visible telemetry for the same ProcessGuid; added focused unit coverage.
- [x] **P1** SSH syslog lifecycle ordering/profile — fixed SSH syslog compound events to use whole-second connection→accepted→pam→logind ordering and per-host monotonic small systemd-logind session IDs; added focused unit coverage.
- [x] Windows auth timing findings from blind review — fixed the confirmed Case A ordering bug where visible 4688 process-create records could precede a later visible same-host/same-LogonID 4624. The root causes were future-session identity selection, parent-chain process backdating before session start, and later 4624 rendering for already-registered sessions. Also fixed account-management SubjectLogonId selection to avoid future sessions, prevented desktop baseline process activity from reusing Type 3 network logons, stopped random 4672 assignment for ordinary users, and added explicit storyline process_access handling so credential-dump actions render Sysmon Event 10.
- [x] **P0** Post-logoff same-LogonID lifecycle contradictions — latest data-only blind review found visible 4634 logoff followed by later 4688 process activity and later Type 7 unlock/4624 for the same host + LogonID. Fixed through session activity/logoff ordering guards and verified against `/private/tmp/eforge-timing-loop12-output/data`: zero visible same-host/same-LogonID `4688`, Type 7 `4624`, or `4801` records after a visible `4634`.
- [x] **P1** Windows 4624 ElevatedToken realism — fixed 4624 rendering so `ElevatedToken` comes from `AuthContext.elevated` instead of the template default, and fixed anonymous logons so they use `NT AUTHORITY`, remote source IP/port/workstation metadata when available, and non-elevated token semantics. Added focused generator and emitter coverage.
- [x] **P1** Anonymous logon field realism — fixed anonymous Type 3 logons so they render `NT AUTHORITY`, remote source IP/port/workstation metadata when available, and non-elevated token semantics.
- [x] **P1** Security/Sysmon logoff source-offset margin — follow-up review of `/private/tmp/eforge-timing-loop6-output/data` found visible Security 4634 logoffs tens of milliseconds before later Sysmon Event 1 process creates for the same LogonID, caused by Security's render-time lifecycle guard ignoring Sysmon source-native collection offsets. Fixed the generator logoff margin after session activity and widened the Windows Security 4634 render-time guard to clear downstream endpoint source offsets. Generated-output probe on `/private/tmp/eforge-timing-loop9-output/data` found zero Sysmon Event 1 records after a same-session visible Security 4634.
- [x] **P0** IDS DNS alert/query contradiction — fixed Snort DNS alert/Zeek DNS payload disagreement by making DNS IDS signatures carry data-driven `dns_query_templates`, loading them with overlay support, and building a canonical `DnsContext` from the selected signature during IDS false-positive generation. Generated-output probe on `/private/tmp/eforge-timing-loop10-output/data` found 13 DNS IDS alerts and zero same-tuple Zeek query suffix mismatches.
- [x] **P0** Timestamp compression bursts — added overlay-aware `timing_profiles.yaml` for causal/source-latency/teardown timing and Windows/Sysmon tied-timestamp collision spacing. Causal DNS/Kerberos/remote-thread/audit offsets and logoff margins now use the profile, and Windows/Sysmon render-time normalization keeps small tied clusters near-zero while spreading large tied clusters across seconds. Generated-output probe on `/private/tmp/eforge-timing-loop11-output/data` found worst 1ms windows of 7 Security events and 4 Sysmon events, down from earlier 174/106 event spikes.
- [ ] **P2** ASA static NAT teardown cadence — follow-up review of `/private/tmp/eforge-timing-loop6-output/data` found Cisco ASA static NAT translation records mechanically paired with immediate same-second connection teardown. Review ASA connection/NAT lifecycle timing as part of source-native network timing profiles.
- [ ] **P2** Deterministic cross-source offset fingerprints — follow-up review of `/private/tmp/eforge-timing-loop6-output/data` still found deterministic-looking Security/Sysmon/eCAR offsets. Fold this into the cross-source timestamp profile work so offsets are stable enough to correlate but varied enough to avoid source-fingerprint artifacts.
- [x] **P0** Blind-review time-window context — every blind reviewer prompt should explicitly state that the dataset is an extract for a bounded collection window, so initiating events that occurred before the window can still have in-window echoes. Acceptable: processes, sessions, connections, leases, or logoffs whose creation/start event predates the extract and is therefore absent. Error: a visible initiating event for the same identifier appears later than its dependent event, such as a 4688 before a later same-host 4624 with the same LogonID. Added this guidance to `/eforge evaluate` for blind qualitative reviews and used it in the current blind-eval prompt.
- [x] **P0** Source-native timestamp precision/rendering profiles — include rendered precision and per-source formatting in the timing audit. Known example: Windows Security XML now renders EVTX-like 100ns precision, but a blind review caught that the 7th fractional digit was previously always `0`. Audited the current renderers: Windows Security/Sysmon share EVTX-like 100ns formatting with deterministic 7th-digit variation, Zeek renders microsecond epoch seconds, eCAR renders integer milliseconds, and proxy/web/ASA/syslog render source-native second precision. Generated-output probe on `/private/tmp/eforge-timing-loop12-output/data` found 17,698 Windows Security timestamps with 7th-fractional-digit coverage across all digits 0-9.
- [ ] **P0** Windows auth/network timing examples to include in the audit — verify remote auth causality across Zeek/Windows/DC evidence: TCP connection start before 4625/4624, established/reset-after-payload state before any host auth result, successful remote 4624 source port matching the network tuple, 4771/4776 offset from member-host 4625 without sub-microsecond cross-host alignment, and audit/process events such as 1102 following the causative process while preserving source-native EventRecordID reset behavior.
- [x] **P0** Loop 12 blind-review timing findings — data-only review of `/private/tmp/eforge-timing-loop12-output/data` scored **92% synthetic**. Fixed the critical Sysmon parent GUID ordering issue by preserving parent start time on `ProcessContext`, filtering future-started parents during parent resolution, and normalizing visible Sysmon parent/child Event 1 ordering. Fixed the high Zeek TLS lifetime issue by data-driving Zeek SSL/X.509 analyzer offsets, enforcing a completed-TLS conn duration floor, and suppressing ssl/x509 analyzer rows for partial TCP handshakes. Generated-output probe on `/private/tmp/eforge-timing-loop17-output/data` found zero Sysmon parent-after-child cases, zero Zeek ssl/x509 rows after conn end, and zero ssl/x509 rows on non-`SF` connections. Low follow-up remains: web access logs can rotate bot/script/browser User-Agents rapidly from the same public IP; track as web-client identity/session realism polish after P0/P1 timing fixes.
- [x] **P1** Loop 17 blind-review follow-up — data-only review of `/private/tmp/eforge-timing-loop17-output/data` scored **87% synthetic**. Fixed actionable findings: Linux `systemd-logind` session IDs/PIDs now come from shared state and timestamp-derived per-host sequencing; ASA connection IDs no longer collide across adjacent-second high-volume bursts; generated SSH session `conn.json` rows include `orig_ip_bytes`/`resp_ip_bytes`; RSA-named TLS issuers no longer choose ECDSA certificate metadata and `eforge validate-config` rejects that combination. Prompt-calibration finding: Type 7 unlock 4624 events are not original session initiators, so reviewers should not treat pre-unlock process activity with the same LogonID as impossible when the original Type 2/10 session began before the extract. Generated-output probe on `/private/tmp/eforge-timing-loop19-output/data` found zero logind PID/order issues, zero ASA concurrent connection-ID reuse, zero SSH rows missing IP byte counters, zero RSA/ECDSA x509 mismatches, and zero process-before-later-non-Type7-4624 cases.
- [x] **P1** Loop 19 blind-review follow-up — data-only review of `/private/tmp/eforge-timing-loop19-output/data` scored **92% synthetic**. Fixed the critical SSH disconnect timing issue by recording SSH transport close time on session state, making logoff/disconnect evidence wait for the latest session end marker, and reusing the same baseline SSH duration for conn.log and syslog disconnect timing. Fixed DNS TXT conn accounting so response-bearing TXT rows retain originator query payload. Fixed denied explicit-proxy CONNECT accounting so proxy-access rows use proxy denial byte/time scale rather than inherited tunnel byte counts. Quick tests, ruff, `eforge validate-config`, and generated-output probes on `/private/tmp/eforge-timing-loop22-output/data` passed for DNS TXT and denied CONNECT, and found zero matching SSH disconnect-before-conn-close cases.
- [x] **P1** Loop 22 blind-review follow-up — data-only review of `/private/tmp/eforge-timing-loop22-output/data` scored **82% synthetic**. Fixed the critical eCAR MODULE/LOAD after PROCESS/TERMINATE issue by tracking process last-activity time in state, marking image-load activity, and delaying stale-process termination after process-dependent telemetry. Fixed the high SSH close mismatch by recording SSH transport close time even for preallocated sessions, suppressing stale tuple-bearing disconnect syslog in favor of generic PAM session-close messages, avoiding standalone disconnect tuples in baseline SSH noise, and treating self-sourced SSH cleanup as generic. Fixed the medium DNS tunnel RTT/duration issue with overlay-aware `dns_tunnel_rtt` config, `eforge validate-config` schema coverage, and DNS conn duration propagation from `DnsContext.rtt`. Generated-output probe on `/private/tmp/eforge-timing-loop29-output/data` found zero eCAR module-after-terminate cases, zero SSH disconnect/Zeek close contradictions, and zero DNS tunnel RTT/duration issues.
- [x] **P1** Loop 23 blind-review follow-up — data-only review of `/private/tmp/eforge-timing-loop29-output/data` scored **82% synthetic**. Fixed the critical SSH same-PID close mismatch by suppressing Linux `sshd` syslog close evidence when the backing SSH transport is stale or self-sourced, leaving bounded-window extracts with unmatched visible opens rather than impossible visible closes. Tightened the data-driven DNS tunnel RTT default from `0.04-1.5s` to `0.04-0.35s` while preserving overlay support and `eforge validate-config` range validation. Generated-output probe on `/private/tmp/eforge-timing-loop30-output/data` found zero SSH same-PID close/Zeek contradictions, zero tuple-bearing disconnect lines, and zero DNS tunnel RTTs above 1s.
- [x] **P1** Loop 24 blind-review follow-up — data-only review of `/private/tmp/eforge-timing-loop30-output/data` scored **85% synthetic**. Fixed the critical eCAR FLOW after visible PROCESS/TERMINATE issue by making connection generation update the owning process last-activity marker, dropping stale non-system PID attribution when the process is no longer running, and protecting Windows PID 4/System in the seeded process map. Fixed the medium Zeek identical-timestamp burst with data-driven `source.zeek_conn_start` jitter in `timing_profiles.yaml`. Generated-output probe on `/private/tmp/eforge-timing-loop31-output/data` found zero eCAR FLOW-after-visible-terminate cases and reduced exact Zeek conn timestamp bursts to a max of 2 rows.
- [x] **P2** Security hardening: validate `dns_tunnel_rtt` overlay shape/range at load/runtime boundary so malformed overlay values cannot crash generation.
- [ ] **P2** Post-timing-audit statistical polish — same-dataset blind reviews of `/private/tmp/eforge-timing-loop31-output/data` scored **30% synthetic** and **60% synthetic** with no Critical/High findings and no recurrence of the prior eCAR/SSH/DNS/Zeek burst timing defects. Remaining medium/low polish: Zeek `conn.json` still has repeated exact duration constants across unrelated rows (`0.8`, `2.0`, `0.01`), two nonlocal SSH failed-password syslog rows lacked exact matching Zeek SSH tuples, and stale `svc_deploy8` SSH failures occur on a very regular two-hour cadence.
- [x] **P1** Explicit proxy origin-error egress regression — in explicit forward-proxy mode, preserve proxy→origin egress emission for canonical origin HTTP 4xx/5xx responses (`cache_result=MISS`) and only short-circuit egress for proxy-generated deny/auth/gateway failure outcomes.

### P2 Windows Event XML Shared Helpers

- [ ] **P2** Review shared Windows Event XML helper opportunities across Security and Sysmon emitters — timestamps now share EVTX-like 100ns formatting, but Security and Sysmon also share the same high-level Event XML envelope. Inventory which pieces can safely move to shared helpers (timestamp formatting, XML escaping, EventRecordID mechanics, common System envelope fields) without hiding provider-specific Security/Sysmon field semantics.

### World Model Refactor

- [x] Open the draft PR from `world-model` into `dev`
Compiled `WorldModel` / `WorldPlanner` behavior is now the shared planning layer for persona placement, host capabilities, proxy/infrastructure routing, and interactive/network/SSH/RDP session bootstrap across baseline and storyline generation.
Runtime ownership state was expanded to track exact session/process/connection provenance, the remaining `hash()`-based realism-critical derivations were replaced with `_stable_seed(...)`, and the contributor/docs/skill guidance was updated to match the new contract.
Verification is complete: dedicated `tests/unit/test_world_model.py` coverage was added and `uv run pytest -v --include-slow` passed (`1483 passed`).

### Recently Resolved

- [x] Blind Windows process/Sysmon/eCAR realism evaluation — separate evaluator scored the regenerated focused dataset 90% synthetic. Highest-impact findings: eCAR THREAD/REMOTE_CREATE disagrees with Sysmon Event 8 on thread IDs/start addresses, process create user/logon identity can disagree across Security/Sysmon/eCAR, and process-create timestamps are too exact across sources. Medium findings covered unmatched terminations, templated process distributions, and pre-seeded process GUID references.

- [x] Pytest stabilization after Windows process/Sysmon/eCAR review — fixed the explicit-proxy storyline integration failure by preventing dynamic HTTPS API-style proxy requests from being modeled as cache HITs, then reran `uv run pytest --include-slow --durations=50 --durations-min=1.0` successfully (`2329 passed, 1 skipped` in 737.74s). Duration data shows runtime is dominated by the medium dataset memory test (410.68s), explicit proxy storyline fixture (139.43s), and medium dataset generation setup (107.60s); the medium/parallel tests were already marked slow, and the explicit proxy correlation fixture is now marked slow too.

- [x] Windows process/Sysmon/eCAR source review — generated a focused Windows-heavy dataset with Windows Security, Sysmon, eCAR, and Zeek. Fixed Sysmon Event 5 `ProcessGuid` mismatches by carrying process start time on termination events, and fixed Windows Security/Sysmon same-second timestamp jitter so rendered XML stays chronological per host. Focused tests and regenerated-output probes passed.

- [x] Windows process/Sysmon/eCAR blind-review follow-up — implemented shared canonical `RemoteThreadContext` evidence for Sysmon Event 8 and eCAR `THREAD/REMOTE_CREATE`, moved user-session process identity correction into generation before Windows Security/Sysmon/eCAR rendering, and switched eCAR module-load generation to the same process-aware DLL profile data used by Sysmon ImageLoaded events. Remote-thread start locations are now data-driven/overlay-aware and covered by `eforge validate-config`. Existing Windows/Sysmon render-time timestamp normalization already prevents exact XML timestamp ties, so no additional timestamp offset was needed in this pass. Verification: focused tests passed, full unit suite passed (`2278 passed, 1 skipped`), Ruff passed, and `uv run eforge validate-config` passed.

- [x] Windows process/Sysmon/eCAR blind-eval cleanup — fixed approved follow-up findings from the 82% synthetic blind eval: eCAR remote-thread `tgt_tid` now matches Sysmon Event 8 `NewThreadId`, Security 4689 avoids blank `SubjectLogonId` for system-owned process exits, process-create render timestamps have deterministic source offsets across Security/Sysmon/eCAR, eCAR `PROCESS/OPEN` uses explicit target fields instead of overloading `command_line`, eCAR module-load timing no longer exactly ties process creation, and failed logons carry explicit eCAR failure outcome/status fields. Focused tests, full unit tests, full non-slow tests, Ruff, and `eforge validate-config` passed.

- [ ] Windows process/Sysmon/eCAR blind-eval follow-up from 88% synthetic review — remaining review item is remote-thread join ambiguity when repeated source/target PID pairs appear. Process lifecycle joins are deferred to the source-specific telemetry coverage/profile design below. The 5156 PID/image attribution, 4688 PID 4 parent fallback, Sysmon/eCAR module-load correlation, and process-access provenance findings were fixed in the canonical emitter field provenance item.

- [x] Canonical emitter field provenance fixes — implemented the approved emitter audit fixes: Windows 5156 process attribution resolves from canonical process state, Sysmon/eCAR share canonical image-load data, Sysmon Event 10 and eCAR `PROCESS/OPEN` use `ProcessAccessContext`, Sysmon parent GUIDs use parent process start time, user process parentage no longer falls back to PID 4, Zeek dhcp.log receives DHCP option-domain data when available, bash history no longer carries non-native `exit_code`, ASA/proxy context-owned fields are honored, and deferred source-specific process lifecycle completeness modeling is documented below.

- [x] Canonical emitter field provenance generated-output evaluation — generated a targeted multi-source dataset under `/private/tmp/eforge-provenance-output` and ran deterministic rendered-output probes for: 5156 PID/image attribution from process state, 4688 parent PID sanity, Sysmon/eCAR image-load agreement, Sysmon/eCAR process-access target/thread provenance, Zeek DHCP option-domain rendering, bash history without `exit_code`, ASA context-owned fields, and proxy CONNECT tunnel scoping. The first probe caught a real WFP process-image propagation bug on explicit proxy client legs; fixed it and reran the probes successfully. Next: targeted blind provenance review, then broad all-data blind review.

- [x] Canonical emitter field provenance blind-review follow-up — targeted blind review scored the focused dataset 88% synthetic. Fixed confirmed actionable findings: Windows 5156 no longer inherits a storyline process from the wrong host/OS, unresolved non-system WFP process images are suppressed instead of rendering `-`, PID 4 WFP fallback renders as `System`, internal DNS preserves scenario IP→FQDN registrations before generated aliases, and `_ldap._tcp...` NXDOMAIN companion probes use SRV. Regenerated-output probes passed. The proxy CONNECT+GET finding was a prompt artifact because the blind prompt omitted the current TLS-inspection assumption; rerun the blind review with that assumption stated.

- [ ] Canonical emitter field provenance blind-review remaining findings from 78% synthetic review — fix Sysmon intra-log causality where file/registry/module follow-on events can render before Event 1 for the same process GUID/PID; normalize bare storyline executable names (e.g. `powershell.exe`) to OS-appropriate full image paths before process creation so Security/Sysmon/eCAR/WFP all receive complete canonical paths; make proxy baseline HTTP path/content-type selection domain-class aware so OS/update/OCSP/CRL hosts do not receive generic browser paths like `/login`, `/favicon.ico`, CSS, image assets, or `text/html`; tune bash typo injection density for short histories.

- [ ] Source-specific process lifecycle completeness modeling — deferred design item. Add a configurable telemetry coverage/profile layer that can model realistic Security/Sysmon/eCAR missingness, ingestion delay, audit-policy gaps, and endpoint coverage variance without ad hoc omissions in individual emitters. This should be part of the broader cross-source distribution realism layer, not a Windows-only workaround.

- [x] Open PR consolidation into `dev` — re-applied the storyline typing-cadence monotonicity fix from PR #81, folded Dependabot pytest/Pygments updates into the dev workflow, and added Dependabot configuration so future dependency PRs target `dev`.

- [ ] **IN PROGRESS** Windows Security/authentication source review — focused baseline eval is complete; fixing high-signal Windows auth realism findings first (4672/session semantics and sparse 4800/4801 rendering), then rerunning focused generation/eval before moving deeper.

- [x] TODO.md reality audit — verified high-signal open realism/code-cleanup findings against the current codebase, marked stale items, and identified the generated-output validation pass needed before deeper realism work.
  Targeted verification: `uv run pytest tests/unit/test_network_realism.py tests/unit/test_activity_helpers.py tests/unit/test_dc_kerberos_logon.py -q --no-cov` passed (25 tests).

- [x] Generated-output TODO validation — generated two temporary 12-hour audit datasets under `/tmp` from the VDF scenario, including a network/IDS sensor variant. Evaluator parsed 1,057,006 records from 11 sources with 99.998% parsability and overall score 86.64. Output metrics confirmed several stale TODOs and several still-real Sysmon/DNS/ASA findings.

- [x] Security: cap `baseline_activity.traffic_rates` override values (max 50,000) to prevent scenario-driven resource exhaustion DoS.
- [x] Security: cap `dns_tunnel` payload/payload_size to 1 MiB to prevent memory exhaustion from untrusted scenarios
- [x] Security: guard web_scan preset overlay merge against non-dict `presets` payloads to prevent malformed overlay crash/DoS
- [x] Fix `_find_user_session` mixed tz-aware/naive `start_time` comparison crash (Aardvark finding)
- [x] Fix RDP remote-logon network evidence duplication/coherence (avoid duplicate type-10 helper connection; preserve shared source-port correlation)
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
- [ ] `eforge generate --force` overwrite can fail for scenarios that do not emit `GROUND_TRUTH.md` — explicit-proxy smoke testing exposed that replacing an existing output directory expects staged ground truth even when fresh no-storyline generation produced only `data/`. Decide whether no-storyline generation should always write an empty `GROUND_TRUTH.md` or overwrite swap should tolerate its absence.

- [x] **`uv.lock` not committed** — gitignored, so CI `setup-uv@v4` cache fails. Remove from `.gitignore` and commit.
- [x] **`eforge validate` can't find personas in dev mode** — works when installed (`eforge validate`) but not via `uv run eforge validate`. Blocks dev workflow.
- [x] **511 ruff lint errors + 102 formatting issues** — CI lint job fails immediately. Auto-fix + suppress false positives (B008 for Typer, N806 for lookup tables, B904 for typer.Exit).
- [x] **Coverage threshold mismatch (local 70% vs CI 90%)** — pyproject.toml `fail_under` doesn't match CI's `--cov-fail-under=90`. Devs pass locally, fail in CI.
- [x] **CI runs tests 3 times** — 3 separate pytest invocations (unit, integration, both again for coverage). Consolidate to single run.
- [x] **No pre-commit hooks** — ruff issues only caught in CI. Add pre-commit framework with ruff check + format hooks.
- [x] Security: sandboxed Jinja template rendering for YAML-defined format templates (SandboxedEnvironment + StrictUndefined) to block SSTI/code execution while preserving safe field interpolation.
- [x] Security: bound baseline failed-logon synthetic service account selection loops to prevent scenario-controlled infinite loops/DoS.
- [x] Security: guard persona `activity_intensity` normalization against all-zero values to prevent divide-by-zero DoS during generation (all-zero overrides now safely map to floor probability instead of crashing).
- [x] Security: prevent nmap CIDR fallback host expansion from materializing full `network.hosts()` lists (large attacker-controlled CIDRs can trigger memory/CPU DoS).
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
- [x] **4672 (Special Privileges) target-host semantics** — elevated-session 4672 is auto-emitted alongside the target-host 4624; Kerberos causal expansion emits DC 4768/4769 only.
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

- [x] Blind HTTP/proxy/network telemetry realism evaluation of `/private/tmp/eforge-http-proxy-review-output/data` — scored highly synthetic due to concrete ASA/Zeek DNS and proxy/client-tap contradictions, with ASA connection-ID artifacts and DNS consistency issues as supporting tells.
- [x] Fresh blind HTTP/proxy/network telemetry realism evaluation of regenerated `/private/tmp/eforge-http-proxy-review-output/data` — TLS-intercept proxy pattern accepted; remaining high-signal findings were plain HTTP proxy/client status contradiction, OCSP responder/issuer mismatch, and generated-looking Zeek certificate FUID artifact.
- [x] Fresh blind HTTP/proxy/network telemetry realism evaluation after latest fixes for `/private/tmp/eforge-http-proxy-review-output/data` — prior critical proxy/client and OCSP/public-responder issues were fixed; remaining evidence is medium/high realism polish around Zeek HTTP body length semantics, Let's Encrypt OCSP responder choice, and ASA connection-ID spacing artifacts.
- [x] Fresh blind Windows authentication/security telemetry realism evaluation of `/private/tmp/eforge-windows-auth-baseline-output/data` completed; assessed high synthetic likelihood from impossible 4672 logon semantics, documentation IP usage, and malformed sparse Windows events.
- [x] Fresh blind Windows authentication/security telemetry realism evaluation of regenerated `/private/tmp/eforge-windows-auth-baseline-output/data` completed; TEST-NET artifact no longer present, with remaining synthetic evidence centered on 4672 logon semantics and empty EventData for 1102/4800/4801.
- [x] Windows 4672 session semantics — removed duplicate DC-side standalone 4672 from Kerberos causal expansion; elevated 4672 now stays tied to the target-host 4624 logon session, and non-service audit fallback logon IDs no longer use SYSTEM's `0x3e7`.
- [x] Windows 4800/4801 rendering — populated workstation lock/unlock EventData fields in the Windows Security XML template.
- [x] Blind Windows authentication/security realism evaluation of current `/private/tmp/eforge-windows-auth-baseline-output/data` completed; prior 4672 issues are fixed, 4800/4801 fields are populated, with remaining synthetic indicators in DC 4625/4776 status contradictions and lock/unlock SessionId mismatches.
- [x] Windows failed-auth DC consistency — failed NTLM validation 4776 now carries the matching failure status instead of success.
- [x] Windows lock/unlock session consistency — 4800/4801 derive a stable SessionId from TargetLogonId so lock/unlock pairs do not change terminal sessions.
- [x] Blind Windows authentication/security realism evaluation of latest regenerated `/private/tmp/eforge-windows-auth-baseline-output/data` completed; prior 4672, 4625/4776, and 4800/4801 findings are fixed, with remaining realism concerns around Kerberos 4768 PreAuthType distribution and missing Zeek visibility for external failed-auth source.
- [x] Windows Kerberos 4768 pre-auth realism — moved TGT PreAuthType/ticket/encryption distributions into `kerberos_realism.yaml`, added overlay-aware loader and `eforge validate-config` schema/coherence checks, and verified generation now produces mostly encrypted timestamp pre-auth with rare populated PKINIT certificate fields.
- [x] Blind Windows authentication/security realism evaluation of latest regenerated `/private/tmp/eforge-windows-auth-baseline-output/data` completed; Kerberos PreAuthType=15 empty-cert issue is fixed, with remaining lower-confidence tells in one repeated 4672 on unlock and absent Zeek visibility for external failed auth.

**Snort/IDS:**
- [x] ✓ Snort protocol field randomly assigned (no binding to SID/rule) — restructured `_FP_SIGS` to protocol-keyed dict with per-signature port and direction
- [x] ✓ Snort flow directions inverted for outbound rules — signatures tagged "in"/"out", src/dst swapped for outbound alerts
- [x] ✓ ICMP connections carry TCP/UDP ports — force src_port=0, dst_port=0 for ICMP in generate_connection()
- [x] ✓² Snort baseline volume too low (1-3/hour) — increased to 5-15/hour per sensor; experts still consider 73/day low vs thousands in real environments
- [x] ✓² Snort alert timestamps not chronologically sorted — enabled _sort_before_flush on SnortEmitter
- [x] Snort SID revisions all `:1:1` — stale audit finding: generated IDS output used varied SIDs and revisions (e.g., `[2012887:1:2]`, `[2000575:1:8]`, `[2009714:1:9]`).
- [x] ~~Snort baseline scan IPs absent from Zeek conn~~ — no longer reproduces; prior visibility fixes (denied traffic visibility, external deny scoping) resolved this
- [x] Snort alert volume still 10-100x too low for real perimeter IDS (experts expect thousands/day) — stale audit finding: generated IDS sensor produced 4,065 alerts in 12h (~8,130/day) on the audit scenario.
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
- [x] GrantedAccess diversity limited to 3-4 values (0x1000/0x1010/0x1410/0x1FFFFF) — fixed with data-driven `process_access_patterns.yaml` baseline pairs and weighted mask alternatives. Verification audit output: 949 Event 10 records used 6 distinct masks (`0x1000`, `0x1400`, `0x1010`, `0x0400`, `0x1410`, `0x0410`).
- [x] CallTrace offsets limited to 2 patterns — moved to calltrace_patterns.yaml with 8 distinct call chains (ntdll, KERNELBASE, kernel32, RPCRT4, wbemcomn, combase, advapi32, sechost)
- [x] Sysmon EventRecordIDs perfectly sequential (no gaps) — gaps widened to 1-7 with 15% chance of 8-50
- [x] Event 8 StartModule/StartFunction always empty for benign pairs — fixed by deterministic source-aware StartModule/StartFunction selection in the Sysmon emitter. Verification audit output: 325/325 Event 8 records had populated StartModule/StartFunction values.
- [x] **P1** Event 3 process-to-destination mismatch — fixed with data-driven `process_network_map.yaml` `dns_tags`, app-specific DNS registry tags, and hostname-aware process attribution in `WorldPlanner.ensure_connection_process()`. Audit regeneration showed 0 bad Teams/Outlook/OneDrive Event 3 pairs; office app records only used allowed endpoint families.
- [x] **P1** Event 3 sampling uses non-deterministic `random.random()` — fixed with per-connection stable sampling using Zeek UID/connection ID/time fallback, plus low-rate browser/app sampling. Verification audit output: 3,478 Event 3 records with 46 unique destination hostnames.
- [x] **P1** Event 7 (ImageLoaded) volume too thin — fixed with process-aware application DLL pool materialization and higher standalone baseline sampling. Verification audit output: 459 Event 7 records across 14 Windows hosts over 12h with 46 unique ImageLoaded paths and no template-wide app DLL assignment to unrelated system processes.
- [x] **P2** Registry TargetObject path diversity — fixed with registry template materialization in `edr_pools.yaml` (`{guid}`, `{hex}`, `{doc}`, `{mru}`, etc.) and process-create registry events. Verification audit output: Event 12/13 records used 1,048 unique TargetObject paths with 0 double-braced TargetObject artifacts.
- [x] Sysmon actor-diversity review follow-up — independent reviewer score improved from 82% synthetic (initial) to 78% synthetic after Sysmon cleanup; completed an actor-diversity pass targeting the remaining process fingerprints.
- [x] Event 8 source/target pairs too narrow — fixed by moving benign CreateRemoteThread pairs into `create_remote_thread_patterns.yaml` and widening seeded actors. Verification audit output: 326 Event 8 records used 10 source/target pairs.
- [x] Event 10 source/target pairs too narrow — fixed by widening `process_access_patterns.yaml` and seeded long-lived process actors. Verification audit output: 950 Event 10 records used 16 source/target pairs.
- [x] Registry writer processes too narrow — fixed with key-family-aware writer selection. Verification audit output: Event 12/13 records used 12 writer process images and 1,968 unique TargetObject paths with 0 template artifacts.
- [x] Event 7 residual attribution issues — tightened generic module/process matching and retained process-aware DLL materialization. Verification audit output: 380 Event 7 records used 42 unique ImageLoaded paths.
- [ ] Cross-source distribution realism layer — defer until data-source reviews are complete. Independent Sysmon reviews found that field-level realism improved, but per-host event volumes and recipe selection remain too uniform. Design a deterministic host/activity profile layer derived from scenario facts (host type, roles, assigned_user, persona, services, stable seed) and use it to shape Sysmon, Windows Security, Zeek, syslog, firewall, web, proxy, and eCAR/EDR rates. Avoid implementing Sysmon-only profile logic unless needed as a narrow bug fix.

**Zeek:**
- [x] Zeek DNS / network support log review — fixed DNS/TLS PTR coherence, added realistic TXT lookup variety, prevented CDN-hostname MX artifacts, increased file-server SMB target coverage, and made SSH pivot UIDs respect sensor visibility. Tests, docs, skills, and skill references updated where needed.
- [x] Blind Zeek/network eval high+medium follow-up — fixed high-impact DNS/TLS/IP coherence, unresolved HTTP URI placeholders, Linux SSH UID metadata, SMB session/operation shape, weird.log conditionality, and NTP syslog semantics. TLS volume clustering remains deferred for a separate design discussion.
- [x] Blind Zeek/network non-TLS follow-up — fixed duplicate exact non-ICMP flows, weird.log overproduction on clean TLS, syslog/eCAR chronological ordering, direct internal DNS cache behavior, DHCP↔conn UID coherence, and ground-truth sensor UID coherence. Blind score improved to 85% synthetic; remaining high-impact findings are TLS/x509/OCSP modeling and SMB Zeek file visibility design items.
- [x] ✓ Cross-sensor UIDs byte-identical — deterministic per-sensor UID derivation (SHA-256 of uid+sensor) preserving intra-sensor cross-log correlation
- [x] ✓ x509 certificate serial numbers all 5 bytes — generate 128-bit (16-byte) serials matching real CA practice
- [x] ✓ NTP Zeek ref_time/org_time/rec_time/xmt_time all 0.0 — populate with realistic values relative to event timestamp
- [x] OTH/"Cc" conn_state over-represented; SF at 88% (real: 55-75%); missing SH/S2/S3 states — rebalanced TCP distribution: SF 82%→62%, added S2/S3 half-closed states, increased S0/REJ/RSTO/RSTR
- [x] SSL ssl_history limited to 2 values (CsiI, CsijI) — stale audit finding: generator now has 5 success patterns + 2 failure patterns, and `tests/unit/test_network_realism.py` verifies diversity.
- [x] Zeek conn history too uniform (ShADadfF dominant) — 26 distinct history patterns in TCP_CONN_STATE_DISTRIBUTION including RST-based terminations, retransmissions, partial closes
- [x] Zeek files not chronologically ordered after multi-source generation — Zeek sensor writers now preserve normal flush behavior and sort the complete NDJSON file by `ts` on close. Focused regression coverage verifies cross-flush ordering for direct and per-sensor outputs.
- [x] SMB volume too low for Windows file server environments — Windows file servers now independently drive SMB baseline targets even when no DC is present, and file-server targets are weighted above DC SYSVOL/GPO traffic.
- [x] SMB session shape and operation mix — file-server SMB baseline traffic now uses larger read/write/metadata-sized connection profiles and emits eCAR FILE READ/WRITE plus create/delete operations for the authenticated user.
- [x] ~~DNS UIDs missing from conn.log (~7%)~~ — no longer reproduces (0/6487 orphans on apt-healthcare-breach); prior visibility fixes resolved this
- [x] UFW BLOCK entries don't appear in conn.log — UFW BLOCK dispatches via SecurityEvent, emits Zeek conn with conn_state='REJ'
- [x] weird.json TCP-specific types attributed to UDP sources — split into protocol-specific pools; UDP gets DNS/checksum/length anomalies at 0.5% rate vs TCP's 3%
- [x] weird.log condition-driven anomaly distribution — weird events now concentrate around partial/reset TCP flows, missed bytes, long bulk sessions, and DNS/UDP-specific oddities instead of uniform random sprinkling.
- [x] Exfiltration connections show 0 bytes transferred — auto-size by technique/description heuristic; added orig_bytes/resp_bytes/conn_state to ConnectionEventSpec; storyline defaults to SF
- [x] No port 135 (RPC/EPMAP) traffic — stale audit finding: baseline legitimate lateral movement, scan ports, blocked ports, RSAT tooling, and Sysmon port-name mapping all include 135/RPC.
- [x] Inconsistent sensor coverage for SSH pivot — SSH session generation now returns an empty network UID when topology says no sensor can observe the SSH leg, allowing storyline ground truth to mark the network evidence as filtered while preserving host-side syslog/eCAR evidence.

**DNS:**
- [x] DNS IP pool reuse: 15+ unrelated SaaS domains resolve to same IP — switched to domain-first selection for baseline web/SaaS; FORWARD_DNS maps domain→IP; fixed 93.184.216.34 mapping (was Reuters, now example.com)
- [x] DNS AAAA records: unrelated services share IPv6 prefix (cross-provider) — stale audit finding: `dns_registry.yaml` now has explicit IPv6 mappings and provider-prefix fallback ranges keyed by IPv4 allocation.
- [x] CloudFront distributions resolve to Microsoft IP ranges (cross-provider) — stale audit finding: CloudFront/AWS registry entries now resolve to AWS-style 52/54 ranges, not Microsoft-owned ranges.
- [x] No TXT queries (SPF/DKIM/DMARC checks) — baseline DNS now includes low-rate TXT companion lookups for SPF/DKIM/DMARC-style mail/authentication noise.
- [x] No Windows telemetry noise in query set — stale audit finding: registry includes Windows/background domains such as `settings-win.data.microsoft.com`, `ctldl.windowsupdate.com`, `crl.microsoft.com`, and `arc.msn.com`.
- [x] TTL distribution too uniform — Phase 6.0: varied TTLs with cache-aging jitter
- [x] Queries default to corp.local instead of scenario domain — stale audit finding: generated internal DNS used `vandynefoundation.org` (e.g., `dc01.vandynefoundation.org`, `_kerberos._tcp.vandynefoundation.org`, `wpad.vandynefoundation.org`), not `corp.local`.
- [x] MX records for CDN domains that shouldn't have mail exchangers — MX queries now use registrable domains only when the hostname is plausible for mail ownership; CDN/static hostnames fall back to TXT support lookups instead.
- [x] DNS/TLS/IP coherence at scale — hostname-aware connection generation now rewrites mismatched destination IPs to the hostname's registered IP pool, and browsing subresources resolve CDN/resource hostnames through the same DNS registry.

**TLS/SSL:**
- [x] TLS/x509 correlation gaps — baseline audit found SSL records without `cert_chain_fuids` and x509 issuer/subject pairings that looked implausible. Added deterministic certificate file UIDs, linked ssl.log to x509.log, and tightened domain-to-CA overrides for common CA-owned/Microsoft domains.
- [x] TLSv13 ratio too low for 2024 timeframe — audit output showed TLSv13 at 19,669/56,372 SSL records (~35%). TLS version selection now uses explicit weighted constants with TLSv13 as the modern majority default.
- [ ] TLS version/cipher suite mismatches
- [ ] Non-intercepting proxy mode — current proxy behavior assumes TLS interception, so HTTPS proxy logs can include CONNECT plus inspected request rows and downstream visibility should follow the inspected transaction. Future config can add tunnel-only/non-intercepting behavior separately because it changes proxy URL visibility, Zeek SSL/x509 certificate chains, HTTP visibility inside CONNECT tunnels, and IDS content inspection semantics.
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
- [x] NTP syslog lifecycle semantics — periodic systemd-timesyncd messages now mix source selection, clock sync, offset adjustments, and timeout messages without repeating initial synchronization after the first host sync.
- [ ] No SSH protocol negotiation messages
- [x] Logrotate/cron.daily fire too frequently (should be daily, not multiple times per hour) — stale audit finding: `systemd_schedules.yaml` defines logrotate and cron-daily as daily scheduled jobs with per-host jitter, outside the per-hour probability loop.
- [x] Centralized syslog timestamps not chronologically sorted — _sort_flat_file = True in syslog.py; sorting in host_base.py
- [ ] Dual SSH syslog entries with mismatched PIDs/ports

**Windows Events:**
- [x] ✓ IpAddress "::ffff:-" malformed — handle "-" string in _ipv6_mapped()
- [ ] DLL file as NewProcessName in 4688
- [x] Low 4689:4688 process termination ratio (57% vs 80-90%) — raised termination probability from 0.5 to 0.85
- [x] EventRecordID gaps too regular — stale audit finding: audit output had 189 distinct Windows Security EventRecordID gaps (max 200) and 50 distinct Sysmon gaps (max 50).
- [x] 4769 TargetUserName double-realm format — stale audit finding: audit output had 3,495 Event 4769 records and 0 double-realm TargetUserName values.
- [x] KeyLength always 0 for NTLM logons — stale audit finding: audit output included both `KeyLength=0` and `KeyLength=128` values.
- [ ] 4648 targets localhost instead of DC for domain commands
- [ ] 4728 MemberName is "-" (should be DN of added member)
- [ ] No 4778/4779 (RDP reconnect/disconnect)
- [x] Process creation timestamp can precede its authorizing logon
- [x] Missing 4634 logoff events for network logon sessions — paired logoffs for type 3 machine account logons on DCs (1-30s delay); baseline type 3/5 already had logoff pairing
- [x] Only AES-256 Kerberos encryption; no RC4/AES-128 mix — stale audit finding: Kerberos TGT/TGS/renewal generation samples `0x12`, `0x11`, and `0x17` with weighted probabilities.
- [x] Only 2 unique TicketOptions values; zero 4771 pre-auth failures — randomized TicketOptions per event type; boosted stale 4771 probability to 15%; added active-user typo 4771 at 2%/hour
- [x] File server has no domain user logon events — type 3 logon+logoff pairs for SMB access in baseline traffic profiles and storyline causal expansion
- [x] NETWORK SERVICE TargetDomainName shows domain instead of "NT AUTHORITY" — _subject_domain() helper in windows.py returns "NT AUTHORITY" for SYSTEM/NETWORK SERVICE/LOCAL SERVICE
- [x] Event 4672 LogonId 0x3e7 for domain users — target-host 4672 now shares the 4624 LogonID, and Kerberos causal expansion no longer emits duplicate standalone DC 4672 records.

**Process Trees:**
- [x] ✓³ explorer.exe parent for everything — spawn_rules.yaml now defines valid parent-child relationships; _resolve_parent() auto-creates intermediate chains (shells for CLI tools, services.exe for system processes, sshd→bash for Linux)
- [x] ✓³ PID allocation monotonic with uniform stride (~4) — replaced choice list with lognormal distribution (Windows mu=1.2 sigma=0.8; Linux mu=0.5 sigma=0.6); PID wraparound skips allocated PIDs
- [x] explorer.exe parent for RDP sessions (should be per-session userinit→explorer) — per-session smss→winlogon→userinit→explorer chain for type 10 logons
- [x] All Linux user processes share same ppid — per-SSH-session sshd fork + bash login shell; session_shell_pid on ActiveSession
- [x] Human Burstiness at 56/100 — retuned Hawkes params (alpha_beta_ratio 0.80→0.60, beta 0.04→0.06), tightened bias clamps (0.95→0.75), narrowed Gaussians
- [ ] Mimikatz at Medium integrity would succeed in scenario but fail in reality — generator doesn't model integrity levels

**HTTP/Proxy:**
- [x] Web/proxy format correctness pass — kept `web_access` aligned to Apache/Nginx combined log format and made `proxy_access` a consistent W3C Extended enterprise proxy log. Current proxy behavior assumes TLS interception, so HTTPS emits CONNECT plus inspected request rows; tunnel-only non-intercepting proxy behavior is deferred. Updated emitted fields, parser coverage, format docs, skill references, and regression tests.
- [x] Explicit proxy blind eval — agent-based review of a fresh explicit-proxy dataset rated synthetic likelihood at 65%. Strengths: client-side sensors see client→proxy, egress sensors see proxy→origin, core sensors see both, proxy access mostly aligns with Zeek HTTP, and IDS alerts have matching visible Zeek connection evidence. Remaining tells are now tracked below.
- [x] Validate requested proxy output requires proxy topology — when `proxy_access` is requested but no scenario system has `roles: [forward_proxy]`, `eforge validate` now warns with actionable topology guidance. Handled in validation, not generation; tests, docs, scenario skill, and skill reference updated.
- [x] Proxy logs omitted/mis-scored in evaluation — proxy parser existed but was not imported into the evaluation parser registry, and optional dash fields were parsed as invalid nulls. Registered `ProxyAccessParser`, added discovery coverage for host-directory `proxy_access.log`, and aligned optional field parsing/format validation.
- [x] Web/proxy access logs not chronologically sorted — baseline audit found per-web-server timestamp inversions. Host-multiplexed web/proxy access writers now sort by rendered request timestamp before flush; focused emitter tests added.
- [x] Web scan request counts too identical across campaigns — duration/end-time web_scan events treated `rate` as exact throughput. Explicit `count` remains exact, while duration/end-time scans now apply deterministic per-campaign rate drift so repeated scanner runs do not produce identical request totals.
- [x] Proxy access logs lack coherent Zeek-observed proxy path — added `environment.proxy.mode` (`transparent` default, `explicit` for PAC/browser-configured proxy) and `listener_port` (explicit default 8080). Explicit proxy generation now emits client→proxy and proxy→origin legs through normal sensor visibility instead of the original direct client→origin network event; validator, signal-integrity eval, docs, skills, and regression tests were updated. The current proxy model assumes TLS interception; non-intercepting tunnel-only behavior remains deferred.
- [x] Explicit proxy DENIED requests still produce upstream origin evidence — denied explicit-proxy transactions now return after the client→proxy/proxy_access event and do not dispatch proxy→origin Zeek HTTP/conn/SSL evidence, firewall/ASA built/deny/teardown transactions, or IDS alerts. Regression coverage includes egress Zeek, Snort, and Cisco ASA emitters.
- [x] Explicit proxy client-side origin DNS too common — fixed two leakage paths: port-only HTTP/S connections now infer service before DNS/proxy routing, and external web hostnames paired with the DNS-server fallback IP are resolved to deterministic external IPs before explicit proxy handling. Private destinations without hostnames now get internal DNS names instead of public SaaS/analytics names. Smoke output reduced client-side DNS from 474 to 171 records and removed tracked analytics/web-origin domains from client DNS while increasing proxy-side origin DNS as expected.
- [x] Explicit proxy TLS completeness gaps — established proxy→origin `service=ssl` connections now get a final SSL/x509 context repair before dispatch if earlier state normalization left them as `conn_state=SF` without SSL context. Normal TLS handshake failures still mutate away from SF. Smoke output showed 0 missing SSL rows by UID for established egress TLS on both core and egress sensors.
- [x] Explicit proxy CONNECT reuse/pooling realism — explicit HTTPS traffic now tracks active `(client, proxy, host, origin, port)` tunnels for 5 minutes and reuses them for ordinary HTTP-context requests without IDS/firewall/custom DNS evidence. This suppresses extra client→proxy CONNECT and proxy→origin TLS legs while preserving high-signal events. Smoke output dropped proxy_access rows 13,406→6,890, CONNECT rows 13,385→6,855, and core Zeek 8080/443 connection rows 13,406/13,687→6,892/7,281.
- [x] Post-CONNECT blind eval — fresh 50/50 agent review of `/tmp/network-observations-set-a/data` rated the HTTP/proxy/Zeek-focused dataset 96% synthetic. Improvements noted: plausible multi-vantage proxy topology, proxy CONNECT to internal proxy followed by proxy-origin TLS, IDS alerts correlated with visible Zeek tuples, and SSL/x509 FUID reference integrity. Remaining findings are tracked below.
- [x] Blind-eval remediation loop — stopped after exceeding the 10-iteration cap for this remediation run. Fixed the highest-impact contained findings: CONNECT and TLS byte/packet invariants, proxy byte/status semantics, internal CA issuer selection, stateful TLS resumption/cert-chain behavior, TLS cipher/key coherence, proxy failure diversity, per-sensor Zeek timing jitter/UID/FUID spaces, x509 SAN rendering and local SSL/x509 reference integrity, CONNECT zero-body Zeek HTTP semantics, HTTP files FUID correlation, and proxied storyline beacon denial behavior. Last blind score before the final structural fixes was still 97% synthetic, so remaining medium/high-impact work is tracked below rather than continuing this loop indefinitely.
- [x] Proxy CONNECT flow accounting invariants — successful explicit-proxy CONNECT rows now carry plausible client/server bytes and packets in Zeek conn while Zeek HTTP CONNECT request/response body lengths remain zero.
- [x] TLS/SNI-bearing flow accounting invariants — established SSL connections now enforce plausible client/server payload and packet floors before SSL/x509 fan-out.
- [x] Proxy byte semantics alignment — proxy access retains proxy request/response byte accounting while Zeek HTTP CONNECT body lengths are zero; HTTP response file FUIDs now stay coherent with files.log after per-sensor FUID derivation.
- [x] Internal certificate issuer realism — internal `.test`/`.local`/`.internal` host certificates now use an enterprise/private CA profile instead of public CA issuers.
- [x] TLS resumption/certificate-chain realism — first-observed SNI handshakes are non-resumed, most resumed sessions omit fresh cert chains, TLS cipher choice is bound to certificate key type and modern destination profiles, and x509 SANs render correctly.
- [x] Proxy edge-case diversity — explicit CONNECT now includes lower-rate denied, auth-required, and gateway error outcomes, and non-2xx CONNECTs stop at the proxy.
- [x] Storyline beacon proxy routing — HTTP/S beacon events from hosts with explicit proxy routes now traverse the proxy instead of raw direct client-origin network connections, including denied proxy evidence and allowed beacons that use documentation-range IPs with explicit external hostnames.
- [x] Three-loop HTTP/proxy blind-review follow-up — completed one root-cause loop after corrected full-output regeneration. Loop31 blind review rated synthetic likelihood at 68%, meeting the configured exit threshold (<=70%); structural probes passed for DMZ proxy browser UAs, GET request bodies, and ASA inbound static NAT. Deterministic eval was attempted on loop31 but stopped after running unusually long without output.
- [x] HTTP/proxy eval fixture coverage — added an explicit-proxy integration fixture that generates `proxy_access`, Zeek, and Cisco ASA together, with allowed HTTPS producing client→proxy plus proxy→origin evidence and denied HTTPS stopping at the proxy before origin-side Zeek/ASA evidence.
- [x] Proxy/Zeek consistency tests — added file-level regression coverage for proxy_access status/host alignment with visible Zeek proxy legs, denied suppression, explicit proxy sensor placement, and TLS-intercepted HTTPS rows on listener-port proxy traffic.
- [x] Regenerate HTTP/proxy blind-review samples with explicit `eforge generate --output ...` — generated `/private/tmp/eforge-http-proxy-review-output/data` from `/private/tmp/eforge-http-proxy-review.yaml` using `--output /private/tmp/eforge-http-proxy-review-output --force`. Structural probes confirmed proxy_access rows, client→proxy Zeek on listener port 8080, allowed proxy→origin Zeek/ASA, denied HTTPS stopping at proxy, and no Squid-specific assumptions.
- [x] Shared HTTP MIME/path coherence helper — centralized extension-to-MIME and MIME-to-size behavior in `generation/activity/http_content.py`, wired it into proxy URI selection, browsing sessions, baseline web requests, and storyline HTTP/beacon/web_scan contexts. Overlay regression coverage verifies an overlay-defined `/status.gif` with `text/html` is normalized to `image/gif`, and `eforge validate-config` passed.
- [x] TLS-intercepted proxy CONNECT/request row separation — inspected HTTPS request rows no longer share exact timestamps, byte counts, and durations with synthetic CONNECT rows. CONNECT setup rows now get deterministic earlier timestamps plus small tunnel-setup byte/time fields, while inspected request rows keep their own accounting. Regression coverage added for listener-port HTTPS proxy traffic.
- [x] DMZ web servers generate desktop-like proxy traffic — blind review found public web servers using the explicit proxy with browser-looking Windows/Linux UAs for SaaS/CDN requests. Fixed by selecting role-aware proxy User-Agents, avoiding browser-session expansion for server-role HTTP(S) traffic, and passing source host identity through outbound IDS baseline events; proxy+IDS regeneration had 0 Mozilla-style DMZ proxy rows across 1,517 DMZ proxy entries.
- [x] ASA inbound static NAT representation still needs a focused probe after correct-output regeneration — loop 17 fixed reversed translation records, but blind review flagged allowed inbound connection builds that exposed private DMZ destinations where public VIP context was expected. Fixed inbound IDS false-positive baseline events plus external storyline web-scan/connection events to enter through static-NAT VIPs; targeted ASA+IDS regeneration had 0 private-private inbound built records and confirmed VIP-in-parentheses plus 305011 static translation records.
- [x] Server-originated proxy User-Agent destination/OS refinement — loop31 blind review found DMZ server proxy traffic no longer uses desktop browser UAs, but package-manager UAs could appear against unrelated SaaS/CDN domains and Fedora `libdnf` could appear from Ubuntu hosts. Added overlay-aware `proxy_user_agents.yaml`, moved proxy UA pools out of Python, and limited package-manager UAs to matching OS families and package/update repository hosts. Targeted loop33 proxy+IDS regeneration had 1,472 DMZ proxy rows, 0 DMZ Mozilla rows, 0 Fedora UA rows, and 0 package-manager UA rows to non-package destinations.
- [x] HTTPS beacon proxy User-Agent passthrough — `service: ssl` storyline beacons that specify `user_agent` but omit HTTP method/URI now write that UA verbatim to proxy CONNECT entries instead of falling back to the generic proxy browser UA pool. Added explicit-proxy storyline regression coverage for repeated HTTPS beacon CONNECT rows.
- [x] Storyline/time-window mismatch validation — blind review caught a stale sample with `time_window.duration: "24h"` but storyline activity at `+36h`, causing source horizon mismatches. `eforge validate` now warns when storyline events fall outside the generation window, and docs/skills note that all storyline/red-herring times should fit inside `time_window`.
- [x] Public web HTTPS and HTTP body semantics follow-up — external public-web baseline traffic now strongly prefers HTTPS, and generated proxy GET/HEAD/CONNECT/OPTIONS Zeek HTTP records keep `request_body_len=0` instead of copying proxy byte accounting into request bodies. Focused regression coverage added for proxy GET body semantics.
- [x] DNS analyzer parity for direct external DNS — DNS-service connections now attach a DNS context when the caller does not provide one, and explicit proxy-origin connections emit resolver evidence from the proxy host. This prevents Zeek `service:"dns"` conn rows without matching dns.log evidence in the normal generator path.
- [x] ASA teardown reason and connection ID realism — ASA connection IDs now use non-wrapping per-sensor counters, and `SYN Timeout` teardown reasons are limited to handshake-only/no-payload TCP connections rather than sampled independently from byte counts.
- [x] Scenario public IP hygiene — bundled/review scenarios that are meant to look like real collected data should avoid RFC 5737 TEST-NET ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) for public NATs, external scanners, and attacker infrastructure. Updated `/eforge scenario`, reference docs, VDF realism fixture, coverage prompt examples, and the suspicious-DNS generator path. External client generation now rejects all non-global special-use ranges, including benchmark space such as `198.18.0.0/15`. Regenerated multi-source VDF output had 0 TEST-NET or benchmark-space hits and deterministic eval scored 97/100.
- [ ] Add RFC 5737 validation warnings for realism-bound scenario fields — warn when `public_cidrs`, NAT `mapped_ip`, storyline `source_ip`/`dst_ip`, DNS `answer_ip`, or similar external-facing fields use `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`. Allow the scenario, but make the warning explicit so documentation-safe examples do not accidentally become realism-eval fixtures.
- [x] Blind HTTP/proxy loop 17 follow-up — fixed high-impact reviewer findings from the corrected multi-source dataset: ASA static NAT interface direction reversal, missing proxy DNS for high-volume explicit proxy hostnames, and public web HTTP Host headers collapsing to bare internal hostnames. Also fixed medium-impact SYN timeout duration tells and excluded non-global generated external client IPs. Focused regression tests passed; regenerated output had no targeted structural hits and deterministic eval passed at 97/100.
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
- [x] Referer header blank across all non-browsing HTTP paths — centralized `pick_referrer()`/`pick_scan_referrer()` helpers; baseline web-server traffic, auto-gen HTTP, storyline HTTP events, and proxy single-connection paths all now emit realistic distributions; scanner Referer behavior declarative via `send_referrer` preset field (Nikto: 30% same-origin; gobuster/sqlmap/dirb/nmap_http: none)
- [x] Nikto UA static test ID `(Test:map_codes)` — `render_ua()` token substitution engine; Nikto UA template uses `@NIKTO_TESTID@` generating unique 6-digit test IDs per request
- [x] Uniform jitter default (0.2) across all periodic event types — per-type defaults: BeaconEventSpec 0.15, WebScanEventSpec 0.4, CredentialSprayEventSpec 0.5, DgaQueriesEventSpec 0.3, DnsTunnelEventSpec 0.25
- [x] DHCP shows full discovery instead of renewals in mid-scenario windows — initial leases emitted during warm-up (suppressed); periodic REQUEST/ACK renewals at T/2 in _generate_system_traffic()

**Cisco ASA:**
- [x] Security: bound threat-detection deny timestamp tracking window to prevent unbounded memory/CPU growth
- [ ] ASA imperfect-observation realism — deferred to a general solution for configurable evidence gaps. Built/Teardown counts are currently perfectly balanced, while real logs can have orphans from rotation boundaries, packet loss, sensor downtime, or collection windows. Keep exact pairing as the training-friendly default unless a realism profile enables dropped/partial firewall evidence.
- [ ] ASA message type diversity limited to 106023/302013-16/305011-12 — missing 111008, 113004, 733100, 106001, 725001, 304001
- [ ] ASA deny baseline burstiness/profile variance — defer to a general per-source activity profile rather than a one-off ASA fix. Current deny events are uniformly spaced (3-7s); real scans should have configurable burst/quiet periods, campaign-level cadence, and source-specific variance.
- [ ] ASA deny metadata diversity — defer to a general field-distribution realism layer. Current deny events use `[0x0, 0x0]` hash values uniformly; a later profile should model when hashes remain zero vs vary by platform/message/context.
- [ ] NAT mapped_ip 45.33.32.1 is scanme.nmap.org — recognizable IP used as scenario PAT address

**eCAR:**
- [x] Limited object diversity on Linux — expanded _EDR_FILE_PATHS_LINUX from 5 to 20 entries (logs, caches, config files, /proc, package manager)
- [x] No FILE events on attack hosts — storyline processes now pass ensure_file_event=True, guaranteeing a FILE/CREATE for the process image
- [x] ensure_file_event PID/image mismatch — Event 11 file_create used child PID with parent image, breaking PID-based joins; fixed to use child's process_name for consistent attribution
- [x] No USER_SESSION events for server-side RDP lateral movement — generate_rdp_session() calls generate_logon() on target, which dispatches USER_SESSION/LOGIN to eCAR with EdrContext
- [x] Vary filenames in file operations — expanded _EDR_FILE_PATHS_WIN from 7 to 21 entries, _EDR_FILE_PATHS_LINUX from 5 to 20 entries
- [x] Template variable leak — literal `{psql_db}` appearing in eCAR output; stale audit finding: Linux query placeholders are handled by `_parameterize_command()`, with `tests/unit/test_activity_helpers.py` covering `{psql_db}` replacement.

**Cross-Source / General:**
- [ ] Configurable cross-source evidence disagreement — deferred by design. Perfect cross-source correlation is useful for training/huntability and should remain the default feature unless a scenario/evaluation profile asks for realism gaps. Later design a deterministic setting for dropped/partial/ambiguous corroborating evidence across Zeek, web, proxy, firewall, IDS, Windows, Sysmon, and eCAR without breaking ground-truth traceability. Include broader sensor-observation timing realism beyond the current per-event jitter: sensor clock skew/drift, NTP corrections, capture-path latency, log buffering, occasional source-specific missing/late records, and policy differences between proxy access and Zeek HTTP.
- [x] Cross-sensor timestamp precision identical to 15+ decimal places — microsecond jitter added in snort.py, windows.py, and storyline.py
- [ ] **P2** Per-host-type event rate multiplier — Domain controllers generate ~50 events/hr but real DCs running AD/DNS/DFS/GPO produce thousands/hr. `system.type` is used for routing but never for volume scaling. Need `event_rate_multiplier` on System model (or implicit per-type defaults) applied in `_calculate_events_for_hour()` and `_generate_system_traffic()`. DCs should be 3-5x workstation baseline; file servers and web servers similarly elevated.
- [ ] Configurable per-entity artifact variation — deferred to the general host/activity profile layer. Encoded PowerShell baseline noise is currently identical across hosts (same Get-Service blob); later profiles should derive stable per-host command variants, encoded payloads, tool versions, and operator habits.
- [ ] Configurable per-host volume variance — deferred to the general host/activity profile layer. Workstation connection counts are suspiciously uniform (808-1068 range); later profiles should widen variance by role, persona, weekday, installed apps, and stable host-specific multipliers.
- [ ] Configurable per-host/source log coverage — deferred to the general imperfect-observation/profile layer. Uniform log file sets across all hosts can be useful for training, but a later setting should allow host-specific telemetry coverage differences, disabled sensors, partial deployment, and collection gaps.
- [x] DNS IP pool reuse causes cross-provider resolution (CloudFront→Microsoft IPs, etc.) — domain-first selection ensures consistent domain→IP mapping via FORWARD_DNS
- [x] AWS region mismatch between DNS PTR and SSL SNI for same IP — AWS hostname/PTR generation now derives a stable per-IP region/edge identity and PTR generation respects known forward hostname context.
- [x] TLS volume clustering design — added data-driven TLS destination profiles with overlay support and `eforge validate-config` schema/tag checks. Auto-generated external TLS now uses weighted enterprise, certificate-infra, package-update, developer-tool, and long-tail browsing profiles with stable per-host preferences. Smoke output had 28,544 TLS SNI rows, 116 distinct names, top SNI share 5.5%, and top-5 share 18.0%.
- [x] TLS/x509/OCSP contained realism pass — fixed IP/PTR-derived SNI without DNS evidence, omitted fresh x509 chains on resumed TLS sessions, staggered conn/ssl/x509/OCSP analyzer timestamps, prevented public-suffix wildcard SANs, and added varied OCSP status/timing behavior. Broader TLS volume clustering remains deferred for user discussion.
- [x] OCSP response cache realism — fixed expired `nextUpdate` values, made OCSP status stable per certificate identity, cached `thisUpdate`/`nextUpdate` windows by certificate/time bucket, and stopped using EC2 PTR-shaped hostnames as random AWS forward DNS/SNI defaults.
- [x] TLS certificate chain depth realism — added data-driven TLS realism config with overlay support for SAN suffixes, OCSP behavior, and chain templates; ssl.log now references leaf/intermediate FUID chains, x509.log emits matching CA/intermediate rows, and per-sensor FUID derivation preserves references.
- [x] TLS realism validate-config coverage — added `tls_realism.yaml` overlay/schema validation to `eforge validate-config` and removed stale hardcoded validation-count docs.
- [x] Scenario hostname authoring guidance — clarified that storyline connection/beacon `hostname` values should be the client-facing DNS name actually used for DNS/SNI/proxy evidence, not reverse-DNS/PTR artifacts.
- [x] Zeek SMB file visibility design — successful SMB data transfers now emit data-driven Zeek files.log observations with SMB source, MIME/analyzer mix, threshold, missing-byte, and timeout behavior from `smb_file_transfers.yaml`. Dedicated Zeek SMB logs remain out of scope; docs and skill references clarify conn.log/files.log/eCAR coverage.
- [x] Blind eval non-clustering follow-up — fixed concrete OCSP joinability, SMB session attribution, and DNS RTT realism findings while leaving cross-source “too perfect” and TLS clustering design deferred. Initial OCSP joinability used conn UID/tuple fields; the follow-up below replaced that with Zeek-native file-analysis linkage.
- [x] Blind eval protocol semantics follow-up — made OCSP Zeek-native via `ocsp.id` → `files.fuid` linkage, prevented public resolvers from answering internal AD/SRV split-horizon names, and fixed NTP client/server mode semantics. Generated smoke output showed 3,340 OCSP rows with 0 missing files.log FUID links, 96 NTP rows with 0 mode-3 records, and 0 internal AD-style DNS queries answered by public resolvers.
- [x] Post-TLS-profile blind review — fresh 50/50 blind review of `/tmp/eforge-blind-tls-review-output/data` rated synthetic likelihood at 90%. TLS clustering was reduced but not eliminated; top score-impacting findings shifted to provider/IP ownership incoherence (e.g., Google/Facebook/AWS names on wrong provider-looking IP ranges), revoked OCSP on successful mainstream browsing certs, templated NTP stratum/ref_id behavior, over-broad DMZ Zeek visibility, and proxy UA/domain mismatches for package/SaaS destinations.
- [x] Post-TLS blind review remediation — fixed provider/IP ownership coherence for curated TLS and site-map hosts, constrained revoked OCSP away from mainstream browsing domains, diversified internal/public NTP stratum/ref_id semantics, tightened multi-segment TAP visibility for internal east-west traffic, and cleaned proxy/TLS destination selection so servers avoid human SaaS pools and OS-specific package traffic uses OS-specific domains. Added focused tests plus `validate-config` coverage for site-map subresource hosts and TLS override tags.
- [x] Post-remediation blind review — generated `/tmp/eforge-blind-post-remediation-output/data` from the current branch and ran a 50/50 blind agent review. Score improved from 90% synthetic to 82% synthetic. Previous high-impact provider/IP/SNI/cert ownership and mainstream revoked-OCSP findings were not repeated for external TLS; remaining top findings are internal/private-IP TLS certificates using public CAs with empty SANs, Zeek files.log schema realism, NTP ref_id semantics, proxy UA/domain coherence for update/certificate endpoints, and a small DHCP visibility leak into the DMZ sensor.
- [x] Internal TLS certificate realism — internal/private-IP TLS sessions now use known internal hostnames, enterprise/private CA issuer, and hostname SANs instead of public CAs on private-IP CNs. Smoke output had 0 private-IP host-certificate CNs and enterprise examples such as `CN=web01.example.com`.
- [x] Zeek files.log schema realism — files.log now emits Zeek-native `tx_hosts`, `rx_hosts`, and `conn_uids` arrays and no longer renders connection-style `uid`/`id.*` fields. Smoke output had 0 schema-mismatch rows.
- [x] NTP ref_id semantics refinement — stratum >1 internal NTP responses now use stable IP-like upstream refids instead of full DNS hostnames. Smoke output had 0 internal NTP rows with hostname/primary-clock-style refs.
- [x] Post-top-three blind review — generated `/tmp/eforge-blind-top3-review-output/data` after internal TLS, Zeek files.log, and NTP ref_id fixes. Blind score regressed to 90% synthetic because the reviewer found deeper x509 identity bugs: duplicate certificate fingerprints with conflicting metadata, provider/CA mismatches for Google PKI and GitHub assets, internal SNI/SAN mismatches, files.log `local_orig` semantics for external response files, and remaining proxy UA/domain coherence issues. Strengths: DMZ visibility coherent, OCSP no mainstream revoked, NTP semantically plausible.
- [x] X509 certificate identity consistency — certificate fingerprints now include certificate-defining metadata for leaf and intermediate certificates, preventing one fingerprint from appearing with conflicting subject/issuer/key fields. Smoke output had 0 duplicate-fingerprint metadata conflicts.
- [x] Provider/CA overrides for PKI and asset hostnames — added CA overrides for `*.pki.goog`, `*.githubassets.com`, and `*.githubusercontent.com` so provider-owned certificate/asset hostnames use coherent issuers. Smoke output had 0 Google PKI/GitHub asset CA mismatches.
- [x] Internal SNI/SAN coherence — explicit internal SNI now controls enterprise certificate subject/SANs for private-IP TLS, rather than being overwritten by the destination system's canonical hostname. Smoke output had 0 internal SNI/SAN mismatches.
- [x] Zeek files.log `local_orig` semantics — OCSP response files now mark `local_orig` according to the transmitting response host, preventing external response files from appearing locally originated. Smoke output had 0 external-transmitter rows with `local_orig=true`.
- [x] Post-x509 blind review — generated `/tmp/eforge-blind-x509-review-output/data` after x509 identity/provider/SNI fixes. Blind score improved from 90% back to 82% synthetic. Previous duplicate-fingerprint/provider/SNI issues were mostly cleared, but the reviewer found the sibling x509 invariant: duplicate `certificate.issuer` + `certificate.serial` pairs with different fingerprints/key metadata. New medium findings: proxy UA/domain coherence, Zeek files.log hash analyzer fields missing, limited DHCP leakage into DMZ sensor, and low-impact NTP uniformity.
- [x] X509 issuer+serial uniqueness — leaf and intermediate serials now include certificate-defining metadata in the deterministic seed, so `certificate.issuer` + `certificate.serial` identifies one certificate profile instead of colliding across different keys/validity windows.
- [x] Zeek files.log hash fields — files.log now emits `md5`, `sha1`, and/or `sha256` when the configured analyzer list includes `MD5`, `SHA1`, or `SHA256`; SMB transfer hashes are deterministic from the transfer identity.
- [x] Proxy UA/domain refinement — `proxy_user_agents.yaml` now has data-driven domain overrides for Windows update, certificate, and telemetry endpoints; CONNECT proxy entries use those overrides instead of generic browser/API UAs.
- [x] DHCP sensor visibility refinement — DHCP lease events are marked link-local and route only to SPAN-style Zeek sensors on the client segment, preventing broadcast DHCP from leaking across unrelated TAP/firewall boundaries. `eforge validate` now warns when a segment has no SPAN Zeek sensor for link-local evidence.
- [x] NTP public server defaults — public NTP fallback choices moved into overlay-capable `network_params.yaml`; scenario-defined internal/domain NTP servers still take precedence, and internal NTP upstream refids draw from the configured public server pool.
- [x] Post-link-local blind review — generated `/tmp/eforge-blind-after-linklocal-output/data` after x509 serial, files hash, proxy UA, DHCP visibility, and NTP config fixes. Blind score improved from 82% to 78% synthetic. Resolved findings: x509 issuer+serial collisions, files hash/analyzer mismatches, DHCP UID linkage, DHCP/link-local leakage, CONNECT raw-IP targets, conn sorting/duplicate flow tells. Remaining high/medium findings are tracked below.
- [x] Proxy UA/domain coherence follow-up — domain-specific proxy User-Agent overrides now run as a final pass even when the proxy context inherited a prebuilt HTTP/browser session UA, so Windows Update, telemetry, CRL, and OCSP proxy rows keep service-specific UAs.
- [x] TLS intermediate CA profile stability — intermediate certificate profiles are cached by subject/issuer and reused across leaf certificates, preserving per-connection FUIDs while keeping serial/fingerprint/key/validity stable for the same CA certificate.
- [x] SMB files.log filename realism — SMB file-transfer rows can now include Zeek-native `filename` values generated from data-driven `smb_file_transfers.yaml` templates with overlay support, schema validation, tests, and docs.
- [x] NTP per-client association stability — NTP version, poll, precision, root delay, and root dispersion are now stable per client/server association while per-event timestamps continue to vary.
- [x] Post-coherence blind review — generated a fresh HTTP/proxy-focused dataset and ran blind 50/50 reviews. Score moved 92% → 86% → 92% synthetic. Completed fixes: reserved fixture domains, proxy cache HIT origin suppression, Let's Encrypt R3 key metadata, proxy W3C `sc-bytes` semantics, HTTPS proxy MISS response-size propagation into proxy→origin TLS/ASA byte accounting, disabled automatic Zeek weird generation pending a future compatibility matrix, removed OCSP files.log records on encrypted SSL UIDs, timestamp-ordered but non-epoch-shaped ASA IDs, ASA teardown timestamps that match rendered durations, Zeek responder packet counts for responder-history markers, failed/rejected Zeek conn service cleanup, and DNS response completion before dependent connection starts. Deferred: proxy resolver mix until a larger sample shows it is still a problem; TLS-intercepting proxy CONNECT+GET behavior is expected under the current project assumption but should be documented in the review fixture if blind reviewers lack scenario context.
- [x] HTTP/proxy blind review critical/high follow-up — fixed denied/inspected HTTPS proxy semantics and local proxy CONNECT timestamp ordering; implemented OCSP option 1 with issuer-aware OCSP responder config plus supporting HTTP/files evidence so `ocsp.id` joins to `files.fuid` and the file row has a visible `conn_uids` link. Broader cross-emitter timing should use a shared event-timing helper/context in a later pass if additional concrete ordering bugs appear.
- [x] HTTP/proxy blind review second critical/high follow-up — denied DNS now renders as source-side query/no-response evidence, proxy tunnel setup status is distinct from inspected request status at the canonical proxy context level, ASA connection ID low-order digits are diversified, and known internal DNS names no longer get random SERVFAILs. Regenerated HTTP/proxy fixture smoke checks showed matching proxy/Zeek CONNECT status counters, no internal `example.com` SERVFAIL rows, varied ASA terminal digits, and intact OCSP files linkage; the denied-DNS case is covered by focused unit tests.
- [x] HTTP/proxy blind review third critical/high follow-up — plain HTTP explicit-proxy client-side Zeek now sees the proxy decision/status/body for denied requests, enterprise-issued certificates use the internal `ocsp.example.com` responder from data-driven TLS realism config, and Zeek UID/FUID derivation skips obvious synthetic marker substrings. Regenerated fixture smoke checks showed the denied proxy row matched a client-side 403/body-size row, enterprise OCSP used the internal responder, and no `FAKE` marker IDs remained.
- [x] HTTP/proxy docs/tests/skills/reference audit — verified coverage for proxy, DNS, ASA, OCSP, and Zeek UID realism changes; added validate-config coverage for OCSP responder hostnames in `dns_registry.yaml`; updated evidence-format docs, config references, skill-local scenario/evidence references, and customization guidance.

**Other:**
- [x] ✓³ Bash history only for root on compromised hosts — baseline SSH sessions now generate per-user bash history for admins on all Linux servers (34 files vs 3); organic noise commands interleaved via generate_bash_command_with_noise()
- [x] Bash history still lacks typos, repeated commands, tab-completion artifacts — bash_commands.yaml with per-role command vocabularies (sysadmin/dba/webadmin/developer/security), template parameterization, 5% typo rate; per-server RBAC user rosters via _get_server_ssh_users()
- [x] Baseline generates IPs outside defined network segments — external IP generator excludes org CIDRs; diagnostic validator warns on out-of-segment internal IPs
- [x] Parsability at ~95% (5% records fail structure validation) — stale audit finding: evaluator parsed 1,056,984/1,057,006 records successfully (99.998% parsability).
- [x] Evaluation schema missing Windows Security EventIDs 4800/4801 — audit evaluator failures were the 22 generated workstation lock/unlock events rejected by `windows_event_security` allowed_values, despite the template task map already including 4800/4801. Added the IDs to the base allowed-values list and covered the regression in format-definition tests.

### Tier 4: Eval Fixes

- [x] Harden temporal causal-account exclusion against non-string SubjectUserName/principal values to prevent evaluator exceptions on malformed logs
- [x] Signal integrity misses web_scan traces in host-scoped web logs and responder-side Zeek HTTP records — generated evidence exists, but evaluator indexing could not find `web_access.log` records by host directory or inbound Zeek HTTP by destination IP. Parser records now carry source-host metadata, and signal-integrity indexing includes responder IPs. Event Presence improved from 1/9 to 9/9 on the HTTP/proxy eval sample.
- [x] Causal Ordering hard failure on generated audit sample — root cause was future same-hour session reuse during non-chronological baseline generation. Session lookup now only reuses sessions whose start time is at or before the activity timestamp. Fresh HTTP/proxy sample eval improved Causal Ordering from 95.53% to 99.94%, and all hard acceptance criteria pass.
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

- [x] `--formats` CLI filter with intersection semantics and group name support
- [x] `format_groups` inventory in `eforge info` output

**Exercises:** 3.1, 3.2, 3.3, 5.1, 5.2 (all need 2-4 week windows)

### Cluster 3: Temporal Baseline Phases — Resolved by Design

Achievable by composing bulk event primitives (beacon, connection, dns_query) over a stable baseline. Students detect injected activity as statistical outliers. No engine changes needed — documented as a scenario authoring pattern.

**Exercises:** 3.2 (gradual behavioral shifts — use beacons with start_time offsets and orig_bytes overrides)

### Cluster 4: Windows Auth Enrichment

Same area of codebase — baseline engine Windows auth generation, persona work schedules.

- [x] Broader baseline 4648 generation (service account delegation, sysadmin RunAs, SCCM/GPO, helpdesk remote)
- [x] Event IDs 4800/4801 (workstation lock/unlock with persona variance, paired 4624 type 7, failed unlock)
- [x] Storyline EventSpecs: explicit_credentials, workstation_lock, workstation_unlock

**Exercises:** 5.1 (4800/4801), 5.2 (4648 breadth)

### Cluster 5: Labeled Data Export

Out of scope — Ex 4.2 MLTK classifier needs real-world labeled domains (threat intel + benign lists), not synthetic EvidenceForge labels. Dataset curation task, not an engine feature.

---

## Notes

- **Testing:** Write tests alongside implementation, not after
- **Documentation:** Update docs incrementally, not all at end
- **Dependencies:** Add via `uv add`, never use `pip` directly
- **Changelog:** When completing a phase, move detailed task history to [CHANGELOG.md](CHANGELOG.md)

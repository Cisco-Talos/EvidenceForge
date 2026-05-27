# EvidenceForge Implementation Plan

**Status:** Phase 8.5 (Dual src/dst HostContext) COMPLETE; Pre-MVP quality fixes ongoing
**Started:** 2026-03-11
**Last Roadmap Review:** 2026-05-26

This file is the durable roadmap and backlog. It is not a session worklog. Use
tracked files under [docs/worklog](docs/worklog) for multi-session effort notes,
loop-by-loop assessment history, handoffs, and branch-local progress details.

See [CHANGELOG.md](CHANGELOG.md) for release history and completed-phase details.

---

## Completed Milestones

**Phase 1: Core Generation.** Pydantic scenario models, StateManager, Windows
Event Security and Zeek conn.log output, hour-by-hour generation engine, and
ground truth documentation.

**Phase 2: Scalability.** Parallel threaded emitters, 7 log formats, persona
temporal distribution, network visibility modeling, and multi-OS support.

**Phase 3: MVP Release.** Skill-based scenario/generate/validate/evaluate
workflow, prebuilt personas, skill installation, and scenario reference docs.

**Phase 4: Data Quality Evaluation.** `eforge eval` with deterministic scoring,
source parsers, and acceptance criteria.

**Phase 5: Data Realism Improvements.** Major generator-level realism fixes for
identity, protocol, process, temporal, and baseline noise patterns.

**Phase 7: Canonical Event Model.** SecurityEvent intermediate representation,
composable contexts, dispatcher routing, and migrated core event families.

**Phase 8.x: Action Bundles and HostContext.** Architecture reset work moved
cross-source lifecycle ownership into action bundles, temporal/source observation
contracts, and dual source/destination HostContext support. Detailed branch and
assessment history belongs in worklogs and changelog entries, not this roadmap.

---

## Pre-MVP Quality Roadmap

Current goal: fix analyst-rejection issues and finish remaining quality work
without turning `TODO.md` back into a high-conflict work journal.

### Active and Near-Term

- [ ] Continue current-dev realism assessment only if another loop is needed;
  use [current-dev assessment worklog](docs/worklog/2026-05-current-dev-assessment-continuation.md)
  for handoff notes, latest loop outcomes, and next target selection.
- [ ] **P1** Reduce syslog memory pressure in long scenarios by allowing barrier
  flushes to write year-partitioned syslog files, while preserving final
  sort/logind normalization at close.
- [ ] **P2** Revisit proxy access log realism and parser compatibility; consider
  switching `proxy_access.log` from W3C Extended format to Apache/Nginx
  combined-style output with absolute URLs and CONNECT targets.
- [ ] **P2** Design richer persona/host story packs, including
  industry-specific bundles, once the first broad workstation-normal expansion
  lands.
- [ ] **P2** Review shared Windows Event XML helper opportunities across
  Security and Sysmon emitters without hiding provider-specific field semantics.

Recently completed: Codex fix-family PR review/rework, full slow-suite
regression cleanup, architecture reset validation, output-target extraction,
source timing planner work, and extensive realism assessment loops. Keep further
per-loop or per-PR details in worklogs or PR descriptions.

### Correctness and Realism Backlog

- [ ] **P1** Route Windows remote-admin command execution through concrete
  execution owners instead of direct `services.exe` parentage; model realistic
  chains such as PsExec service wrapper → `cmd.exe`, WMI provider, PowerShell
  remoting, or temporary service binaries with matching lifecycle evidence.
- [ ] **P1** Reduce high-frequency Linux `systemd-journald` runtime-size filler;
  gate those messages around startup, rotation, vacuum, or explicit journal
  pressure instead of emitting them as dense background texture.
- [ ] **P2** Make Sysmon Event ID 10 LSASS access call traces source-image-aware
  so module stacks are plausible for the accessing process and are not reused
  across incompatible sources such as `csrss.exe`, `services.exe`, and
  `svchost.exe`.
- [ ] **P2** Widen ordinary SMB file-transfer filename, path, and size
  distributions; add organically recurring documents and fewer semantically
  assembled one-off business filenames.
- [ ] **P2** Add friction and timing texture to staged intrusion/exfiltration
  chains, including retries, failed commands, dwell-time slack, partial cleanup,
  tool residue, competing benign traffic, and less perfectly staged large-file
  handoffs.
- [ ] **P3** De-rate uniform Windows maintenance and endpoint startup palettes,
  especially repeated `cleanmgr.exe`, `gpupdate.exe`, and clustered VPN/ZTNA
  tray launches on DC/server roles.
- [ ] **P3** Validate Windows Security Event ID 1102 rendering against real
  exported XML and ensure audit-log-clear subject/account fields appear in the
  correct native structure.
- [ ] Ground truth File IOCs section truncated in `GROUND_TRUTH.md` output.
- [ ] Add RFC 5737 validation warnings for realism-bound scenario fields such as
  `public_cidrs`, NAT `mapped_ip`, storyline `source_ip`/`dst_ip`, and DNS
  `answer_ip`.
- [ ] Replace or data-drive recognizable `45.33.32.x` public IPs remaining in
  built-in scan/attacker pools.
- [ ] Add non-intercepting proxy mode. Current proxy behavior assumes TLS
  interception, so HTTPS proxy logs can include CONNECT plus inspected request
  rows.
- [ ] Align proxy format/auth realism with common enterprise products:
  standard Squid/Blue Coat-style output and authenticated usernames where
  appropriate.
- [ ] Expand ASA message type diversity beyond 106023, 302013-16, and 305011-12.
- [ ] Add SSH protocol negotiation messages.
- [ ] Fix DLL files rendered as `NewProcessName` in Windows 4688 events.
- [ ] Fix 4648 targets that render as localhost instead of the DC for domain
  commands.
- [ ] Render 4728 `MemberName` as the added member DN instead of `-`.
- [ ] Add Windows 4778/4779 RDP reconnect/disconnect evidence.
- [ ] Model integrity levels well enough that Mimikatz at Medium integrity does
  not appear to succeed unrealistically.
- [ ] Add configurable per-host/source log deployment coverage for named host
  groups, disabled sensors, partial deployments, and collection windows.
- [ ] **P2** Profile generation speed and efficiency without instrumentation
  noise, then decide whether to optimize generation or adjust stale performance
  assertions.

---

## Post-MVP Enhancements

### Short-Term

- [ ] Configurable work-week schedules and per-persona day-of-week overrides.
- [ ] Storyline cadence field: `human`, `automated`, or periodic interval with
  jitter.
- [ ] Cloud/SaaS log formats: Azure AD, AWS CloudTrail, GCP audit logs, and M365.
- [ ] `snort_alert` typed event spec for IDS signature declarations.
- [ ] HTTP proxy server support for Squid, Blue Coat, and Zscaler.
- [ ] Checkpointing and resume for long-running generation.
- [ ] Additional skills: create-persona, create-log-format, create-network, and
  analyze-output.
- [ ] Example scenario collection for ransomware, credential stuffing, and
  insider threat.
- [ ] Config file inheritance/templating.
- [ ] Overlay `_replace: true` recursive propagation for nested lists.
- [ ] Overlay `_delete: true` for removing built-in entries.
- [ ] Subset sensor format support, such as `log_formats: [zeek, -zeek_dns]`.
- [ ] PyPI package distribution.
- [ ] Network diagram ingestion for auto-inferred sensor placement.
- [ ] Performance optimizations such as Rust extensions or better parallelism.
- [ ] Full user directory export as separate CSV.
- [ ] Separate student/instructor output packages.

### Medium-Term

- [ ] Web UI for scenario creation.
- [ ] Streaming output to SIEM/data lakes.
- [ ] Log format auto-detection from samples.
- [ ] D3FEND defensive response modeling through scenario defense profiles.
- [ ] ML-informed baseline profiles from sanitized real logs.

### Long-Term

- [ ] OT/ICS environment simulation.
- [ ] Real-time log streaming mode.
- [ ] Collaborative scenario editing.
- [ ] Scenario marketplace.
- [ ] Integration with attack frameworks such as CALDERA and Atomic Red Team.
- [ ] High-performance generation mode for enterprise-scale scenarios.

---

## Field Test Gaps

Gaps identified from FOR668/FOR669 exercise data comparisons. Completed cluster
details should live in changelog or worklogs; only remaining implementation work
is tracked here.

### Configurable Bulk Events and DNS Independence

- [ ] DGA algorithm presets for known malware families.
- [ ] Dictionary-based DGA using word-combination domains.
- [ ] `active_hours` / `active_days` on periodic event types.
- [ ] Connection to non-listening host (`REJ`/`S0` without firewall deny).

### Resolved Clusters

Format filtering is implemented via `--formats` and `format_groups`.
Temporal-baseline phase needs are handled by composing existing bulk primitives.
Windows auth enrichment covered broader 4648 generation, 4800/4801, and
storyline lock/unlock specs. Labeled data export remains out of scope because it
requires real-world labeled domains.

---

## Maintenance Notes

- Read this file at the start of each repo session.
- Do not edit this file for routine "started", "in progress", or "completed"
  task status. Use a tracked worklog for multi-session memory instead.
- Update this file only for durable roadmap/backlog changes, milestone
  completion, priority changes, or release/integration reconciliation.
- When a phase is fully complete, summarize it here and move detailed history to
  [CHANGELOG.md](CHANGELOG.md) or a focused worklog.

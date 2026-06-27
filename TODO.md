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
- [ ] **P1** Feed the latest post-fix Host-review priors into the next
  assessment loop: dataset-wide uniform Sysmon collection/event-family shape,
  tight eCAR wrapper/child timing around DC service/task execution, residual
  service/task parentage edge cases, and regular eCAR `FLOW` actor omission.
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
- [ ] **P2** Add output-target ingest guides covering which generated sources
  are parsed and normalized, parsed-only, unsupported, and how to ingest each
  target-specific dataset.

Recently completed: Codex fix-family PR review/rework, full slow-suite
regression cleanup, architecture reset validation, output-target extraction,
source timing planner work, identity-directory and endpoint host-clock realism,
and Host/EDR reviewer-1 fixes for journald sparsity, polkit role gating, remote
command ownership, Windows maintenance cadence/runtime, and source-aware LSASS
call traces. Keep further per-loop or per-PR details in worklogs or PR
descriptions.

### Correctness and Realism Backlog

- [ ] **P1** Add source-side file-read, archive, browser-upload, or
  proxy-client staging evidence around large outbound HTTP POST/upload flows so
  multi-hundred-MB uploads have plausible endpoint preparation and ownership.
- [ ] **P1** Model Windows inbound/server-side endpoint network telemetry for
  DC/server roles, including Security 5156 and Sysmon Event 3
  `Initiated=false`, or add an explicit collection profile that plausibly
  filters inbound endpoint flow events while preserving hunt semantics.
- [ ] **P1** Separate public IP pools by role so hostile scanner/red-herring
  sources, ordinary public web clients, crawlers, API clients, ordinary service
  responders, public DNS/NTP/CDN destinations, and PTR/provider identities do
  not reuse the same IPs in contradictory ways; keep User-Agent/persona behavior
  stable per external source.
- [ ] **P1** Model Windows Security and Sysmon `EventRecordID` gaps against
  plausible hidden event volume while preserving near-adjacent native pairings
  such as Security `4624`/`4672` and tightly coupled Sysmon process events.
- [ ] **P2** Validate and improve Sysmon `ProcessGuid` morphology against
  native Sysmon output while preserving stable process correlation.
- [ ] **P2** Separate NTP infrastructure/server IP pools from hostile scanner
  pools and make UDP/123 Zeek output consistently include or omit NTP analyzer
  evidence according to modeled sensor configuration.
- [ ] **P1** Improve public PTR, TLS, and provider realism so public reverse DNS
  is sparse/provider-style rather than forward-hostname-derived, and
  SNI/certificate issuer/provider relationships remain plausible.
- [ ] **P2** Widen ordinary SMB file-transfer filename, path, and size
  distributions; add organically recurring documents and fewer semantically
  assembled one-off business filenames.
- [ ] **P2** Add friction and timing texture to staged intrusion/exfiltration
  chains, including retries, failed commands, dwell-time slack, partial cleanup,
  tool residue, competing benign traffic, and less perfectly staged large-file
  handoffs.
- [ ] **P2** Add perimeter TLS imperfection for public-facing services,
  including missing SNI, IP-literal/default scanner SNI, malformed handshakes,
  failed handshakes, and reset outcomes tied to scanner/client families.
- [ ] **P3** Continue de-rating uniform Windows endpoint startup palettes,
  especially repeated `gpupdate.exe` and clustered VPN/ZTNA tray launches on
  DC/server roles.
- [ ] **P2** Add session-aware RDP baseline texture so repeated remote desktop
  activity reconnects, replaces, or reuses sessions instead of stacking many
  concurrent client launches to DC/file-server roles.
- [ ] **P2** Diversify Linux/eCAR temporary file paths by process family, user,
  daemon role, and OS convention instead of reusing generic `/tmp` and
  `/var/tmp` templates across unrelated processes.
- [ ] **P2** Reduce exact-hour proxy and update bursts, keep browser/User-Agent
  families consistent per host/session, vary Linux cron/sysstat schedules by
  host history, and add realistic network collection imperfections such as
  occasional Zeek `missed_bytes`, incomplete TLS/x509 companion evidence, and
  less curated IDS alert clustering.
- [ ] **P3** Polish proxy/web application semantics for SaaS token endpoints,
  MIME/status combinations, scanner request texture, and selective large-file
  extraction imperfection.
- [ ] **P2** Improve DNS TTL texture by binding public and internal TTLs to
  resolver/cache/domain-family behavior instead of broad low-value randomization
  outside explicitly suspicious DNS-tunnel activity.
- [ ] **P2** Bind endpoint software inventory, module-load noise, and registry
  side effects to host role/cohort; avoid repeated writes to static uninstall
  metadata such as `DisplayName`, `Publisher`, and `DisplayVersion`, especially
  on server and domain-controller roles.
- [ ] **P2** Improve eCAR `FLOW` actor semantics so rows with PIDs either carry
  coherent process/principal context or intentionally omit actor identity when
  endpoint attribution is unavailable.
- [ ] **P2** Enforce Zeek file/connection timing contracts so `files.log` rows
  referencing a connection UID land inside that visible connection interval, or
  the connection timing expands to cover the file observation.
- [ ] **P2** Improve Linux eCAR thread semantics so `tid` is populated from a
  plausible thread model or omitted when unavailable instead of copying `pid`
  across every Linux flow/file/process row.
- [ ] **P2** Make SSH eCAR session login/logout tuple fields symmetric when the
  transport tuple is known, including `src_port` on both sides of the same
  `objectID`.
- [ ] **P2** Tighten Linux SSH command/process-to-transport timing so most LAN
  SSH commands reach the TCP/22 connection in sub-second to low-single-digit
  seconds, reserving longer gaps for DNS, retries, or explicit delay.
- [ ] **P1** Bind Linux bash-history command sequences to concrete SSH or local
  session intervals so commands, especially `exit`, do not render after all
  visible sessions for that user/host have closed unless supporting console,
  tmux, screen, sudo, or detached-shell evidence exists.
- [ ] **P2** Reduce direct root/password SSH volume and model routine Linux
  administration through bastions, named admin users, sudo, and service
  automation instead of repeated polished interactive root access.
- [ ] **P2** Align DHCP syslog renewal promises with the next DHCPREQUEST/ACK
  schedule and vary source-native syslog timestamp suffixes within renewal
  triplets.
- [ ] **P2** Add per-host endpoint observation jitter for paired source and
  destination eCAR `FLOW` rows so cross-host endpoint observations do not land
  on the same millisecond by default.
- [ ] **P2** Normalize eCAR service-process principal attribution so the same
  actor/pid does not alternate between missing and populated principal identity
  without an explicit collection profile reason; for proxies, separate local
  daemon ownership from original client/user attribution.
- [ ] **P2** Enforce monotonic bash-history timestamps per file unless modeling
  multiple shell sessions explicitly, and filter incomplete shell constructs
  such as standalone `if` from generic command pools.
- [ ] **P2** Diversify LDAP discovery command texture by tool, filter, user,
  host role, and result/failure pattern so repeated `ldapsearch` reconnaissance
  does not appear as one procedural command pool across many hosts.
- [ ] **P3** Validate SSH `Accepted publickey` syslog formatting against native
  OpenSSH variants and include key type/fingerprint details when configured.
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

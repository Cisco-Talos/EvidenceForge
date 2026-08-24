# EvidenceForge Implementation Plan

**Status:** Phase 8.5 (Dual src/dst HostContext) COMPLETE; post-1.0 quality improvements ongoing
**Started:** 2026-03-11
**Last Roadmap Review:** 2026-08-24

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

**Phase 3: Initial Product Release.** Skill-based scenario/generate/validate/evaluate
workflow, prebuilt personas, skill installation, and scenario reference docs.

**Phase 4: Data Quality Evaluation.** `eforge eval` with deterministic scoring,
source-instance-aware parsers, inferred narrative pivots, acceptance criteria,
and exact correlated-IDS integrity gating.

**Phase 5: Data Realism Improvements.** Major generator-level realism fixes for
identity, protocol, process, temporal, and baseline noise patterns.

**Phase 7: Canonical Event Model.** SecurityEvent intermediate representation,
composable contexts, dispatcher routing, and migrated core event families.

**Phase 8.x: Action Bundles and HostContext.** Architecture reset work moved
cross-source lifecycle ownership into action bundles, temporal/source observation
contracts, and dual source/destination HostContext support. Detailed branch and
assessment history belongs in worklogs and changelog entries, not this roadmap.

**Scenario 2.0 and composable packs.** Added optional industry/organization packs,
immutable per-run effective configuration, exact and provenance-rich composition,
authoritative resolved scenarios, run manifests, sample packs, and pack/resolve CLI
workflows. See the
[scenario composition worklog](docs/worklog/2026-08-14-scenario-pack-composition.md).

---

## Quality Roadmap

Current goal: fix analyst-rejection issues and finish remaining quality work
without turning `TODO.md` back into a high-conflict work journal.

### Active and Near-Term

- [x] **P1** Build dedicated pack-management, industry-pack, and organization-pack authoring
  skills and integrate pack discovery/consumption with the scenario, config, and validation
  workflows. The implementation adds runtime-effective public catalogs, stable JSON validation and
  provenance, safe init/copy lifecycles, and six successful clean-room authoring trials. See the
  [pack-authoring skills worklog](docs/worklog/2026-08-14-pack-authoring-skills.md).
- [x] **P1** Complete realism-remediation Batches 0–2: approve the canonical contracts, add the
  behavior-preserving contract foundation, and implement the session/process/authentication
  vertical slice. See the [approved contracts](docs/design/realism-review/contract-proposals.md),
  [foundation worklog](docs/worklog/2026-08-05-canonical-contract-foundation.md), and
  [session/authentication worklog](docs/worklog/2026-08-05-session-auth-lifecycle.md).
- [x] **P1** Run the isolated four-specialty blind panel against the post-Batch-2 integrated
  output and verify material findings. The six originally targeted contradictions remain cleared,
  but the panel exposed validated sibling lifecycle defects; see the
  [panel summary](docs/design/realism-review/post-batch-2-blind/summary.md).
- [x] **P1** Close the failed post-Batch-2 blind gate before Batch 3: repair host-scoped Linux PID
  allocation, SSH responder process-observation ordering, Windows module startup/compatibility
  timing, and Windows EventRecordID rate modeling, then regenerate and repeat the isolated panel.
  The bounded gate passed after five repair loops; see the
  [final panel summary](docs/design/realism-review/post-gate-loop5-blind/summary.md).
- [x] **P1** Implement Batch 3, the network/protocol/IDS vertical slice: make the network plan
  authoritative for source-visible intervals, protocol/file children, and IDS eligibility, with
  full/filter/parallel projection-equivalence tests. This targets `REAL-005`, `REAL-007`, and
  `REAL-009`. See the [Batch 3 worklog](docs/worklog/2026-08-07-network-protocol-ids.md) and
  [empirical results](docs/design/realism-review/batch3-results.json).
- [x] **P1** Implement Batch 4 world-capability and distribution-state contracts for `REAL-008`
  and `REAL-012`, including the remaining AAAA and OCSP distribution findings. See the
  [Batch 4 worklog](docs/worklog/2026-08-07-world-capability-distribution-state.md) and empirical
  results package.
- [x] **P1** Implement Batch 5 source-native projection and evaluator-validity work for
  `REAL-010` and `REAL-011`, including the evaluator proof gaps recorded by Batch 4. See the
  [Batch 5 worklog](docs/worklog/2026-08-07-projection-evaluation-validity.md) and
  [empirical results](docs/design/realism-review/batch5-results.json).
- [x] **P1** Complete Batch 6 input-safety, workload-budget, authoring, and reproducibility work,
  including the deferred evaluator-memory capacity decision (`REAL-013`, `REAL-014`,
  `SEC-001` through `SEC-010`, and `SEC-DEFER-001`). See the
  [Batch 6 worklog](docs/worklog/2026-08-07-input-safety-budgets.md) and
  [empirical results](docs/design/realism-review/batch6-results.json).
- [x] **P2** Complete behavior-preserving Batch 7a compatibility cleanup: enforce closed dispatch
  admission, remove observed-time state feedback and duplicate sensor NAT maps, delete unreachable
  event aliases, refresh the path census, and reconcile architecture/scenario/evaluation/security
  documentation. See the [Batch 7 worklog](docs/worklog/2026-08-07-compatibility-documentation.md)
  and [results](docs/design/realism-review/batch7-results.json).
- [x] **P2** Implement the approved direct Batch 7b migration: replace the mutable event carrier,
  flat `NetworkContext`, `EdrContext` identity fields, TLS/X.509/OCSP/proxy/file views, singular IDS
  input, and sequence-derived event IDs without internal compatibility layers. Preserve the CLI,
  authored schema, and source formats; version the ground-truth schema. Optimize indexed lookup
  speed while proving duration-stable retained state. See the Batch 7 worklog for the approved
  implementation contract and [Batch 7b results](docs/design/realism-review/batch7b-results.json).
- [x] **P1** Close the post-Batch-7b effectiveness gate before opening the cumulative PR to `dev`:
  repair the controlled SSH source-order regression, inbound Windows 5156 local-process ownership,
  file/application/transport loss accounting, clock-derived Linux PID allocation, and missing SSH
  close ownership. The definitive repeat is byte-identical, the expanded probe is clean, and the
  requested blind panel is complete. See the
  [effectiveness report](docs/design/realism-review/post-batch7b-effectiveness/REPORT.md).
- The complete dependency order and acceptance boundaries remain in the
  [final review report](docs/design/realism-review/final-report.md#dependency-ordered-remediation-roadmap);
  exact evidence, owners, remediation, and tests remain in
  [the machine-readable finding register](docs/design/realism-review/findings.json).
- [ ] Continue current-dev realism assessment only if a separately approved future loop is needed;
  use [current-dev assessment worklog](docs/worklog/2026-05-current-dev-assessment-continuation.md)
  for handoff notes, latest loop outcomes, and next target selection.
- [x] **P1** Complete the V2 family-level realism foundations: scalable indexed state,
  execution/effect reconciliation, append-only lifecycle authority, one timing/clock runtime,
  compiled deployment/content identity, explicit collection policy, and persistent application
  channels. Preserve legacy authored inputs through boundary normalization and prove flat lookup,
  bounded retention and deterministic output, then record a fresh blind-panel measurement. The
  final automated score is 96.8965 and the frozen blind average is 75.75: 6.25 points worse than
  the immediate Loop 30 baseline, but 17.5 better than the later post-P1 checkpoint. See the
  [implementation worklog](docs/worklog/2026-08-16-v2-family-foundations.md) and
  [final assessment](docs/design/realism-review/v2-family-foundations-final/REPORT.md).
- [ ] **P1** Close the final V2 blind-panel endpoint contradictions: canonical Sysmon occurrence
  timing, process-dependent-before-create/after-terminate rejection, complete RDP bootstrap and
  Windows logon identity, and OS-build-aware bootstrap binary hashes. Keep the independent report
  evidence and priorities in the
  [final V2 assessment](docs/design/realism-review/v2-family-foundations-final/REPORT.md).
- [ ] **P2** Improve the final V2 panel's lower-confidence realism findings: explicit proxy DNS
  cache causality, role-appropriate NTP coverage, shell-pipeline process ownership, and more
  user-specific administrator command pacing and vocabulary.
- [ ] **P1** Feed the latest post-fix Host-review priors into the next
  assessment loop: dataset-wide uniform Sysmon collection/event-family shape,
  tight eCAR wrapper/child timing around DC service/task execution, residual
  service/task parentage edge cases, and regular eCAR `FLOW` actor omission.
- [ ] **P2** Revisit proxy access log realism and parser compatibility; consider
  switching `proxy_access.log` from W3C Extended format to Apache/Nginx
  combined-style output with absolute URLs and CONNECT targets.
- [ ] **P2** Review shared Windows Event XML helper opportunities across
  Security and Sysmon emitters without hiding provider-specific field semantics.
- [ ] **P2** Add output-target ingest guides covering which generated sources
  are parsed and normalized, parsed-only, unsupported, and how to ingest each
  target-specific dataset.

Recently completed: Codex fix-family PR review/rework, full slow-suite
regression cleanup, architecture reset validation, output-target extraction,
source timing planner work, identity-directory and endpoint host-clock realism,
long-scenario duration-stable state and syslog spooling, and Host/EDR reviewer-1
fixes for journald sparsity, polkit role gating, remote command ownership,
Windows maintenance cadence/runtime, and source-aware LSASS call traces. Keep
further per-loop or per-PR details in worklogs or PR descriptions.

### Correctness and Realism Backlog

- [ ] **P1** Make process-to-file and process-to-registry effects actor-native by construction:
  stop attaching Defender, WER, CBS, Office MRU, UserAssist, and shell-state artifacts to arbitrary
  live or newly launched processes, and add ProcessGuid/PID causality probes for each family.
- [ ] **P1** Give one-shot Windows foreground tools executable-aware lifetimes so argument-less
  `runas.exe`, `git`, `kubectl`, `wevtutil`, and similar commands do not survive until interactive
  session teardown unless an explicit hung/long-running outcome owns that lifecycle.
- [x] **P1** Add source-side file-read, archive, browser-upload, or
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
- [x] **P2** Add true HTTP multipart transactions with ordered/nested parts,
  per-part size/MIME/filename/FUID metadata, envelope overhead, curl form parsing,
  multiple correlated local file reads, proxy legs, and span-aware loss. See the
  [research/implementation record](docs/worklog/2026-08-12-http-multipart-zeek-research.md).
- [ ] **P2** Add HTTP range identity and reassembly for 206 and
  `multipart/byteranges`, including cross-transaction and cross-connection FUID
  reuse, sparse offsets, instance size, overlap, and missing-range semantics.
- [ ] **P3** Add explicit HTTP chunked/content-coded multipart framing. Model
  chunk layout and Zeek weird behavior separately from semantic parts, and model
  top-level gzip/deflate before enabling these authored combinations.
- [x] **P2** Replace inferred SMB/445 file behavior with canonical Windows SMB2/3
  storage activity: reusable sessions/trees, share mappings and mount paths,
  stateful file operations, native Zeek SMB/file projection, and correlated
  Windows/eCAR evidence. Generic connection events remain transport-only. See the
  [SMB redesign worklog](docs/worklog/2026-08-13-smb-redesign.md).
- [x] **P2** Extend canonical SMB2/3 disk-share activity to explicit Linux clients and Samba
  servers: mounted CIFS and direct `smbclient` modes, POSIX paths, ext4/XFS backing storage,
  mixed-platform mapping presentations, distinct actor/credential/effective identities,
  profile-gated Samba audit evidence, cross-platform Zeek/eCAR projection, and storage manifest
  schema v2. GVFS remains background transport texture rather than typed file activity. See the
  [Linux SMB support worklog](docs/worklog/2026-08-14-linux-smb-support.md).
- [ ] **P3** Add generalized Zeek `kerberos.log` and `ntlm.log` projections across
  applicable authentication protocols, including SMB, with sensor-visibility and
  encryption semantics; do not implement SMB-private authentication emitters.
- [ ] **P3** Evaluate capacity/free-space, quotas, disk-full outcomes, deduplication,
  sparse allocation, and storage compression for the bounded canonical catalog.
- [ ] **P3** Expand SMB failure and lifecycle texture beyond common outcomes,
  including stale mappings and interrupted or partial operations.
- [ ] **P3** Extend SMB authorization with optional dual share/NTFS ACLs, inheritance
  and deny ordering, per-path ACLs, and public SACL/audit-policy authoring.
- [ ] **P3** Add optional actor-native SMB endpoint companions for MRU state,
  antivirus scans, search indexing, and backup-agent activity, gated by host role,
  installed software, and collection profile.
- [ ] **P3** Evaluate higher-fidelity Zeek SMB file analysis against native pcaps,
  including compatible cross-operation FUID reuse, span/offset aggregation, timeout
  finalization, and partial MIME/hash semantics; implement only analyst-visible value.
- [ ] **P3** Optionally materialize SMB file artifacts and richer physical/semantic
  lineage from canonical metadata/version state without requiring artifacts for
  standard datasets; evaluate durable recursive directory mutation separately.
- [ ] **P3** Extend canonical SMB beyond the completed Windows/Linux SMB2/3 disk-share slice as
  scenario demand warrants: SMB1, DFS, IPC$/named-pipe/print, clustering,
  leases/oplocks/durable handles, byte-range locks, multichannel/RDMA/QUIC, KSMBD, SMB POSIX
  extensions, typed GVFS activity, optional Linux Audit/kernel-CIFS diagnostics, and advanced
  dialect/signing/authentication or server-wide encryption controls.
- [ ] **P3** Add FTP control and data-channel protocol support with
  authentication, `RETR`/`STOR`, paths and results, `ftp.log`, and directional
  file analysis.
- [ ] **P3** Add TLS client-certificate/mTLS profiles with client chains,
  `client_cert_chain_fuids`, X.509/file projection, and TLS-version-specific
  visibility semantics.
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
- [ ] **P2** Remove source-native network timing and loss lattices: avoid preserving identical
  microsecond residues through integer-millisecond protocol offsets, model directional capture gaps
  more often than symmetric `Gg`, and render response-triggered IDS alerts with response direction.
- [ ] **P2** Track SOF-ELK HTTPD parser handling of domain-qualified and
  machine-account proxy usernames. The SOF-ELK target currently strips the
  Windows domain prefix from `DOMAIN\user` and the trailing `$` from `machine$`
  auth tokens because SOF-ELK's HTTPD grok rejects those values; if SOF-ELK
  accepts them later, revisit whether the SOF-ELK combined text target should
  preserve the full value like the default target does.
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
- [x] **P2** Enforce Zeek file/connection timing contracts so `files.log` rows
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
- [x] **P2** Profiled long-scenario generation and removed duration-growing
  connection, session, process/thread, expiry, Linux PID, logind, and
  multi-host syslog retention paths. See
  [the long-scenario performance worklog](docs/worklog/2026-07-27-long-scenario-performance.md).

---

## Future Enhancements

### Short-Term

- [ ] Configurable work-week schedules and per-persona day-of-week overrides.
- [ ] Storyline cadence field: `human`, `automated`, or periodic interval with
  jitter.
- [ ] Cloud/SaaS log formats: Azure AD, AWS CloudTrail, GCP audit logs, and M365.
- [x] Correlated multi-SID IDS attachments on typed transport-owning events,
  including connections, beacons, remote sessions, DHCP, scans, and DNS activity,
  with sensor-local Snort-style alert filtering and reporting.
- [ ] Extend correlated IDS attachments to typed `email_message` and `email_read`
  events so asserted SIDs follow the real mail transports produced by modeled
  routing and sensor placement. IDS sensors do not currently decrypt traffic;
  before implementation, decide whether STARTTLS and implicit TLS suppress every
  candidate or permit signatures classified as detectable from flow,
  pre-encryption, or TLS metadata. Plaintext mail is eligible only when a
  storyline or background path explicitly asserts a signature.
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

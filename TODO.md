# EvidenceForge Implementation Plan

**Status:** 2.2.0a6 published; 3.0.0rc1 prepared on dev for the approved Studio and mixed-OS product milestone; published alpha history retained; stable target 3.0.0
**Started:** 2026-03-11
**Last Roadmap Review:** 2026-10-21

This file is the durable roadmap and backlog. It is not a session worklog. Use
tracked files under [docs/worklog](docs/worklog) for multi-session effort notes,
loop-by-loop assessment history, handoffs, and branch-local progress details.

See [CHANGELOG.md](CHANGELOG.md) for release history and completed-phase details.

---

## Completed Milestones

**EvidenceForge Studio core replacement.** Accepted the Tauri/React scenario workspace app
on October 2, 2026; `eforge-desktop` now launches Studio and the Qt UI/dependency is retired.
Queued generations capture immutable resolved inputs. The seven workflow stages remain active;
start with the [current Studio handoff](docs/worklog/2026-10-02-studio-handoff.md), then
consult the [detailed rebuild worklog](docs/worklog/2026-09-30-studio-rebuild.md).

**2.0.1 cleanup and correctness.** Simplified generation ownership and shared infrastructure,
corrected foreground lifecycle, resolver selection, and Kerberos timing, and repaired long-run
SSH checkpoint identity retention. See [CHANGELOG.md](CHANGELOG.md#v201-2026-09-14).

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

**Schema 3 and authored releases.** Shared file services now support independent drafts,
immutable scenario/pack publication, frozen dependencies/configuration, exact lineage, notes,
linked upgrades and portable archives through CLI, native skills and Studio. See the
[artifact lifecycle worklog](docs/worklog/2026-10-07-schema3-artifact-lifecycle.md).
Studio Properties now consolidates draft metadata, notes history and exact validation provenance;
bundle details summarize generated data. See the
[Properties worklog](docs/worklog/2026-10-08-studio-properties.md).

---

## Quality Roadmap

Current goal: fix analyst-rejection issues and finish remaining quality work
without turning `TODO.md` back into a high-conflict work journal.

### Active and Near-Term

- [ ] **P2 — Optional native file and folder browsers throughout Studio:** Review every
  file/path entry point, including startup workspace recovery, Settings, imports,
  exports and executable selection. Offer an appropriate optional file/folder chooser
  on macOS, Linux and Windows while retaining direct path entry. This is deferred UI
  work; do not bundle it into the immediate workspace-opening feedback repair.

- [ ] **P2 — Supported Studio workspace relocation:** Provide a reviewed move/relink
  workflow on all platforms that preserves scenario/pack registrations, projects,
  conversations, validation history, generated runs and evaluations. Account for
  absolute paths, Codex sessions, private metadata and retained checkpoints; preserve
  immutable provenance. Back up state, block active writers and handle destination
  conflicts and interrupted moves. Selecting another workspace currently does not
  migrate these associations. See the
  [Windows laptop follow-up](docs/worklog/2026-11-11-studio-windows-x86_64.md).

- [ ] **P3 — Move a workspace from Settings:** Once supported relocation is available,
  offer an explicit option to move workspace content to a newly selected location,
  with review and clear progress. Keep opening an existing workspace distinct from
  moving the current workspace. Depends on the P2 relocation/history work above.

- [x] **P1 — Windows x86_64 Studio CI preview:** Implemented the unsigned dual-scope
  NSIS installer, standalone payload, private runtimes and native Studio/recovery gates
  through PR #477. Installed verification and native regression/package evidence
  are recorded separately from pending desktop acceptance; publication remains separate. See the
  [Windows preview worklog](docs/worklog/2026-11-11-studio-windows-x86_64.md).

- [x] **P2 — Opt-in Windows clean uninstall:** Implemented three separately selected,
  reviewed cleanup choices for private state/runtimes, known skills/publisher settings,
  and managed authored work/output. Default uninstall preserves data; account-bound
  ownership checks protect unrelated files and other profiles. Maintenance precedes
  scope selection. Native and installed evidence is recorded separately from genuine
  Windows 11/UAC/alternate-account acceptance, which remains below. See the
  [Windows preview worklog](docs/worklog/2026-11-11-studio-windows-x86_64.md).

- [x] **P2 — Studio slow-start and shutdown handling:** Implemented bounded Windows
  startup waits, prompt dead-helper handling, private startup phase timings and
  cooperative idle event-socket shutdown, with native regression coverage. Laptop
  startup timing remains part of desktop acceptance. See the
  [Windows preview worklog](docs/worklog/2026-11-11-studio-windows-x86_64.md).

- [ ] **P1 — Review whether ES ingress sorting scratch is necessary:** Explain why
  `.eforge-es-ingress/<host>/.efsort-*` exists, what it retains, and whether its
  intermediate directories/files or a separate sorting pass can be eliminated.
  Compare alternatives while preserving chronological ES delivery, bounded memory,
  deterministic output and exact checkpoint/recovery. Treat removal of the need
  for this scratch as a separate architectural review from the immediate Windows
  cleanup repair. See the
  [Windows generation follow-up](docs/worklog/2026-11-11-studio-windows-x86_64.md#laptop-reaches-100-percent-windows-scratch-removal-denied-november-13).

- [ ] **P2 — Complete deep Windows workspace path qualification:** The output/
  checkpoint repair covers the observed long-path generation failure. Extend
  policy-independent native coverage to unusually deep authoring, import/export,
  external-tool and SQLite paths; review remaining direct I/O boundaries without
  leaking device-prefixed paths into public metadata or weakening containment.
  See the [filesystem review](docs/worklog/2026-11-11-studio-windows-x86_64.md#laptop-generation-failure-and-filesystem-review).

- [ ] **P1 — Windows 11 x86_64 desktop acceptance:** Test browser-downloaded unsigned
  setup, both scopes, UAC cancellation/alternate administrator credentials, intended-user
  ownership, ordinary-user GUI workflows, and successful packaged authoring with MXC.
  Exercise all three optional uninstall cleanup choices and subsequent fresh setup;
  verify default preservation and cleanup ownership when another administrator elevates.
  Genuine separate-account isolation remains required before claiming that capability.
  Laptop test/fix iterations may use explicit unqualified build-only Windows previews;
  full CI and installer qualification remain required before declaring testing complete.
  Qualify the local `%USERPROFILE%\EvidenceForge` default, separate run destinations,
  retained legacy workspace paths and retryable deletion of read-only checkpoint trees.
  Cloud-synced active workspaces/run folders remain outside the local-NTFS baseline.
  Legacy separate-account Codex authoring is unsupported; runtime ACLs remain private.
  This preview excludes ARM support, signing and automatic runtime pruning. See the
  [Windows preview worklog](docs/worklog/2026-11-11-studio-windows-x86_64.md).
- [ ] **P1 — Evaluate Mac ES JSON key-order variation internally:** Prototype simple,
  reproducible collector-scoped ordering generated and cached from schema keys.
  Measure serialization and end-to-end performance against its raw-log training
  value, then decide whether to adopt it. Avoid a maintained native-permutation
  catalog; preserve values, array/entitlement order, filtering and exact recovery.
  This evaluation is separate from slash escaping; no contributor ordering PR is needed.
  See the [Issue 478 review](docs/worklog/2026-11-12-issue478-macos-es-review.md).

Source-aware ground truth, deterministic agreement scoring and action-specific visibility
validation are implemented on `codex/ground-truth-reconciliation`; source exclusions now retain
exact instances and independent restrictions. Validation and comparison evidence are in the
[ground-truth worklog](docs/worklog/2026-11-10-ground-truth-reconciliation.md#source-aware-evaluation-and-visibility).

- [ ] **P1 — Evaluate full datasets without fixed corpus-size caps:** Replace
  whole-corpus byte/file/record ceilings with streaming evaluation and bounded or
  disk-backed indexes across CLI and Studio. Preserve full scoring coverage and
  per-record input protections; verify score equivalence and memory use on large
  datasets. See the [Studio evaluation diagnosis](docs/worklog/2026-11-10-ground-truth-reconciliation.md#live-studio-evaluation-failure-diagnosis).

- [ ] **P0 — Reconcile full mixed-fleet ground-truth acceptance (release blocker):** The unchanged
  canonical iteration benchmark fails schema-v5 agreement despite strong blind
  source reviews. Qualify remaining native projection requirements, missing or
  duplicate evidence, capability/filter decisions and timing dependencies against
  exact records; repair their owners without lowering the 95% gate or changing
  the workload. Current repairs and residual evidence are in the
  [assessment worklog](docs/worklog/2026-11-11-iteration-test-loops89-98.md).
  The Windows laptop report also exposes shared SMTP boolean comparison, DNS SRV
  projection and HTTP proxy CONNECT-expectation defects reproduced on macOS. Track
  those as general data-quality work, separately from Windows installer/Studio
  acceptance; remaining capability/filter disagreements still need exact-bundle
  diagnosis. See the [laptop report analysis](docs/worklog/2026-11-11-studio-windows-x86_64.md#shared-evidence-disagreements-reproduced-on-macos-november-13).

- [ ] **P2 — Remove the shared Linux PID churn floor:** Ten hosts share a
  940-PID ten-minute mode caused by clipping hidden churn to temporal reorder
  capacity. Model workload and allocation headroom together while preserving
  chronological allocation, out-of-order reservations, uniqueness and exact
  recovery; do not jitter rendered PIDs or cron schedules. See the same
  [assessment worklog](docs/worklog/2026-11-11-iteration-test-loops89-98.md).

- [ ] **P2 — Explicit story-role labels:** Add reviewed typed labels such as
  `EXFILTRATION` and `TOOL_DOWNLOAD` to authored actions and preserve them
  deterministically in ground truth. Keep role authoring separate from factual
  occurrence and observation reconciliation. See the
  [ground-truth worklog](docs/worklog/2026-11-10-ground-truth-reconciliation.md).

- [ ] **P2 — Bound Linux CI package setup and mirror failover:** Avoid spending a
  full job budget on stalled Ubuntu package-index downloads. Use bounded network
  timeouts/retries and verified mirror fallback while retaining native dependencies,
  environment fingerprints and every test gate. A6 recovered through a failed-job
  retry without rebuilding successful installers. See the
  [release handoff](docs/worklog/2026-11-09-release-2.2.0a6.md).

- [x] **P2 — Streamline CI and reuse verified test results:** Integrated eight
  routine shards per OS, four balanced slow shards, verified equivalent-input
  reuse, shared native recovery and overlapping installer builds. Required PR and
  full slow/portability checks pass; release coverage and packaged gates remain
  enforced. See the [CI investigation](docs/worklog/2026-11-09-ci-streamlining.md)
  and [a6 release handoff](docs/worklog/2026-11-09-release-2.2.0a6.md).

- [x] **P1 — Alpha-5 source-launched Studio acceptance:** On November 9 the user
  reported Studio testing is fine after chat-engine alignment, request feedback,
  Environment inspection retention and the IOS XE/XR classification correction.
  Final integration and exact-release-snapshot automated gates remain separate.
  See the [release handoff](docs/worklog/2026-11-07-alpha5-readiness.md).

- [x] **P0 — Restore integrated MacOS-test acceptance:** Revision 482 passes the
  unchanged workload with 200/200 native forks, 256/256 execs, 176/176 known exits,
  all 85 authored Mac starts and zero same-profile browser overlaps. Evaluation
  passes at 95.70 across 251,687 records; combined workstation and positive
  filesystem exact recovery/filter checks pass. Shared launch preflight and
  event-time process/network ownership address the causes. Broader catalog
  audit across platforms, user acceptance and release gates remain separate. See the
  [fresh acceptance worklog](docs/worklog/2026-11-06-macos-final-acceptance.md).

- [x] **P1 — Standard Mac app/tool launch qualification:** All sixteen standard/default
  persona profiles pass native launch preflight. Fifteen installed CLI/runtime images
  have functional tests and repeated startup-signing checks; four desktop mains use
  user-accepted provisional research models. Query admission, bundled Python shell
  ownership and PowerShell's real image/exec environment are repaired. Full helper
  graphs, exact build parity and broader catalog behavior remain separate. See the
  [catalog worklog](docs/worklog/2026-11-07-macos-catalog-qualification.md) and
  [metadata scope](docs/design/macos-workstation-feasibility/catalog-native-metadata.md).

- [ ] **P2 — Audit the entire application catalog on every supported platform:**
  Perform specific installations and execution tests for Windows, Linux and macOS
  catalog apps/tools/runtimes. Review paths, versions, executable/signing metadata,
  launch ownership, argv, helpers, completion and process/network attribution;
  replace research/model assumptions with measured contracts where practical.
  The user accepts provisional researched desktop-app metadata for this release.
  Current Mac qualification evidence and remaining assumptions are tracked in the
  [catalog worklog](docs/worklog/2026-11-07-macos-catalog-qualification.md).

- [x] **P1 — Bounded Mac background/helper expansion:** Shared pre-window root
  cfprefsd/launchservicesd and qualified VS Code main/helpers now use canonical
  ownership and recovery. Browser instance ownership and process/network attribution
  are repaired. Docker Desktop and broader helper populations remain explicitly
  deferred; additional installations are not required for this release. See the
  [research scope](docs/design/macos-workstation-feasibility/background-process-research.md)
  and [follow-through worklog](docs/worklog/2026-11-06-macos-realism-follow-through.md).

- [x] **P1 — Bounded native Mac filesystem integration:** Controlled create,
  modified-close, rename/replacement and unlink references now drive canonical
  file/process identity and native/eCAR rendering, including positive VS Code save
  activity and exact recovery/filter tests. Broader reads, mapping and filesystem
  artifacts remain outside scope. See the same follow-through worklog.

- [ ] **P2 — Recalibrate Mac-inclusive memory forecasts:** Compare forecasts with
  retained measurements of Mac native/process/helper workloads, including peak live
  process-tree RSS and checkpoint hydration. The bounded 26-hour three-host probe
  reaches about 320 MiB, slightly above its 314 MiB upper estimate; the earlier
  six-host MacOS-test run showed a larger miss. Improve per-family budgeting using
  representative measured inputs; do not present forecast ranges as hard capacity
  guarantees. See the [alpha-5 readiness worklog](docs/worklog/2026-11-07-alpha5-readiness.md).

- [ ] **P2 — Retire owned Windows/Sysmon scratch after checkpoint operations:**
  A verified 26-hour mixed-fleet suspend/verify/resume run leaves four owned SQLite
  spool directories (about 7.5 MiB allocated) after successful completion. Preserve
  immutable recovery and source-finalization safety while releasing obsolete runtime
  scratch from suspension and verification; add exact owned-path/identity cleanup
  checks. Keep this distinct from broader spool relocation. Evidence is in the
  [alpha-5 readiness worklog](docs/worklog/2026-11-07-alpha5-readiness.md).

- [x] **P0 — Native Mac mounted-SMB helper coverage:** Mounted-share helpers now use
  the supported native process lifecycle. The fixed Mac-inclusive assessment keeps
  complete fork/exec/exit coverage and matches all eleven mounted-helper exits in
  loop62, with zero aggregate births. Native identity chronology was repaired
  separately in loop64. See the [loop worklog](docs/worklog/2026-11-05-iteration-test-loops44-63.md).
- [x] **P0 — Native Mac identity chronology:** Loop64 assigns public generations from
  one canonical chronological allocation ledger while preserving immutable planning
  reservations and proofs. Fresh data has zero reversals across 219 new allocations,
  1,608 consistent token references and 117 matching native/eCAR exec transitions.
  Exact checkpoint/resume and native-only filter equivalence pass; source dictionary/
  array tokens, schema types and rollback remain covered. This closes the observed
  chronology defect, not broader claims about hidden host churn or native fidelity.
  See the [new loop worklog](docs/worklog/2026-11-06-iteration-test-loops64-68.md).
- [x] **P0 — Mac process-start coverage:** The bounded two-Mac workstation matrix now
  reconciles every in-window canonical fork/exec, rejects unsupported starts, and passes
  combined exact recovery/filter equivalence with positive background activity. The quiet
  primary remains separately reported. See the [contract](docs/design/macos-workstation-feasibility/es-exec-completeness.md),
  [recovery acceptance](scenarios/macos-workstation-recovery/README.md) and
  [worklog](docs/worklog/2026-10-28-macos-es-exec-completeness.md).
- [x] **P0 — Actual MacOS-test start coverage:** The unchanged November 4 workload now
  passes complete ES coverage: 229/229 forks, 291/291 execs, zero aggregate starts,
  all 85 authored Mac starts and all 291 eCAR exec transitions independently matched.
  Root caller/job ownership, literal argv, Homebrew tools and fifteen existing GUI
  main templates are repaired. This is start-coverage acceptance; unknown exits,
  runtime model choices and exact vendor-build limits remain explicit. See the same
  [worklog](docs/worklog/2026-10-28-macos-es-exec-completeness.md).
- [x] **P1 — Mac walkthrough defects:** Revision 381 constrains successful sleep completion
  and requires canonical interactive-shell eligibility for history. Unchanged MacOS-test
  now measures 600.005884 seconds for sleep-600; all thirteen removed history entries
  belong to noninteractive SSH commands that remain in ES. Start coverage remains complete.
  See the same [worklog](docs/worklog/2026-10-28-macos-es-exec-completeness.md).
- [x] **P1 — Actual MacOS-test exit completeness:** The approved ordinary-close model and
  canonical command/accounting repairs now publish all 200 in-window exits, with exact
  eCAR lifetime/final-execution matches and zero unknown results. All 23 existing failed
  PostgreSQL/MySQL attempts have nonzero native results. Start coverage remains 229/229
  forks, 291/291 execs and 85/85 authored starts. See the same worklog.
- [ ] Finish user acceptance of the finite Mac endpoint delivery sequence: supported
  process starts/exits, reference-qualified minimum Unified Log coverage and combined
  recovery/filter verification now pass within the documented scope. No open-ended
  catalog expansion or repeated blind-assessment loop. Scope and
  evidence blockers are fixed in the [delivery plan](docs/design/macos-workstation-feasibility/endpoint-delivery-acceptance.md)
  and the same worklog. New SSH/launchd ULF templates require bounded native references;
  existing ES-only references do not close those gates. Ordinary-verbosity SSH accepted
  authentication is implemented; the user retained that verbosity and left VERBOSE
  session messages gated on November 3. Launchd ULF remains unqualified after a
  final corrected capture with passing controls/cleanup and zero qualifying rows.
  The finite collection sequence has ended; no diagnostic-file source is implicitly added.
  On November 4 the user agreed to keep that family gated and requested a fresh
  `MacOS-test` regeneration/review before accepting the approach. Do not open a PR
  into `dev` until the user is satisfied with that result.

- [x] **P1** Repair Mac ES source chronology through immutable occurrence ingress, exact
  canonical admission and ordered final delivery. Seed-123 warm-up, filtered output and native
  checkpoint/resume now pass; see the [coverage worklog](docs/worklog/2026-10-27-macos-native-coverage.md).

- [x] **P1** Add current-profile Mac command coverage diagnostics, qualified plain nested-shell
  producers and mixed-workload acceptance. Shared passive Zeek histories and bounded Mac query
  timing were repaired after the first panel. This is bounded engineering acceptance, with no
  renewed authenticity claim. See the same coverage worklog and the
  [next GUI launch reference proposal](docs/design/macos-workstation-feasibility/gui-launch-reference-plan.md).

- [ ] **P1 — Baseline-volume feasibility warning:** Replace the storyline-count-only
  warning with an estimate that accounts for environment size, collection duration,
  benign authored activity and evidence expansion. Reconcile the validator's
  500:1 low-intensity target with the evaluator's 200:1 target through one owned
  policy, and distinguish the rough record-to-storyline proxy from actual
  benign-to-attack volume. The Mac-inclusive iteration benchmark warns at 107
  entries despite its preceding output scoring 100 for volume adequacy (1208:1).
  Keep its baseline unchanged while this diagnostic repair is deferred; see the
  [promotion worklog](docs/worklog/2026-11-05-iteration-test-promotion.md).
- [x] **P1 — Canonical HTTP request-target normalization:** Loop47 separates navigation
  URLs from wire targets and Referers before shared HTTP/proxy construction; encoded
  fragments and query strings retain their meaning. Family probes and focused tests
  cover both source views. See the same [loop worklog](docs/worklog/2026-11-05-iteration-test-loops44-63.md).
- [x] **P1 — Native TCP counter projections:** Loop45 separates sequence-derived stream
  extent from captured payload/packet ledgers, including application children sharing
  a transport. Legacy observations preserve unknown extent rather than inventing it.
  HTTP file/body gap reconciliation is recorded separately below.
- [x] **P0 — TCP capture-loss packet/history accounting:** Loop49 enforces physical
  packet minima for observed exclusive history classes through the shared network
  observation owner and SMB rebinding. Fresh family probes retain zero qualified
  contradictions; see the same loop worklog.
- [x] **P1 — HTTP file/body/transport loss semantics:** A frozen physical capture basis
  and channel-owned byte spans now reconcile transport loss, file completeness and
  recognized HTTP body gaps. Loop68 retains zero body/direction/aggregate-budget defects
  across 501 qualified entities. Compression, raw omissions and analyzer-local gaps remain
  separate qualifications. See the [new worklog](docs/worklog/2026-11-06-iteration-test-loops64-68.md).
- [ ] **P1 — Application-bound proxy request identity:** Loop63 finds seven exact-tuple
  browser-family mismatches and 29 Zoom-owned CONNECT flows carrying mixed Edge/Firefox
  identities. Bind actual client/process identity before request header, byte budget and
  proxy affinity freeze; preserve loop57's agreement between finalized source views.
  Known browser/helper defaults now bind before freeze: loop68 has zero family mismatches
  across 802 joined browser flows. Nonbrowser application routing and mobile/default agents
  remain open, including 44 Zoom-owned browser-header flows. Preserve actual client intent
  and explicit header overrides rather than inventing a vendor agent or blanking the field.
  Header overrides/intermediaries remain alternatives, so qualify the intended client model.
  See the [new worklog](docs/worklog/2026-11-06-iteration-test-loops64-68.md).
- [x] **P1 — Site-owned web asset identity:** Default resource size/content identity now
  belongs to its origin/path; explicit shared resources retain shared bytes. Loop68 has
  47 favicon sizes across 47 hosts and eight logo sizes across eight hosts; the modeled
  common font stays shared. Same-site repeats remain stable. See the same new worklog.
- [x] **P1 — Windows logon failure-condition semantics:** A typed canonical condition
  supplies main status, specific substatus and the matching native resource reason.
  Microsoft documentation confirms the previous lockout resource was wrong for the
  generic disabled-account failure. Loop68 has zero mismatches across 20 failures,
  retaining disabled-state normalization. See the same new worklog.
- [x] **P0 — MySQL protocol confirmation prerequisites:** Canonical finalization now
  separates a requested service from supported analyzer confirmation. Fresh full-open,
  no-gap exchanges require the configured payload directions; malformed/client-only
  and banner-only bytes remain intact without an unsupported MySQL label. Loop68 has
  zero violations across 492 qualified sensor observations; midstream/gapped evidence
  remains qualified. See the same new worklog and tagged Zeek 8.0.5 references there.
- [x] **P1 — Native Mac inode allocation chronology:** Installed-file identity now
  follows existing modeled birth chronology instead of lexical path order. Both Mac
  inventories retain stable metadata and zero birth-order inversions; exact native
  recovery/filter checks pass. Dense allocation is still a bounded model, not full APFS
  fidelity. See the same new worklog.
- [ ] **P1 — Interactive workflow pacing:** Replace repeated approximately 96-second
  editor/build launch slots with task/completion/think-time ownership, preserving
  explicitly intended automation. Two independent reviewers identify the same measured
  developer burst in loops66–67. Verify the planner rather than adding emitter jitter.
  See the same new worklog.
- [ ] **P1 — UDP source-state lifetime and duration:** Separate ASA datagram state
  expiration from application completion, qualifying configured idle policy, DNS inspection
  and exceptional removal. Reconcile Zeek duration presence with measured elapsed time
  rather than one-way state labels. Loop67 finds 11 same-second UDP syslog state deletions
  and systematic one-way duration omissions. See the same new worklog.
- [ ] **P1 — Windows session bootstrap ownership:** Verify and repair the session-specific
  SMSS parent across local and RDP bootstrap paths, preserving canonical identities and
  source agreement. Loop65 identifies 24 Winlogon creations on six hosts sharing one
  per-host parent across distinct terminal sessions. See the same new worklog.
- [ ] **P1 — Browser instance lifecycle:** Model persistent browser ownership per host,
  user and resolved user-data directory, with short forwarding invocations for additional
  windows when appropriate. Loop65 finds seven visibly overlapping Mac roots and a Windows
  sibling; retain profile-isolation alternatives and authored process intent. See the same
  new worklog.
- [ ] **P1 — Linux logind allocation chronology:** Replace the elapsed-time-derived
  eight/nine-IDs-per-minute model with actual modeled session allocation ownership,
  including supported background sessions. Loop64 measures near-clock progression on
  three hosts. Preserve rollback, out-of-order planning and recovery; do not conceal the
  pattern with arbitrary gaps. See the same new worklog.
- [ ] **P2 — Bounded source follow-ups:** Qualify snapd task IDs and stateful daemon
  diagnostics; inspect Windows registry actor authority and request/use timing; review
  Mac short-utility outcomes and terminal ancestor-close fences. Keep version, collection,
  blocking and asynchronous-reporting alternatives explicit. Evidence and ranked scope
  remain in the same new worklog rather than a growing roadmap history.
- [ ] **P1** Investigate the repeated Windows process-birth readiness floor through its activity
  and timing owners. The historical panel identifies 14 Windows births in two milliseconds;
  retain startup and collection alternatives. The separate bounded Mac query timing repair
  is recorded in the current coverage worklog above. See the same assessment.
- [ ] **P1** Migrate the Mac branch's remaining continuous timing-RNG call sites to the
  shared timing owner and reconcile moved selectors without weakening the inventory cap.
  The slow static guard has nine pre-existing excess calls; the November 4 exit repair
  adds none. See the [Mac worklog](docs/worklog/2026-10-28-macos-es-exec-completeness.md).
- [ ] **P2** Add native sqlcmd process/network correlation with explicit endpoint ownership.
  Keep the new network action independent of
  later activity selection/ownership; prototype failures and scope are recorded in the
  same Mac worklog. This is separate from the supported workload's exit-completeness gate.
- [ ] **P1/P2** Correct native SMB service-type and NTP reference-ID semantics through the
  protocol facts/projection owners after qualifying the exporter contract. Keep broader
  HTTP owner and remote-auth visibility findings as qualified leads, not assumed defects.
  See the same assessment for primary references, scope and remaining uncertainty.

- [x] **P1** Include verified published Schema 3 industry/organization packs in CLI discovery
  and dependency locking, with exact references, isolated integrity findings and consistent
  duplicate handling. Generation behavior revision 164 covers the composition change. See the
  [pack discovery worklog](docs/worklog/2026-10-13-studio-pack-discovery.md).
- [x] **P1** Improve Studio chat with reliable Stop, Queue/Steer follow-ups, an ordered commentary
  and tool timeline, timers, clarification cards, grouped file summaries, copy controls, saved
  drafts and reading positions, and an expandable conversation layout. Chat file-action shortcuts
  were removed at the user's request. Search and broader status descriptions remain deferred; see the
  [chat experience worklog](docs/worklog/2026-10-13-studio-chat-experience.md).
- Published and verified `2.2.0a4` with the missing-project-pack diagnostic correction.
  All 24 release jobs passed, including native recovery, 74.04% coverage and three installers
  with verified public checksums. The failed, unpublished a3 tag is preserved. See the
  [alpha release worklog](docs/worklog/2026-10-14-release-2.2.0a3.md).
- [x] **P2** Streamline Studio object actions with complete, consistent three dots menus,
  selected text shortcuts, stable disabled actions, shared ordering and confirmed removal
  behavior. The agreed requirements, implementation and validation are recorded in the
  [object action worklog](docs/worklog/2026-10-12-studio-object-actions.md).
- [x] **P1** Reproduce and fix the `apt-healthcare-breach` preview generation failure at
  collection hour 9 (`Deferred session process projection has no unique transport endpoint`).
  Diagnose the owning network/session planner contract and add a focused regression; the run
  stopped before its first checkpoint. See the
  [Studio rebuild worklog](docs/worklog/2026-09-30-studio-rebuild.md).
- [x] **P1** Preserve Windows facts in Snare and validate its native representation. All 43 variants
  have typed projections and field-level gates against both frozen SOF-ELK revisions; historical
  ambiguity remains explicit. See the [validation worklog](docs/worklog/2026-09-15-record-validation.md).
- [ ] **P2** Follow up upstream Snare extraction limitations: ParentImage/CurrentDirectory patterns
  require backslashes after the pipeline replaces them, and POSINT patterns omit zero ports.
  EvidenceForge preserves these raw values; structured indexing needs upstream parser work and
  renewed compatibility gates. No upstream changes are part of this branch.
- [ ] **P1 — deferred** Investigate the existing iteration-scenario temporal-integrity failure
  (40/48 visible events, 83.33%, below the unchanged 85% gate). Separate expected-time matching,
  ordering, missing traces, and source-observation timing before assigning fixes to their owning
  layer. Baseline/candidate evidence bytes match; this predates the validation refactor and is
  deferred from this branch by user decision. See the same worklog for the eight findings.
- [ ] **P2** Investigate generation coverage for Zeek packet-filter/reporter/weird diagnostic
  sources separately from their dedicated renderer/parser/validator fixture coverage.

- Published the `2.2.0a2` prerelease from `dev` with verified Apple Silicon macOS and Linux
  ARM64/x86_64 installers and checksums. All routine, coverage, slow, portability and native gates
  passed; recent manual acceptance was retained by explicit user decision. Target `2.2.0`
  for the next stable `dev` → `main` release. Other-distro and clean-machine acceptance remain
  open. See the [release worklog](docs/worklog/2026-10-12-release-2.2.0a2.md) and
  [release instructions](docs/releases.md).
- [x] **P1 — 2.2.0a2 Linux installer acceptance:** Native Ubuntu 24.04 ARM64 and x86_64
  AppImage builders, packaged verification and Studio recovery CI are implemented; all three
  native installer jobs passed. The user reported the x86_64 setup works on the supplied VM
  on October 12. Updated x86_64/ARM64 previews include the publication workflow fix and pass
  native packaged verification. On October 12 the user accepted recent testing on all systems,
  including the most recent macOS build, waived repeat interactive smoke tests and authorized
  publication. Automated release gates still apply; other distro/clean-machine testing remains
  open. See the [release worklog](docs/worklog/2026-10-12-release-2.2.0a2.md) and
  [publication worklog](docs/worklog/2026-10-12-publication-draft-completion.md). See the
  [Linux release build worklog](docs/worklog/2026-10-11-linux-release-builds.md).
- [x] **P2** Implement native Windows NTFS generation and checkpoint recovery, with passing
  Windows/Linux routine CI and local macOS validation in PR #419. Existing POSIX implementations
  remain in place. See [platform details](docs/design/native-windows-filesystem.md) and the
  [validation worklog](docs/worklog/2026-09-14-windows-ci-checkpoints.md).
- [ ] **P2** Require `Required CI` through dev branch protection. The workflow aggregates Linux,
  Windows, and lint successfully, but dev currently has no protection or effective branch rules.
  Main already requires `Required CI` and `Required Release CI`; preserve those protections.

- [x] **P1** Add source-instance-aware evidence reachability validation so impossible persistent
  SMB output selections fail before generation, invisible authored behavior produces actionable
  warnings, and runtime `--formats` narrowing rechecks the same canonical contracts. See the
  [evidence reachability worklog](docs/worklog/2026-09-09-evidence-reachability-validation.md).

- [x] **P1** Complete the Pack Schema 2.0 release workflow: publisher-qualified identities,
  deterministic lock refresh, immutable `.efpack` closure import/hydration, resilient all-scope
  inventory, updated skills, and small/medium healthcare consumers. See the
  [Pack Schema 2.0 release workflow worklog](docs/worklog/2026-08-26-pack-schema-2-release-workflow.md).

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
- [x] **P1** Complete the V2 family-level realism foundations: scalable indexed state,
  execution/effect reconciliation, append-only lifecycle authority, one timing/clock runtime,
  compiled deployment/content identity, explicit collection policy, and persistent application
  channels. Preserve legacy authored inputs through boundary normalization and prove flat lookup,
  bounded retention and deterministic output, then record a fresh blind-panel measurement. The
  final automated score is 96.8965 and the frozen blind average is 75.75: 6.25 points worse than
  the immediate Loop 30 baseline, but 17.5 better than the later post-P1 checkpoint. See the
  [implementation worklog](docs/worklog/2026-08-16-v2-family-foundations.md) and
  [final assessment](docs/design/realism-review/v2-family-foundations-final/REPORT.md).
- [x] **P2** Switch `proxy_access.log` from W3C Extended format to Apache/Nginx
  combined-style output with absolute URLs and CONNECT targets, with target-specific parser
  compatibility coverage.
- [ ] **P2** Review shared Windows Event XML helper opportunities across
  Security and Sysmon emitters without hiding provider-specific field semantics.
- [x] **P2** Add output-target ingest guides covering which generated sources
  are parsed and normalized, parsed-only, unsupported, and how to ingest each
  target-specific dataset.
- [x] **P1** Add focused machine-readable `eforge schema` selectors, executable minimal examples,
  actionable grouped validation diagnostics, and staged authoring guidance while retaining focused
  references as the semantic authoring guide.
- [x] **P1** Before the final 2.0.0 release, reconcile the roadmap and release documentation:
  retire completed or stale TODO items, align the README proxy-format description with the
  implemented combined-log output, update Ruff's target to Python 3.12, and clear release-tree
  whitespace and working-copy hygiene issues.

Recently completed: Codex fix-family PR review/rework, full slow-suite
regression cleanup, architecture reset validation, output-target extraction,
source timing planner work, identity-directory and endpoint host-clock realism,
long-scenario duration-stable state and syslog spooling, and Host/EDR reviewer-1
fixes for journald sparsity, polkit role gating, remote command ownership,
Windows maintenance cadence/runtime, and source-aware LSASS call traces. Keep
further per-loop or per-PR details in worklogs or PR descriptions.

### Correctness and Realism Backlog

- [ ] **P1 — Canonical shell execution and completion model:** Replace the temporary
  unlisted natural-completion success assumption with canonical shell outcomes.
  Implement bounded parsing with correct quoting/escaping,
  command-list/conditional/pipeline execution, canonical
  process outcomes and shell-result propagation. Use overlay-capable YAML behavior
  overrides over declared default outcomes and varied durations, respecting known
  failures, builtins, persistent processes, source qualification and exact recovery.
  A conservative simple-command fast path may share the tokenizer. Apply the same
  contracts to baseline and authored producers; avoid command-specific completion
  patches for the reproduced missing ES exits. User accepted the direction; detailed
  grammar scope is in the [Issue 478 review](docs/worklog/2026-11-12-issue478-macos-es-review.md).

- [ ] **P2 — Native Mac filesystem stat realism:** Qualify protected-file flags and
  package timestamp provenance, initial directory populations and link-count changes,
  and required volume/device relationships through canonical filesystem providers.
  Split small metadata/state fixes from broader sealed/data-volume modeling. User
  wants bounded contributions; see the [Issue 478 review](docs/worklog/2026-11-12-issue478-macos-es-review.md).
- [ ] **P2 — Define Mac audit-version host-history requirements:** Internal investigation
  confirms that PID allocation includes hidden boot/activity churn while published
  audit versions count only explicit modeled allocations. Discuss the shared-history
  model with the contributor before implementation. Preserve chronological fork/exec
  identity, parent/responsible references, filtering and exact recovery; avoid numerical
  PID/version invariants or emitter offsets. The separately reproduced fork-time
  artifact was repaired in the shared timing path. See the same Issue 478 review.
- [ ] **P2 — Bounded Mac ES open/write coverage:** Define canonical file/descriptor
  producers, mutations, timing and observation scope before adding native open/write
  projections. Opening does not establish a read; notifications do not supply byte
  counts. User wants a scoped contribution; see the same Issue 478 review.
- [ ] **P2 — Mac ES BTM and session-event projections:** Scope independent BTM,
  OpenSSH connection-level login/logout and graphical loginwindow session slices
  over their canonical owners, with version-qualified native references and
  correlation/recovery gates. User wants contributor PRs; see the same Issue 478 review.

- [ ] **P2 — Revamp OS-family modeling and classification:** Evaluate an explicit typed
  OS-family field in the scenario/system schema, retaining OS name/version/build as
  descriptive metadata and an intentional category for network appliances/other systems.
  Resolve platform identity once for validation, generation, deployment, storage,
  evaluation and resource forecasting. Define conflict diagnostics, legacy-input inference
  and migration, and corresponding Studio/skill authoring support; keep version,
  architecture and source-capability admission separate. Field names and schema scope
  remain design work. Keep the current classifier while this is deferred; the motivating
  IOS XE/XR collision is recorded in the
  [classification worklog](docs/worklog/2026-11-09-ios-platform-classification.md).

- [x] **P2** Preserve SSH receiver evidence when filtering an external-source SSH scenario
  from eCAR/Zeek/syslog to eCAR alone. Exact publication now supports an absent Zeek owner;
  direct/deferred, threaded, checkpoint and fresh-process filtering regressions pass.
  See the [Mac implementation worklog](docs/worklog/2026-10-15-macos-workstation-implementation.md).

- [ ] **P2** Design and implement general authored entity availability/participation controls
  across all evidence families. Support entities appearing during a scenario without generating
  earlier activity merely because they are declared in the environment; the motivating case is
  FOR668 `scenario-3_1`'s rogue device appearing before its intended arrival. Apply the mechanism
  through canonical planning and lifecycle owners across warmup, baseline, storyline, causal
  prerequisites, and source/destination selection, rather than DHCP-specific checks or filtering
  rendered rows. Define physical presence separately from collection visibility, and preserve
  realistic evidence from other entities (such as failed attempts to reach an absent host).
  Cover exact activation boundaries, correlated evidence, lifecycle transitions, and checkpoint
  resume; retain existing behavior when controls are omitted. Document supported authoring and
  limitations in the scenario/configuration skills. Final schema and scope remain design work.
- [x] **P2** Bind ambient Linux `systemd-resolved` traffic to each host's selected DNS
  resolvers. The cross-host syslog pass now reuses the correct pool, with address-only evidence
  corrections and compatible checkpoint recovery verified. See the
  [cleanup worklog](docs/worklog/2026-09-12-behavior-preserving-cleanup.md#host-specific-resolver-correction--complete).
- [x] **P1** Make process-to-file and process-to-registry effects actor-native by construction.
  Data-driven executable eligibility and canonical process/session ownership now cover Defender,
  WER, CBS, Office MRU, UserAssist, and shell-state artifacts, with PID/ProcessGuid correlation
  checks. The dedicated Loop 41 assessment and Loop 42 target confirmation found no recurrence; see
  `docs/worklog/2026-08-09-iteration-test-expanded-ids-loops-35-44.md`.
- [x] **P1** Finish executable-aware lifetimes for one-shot Windows foreground tools. Typed
  preflight plans now distinguish bounded, operation-, session-, and persistent ownership;
  argument-less/help/error `runas`, `git`, and `kubectl` close promptly, while transfers and
  continuous modes retain only their real owner.
- [x] **P2** Separate the collection cutoff from the modeled lifecycle horizon. The scenario end
  means "we stopped collecting data," not that systems shut down or every active connection,
  session, process, and application operation ended cleanly. Mirror warm-up behavior at the tail:
  allow lifecycles that start before the exclusive collection end to remain active afterward,
  emit only source-native rows actually observed before the cutoff, and do not synthesize an
  in-window close, logoff, teardown, or completion merely to drain runtime state. Decouple the
  output window from network leases, application/channel registry bounds, lifecycle journals, and
  terminal zero-owner assertions; finalize an explicit active-at-cutoff snapshot and then release
  its runtime ownership safely. Decide during design whether ground truth records only
  `active_at_collection_end` or also retains the exact modeled future close. This must not be used
  to conceal pathological durations such as runaway SMB file-size growth, which remains a
  separate root-cause fix. Implemented by retaining exact modeled future deadlines internally and
  admitting only source-native observations before the exclusive collection cutoff; see
  `docs/worklog/2026-09-08-collection-lifecycle-boundary.md`.
- [x] **P1** Honor authored cross-event `process_ref` / `parent_ref` lifecycles. Keep a referenced
  parent alive through dependent child creation, prevent independent storyline jitter from
  inverting same-time parent/child events, and preserve a live authored source for subsequent
  process-access effects instead of silently recording `no_live_source_process`. Implemented with
  release-aware named-process retention, exact-parent admission, and authored group ordering; see
  `docs/worklog/2026-09-09-storyline-parent-snort-route-identity.md`.
- [x] **P1** Canonicalize sensor identity before assigning Snort and sibling sensor output routes.
  TEST1 had one authored `IDS-NG-EDGE` sensor whose raw and canonical hostname aliases resolved to
  the same physical path on case-insensitive filesystems. Emitter setup now consumes the canonical
  source hostname while exact-publication collision checks remain strict for distinct sensors; see
  `docs/worklog/2026-09-09-storyline-parent-snort-route-identity.md`.
- [x] **P1** Add source-side file-read, archive, browser-upload, or
  proxy-client staging evidence around large outbound HTTP POST/upload flows so
  multi-hundred-MB uploads have plausible endpoint preparation and ownership.
- [x] **P1** Finish Windows inbound/server-side endpoint network telemetry for DC/server roles.
  Canonical initiator/responder observation plans now render responder-owned Security 5156 and
  deployed Sysmon Event 3 with `Initiated=false`, exact tuple/process identity, and coherent
  denial/deployment/observation-policy behavior.
- [x] **P1** Finish public-IP role partitioning. The canonical public identity registry now owns
  deterministic role/provider bindings for scanners, authentication, C2, humans, crawlers, API
  clients, ordinary responders, CDN, DNS, NTP, and mail, including DNS/PTR/TLS/client traits and
  explicit sharing diagnostics.
- [x] **P1** Model Windows Security and Sysmon `EventRecordID` gaps against
  plausible hidden event volume while preserving near-adjacent native pairings
  such as Security `4624`/`4672` and tightly coupled Sysmon process events.
- [x] **P2** Validate and improve Sysmon `ProcessGuid` morphology against
  native Sysmon output while preserving stable process correlation.
- [ ] **P2** Make UDP/123 Zeek output consistently include or omit NTP analyzer evidence according
  to modeled sensor configuration. NTP infrastructure/server identities are now separated from
  hostile scanners by the canonical public identity registry.
- [x] **P1** Improve public PTR, TLS, and provider realism. Public PTR responses are now
  deterministically sparse and provider-style rather than forward-hostname echoes; domain-aware CA
  overrides keep SNI/certificate issuer relationships plausible, and raw-IP TLS avoids invented
  SNI and public-CA DNS identities. Covered by public-DNS, TLS, certificate, and raw-IP regressions.
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
- [ ] **P2** Add typed RAR archive creation with explicit source-file membership, archive content
  identity, source-to-archive lineage, and process-owned endpoint evidence so later SMB/HTTP/FTP
  transfers preserve the exact staged archive rather than inferring it from a command line.
- [ ] **P3** Extend canonical SMB beyond the completed Windows/Linux SMB2/3 disk-share slice as
  scenario demand warrants: SMB1, DFS, IPC$/named-pipe/print, clustering,
  leases/oplocks/durable handles, byte-range locks, multichannel/RDMA/QUIC, KSMBD, SMB POSIX
  extensions, typed GVFS activity, optional Linux Audit/kernel-CIFS diagnostics, and advanced
  dialect/signing/authentication or server-wide encryption controls.
- [ ] **P3** Add typed FTP upload/retrieval with authentication, `RETR`/`STOR`, exact local and
  remote paths/results, archive/content identity propagation, correlated control and negotiated
  data channels, `ftp.log`, and file analysis whose byte direction follows the actual transfer.
- [ ] **P3** Add TLS client-certificate/mTLS profiles with client chains,
  `client_cert_chain_fuids`, X.509/file projection, and TLS-version-specific
  visibility semantics.
- [ ] **P3** Remove the 2.x public-identity compatibility adapters and legacy overlay filenames in
  EvidenceForge 3.0 after migration telemetry and documentation have had a full major-version
  window.
- [ ] **P3** Evaluate a typed Scenario schema field for scenario-local public identity bindings in
  a future schema revision; 2.0 intentionally keeps this project-wide registry overlay-only.
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
- [x] **P1** Bind Linux bash-history command sequences to concrete SSH or local session intervals.
  Commands are fitted to visible session windows or suppressed when no owner exists, including
  serialized commands after session close; the Loop 238 hard probe checked 202 commands with zero
  outside syslog/eCAR session intervals. See
  `docs/worklog/2026-05-current-dev-assessment-continuation.md`.
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
- [x] Render 4728 `MemberName` as the added member DN instead of `-`.
- [x] Add Windows 4778/4779 RDP reconnect/disconnect evidence.
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
- [x] Storyline cadence field: `human`, `automated`, or periodic interval with
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
- [x] **Checkpointing and resume for long-running generation.** Cadence-only incremental
  checkpoints now preserve bounded live state and immutable deltas, atomically retain two
  recoveries, resume portably, and reproduce byte-identical deterministic bundle content. The
  selected default is 24 simulated hours. See
  [the incremental checkpoint worklog](docs/worklog/2026-09-02-incremental-generation-checkpoints.md).
- [x] **Behavior-aware, attemptable checkpoint resume and exact-behavior recovery.** Runtime and
  environment drift now attempts full hydration, while immutable run identity, OOB authorization,
  integrity, and unsupported state contracts remain hard boundaries. Declared behavior history
  distinguishes localized, material, and unknown output risk; successful non-exact restoration
  migrates at the same cursor with complete provenance. Lifecycle restoration distinguishes
  aged-out parents from cycles and restores large retained graphs in near-linear time. See the
  [compatible-resume worklog](docs/worklog/2026-09-06-compatible-checkpoint-resume.md).
- [ ] Consolidate checkpoint-capable emitter spools into the protected
  `.eforge-generation/` workspace. Active spools intentionally remain in their established
  runtime locations for the initial checkpoint release; revisit placement only after production
  experience confirms the incremental adapters are stable.
- [ ] Additional skills: create-persona, create-log-format, create-network, and
  analyze-output.
- [ ] Example scenario collection for ransomware, credential stuffing, and
  insider threat.
- [ ] Design easier delivery and discovery of example scenarios, including Studio.
  Contributed exercises belong under the existing `scenarios/` directory for now;
  repository examples are not a bundled installer library. See the
  [Issue 478 review](docs/worklog/2026-11-12-issue478-macos-es-review.md).
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

- [x] Implement and assess the bounded macOS 26 arm64 **modeled workstation** scope,
  including mixed-fleet benchmarks, reviewer updates, modeled SSH fork/v10, catalog and
  owner-level repairs, filtering and exact recovery. Experimental engineering acceptance
  is not full native fidelity or an authenticity pass. See the
  [acceptance record](scenarios/macos-assessment/ACCEPTANCE.md) and
  [assessment worklog](docs/worklog/2026-10-21-macos-assessment.md).
- The active generation target has moved to **macOS 27 arm64** through a selectable
  profile catalog; all unqualified Mac targets fail validation independently of selected sources.
  Human-reviewed private shape evidence admits bounded v11 fork/exec/known-exit projection.
  The fixed local/Terminal/iTerm2/Finder/Chrome/SSH/selected-system-job workload now passes
  complete independent process-start census, filtering and exact recovery. Unknown terminal
  outcomes, unqualified app/launch families and launchd ULF remain explicit limits. See the
  [current delivery results](scenarios/macos-workstation-acceptance/REPORT.md) and
  [profile worklog](docs/worklog/2026-10-24-macos27-native-process-profile.md).
- [x] Implement bounded macOS 27 native app-policy refusal through explicit
  `process.outcome: policy_refused`, with canonical target PID, boot-owned kernel writer and
  distinct sender facts. Existing pre-child/returning-exec semantics remain intact. Exact
  cause and fork/exec stage remain unqualified; no repeat capture is required. See the
  [acceptance and limits](docs/worklog/2026-10-26-macos-gatekeeper-reference.md).
  Filesystem artifacts, binary containers, Intel/Rosetta, sleep/wake, roaming and
  Mac SMB serving remain outside the bounded scope. See the
  [capability matrix](docs/design/macos-workstation-feasibility/capability-matrix.md).

- [ ] Validate Studio account isolation with genuinely separate OS accounts on macOS when a
  suitable test host is available. User explicitly deferred account creation on
  October 6. UID/SID simulations and same-account native helper/locking tests are implemented;
  they do not substitute for this cross-account acceptance. Linux and Windows GUI testing is
  deferred until future platform exploration. See the
  [isolation worklog](docs/worklog/2026-10-06-studio-user-isolation.md).

- [x] **P1 — public Studio release gate:** Version Studio-owned SQL/JSON settings and filesystem
  layouts; require verified backups, interrupted-upgrade recovery, pre-use restoration and
  native crash/fault gates on macOS, the only currently supported GUI platform. Linux and Windows
  GUI support and native acceptance are deferred by the October 6 user decision. Engine-owned
  formats and engine/CLI platform support stay outside this scope change.
  Implementation and macOS evidence are tracked in the
  [upgrade worklog](docs/worklog/2026-10-05-studio-state-upgrades.md); see
  [contracts and test traceability](docs/studio-state-upgrades.md). Require the macOS native GUI
  gates and existing engine/CLI and release checks before closing this release gate. These
  checks passed for `v2.2.0a1`; see the
  [release installer worklog](docs/worklog/2026-10-09-release-installers.md).

- [ ] Automate clean-room scenario-agent acceptance after the 2.0 release, measuring first-draft
  structural validity, passes to zero errors, required-reference loading, warning churn, and
  repair regressions across representative scenario families. Use manual scenario-authoring
  acceptance for the 2.0 release candidates and final release.
- [ ] Complete the seven Studio workflow stages after accepted core parity. Find/resume has
  project-aware lists, saved views, contextual search, and a command menu. Environment inspection
  and exact pack choices are available; optional portable project/scenario overlay contexts are
  implemented. Pack creation/editing/import/export and reviewed exact-version deletion are part
  of Stage 2; see the [pack lifecycle review](docs/worklog/2026-10-06-studio-pack-lifecycle.md).
  Broader guided editing, complete effective-value origins, isolated scenario **and pack** authoring
  revisions, deeper preflight, resource-aware scheduling, evaluation comparisons, and delivery presets remain. Review each stage with the user before advancing. See the
  [Studio rebuild worklog](docs/worklog/2026-09-30-studio-rebuild.md).
  All CLI/skill changes must preserve traditional command-line and native-harness workflows.
  New configuration scopes must be optional, file-based, independently usable without Studio,
  and preserve existing root selection and family-specific merge contracts.
- [ ] Package standalone Studio with a private Python runtime, CLI/service, resources and skills.
  Initial field test targets Apple Silicon macOS 26; Developer ID signing/notarization are
  deferred by user decision. Universal macOS delivery is blocked by the locked cryptography
  dependency's missing Intel wheel. macOS is the only supported GUI platform for now; explore
  Linux and Windows later, with packaging and native acceptance planned separately before support.
  Codex remains separately installed. Require native macOS builds and clean-machine acceptance.
  See the [standalone worklog](docs/worklog/2026-10-03-studio-standalone-macos.md) and
  [Studio guide](docs/studio.md); the
  [Studio handoff](docs/worklog/2026-10-02-studio-handoff.md) retains workflow-stage decisions.
  Automatic runtime retention, configurable rollback days, and visible uncertain-removal warnings
  are implemented; see the [runtime cleanup worklog](docs/worklog/2026-10-06-studio-runtime-cleanup.md).
- [x] Add Studio scenario YAML import with dependency review, nested includes and supporting
  assets, optional advisory validation, and persistent missing-pack findings. Add pack-panel
  import/export with exact versions, selectable reviewed packs, and locked dependency closure;
  source workspaces supply copies into the destination workspace. See the same Studio worklog for the import design decisions.
- [ ] Extend Studio's new read-only import of complete CLI and earlier desktop bundles to
  incomplete external bundles with recognized checkpoints. The Bundles page now indexes complete
  external bundles by folder or workspace discovery, while Studio-owned incomplete jobs already
  appear there. Keep external files outside Studio's delete controls.
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

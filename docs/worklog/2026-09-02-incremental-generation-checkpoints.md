# Incremental Generation Checkpoints

## Objective

Implement cadence-only crash-safe generation checkpoints whose foreground work depends on changes
since the previous checkpoint plus bounded live state, not all historical generator state. Resume
must remain portable and byte-identical, and the selected default cadence must add no more than 5%
median wall time on every representative workload, including a 60-day scenario.

## Branch history

- This implementation starts from clean `dev` commit `a530d9d91` on
  `codex/generation-checkpoints`.
- The rejected full-snapshot experiment is preserved remotely on
  `origin/codex/generation-checkpoints-full-snapshot` at `c21eeeda5`.
- That experiment established the CLI/safety requirements and proved byte-identical recovery, but
  its full-history capture grew from 4.80 foreground seconds after simulated hour one to 13.69
  seconds after hour three. Its projected 60-day cost was unacceptable.

## Locked decisions

- Checkpoints occur only at positive cadence multiples across the continuous warm-up and
  collection hour count. There are no forced initialization, phase-boundary, tail, or
  pre-finalization checkpoints.
- `--checkpoint-hours 0` disables checkpoint creation. A run interrupted before its first cadence
  point has no resumable recovery point.
- Active emitter spools stay in their current locations. Checkpoints import only new immutable
  runs, append chunks, or logical SQLite rows and restore protected spools freshly.
- Recovery points share content-addressed immutable segments. A checkpoint captures bounded live
  heads and seals only the delta since its predecessor; it never reprocesses older segments.
- The stdlib packed representation is the baseline. A third-party codec or store is retained only
  if it reduces checkpoint-path work by at least 20% and worst-workload total overhead by at least
  three percentage points without regressing another representative workload.
- No project version bump occurs on this feature branch.

## Acceptance record

Record implementation commits, schema decisions, fault results, byte-identity comparisons,
checkpoint-time growth at simulated hours 6/24/168/720/1440, codec/store trials, resource forecast
calibration, and the final three-pair performance matrix here. Do not reconcile the durable TODO
until every correctness and performance gate passes.

## Implementation record

- The initial store publishes canonical bounded heads and content-addressed immutable segments,
  retains two manifests, garbage-collects only unreferenced objects, validates recovery hashes,
  and falls back from a corrupt newest generation. Inherited segments are carried by reference
  and are not reopened or rehashed during a later commit.
- The cadence coordinator transactionally prepares explicit participants and advances their delta
  watermarks only after the manifest is durable. Failed publication aborts every prepared owner.
  No general object-graph encoder or fallback exists.
- Append-only spool adapters use logical names, committed lengths, fixed maximum chunk sizes, and
  chained SHA-256 records. A later checkpoint reads strictly from the prior committed length;
  focused coverage observed nine bytes on the initial seal and only five newly appended bytes on
  the next seal. Recovery validates the complete chain and recreates fresh files without storing
  runtime paths.
- Immutable external-sort run adapters import each logical run once. Later checkpoints skip every
  imported run without reopening it; recovery validates the content index and recreates the runs
  at fresh owner-selected locations.
- SQLite spool adapters install explicit dirty-row triggers on an owner-declared table set. The
  first recovery segment contains canonical schema plus current logical rows; subsequent segments
  contain only the final value or deletion for rowids changed since the preceding durable point.
  Focused coverage updates, deletes, and inserts between checkpoints, observes four dirty rows,
  emits no segment when the next point is unchanged, and rebuilds an equivalent fresh database
  with its indexes. Hydration also accepts a freshly initialized emitter database with the exact
  schema, clears its bootstrap rows, and applies checkpoint rows before installing new dirty-row
  triggers. SQLite database files and prior logical segments are never copied again.
- Segment references now carry authenticated per-owner ordinals. Publication preserves append
  order and hydration sorts by that ordinal, so content hashes cannot accidentally reorder file
  chunks or logical database deltas. The authoritative recovery index also authenticates each
  manifest; a semantically valid but modified newest manifest falls back to the previous point,
  while a corrupt pointer is rejected rather than guessed around.
- The generation engine now exposes an internal cadence hook after the complete hourly sweep and
  lifecycle/channel watermark advancement. It counts warm-up and collection continuously, runs
  only at exact positive multiples, takes an emitter barrier only when due, and reports the
  post-boundary cursor (`warmup`, `collection`, or `tail`). It does not add initialization,
  phase-only, or pre-finalization recovery points; the public CLI remains intentionally unwired
  until all required owners can hydrate safely.
- The active generation RNG has a portable, explicit MT19937 schema: 624 unsigned state words,
  the bounded index, algorithm/version tags, and optional Gaussian cache. An exact-stream test
  advances the generator, restores the numeric head, and reproduces the next twenty 64-bit values.
- Warm-up boundary ordering is explicit. When cadence lands exactly at collection start, the
  warm-up-only texture state is reset and sensor startup evidence is emitted before the single
  post-transition collection cursor is offered to the checkpoint controller.
- StateManager, the outer lifecycle registry, and every lifecycle partition now have exhaustive
  field inventories covering bounded live authority, derived/rebuilt indexes and infrastructure,
  and transient owners that must be empty at a checkpoint barrier. Structural tests compare the
  inventories with the runtime objects so adding an unclassified field fails the checkpoint test
  gate. The barrier validator also rejects an in-flight prepared mutation instead of capturing an
  unsafe capability graph.

## Validation record

- After adding the cadence hook, the first default-suite run found two minimal BaselineMixin test
  harnesses that intentionally do not construct a complete GenerationEngine. The hook call site
  now remains optional for those harnesses; both regressions pass.
- The clean repeat completed with 8,030 passed, 5 skipped, and 2,009 deselected in 174.43 seconds.
- The focused incremental checkpoint module currently has 29 passing tests, including exhaustive
  core-owner inventories and transient barrier rejection.
- The first lifecycle bounded-head slice uses hard-coded field codecs and stable partition/handle
  iteration rather than a reflective graph encoder. It round-trips active and closed process and
  session authority, including dependents, holds, barriers, tickets, and ledger aggregates, while
  retaining the registry object identity and rebuilding routes, locks, and indexes. The second
  unreleased head schema retains bounded aggregate counts/digests and durable commit identities,
  so hydration no longer needs discarded transition/hold detail and correctly reconstructs a
  compacted entity. The third unreleased head schema also restores active and tombstoned
  service/process and cross-host transport/session bindings, including exact transport binding
  counts. The fourth schema restores retention, foreground, and singleton leases through their
  validated APIs, rebuilds deadline/resource/temporal indexes, and preserves renewed or bound
  deterministic commit keys. The focused change and 103 broader lifecycle/lease tests are green;
  the lifecycle registry no longer has an unsupported mutable family. The public generator
  remains unwired pending the other mutable owners.
- The first StateManager head uses an explicit allowlist for runtime dataclasses and safe primitive
  containers; it has no arbitrary dataclass, object-dictionary, import, or graph fallback. Live
  sessions, processes, threads, connections, retained identity indexes, PID/logind allocation
  windows, DNS state, and bounded allocators are captured as a rebuilt live head. Four
  history-growing identity/ordinal ledgers use an opt-in mutation recorder that is dormant when
  checkpointing is disabled and emits only last-write-wins changes since the prior durable point.
  A two-generation test proves allocator-only changes leave the head byte-identical and produce a
  two-record second delta; hydration applies both generations and resumes the next ordinal. An
  hourly-barrier probe of both the minimal fixture and the dedicated two-hour SMB calibration
  fixture observed zero active/terminal pin capabilities, install receipts, acknowledgements,
  session owners, reserved bytes, and retained bytes at every warm-up, collection, and tail
  boundary. Those capability families are therefore classified as transient-empty and fail the
  barrier if they ever leak, instead of persisting stale secrets. The focused module has 31
  passing tests and 214 broader StateManager/lifecycle/transport-lease tests pass.
- The source-timing planner now has its own exhaustive inventory and bounded live-head
  participant. All 17 cross-event cache families export only visible semantic key/value/deadline
  rows; compact handles, expiry tombstones, cache metrics, source-clock memoization, audit
  counters, locks, secrets, and preparation infrastructure are rebuilt. Every capability,
  detached binding, claim, and retained receipt must be absent at the barrier. The complete
  family-shape round trip is green, a real hour-one generation barrier produced an 895-byte head
  with no immutable delta, and 158 checkpoint/source-timing regression tests pass.
- The protocol-neutral application-channel registry now exports one normalized bounded head for
  open channels, retained closed tombstones, active operations, and completed-operation IDs.
  Hydration recreates fresh packed stores, expiry ownership, channel/transport/operation routes,
  and counters from stable semantic IDs rather than retaining compact handles. Prepared
  admissions, close projections, recovery journals, weak receipts/proofs, and mutation claims are
  required to be empty. Focused open/closed/active/used-ID replay and all 146 checkpoint and
  application-channel regression tests pass; the minimal hour-one barrier head is 212 bytes.
- The first generation-engine progress head now captures the core history-sensitive scheduling
  maps, executed authored-event sets, ground-truth accumulators, Hawkes continuity, audit/task
  counters, and DHCP leases without serializing the engine object graph. DHCP rows replace their
  runtime `System` reference with a hostname identity and preserve the renewal generator through
  the numeric RNG schema; hydration binds each row to the freshly compiled scenario object. A
  focused round trip is green, and a real minimal hour-one barrier produced a 7,473-byte head
  with no immutable segments. Scenario-dependent Linux, protocol, and activity caches remain to
  be classified before the engine participant can be wired into production cadence checkpoints.
- The authored-intent execution ledger now has an exhaustive owner inventory and a bounded
  semantic head for lifetime count/digest aggregates, deterministic identity samples, 30-day
  reporting buckets, the seven-day/capacity-limited exact identity cache, and its watermark.
  Hydration rebuilds the eviction heap and all locks, secrets, and batch infrastructure; any
  prepared reservation, retained receipt, or mutation claim fails the checkpoint barrier. The
  64-test ledger/checkpoint regression group passes, and a real minimal hour-one barrier produced
  a 236-byte head with no immutable segments.
- The reconnectable RDP manager now exports only retained logical-session snapshots, active
  operation identities, active retention leases, scalar high-water diagnostics, and its canonical
  watermark. Hydration runs after application-channel hydration and rebuilds packed handles,
  logical/affinity routes, expiry and blocker indexes, close tokens, counters, caches, locks, and
  capability authority. Prepared admissions and mutation claims must be empty. A populated
  session/operation/lease round trip continues through finalization and lease release, 62 focused
  RDP/checkpoint regressions pass, and a real minimal barrier produced a 260-byte empty head.
- The shared timing runtime now has explicit inventories for its runtime, audit, bounded
  relationship counters, and source-clock registry. Exact audit slots (including collision
  labels), distribution counts, totals, and mutation version persist in one bounded head. The
  stateless source-clock values remain reproducible from semantic keys, so hydration clears the
  LRU and rebuilds cache diagnostics, locks, samplers, and ownership lanes; a retained owner claim
  fails the barrier. The 105-test core timing/checkpoint group passes, and a real minimal
  hour-one barrier produced a 7,928-byte head with no immutable segments.
- `ExpiringIndex` now exports stable live semantic rows and hydrates them into a fresh index while
  rebuilding expiry/protection authority. Stale heap nodes, obsolete versions, and compaction
  diagnostics are intentionally excluded, so activity and protocol owners can checkpoint bounded
  expiry-backed state without turning internal maintenance history into durable history. Hydration
  rejects duplicate/out-of-order rows and non-orderable NaN deadlines. The generation-index and
  incremental-checkpoint group has 95 passing tests.
- The canonical network runtime now has an exhaustive owner inventory and one bounded semantic
  head for live/tombstoned planner points, committed transport leases, transport freshness,
  allocators, and its watermark. Hydration reconstructs the point, lease, and freshness deadline
  heaps; tuple/endpoint reverse routes; counters; and constant-time state digests. Open or prepared
  transactions, point batches, claims, reservations, pending leases, and partial watermark pages
  fail the barrier. A populated round trip continues watermark pruning after restore, and semantic
  row tampering is rejected by the participant digest. The 101-test checkpoint/network-runtime/
  transport-lease group passes. Cryptographic material remains a separate unresolved participant.
- Cryptographic material is now a separate incremental participant. The mutation tail records
  only newly published point identities/generations and DKIM cache identities; checkpoint segments
  do not copy DER public keys, authority material, certificates, or wrapper payloads. Recovery
  validates each inert identity, deterministically rebuilds its value using the exact production
  builders, reconstructs capacity accounting and order-independent digests, and then attaches a
  fresh recorder. Prepared overlays, claims, receipts, reservations, and retained capability bytes
  must be empty at the barrier. A two-generation test proves the second segment contains only its
  one new key and the cumulative restore reproduces TLS/CA/certificate/DKIM values and the registry
  digest; 117 checkpoint and cryptographic-material regressions pass.
- The HTTP protocol manager now has explicit manager, shard, and packed-store inventories plus a
  bounded live head containing only open transport sidecars. The shared application registry is
  authoritative for owner/channel/binding identity; HTTP hydration validates those stable tokens,
  then rebuilds packed rows, channel/affinity digest routes, decode caches, and exact reuse-expiry
  heaps. Prepared coupled admissions and receipts fail the barrier. A populated application+HTTP
  restore successfully reuses the original channel, and all 97 checkpoint/HTTP tests pass.
- The explicit-proxy protocol manager now has exhaustive manager, shard, and packed-tunnel-store
  inventories plus a bounded head containing only open proxy tunnel sidecars. The restored shared
  application registry authenticates owner, affinity, client-transport, and interval identity;
  hydration rebuilds fresh packed rows, affinity/origin routes, caches, and expiry authority. The
  expiry is derived from the earlier of the tunnel reuse cutoff and application idle deadline,
  matching the production manager rather than storing duplicate authority. Prepared admission
  capabilities fail the barrier. A populated application+proxy restore reuses the original tunnel,
  and all 91 incremental-checkpoint/proxy tests pass.
- The SSH protocol manager now persists its existing packed rows for open sessions and active
  child operations instead of reconstructing per-row checkpoint objects. The shared application
  registry reauthenticates every session, operation, transport interval, affinity, and owner;
  hydration obtains fresh application close tokens and rebuilds SSH expiry, child/operation routes,
  packed generations, and decode/hot caches. Prepared admission capabilities are transient-empty.
  A populated restore can finalize the recovered child and close its session, and the 80-test
  incremental/SSH manager/prepared-admission/source-port regression group passes.
- The reusable SMB channel manager now has explicit manager, shard, compact-store, and mutable
  session-record inventories. Its bounded head retains packed transport plans, semantic session
  metadata, exact sensor observations, trees, and active handles, but strips process-local common
  close locators. Hydration reauthenticates each channel and active handle against the restored
  application registry, installs a fresh close token, and rebuilds expiry, affinity indexes,
  counters, caches, and packed-store bookkeeping. A restored session reuses its original tree and
  exact sensor view. The incremental/SMB/persistent-projection regression group has 188 passing
  tests (29 slow tests excluded by the routine marker policy). Persistent SMB projection and
  continuation authorities remain separate owners to classify.
- Runtime local-artifact retention now has an explicit bounded participant over its existing
  packed payloads. The head preserves exact shard/handle/free-list topology, retention deadlines,
  due-but-leased markers, lease insertion order, allocation cursors, and the canonical watermark;
  recovery validates and re-packs every inert artifact row before rebuilding routes, equality
  indexes, deadline heaps, and owner indexes. Prepared publications and retained capabilities fail
  the barrier. Historical index backing and diagnostic high-water values are deliberately rebuilt,
  not persisted. The generation-index and incremental-checkpoint group has 112 passing tests.
- The ActivityGenerator retention audit now classifies every mutable field discovered across the
  whole class, including future close journals, foreground finalizers, exact SID/TTY preparation
  state, and rebuilt aliases; two unused duration-risk maps were removed. Email artifact-manifest
  rows now use the existing SQLite streaming spool instead of a history-growing Python list. Its
  checkpoint adapter test seals one base plus one row delta, hydrates a fresh spool, resumes the
  append ordinal, and publishes the same deterministic sorted JSON shape. The 10 retention/spool
  tests and the focused slow end-to-end email generation test pass; a real hour-one barrier audit
  classified all 72 materialized mutable fields without fallback.
- The 17-family process-runtime cache bundle now has one explicit bounded checkpoint participant.
  It encodes only visible semantic key/value/deadline rows, per-family watermarks, and the three
  exact process-to-cache reverse-route families; compact handles, expiry heaps, locks, metrics,
  retained-size accounting, and ActivityGenerator aliases are rebuilt. The inert value allowlist
  now includes the two-field `RuntimeProcessBinding` record, with no generic dataclass fallback.
  Hydration requires the canonical family order, validates finite deadlines, duplicate/hashable
  keys, exact UTC process identities, and reverse routes that resolve to live rows. All 71
  incremental-checkpoint and process-runtime-cache tests pass, and repository-wide Ruff checks are
  clean.
- Direct `ActivityGenerator` runtime state now has an explicit packed participant over its bounded
  maps, two expiring indexes, two standalone bounded caches, allocator/watermark scalars, and
  foreground finalizers. Scenario `System` references in finalizers are stored as host identity
  tokens and rebound against the freshly compiled scenario. Shared protocol/runtime managers and
  the email SQLite spool remain external participants; prepared mutations and the Linux/SSH/RDP
  deferred-close journals currently fail the barrier until their own semantic schemas land. A
  fresh-engine hydration probe reproduced the 20,645-byte hour-one head exactly. A separate
  48-hour probe at six-hour cadence grew from 100,181 bytes at simulated hour 6 to 539,988 bytes at
  hour 54; most growth was in recent process-create/source-bound and termination lookup state, with
  smaller connection-reuse and singleton-interval growth. This is not yet a performance acceptance
  result: those owners retain a fixed recent/live window and must be probed through hours 168, 720,
  and 1,440 before the scaling gate can pass.
- Recovery now uses explicit dependency priorities rather than owner-name order: State, timing,
  cryptographic, and shared-registry authorities hydrate before protocol/runtime dependents, with
  activity, engine, and the generation RNG following them. Publication order remains stable by
  owner name. A coordinator test proves the two orders independently, and all 63 incremental
  checkpoint tests pass.
- Installed RDP terminal continuations now discard one-shot network/application publication
  receipts after their authenticated handoff, removing a hidden capability edge that previously
  kept the application and RDP receipt registries non-quiescent. The activity head stores only an
  untouched future continuation's stable scenario tokens, State identities, canonical network
  transaction, manager snapshot, deadlines, generation, and source tag. Hydration rebinds those
  facts to fresh State, application, and RDP owners; any partially published terminal phase still
  fails closed. The safe value codec gained explicit fixed schemas for process/session/thread
  identities and network transactions, with no generic dataclass path. All 201 SSH/RDP deferred
  production tests and all 63 incremental checkpoint tests pass.
- Untouched SSH close continuations now use the same bounded semantic treatment. The activity
  head records the immutable close plan, transport, source process identity, source-native auth
  times, and the small set of terminal phases already completed before deferral. Recovery creates
  a fresh transaction capture and reauthenticates the plan against the restored common application
  and SSH managers plus fresh dispatcher/emitter owners. Legacy tuple entries, retained receipts,
  active phase bindings, descendant schedules, and application-retirement progress fail closed.
  A real production-bundle test restores the continuation into fresh State/application/SSH owners
  and reproduces its head exactly; the complete 202-test SSH/RDP deferred suite and 63 checkpoint
  tests pass. This testing also exposed a separate blocker for full participant wiring: ordinary
  recent SSH activity leaves source-timing preparation receipt authorities and lifecycle closed-
  transport receipts live at a cadence barrier. Those owners need semantic receipt compaction or
  explicit durable summaries before the production coordinator can accept the barrier.

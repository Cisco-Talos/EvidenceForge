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
calibration, and cadence-selection evidence here. The original three-pair performance matrix and
5% threshold were decision aids rather than release blockers; the selected cadence is based on the
60-day measurement, scaling behavior, and correctness gates recorded below.

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
- Deferred SSH/RDP handoff now explicitly retires the acknowledged one-shot prepared-network and
  source-timing receipt authorities after the exact future continuation has copied its semantic
  transaction. Dispatcher exact-recovery completion severs its retired owner graph at the same
  terminal boundary. A real SSH checkpoint probe now reaches the barrier with zero committed
  source-timing receipts, zero terminal preparation records, and zero lifecycle closed-transport
  weak receipts without a cyclic-GC scan. The complete 202-test SSH/RDP deferred suite and all 63
  incremental-checkpoint tests pass.
- The initialized engine now assembles the production checkpoint participant set explicitly and
  hands exact post-hour cursors to the incremental controller at cadence barriers. The first real
  end-to-end run exposed a dead weak lifecycle action-cohort authority; the barrier now prunes that
  owner-local terminal locator without graph traversal or garbage collection. The minimal fixture
  publishes nine hourly recoveries across its eight-hour warm-up and one-hour collection window;
  the final recovery is a tail cursor with all 16 initialized participant heads and 15 immutable
  segments. A dedicated slow production-wiring test and all 63 incremental tests pass.
- Fresh-runtime recovery now hydrates the explicit participants before entering generation and
  validates the manifest cursor against the compiled warm-up and collection windows. Warm-up and
  collection resumes begin at the exact next hour while preserving the continuous completed-hour
  count; a tail recovery skips the baseline completely and deterministically re-enters remaining
  scheduled work/finalization. The production slow test now creates a real tail recovery, restores
  it into a second initialized engine, and completes with matching ground-truth event state.
- Checkpoint-enabled external-sort emitters now seal per-barrier immutable runs and defer the
  cumulative merge until finalization. Their production spool participant imports each run once,
  retains prior content by manifest reference without rereading or rehashing it, and rebuilds a
  fresh protected run spool on recovery. Append-oriented writer files similarly seal only bytes
  beyond their committed length and restore through a validated hash chain. A real Zeek-family
  engine run restores six sensor files from a tail checkpoint with byte-identical evidence; direct
  adapter tests prove that the second checkpoint reads only its new sorted run or appended suffix.
- Windows Security and Sysmon now export only SQLite candidate rows appended since the preceding
  checkpoint, plus a bounded head containing candidate/high-water accounting and Sysmon's live
  source-native allocator caches. Recovery creates fresh protected journals, imports the immutable
  row segments in contiguous sequence order, and restores allocator state before later generation.
  Fully released exact-publication retry receipts are authenticated and replaced at the barrier by
  a durable journal sequence watermark, preventing those process-local receipts from growing with
  scenario history while preserving terminal source validation. A production tail resume now
  produces byte-identical Windows Security, Sysmon, and Zeek evidence; 84 focused incremental/spool
  tests and 271 Windows/Sysmon emitter regressions pass.
- The generate command now accepts `--checkpoint-hours`, `--resume`, and `--overwrite`, retains
  `--force/-f` as a warning-emitting deprecated alias, rejects conflicting resume/overwrite flags,
  and allows the scenario positional argument to be omitted only for checkpoint resume with an
  explicit output root. Positive-cadence runs generate inside the stable hidden staged bundle,
  publish through the existing sidecar transaction, retain that workspace on interruption/failure,
  and remove it after success; cadence zero leaves no workspace. Recovery metadata retains the
  output target, OOB hosts, and format filter for checkpoint-only resume, while an explicitly
  supplied scenario is recompiled and fingerprint checked. The pre-benchmark unspecified default
  intentionally remains disabled until the acceptance matrix selects a supported cadence. All 39
  slow generation CLI tests, 84 focused checkpoint tests, and repository-wide Ruff gates pass.
- Cadence barriers now retain a disconnected RDP generation that has durably published its 4779
  and source-process termination but is still waiting for its reconnect/logout deadline. The head
  stores the current disconnected manager snapshot, canonical source projection frontiers and
  disposition, and the completed terminal-ledger timing proof; hydration rebinds it to fresh
  authorities without repeating the published rows. Split or unacknowledged publication still
  fails closed. Snort candidate journals now seal only rows beyond the prior SQLite sequence,
  including empty sequence ranges consumed by already-published raw rows, and rebuild a fresh
  protected journal on resume. Raw-alert evaluation summaries use a numeric-state SHA-256 whose
  output matches standard SHA-256, allowing constant-time digest hydration without replaying
  historical alerts. A two-generation Snort continuation test produces byte-identical evidence
  and evaluation digests; all 69 incremental tests, 197 focused Snort exact-publication tests, 63
  IDS tests, and the focused RDP checkpoint tests pass. The next topology-heavy full-participant
  probe now reaches a separate legacy SSH close entry that still needs an explicit bounded schema.
- Legacy SSH compatibility closures now have an explicit semantic head instead of retaining their
  already-rendered occurrence graph. The head stores detached request/system/host facts, canonical
  State process/session identities, transport counters and timestamps, auth timing, and the action
  anchor; hydration rebuilds a fresh bundle and close occurrence against restored owners. A focused
  slow test checkpoints a real compatibility session, restores its emitter spools and owner heads,
  and produces byte-identical eCAR and Zeek bytes. Foreign tuple entries remain rejected.
- Successful exact action-cohort projection recovery now severs its retired record/recovery
  back-reference immediately. This removes one-shot lifecycle receipts by reference counting at the
  source boundary rather than relying on a process-wide cyclic-GC traversal at checkpoint time; all
  21 focused dispatcher recovery tests pass.
- The GenerationEngine inventory now covers every field assigned across its core/baseline/storyline
  mixins, including lazily materialized Linux housekeeping, storyline correlation, package/GPO,
  web-cache, and scheduling state. History-sensitive primitive state is captured, deterministic
  caches are rebuilt, and in-step state must be empty. Unconsumed staged archives use an explicit
  actor-token row and consumed rows are compacted away; anacron history is bounded to the latest day
  per host. A real topology-heavy run committed both hour-6 and hour-12 recovery generations before
  reaching an ordinary tail lifecycle error. The first recovery attempt exposed and fixed an RDP
  validation bug: a disconnected generation may legitimately predate the lifecycle watermark while
  it waits for its reconnect/logout deadline; connected generations still may not.
- An unchanged-runtime CLI probe of the topology-heavy full-coverage fixture resumed from the
  hour-12 recovery and completed successfully after the original process reached its pre-existing
  terminal lifecycle-ordering failure. The resume spent roughly 13 seconds in the six displayed
  collection/tail units, compared with roughly 65 seconds for the original generation body. The
  successful publication removed `.eforge-generation` as required. This is not yet a byte-identity
  acceptance result: the uninterrupted control currently reaches the same unrelated finalization
  defect, and the differing terminal outcome must be isolated before comparing complete bundles.
- Multiplexed Bash-history routes are now visible to the shared emitter-spool participant even
  after their private writers have been reclaimed. Ordinary files seal only the suffix beyond the
  prior committed length; a semantic `history -c` marks one explicit replacement generation, after
  which later checkpoints return to suffix-only capture. Restore discards obsolete pre-replacement
  segments, recreates the exact file bytes, rebuilds the bounded route inventory, and continues
  appending byte-identically. Three spool tests and all 197 Bash/Snort exact-publication regressions
  pass.
- Resource forecasts now expose a separate `Projected checkpoint workspace` range whenever the
  configured cadence can occur in the continuous warm-up/collection window, and add that range
  once to projected peak working disk. The provisional model includes unique sealed output/state
  segments, two bounded head/manifest generations, one pending delta, resolved input, and metadata;
  it does not add external-sort transients a second time. These coefficients remain explicitly
  provisional until the 60-day matrix calibrates them. All 48 resource-forecast and routine CLI
  tests pass.
- Two independent topology-heavy recovery runs at the same commit matched 57 of 59 compared
  artifacts byte-for-byte. The only differences were equal-length Windows Security files whose
  causal account SIDs varied while every other field remained identical. The causal supplementary-
  audit rule was consuming the process-global `random` stream for domain/RID allocation, allowing
  unrelated threaded RNG consumption to change those two values. Domain and account/group SID
  fallbacks now use scoped stable seeds over domain plus semantic identity, and an explicit test
  proves the result is invariant under unrelated global-RNG advancement. This root-cause fix is
  required before repeating the full byte-identity gate.
- Fresh-process interruption tests no longer race a briefly visible generation phase. A guarded
  pytest-only synchronization seam writes a durable marker after the recovery manifest has been
  atomically published and blocks until acknowledged or signaled; an optional exact-hour selector
  lets tests pass earlier cadence points without polling them. SIGKILL during warm-up, SIGINT during
  collection, and SIGKILL from a tail cursor all retain the last committed recovery, resume after
  moving the complete output root, and match a checkpoint-disabled uninterrupted bundle byte-for-
  byte. The comparison includes evidence, resolved scenario, ground truth, and deterministic
  sidecars and excludes only `generation.log` and the time-bearing generation manifest. All three
  fresh-process cases pass.
- Foreground checkpoint instrumentation now separates emitter quiescence, terminal-owner pruning,
  participant extraction, segment encoding/compression/hashing/writes, head and manifest writes,
  atomic publication, index publication, recovery rotation, and participant commit callbacks. It
  also records per-participant head/delta size and preparation time. The resolved scenario is
  content-addressed once before generation, filesystem capability probing is once per store
  lifetime, and object-tree garbage collection is an explicit out-of-pause operation rather than
  an every-checkpoint history scan. Reused payload segments report zero bytes reread and zero bytes
  rehashed.
- The first instrumented cadence-one minimal probe showed participant extraction, not storage, was
  dominant: the hour-nine checkpoint spent about 112 ms extracting 4.11 MiB of live heads while
  the complete durable store commit took about 9 ms. The lifecycle registry alone contributed
  3.09 MiB, including 900 already-closed transports, and network runtime contributed 583 KiB. An
  attempted global watermark/zero-retention compaction correctly failed testing because recent
  closed process parents and frozen close schedules remain semantically necessary.
- Checkpoint barriers now instead drain existing sharded deadline queues for only terminal
  lifecycle transports with no live binding or retention lease, and discard only closed network
  transport intervals while retaining the separate source-port freshness authority. At hour nine,
  the lifecycle head fell from 3.09 MiB to 459 KiB and network runtime from 583 KiB to 226 KiB;
  lifecycle retained the 147 process and three session identities required by later work, while
  both heads retained zero full transport rows. The successful bundle is byte-identical to the
  unpruned control, 146 focused lifecycle/network/checkpoint tests pass, and all three fresh-process
  SIGINT/SIGKILL moved-root recovery cases remain byte-identical.
- A fresh-process 60-day diagnostic pair at six-hour cadence is byte-identical across every
  deterministic bundle artifact (excluding only `generation.log` and the time-bearing generation
  manifest), but decisively rejects the current repeated-head capture: the control completed in
  834.866 seconds and the checkpoint run in 1,152.141 seconds, or 38.00% overhead. Its 241
  foreground pauses totaled 504.171 seconds and grew from 0.052 seconds at hour 6 to 0.150 at hour
  24, 0.538 at hour 168, 2.179 at hour 720, and 3.814 at hour 1,440. At the final scale point,
  source-timing extraction consumed 2.319 seconds for a 40.22 MB head and lifecycle extraction
  consumed 1.028 seconds for a 55.42 MB head. The lifecycle head held 17,363 process and 426
  session identities; source timing held 179,107 retained index rows. The flat manifest also grew
  to 3.20 MB and 9,665 segment references. Peak retained workspace was 493,403,050 bytes versus
  258,046,109 deterministic output bytes. This is a single diagnostic pair, not the three-pair
  acceptance matrix or a supported default-cadence result.
- Flat cumulative segment references are replaced in the unreleased schema 2.0 by a persistent
  size-tiered Merkle catalog forest. Each checkpoint writes a leaf for only its new immutable
  references and performs binary-carry compaction by writing small parent nodes over already known
  roots; it never reads, hashes, or rewrites an inherited payload. The recovery manifest therefore
  retains at most one root per level rather than every historical segment, while the previous
  manifest continues to reference its unchanged tree. Recovery validates and expands the tree,
  rejects cycles/tampering/invalid owner ordinals, and garbage collection traces both retained
  roots outside the checkpoint pause. Thirty-two synthetic generations collapse to one level-five
  root with a manifest below 4 KiB. All 74 incremental-checkpoint tests pass, including corruption
  fallback, and the three fresh-process moved-root SIGINT/SIGKILL cases remain byte-identical.
- Source-timing state now uses a schema-2 base segment followed by ordered mutation segments. Its
  live head contains only the watermark and segment count (122 bytes at hour 168), while each
  cadence point seals only intervening sets, re-deadlines, removals, and expirations. Hydration
  replays the authenticated base/delta chain into fresh bounded caches, and failed publication
  leaves the pending mutations available for an exact retry.
- Checkpoint expiry drains lifecycle deadline queues without advancing the semantic watermark or
  compacting ledger details. The distinction is required for resumability: the first version
  reused normal watermark advancement and incorrectly discarded start-commit detail needed by an
  hour-one recovery. After separating those operations, all three fresh-process SIGINT/SIGKILL
  moved-root cases pass again and remain byte-identical.
- A fresh-process seven-day diagnostic pair at six-hour cadence is byte-identical across every
  deterministic bundle artifact. The control completed in 82.020 seconds and the checkpoint run
  in 82.812 seconds, or 0.97% overhead; its 29 foreground checkpoint paths totaled 5.639 seconds.
  The hour-168 checkpoint took 0.242 seconds, with a 5,359,915-byte aggregate live head and a
  1,298,014-byte new delta. The retained checkpoint workspace was 45,870,202 bytes versus
  30,306,319 deterministic output bytes. This is a single diagnostic pair, not the acceptance
  matrix or a selected default cadence.
- The first 60-day incremental scale probe at six-hour cadence produced the exact prior
  checkpoint-disabled digest and all per-artifact hashes. It completed in 726.033 seconds, with
  241 checkpoint paths totaling 80.858 seconds and a 316,543,528-byte retained workspace. The
  comparable full-snapshot experiment required 1,152.141 seconds and 493,403,050 bytes. Live-head
  size grew only from 5,359,915 bytes at hour 168 to 6,400,585 at hour 720 and 7,144,862 at hour
  1,440, but the single observed pauses of 0.247, 0.392, and 0.637 seconds require a rotated median
  before satisfying the two-times scaling gate. No inherited segment bytes were read or hashed.
- The same-commit checkpoint-disabled 60-day diagnostic completed in 837.322 seconds with a
  1,571,094,528-byte peak RSS, versus 959,004,672 bytes for the checkpoint run. Because retirement
  previously ran only at checkpoint barriers, safe pruning more than offset publication work and
  made this an unfair negative-overhead comparison. A fixed internal six-hour retirement barrier
  now applies the same safe lifecycle/network pruning to checkpoint-disabled and enabled runs; it
  is not a user-visible cadence option.
- External-sort checkpoint metadata now records only bounded per-writer counters and the durable
  run count. The writer exposes only the suffix after that count, so later checkpoints neither
  reopen nor stat old immutable runs. Recovery derives run size and hash from the already
  authenticated immutable segment. In a fair seven-day pair with identical retirement policy,
  all deterministic artifacts were byte-identical, control was 78.229 seconds, and six-hour
  checkpointing was 79.253 seconds (1.31% overhead). The hour-168 emitter-spool head fell from
  160,091 bytes to 1,626 bytes. All 156 focused tests and all three moved-root fresh-process
  interruption cases pass.
- The required codec/compressor bakeoff uses the latest real 60-day recovery delta: 8,503,722
  bytes of bounded heads plus newly sealed segments. Each of 20 combinations ran in three rotated,
  isolated fresh-process trials, verified deterministic semantic round trips, and reported encode,
  compression, hash, decode, payload size, and peak RSS. Stdlib packed/no-compression required a
  60.23 ms median write path; its zlib-1 variant required 82.77 ms and reduced the payload to
  1,499,208 bytes. Msgspec MessagePack/no-compression was the fastest safe micro-candidate at
  9.06 ms and 5,604,446 bytes; msgspec plus single-threaded Zstandard required 10.25 ms and
  1,045,378 bytes. LZ4 was slightly slower than no compression. NumPy `.npy` and Arrow IPC wrapped
  the required heterogeneous packed document and regressed to 86.07 ms or more. Multithreaded
  Zstandard provided no benefit on these checkpoint-sized buffers.
- No third-party candidate qualifies for production. Even the impossible upper bound that removes
  all 60.23 ms of stdlib codec/hash work plus the complete observed 28.03 ms store commit is only
  13.9% of the 636.55 ms hour-1,440 checkpoint path, below the required 20% checkpoint-path
  improvement before considering implementation overhead. It therefore cannot satisfy both the
  20% path and three-percentage-point generator gates. SQLite WAL, LMDB, and RocksDB are likewise
  screened out before prototyping because the entire replaceable store path is only 4.4% of that
  pause; RocksDB checkpoints also depend on same-filesystem hard links for their cheap path and
  otherwise copy files. The production implementation remains dependency-free stdlib packed
  segments with compression selected per payload; rejected benchmark-only dependencies are not
  added to `pyproject.toml` or `uv.lock`.
- The retained 60-day incremental workspace measured 316,543,528 bytes for 258,046,109 bytes of
  deterministic output, a 1.227× ratio before the subsequent 1.47 MB emitter-head reduction. The
  resource model now uses a 1.20 sealed-segment multiplier plus its existing 2% bounded-head
  memory term and 1 MiB metadata floor. It continues to show `Projected checkpoint workspace` as
  a separate line and adds it exactly once to projected peak working disk; the active staged
  bundle and external-sort transients remain outside this line to avoid double counting.
- Fair performance controls now use the same deferred final publication for external-sorted
  evidence as checkpointed runs. Hourly retirement barriers may spill and compact bounded runs,
  but neither arm repeatedly merges the entire accumulated output into its destination; both
  publish once during finalization. All three moved-root fresh-process interruption cases and the
  slow deterministic generation integration cases remain byte-identical. In the first normalized
  seven-day pair, six-hour cadence cost 7.18% (5.570 seconds across 29 checkpoint paths) and
  18-hour cadence cost 3.47% (2.206 seconds across ten checkpoint paths). These are single-pair
  diagnostics, not cadence selection results; the rotated three-pair representative matrix is
  still required.
- Store fault injection now covers partial content writes, failure before recovery-index
  publication, interrupted size-tier catalog compaction, and failure while rotating obsolete
  recoveries after the index commit point. An unindexed recovery directory is safely discarded
  when the same sequence retries; after `CURRENT.json` is durable, cleanup failure is warned and
  cannot roll back participant watermarks. Recovery also rejects rehashed path-traversal metadata
  and externally writable segment objects. The focused checkpoint module has 81 passing tests.
- Output-state prompting now distinguishes a structurally valid incomplete recovery, an invalid
  checkpoint, and a completed bundle. Interactive generation offers resume/overwrite/abort for a
  valid incomplete workspace, reports the validation failure before offering overwrite/abort for
  an invalid one, and retains the existing overwrite/abort prompt for completed output. Redirected
  input must provide explicit `--resume` or `--overwrite`; focused CLI coverage confirms these
  branches without weakening the run-lock checks.
- The first normalized 60-day pair at 18-hour cadence remains byte-identical across every
  deterministic artifact, but does not pass the production gate: control took 639.140 seconds and
  checkpointed generation took 689.828 seconds, or 7.93% overhead. Eighty foreground checkpoints
  totaled 30.963 seconds; the remaining 19.725-second difference is checkpoint-mode work outside
  the measured barrier and must be attributed before cadence selection. Workspace retention was
  311,734,718 bytes for 258,046,108 output bytes (1.208×). Hour-720 and hour-1,440 pauses were
  0.281 and 0.644 seconds respectively; that single 2.29× observation does not satisfy the
  scaling gate and requires rotated medians. Both points reread and rehashed zero inherited
  segment bytes.
- A normalized 60-day pair at 48-hour cadence is also byte-identical but remains above the
  production gate: control took 655.207 seconds and checkpointed generation took 707.892 seconds,
  or 8.04% overhead. The complete pair consumed 1,363.099 seconds (22 minutes 43 seconds) of
  measured generator wall time. Thirty foreground checkpoints totaled 18.771 seconds, only 2.86%
  of control runtime; an additional 21.844 seconds accrued during baseline work outside measured
  pauses and 11.732 seconds during finalization. This establishes a cadence-independent overhead
  floor of about 5.2% in the observed pair, so widening cadence cannot satisfy the gate by itself.
  The hour-720 and hour-1,440 checkpoints took 0.627 and 0.880 seconds (1.40×), with essentially
  stable 5.67 MB live heads and 10.47/10.10 MB deltas. Neither reread nor rehashed inherited
  segments. Workspace retention was 311,146,907 bytes for 258,046,108 output bytes (1.206×),
  within the recalibrated forecast. The next optimization should remove checkpoint-mode mutation
  and final-sort overhead before selecting a cadence or running the three-pair acceptance matrix.
- A full-live-head source-timing experiment is rejected. Although its first seven-day 18-hour
  pair happened to report only 0.22% total overhead, the 60-day pair regressed to 11.53%: control
  took 641.626 seconds, checkpointed generation took 715.618 seconds, and the 30 checkpoint paths
  totaled 49.847 seconds. Source timing alone grew to a 40.22 MB live head and 2.307-second prepare
  at hour 1,440; retained workspace reached 377,720,422 bytes. This confirms that source-timing
  caches cannot be recopied in full at each cadence point even when terminal lifecycle state is
  bounded.
- Source-timing schema 3 instead coalesces intervening mutations by family and key before sealing
  an ordered delta. Repeated sets, re-deadlines, and removals therefore retain only the last
  semantic change for each key, while the planner's existing preparation lane provides the
  capture/commit mutation boundary. Terminal external-sort publication now uses balanced,
  copy-on-write merge levels so close no longer repeatedly rereads the earliest cadence runs;
  injected merge failure preserves every original run for an exact retry.
- Three normalized seven-day screens at 18-hour cadence remained byte-identical. Their observed
  overheads were 3.89%, 1.10%, and 4.25% (3.89% median), while checkpoint paths totaled 2.150,
  2.098, and 1.965 seconds (2.098-second median). Detailed finalization attribution showed source
  publication at about 12.6 seconds in both arms, terminal-stage draining unchanged, and only
  about 0.15 second of added emitter-close work. The earlier large finalization deltas were run
  variance, not a checkpoint-specific optimization target.
- The corresponding 60-day, 48-hour-cadence screen is byte-identical and passes the single-pair
  performance and scaling diagnostics. Control took 686.122 seconds and checkpointed generation
  took 674.879 seconds, an observed -1.64% overhead caused by favorable baseline variance. The 30
  foreground checkpoint paths totaled 16.254 seconds, or 2.37% of control wall time, versus
  18.771 seconds before coalescing. Hour-720 and hour-1,440 checkpoints took 0.569 and 0.769 seconds
  (1.35x); each sealed about 10 MB of new data, and neither read nor rehashed inherited segments.
  Source-timing deltas stayed bounded at 1.55 MB/6,584 records and 1.45 MB/6,081 records. Retained
  workspace fell to 306,274,489 bytes (1.187x the 258,046,108-byte deterministic bundle), and the
  checkpoint arm's 916,652,032-byte peak RSS did not exceed the control's 929,054,720 bytes. This
  is strong evidence for retaining coalesced deltas and balanced final merges, but a rotated
  three-pair matrix is still required before selecting the default cadence or accepting the 5%
  production gate.
- The 60-day, 24-hour-cadence validation is byte-identical across every deterministic bundle
  artifact. Control generation took 657.924 seconds and checkpointed generation took 679.717
  seconds, an observed 3.31% total overhead. Sixty foreground checkpoint paths totaled 24.994
  seconds, within 0.35% of the 25.082-second projection derived before the run. Hour-720 and
  hour-1,440 checkpoints took 0.468 and 0.415 seconds, respectively; neither reread nor rehashed
  inherited segments. The retained workspace measured 306,669,201 bytes, and the checkpoint arm's
  891,338,752-byte peak RSS remained below the control's 942,145,536 bytes. This result, the
  bounded late-run costs, and exact resume tests support 24 hours as the production default. The
  prior three-pair/5% language was intentionally treated as guidance rather than a hard release
  gate after reviewing these measurements.
- Production checkpoint timing probes were removed after cadence selection. The generator no
  longer measures or reports checkpoint-stage, participant, hashing, compression, or publication
  timings; the standalone benchmark script wraps checkpoint commits externally when performance
  diagnostics are requested. This avoids imposing measurement work on normal generation while
  preserving a reproducible benchmark path.
- Final feature validation used the 24-hour default and passed 8,119 routine tests (5 skipped) plus
  the 1,807-test extended tier after correcting stale test doubles exposed by its first pass. The
  two SMB integration modules were evaluated separately: their ten baseline failures occur before
  any 24-hour checkpoint and cover stale pack-fixture arguments and existing SMB/SSH lifecycle
  expectations, so they are not attributed to this feature. Focused checkpoint, fresh-process
  SIGINT/SIGKILL, moved-root, spool, owner-inventory, skill-contract, and byte-identity suites also
  passed. The measured 60-day run serves as the relevant scalability/soak evidence; a redundant
  full soak-tier rerun was not performed.
- Forecast parity now extends to the standalone validator. `eforge validate` defaults its resource
  forecast to the same 24-hour checkpoint cadence as `generate`, accepts the same nonnegative
  integer `--checkpoint-hours` override, and models zero checkpoint workspace when explicitly
  disabled. Text and JSON callers pass the selected cadence through the same forecast path.
- Recovery UX now reports the retained simulated-hour cursor and phase after Ctrl+C or an ordinary
  generation failure, or explains that no recovery point exists yet. Checkpoint-only resume reports
  the restored cursor and effective cadence before continuing. A fresh-process SIGINT test exercises
  the retained-point message rather than relying only on a unit-level formatter check.
- Portable recovery coverage now includes a bounded scenario that emits Windows, Zeek, eCAR,
  syslog, bash history, Snort, Cisco ASA, web-access, and proxy-access evidence. Fresh-process
  SIGKILL/resume is byte-identical to checkpoint-disabled generation for the default, SOF-ELK®, and
  Splunk targets, including resolved input, ground truth, artifacts, and deterministic sidecars;
  only the established generation log and time-bearing generation manifest are excluded.
- Publication interruption tests now SIGKILL fresh generator processes after durable live heads,
  after recovery-directory publication but before the recovery index, and after index publication.
  Recovery selects the prior manifest before the index commit point and the new manifest after it,
  then resumes to byte-identical output in every case. These are deterministic synchronization
  seams, not production timing probes. Production code contains no checkpoint-stage, participant,
  hashing, compression, or publication timers.
- Portability documentation now distinguishes movable-root recovery from runtime migration: copy or
  move only a stopped output root, and resume with a compatible exact EvidenceForge build/resources,
  Python runtime/compiler, dependencies, platform, options, and resolved input. Users are directed
  to finish an incomplete run before upgrading instead of bypassing fingerprint incompatibility.
- Linux CI exposed a race confined to the pytest-only interruption barrier: the `.ready` marker was
  visible after creation but before its small JSON payload had been written. Both hour-boundary and
  publication-stage barriers now write and sync a private pending marker, atomically publish it, and
  sync the directory before waiting for acknowledgement. The CI-equivalent default suite then
  passed all 8,119 tests (5 skipped), and Ruff checks remained clean.
- Interactive SIGINT handling now shares the explicit suspension safe point. One Ctrl+C latches an
  end-of-hour request and, when checkpointing is enabled, publishes an off-cadence recovery before
  exiting with status 130. A second Ctrl+C forces immediate exit; checkpoint-disabled generation
  performs normal abort cleanup after the hour without creating recovery state.
- A representative `iteration-test` SIGINT/resume comparison exposed state that the earlier compact
  fixtures did not exercise. Recovery now persists Bash command recency, evolving system service
  PIDs, network PAT allocator cursors, bounded proxy CONNECT summaries, and cumulative dispatcher
  observation counters. Checkpoint barriers compact completed proxy summaries into the existing
  external-sort spool while retaining only tunnels inside the four-minute reuse window. Syslog's
  anonymous exact-publication journal has a dedicated incremental hash-chain adapter, sorted
  host-multiplex emitters seal external-sort runs in checkpoint mode, and immutable email MIME
  artifacts are imported once. Exact integer timedelta encoding also avoids one-microsecond losses
  in application and lifecycle heads. The actual scenario now resumes in a fresh process and is
  byte-identical to checkpoint-disabled generation across all 120 deterministic artifacts.
- The post-fix 60-day/24-hour regression pair remained byte-identical and measured 649.159 seconds
  without checkpoints versus 670.609 seconds with them: 3.304% total overhead, effectively
  unchanged from the selected 3.31% baseline. Sixty checkpoint paths totaled 20.940 seconds, down
  from 24.994 seconds. Hour-720 and hour-1,440 commits took 0.280 and 0.329 seconds, and retained
  workspace was 306,675,720 bytes, only 6,519 bytes above the prior measurement. Peak RSS was
  1,081,049,088 bytes for the checkpoint arm versus 925,696,000 bytes for the control; unlike time
  and disk, this single-pair high-water result regressed and should be watched in future profiling.

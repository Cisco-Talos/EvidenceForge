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

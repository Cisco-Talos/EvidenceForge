# Checkpoint Operations

## Objective

Add human-friendly inspection and planned suspension for incremental generation checkpoints:
`eforge checkpoint status DIRECTORY` performs thorough read-only recovery validation and storage
accounting, while `eforge checkpoint suspend DIRECTORY` asks an active generator to stop at the
next completed simulated-hour barrier after publishing an explicit recovery point.

## Locked decisions

- The bundle root is a positional argument; `--output` is not used by checkpoint subcommands.
- Status is thorough by default. Human output emphasizes recovery state, cursor, cadence,
  compatibility, storage, warnings, and the resume command. `--verbose` adds implementation
  diagnostics, while `--json` always returns the full structured report.
- Storage totals count unique managed regular files, exclude unrelated user files, and distinguish
  staged generated data, checkpoint recovery overhead, and the complete known managed working
  footprint. Categories that cannot be measured safely are omitted rather than shown as unknown.
- Suspension is cooperative rather than signal-based. The requesting command immediately warns
  that suspension is not immediate. The generator finishes the current simulated hour, uses the
  existing quiescent checkpoint barrier to publish an off-cadence recovery, and exits cleanly.
- An off-cadence suspension does not move the cadence anchor. For example, a suspension at hour 37
  with a 24-hour cadence still schedules the next automatic checkpoint at hour 48.
- The first Ctrl+C is a process-local cooperative suspension request. It is acknowledged
  immediately, stops at the completed-hour barrier, and publishes an off-cadence recovery when
  checkpointing is enabled. With `--checkpoint-hours 0`, it stops after the hour through ordinary
  abort cleanup without creating a recovery. A second Ctrl+C forces immediate exit.
- No generator checkpoint-path timing probes are reintroduced.
- Checkpoint-enabled generation creates its protected workspace and controller marker before
  warm-up even when the total run is shorter than one cadence. Status therefore distinguishes an
  active run awaiting its first checkpoint from a directory where no checkpoint workspace exists.
- A mistakenly supplied generated `data/` directory is detected without recursively measuring its
  contents, and status/suspend give the exact command using the parent bundle root.
- Recovery status leads with phase-local progress while retaining the continuous cadence count. A
  two-hour warm-up followed by one completed hour of a six-hour output window is rendered as
  `collection hour 1 of 6 (3 total simulated hours completed)`, matching the generator's phase-local
  `Hour N/6` display without obscuring the cadence anchor.

## Validation record

Record focused unit/CLI tests, byte-identical suspension/resume coverage, default/slow suite
results, Ruff results, and status-validation timing observations here.

## Implementation record

- The checkpoint CLI is a nested Typer command group with positional output roots. Human status
  renders an operator-focused summary; verbose output adds recovery-generation, lock, fingerprint,
  filesystem, forecast, validation-work, and storage diagnostics; JSON always serializes the full
  frozen Pydantic report.
- Status uses a read-only store path that neither creates directories nor runs the atomic/durability
  probe. It authenticates the authoritative index, both indexed manifests, catalog forests,
  content-addressed segments, live heads, and resolved input. It recompiles that stored resolved
  input and reproduces the complete runtime fingerprint without hydrating generation state.
- Storage accounting deduplicates managed files by device/inode and excludes unrelated root entries.
  It separates the current staged/generated bundle, checkpoint workspace, retained prior published
  bundle, available disk, and total known managed footprint. Durable spool copies imported into the
  checkpoint are included in checkpoint storage; external runtime spools are not exposed as a
  status field.
- A protected controller capability, idempotent suspension request, and durable suspension
  acknowledgement live in the hidden workspace. Control records are canonical Pydantic JSON,
  owner-only, no-symlink files published with atomic replacement and directory synchronization.
  Fixed-name requests use atomic create-once publication, so concurrent operators converge on the
  same request instead of replacing one another. Lock and control reads bind validation to an open
  no-follow descriptor to reject symlink swaps and unsafe ownership or permissions.
- The engine checks for a request at completed-hour boundaries. A request makes that boundary
  checkpoint-due, reuses emitter quiescence, retirement, watermarks, transient validation, and the
  normal transactional participants, and acknowledges only after the recovery manifest commits.
  The intentional suspension signal bypasses abort/finalization cleanup, so the selected checkpoint
  stays authoritative. The CLI then releases the run lock, preserves the workspace, reports the
  exact cursor and resume command, and exits successfully.
- Compact fingerprint-component metadata is included in new recovery manifests. This permits
  verbose status to identify component-level mismatches while the aggregate fingerprint remains
  authoritative and older manifests remain readable.
- Generation installs a two-stage SIGINT latch around the engine. The first signal cannot interrupt
  a checkpoint transaction; the completed-hour path either publishes a local suspension recovery
  or, if the signal arrives during an already-due commit, acknowledges that recovery without
  duplicating it. The second signal uses immediate process termination and therefore has the same
  stale-lock/staging implications as a hard kill; normal recovery and stale-lock reclamation remain
  authoritative.

## Validation results

- Two-stage Ctrl+C coverage passed: focused signal/controller/engine contracts; a fresh-process
  off-cadence SIGINT followed by resume with byte-identical deterministic output; a signal arriving
  after an ordinary cadence publication without a duplicate checkpoint; checkpoint-disabled
  end-of-hour cleanup with no recovery workspace; and a second-SIGINT forced exit. The focused
  routine checkpoint, CLI, generation-skill, and installer group passed 183 tests with 79
  slow-marker deselections. Repository-wide Ruff check and format-check passed.
- Phase-local recovery rendering passed the 104-test focused checkpoint, CLI, generation-skill,
  and installer group with 54 routine-marker deselections. The exact regression fixture uses a
  two-hour warm-up and six-hour collection window and verifies both the human
  `collection hour 1 of 6 (3 total simulated hours completed)` output and the corresponding JSON
  phase counters. Repository-wide Ruff check and format-check passed; the slow tier was not
  repeated for this presentation-only follow-up.
- The bundle-root discovery and pre-first-checkpoint UX follow-up passed 103 focused checkpoint,
  CLI, generation-skill contract, and skill-installer tests with 54 deselected. The exact mistaken
  `scenarios/iteration-test/data` status invocation returned immediately with `no checkpoints
  found` and the corrected parent-root command. Repository-wide Ruff check and format-check passed;
  the slow tier was intentionally not repeated for this bounded control-initialization and output
  change.
- The final focused checkpoint, CLI, skill-contract, and installer group passed 186 tests with 54
  deselected by the routine marker policy.
- The fresh-process planned-suspension test requests an off-cadence stop, observes the durable
  suspended cursor, resumes in a new process, and compares the resulting bundle against a
  checkpoint-disabled uninterrupted run. Every deterministic file is byte-identical; the only
  established exclusions remain `generation.log` and the time-bearing generation manifest. The
  final isolated test took 41.46 seconds.
- Thorough status against the retained real 60-day workspace validated both recovery generations,
  9,949 selected segments, 19 live heads, and a 316,543,528-byte checkpoint workspace. Content
  validation took 4.20 seconds and the complete CLI invocation took 5.50 seconds. Integrity passed;
  compatibility correctly failed because this feature changes the build fingerprint relative to
  that archived run.
- The definitive default suite passed 8,128 tests with 5 skipped and 2,037 deselected in 195.25
  seconds. The full slow release tier passed 1,808 tests with 8,362 deselected and no coverage
  instrumentation in 692.41 seconds.
- Repository-wide Ruff check and format-check gates pass across all 746 formatted files.
- A later full-slow run exposed 17 stale mocked CLI tests after persistent checkpoint staging began
  at generation startup. Their fake engines searched for the retired `.eforge_staging_*` path and
  therefore emitted no bundle into `.eforge-generation/staged`; six rollback tests could also pass
  without reaching their intended injected fault. Earlier checkpoint validation missed this because
  the full slow tier passed before startup staging changed, that follow-up ran focused tests only,
  and the whole mocked generate class was marked slow and excluded from the routine gate.
- The repair makes mocked engines emit through the actual `GenerationEngine` constructor paths,
  verifies that fault injections are reached, and asserts successful CLI exit codes where tests had
  previously ignored them. Only fresh-process generation, signal, resume, cross-format, and atomic
  publication cases remain slow; narrow mocked generate contracts now run in the routine suite.
- The CLI now validates the complete required generated bundle before reporting success in both
  direct (`--checkpoint-hours 0`) and staged modes. Failures during replacement report explicitly
  when existing output was preserved, independently of whether a persistent checkpoint workspace
  is retained.
- Post-repair validation passed 77 focused routine CLI tests with 14 slow cases deselected, the full
  default gate with 8,190 passed and 5 skipped in 235.48 seconds, and the full slow release tier with
  1,772 passed in 916.42 seconds. Fresh-process SIGINT/SIGKILL, moved-root, all-format-target, and
  representative iteration-scenario resume tests all retained byte-identical deterministic output.
  Repository-wide Ruff check and format-check passed across all 753 files.

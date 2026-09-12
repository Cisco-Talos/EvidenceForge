# Behavior-preserving 2.0.0 cleanup

## Second-pass status — acceptance reopened

The first-pass preservation claim below is limited to its exercised matrix. Review found a
misplaced scenario-deadline lookup in the process service. The user authorized a six-item second
pass: correct foreground ownership against real process/session behavior, then consolidate shell
policy, storyline session resolution, handler helpers, network stage records, and process services.
Original dev remains a comparison reference, not the correctness authority for the correction.
The first-pass checkout is preserved at `/private/tmp/eforge-cleanup-first-pass` (`2c7dee2a`).
No dependency/version/checkpoint-schema changes, merge, or release are authorized.

Implementation is in progress. Final acceptance is not complete.

## First-pass status (historical)

All seven items are complete on `codex/2.0.0-code-cleanup`, in seven sequential refactor commits.
Final gates: **8,418 standard tests passed** (27 existing skips), **1,780 slow tests passed**,
**44 frozen byte-comparison cases passed**, and **12 checkpoint resumes passed**. Ruff lint,
formatting, whitespace, and behavior-manifest checks against the predecessor and original dev pass.
Original 2.0.0 checkpoints remain compatible under compatible policy; exact policy correctly rejects
the changed build. Version/dependency declarations and the original dev ref are unchanged.
No merge or release was performed. The execution record below retains intermediate failures and
historical pending notes; this final status supersedes those notes.

## Contract and baseline

- Approved implementation order: shared shell-history policy; shared timing constructor;
  configuration validation; checkpoint scratch cleanup; storyline dispatch; shared Windows/Sysmon
  infrastructure; full process and network ownership extraction.
- Branch: `codex/2.0.0-code-cleanup`, based on clean `dev` at
  `e4035435e8e53400ab25a74fe551313354369203` (version 2.0.0).
- Preserved baseline checkout: `/private/tmp/eforge-200-cleanup-baseline`.
- Use the same locked Python environment for baseline/candidate comparisons. Installed the `dev`
  extra with `uv sync --frozen --extra dev`; no dependency/version declarations changed.
- Acceptance: unchanged evidence file set and raw bytes, including ground truth. Only runtime
  diagnostics and field-level build/run/checkpoint provenance may differ. No rewritten golden data.
- Between every item: standard pytest, focused tests, Ruff lint/format, behavior-manifest check,
  baseline and predecessor byte comparisons. Final: all standard and slow tests; relevant soak
  diagnostics only. Preserve original checkpoint hydration and resumed evidence.
- Append `impact: none` behavior revisions with updated digests for covered code changes. Preserve
  existing classification and exact-build resume policy.

## Execution record

- Created branch and detached baseline worktree. Standard baseline suite started; results pending.
- Added an initial fresh-process evidence capture/comparison harness. Full matrix, provenance
  checks, and original-build checkpoint fixtures remain to be completed before acceptance.
- Item 1 completed: shared policy in `config/shell_history_policy.py`, used by validation and
  generation without importing the generator to discover account eligibility.
- Item 1 gate: 8,406 standard tests passed, 27 skipped, 2,009 deselected (293.29 seconds).
  Focused policy/behavior tests: 32 passed. Comparison-harness tests: 3 passed separately.
  Ruff check/format, whitespace, and behavior revision 43 validation against `e4035435` passed.
- Original baseline minimal repeat: all 16 artifacts matched (raw evidence; manifest creation time
  exempt). Item 1 minimal and all-format/default/seed-42 comparisons passed (16 and 26 artifacts).
- All 32 original baseline matrix captures completed. A separate original-build repeat/comparison
  is running; the expanded final matrix is not yet accepted.
- Original-build checkpoints retained for seeds 42/137 and default/sof-elk/splunk targets under
  `/private/tmp/eforge-cleanup-evidence/checkpoints`. Never resume those originals directly.
- A copy of the original default/42 checkpoint successfully resumed under item 1 with normal
  compatible policy. All evidence and ground-truth bytes matched original uninterrupted CLI output.
  Only manifest creation time, resume lineage, and explicit-vs-adopted seed override bookkeeping
  differed; effective seed remained 42. Final automated provenance comparison remains outstanding.
- An exploratory standard run begun before item 1 also passed (8,397 tests); the dedicated item 1
  gate above is the authoritative validation after all production changes.

### Item 2 — shared timing constructor

- Shared the existing mixture constructor through `timing.distributions.uniform_distribution`;
  retained action-local import aliases and exact distribution classes/representation.
- Added exact sample expectations captured from the original build for seeds 42 and 137.
- Gates: 39 focused tests passed; 8,412 standard tests passed, 27 skipped, 2,009 deselected
  (285.44 seconds); Ruff lint/format and whitespace passed. Behavior revision 44 validated.
- All-format/default/42 evidence matched both original `dev` and item 1 (26 artifacts).
- Full original-build repeat matrix passed all 32 cases, including both seeds, three targets,
  serial/threaded emitters, format filtering, and Windows/Linux SMB.
- Automated original-default/42 checkpoint hydration, compatible migration, and evidence comparison
  passed. Verification's protected-path checks reject the macOS `/var` temporary-path alias;
  the harness now supplies a canonical temporary directory, without changing product checks.
- Standard-suite skips include unavailable gitignored `sample_data/` and optional external-parser
  fixtures; full reason list is in `/private/tmp/eforge-cleanup-item2-tests.log`.
- Items 3–7 and the final full standard/slow and expanded checkpoint matrix remain outstanding.

### Item 3 — configuration validation phases

- Moved reusable validation to `validation/configuration.py` with explicit legacy CLI re-exports.
  The public coordinator is 26 lines; effective loading/orchestration is 253 lines, followed by
  12 explicitly ordered domain checks. DNS indexes and shared IDS callbacks have a named result.
- Raw overlay validation precedes delayed scope activation. The scoped overlay discovery pass
  remains explicit, preserving the old recursive pass's scope-dependent diagnostics and counts.
- Default configuration result exactly matches original `dev`: 92 files checked, no issues.
- Gates: 65 focused non-soak tests and all 91 exhaustive configuration soak cases passed;
  8,412 standard tests passed, 27 skipped, 2,009 deselected (289.08 seconds). Ruff and whitespace
  passed. All-format/default/42 bytes match both original baseline and item 2.
- Behavior digest remains revision 44: neither CLI nor validation module paths belong to the
  existing generation behavior surface, and the checker confirms no surface change.
- Items 4–7 and final standard/slow/expanded-checkpoint acceptance remain outstanding.

### Item 4 — checkpoint scratch resource ownership

- Replaced arbitrary object-graph traversal with construction-time owner registrations for
  SQLite connections, directory descriptors, child writers, and base-emitter workers.
  Disposal remains separate from normal finalization and preserves primary-error handling.
- Focused regression coverage includes duplicate descriptors, partial initialization, unowned
  handles, worker shutdown, repeated disposal, and SQLite close failure. The existing synthetic
  checkpoint owner now explicitly registers its connection; its no-finalization assertion remains.
- Gates: 146 focused tests, 3 targeted slow checkpoint tests, and 8,416 standard tests passed;
  27 standard skips and 2,009 deselections (298.81 seconds). Initial focused failure was the
  synthetic owner's missing registration; the corrected repeat passed. Ruff/format passed.
- Revision 45 validated against item 3. All-format/default/42 raw evidence matches original
  baseline and item 3. Original-build checkpoint verification and compatible resume also passed
  with byte-identical evidence and validated provenance.
- Items 5–7 and final comprehensive acceptance remain outstanding.

### Item 5 — typed storyline dispatch

- Extracted all 32 typed branches into six family modules with explicit selection and a
  shared ephemeral context. The coordinator retains RNG acquisition, future specs, ground-truth
  initialization, and visibility lookup. All extracted execution bodies have identical ASTs to
  original dev; no action-bundle routing or branch ordering changed.
- Shared storyline helper imports resolve during execution, preserving existing instrumentation
  seams without retaining a mocked helper at first module import. The initial standard run exposed
  13 helper-binding failures and one source-location assertion; these were corrected, retaining
  DHCP's exact ownership-wiring assertions at the moved handler location.
- A draft supplemental fixture also caused one initial standard failure (invalid 20-minute warmup).
  Its construction errors were resolved against original dev: use a one-hour warmup and a distinct
  DHCP server. The frozen fixture lives under scripts/fixtures, separate from authored examples.
- Gates: initial focused 154 passed; expanded repeat 360 passed; final standard 8,416 passed,
  27 skipped, 2,009 deselected (303.53 seconds). Ruff, format, manifest revision 46, and harness
  tests passed. All 32 original matrix cases passed during extraction; a final all-format/42
  capture after the helper-binding correction matches both original dev and item 4.
- Added six bounded supplemental cases covering remote sessions, admin/task/service actions,
  DHCP/DNS, locking, process lifecycle, and proxy output across seeds 42/137 and all three targets.
  All six original-build repeats and all six item-5 comparisons passed (28–29 artifacts each).
  Input SHA-256 values are locked in scripts/fixtures/cleanup-inputs.json and checked before capture.
- Items 6–7 and final standard/slow/checkpoint acceptance remain outstanding.

### Item 6 — composed Windows/Sysmon journal infrastructure

- Shared 26 identical spool, journal, owner-fencing, and terminal-cleanup operations through
  source_journal.py. Existing emitter methods forward to the helpers; provider rendering, record
  IDs, causal adjustments, mutable state, lock order, and checkpoint adapters remain in place.
  Provider names are explicit parameters so existing error strings remain exact.
- Gates: 163 focused tests and 181 targeted slow finalization/publication tests passed; standard
  suite 8,416 passed, 27 skipped, 2,009 deselected (291.48 seconds). Ruff/format/whitespace passed.
  Behavior revision 47 validated against item 5.
- All-format/default/42 evidence matches original dev and item 5. All six supplemental cases
  match the frozen original outputs. Original-default/42 checkpoint verification and compatible
  resume reproduce byte-identical evidence with validated provenance.
- No runtime owner or retention policy was added, so no additional scalability soak was warranted.
  Item 7 and final comprehensive gates remain outstanding.

### Item 7 — sequential ownership decomposition

- Protocol stage: moved 82 definitions into common, HTTP, DNS, NTP, proxy, and transport modules.
  The network planner now uses direct imports and its existing executor protocol, with no import
  of the activity-generator module. Generator imports preserve legacy helper entrypoints.
- The first standard run found 11 test-binding/source-inventory failures after the move. Updated
  fault injection at the new owners without weakening assertions. Timing inventories now follow
  the moved callers, retaining the exact 359-call global ceiling. Focused repeat: 224 passed;
  targeted network identity and timing-policy slow tests: 86 passed.
- Protocol standard gate: 8,416 passed, 27 skipped, 2,009 deselected (297.25 seconds). All-format/42
  raw bytes match both original dev and item 6. Expanded checkpoint harness confirms exact-policy
  rejection leaves the checkpoint pointer unchanged; compatible hydration/resume and declared
  behavior-history provenance match with byte-identical evidence.
- Process execution and network stage decomposition remain in progress. Revision 48 is reserved
  for the complete item; it is not yet committed or accepted as a completed item.
- Process stage: creation and termination now execute in bundle-owned services. Their ephemeral
  bindings inject the existing state/dispatch owners (creation additionally binds lifecycle/content
  ownership); helper callbacks still use the existing runtime's timing/configuration services.
  Legacy generator methods forward to the services, and bundles no longer call those adapters.
- Process gates: corrected service-delegation tests retain preflight-before-execution checks;
  557 focused, 15 targeted slow, and 8,416 standard tests passed (295.45 seconds; 27 skipped,
  2,009 deselected). All six supplemental cases match original dev and item 6 directly.

- Network stage: split request resolution, transport planning, protocol/evidence planning,
  prepared publication, commit, and publication into six explicit stages with frozen typed
  intermediate records. These records carry existing references without new durable state or RNGs.
  The existing transaction boundary retains claims, cancellation, timing seals, and recovery;
  persistent SMB and indeterminate-commit recovery paths remain distinct.
- Compared the moved network statements structurally against item 6: control flow and execution
  order are preserved, apart from import placement, direct helper qualification, and one dead
  local assignment. Added executable ownership regression tests for both final architecture gates.
- Network focused gate initially passed 610 tests with one source-inventory failure. Updated that
  inventory to inspect the six stages and assert their exact coordinator order; its existing
  mutation/publication assertions remain. Corrected focused gate: 43 passed. Targeted network
  slow gate: 86 passed. Network standard gate: 8,416 passed (310.58 seconds).
- Final standard gate, including the two new ownership tests: **8,418 passed, 27 skipped,
  2,009 deselected** (300.91 seconds). The 27 skips comprise three opt-in external-parser tests,
  one license-gated Splunk container test, one existing full-engine-only web-access case, and
  22 cases needing the gitignored sample_data directory. No new skips were introduced.
- Final targeted retention soak: **3 passed**, 69 deselected (14.06 seconds), covering 1,000
  capacity-one handoffs each for ordinary, HTTP, and proxy network carriers. The full soak tier
  remains excluded. Item 3 separately passed its 91 configuration soak cases.
- The first complete final slow run reported **1,779 passed, 1 failed** (1,164.83 seconds).
  The failure was the remaining timing source-inventory expectation for the moved network helper
  and transport stage. Updated only those expected source locations; all eight tests in that file
  then passed. The clean complete repeat passed **1,780 tests**, 8,674 deselected, in 1,124.38 seconds.
  The earlier failed run is retained as a failure, not counted as a passing gate.
- A second bounded fixture covers periodic and content handlers (beacon, DGA, DNS tunneling,
  credential spray, port scan, mail, spillage, adversarial payload, and raw events). Its initial
  draft paired Windows logoff was rejected by original dev's process-lifecycle constraints;
  the fixture uses the existing Linux unpaired-logoff fallback instead. The successful original
  inputs were frozen before candidate comparison. No production behavior or golden data changed.
- Final raw-byte comparisons: **44 cases passed** (32 core, six typed-handler supplements,
  six periodic/content supplements). Both seeds and all three targets are included; the core
  all-format cases also cover serial/threaded and full/narrowed formats. Original-build repeats
  passed for every group. Final predecessor comparison passed for all-format/default/42 and all
  six typed-handler supplements. Evidence and ground truth are compared without sorting records,
  normalizing timestamps, or rewriting identifiers.
- Final checkpoint matrix: **12 resumes passed** across seeds 42/137 and default/sof-elk/splunk:
  six original-dev checkpoints hydrate and resume compatibly with byte-identical evidence;
  six same-build checkpoints resume exactly with byte-identical evidence. Exact policy rejects
  all six different-build originals without modifying their checkpoint pointer. Original durable
  checkpoints remain untouched; verification/resume always operates on copies.
- Provenance checks enforce exact field sets, recorded file hashes, seed adoption, run lineage,
  consistent build identities, and the six appended behavior revisions. The compatible change
  classification remains localized. Revision 48 and the unchanged fingerprint algorithm pass
  manifest validation against item 6 and original dev.

## Acceptance artifacts and reproduction

The durable [evidence hash report](2026-09-12-cleanup-evidence-hashes.json) records the original
commit, candidate build identity, dependency lock hash, frozen input hashes, all 44 per-file
comparison snapshots, and the six paired checkpoint cases. Full generated artifacts and command
logs remain in `/private/tmp/eforge-cleanup-evidence` and `/private/tmp/eforge-cleanup-*.log`;
these temporary files are not committed and should be retained if future investigation needs them.
The report is a durable record; the scripts can regenerate evidence using the preserved checkout.

Use the same `.venv/bin/python` for both builds, and fresh output directories for every capture:

```sh
.venv/bin/python scripts/cleanup_output_matrix.py --source /private/tmp/eforge-200-cleanup-baseline --fixtures /private/tmp/eforge-200-cleanup-baseline/tests/fixtures/scenarios --output /private/tmp/cleanup-recheck-baseline
.venv/bin/python scripts/cleanup_output_matrix.py --source "$PWD" --fixtures /private/tmp/eforge-200-cleanup-baseline/tests/fixtures/scenarios --output /private/tmp/cleanup-recheck-final --baseline /private/tmp/cleanup-recheck-baseline
.venv/bin/python scripts/cleanup_supplement_matrix.py --source "$PWD" --output /private/tmp/cleanup-recheck-typed --baseline /private/tmp/eforge-cleanup-evidence/supplement-baseline
.venv/bin/python scripts/cleanup_supplement_matrix.py --source "$PWD" --fixture scripts/fixtures/cleanup-periodic-content.yaml --output /private/tmp/cleanup-recheck-periodic --baseline /private/tmp/eforge-cleanup-evidence/periodic-baseline
.venv/bin/python scripts/cleanup_checkpoint_matrix.py --source "$PWD" --baseline-source /private/tmp/eforge-200-cleanup-baseline --original-checkpoints /private/tmp/eforge-cleanup-evidence/checkpoints --output /private/tmp/cleanup-recheck-checkpoints
.venv/bin/python scripts/report_cleanup_acceptance.py --evidence-root /private/tmp/eforge-cleanup-evidence --output docs/worklog/2026-09-12-cleanup-evidence-hashes.json
uv run pytest
uv run pytest -m slow --no-cov
uv run ruff check .
uv run ruff format --check .
.venv/bin/python scripts/check_generation_behavior.py --base-ref e4035435e8e53400ab25a74fe551313354369203
```

The focused original-checkpoint capture helper accepts `--source`, `--fixture`, `--output`,
`--target`, and `--seed` if the temporary checkpoint fixtures need rebuilding. The core and
supplement matrix scripts can also regenerate original repeatability controls before comparison.

Remaining opportunities are narrower extractions within the still-large process creation service
and network request/protocol stages. They are separate future work: this cleanup establishes the
ownership boundaries while preserving the mature execution and recovery paths.

Final command logs: `/private/tmp/eforge-cleanup-final-standard.log`,
`/private/tmp/eforge-cleanup-final-slow.log` (initial failure),
`/private/tmp/eforge-cleanup-final-slow-repeat.log` (complete passing repeat),
`/private/tmp/eforge-cleanup-final-targeted-soak.log`, and
`/private/tmp/eforge-cleanup-final-checkpoints.log`. Final behavior surface digest:
`bfb6f5cb93f045f2248734740261068f605a9fed3c42251275499a2b1031f0bf` (revision 48).

## Second-pass execution

### Item 1 — foreground ownership

- Active unbounded foreground occupancy is derived from existing process/session state; no new
  durable owner map or invented collection-end termination is introduced. Unknown release means
  later same-shell work is unavailable. Prospective session fences are derived, not cached as
  actual releases, so earlier actual termination can release the shell.
- Removed the misplaced service-local scenario-end lookup along with the original speculative
  release bookkeeping. Generation/telemetry callers now handle unavailable shell slots explicitly.
- Focused tests, matrix attribution, behavior revision, and checkpoint acceptance are pending.

- Revision 49 is localized. Revision 48's preservation claim was incomplete: its service-local
  deadline lookup dropped original dev's fallback reservation. Original dev also incorrectly
  retained speculative collection/session reservations after actual earlier termination.
- Added native eCAR lifecycle captures (eight fixed cases, seeds 42/137, serial/threaded), plus
  six end-to-end shell cases. Native seed 42 demonstrates: original dev reserves 13:12:00.991
  despite no known completion; revision 48 admits a second command at 13:00:30; the correction
  reports no available slot. Earlier real termination now permits the 13:00:30 command,
  including an exact legacy reservation. Separate shells and explicit concurrency remain usable.
- Investigation preserved the existing background-monitor contract: shell preparation explicitly
  adds `&` to tail/watch/follow history, while process argv omits shell syntax. A trial treating
  those stripped arguments as foreground incorrectly blocked later work and was discarded.
  The new six-case scenario reproduces byte-identically under original dev, revision 48, and
  the final item-1 implementation; direct canonical fixtures cover truly unknown foreground release.
- Focused suites passed 578 cases before discarding that background-policy trial; the final
  selection has 576 cases (two redundant trial-only parameters removed). An added completion
  test exposed a datetime-max overflow in legacy matching; skipping impossible candidate deadlines
  fixed it. The manifest's first summary exceeded its 240-character schema limit and was shortened.
- The first two standard runs and core captures were intentionally interrupted during the policy
  investigation. A subsequent standard run stopped making progress at the ASA identifier test;
  it was interrupted for a repeat with faulthandler diagnostics. None counts as a passing gate.
  The initial new scenario draft used unsupported zero traffic rates; it was rejected before
  generation, then corrected to bounded supported positive rates before controls were frozen.

- Full-suite diagnostics isolated an existing ASA weak-reference registry deadlock: cyclic GC
  runs `discard()` while `bind()` holds its non-reentrant lock (stack in standard-4.log).
  The new bounded subprocess regression also times out against preserved revision 48, proving
  the defect predates this pass. The constructor registry now uses an RLock; rendering, state,
  authentication checks, and writer locks are unchanged. Revision 50 records this internal repair
  as impact none. It is included as a small prerequisite to reliable acceptance gates.
- Actual earlier completion now supersedes bounded-process reservations too (sleep 600 terminated
  at 20 seconds), while a remaining pipeline sibling retains its own planned completion fence.
  Only an exact process-owned reservation is removed, using existing finalizer/session state.
- Final focused item-1 process/ASA tests: 650 passed, 2 deselected. Supplemental timing and manifest
  checks: 42 passed. The first full run after the GC fix completed with 8,406 passed and 23 failures:
  it overlapped the final bounded-release edits, invalidating loaded-source inspection and cached
  behavior digests. That run is not an acceptance gate; a fresh run against frozen sources is active.
- Native fixture coverage is now nine cases × two seeds × serial/threaded = 36. All corrected
  state contracts pass. Original and corrected repeatability controls are retained. The corrected
  old-build checkpoint/default/42 resumes to exactly the corrected uninterrupted CLI evidence and
  ground truth; its earlier comparison with original dev correctly failed on Linux eCAR/syslog
  timing. Exact-policy rejection, integrity, migration history, and compatible hydration passed.
- The initial 32 core captures were byte-identical before bounded early-release correction.
  The final core comparison now has intentional differences and is being completed and attributed;
  existing accepted controls are preserved, never rewritten. Final source edits are frozen during
  these gates. Structural baseline inventory is in 2026-09-12-second-pass-structure-before.json.

- Final typed admission regression: rejected foreground work must not emit preparatory bash
  history. Its targeted test failed before moving the existing friction emission behind the
  read-only availability check, then passed. The 196 process/storyline tests passed afterward.
  Full-coverage/42 and all six typed cases stayed byte-identical to the accepted correction.
- **Item 1 acceptance:** standard suite **8,432 passed, 27 existing skips, 2,009 deselected**
  (299.37 s); focused process/ASA **650 passed**; final process/storyline **196 passed**;
  targeted slow timing-policy tests **3 passed, 116 deselected**; both Ruff checks and manifest
  validation against `2c7dee2a` passed (revision 50, digest
  `31ec2940524b29b9efdeb0cd61ef7b15c236574fbd160b6294947aa6e18055b3`).
- The 44 existing cases retain identical ground truth. Eight core cases intentionally change
  only Linux eCAR/syslog: all-format seed 42 full-format runs across the three targets and two
  emission modes; full-coverage/42 (MAIL-01 and WEB-01); Linux SMB/137 (SAMBA-01). All other
  files and all other 36 existing cases are byte-identical to original dev. The early-release
  change is isolated by the preceding 32-case control, which retained the old bounded release
  and reproduced all original bytes. For example, one default/42 sudo `free -m` launch moves
  from 10:00:39.748 to 10:00:39.396, and its child/termination records and time-derived process
  identities follow the corrected launch. Counts, principals, commands, and unrelated sources
  are preserved in that example. This is a scheduling correction, not an output normalization.
- Six new end-to-end shell cases are identical across original dev, revision 48, and correction.
  The native 36-case matrix exercises the intentional differences directly; both original and
  corrected repeatability controls pass. Explicit concurrency is unchanged, unknown release no
  longer admits a sibling, and early completion/termination releases both bounded and unbounded
  commands. Ground truth in those native controls deliberately records the changed admission.
- **All 12 checkpoint resumes passed** (original compatible plus current exact for seeds 42/137
  and default/sof-elk/splunk), using the corrected uninterrupted build as the evidence authority.
  All six originals are rejected under exact policy without pointer mutation. File hashes,
  integrity/hydration, migration history and provenance were verified. The checkpoint matrix
  now accepts `--control-source` to make the selected corrected reference explicit.
- Structural baseline: 46 handler helper-name imports from the coordinator; network records have
  240 field declarations, 240 input-unpack assignments and 78 pure-forward locals (22 in commit);
  process creation/termination consume 53/17 broad runtime members. These are measured by
  `scripts/measure_cleanup_structure.py` for the remaining five items.

### Item 2 — shared shell-history policy

- Item 1 committed as `ffdce735`; its accepted source is preserved separately at
  `/private/tmp/eforge-cleanup-corrected`. The durable corrected evidence reference has 86 cases
  and 12 verified resumes; original controls remain intact.
- EDR shell-history file selection now calls the same predicate as validation and bash generation.
  The surrounding executable/path conditions, lowercasing behavior, and random draws are unchanged.
  Other account classifications remain purpose-specific. Revision 51 declares impact none.
- Item 2 gates pending.

- **Item 2 acceptance:** focused tests **109 passed**; standard suite **8,432 passed, 27 existing
  skips, 2,009 deselected** (291.12 s); Ruff and revision-51 manifest validation passed. All-format
  default/42 plus all six typed-handler captures are byte-identical to the corrected item-1
  reference. The isolated five-account EDR duplicate is removed; validation and both generation
  paths now consume the one shared predicate. Digest:
  `98710feccb126f39e59257e823d199cf0bfc375109ced87fdad4464906803c18`.

### Item 3 — shared storyline process-session resolution

- Item 2 committed as `bd20077e`. Typed process events and command spills now use one
  resolver for account classification, host-scoped reuse, required lifetime, creation, and
  recording. The spill entrypoint remains a forwarding adapter. The typed no-planner path
  retains its unfiltered user-session lookup, newest-host selection, Type 3 creation, and recording.
- Eighteen characterization cases passed before extraction and after it, asserting concrete
  call order and exact RNG state for ordinary users, interactive Linux root, local daemons,
  case-sensitive account classification, built-in/declared services, existing sessions, and fallback.
- Focused session/spill suites: **292 passed**, 29 deselected. All six typed and six periodic
  captures are byte-identical to the corrected reference; the typed six also match item 2.
  The timing inventory now has 358 continuous draw sites (one duplicate removed); its three
  targeted slow tests pass. No executed draw is added or removed on an existing path.
- The first focused invocation named a nonexistent test file and collected nothing; corrected
  paths passed. Ruff initially rejected the sentinel exception's missing Error suffix; fixed.
  Revision 52 and Ruff gates pass; standard suite pending.
- **Item 3 acceptance:** standard suite **8,450 passed, 27 existing skips, 2,009 deselected**
  (292.56 s). Both Ruff checks, revision-52 manifest validation against `bd20077e`, 292 focused
  cases, three targeted slow inventory cases, and the 12 evidence cases pass. Digest:
  `baf280f1c716f03d4e47edafcf3cc35bdee73626dd9d6ade146b5dfb63ec161d`.

### Item 4 — one-way handler helper dependencies

- Item 3 committed as `233bbf7a`. Twenty-eight shared helper implementations now live in four
  focused IDS, HTTP, process parsing, and periodic modules. Coordinator exports retain explicit
  aliases, while execution references the owning modules. The 46 runtime helper-name imports
  back from typed handlers to the coordinator are gone; annotation-only imports remain.
- AST comparison confirms all 28 moved function bodies are unchanged. Regression checks enforce
  the dependency direction and alias identity. Periodic tests patch the actual helper owner;
  the slow timing inventory changes source paths only. Preparation included a transient syntax
  error from an overly broad annotation edit; it was corrected before running acceptance tests.
- **Item 4 acceptance:** focused **372 passed**; standard **8,452 passed, 27 existing skips,
  2,009 deselected** (297.17 s); targeted slow timing inventory **3 passed**. Both Ruff checks
  and revision-53 manifest validation against `233bbf7a` pass. Six typed and six periodic cases
  match both item 3 and the corrected reference; all-format/default/42 matches the corrected
  reference too. Digest: `a37351d86be543418deebf730b4ba6b746d7c5032db6df1bb07840b6f343d2d6`.

### Item 5 — composed network stage interfaces

- Item 4 committed as `5858a0a8` and preserved in a detached comparison checkout. Stable request
  facts, endpoint identity, protocol inputs, existing application intents, canonical publication
  inputs, and prepared source work now travel as composed records. Changed fields remain explicit
  local variables until their phase returns revised records; unchanged groups travel by reference.
- Field declarations fall from 240 to 129, top-level input unpacks from 240 to 39, and locals
  used only for forwarding from 78 to **zero**. The remaining unpacks name actual phase work or
  shared groups. All five downstream stages retain their exact branch and return counts.
  AST comparison confirms every non-stage planner method and the transaction boundary are unchanged.
- New integration tests observe the actual six-stage path, one shared boundary, shared facts and
  publication objects, and the authenticated final receipt. Failures injected immediately before
  commit and immediately after commit preserve the distinct cancellation and committed recovery
  outcomes. Existing fault coverage runs against the new grouped inputs too.
- Initial extraction tooling expected an absolute import where the planner used a relative import;
  corrected before tests. Three unused group aliases were removed after lint inspection.
- Focused **46 passed**, 83 deselected; targeted slow network/timing **86 passed**, 46 deselected.
  Ruff checks and revision-54 manifest validation pass. Standard and expanded byte gates pending.
- **Item 5 acceptance:** standard **8,455 passed, 27 existing skips, 2,009 deselected**
  (308.45 s); focused **46 passed** and targeted slow **86 passed**. All **44 existing matrix
  cases** match both the preserved item-4 checkout and accepted corrected reference byte for
  byte. File sets, ground truth and manifest-listed hashes are unchanged. Both Ruff checks and
  revision-54 validation pass; digest
  `fbd9b98cf01a5e94bc0bffe752e547ee80a891afc9bbaabf2e81a814b16ba7e7`.

### Item 6a — shared process command normalization

- Item 5 committed as `5bcad92d`. Preflight and execution share one pure image/command/executable
  normalizer. The later duplicate Defender-path rewrite was removed after verifying no intervening
  assignment can change the image. Actor revalidation and deliberately different timing paths remain.
- Nine native Windows process cases × seeds 42/137 × serial/threaded emission add **36 controls**
  for batch scripts, unchanged non-batch scripts, PSEXESVC and Defender paths, persistent/browser
  reuse, preferred-browser precedence, exact parents, and source-deadline rejection. All match
  original dev and the accepted pre-process source (`5858a0a8`); the pre-process control repeats
  exactly. The initial eight-case draft is retained separately; the added batch case was frozen
  before process production edits. Native drivers are hash-locked, and both native matrices now
  use one shared runner. The durable process-reference JSON records every file hash.
- Focused normalization/process tests: **155 passed**, 60 deselected. Candidate process **36/36**
  and foreground **36/36** raw comparisons pass; all-format/default/42 and six typed cases also
  match item 5. The expanded final evidence matrix is now **122 cases** (44 original, six shell
  scenarios, 36 foreground native and 36 process native).
- Initial preparation lint caught a now-redundant normalizer call and import order; corrected.
  The first focused invocation named a nonexistent test file and ran no tests; correct paths pass.
  Both Ruff checks and revision-55 manifest validation pass; standard suite pending.
- **Item 6a acceptance:** standard **8,455 passed, 27 existing skips, 2,009 deselected**
  (300.39 s), focused **155 passed**, all **79 selected byte cases** passed (72 native plus
  all-format/default/42 and six typed), and both Ruff checks pass. Revision-55 digest:
  `a4005912398a4efceca4c1cce7f1513d1aa62e7f7baf2d90015381924e8e9345`.

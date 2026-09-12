# Behavior-preserving 2.0.0 cleanup

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

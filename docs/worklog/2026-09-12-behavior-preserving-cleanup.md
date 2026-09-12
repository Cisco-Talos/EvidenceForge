# Behavior-preserving 2.0.0 cleanup

## Final process-ownership pass — complete

All three remaining opportunities are complete in four independently gated implementation commits
on `codex/2.0.0-code-cleanup`, starting from clean
`010ae90ff3dc345d5f05224345c4d529b87fe37a`: platform parent policies, the 35 selected internal
forwarding calls, explicit preflight ownership, and staged planning/reservations.
The corrected foreground behavior is preserved. No evidence exception, golden update,
package/dependency/schema change, fingerprint-policy change, merge or release was introduced.

Final acceptance passes: **8,489 standard tests** (27 unchanged existing skips), **1,780 slow
tests**, **194 raw-byte comparisons**, **18 successful checkpoint resumes**, **12 older-build
exact-policy rejections**, **seven targeted retention soak tests**, both Ruff checks and behavior
validation against the previous item, `010ae90f` and original dev. Full soak is excluded as agreed.
Artifact hashes and field-level provenance were verified; the final report is
`2026-09-12-process-ownership-evidence.json`. Final acceptance below supersedes historical pending
notes; all failed attempts and repairs remain recorded.

The starting checkout is preserved at `/private/tmp/eforge-cleanup-process-baseline`.
The existing 122 byte controls and 12 resumes re-verify, with a fresh verification report at
`/private/tmp/eforge-cleanup-pass3-existing-controls.json`. The frozen source hashes, parent
method inventory and 35 call sites across 20 generator methods are recorded in
`2026-09-12-process-cleanup-baseline.json`.

New native controls cover 18 parent/preflight paths × two seeds × serial/threaded emission.
The first driver draft incorrectly treated `RunningProcess` as a Pydantic model; the first
matrix draft omitted Linux PID 1. These setup errors were fixed before freezing accepted controls.
The first 15-test characterization run also had setup errors (the state map name and Linux
bootstrap parent); its repeat passed 13 and failed two because assigning `end_time` bypassed
canonical termination indexes. The fixtures now call the existing `StateManager.end_process`.
All these attempts occurred before production edits; no expected production behavior was changed.

### Parent extraction acceptance attempts

The frozen additional reference contains 72 repeatable cases (18 paths, two seeds,
serial/threaded), expanding 122 controls to 194. A draft module-plan serializer also failed;
its concurrent repeat was stopped (exit 130) before correcting and freezing the driver.
All draft captures and logs remain available; accepted reference hashes are in
`2026-09-12-parent-preflight-reference.json`.

The initial parent split passed 516 focused tests, 15 timing slow tests and 60 parent/publication
slow tests. All 162 native/supplement byte cases passed. The standard run passed 8,483 tests
and failed one documentation first-reference trademark check, with 27 existing skips.
The core matrix stopped at Linux SMB seed 42: a missing scenario-start binding skipped visible
Linux shell materialization and changed parent IDs and dependent evidence. Acceptance was blocked.
The helper now explicitly receives the current scenario start; two bounded tests cover the
materialization guard, and the failing SMB case again matches all 25 artifacts byte for byte.
The documentation first reference was corrected. No baseline or expected evidence changed.

Platform policy also owns the remaining Windows account/session fallback operations, invoked
at the existing shared branch points. Shared history and active-shell querying have dedicated
owners so platform helpers never call back into the parent coordinator. Final parent gates
are being rerun after these changes.

### Item 1 accepted — platform parent policies

Final parent gates: 57 focused tests, **8,486 standard tests passed**, 27 existing skips,
2,010 deselected (301.33 seconds); **75 targeted slow tests passed**, two deselected
(15.73 seconds); both Ruff checks, whitespace and revision-59 manifest validation against
`010ae90f` pass. All **194 raw-byte controls** match their frozen corrected baseline, with
manifest hashes verified. No checkpoint resume is claimed at this boundary; six fresh revision-58
checkpoints have been preserved for the final 18-resume gate.

The shared coordinator is 1,400 lines (previously 2,074), retaining 26 existing signatures plus
three ephemeral helper bindings. Windows policy is 826 lines with six explicit dependencies;
Linux policy is 249 lines with seven; shared history is 76 lines with three. Shared active-shell
querying moved into the existing query owner. Total lines increase because the compatibility
adapters and explicit bindings remain; the improvement is single policy ownership, not fewer
lines. Helpers contain no generator reference or callback into the parent coordinator.
The 35 internal forwarding calls remain intentionally unchanged until item 2.

Representative paths: shared explicit-parent validation → platform existing fallback; shared
account/session classification → Windows role policy; shared spawn rules → Linux shell/service
selection → shared recursive chain materialization. The Linux observation-start binding now
covers both warmup-parent reuse and visible-shell materialization.

Final source digest: `bdde3219a09aa938f04c826e517b64c070cf24f1b4229e3c6cae0650c458e2f7`.
Report: `2026-09-12-process-parent-evidence.json`, SHA-256
`daf6ece96b2e953206b94a0d5a3b39d8ff07c7b4c51ce23e5cb5c4beeffdcd53`.
Logs: `/private/tmp/eforge-cleanup-pass3-item1-final-{standard,slow,core,native,supplements}.log`
and `/private/tmp/eforge-cleanup-pass3-parent-final-focused.log`.

### Item 2 acceptance — internal parent calls

Item 1 is committed as `788c3680`. Item 2 migrates exactly the frozen 35 calls across
20 generator methods, preserving every argument expression (none contains a nested call)
and binding a fresh parent owner at the existing operation point. All old forwarders remain.
Revision 60 uses digest `d8e9447c3fb1787a6c3dc137b84b05a763d09dae6406df0b3a38f633f8646de1`.
The complete 194-case matrix matches both `010ae90f` and the preceding parent commit.
The measured remaining frozen forwarding-call count is zero.

The first standard run passed 8,482 tests and failed four fixture interceptions: two bounded
application-catalog cases, the outbound mail worker fault, and a minimal Linux pipeline fixture
still mocked the generator forwarders. Their stubs now target the parent owner; assertions,
expected timing, error and residue behavior are unchanged. All 44 affected caller tests pass.
The standard suite is being repeated before committing; 63 other focused tests and both Ruff
checks already pass. First-run and repeat logs are retained separately.

Before preflight extraction, two additional reservation characterizations were exercised against
the current implementation: repeated cleanup and failure after new reservations while preserving
a caller-supplied token. The first draft tried to patch a read-only slotted manager method and
failed one test; class-level fault injection corrected the fixture. Both tests now pass, with no
production change. Drafts/logs remain under `/private/tmp/eforge-cleanup-pass3-preflight-extra-*`.

### Item 2 accepted — direct internal parent ownership

The standard repeat passed **8,486 tests**, with 27 existing skips and 2,010 deselected
(286.63 seconds). Together with 63 focused tests, 44 caller tests, both Ruff checks,
revision-60 validation against `788c3680`, and 194 raw-byte comparisons against both references,
all item-2 gates pass. No targeted slow run was required for this forwarding-only migration.
The first failed standard attempt remains recorded above; no production regression or changed
expected evidence was accepted.

Report: `2026-09-12-process-parent-callers-evidence.json`, SHA-256
`ed5ec27cc872b7627bd6a6107beaf1f128a53644a56b994252e46c43197daa0a`.
Logs: `/private/tmp/eforge-cleanup-pass3-item2-{focused,caller-tests,standard,standard-repeat,
core,native,supplements}.log`. Existing adapters and all public family action interfaces remain.

### Item 3a acceptance — explicit process preflight owner

Item 2 is committed as `c72b3a4f`. `ProcessPreflightPlanner` now owns bounded source-deadline
admission, command/endpoint planning, lifetime previews, scoped endpoint RNG construction,
and uncommitted artifact cleanup. Its 11 explicit dependencies are existing state/timing/
dispatch/content owners, four existing process owners, and narrow reuse/scanner capabilities.
No generator object or new durable state is introduced. Generator hooks and the scanner-count
entrypoint forward; eight implementations shrink from 785 generator lines to 65 forwarding lines.
The shared file-action mapping and process artifact-owner classifier moved to existing pure policy.

Scratch extraction drafts had relative/duplicate-import and indentation issues; these were fixed
before production extraction. The first focused production run passed 563 and failed four tests
that still patched the old RNG owner or inspected the generator implementation. Patches and source
inspection now target the planner; expected evidence and assertions remain unchanged. The repeat
passed **567 tests**, four deselected (11.04 seconds). **78 artifact rollback/recovery tests** pass
(4.44 seconds), as do **75 targeted slow timing/parent checks** (14.94 seconds). A new bounded
retention soak passes 1,000 prepare/cancel operations with no live planner references, reserved
slots, prepared/claimed publications, or canonical artifact/process residue (1.87 seconds).

Revision 61 uses digest `bf62dcb13a743846cec4b2b300cb40dc1849d35e059b5ffc9a60ffff212a56cb`.
Both Ruff checks and manifest validation against `c72b3a4f` pass. Standard tests and the complete
194-case byte matrix are running; this item is not committed or accepted yet.

### Item 3a accepted — preflight implementation ownership

The complete standard suite passes **8,489 tests**, with 27 existing skips and 2,011 deselected
(300.15 seconds). All **194 raw-byte cases** match `010ae90f` and `c72b3a4f`, with artifact
hash verification. Combined with 567 focused, 78 rollback/recovery, 75 targeted slow tests,
the 1,000-operation reservation soak, both Ruff checks and revision-61 validation, all owner
extraction gates pass. No changes to prepared-result types, bundle cleanup placement, optional
hook discovery, execution publication/commit boundaries or checkpoint representations were made.

Report: `2026-09-12-process-preflight-owner-evidence.json`, SHA-256
`407b4cbd93dd5f47c71d20a43a096a82b88524e26c6fa3d1c3980b88e0fe2e3c`.
Logs: `/private/tmp/eforge-cleanup-pass3-item3a-{focused,focused-repeat,standard,core,native,
supplements,recovery,slow,reservation-soak}.log`. The two endpoint-preparation failure scopes
are still intact; separating their cohesive operations is the next independently gated substep.

### Item 3b / final acceptance — in progress

Item 3a is committed as `e65109ce`. Preparation now follows six explicit operations in its
original order: actor/effect selection (277 lines), allocation-free endpoint/cohort validation
(29), endpoint artifact reservation (85 after correcting the issue below), lifetime/deadline
preview (49), root-binary reservation (69), and existing prepared-result assembly. The coordinating
side-effect method shrinks from 540 to 62 lines. Three ephemeral records carry only produced
values (five selection fields, three reservation fields, two lifetime fields); runtime owners,
mutable drafts and RNGs are not copied into these records.

The first focused run passed 566 and failed the new caller-token regression: an extracted local
`newly_reserved` declaration shadowed the preparation-owned list, so a later lifetime rejection
left one new token reserved. Removed that declaration; both reservation stages now append to the
same preparation-local list, and the original two exception scopes remain intact. The repeat
passes **567 tests**, four deselected (10.42 seconds). No expected value or golden evidence was
changed to accommodate the failure. The existing registry source-inspection assertion now points
to the effect-selection operation containing that unchanged logic.

Final-source **78 rollback/recovery tests** pass (3.87 seconds), and **seven targeted retention
soak tests** pass (48.00 seconds), including the new 1,000-cycle reservation cleanup check.
Full soak remains excluded. Revision 62 uses digest
`52f9757f67793ce4771f6b93cc9aeeebe826d10f01553f7dfc1d4458774a8180` and validates against
`e65109ce`, `010ae90f` and original dev `e4035435`; both Ruff checks pass.
Full standard/slow suites, 194 byte comparisons and the expanded 18-resume checkpoint gate are
running against this frozen production source. Item 3b is not yet accepted or committed.

Final candidate prefix: `/private/tmp/eforge-cleanup-evidence/pass3-final`.
Final checkpoint root: `/private/tmp/eforge-cleanup-evidence/pass3-final-checkpoints`.
The six preserved `010ae90f` checkpoints are in `pass3-baseline-checkpoints`, alongside the
preserved original-dev checkpoints. Final logs use `/private/tmp/eforge-cleanup-pass3-final-*`.

### Final process-ownership acceptance and review

All requested final gates pass on the frozen revision-62 source:

| Gate | Result |
|---|---|
| Full standard suite | 8,489 passed; 27 existing skips; 2,011 deselected; 311.56 seconds |
| Full slow suite | 1,780 passed; 8,747 deselected; 1,136.22 seconds |
| Final focused process tests | 567 passed; four deselected; 10.42 seconds |
| Final artifact rollback/recovery | 78 passed; 3.87 seconds |
| Targeted process/network retention soak | Seven passed; 108 deselected; 48.00 seconds |
| Frozen evidence and ground truth | 194 cases match both `010ae90f` and the preceding accepted commit |
| Checkpoint hydration/resume | Original dev compatible: six; revision 58 compatible: six; final exact: six |
| Older-build exact policy | 12 rejections; checkpoint pointers unchanged before compatible retries |
| Ruff / whitespace / behavior history | All pass; revision 62 validates against `e65109ce`, `010ae90f`, `e4035435` |

The 27 skipped test identities were compared with the previously accepted standard log and are
identical: three external parser checks, one optional Splunk integration, one full-engine web-access
case and 22 external sample-data checks. No new skip was introduced. The full soak tier and release
coverage gate are outside this feature-branch scope. An optional OS process-status probe was denied
by the sandbox; completed pytest logs and tool exit statuses independently confirmed the gates.

The final raw-byte/provenance verification was repeated after all tests completed, and the report
itself was byte-identical. Report SHA-256:
`b91f1885d83db5ab3fdde8d2940aa28040a8e702f239bbeac0fa7f71f654448d`.
It records every case's actual file hashes, all 18 resume artifact sets, 12 exact-rejection log
hashes, frozen input hashes, the original caller inventory, baseline dependency access counts and
current owner fields/operation sizes. The package version and dependency declarations were also
compared as raw bytes with `010ae90f` and are unchanged.

| Structural measure | Before | After |
|---|---|---|
| Shared parent coordinator | 2,074 lines | 1,400 lines; shared ancestry, history coordination and recursive/service-worker materialization remain here |
| Platform parent policy | Embedded in coordinator | One Windows helper (six explicit inputs), one Linux helper (seven), shared history helper (three) |
| Frozen internal parent forwarding calls | 35 across 20 methods | Zero; all compatibility forwarders remain available |
| Generator preflight implementation | 785 lines across eight methods | 65 forwarding lines; implementation belongs to `ProcessPreflightPlanner` |
| Preflight preparation coordinator | 540 lines | 62 lines following the six preparation phases |
| Preflight dependency contract | 18 direct generator attributes, including internal helpers, plus one optional cutoff attribute | 11 named current-owner/capability inputs; no broad generator field |

The dependency counts describe different interface shapes, not a claim that eight independent
runtime authorities disappeared. Existing state, timing, registry, cache and lifecycle owners
remain authoritative. The new records contain only phase results. No planner retains independent
state or RNGs; current bindings and zero retained services/reservations are exercised by the
replacement-owner tests and retention cases.

Representative final paths are shared parent validation → platform policy → shared recursive
materialization; direct internal caller → fresh parent owner; and bounded admission → actor/effect
selection → allocation-free endpoint/cohort validation → endpoint reservations → lifetime/deadline
preview → root-binary reservation → existing prepared result → unchanged bundle execution and cleanup.
A failure during endpoint reservation uses its existing inner cleanup scope. A later lifetime or
root-binary failure uses the existing outer scope over the same local new-token list. Explicitly
supplied tokens stay outside that list. Publication and canonical commit remain execution-owned.

Residual complexity is deliberate: shared ancestry repair remains substantial, effect selection
still contains the existing file/module/registry branches, and compatibility/public action adapters
remain. This pass completes its three opportunities without a broader adapter purge or a change to
those policies. Raw evidence, ground truth, corrected foreground behavior, checkpoint representations,
and compatible/exact policy behavior remain preserved by the exercised gates.

Implementation history: `788c3680` (platform parents), `c72b3a4f` (35 internal calls),
`e65109ce` (preflight owner), followed by the final `refactor: stage process preflight reservations`
commit containing revision 62 and this acceptance record. Final logs are
`/private/tmp/eforge-cleanup-pass3-final-{standard,slow,core,native,supplements,checkpoints,
recovery,retention-soak}.log`; the staged-preflight focused attempts use
`/private/tmp/eforge-cleanup-pass3-item3b-focused{,-repeat}.log`.
All earlier checkouts, captures and reports remain preserved. Delivery is the dedicated branch;
no merge or release is part of this effort.

## Second-pass final status

The first-pass preservation claim below is limited to its exercised matrix. Review found a
misplaced scenario-deadline lookup in the process service. The user authorized a six-item second
pass: correct foreground ownership against real process/session behavior, then consolidate shell
policy, storyline session resolution, handler helpers, network stage records, and process services.
Original dev remains a comparison reference, not the correctness authority for the correction.
The first-pass checkout is preserved at `/private/tmp/eforge-cleanup-first-pass` (`2c7dee2a`).
All six second-pass items are complete on `codex/2.0.0-code-cleanup`. Final gates pass:
**8,468 standard tests** (27 existing skips), **1,780 slow tests**, **122 frozen byte comparisons**,
**12 checkpoint resumes**, **six targeted retention soak tests**, both Ruff checks, artifact-hash
verification and behavior-manifest validation. Full soak remains excluded as agreed.
No dependency/version/checkpoint-schema or fingerprint-algorithm changes, merge, or release were
made. Original checkpoints remain load-compatible; exact policy still rejects a different build.

Revision 49 records the intentional foreground correction. Eight original matrix cases change
only Linux eCAR/syslog evidence; the remaining original evidence and ground truth stay identical.
All subsequent refactors match the accepted corrected references byte for byte. The final
structural review, measured counts, limitations, hashes and reproduction tools appear below.
This final status supersedes historical pending notes; failed and interrupted attempts remain
recorded for handoff. Original dev and first-pass preservation claims do not override the
foreground lifecycle correction.

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

### Item 6b — shared process reuse decisions

- Item 6a committed as `2ebd6d09`. Eight precedence/visibility characterization tests passed
  before this extraction. Bounded preflight and ordinary execution now share one selection
  implementation, preserving singleton, service, persistent-application and browser precedence.
  Explorer bootstrap remains unavailable to preflight. Bounded reuse token revalidation moved
  into the process service; generator entrypoints remain adapters.
- Completion bookkeeping is shared: source checks, optional-effect auditing, and the deliberately
  different activity-update rules retain their existing order. Authenticated bounded reuse skips
  redundant visibility checks only after its original full token/actor/precedence revalidation.
- The first focused run failed 68 cases because the moved reuse token was imported from a package
  that does not re-export it. Importing its defining module fixed the error; the repeat passed
  **163 tests**, 60 deselected. Targeted slow process/lifecycle tests: **60 passed**, 155 deselected.
  Standard and byte gates are running against frozen production sources.
- **Item 6b acceptance:** standard **8,463 passed, 27 existing skips, 2,009 deselected**
  (294.66 s); focused **163 passed**, targeted slow **60 passed**; both Ruff checks and
  revision-56 validation pass. All **79 selected byte cases** match both item 6a and frozen
  corrected references. Digest:
  `5027a78fa82410da461c82599a38ee488ef1b3d583e5c7182bd5d99285cdb611`.

### Item 6c — explicit process preparation and publication

- Item 6b committed as `79529f46`. Creation now coordinates admission, actor resolution, launch
  and parent planning, exact root planning, canonical evidence preparation, source/artifact
  preparation, publication, and post-publication bookkeeping. Each operation receives the records
  it consumes; unchanged actor/root identities travel by reference. Due lifecycle closes still
  commit before root allocation planning and source timing preparation.
- The two existing cohort/materialization commit paths retain their claim order, cleanup and
  publication handling. Two new integration cases inspect the actual publication boundary:
  preparation has no root in State or emitted root row, and publication commits both State and
  timing before post-launch work. Existing fault tests cover artifact and cohort rejection.
- Focused **165 passed**, 60 deselected; targeted slow timing **12 passed** and RNG inventory
  **3 passed**. The first timing invocation selected no tests because that file is slow-tier;
  the explicit slow repeat passed. Inventory entries name the new evidence/publication operations.
- All **79 selected raw-byte cases** match item 6b and their accepted corrected references.
  Both Ruff checks and revision-57 manifest validation pass. Digest:
  `5080fb93deec21296908ef1499ed6a06bcbed2494272556b9f49ee1dd21ff8f1`.
- **Item 6c acceptance:** standard **8,465 passed, 27 existing skips, 2,009 deselected**
  (296.56 s). All focused, slow timing, lint, manifest and selected byte gates passed.

### Item 6d — explicit process owners and current capability bindings

- Item 6c committed as `7a28bbda`. Creation and termination services no longer import, accept,
  or hold a broad generator object. The bundle asks its provider for a freshly bound service.
  Process actors, canonical State queries, parent/service chains, reuse, launch scheduling,
  foreground lifecycle, source timing and endpoint evidence now have focused implementation owners.
  System-process execution and image-load implementation moved too; generator entrypoints forward.
- This moves 108 generator method implementations, 26 module-level policy definitions and eight
  class policy sets into process-owned modules. All dictionaries, caches, RNGs and lifecycle,
  timing, identity and publication authorities stay on their existing owners. Factories bind
  current references on each call, including after hydration or watermark replacement. Existing
  lazy source-cache initialization remains on the generator binding boundary.
- Remaining cross-family capabilities are 16 typed callbacks for host/user identity, shared
  activity timing, session bootstrap/teardown, collection visibility, scanner requests and public
  process action requests. They do not reproduce the old 53-member creation/17-member termination
  generator interface. Session teardown's ContextVar and exact generator-owner authentication
  remain with the session implementation; process operations ask that owner about frozen closes.
- Initial extraction diagnostics caught missing/relative imports, a generated annotation typo and
  a misplaced declaration block; these were fixed before acceptance tests. The first focused run
  still patched the old reuse owner; the next identified four old service-factory patches and one
  parent fault-injection patch. Updating the patch locations preserved all behavioral assertions.
- Focused process/activity **630 passed**, 62 deselected; separate process/cache retention
  **21 passed**; timing inventory/claim-order slow **15 passed**. A mistaken ownership-test command
  named nonexistent files and collected nothing; the corrected invocation ran the 21 real cases.
- The first full standard run was **9 failed, 8,458 passed, 27 existing skips, 2,009 deselected**.
  Those failures were partial `object.__new__` fixtures or patches at former helper locations.
  Tests now construct initialized owners and patch actual source-timing/SSH/foreground helpers.
  No expected values were changed. A repeat found one more nested partial fixture; the complete
  affected group then passed **178 tests**. The full standard gate is being repeated.
- All **122 frozen byte cases** and **12 checkpoint resumes** pass. The final report re-verifies
  each file set, every raw evidence/ground-truth hash, manifest-listed hashes, and the exact
  field-level resume/provenance policy. Seventy-nine relevant cases also match item 6c directly.
  Original-build exact policy rejects all six older checkpoints without rewriting their pointers;
  compatible policy hydrates them and yields the corrected uninterrupted reference.
- Targeted network retention soak: **5 passed**, 68 deselected (44.29 s), including 45 simulated
  days and capacity-one ordinary/HTTP/proxy publication. Targeted process soak: **1 passed**,
  2 deselected (4.76 s), covering 960 create/terminate lifecycles over 30 simulated days. At days
  7 and 30 no ephemeral services remain reachable; source/terminal caches drain and successive
  operations bind the replacement watermark-owned dictionaries.
- Revision 58 validates against both item 6c and original dev. Digest:
  `1f5580ec1a92690365240ba80e90e64fad178c2beb46158c6a654cf17f9ab84b`.
  Full slow release gate is running; full soak remains excluded.
- The repeated standard gate passed **8,467 tests**, 27 existing skips, 2,010 deselected
  (309.46 s). Final inspection then identified an unseeded-generator edge: binding a missing
  `_system_pids` to a temporary dictionary could retain that fallback across helper calls. The
  binding now carries absence explicitly and obtains the original fresh fallback for each read;
  an actual seeded role table still passes by reference. A new integration check confirms that
  canonical systemd materialization creates no parallel role table on the ephemeral service.
- The first full slow run was deliberately stopped (exit 143) before that final production edit;
  it is **incomplete**, not passing. Its 60-second faulthandler reports came from long-running
  medium-dataset/iteration tests, not assertion failures. All final gates are rerunning in fresh
  `pass2-final2-*` captures; the earlier passing captures and report remain preserved separately.
  Final focused repeat: **631 passed**, 63 deselected.
- The first exploratory process-soak probe omitted its `EventDispatcher` and failed before
  parent publication. Supplying the production-shaped dispatcher corrected the probe setup.
  The final-source targeted retention repeat passes **6 tests**, 71 deselected (51.62 s).

### Final structural review

| Contract | Before this pass | Final implementation |
|---|---|---|
| Shell-history eligibility | Shared predicate plus an EDR duplicate | One predicate used by validation and both generation paths |
| Storyline process sessions | Separate typed and spill decisions | One resolver, with the existing no-world-planner fallback |
| Handler imports of coordinator helpers | 46 imported helper names | 0 runtime helper imports back to the coordinator |
| Network stage fields | 240 declarations / 240 top-level unpacks | 129 declarations / 39 group or phase unpacks |
| Network locals used solely to forward fields | 78 | 0 |
| Broad generator members used by create/terminate services | 53 / 17 | 0 / 0 |
| Process implementation ownership | Generator callbacks behind the services | 108 moved methods and explicit State/timing/lifecycle/evidence owners |

The 16 remaining typed callbacks cross actual shared-identity, timing, session, scanner or
public action-request boundaries. They are not a renamed generator facade. All creation,
termination, system-process and image-load implementations now live in process-owned services;
generator methods preserve forwarding entrypoints. Services retain no independent RNG or durable
cache. The serialized runtime owners and fingerprint algorithms are unchanged.

Representative paths checked:

- Typed process and standalone command spill → common session resolver → existing process bundle.
  Interactive root, local daemons, existing-session precedence and absent world planner retain
  their prior branch order and exact RNG state.
- Ordinary process → admission → actor → launch/parent → independent due closes → exact root
  plan → canonical evidence → prepared publication → original commit boundary → bookkeeping.
  Reuse can return before root allocation; exact-parent and visibility rejection remain intact.
- Network → request resolution → transport planning → protocol evidence → publication preparation
  → commit → publication. The same transaction boundary owns all claims, cancellation, timing
  seals and recovery. Before-commit rejection and after-commit recovery remain distinct.
- Occupied Linux shell → existing process/session lifecycle lookup. Unknown completion blocks
  sequential work; actual termination or teardown releases it. Collection cutoff creates no close.
  Explicit concurrency and other shells retain their existing independent paths.

Remaining opportunities are narrower follow-ups: separate Windows and Linux parent-selection
policy within the large parent owner, and migrate additional callers from compatibility adapters
to the focused owners where that improves clarity. The existing preflight endpoint-effect planner
and artifact-reservation cleanup entrypoints also remain in the generator; this pass shares their
normalization, actor and reuse decisions with execution, but does not extract that separate
artifact-planning coordinator. The creation/termination services and their process helpers consume
the explicit owners described above. These remaining areas are outside the dependency count,
which measures the creation and termination services specifically.

### Final-source acceptance results

The final source is frozen at behavior revision 58 with surface digest
`d9cafeb7c0b89b37c6868472fb1a685235dc57f008b5b0e825033a6b7bf37c9c`.
The earlier revision-58 digest above describes the superseded pre-fallback capture, not this
accepted source. All final captures use the new, separately preserved `pass2-final2-*` prefix.

- Standard: **8,468 passed, 27 existing skips, 2,010 deselected** (312.76 s).
- Full slow suite: **1,780 passed, 8,725 deselected** (1,155.62 s). This is the complete
  `uv run pytest -m slow --no-cov` gate against the final source, with no skips or failures.
- Focused process/activity: **631 passed**, 63 deselected (11.43 s).
- Behavior compatibility, RNG inventory and timing/claim contracts: **38 passed** (14.16 s).
- Targeted process/network retention soak: **6 passed**, 71 deselected (51.62 s).
- Both Ruff checks pass: **833 files already formatted**. Whitespace validation passes.
- Behavior-manifest validation passes against item 6c (`7a28bbda`) and original dev (`e4035435`).
- Expanded matrix: **122 raw-byte comparisons pass** against the accepted corrected references;
  **79** relevant captures also match item 6c directly. No additional evidence or ground-truth
  differences were accepted during items 2–6.
- **12 checkpoint resumes pass**: six original-build compatible resumes and six same-build exact
  resumes. The six original checkpoints are also rejected under exact policy. Integrity, actual
  manifest-listed artifact hashes and the field-level provenance allowlist all verify.
- Final structural inventory was recomputed and matches the source. Version, dependency,
  checkpoint-schema and fingerprint-algorithm files are unchanged from the first-pass endpoint.
- **All final acceptance gates pass.** The full soak tier was excluded as agreed; the six
  relevant retention soak cases ran. The 27 standard skips remain the existing three SOF-ELK®
  parser integrations, one Splunk integration, one full-engine web-access case and 22 external
  sample-data checks. No new skips or changed golden expectations were introduced.

The final machine-readable reports are:

- `2026-09-12-second-pass-evidence.json`: SHA-256
  `97e61e2c86eeddd3bf96b0802430f5bef615a26dbadfc4095be639c0701f47ae`.
- `2026-09-12-second-pass-structure-comparison.json`: SHA-256
  `4244d8eeaf52c0e9db469140b53c517896cc63bfb99b199aae7b7de523ec8f2b`.

Final logs are `/private/tmp/eforge-cleanup-pass2-final2-{standard,slow,core,native,supplements,
checkpoints,behavior-timing,retention-soak}.log`; the focused final-source log is
`/private/tmp/eforge-cleanup-pass2-item6d-focused-final-2.log`. Frozen captures and original,
first-pass and accepted corrected checkouts remain in their recorded `/private/tmp` locations.

Delivery remains the dedicated branch. Items 1–5 and process substeps 6a–6c are recorded in
`ffdce735`, `bd20077e`, `233bbf7a`, `5858a0a8`, `5bcad92d`, `2ebd6d09`, `79529f46`, and
`7a28bbda`; the final capability-binding substep and this acceptance record are delivered together
as `refactor: bind process services to explicit current owners`. No merge or release is part of
this effort.

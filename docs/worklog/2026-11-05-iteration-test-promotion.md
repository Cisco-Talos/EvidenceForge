# Mac-inclusive iteration-test promotion

The user authorized correcting the scenario-authored Mac timing findings and
replacing the canonical `iteration-test` with the Mac-inclusive version, while
preserving the old version for reference. This supersedes the earlier assessment
instruction to leave those authored timings unchanged. No engine behavior changed.

## Sources and preservation

- Active: `scenarios/iteration-test/scenario.yaml`, retaining its original identifier
  and output destination. Scenario 2.0, the pinned package industry
  `evidenceforge/technology@1.0.0`, separate environment/baseline includes and the
  adjacent relative email corpus are retained.
- Exact pre-Mac snapshot: `tests/fixtures/scenarios/iteration-test-pre-macos/`.
  Its five authored files (scenario, environment, baseline, corpus and environment
  briefing) are byte-identical to the previous canonical files. `ORIGIN.json` seals
  their SHA-256 hashes; the scenario hash is
  `071a3425d48b5f2ae20eef495f4c3cccfc1d2fabe835ce73614e18ab6b7418c4`.
  The original name and output destination are deliberately unchanged. Its README
  requires a separate explicit output directory when regenerating this reference.
- The retained `scenarios/iteration-test-macos/` source receives matching timing
  changes. Its initial origin/activity metadata, partial diagnostic and all loops
  1–42 remain historical. The revised README points future work to the canonical
  scenario; no historical score or generated evidence was rewritten.

The active environment has nine named users and 23 systems, including two macOS 27
arm64 workstations, and uses November 2, 2026, 13:00–19:00 UTC with two hours of warmup.
The baseline and existing Windows/Linux storyline remain intact, apart from the
inherited raw Apache record's date adjustment already present in the Mac variant.
Original output formats plus native ES, bounded Unified Log and zsh history remain
selected, with complete Mac process coverage and the default generation target.

## Authored timing changes

Twenty-five groups now use existing canonical spacing policies:

- Two introductory terminal task groups use human cadence.
- Twelve longer local terminal groups and three SSH inspection groups use interval
  spacing with jitter (0.35 local, 0.30 remote), preserving approximate work spans.
- Two Chrome main/helper groups use automated delays of 300 ms–2 s.
- Six inventory activate/exit groups use automated completion delays of 100–750 ms,
  replacing their exact two-second lifetimes. Exit code 0 remains the explicitly
  authored nominal result. The bounds are illustrative, not an empirical native
  runtime calibration.

No literal fractional digits or source-local timestamp noise were introduced.
Process/session readiness, lifecycle ordering and cross-source observations retain
their existing canonical owners. The active `ORIGIN.json` records every before/after
spacing policy and archive provenance.

## Verification

- All three authored roots validate successfully with zero errors. Active and Mac
  variant each retain one intentional low-baseline/noise-to-signal warning and 27
  informational pivot suggestions. The preserved original has no warnings and 24
  informational suggestions; their bytes were not changed to clear diagnostics.
- Non-writing composition explanation succeeds with the same pinned technology pack
  and digest `11e90fb8aa02c2a97d55b6a90fb9b7c192470215174f10f2832da6c253c62928`.
- Five archive hashes verify. Compiled active/Mac variant semantics match after
  excluding their intentionally different names, descriptions and output destinations.
- A direct seeded scheduling-policy probe covers all 25 groups: replay is exact,
  offsets strictly increase, and each sampled group has varying fractional seconds.
  Six sampled inventory delays span 0.248763–0.731915 s. This tests policy execution,
  not rendered native output or an authenticity score.
- The existing slow composition-lineage regression now retains the original
  Scenario 1.0 → pre-Mac packed comparison and additionally checks promotion preserves
  users, hosts, inherited events, baseline, pack and formats while adding Mac support.
  It passes. An initial default invocation selected no tests because the module is
  slow; the explicit `-m slow --no-cov` run executes it. A test accessor was corrected
  from attribute to dictionary access before the passing rerun.
- All 47 timing/cleanup tests pass. Whole-tree Ruff check and formatting pass
  (1,449 Python files). No new test was added, and no full suite was run.

Existing adjacent generation bundles and evaluation reports are stale for the
revised scenario. No generation, assessment loop, commit or version bump was run.
New scores require fresh generation and review; previous trends must remain labeled
as preceding this authored timing revision.

A subsequent user-authorized fresh assessment is complete as Mac-series loop43
under the canonical path. See [its worklog](2026-11-05-iteration-test-loop43-assessment.md)
for rendered timing verification, scores and remaining findings. This later run is
separate from the authoring/promotion validation described above.

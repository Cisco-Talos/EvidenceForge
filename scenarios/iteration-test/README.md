# Canonical iteration-test benchmark

The November 20, 2026 benchmark promotes the assessed
[`iteration-test-realism-candidate`](../iteration-test-realism-candidate/README.md).
It retains Scenario 2.0, the exact packaged technology 1.0.0 industry pack,
9 named users, 23 systems, seed 42, a six-hour collection window beginning
November 2 at 13:00 UTC, and two hours of warmup.

The authored workload adds cross-platform diagnostic download/execute/follow-up
sequences, explicitly launched VS Code on one Mac, practical Mac diagnostic and
configuration work, and an explicit mounted-share read/save sequence. The existing
Windows/Linux narrative, Mac launch-item lifecycles, source selections and low
baseline remain. Reviewer instructions and examination requirements are unchanged.

## New assessment history

**Epoch: `2026-11-20-realism`. This history starts at loop 1.**

`blind-test/` contains only this epoch's generated bundles, reports and scores.
Do not carry earlier loop numbers forward, seed this history
with the candidate trial score, or combine its rolling averages with older epochs.
This is an explicit reset because the authored scenario changed substantially.
See [history policy](blind-test/README.md) and [epoch metadata](blind-test/HISTORY.json).
The current run is indexed in [series progress](blind-test/SERIES.json).

## Previous versions and evidence

- The previous scenario YAML and its required YAML includes are at
  [`iteration-test-previous-2026-11-20`](../iteration-test-previous-2026-11-20/scenario.yaml).
  Old datasets and reports are not part of that version archive; they were
  removed on November 20 after explicit cleanup authorization.
- The exploratory candidate's authored YAML remains under
  [`iteration-test-realism-candidate`](../iteration-test-realism-candidate/README.md).
  Its obsolete trial artifacts were deleted after promotion; no trial score is
  part of this new series.
- Older Windows/Linux authored snapshots remain in
  [`tests/fixtures/scenarios/iteration-test-pre-macos`](../../tests/fixtures/scenarios/iteration-test-pre-macos/README.md).
- `ORIGIN.json` records promotion, source and prior authored hashes. Only the canonical name, destination hint and
  description change from the promoted candidate; its activity is retained.

Each assessment stores its output separately under `blind-test/loop-N/`.
Validation intentionally retains the eight candidate
warnings about the low baseline, warmup logons outside collection, and download
commands whose network consequences are inferred automatically.

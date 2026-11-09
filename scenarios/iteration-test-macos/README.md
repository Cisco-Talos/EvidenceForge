# Mac-inclusive iteration-test variant and assessment history

The Mac-inclusive benchmark was promoted to the canonical
[`scenarios/iteration-test`](../iteration-test/README.md) on November 5, 2026.
Use that canonical path for future iteration work. This variant remains available
with the same revised timing policies, its original name and output destination,
and all historical assessment evidence.

The original Windows/Linux authored inputs are preserved byte for byte in
[`tests/fixtures/scenarios/iteration-test-pre-macos`](../../tests/fixtures/scenarios/iteration-test-pre-macos/README.md).
The original `ORIGIN.json` and `MACOS-ACTIVITY.json` here describe the creation of
this Mac variant; they are historical provenance, not seals of the revised YAML.

## Current timing policy

Introductory terminal queries use human cadence; longer local/SSH task groups use
jittered intervals preserving approximate work spans. Chrome helper starts use
300ms–2s automated delays, and each inventory activation declares its successful
completion after a variable 100–750ms. All variation enters canonical scheduling;
process identities, ordering and cross-source timestamps keep their existing owners.
The inventory bounds are an illustrative model, not empirically calibrated timings.
Scenario 2.0, the pinned technology pack, 9 users/23 systems, six-hour November 2,
2026 window and two-hour warmup are retained. Native ES, bounded ULF and zsh history
remain selected with complete process coverage.

## Historical assessments

Loops 1–42 under `blind-test/` predate these scenario timing edits. Their data,
reports and scores remain historical evidence and have not been rewritten. Start
with the [ten-loop report](blind-test/REPORT.md) and
[worklog](../../docs/worklog/2026-11-04-iteration-test-macos-assessment.md).

The initial partial-coverage `diagnostic-scenario.yaml` is also historical. Later
complete-coverage generation and helper-exit repairs are documented in the worklog;
the initial diagnostic did not establish those guarantees. Existing generated output
must be regenerated before it can represent the revised source. No new assessment
loop or generation was run as part of this authoring/promotion change.

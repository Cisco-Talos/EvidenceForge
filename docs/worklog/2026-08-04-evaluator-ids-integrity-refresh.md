# Evaluator IDS Integrity Refresh

## Scope

Refresh `eforge eval` after expanding authored IDS attachments to transport-owning
events. The evaluator now treats correlated IDS output as an exact acceptance
contract and updates older evidence assumptions exposed by
`iteration-test-expanded-ids`.

## Implemented

- Added bounded schema-v1 `ids_evaluation` ground truth with per-sensor/SID
  candidate, emitted, policy-filtered, observation, origin, and ordered digest
  totals, plus Markdown parity.
- Added zero-weight `plausibility.ids_integrity` at a 100% hard-gate threshold.
- Preserved parser source instances, made Snort parsing scenario-year-aware and
  IPv4/IPv6 safe, stabilized record ordering and sampling, and sourced report
  generation time from canonical ground truth.
- Corrected STARTTLS/IMAPS/OWA matching, appliance-hostname comparisons,
  case-insensitive TLS name agreement, eligible bash-history expectations, and
  process-parent PID lifetime checks.
- Replaced global-consecutive pivot scoring with an inferred typed-indicator
  graph and expanded event/transport trace contracts.

## Calibration

The regenerated `iteration-test-expanded-ids` dataset contains 87,707 parsed
records across 20 sources. Two evaluations are identical after removing
`evaluated_at`. IDS integrity passes 225/225 exact checks, all 46
expected-visible storyline events are found, and the prior ASA-hostname and
SSL/X.509 case-only false mismatches are absent. Remaining lower-scored findings
are reported as calibration signals rather than acceptance failures.

## Verification

- Focused evaluator, parser, generation, ground-truth, observation, email,
  network, IDS, documentation, and installer tests pass.
- Default suite: 5,077 passed, 19 skipped.
- Slow-inclusive suite: 5,090 passed, 6 skipped.
- Ruff lint/format, generated-skill `quick_validate.py`, temporary Claude and
  ChatGPT/Codex installations, and `git diff --check` pass.

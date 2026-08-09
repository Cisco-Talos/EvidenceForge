# Evaluation Rules

YAML files defining data quality evaluation rules. Used by the evaluation
dimensions in `evidenceforge.evaluation.dimensions` to score generated output.

## Loader

`evidenceforge.evaluation.rules` — provides `load_rules_file(name)`.

## Files

| File | Purpose |
|------|---------|
| `causal_pairs.yaml` | Temporal ordering rules — validates events occur in logical causality order (e.g., logon before process creation). Structure: `pairs` list with `before`/`after` format/condition/match_fields. |
| `co_occurrence.yaml` | Field co-occurrence validation — checks that related fields are consistent (e.g., network logon type 3 requires a valid IP). Structure: per-format rules with `condition`/`checks`. |
| `cross_source_pairs.yaml` | Canonical cross-source joins and shared-field agreement rules. |
| `distributions.yaml` | Reference probability distributions for population statistics checks (e.g., EventID distribution, protocol types). Structure: per-format field distributions with reference probabilities. |
| `thresholds.yaml` | Minimum, aspirational, and hard-gate acceptance policy for every scored contract. |
| `timing_bounds.yaml` | Source-family and event-family timing bounds used by temporal diagnostics. |

## Acceptance Semantics

Evaluation keeps the original four weighted pillars for API compatibility and also reports five
concern-oriented categories: source schema, canonical invariants, declared scenario completeness,
distribution/realism diagnostics, and optional expert comparison.

Hard gates are non-vacuous. A configured required measure that is missing or unmeasurable fails
acceptance. A scorer may mark a measure inapplicable only when the scenario cannot exercise the
contract; an explicit skip is reported as `N/A` and is not treated as 100. Authored scenarios gate
source-schema conformance, cross-source field agreement, causal ordering, event presence, authored
intent reconciliation, indicator accuracy, pivot linkability, temporal integrity, and storyline
trace coverage. IDS integrity is also a zero-weight 100% gate when canonical IDS ground truth is
available.

`GROUND_TRUTH.json.intent_reconciliation` is evaluated against a fresh independent
`AuthoredIntentLedger` built from the scenario. Stable intent IDs, authored metadata, planner
acknowledgement, dispatched occurrence references, and source-observation outcomes must agree.
Dropped, filtered, delayed, or out-of-window evidence is exempt only when the bound observation
manifest proves that source decision.

## Adding a New Rule File

1. Create `{name}.yaml` in this directory.
2. Load it via `load_rules_file("{name}.yaml")` from the evaluation dimensions code.

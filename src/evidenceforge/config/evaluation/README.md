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
| `distributions.yaml` | Reference probability distributions for population statistics checks (e.g., EventID distribution, protocol types). Structure: per-format field distributions with reference probabilities. |

## Adding a New Rule File

1. Create `{name}.yaml` in this directory.
2. Load it via `load_rules_file("{name}.yaml")` from the evaluation dimensions code.

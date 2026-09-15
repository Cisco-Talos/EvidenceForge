# Input validation and evidence validation

`validate-config` checks effective supported configuration and packaged record contracts.
`validate`, `resolve`, and `generate` preflight the required package contracts alongside their
existing scenario and configuration checks. Passing input validation does not mean that generated
evidence has been evaluated. `generate` does not automatically run dataset evaluation.

Run `eforge eval <bundle> --format json` to assess evidence. Schema compliance and objective
record correctness require 100%: a single malformed or contradictory record fails acceptance.
A completed report still exits 0 even when `acceptance_passed` is false. Engine failures exit 22
and must never be presented as successful acceptance. Existing report keys remain; sub-scores
also expose bounded `sample_findings` with rule ID, format/variant, fields, category, severity,
outcome, and message. Counts cover all records, not just these diagnostic samples.

Realism diagnostics are separate from objective correctness. Sparse endpoint metadata, zero-duration
observations, and unusual certificate validity intervals can be legitimate evidence. Specialized
lifecycle, collection-visibility, cryptographic, and cross-record evaluators retain their ownership;
partial observation does not excuse contradictions within a visible record.

Rules and thresholds are package-owned developer interfaces. They cannot be overridden in scenario
YAML, `.eforge/config`, pack catalogs, or environment variables. Supported Scenario 1.0/2.0, overlay
syntax and merge precedence, pack/release schemas, and project-root resolution are unchanged.
Do not add a threshold override or weaken a rule to make a dataset pass.

## Developer contract

Definitions live in `src/evidenceforge/config/formats/*.yaml`. `validators` contains rules with
`id`, `message`, `severity`, optional `when` and `exclude` conjunctions, and nonempty `checks`.
Supported operations are `presence`, `compare`, `membership`, `bounds`, `length`, `pattern`,
`same_length`, `combination`, and the named `address_family` predicate. There is no expression
language, dynamic code loading, or JSON Logic fallback. Unknown keys/operators, invalid references,
regexes, duplicate identities, and inverted bounds are definition errors.

```yaml
validators:
  - id: example.counter
    message: Response count must not exceed request count
    when:
      - {op: presence, field: requests}
      - {op: presence, field: responses}
    checks:
      - {op: compare, field: responses, relation: le, other_field: requests}
```

Missing and null are absent for `presence`; empty strings, empty lists, zero, and source-native
sentinels are present. Apply explicit comparisons/exclusions for empty values and sentinels.
List schemas declare `item_type`; numeric values must be finite, and numeric bounds apply to
integers and floats. Parsers own documented source-native conversions. Windows variants declare
`event_id` and explicit `event_ids` aliases; do not add a second hand-maintained selection table.

`validate_event` retains `valid` and `errors` compatibility views and adds `findings`. Rule outcomes
are `pass`, `fail`, `not_applicable`, and `evaluation_error`. Invalid prerequisite fields skip their
dependent rules to avoid duplicate penalties. Rule execution errors are always errors, including
for diagnostic rules. Unavailable schemas and invalid engine policy cannot yield acceptance.

Add positive, negative, conditional, missing/null/sentinel, malformed-definition, parser-to-score,
and single-violation acceptance coverage when extending a contract. Preserve positive examples
of deliberately unusual evidence. Changes to rule YAML can affect checkpoint behavior provenance;
use the generation-behavior manifest workflow and prove raw-byte compatibility separately.


## Validation coverage and execution failures

Every parser source has an explicit package-owned validation route. Native log sources require a
format schema; email artifact manifest entries use structural artifact validation and retain their
specialized email consistency checks. An unknown source or unavailable native schema is an engine
error, never an implicitly passing record. Empty email sections and optional metadata remain valid.

A failed scoring pillar stops evaluation with exit 22 and no quality report. Successful JSON mode
writes one report object to stdout; warnings and progress go to stderr. A completed report may still
fail acceptance and exit 0. Use `--verbose` for an execution-failure traceback. Do not interpret a
partial collection of pillar scores as an overall quality result.

Developer coverage checks reconcile all parser routes, native schemas, emitter registrations, and
rendering paths. Routine tests render, parse, and validate every native format and supported Windows
variant. The slow iteration-scenario gate checks fresh-process byte equality, bundle integrity,
complete evaluation, and exact record validation, including email artifacts and observation gaps.

### Malformed evidence versus evaluator faults

A returned `evaluation_error` finding stops scoring before aggregation, including diagnostic and
artifact rules. The CLI returns 22, identifies the rule/source/variant/fields on stderr, and emits no
report. The library compatibility view still returns `valid=False`, errors, and structured findings.

Malformed records remain counted in source totals and exact schema acceptance. Once recorded as
schema/parse failures, they do not enter later pillars' typed distribution or cross-source indexes.
Those scores describe usable evidence and cannot override failed schema acceptance. Well-typed
records with cross-field contradictions still reach specialized evaluators. This prevents malformed
identities, timestamps, and collections from turning ordinary invalid evidence into engine faults.

Splunk web/proxy JSON is parsed through its supported field aliases before shared validation.
Malformed native fields and conflicting aliases remain counted failures. SOF-ELK Snare projection
coverage is still a known gap on this branch: its omitted XML metadata and flattened identity labels
need an explicit native contract; current schema failures are not waived. See the validation worklog
for the retained target fixtures and merge-readiness evidence.

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

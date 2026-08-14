# Evaluation configuration (developer-only)

This is not a project-overlay authoring reference. Evaluation rules and scoring policy are
engine-owned. `.eforge/config/evaluation`, pack catalogs, scenario YAML, and environment variables
cannot replace them.

Packaged rule files live under `src/evidenceforge/config/evaluation/` and include thresholds,
co-occurrence, distributions, causal/timing checks, and cross-source rules. They must remain aligned
with evaluator code, parsers, ground-truth contracts, observation semantics, and format definitions.

Use the evaluate skill to run or interpret `eforge eval`. A request to change scoring policy is a
source-code development task, not an `eforge-config` overlay task. For an authorized developer
change:

1. Identify the evaluator and parser that consumes the rule.
2. Edit the packaged rule and owning evaluator together when their contract changes.
3. Add focused evaluator tests for passing, failing, legacy, and observation-aware cases.
4. Run the project lint and test gates.

Do not copy packaged evaluation YAML into `.eforge/config`, invent
`EFORGE_EVAL_CONFIG_DIR`, or claim a project can tune acceptance thresholds independently of the
engine version.

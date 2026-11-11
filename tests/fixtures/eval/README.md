# Evaluation regression oracle

`reference-f93a25bf.json` was generated from an untouched `git archive f93a25bf src` export,
using `eval/good` and `scenarios/retail-store-ftp-attack.yaml` from these fixtures. It is the
pre-streaming evaluator's complete JSON report with only `evaluated_at` omitted.

The new evaluator must match it in both memory and forced-spill modes, excluding its additional
`supplementary.evaluation_resources` diagnostics. Do not regenerate the oracle using the new
engine: that would only compare the new implementation against itself. Larger legacy and schema-5
retained bundles are compared separately; see the streaming evaluation worklog for provenance.

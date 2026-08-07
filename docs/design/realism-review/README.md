# Complete Code and Realism Review

This directory is the tracked evidence package for the complete EvidenceForge code and
realism review frozen at `dev` commit `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`.

## Review status

| Phase | Status | Primary artifact |
| --- | --- | --- |
| Baseline freeze | Complete | `review-baseline.json` |
| Architecture and object-model gate | Accepted 2026-08-05 | `architecture-object-model.md` |
| Event/context path census | Complete | `event-context-path-census.md` |
| Cross-cutting audits | Complete | `source-references.json`, `findings.json` |
| Empirical campaign | Complete with documented limitations | `empirical-results.json`, `probe-*.json` |
| Blind expert review | Complete | `blind-summary.md`, four individual reports |
| Security review | Complete; one deferred capacity question | `security-review.md` |
| Final synthesis and remediation roadmap | Complete | `final-report.md` |
| Contract proposal approval | Approved with amendments 2026-08-05 | `contract-proposals.md` |

The review paused after the architecture assessment and resumed after user acceptance. No
generator fix, public API change, schema migration, or version bump was made during the campaign.

The canonical contracts were approved with amendments on 2026-08-05. Implementation is authorized
only as bounded, separately reviewed feature-branch batches.

## Package contents

- `architecture-object-model.md`: actual architecture, ownership assessment, object-model audit,
  architecture findings, target architecture, and migration order.
- `event-context-path-census.md`: reviewed path analysis and parallel-path conclusions.
- `path-classifications.json`: grouped review decisions merged into every matrix row.
- `event-context-paths.json`: exhaustive machine-readable path census.
- `coverage-summary.json`: completeness accounting for event, context, plan, bundle, emitter, and
  evaluator coverage.
- `source-references.json`: official/public source-native reference ledger for all 23 formats.
- `empirical-results.json`: reproducible scenario, profile, parser, stress, and invariant results.
- `probe-*.json`: durable results from the generated-output invariant probe.
- `blind-*.md` and `historical-blind-evidence.json`: isolated current expert reviews and separately
  labeled historical recurrence evidence.
- `post-gate-loop5-blind/`: final isolated post-Batch-2 gate panel, scores, and verified finding
  dispositions after the five bounded lifecycle/module repair loops.
- `security-review.md`: sealed security-scan summary, threat model, findings, and limitations.
- `findings.json`: normalized 34-row validated finding register.
- `contract-proposals.md`: proposal-only canonical contracts behind a separate approval gate.
- `final-report.md`: final synthesis and dependency-ordered remediation roadmap.

Generated datasets and temporary probe outputs remain untracked. Commands, inputs, hashes, output
locations, failures, and limitations are recorded in the focused worklog at
`docs/worklog/2026-08-05-complete-realism-review.md`.

# Batch 5: Projection Fidelity and Evaluation Validity

**Branch:** `codex/batch5-projection-evaluation`

**Parent:** `91247365` (`fix: enforce world capability and distribution contracts`)

**Review baseline:** `0a035e97`
**Findings:** `REAL-010`, `REAL-011`

## Purpose

Close the fifth approved remediation batch without allowing blind-review iteration to replace the
dependency-ordered review plan. This batch owns source-native projection fidelity, durable
authored-intent reconciliation, and evaluator acceptance validity. It does not add another blind
panel gate and does not take on Batch 6 input-safety or workload-budget work.

## Reconciled starting state

- `REAL-011` is no longer an active code defect. Commit `739dbea2` changed Event 4648 to the
  provider-native `IpAddress`/`IpPort` names while repairing the post-Batch-2 blind gate. The
  format definition, renderer, source ledger, and realism probe now agree. Batch 5 will preserve
  that fix with a provider-field snapshot and rendered/parser round-trip proof, then update the
  stale finding state.
- `REAL-010` remains active. Empty or inapplicable denominators can still score 100, only a subset
  of scenario-completeness measures are hard gates, an unevaluated hard gate is ignored, and an
  empty dataset currently receives a perfect overall score.
- The behavior-preserving foundation already supplies `AuthoredIntentLedger`, stable action IDs,
  semantic occurrence keys, shadow-sealed occurrence snapshots, and a source-observation
  manifest. Ground truth does not yet reconcile them and evaluation still resolves most expected
  evidence directly from scenario intent.

## Approved executable contract

1. **Authored intent stays independent.** Every typed storyline and red-herring specification is
   represented in the authored ledger before generation. Ground truth must retain an explicit
   reconciliation row even if planning or execution produces no event dictionary.
2. **Planning and occurrences are linked, not inferred later.** Storyline execution binds the
   active authored intent ID at the dispatcher boundary. Dispatched semantic occurrence IDs and
   action IDs are collected for that intent. Legacy events without semantic keys remain explicit
   proof gaps; they do not receive invented action identities.
3. **Observation is intent-scoped.** Source decisions are accumulated per intent as well as per
   storyline cluster. Expected source evidence in evaluation comes from the recorded decisions;
   legitimate dropped, filtered, delayed, and out-of-window outcomes remain visible rather than
   being treated as missing generation.
4. **Ground truth is additive and backward compatible.** Keep schema version 1 and existing event
   fields, while adding optional reconciliation metadata and a top-level intent reconciliation
   summary. Existing documents continue to load.
5. **No vacuous hard-gate pass.** A required hard gate with no measurable denominator is
   indeterminate and makes acceptance indeterminate or failed according to gate policy; it is
   never silently omitted from `all()`.
6. **Separate evaluation concerns.** The report exposes stable category summaries for
   parseability/source schema, canonical invariants, scenario completeness, distribution/realism,
   and optional expert comparison. Existing pillars remain for compatibility.
7. **High-impact mismatches gate acceptance.** Event presence, indicator accuracy, pivot
   linkability, temporal integrity, storyline trace coverage, source-schema conformance,
   cross-source field agreement, causal ordering, and IDS integrity have explicit acceptance
   behavior. Scenario-free metrics may be skipped; authored scenarios may not turn zero checks
   into 100.
8. **Known-bad proofs are mandatory.** Empty output and fixtures with missing declared evidence,
   broken pivots, incorrect indicators, temporal inversions, or cross-source disagreement must not
   pass. Legitimate observation-profile gaps must remain exempt when the bound manifest proves
   the source decision.

## Work plan

- [x] Add dispatcher-owned intent occurrence/observation accounting and bind both storyline and
  red-herring specifications to their authored IDs.
- [x] Extend canonical ground truth with backward-compatible reconciliation metadata and validate
  authored/planned/occurred/observed states.
- [x] Make causality denominators non-vacuous and make unevaluated required gates explicit.
- [x] Add evaluation-category summaries and hardened acceptance configuration.
- [x] Add known-bad acceptance fixtures plus Event 4648 provider-field snapshot and round-trip
  tests.
- [x] Run focused tests, all non-slow tests, scoped slow tests, Ruff, config validation, repeat
  generation, probes, and before/after evaluation comparisons.
- [x] Reconcile `REAL-010`/`REAL-011`, update the review package and `TODO.md`, and commit the batch.

## Evidence ledger

### Implementation and empirical results

- Added an independent `IntentExecutionLedger` and additive schema-v1 ground-truth reconciliation.
  The six-hour complete and enterprise controls each reconcile 11/11 expected, planned, occurred,
  and observed authored intents. All 11 have dispatched event references; one current bundle path
  also carries stable action/occurrence identity, while legacy paths remain explicit proof gaps.
- Added five concern-oriented evaluation categories without removing compatibility pillars. Missing
  hard measures fail, explicit inapplicability reports `N/A`, and source/schema, canonical,
  declared-scenario, distribution, and optional-expert concerns no longer share one opaque score.
- Promoted format constraints, cross-source field agreement, indicators, pivots, temporal
  integrity, trace coverage, and intent reconciliation to hard acceptance contracts. Durable named
  bad cases live in `tests/fixtures/eval/known_bad/acceptance_cases.json`.
- The 453,560-record retail control now fails rather than scoring a misleading pass: event presence
  is 1/22, pivots are 0/24, temporal integrity is 1/22, and 22 authored events have no enabled
  expected source group. Overall quality is 78/100 and acceptance is false.
- The complete branch control parses 48,719 records and reports source schema 100, canonical
  invariants 99.995, scenario completeness 85.905, distribution diagnostics 91.158, and acceptance
  false for the pre-existing indicator (83.761) and pivot (40) defects. Its realism probe is clean.
- The enterprise control parses 49,430 records. Its manifest records 343 delayed and two filtered
  intent-scoped observations; trace coverage remains 100, proving legitimate profile decisions are
  not false failures. Acceptance still rejects the same indicator/pivot defects. The expanded probe
  found one proxy-host Linux PID chronology reversal, recorded as an out-of-scope existing sibling
  for later lifecycle work rather than silently fixed in this batch.
- A detached exact-parent build at `91247365` and the final Batch 5 complete control have the same
  39-file data manifest SHA-256,
  `b413ba25bd1dba51aff5ddcd65ceb829417692616c7a0947e140a3b24f058f29`.
  Repeat Batch 5 outputs are byte-identical. Ground-truth changes are intentionally additive.
- Event 4648 provider-native `IpAddress`/`IpPort` behavior is protected by exact field-order and
  rendered/parser tests; the realism probe reports no legacy network-field names.

### Validation ledger

- Focused evaluation, ground-truth, spillage, dispatcher, and activity campaign: 555 passed.
- Targeted final contract tests: 70 passed; durable bad-case/threshold/logon fixture tests: 29
  passed.
- Full non-slow suite: final unrestricted run passed with 5,195 passed and 41 skipped in 244.47
  seconds. The first run's Batch 5 test-double omission was corrected, and running outside the
  managed localhost-bind restriction allowed the existing Splunk harness socket test to execute.
- Targeted parallel slow suite: 5 passed.
- Config validation: 0 errors, 0 warnings, and 0 info items across 87 files.
- Complete, enterprise, retail, parent-control, and repeat outputs remain under `/private/tmp` and
  untracked. `batch5-results.json` records commands, locations, hashes, scores, and limitations.

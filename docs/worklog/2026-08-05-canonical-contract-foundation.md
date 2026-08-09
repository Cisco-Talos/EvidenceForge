# Canonical Contract Foundation Worklog

## Status

Implementation and validation completed on 2026-08-05 after explicit user approval of the
reviewed canonical contracts and six amendments.

Branch: `codex/canonical-contract-foundation`

Baseline: `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`

## Approved foundation scope

- Record the approved contract amendments and retain the completed review as an independent
  documentation commit.
- Introduce a closed internal event-kind registry and machine-readable contracts.
- Add behavior-preserving seal validation in shadow/assert-only mode.
- Add stable semantic occurrence-key scaffolding without replacing existing event IDs.
- Add an independent authored-intent ledger scaffold so missing planned actions cannot disappear
  from the eventual ground-truth oracle.
- Add early path/workload safety boundaries where they can remain compatible with existing
  scenarios and generated output.
- Add closure and negative-contract tests generated from the reviewed inventory.

## Explicit non-goals

- No public scenario-schema migration.
- No replacement of current event IDs or ground-truth output.
- No enforcement that changes generated evidence in the foundation batch.
- No session/process/authentication family migration; that is the next vertical slice.
- No compatibility-field removal or version bump.

## Binding amendments

1. Ground truth retains independent authored intent and reconciles every transition.
2. Occurrence identity prefers semantic instance keys over positional ordinals.
3. Missing infrastructure fails validation unless synthesis is explicitly requested.
4. Ownership means one authority per shared fact/lifecycle, not one monolithic class.
5. Observation and evaluation explicitly represent legitimate partial visibility.
6. Path and resource safety starts in the foundation work rather than the final migration batch.

## Commit structure

1. `docs:` completed review package and approved contract record.
2. `feat:` or `refactor:` behavior-preserving contract foundation and tests.

## Validation gates

- Existing generated output remains byte-identical for deterministic fixtures unless a separately
  reviewed safety boundary intentionally rejects invalid input.
- New registry inventory is closed over constructors and emitter consumers.
- Shadow validation records illegal combinations without mutating events or routing.
- Existing non-slow tests and Ruff checks pass.
- Focused tests cover unknown kinds, missing/forbidden contexts, semantic occurrence keys,
  authored-intent reconciliation scaffolding, and early safety boundaries.

## Implementation progress

- Created and switched to `codex/canonical-contract-foundation` at the frozen reviewed baseline.
- Committed the complete review and approved contract record separately as `7238ca61`
  (`docs: publish complete realism review`).
- Added `events/contracts.py` with closed domains for 47 produced canonical event kinds, 42
  semantic context fields, and all 23 concrete formats.
- Added one frozen `EventKindContract` per produced kind, including required/optional/forbidden
  contexts, host semantics, identity and lifecycle requirements, state effects, compatibility
  producer boundaries, and emitter consumers.
- Kept `raw` outside the canonical registry and explicitly retained `module_load` and
  `special_privileges` as legacy consumer-only names.
- Added dispatcher shadow sealing after identity planning. It captures an immutable occurrence
  snapshot and aggregates violations without changing dispatch, state, timing, observation,
  routing, or projection.
- Added stable `ActionAnchor.action_id` and semantic `OccurrenceRole`/`SemanticOccurrenceKey`
  scaffolding without replacing the existing dispatch-sequence event ID.
- Added `AuthoredIntentLedger`, captured before generation from storyline and red-herring specs.
  Its reconciliation API exposes missing and unexpected planned intent IDs; current ground-truth
  output is intentionally unchanged.
- Added bounded scenario include depth/file/byte accounting with compatibility defaults of 32
  levels, 256 files, and 16 MiB.
- Added a shared safe-child resolver and applied it to email `.eml` artifact writes, rejecting
  traversal, subdirectories, absolute paths, and existing symlink escapes.
- Added reviewed-inventory closure checks, literal-constructor drift checks, negative contract
  tests, semantic identity stability tests, intent reconciliation tests, include-budget tests, and
  artifact path tests.

## Empirical compatibility checks

- Focused event/dispatcher/utility tests: 176 passed.
- Focused contract, intent, utility, and artifact-safety tests: 81 passed.
- Minimal generation data is byte-identical to the frozen review output.
- Minimal generation produced no shadow contract violations.
- The existing branch-office scenario completed under shadow mode. The registry exposed current
  debt rather than blocking it: 355 logoff, 137 logon, and 218 machine-logon occurrences lack the
  proposed canonical identity plan; one SSH session lacks a required context. These diagnostics
  are inputs to the next session/authentication vertical slice, not foundation enforcement.
- The six-hour branch-office enterprise dataset is byte-identical to the frozen review output.
- `uv run pytest --no-cov -q`: 5,098 passed, 41 skipped in 224.02 seconds.
- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: passed; 452 files already formatted.
- `git diff --check`: passed.
- The first complete-suite attempt exposed one documentation-policy failure because the review
  worklog used the SOF-ELK® name without its required first-reference trademark. The review
  package was corrected to use the required form, the stale empirical CLI option `--output-dir`
  was corrected to `--output`, affected JSON files passed `jq empty`, and the clean complete-suite
  rerun passed.

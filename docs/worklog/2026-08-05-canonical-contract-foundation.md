# Canonical Contract Foundation Worklog

## Status

Implementation started on 2026-08-05 after explicit user approval of the reviewed canonical
contracts and six amendments.

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

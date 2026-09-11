# Skill Reliability and Context Optimization

## Scope

Improve the canonical development skills in `commands/eforge` for reliable chat-based use,
especially with smaller context windows. The pack-management, industry-pack, and
organization-pack skills were already forward-tested in the preceding effort; this work focuses
on config, evaluate, generate, validate, and scenario, plus the CLI contracts those skills need.

## Branch

- `codex/skill-reliability-optimization`, created from the merged `dev` tip.
- Do not edit generated `.agents` content; `commands/eforge` remains canonical.
- Preserve unrelated untracked `coverage.xml` and
  `docs/worklog/2026-08-04-iteration-test-expanded-ids-assessment.md`.
- Do not bump the package version on this feature branch.

## Durable decisions

- Validation-only requests are read-only. File repair requires an explicit fix request.
- Repairs use three classes: mechanical changes may be automatic; directly implied intent may be
  applied and reported; semantic choices require user input.
- Deterministic evaluation is separate from blind expert review. The evaluate skill does not
  claim a review is blind after reading ground truth or evaluation results.
- Generation starts with normal CLI output, uses verbose output for diagnostic retries, and uses
  debug output only for unresolved engine failures.
- A resolved scenario is authoritative generated input and must not be overwritten by replay.
- Main skill bodies carry only routing, safety boundaries, and core workflows. Detailed material
  is loaded conditionally from focused references.
- Stable machine-readable CLI output and source-aware diagnostics are preferred over asking an AI
  to parse Rich terminal prose or guess which include owns a failing field.

## Validation record

- Rewrote the five pre-existing development skills (`config`, `evaluate`, `generate`,
  `scenario`, and `validate`) around compact core workflows and conditionally loaded focused
  references. Fresh ChatGPT/Codex installation produces eight valid skills; all eight passed the
  skill-creator validator.
- Added stable JSON contracts and source-aware diagnostics for validation, config inspection,
  config validation, scenario resolution, and storyline schema discovery. Added non-writing
  composition explanation, opt-in effective-scenario output, resolved-input replay protection,
  deterministic exit handling, and per-project immutable config isolation.
- Added a typed registry for all project-overlay configuration families. Closed validation/runtime
  gaps for RSAT overlay merging and TLS domain CA overrides, and documented family-specific merge
  semantics.
- Clean-room forward tests passed for validation, generation, configuration, and deterministic
  evaluation. The validation/config trials made no writes; generation used a fresh temporary
  bundle and verified authoritative sidecars; evaluation ran exactly once and correctly separated
  process success from an acceptance failure.
- Integrated skill and CLI contract suite: `100 passed`.
- Full default suite: `5749 passed, 21 skipped` in 7m43s. The first full run caught one missing
  SOF-ELK® trademark marker in a new focused reference; the marker was fixed and the full suite was
  rerun cleanly.
- Final quality gates: `uv run ruff check .` passed and
  `uv run ruff format --check .` reported all 507 files formatted.
- Built wheel and source distribution under `/private/tmp`; all 36 canonical
  `commands/eforge` files were byte-identical in both artifacts, and neither artifact contained
  `.agents`. Git tracks zero `.agents` files.

## Handoff

- No package version files were changed.
- Unrelated `coverage.xml` and
  `docs/worklog/2026-08-04-iteration-test-expanded-ids-assessment.md` remain untracked and
  untouched.
- The feature branch is ready for review and merge into `dev`.

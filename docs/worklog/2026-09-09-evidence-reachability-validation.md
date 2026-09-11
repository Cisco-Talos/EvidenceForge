# Evidence Reachability Validation

## Scope

Add a shared, source-instance-aware validation contract for configured behavior that has no
possible evidence projection. The immediate reproducer is persistent Windows SMB selected during
baseline warm-up when the effective output set contains no supported SMB projection target.

## Contracts

- Behavior owners declare acceptable projection alternatives once; validation and runtime guards
  consume that declaration rather than maintaining private format lists.
- Reachability is evaluated against the compiled collection deployment after format expansion,
  platform/role applicability, observation overrides, and collection windows.
- A behavior is unreachable only when no source can ever express it. Probabilistic observation
  loss does not make a behavior unreachable.
- Explicit authored behavior with no projection is reported at its authored event path. Related
  occurrences are grouped by behavior and target to avoid warning floods.
- A guaranteed runtime prerequisite failure is an error. A valid but wholly invisible authored
  behavior is a warning so an author may intentionally retain it.
- `eforge generate --formats` repeats reachability after applying the runtime intersection and
  rejects new blocking findings before output setup or warm-up.
- Runtime exact-publication guards remain in place as defense in depth.

## Verification

- `uv run ruff check .`: passed.
- `uv run ruff format --check .`: 762 files already formatted.
- Focused reachability, validate/generate CLI, and behavior-manifest tests: 33 passed.
- Broad validation/CLI/source-contract regression subset: 259 passed, 14 deselected.
- Full routine suite: 8,318 passed, 5 skipped, 2,008 deselected.
- Full slow suite (`uv run pytest -m slow --no-cov -q`): 1,779 passed, 8,552 deselected.

## Result

`eforge validate` now rejects persistent Windows SMB configurations that have no eligible
projection route before generation starts. Valid but entirely invisible authored endpoint behavior
is reported as a warning. The analyzer uses the compiled source deployment, including host/sensor
applicability, collection capabilities, source enablement, deterministic missingness, and collection
windows. Runtime format narrowing invokes the same analyzer, while the existing exact-publication
guard remains as defense in depth.

# Windows Spool Performance

## Context

The Windows spool repro in `/Users/bianco/eforge-work/windows_spool_bug` showed
super-linear generation time for Windows-output baseline scenarios. Instrumentation
before the fix confirmed the primary hotspot was Windows Security finalization:

- 6h repro: Security spool rows were scanned repeatedly during final flush.
- 12h repro: Security final flush scanned 88,200 rows 13 times and spent 16.45s
  in Security flush alone; Sysmon flush was 1.42s.
- A 24h pre-fix run was stopped after several minutes without producing output.

## Fix

- Security spool rows now carry ordinary SQLite metadata columns for `event_id`,
  `computer`, and `sort_key`.
- Final Security spool repair loads decoded rows once, runs the existing timestamp
  ordering repairs against that decoded set, batch-updates changed payloads, and
  deletes suppressed lock/unlock rows.
- Security parent/child 4688 ordering now uses a parent graph walk instead of
  iterative whole-spool relaxation.
- Sysmon Event 1 parent ordering uses the same non-iterative graph walk.

## Validation

- `uv run pytest --no-cov tests/unit/test_emitters.py tests/unit/test_sysmon_emitter.py`
  passed with 132 tests.
- `uv run ruff check .` passed.
- `uv run ruff format --check .` passed.

Post-fix repro timings:

- 6h full repro: `real 51.50s` (previous comparable run was about 56s).
- 12h full repro: `real 67.51s` (previous instrumented run was 78s, including
  16.45s Security finalization).
- 24h full repro was attempted but stopped after roughly 3.5 minutes. This still
  needs separate follow-up if 24h wall time remains a hard acceptance target; the
  targeted Security finalization cliff is covered by the 12h before/after and the
  unit regression that asserts one decoded spool repair load during final flush.

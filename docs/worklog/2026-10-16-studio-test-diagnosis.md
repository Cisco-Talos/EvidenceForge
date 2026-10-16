# Studio test failure diagnosis — October 16, 2026

## Scope and checkout

Diagnose Studio test failures and recommend root-cause fixes; implementation was not requested.
Created the isolated worktree `/Users/bianco/.codex/worktrees/studio-test-diagnosis/EvidenceForge`
on branch `codex/studio-test-diagnosis` from `dev` at
`5ce84103fccd630a748cf59ab19808f9fa0699bc`. A fetch confirmed `origin/dev` has the same SHA.
The user's active checkout and its uncommitted work were not modified.

## Confirmed failure

[CI run 38640245039](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/38640245039),
for tzdata update PR #455, failed in **Studio (ubuntu-24.04) / Test frontend interactions**.
The frontend result was 339 passed, one failed, across 33 files. The failing test was
`desktop-ui/tests/ChatExperience.test.tsx:105`,
`live timer becomes a fixed completed duration and retains commentary`.
At line 110 it expected `Working for 24s`; the captured DOM displayed `Working for 25s`.
The macOS and Linux ARM64 Studio jobs, all three state-recovery jobs, and both engine test
jobs passed in that run. Required CI failed as a consequence of the frontend job failure.

### Root cause

The module-level `seed` at line 13 captures `Date.now() / 1000 - 24` during file evaluation.
Six earlier tests execute before the timer test. The timer test reuses the old timestamp and
asserts an exact 24-second label against the real clock. Once more than one second passes
between fixture creation and rendering, the expectation can no longer be true.

`ChatView.tsx:178` updates the current time every second, and line 321 renders elapsed time.
`chatTimeline.ts:91` floors milliseconds to seconds. Their behavior explains the observed 25s
label correctly. This is a wall-clock-dependent fixture/assertion defect, not evidence of a
tzdata regression or a production timer defect. The fixture originated in commit `bca61b03e`.

### Recommended root-cause fix

1. Enable Vitest fake timers and set a fixed system time inside this timer test.
2. Construct its `started_at` after setting that clock; avoid the module-load timestamp for
   time-sensitive assertions. A fresh-turn fixture factory is also suitable for shared setup,
   but rebuilding the fixture alone still leaves an uncontrolled wall-clock boundary.
3. Flush the async snapshot load with React `act`, then assert the exact 24-second label.
4. Advance the clock by 1,000 ms inside async `act` and assert the 25-second label.
5. Deliver the completion event with `durationMs: 66000`, assert `Worked for 1m 6s`, advance
   another five seconds, and assert that the duration remains fixed and commentary remains.
6. Keep cleanup and restoration of real timers in `afterEach` (already present).

Do not increase timeouts, loosen the assertion to any duration, add retries, or change the
production timer to accommodate the fixture. The test should retain precise behavioral checks.

## Verification

All local tests ran in the isolated worktree with dependencies installed from the lockfile.
No running Studio helper, user conversation, or installed application was contacted.

- Unchanged `dev`: `npm test` — **340 passed in 33 files**.
- Controlled reproduction: temporarily mocked `Date.now()` to exactly
  `(seed.started_at + 25) * 1000` in the failing test. Running just that test reproduced the
  same missing-24s assertion and rendered 25s (**one failed, 13 skipped**).
- Temporary candidate implementing the controlled clock and stronger tick/fixed-duration
  assertions: `npm test -- tests/ChatExperience.test.tsx` — **14 passed**.
- Reverted all experimental test edits after verification. Production code remains unchanged.

Local diagnostic artifacts (disposable): `/tmp/studio-ci-38640245039.log`,
`/tmp/studio-diagnosis-baseline.log`, `/tmp/studio-diagnosis-clock-drift.log`,
`/tmp/studio-diagnosis-clock-control.log`, and `/tmp/studio-timer-recommended-fix.patch`.
The patch is a tested recommendation, not an applied change or committed fix.
Local verification was on macOS; Linux evidence comes from the CI log, not a new local Linux run.

## Other recent red CI runs

[Run 38642435227](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/38642435227)
(Pydantic PR #457) and
[run 38638684651](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/38638684651)
(FastAPI PR #450) passed all Studio and Studio state-recovery jobs. Their Windows engine test
steps were cancelled at approximately the 45-minute job limit, causing Required CI to fail.
These are separate engine/runtime investigations; this diagnosis does not establish their
underlying slow or hanging test. Do not attribute them to Studio or claim the dependency
updates caused the chat timer flake.

## Follow-up: the six failures reported in the macOS implementation chat

The first pass above was incomplete: the user was referring to six local Python integration
failures reported in **Assess macOS workstation support**, not the recent frontend CI failure.
Read-only inspection of that chat and its retained diagnostic output identified the exact cases.
They are reproduced independently below on unchanged `dev` in this worktree.

| Test | Original failing operation |
| --- | --- |
| `test_wal_resident_records_survive_failed_database_publication[False]` | Read backup inventory |
| `test_wal_resident_records_survive_failed_database_publication[True]` | Read backup inventory |
| `test_backup_ignores_uncommitted_writer_then_retry_succeeds` | Verify backup digest |
| `test_independent_sqlite_writer_blocks_publication_and_allows_retry` | Backup error masks the expected writer-conflict diagnostic |
| `test_missing_derived_tables_are_rebuilt_without_changing_user_metadata` | Read database inventory after store close |
| `test_committed_wal_and_uncommitted_rows_are_handled_by_backup` | Verify backup digest |

The first five cases are in `tests/integration/test_studio_state_edges.py`; the last is in
`tests/integration/test_studio_state_upgrade.py`. All converge on read-only SQLite reopening
of a WAL-mode database without its sidecars. Most raise `sqlite3.OperationalError: unable to
open database file`; the writer-conflict case fails because this earlier error replaces the
expected `Database is in use` message.

### Controlled runtime comparison

Ran both complete integration modules, using the same source and locked dependency versions:

| Runtime | SQLite | Result |
| --- | --- | --- |
| pyenv CPython 3.12.9 | Apple/system 3.51.0 | **6 failed, 139 passed, 1 skipped, 45 deselected** |
| uv-managed CPython 3.12.11 | standalone 3.49.1 | **145 passed, 1 skipped, 45 deselected** |

`otool -L` confirms the pyenv `_sqlite3` extension links `/usr/lib/libsqlite3.dylib`.
The managed comparison used a disposable environment at `/tmp/studio-diagnosis-managed-py312`;
the user's active checkout and its Python environment were not changed.

A minimal reproduction, independent of EvidenceForge, creates a WAL database, commits a row,
uses SQLite's backup API to copy it to a fresh file, closes that backup, and reopens it with
`mode=ro`. The backup retains WAL header bytes `02 02` and has no sidecars. The system-linked
runtime returns `SQLITE_CANTOPEN` on the first query despite a writable temporary directory.
The standalone Python 3.12 runtime and the installed Homebrew Python 3.13/3.14 runtimes
(SQLite 3.54.0) read it successfully. Opening the failed copy read-write first creates
sidecars and permits a subsequent read-only query on the system runtime.

This isolates a runtime-specific SQLite WAL/read-only compatibility failure. It does not prove
that every upstream SQLite 3.51 build has the problem, nor identify the internal Apple VFS
implementation defect. It is not a Mac evidence-generation regression or six unrelated bugs.
It can affect Studio's real upgrade/recovery reads under this source-run interpreter; the
failures should not be dismissed as test assertions alone.

SQLite's [WAL documentation](https://www.sqlite.org/wal.html#read_only_databases) describes
read-only WAL access when sidecars exist or can be created. The failing runtime does not satisfy
the expected behavior demonstrated by the other runtimes in this controlled probe.

### Recommended root-cause fixes

1. **Make the supported source runtime reproducible.** Use a validated standalone Python/SQLite
   build for Studio source runs and tests, explicitly requesting uv-managed Python rather than
   accepting an arbitrary pyenv interpreter linked to the OS SQLite library. Rebuilding pyenv
   against a verified SQLite distribution is an alternative. Pin and test the selected build;
   a Python version requirement alone does not establish SQLite compatibility. The existing
   packaged Studio runtime is separately assembled from python-build-standalone; this diagnosis
   did not rerun or modify an installed package.
2. **Detect unsupported runtime behavior before touching user state.** Add a small temporary-file
   compatibility probe for backup and read-only WAL reopen, and an actionable diagnostic with
   Python/SQLite identity and supported-runtime guidance. Preserve the current fail-closed
   upgrade behavior. Use a behavioral test rather than banning all builds with one version.
3. **Treat snapshot normalization as a separate portability improvement, not the complete fix.**
   An experiment changed only the SQLite backup destination to `journal_mode=DELETE` before
   publication. This repaired the minimal backup read, but all six selected integration cases
   still failed farther along: post-checkpoint live database reads, retry/publication checks,
   and closed-store inventory still exercise the same incompatible runtime. A partial backup-only
   patch would move the error instead of resolving the whole contract.
4. Keep the six preservation tests and add the tiny runtime contract test. Do not replace all
   read-only opens with read-write access or add `immutable=1` to live databases. The latter
   disables locking and change detection and is appropriate only when immutability is proven;
   see [SQLite URI semantics](https://www.sqlite.org/uri.html#uriimmutable).

No production SQLite code was changed. Runtime standardization and preflight remain
recommendations, as requested. The snapshot experiment was a process-only monkeypatch in a
`/tmp` runner, not an edit to the source tree.

Evidence: `/tmp/studio-six-diagnosis.log`, `/tmp/studio-six-managed-runtime.log`,
`/tmp/studio-sqlite-backup-probe.py`, `/tmp/studio-six-normalized-snapshots.log`.

## Timer fix authorized and implemented

The user subsequently requested that the timer issue be fixed as well. Applied the previously
verified change to `desktop-ui/tests/ChatExperience.test.tsx`: fixed test clock, locally computed
start time, explicit one-second advancement, and a five-second post-completion check that the
saved duration stays fixed. Production timer code is unchanged.

- Full frontend suite after the applied fix: **340 passed in 33 files**.
- `uv run --no-sync ruff check .`: passed.
- `uv run --no-sync ruff format --check .`: passed (1,044 files).
- `git diff --check`: passed.

The earlier description of the timer patch as unapplied refers to the initial diagnosis only;
it is now an uncommitted change on `codex/studio-test-diagnosis`.

Reproduction commands from this worktree:

```sh
# Existing pyenv-backed .venv: reproduces the six failures.
uv run --no-sync pytest --no-cov \
  tests/integration/test_studio_state_edges.py \
  tests/integration/test_studio_state_upgrade.py

# Independent managed-runtime comparison; does not replace the existing .venv.
UV_PROJECT_ENVIRONMENT=/tmp/studio-diagnosis-managed-py312 \
  uv sync --python 3.12 --managed-python --extra studio --extra dev --locked
UV_PROJECT_ENVIRONMENT=/tmp/studio-diagnosis-managed-py312 \
  uv run --no-sync pytest --no-cov \
  tests/integration/test_studio_state_edges.py \
  tests/integration/test_studio_state_upgrade.py
```

The managed runtime resolved to CPython 3.12.11 in this experiment; record the actual SQLite
version as well when repeating it. This comparison is evidence for runtime selection, not a
request to change the product's pinned installer runtime or the user's other checkout.

Additional independent Studio service/unit gate on the original pyenv runtime:
`uv run --no-sync pytest --no-cov tests/unit/test_studio_*.py tests/unit/test_desktop_*.py tests/unit/test_resource_prediction.py`
completed with **533 passed and 1 skipped** in 329.92 seconds. This reinforces that the six
reproduced failures are in the WAL integration paths, not a generally failing Studio unit suite.


## Managed Python fix authorized and implemented

The user requested the uv-managed Python fix and explicitly excluded the installed macOS app.
Added `[tool.uv] python-preference = "only-managed"` to `pyproject.toml`, so ordinary project
`uv sync` and `uv run` select managed CPython. Updated `CONTRIBUTING.md` with explicit setup
flags, existing-environment migration guidance, interpreter verification, and the separate
flags needed for a tool environment that runs Studio modules.

Rebuilt only this diagnostic worktree's `.venv` using managed CPython 3.12.11 with SQLite 3.49.1.
The user's active checkout and installed app were not modified. No production SQLite logic or
runtime preflight was added; the earlier runtime-standardization recommendation is now
implemented, while the preflight remains a separate recommendation.

Validation:

- `uv sync --locked --all-extras` succeeded with the new project setting.
- Both affected integration modules: **145 passed, 1 skipped, 45 deselected** in 12.92 seconds;
  all six original failures pass. Output: `/tmp/studio-managed-default-tests.log`.
- Created a disposable pyenv-backed environment at `/tmp/studio-managed-migration-proof`, then
  ran ordinary `uv sync --locked --extra studio --extra dev` with `UV_PROJECT_ENVIRONMENT`
  pointing there. uv automatically replaced CPython 3.12.9 with managed CPython 3.12.11;
  verified its managed `sys.base_prefix` and SQLite 3.49.1. No manual deletion was needed.
- Ruff check and format check passed; `git diff --check` passed. Lockfile unchanged.
- The timer fix's full frontend result remains **340 passed in 33 files**; subsequent edits
  affect only uv configuration and development documentation.

The earlier pyenv reproduction command describes the pre-fix environment. With the new project
setting and refreshed `.venv`, that same command now passes.

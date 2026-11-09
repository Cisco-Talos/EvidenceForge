# Dependabot integration and fresh full-suite CI

The user authorized merging all open Dependabot PRs into dev and restarting the
full suites with the 120-minute limits from PR #464 (`e51eb56f`). No release tag
or publication is part of this work.

## Integration

PR #462 (setup-uv 10.3.3) merged directly as `af14962d`. The remaining ten PRs
are retained as merge parents on `codex/dependabot-integration-20261109`, resolving
adjacent workflow edits and overlapping lockfile updates together:

| PR | Update |
| --- | --- |
| #460 | setup-python 7.1.0 |
| #456 | setup-node 7.1.0 |
| #451 | upload-artifact 7.0.2 |
| #458 | virtualenv 21.14.13, superseded by #461's locked 21.15.1 |
| #461 | filelock 4.2.1; python-discovery 1.6.7; virtualenv 21.15.1 |
| #457 | Pydantic 2.14.1 / pydantic-core 2.50.1 |
| #455 | tzdata 2026.5 |
| #454 | Typer 0.27.3 |
| #450 | FastAPI 0.143.0 |
| #453 | Ruff 0.17.0 |

Filelock and virtualenv originally targeted main; they were retargeted to dev.
Their older main ancestry also conflicts with newer release-workflow and scenario
edits. Keep dev's current files and integrate only the reviewed dependency changes.
Keep lock revision 5, the current package set and product version 2.2.0a5. Retain
the newer overlapping virtualenv/python-discovery versions from #461. Merge the
refreshed setup-python head as well as its original reviewed head.

The timezone PR's old Studio failure was the chat elapsed-timer assertion already
repaired on dev. The old Pydantic and FastAPI Windows jobs were cancelled. These
historical checks do not establish the combined snapshot's result.

## Verification and restart

`uv sync --locked --all-extras` accepts the combined lock without changing it.
Ruff 0.17.0 lint/format pass across the repository (1,512 Python files). Version
synchronization and the revision-499 generation-behavior declaration pass.
Focused CLI/model/schema/Studio/config/release-pipeline tests pass: 375 passed,
107 deselected, in 139.25 seconds.

Use a merge-preserving integration PR into dev so all reviewed Dependabot heads
remain in dev's ancestry and the normal PR workflow starts fresh full Linux and
Windows suites with the 120-minute budget, plus native Studio/recovery checks.
Check results on the combined snapshot; older individual dependency checks and
the cancelled 45-minute Linux run cannot substitute for them.

PR #465 merged the integration as `c922fffb`; all eleven original Dependabot PRs
are marked merged and none remain open. CI run `42675010508` started on the
integration PR; its source tree is identical to the merged dev tree.

The user then requested synchronization and a fresh CI run directly on dev.
Local dev matches origin/dev. CI previously triggered only on main pushes and
PRs, with no manual dispatch. Add dev to its push branches and a manual dispatch
entry point; manual runs compare generation behavior with HEAD's first parent.
Keep existing read-only permissions, concurrency, suites and 120-minute full-suite
timeouts. Merging this workflow change starts CI on the resulting dev commit.

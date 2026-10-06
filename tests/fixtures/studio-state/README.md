# Frozen historical Studio fixtures

These files are hand-maintained, sanitized historical inputs. They are not serialized from current
Studio Pydantic models. Preserve their bytes as historical evidence; add fixtures rather than
rewriting old fixtures to make a changed reader pass.

| SQL fixture | Historical source | Shape exercised |
| --- | --- | --- |
| `preview.sql` | `a271102f` Studio preview, `store.py` schema | Original tables before imported bundles and history removal |
| `imports.sql` | `46d9ab70` imported bundles | Adds read-only imported bundle references |
| `history.sql` | `db3f73bf` job cleanup | Adds removed-history identities |
| `legacy.sql` | Studio library organization through `a2586655` | Library preference tables, before the two conditional columns |

The test loader also exercises the legacy schema with the conditionally added
`validations.dependency_sha256` and `items.search_entries` columns, both separately and together.
These are version-0 shapes because historical Studio did not stamp `user_version`.

`records.json` contains literal saved records: multiple workspaces, projects, views, library
assignments, conversation thread/draft associations, queued/paused/completed/failed jobs,
evaluation jobs, removed history, imported roots, custom output paths, Unicode and nullable
values, and populated derived caches. `@ROOT@` is replaced with a disposable test root. No real
Codex history, credentials, authentication tokens or production records are included.

`tests/support/studio_state.py` inserts these raw records directly using SQL. Its independent
inventory reads rows and parses raw JSON without current model construction. Synthetic engine
sentinels provide content-hash isolation checks; they are not scenarios for generation. Tests
that need valid engine authoring/generation use the repository's existing Studio fixtures.

The native subprocess worker and boundary declarations live in `tests/support/`. No production
application enables crash injection through environment variables. Native tests kill only their
exact unreaped `Popen` child, fail if the synchronization barrier times out, and reopen the fixture
in another interpreter. Every data root is disposable.

# Studio state upgrades and recovery

User approved implementation October 5, 2026. Branch: `codex/gui`. Engine-owned formats remain
outside scope. No DMGs, production data migrations or application version bump were performed.
Implementation validation used disposable roots. The user authorized committing and pushing the
cumulative upgrade/lifecycle/isolation work on October 6.

## Delivered implementation areas

1. **Contracts and baseline adoption.** `state_schema.py` freezes historical SQL;
   `state_records_v1.py` freezes saved-record readers and defaults. `state_migrations.py` declares
   immutable checksummed SQL/JSON/settings/layout/file contracts. `state_database.py` recognizes
   four historical table sets and both conditionally added columns, validates authoritative
   records, commits transformations/ledger/version together, fingerprints preserved state, and
   repairs only derived caches. Guarded settings and database stores reject unprepared state.
   Independent SQL and literal JSON fixtures cover six historical variants. Fresh installations
   initialize directly at version 1 without warning or backup.
2. **Backups, lifecycle and recovery.** `state_upgrade.py` and `state_io.py` implement prepared
   operation IDs, input rechecks, OS ownership locks, worker/authoring refusal, verified SQLite
   backup API snapshots, full-image seals and logical fingerprints, private images and journals,
   original absence, resumable restore, path/directory ownership checks, bounded file copies,
   and unresolved/newest-three retention. A WAL checkpoint materializes committed pages before
   replacement, preserving retryable original state if publication fails. Ledger timestamps are
   frozen per operation and included in conflict fingerprints. Startup, scheduling, scanning,
   normal HTTP and WebSocket activity remain gated during preparation. Authenticated helper
   replacement and process identity checks remain in place. Workspaces prepare lazily, share
   mutation ownership, and missing registered workspaces are not recreated. Normal directory
   initialization is retained for fresh installations when the selected folder already exists.
3. **UI and native gates.** Maintenance API exposes status, upgrade and restore; duplicate actions
   coalesce, opposing concurrent actions and stale IDs refuse. React renders the warning before
   explicit **Continue with upgrade** acceptance (revised by the user's follow-up), named progress,
   recovery actions/details, and alternative workspace selection.
   API schema generation is explicitly side-effect free. CI requires native macOS recovery,
   including bounded extended tests without coverage. The October 6 user support decision deferred
   Linux/Windows GUI gates; the original three-platform plan is superseded. The recovery job adds
   no DMG build. Documentation includes first-adoption compatibility, recovery scope, future
   migration rules, fixture provenance and a named-test traceability table.

The initial release adds markers and identities without reorganizing existing directories.
Scenarios/packs/documents/checkpoints, retired Qt data and Codex histories remain untouched.
Restoration is available for failed/interrupted preparation before normal use, never later rollback.
A completed restore remains in maintenance mode until explicit retry or a compatible older build.

## Validation evidence on macOS

- Full relevant Studio/desktop/resource-prediction + routine recovery regression run:
  **408 passed, 1 skipped** (196.91 seconds). The skip is the native Windows ACL test.
- Final focused run after preparation/duplicate-request refinements: **263 passed, 1 skipped**
  (64.82 seconds), covering all state tests, existing Studio service tests and runtime handoff tests.
  This includes 175 routine state tests and 88 existing service/runtime tests. After adding the
  missing-worker-identity refusal, the final state-only run passed **176 tests, 1 skipped**
  (16.98 seconds).
- Required extended suite on the final backend: **145 passed** (70.35 seconds), including 99 native termination cases,
  every coarse boundary, every package/pointer journal publication, repeated recovery, WAL-resident
  committed records, restore interruption, synthetic filesystem moves, a large history and many
  affected files. Native WAL cases also passed separately after their introduction.
- Frontend: **212 tests passed**, generated API types current, TypeScript/Vite build passed.
- Full Ruff check and format check passed: 966 Python files formatted consistently.
- Generation behavior declaration remains current (revision 158, digest
  `8587aa35fee18c127955a14ae30a989376606c2534f2df3a4a054c8dd234ae81`).
- CI YAML parsed successfully; recovery is required by `ci-required`. The original three-platform
  matrix was narrowed to supported macOS GUI acceptance on October 6.
- `git diff --check` passed; the three application version declarations are unchanged.

Tests use test-only observers and I/O adapters, precise barriers, and exact unreaped `Popen` child
termination. The filesystem durability model replays actual write/copy publication and detects
missing file or namespace flushes. Process-crash results and modeled power-loss assumptions are
reported separately; neither certifies every storage-device failure.

## Release acceptance still pending outside this local session

Native macOS recovery CI results must pass before release. Linux and Windows GUI acceptance,
including the native Windows ACL case skipped locally, is deferred by the October 6 user decision.
Existing release coverage/version/tag checks and native packaging acceptance
remain release requirements; no feature-branch version bump was made. The durable P1 release gate
in `TODO.md` remains open for these results. See the October 6
[isolation worklog](2026-10-06-studio-user-isolation.md) for final cumulative validation and delivery.

See [contracts, recovery instructions and test traceability](../studio-state-upgrades.md) and
[fixture provenance](../../tests/fixtures/studio-state/README.md). When adding migrations, retain
historical declarations/readers, introduce new versions, and extend the boundary and native matrix.

## Follow-up: acknowledgement and transient completion notice

User reported that the automatic upgrade warning disappeared too quickly, and its persistent
main-interface banner returned after quitting/reopening. Upgrade warnings presented in maintenance
now wait for **Continue with upgrade**; polling can observe an operation accepted in another
window but never initiates an upgrade itself. The completion message uses the existing five-second
notification and is consumed once. An initial ready status, including reconnection to the retained
helper on later launches, no longer produces an upgrade notice.

At the time of this follow-up, the helper had a separate lifetime and no idle exit; this was
subsequently corrected in the [October 6 lifecycle fix](2026-10-06-studio-helper-lifecycle.md).
The user's initial question was answered without changing shutdown behavior. This
follow-up changes frontend interaction and notification delivery, not backup or migration steps.
Regression coverage verifies no upgrade request before acceptance, busy feedback after acceptance,
one-time completion across reconnect/restart, and expiration through the existing notification.
Validation: all **214 frontend tests** passed; generated API type check and TypeScript/Vite build
passed. No backend persistence or helper shutdown changes were made in this follow-up.

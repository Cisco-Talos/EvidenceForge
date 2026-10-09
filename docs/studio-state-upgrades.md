# Studio state upgrades and recovery

Studio prepares its persistent UI state before opening a normal session. The first adoption
upgrade recognizes supported unversioned Studio data, preserves it in a verified recovery
package, and adds version markers without moving existing content. New installations initialize
at version 1 without an upgrade backup or compatibility warning.

This covers the Studio database and its saved JSON, settings, workspace/library organization,
project and conversation associations, job metadata, imported-bundle references, and Studio's
private filesystem conventions. Scenarios, packs, generated documents, immutable generation
inputs, checkpoints, retired Qt state and Codex-owned conversation histories are outside this
migration. Conversation records preserve thread IDs and draft associations; they do not back up
Codex itself.

## What users see

The upgrade screen keeps its warning and details visible until the user selects **Continue with
upgrade**. It does not dismiss the warning or start the prepared operation on a timer. A window
reconnecting to an already-running, accepted upgrade continues to monitor it. Named phases and
step counts report progress. Normal API operations, scanning,
authoring and job scheduling remain gated until preparation and validation finish. Health reports
helper availability separately from readiness. When this window observes an upgrade complete,
the existing notification system displays a completion message for five seconds. It does not
repeat the pre-upgrade warning on reconnection or later application launches.

After a failure, Studio offers **Retry upgrade**, **Restore previous UI state**, and **View
details** when those actions are safe. Restoration verifies the original package, restores original
contents or original absence, and leaves Studio in maintenance mode. Choose Retry to attempt the
upgrade again, or close Studio and reopen a compatible previous application. Restoration does
not install that application. A missing or incompatible selected workspace also lets you choose
another workspace; its records are retained and a missing registered directory is not recreated.

Restoration is for failed or interrupted preparation before normal use resumes. There is no
built-in rollback after successful preparation and subsequent activity. Independently edited
files, unknown worker ownership, active workers or retained active authoring block the operation;
Studio does not terminate processes to make an upgrade proceed. Resolve the reported conflict
and retry. Unsupported newer versions and malformed authoritative state remain blocked rather
than being reset.

## Contracts and package locations

The four versions are independent of the application release number:

| Contract | Version 1 marker | Authority |
| --- | --- | --- |
| Database and its saved JSON | SQLite `PRAGMA user_version` | Studio SQL and record interpretations |
| Settings | `{schema_version: 1, settings: ...}` | Disk-only envelope; settings API shape is unchanged |
| Private layout | `studio-state.json` in the private data directory | Stable installation identity and private conventions |
| Workspace layout | `.eforge/studio/layout.json` | Stable workspace identity and Studio-managed conventions |

Layout documents also record manifest format, application/runtime provenance and migration
checksums. The database ledger records immutable migration IDs, checksums, application/runtime
provenance and application timestamps. Workspace receipts are namespaced by workspace identity.
Workspaces are prepared on selection, so unavailable unrelated workspaces do not block opening
a supported workspace.

Packages live in `studio-upgrades/` beneath the private data directory, outside cache and runtime
installations. User data locations and routine backup instructions are listed in the
[Studio guide](studio.md#workspace-and-saved-studio-data).
Each operation has its own package containing original and proposed images, a sealed manifest,
and a durable journal. SQLite snapshots use the backup API and include committed WAL data but
exclude uncommitted transactions. Both complete image checksums and logical database fingerprints
are checked. Only declared affected files are included; bundles and pack repositories are not
recursively copied. Private directories and files retain owner-only restrictions.

All unresolved packages and the newest three completed packages are retained. Pruning occurs
only after another successful upgrade; cleanup failure retains packages and cannot invalidate a
successful operation. Already-current startup creates no additional recovery package.

Earlier unversioned binaries cannot acquire these safeguards retroactively. Before returning to
one, use the verified pre-adoption backup rather than letting it open upgraded private state.
For a failed upgrade, use the restoration action, close the current helper and workers, and then
open the compatible build. After a successful upgrade, built-in restoration is unavailable: any
manual recovery must use verified original images in a separate private profile, with all affected
applications stopped, and must account for newer activity absent from that snapshot. Never replace
current state with an unchecked image or run two builds against the same profile. Retain the
package's manifest and journal with those images. Workspace and engine files remain at their
original locations; the package is not a complete copy of the project or Codex history.

## Execution and interruption protocol

The order is inspect, acquire ownership and recheck, display any compatibility warning, create
and verify the backup, transform, validate, durably record completion, and enable normal activity.
The warning remains visible until explicit acceptance triggers the frontend's mutation request.
Mutation requests contain the
prepared operation ID; duplicate requests coalesce and stale identifiers are rejected.

Global and workspace ownership use OS locks held through normal activity, so upgrades and normal
Studio mutations share ownership. Authenticated helper replacement retains runtime/process
identity verification. Verified orphan workers also block migration; stale or reused PIDs do not
cause another process to be stopped. Queued records without live workers remain eligible while
scheduling is suspended.

Database transformations, ledger entries and the version marker commit in one transaction in a
private working image. Before publishing that image, committed WAL pages in the original database
are checkpointed; a busy independent reader/writer refuses publication. This preserves retryable
original logical state if replacement fails. Settings and layout images publish through flushed
temporary files and atomic replacement; layout markers publish after their declared file steps.
Original absence is a supported before-image, including an absent original database.

The package journal publishes before its discovery pointer. Startup compares both journals,
checks operation ownership and the package seal, and compares observed files against verified
before/after images. A proven interrupted step is skipped or completed, rather than blindly
repeated. Unknown intermediate or independently changed state remains behind the maintenance
gate. Restoration uses the same observed-state protocol and journal, and can itself be resumed.
Fresh initialization has its own frozen input proof and durable journal, without a recovery
package, and refuses to adopt independently populated state.

Manifests and journals supply evidence, not path authorization. Destinations come from code
and registered roots; exact declared keys, locations and migration checksums must match.
No-follow filesystem operations reject symlinks, reparse points and hard-linked files. Recorded
directory identities and publication-time rechecks detect path substitutions and conflicting
edits. Local filesystems are the supported transactional boundary; shared or independently
modified workspaces must stop on conflict.

POSIX publication flushes the file and parent directory; Windows uses native handle operations,
owner ACLs, flushed files and write-through replacement. Process termination tests establish
process-crash behavior. A separate filesystem durability model checks ordering assumptions,
including deliberately weakened flush protocols. Neither is a certification against every
hardware, storage-controller or power-loss failure.

**Current GUI support is macOS only.** Linux and Windows ownership/publication adapters remain
experimental. Their native GUI acceptance is deferred until those platforms are considered for
support; engine and CLI acceptance on those platforms is unchanged.

## Adding a future migration

Review the three implementation areas together: frozen contracts and guarded readers; backup,
execution and recovery coordination; frontend and native release gates.

1. Add a new immutable declaration in `state_database.py` or `state_migrations.py`. Never edit a
   released declaration, SQL, defaults or decoder. Declare source/target versions, compatibility
   impact, exact affected files, preconditions/postconditions and recovery behavior. Consecutive
   transitions must be unambiguous; skipping releases executes the full ordered chain.
2. Freeze the historical decoder for the new saved-record contract. A JSON interpretation change
   requires a database migration even when SQL columns stay unchanged. Preserve IDs, timestamps
   and associations; never persist new IDs or times from current model default factories.
3. Extend supported-version recognition and target readers/settings/layout validation. The current
   shipped reader supports versions 0 and 1; synthetic versions 2 and 3 in tests are not advertised
   as production formats. Add workspace declarations and exact path bindings before implementing
   a filesystem move. The first adoption release has no relocation declarations.
4. Add independently authored historical fixtures and preservation inventories. Include literal
   historical defaults and malformed/future cases. Schema-contract tests deliberately fail when
   saved models change without updating the versioned contract.
5. Enumerate every new persistent publication boundary, including package/pointer journals and
   restoration. Add deterministic observer barriers and injectable I/O adapters in tests. Normal
   applications have no environment-controlled crash hooks.
6. Run routine tests and the required extended matrix on the supported native macOS CI runner.
   Update the traceability table and worklog; use existing release coverage and version-bump rules.
   Any future GUI platform must pass its own native crash, recovery and ownership gates before
   support is advertised.

Derived FTS and validation/dependency/prediction caches can be rebuilt after authoritative
validation. Missing or malformed authoritative records must never be silently deleted. API-type
generation uses a schema-only application and cannot initialize real data.

## Test traceability and release gate

Fixtures and their provenance are documented in
[`tests/fixtures/studio-state/README.md`](../tests/fixtures/studio-state/README.md). Test names below
are executable contracts, not substitutes for review of each invariant. Parameterized cases cover
both expected results and safe refusal. Inventories read SQL and frozen JSON directly rather
than constructing all evidence through current models. Native tests kill the exact harness-owned
child at a barrier, fail on barrier timeout, and recover in a fresh interpreter.

| Guarantee / failure class | Named evidence |
| --- | --- |
| Every supported legacy shape preserves IDs, counts, relationships, paths and preferences | `test_historical_upgrade_preserves_independent_inventory` |
| Frozen saved schemas/defaults cannot change unnoticed | `test_current_saved_record_schema_matches_frozen_version_one` |
| Skipped versions, SQL + JSON changes and idempotency | `test_consecutive_sql_and_json_transforms_preserve_ids_and_timestamps`, `test_consecutive_migrations_and_failure_rollback_are_transactional`, `test_sql_registry_preserves_semicolons_in_literals_and_trigger_bodies` |
| Settings preserve unspecified values and historical defaults | `test_settings_chain_uses_frozen_literals_and_retains_unspecified_values` |
| Future/malformed versions, ledger disagreement, damaged SQL/JSON and missing authoritative state refuse writes | `test_unsupported_or_corrupt_state_is_not_rewritten`, `test_layout_headers_reject_malformed_or_future_versions`, `test_missing_authoritative_table_is_not_silently_recreated`, `test_non_object_authoritative_json_is_refused_before_writes` |
| Fresh/current startup has no backup or repeated warning; interrupted fresh initialization is safe | `test_fresh_install_initializes_without_backup_or_warning`, `test_current_startup_does_not_back_up_or_repeat_adoption_warning`, `test_fresh_initialization_crashes_resume_without_a_recovery_backup`, `test_initialization_refuses_independently_populated_database` |
| Only derived state is rebuilt | `test_corrupt_derived_records_and_missing_search_are_rebuilt_only`, `test_missing_derived_tables_are_rebuilt_without_changing_user_metadata` |
| SQLite backup includes committed WAL, excludes uncommitted rows, tolerates readers; publication failure retains WAL records | `test_committed_wal_and_uncommitted_rows_are_handled_by_backup`, `test_backup_ignores_uncommitted_writer_then_retry_succeeds`, `test_wal_resident_records_survive_failed_database_publication`, `test_native_wal_upgrade_and_restore_crashes_retain_committed_records`, `test_independent_sqlite_writer_blocks_publication_and_allows_retry` |
| Incomplete/corrupt/malicious packages cannot authorize restoration | `test_bad_package_cannot_authorize_restoration`, `test_injected_partial_io_never_accepts_an_incomplete_package` |
| Disk exhaustion, permission errors, I/O errors, short writes, failed flush/rename retain recoverable state | `test_storage_errors_never_report_success_or_destroy_recovery`, `test_failed_atomic_publication_retains_previous_file`, `test_atomic_publication_handles_short_writes_and_copy_permissions` |
| Every coarse persistence boundary survives raised errors and native termination | `test_io_failure_has_safe_retry_and_preserves_records`, `test_native_upgrade_boundary_crashes_recover_without_record_loss` |
| Every upgrade/restore package and pointer journal publication survives interruption | `test_each_upgrade_journal_io_error_preserves_recovery`, `test_each_restore_journal_io_error_preserves_recovery`, `test_every_upgrade_journal_publication_survives_native_termination`, `test_every_restore_journal_publication_survives_native_termination` |
| Restoration preserves original contents/absence, survives repeated crashes and never becomes later rollback | `test_failed_upgrade_restores_original_contents_and_absence`, `test_restore_recovers_original_absence_of_each_private_file`, `test_restore_can_itself_fail_and_resume`, `test_native_restore_boundary_crashes_resume_restoration`, `test_repeated_upgrade_and_restore_crashes_keep_original_backup`, `test_api_warns_and_gates_before_upgrade_and_rejects_stale_restore` |
| Filesystem steps preserve layout identity, only advance markers after success, and restore safely | `test_consecutive_directory_relocations_are_backed_up_and_recoverable`, `test_native_filesystem_step_crashes_preserve_or_restore_originals`, `test_file_declarations_cannot_include_engine_or_external_paths` |
| Traversal, substitutions, links/reparse points, aliasing and independent edits never overwrite unrelated files | `test_aliased_state_is_rejected_without_external_writes`, `test_swapped_settings_parent_cannot_overwrite_external_file`, `test_regular_parent_substitution_is_refused_before_external_overwrite`, `test_independent_leaf_edit_at_publication_is_not_overwritten`, `test_independent_changes_block_restore_without_overwrite` |
| Concurrent launches, duplicate requests and obsolete IDs cannot conflict | `test_duplicate_threads_apply_exactly_one_transition`, `test_http_duplicate_restore_observes_existing_operation_and_conflicts_refuse`, `test_http_preparation_holds_ownership_before_warning_and_backup`, `test_inspection_change_refuses_obsolete_preparation_without_backup`, `test_lock_and_obsolete_requests_refuse_conflicting_operations`, `test_losing_launch_cannot_overwrite_owner_journal`, `test_native_crash_smoke_preserves_identity_and_releases_lock` |
| Live/orphan/unknown workers and active authoring block; unrelated processes survive | `test_worker_ownership_never_stops_a_process`, `test_running_job_without_worker_identity_blocks_preparation`, `test_retained_authoring_blocks_upgrade_without_clearing_associations`; existing `test_studio_runtime.py` helper handoff tests |
| Missing workspaces remain registered and another workspace can open | `test_missing_registered_workspace_is_not_recreated_and_another_can_open`, `test_missing_workspace_outside_recents_is_still_registered`, `test_unavailable_other_workspace_does_not_change_saved_selection` |
| Workspace/private/engine/Qt/Codex isolation | `test_workspace_scope_preserves_private_state_and_engine_files`, `test_upgrade_preserves_engine_qt_and_codex_history_bytes` |
| Pending packages survive retention/pruning failures | `test_retention_keeps_pending_and_latest_three_completed`, `test_pruning_failure_does_not_make_successful_upgrade_recoverable` |
| Private access restrictions persist on native platforms | `test_private_permissions_survive_upgrade_and_restoration`, `test_windows_backup_and_restoration_keep_owner_only_acls` |
| Large histories and many files preserve state with progress | `test_large_history_preservation_and_responsive_progress`, `test_many_affected_files_use_bounded_copy_and_survive_restart` |
| Real file/copy publication follows durability ordering; weakened protocols are detected | `test_actual_atomic_publication_has_durable_bytes_before_namespace` |
| Authenticated maintenance, 503 gates, health readiness and side-effect-free schema generation | `test_api_warns_and_gates_before_upgrade_and_rejects_stale_restore`, `test_schema_generation_has_no_state_side_effects` |
| Explicit upgrade acceptance; completion toast expires and never replays on reconnect/restart; failed/restored/future state stays gated | `desktop-ui/tests/useStudio.test.tsx`, `desktop-ui/tests/StateMaintenance.test.tsx`, `desktop-ui/tests/App.test.tsx`, `desktop-ui/tests/useNotice.test.tsx` |

Routine commands, from the repository root:

```sh
uv run pytest --no-cov tests/integration/test_studio_state_*.py tests/unit/test_studio_state_*.py
uv run pytest --no-cov tests/unit/test_studio_*.py tests/unit/test_desktop_*.py tests/unit/test_resource_prediction.py
npm --prefix desktop-ui test
npm --prefix desktop-ui run types:check
npm --prefix desktop-ui run build
uv run ruff check .
uv run ruff format --check .
```

Required extended gate for changes to upgrades, backup, recovery, startup, persistence or the
relevant filesystem helpers:

```sh
uv run pytest -m slow --no-cov tests/integration/test_studio_state_crashes.py tests/integration/test_studio_state_edges.py tests/integration/test_studio_state_migrations.py
```

`Studio state recovery` in `.github/workflows/ci.yml` runs routine and required extended tests
natively on macOS and is a dependency of the aggregate CI gate. Linux and Windows GUI native gates
are deferred by the October 6 support decision. Optional soak
runs do not replace this gate. Release coverage uses the repository's existing default-suite
70% requirement, separately from the extended tests; slow/soak are never run under coverage.
No DMG build is added or required by the recovery job.

Failure artifacts use disposable fixtures and sanitized versions, journals, boundaries and
inventories. No production state or authentication tokens belong in those artifacts. Release
acceptance requires the macOS native GUI gates and applicable backend/frontend, generated-type,
lint, build and release checks to pass. Local macOS results do not replace CI or establish support
for Linux or Windows. The existing engine/CLI Linux and Windows gates remain required.

The artifact naming feature adds database migration `studio-db-0002` (1 → 2). It defaults
`items.display_name` and `conversations.draft_display_name` to null without changing identities,
source paths, timestamps, projects, threads or runs. Version 1 decoders and migration checksums
remain frozen; version 2 has a separate frozen reader. Artifact titles remain authoritative in
portable Schema 3 YAML; the catalog field is a derived cache. The conversation field remembers
an optional title before the authored file exists. Older Studio readers cannot accept these new
JSON fields, so upgrading existing state uses the normal reviewed backup/recovery workflow.

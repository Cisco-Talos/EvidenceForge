# Studio managed draft creation and missing-source recovery

## Scope and cause

User approved preventing the duplicate/missing-scenario condition and testing on macOS first.
The Linux investigation is in `2026-10-09-studio-linux-setup.md`, section “Duplicate scenario
investigation — source moved after indexing”. Studio supplied a nonexistent legacy authoring
path; the scenario skill created a managed scaffold elsewhere, then moved only its YAML to
Studio's target. Path-based indexing kept both registrations and a stale receipt. Both YAML
snapshots recorded the same draft UUID. This is shared application behavior.

## Implementation

- New scenario conversations immediately create the canonical shared CLI scaffold, bind a real
  catalog item, and select its authoring conversation. Project context is applied on creation.
  Preview-era pending conversations acquire or bind a real source before their next turn.
- First and resumed Codex instructions preserve the supplied draft path, UUID, receipt and
  companions. The canonical artifact lifecycle skill reference gives the same guidance.
- Indexed root-document scalar entries retain draft identity without changing the persisted
  CatalogItem schema. Scans reconnect exactly one missing draft with one live UUID match inside
  the workspace. Ambiguity, active chats/jobs and conflicting project/folder assignments stop
  automatic reconciliation. Same names alone never match.
- Relinking is a SQLite transaction preserving the original item ID and merging conversation
  associations. Cache invalidation refreshes validation/dependencies/forecasts. Durable relocation
  events retain previous source paths; original generation/evaluation records and captured inputs
  remain unchanged. Frontend run selection, state summaries and export use these associations.
- Snapshot-only missing flags route the library to a recovery page, with native Browse, exact
  path selection and guarded manual relink. Legacy relink requires identical bytes.
- Removing a missing registration archives its metadata and keeps chats, Codex threads, events,
  source trees and job records. If the original path returns with the same draft ID (or exact
  legacy bytes), indexing recovers the prior item ID and GUI metadata. This requires no database
  schema migration. Chats stop appearing under the removed entry until that recovery.

## macOS evidence

- New recovery contract suite: 11 passing tests, including canonical receipt/source creation,
  in-place draft conversation reuse, missing registration removal and restoration, unique moves,
  original ID/project preservation, two existing registrations' conversation merge, immutable
  jobs, ambiguous copies, independent same-name drafts, active-work guards, legacy exact-byte
  recovery, authorization, external paths and symlinks.
- Studio service + recovery suites passed 90 tests before the added preview-era/resume variant;
  both variants of first/resumed draft instructions then passed independently. Artifact lifecycle,
  pack lifecycle and skill installation suites passed in the preceding combined run (76 tests).
- Frontend recovery, App and ImportDialog tests passed 117 tests after adding the App missing-page
  check. Full frontend suite also exposed older publication-default and diagnostics request-count
  assumptions from earlier work in this branch; those fixtures were aligned with the current UI.
- Native debug `.app` built successfully on Apple Silicon macOS using
  `npm --prefix desktop-ui run build:native -- --debug --bundles app -- --locked`.
- Native UI acceptance used isolated state/workspace under
  `/private/tmp/eforge-source-recovery-acceptance/`. Created `mac-recovery-test` through the UI;
  checked that YAML and `draft.json` existed before any authoring message. Moving its YAML then
  clicking Refresh retained one library row and changed the source path. Holding the source
  outside the workspace showed “Source missing”; its recovery page displayed the indexed path,
  Locate source, native Browse, retained conversation count and removal review. Cancelling removal
  and manually locating the restored file returned to the scenario workspace, preserving its
  original conversation. No LLM authoring turn or generation was sent for native acceptance.
- The user's macOS scenarios and runs were not used for destructive testing. The Linux VM has
  not received this change during macOS acceptance.

### Final checks

- Combined backend run passed all **167 tests** (Studio service, 9 recovery contracts, artifact
  lifecycle, pack lifecycle, skill installation). Added archive-ID reuse and conflicting-project
  regressions afterward; the complete **11-test recovery suite** passed on the final code.
- All **292 frontend tests in 29 files** passed. Type generation check, TypeScript/Vite build,
  native macOS `.app` build, repo-wide Ruff lint and formatting checks passed. Generation behavior
  manifest remains current at revision 161, digest
  `bd9e13343c8fb72dfdbbb03a284357a3a0664d362c1b0503222bc76b2b6584d4`.
- Final native build is available at
  `desktop-ui/src-tauri/target/debug/bundle/macos/EvidenceForge Studio.app`. Closed the isolated
  acceptance app and reopened the normal macOS workspace, confirming its four original entries
  and connected Codex status. Linux source/state and the released DMG remain unchanged.

## Remaining acceptance / limits

Run Linux native acceptance after macOS review, with a private-state backup before reconciling
its existing stale/live pair. Preserve the orphan managed receipt and any companions until their
ownership and relocation are reviewed; automatic reconciliation changes index associations only.
Automatic movement reconciliation currently covers Schema 3 drafts with a cached root UUID,
not arbitrary legacy edits, published release movement, or ambiguous copies. Manual legacy
recovery accepts exact source bytes, not a guessed same-name match. Existing installed skill
copies are not overwritten automatically; Studio's direct start/resume instructions also enforce
canonical draft use. No version bump, commit, DMG publication or VM state mutation in this task.

# Studio pack lifecycle review

The user approved an end-to-end Stage 2 review on October 6, including deletion, for both
industry and organization packs. Work is on `codex/studio-pack-lifecycle`, from a clean `dev`.
No real packs, scenarios, conversations, helper or generated runs are modified by acceptance
checks. No application version bump or DMG is part of this effort.

## Scope and findings

Creation, skill-guided conversations, cloning, structured asset edits into new versions,
reviewed `.efpack`/source-workspace imports, portable closure export and scenario selection are
already delivered. They remain the owning paths. Two missing product paths were addressed:
pack workspaces had no validation/release review and pack versions had no deletion action.

- **Validation & release** checks current canonical catalogs and locked dependencies, showing
  the exact identity, digest, catalog export counts and organization model contributions.
  Invalid packs expose findings and prepare a repair conversation; the user submits the draft.
  Export uses the existing native Save/portable `.efpack` path and revalidates its captured closure.
  This is file-based sharing; remote registry/marketplace publication remains future work.
- **Delete version** appears in workspace-pack library and workspace menus. Bundled packs are
  protected. Review checks actual scenario/include/context references and organization dependency
  locks, including scenarios indexed before their YAML became unreadable. Consumers, unknown
  references and active authoring block removal. Exact version and repository location matter;
  a package or different project/version with the same name does not block an unrelated copy.
- The final confirmation rechecks all version files (including non-semantic companions), directory
  identity and consumer inventory. Source scans, asset edits/imports and authoring submission
  coordinate with deletion. A stale review requires refresh. Captured runs and exports are untouched.
- Removal atomically moves the exact version into `.eforge/deleted-packs/<operation>/pack` and
  removes its local Studio index/conversation associations, preserving Codex histories. A private,
  version-1 `deletion.json` receipt precedes the move. POSIX path traversal/rename use no-follow
  directory handles and flushed publication. Interrupted index cleanup reconciles on later scans;
  a failed SQLite transaction restores the original file location. Retained files and receipt allow
  recovery to the original path. There is no automatic purge or GUI restore action in this slice.
  Native Windows GUI support remains deferred; its portable fallback is not claimed as acceptance.
- Pack validation proves pack structure/semantics, not completeness of a partial organization.
  The UI explains that a consumer scenario still needs validation. Isolated conversational drafts,
  revision acceptance/history and broader structured editing remain Stage 3/Stage 2 follow-ups.

## Acceptance

Disposable API trials for each pack type cover create, structured add, new exact version,
canonical validation, portable export, reviewed import in a second workspace, digest preservation,
consumer compilation, referenced-version refusal and unreferenced exact-version removal.
Existing authoring tests verify first-turn skill selection for both pack types; no paid/live
LLM authoring turn was initiated. Additional tests exercise stale files/new consumers, package and
foreign-root protection, included path references, locked dependencies, corrupt catalogs,
unreadable indexed consumers and organization manifests, private recovery paths, active turns, captured artifact preservation,
interrupted retirement and index-failure rollback.

Visual checks used an isolated preview workspace: canonical organization/dependency validation,
scenario-consumer refusal and successful deletion of an unreferenced industry version. The
deleted version disappeared from the library while its retained recovery files remained.
The dialog's initial placement below the viewport was caught and corrected during this review.
Screenshots are retained under
`/Users/dabianco/.codex/visualizations/2026/10/06/01a1124a-9080-70d1-9f27-10c6f5e05cb0/`
as `studio-pack-release.png`, `studio-pack-delete-review.png` and `studio-pack-deleted.png`.
Temporary preview processes were stopped; the user's running helper was not restarted.

The frontend's 224 tests, generated-type consistency check, production build and Apple Silicon
macOS `.app` build passed. Vite retains the existing large-chunk advisory. Full Ruff lint,
formatting and whitespace checks passed. The final relevant backend/skill suite passed all
239 tests, including the unreadable-organization regression. No full-engine, coverage, extended
release or soak gate is claimed for this Studio slice.

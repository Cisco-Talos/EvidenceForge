# Publication completes its source draft

## User intent and scope

Before publishing 2.2.0a2, the user requested that publishing a scenario leave its published
version in the library and consume the draft it came from. Revising a release creates a new
independent draft. The user explicitly confirmed the same workflow for industry and organization
packs. Older published versions should remain available but be hidden by default.

## Shared lifecycle and recovery

The immutable release receipt already records the exact finalized draft ID and digest as its
last parent. Shared artifact services use that verified authority to identify completed drafts.
Draft inventory and file-backed libraries omit completed snapshots; supported editing and resume
operations require a new draft from the release. Earlier ancestors and independent siblings are
not consumed. Drafts with unpublished edits made after earlier application versions published them
remain discoverable rather than losing those edits. No authored source bytes are rewritten or
removed. Retained files support exact ancestry and historical comparisons.

Completion becomes authoritative only with the atomic installation of a verified release.
Validation failures and failures before installation leave the draft editable. A committed
publication interrupted during Studio index transfer is reconciled on refresh/restart, preserving
the existing release and avoiding duplicate publication. The existing deletion identity receipt
now also retains the finalized draft reference, preventing a deleted release from resurrecting
its unchanged completed draft. It retains no authored files, assets, notes or generated data.

Studio consolidates the draft/release registrations in one SQLite transaction, retaining the
draft's stable item ID, project/folder/visibility, conversations and prior source paths. Captured
job inputs and Codex thread identifiers are unchanged. Pending/running generations keep their
captured inputs; an active authoring turn must finish before publication. Persisted record shapes
and database schema are unchanged, so no database migration is needed.

## Library presentation

Computed lineage metadata identifies exact published versions. Scenario and pack libraries select
the newest numeric release version in each family by default, retaining active drafts, legacy
sources and separate publisher forks. **Show previous versions** restores the older rows;
explicit pack-version filtering also selects an older release. This does not change exact
references or immutable files. The publication dialog and canonical lifecycle/Studio guides
describe the same workflow. The generated API types include the computed version metadata.

## Validation and release handoff

New shared completion regressions cover scenario and both pack kinds, new-draft identity,
independent siblings and fork ancestors, failure before commit, old unpublished edits,
companion-file mutation guards and permanent release deletion. Studio regressions cover stable
registration, chat/project/run preservation and interrupted index reconciliation. Interface tests
cover numeric versions and the previous-version toggle.

Initial lifecycle group: 84 passed, one slow test deselected. All 298 frontend tests pass;
generated API freshness and production build pass. The existing frontend chunk-size warning
remains. Broader native Studio/desktop/artifact/skill regressions pass: 634 tests, 54 expensive
tests deselected. The final completion/publication/deletion group passes all 46 tests, including
companion-file guards. Cross-platform CI and updated native previews are pending.
An additional fault probe reproduced a completed staging receipt being observed before its
exclusive publication rename. Completion now requires the exact canonical publisher/kind/name/
version directory, ignoring staging trees and misplaced receipts. All 26 completion and Studio
source-history tests pass with that correction, including a read during the pre-rename fault.
Generation behavior remains revision 162 with the unchanged surface digest. Product
version remains 2.2.0a2. No release tagging or publication is authorized or performed.

The previously accepted x86_64 VM preview predates this change. Updated native preview artifacts
and their source snapshots will be recorded after verification.

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
companion-file guards. The final cross-platform CI and native preview evidence is recorded below.
An additional fault probe reproduced a completed staging receipt being observed before its
exclusive publication rename. Completion now requires the exact canonical publisher/kind/name/
version directory, ignoring staging trees and misplaced receipts. All 26 completion and Studio
source-history tests pass with that correction, including a read during the pre-rename fault.
Generation behavior remains revision 162 with the unchanged surface digest. Product
version remains 2.2.0a2. No release tagging or publication is authorized or performed.

The previously accepted x86_64 VM preview predates this change. Updated native preview artifacts
and their source snapshots will be recorded after verification.

Cross-platform CI exposed four existing launchd fixture failures on Linux: patching the global
`sys.platform` also activated macOS `/tmp` alias normalization in unrelated private-state I/O.
The helper tests now simulate the platform only in the background-launch module, leaving real
filesystem semantics and ownership checks intact. All five launch contracts pass on both native
macOS and the x86_64 Linux VM. This changes tests only; packaged application code is unchanged.

## Updated native previews

Both previews were built from exact application snapshot
`96642857a82fd11472da649c7364f8e950cc7b90`; later commit `0e5bcdf4` changes only test fixtures.
Each VM passed 34 publication/Studio tests, all 298 frontend tests, 12 native shell contracts,
version freshness, packaged CLI/resource checks, checkpoint-enabled generation and bundled
GStreamer appsink verification. Installer-pair and checksum checks also passed after download.

- x86_64: `dist/linux/96642857-vm/x86_64/EvidenceForge-Studio-2.2.0a2-x86_64-test.AppImage`,
  141769208 bytes; SHA-256
  `3dc18c6f3ec011cd9163a66fe3b24f36624a503c9456e13c5b8ebc996ac4141a`.
- ARM64: `dist/linux/96642857-vm/aarch64/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage`,
  135346696 bytes; SHA-256
  `9cc15d30f66e0e234e44029f83d688d7f8bd959551b9810bb3a82109c9e8ccd0`.

VM checkout/logs are retained under `~/eforge-previews/96642857/`; existing host checkouts
and earlier preview installers were preserved. ARM packaging resumed after the Mac backing
volume ran short of free space and the user restored the VM. Only disposable local Rust
compilation caches were cleared. The original interrupted log is retained beside the resumed
log. Both final build statuses are zero.

The user has not yet accepted these updated previews. No release tag or publication was made.

## Integration and cross-platform gates

[PR #446](https://github.com/Cisco-Talos/EvidenceForge/pull/446) merged into `dev` as
`8562df28bb4fa378e040e6c3c7e58c23381731f6`. All required gates passed in
[CI run 38283012340](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/38283012340):
Linux engine 11923 passed, 70 skipped; Windows engine 11960 passed, 33 skipped;
Studio backend/frontend/native shell/build gates on macOS, Linux x86_64 and ARM64;
native recovery gates on all three hosts; Windows checkpoint durability; lint and Required CI.
All nine completion regressions passed on both Linux and Windows. Each native Studio backend
suite passed 473 tests, with all 298 frontend tests and 12 shell contracts passing.

CI checked out synthetic PR merge `bc5f4effca8143d41c52fc7f4940f40ab8d58ceb` (head `0e5bcdf4`
into base `f7cb9cea`); its tree matches the integrated dev merge. The Apple Silicon standalone
app passed isolated packaged CLI/resources, behavior/runtime checks and checkpoint generation.
The CI archive is saved at `dist/macos/0e5bcdf4-ci/EvidenceForge-Studio-aarch64-test.zip`;
SHA-256 `9a52210c61a0f4d6102749be999004e8a819f87978d64df7785fc9f093a484df`.
The downloaded ZIP passes compressed-data integrity verification. This is a test app archive,
not a release DMG. Updated native GUI acceptance remains open before publication.

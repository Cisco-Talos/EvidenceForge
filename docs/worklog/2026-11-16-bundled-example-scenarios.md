# Bundled example scenarios

Branch: `codex/bundled-example-scenarios`, based on `dev`.

## Approved decisions

Ship a browsable offline `examples/<scenario>/<version>/` collection of published Schema 3
scenario releases under the existing `evidenceforge` publisher. The collection may be empty;
real example authoring is deferred. Reuse shared file services, with no new CLI commands or
required skill changes. Preserve all authored source companions in managed publication/forks.

First run enrolls only the new OS user's original default workspace and creates an Example
Scenarios project, including for an empty collection. Existing users are never automatically
enrolled. New versions/additions install on launch/return to that workspace while its tracked
project exists. Project renames preserve enrollment; project deletion stops automatic updates.
Individual deletion suppresses its scenario family until manual installation. Custom workspaces
remain manual-only even after installation. Settings offers install/update and folder opening.

Use the existing Packs latest-version presentation. Forks select a destination project (default
Ungrouped), configured user publisher or the ordinary anonymous-draft behavior, with exact official
ancestry. Preserve releases, user work and deliberate project moves. Deleted releases can only be
restored using their original recorded digest, without freeing reserved identities.

## Implementation

Added shared receipt-based source/installed collection discovery and wheel resource inclusion,
directory import and exact-digest restoration. Managed source capture preserves nested authored
companions while retaining include/corpus checks. Trusted package-resource reads support package
manager hardlinks; workspace imports remain independent regular files and ordinary artifact
operations retain their default hardlink rejection.

Database migration `studio-db-0004` adds frozen example installation records without enrolling
existing users. First-run enrollment precedes initialization completion. Additive installation,
family exclusions, pending restoration and index intents preserve project placement across
interruptions. Settings installs bind their requests to the reviewed workspace. Project deletion
cancels pending manual installation and serializes with library installation.

Studio Settings provides install/update, retry, empty-collection feedback and folder access.
New draft and Clone from an installed example select a project and use configured/anonymous publisher
semantics. Existing latest-release filtering remains shared with Packs. Contributor and operator
documentation explain how to add published content later; no real scenarios were added.

The existing Studio CI source gate now includes the fast integration module. Shared collection
integrity tests run in routine CI, generation is marked slow, and existing packaged verification
checks inventory parity and imports one release when the collection is populated.

## Validation

- Routine collection/lifecycle/Studio checks passed, including five collection tests,
  fourteen installation/API tests and thirty lifecycle tests. Separate lineage/removal/properties regression checks passed
  after retaining repairable-semantic-error behavior in source capture.
- State migration, recovery, edges and frozen contracts: 174 passed, one skipped.
- Full Studio source gate: 607 passed, sixteen platform skips and one outdated project-count
  expectation. Updated that test to preserve/check the new default project; the entire affected
  service module plus the example integration module then passed cleanly (118 tests).
- Frontend: all 387 tests passed, including the official-example Clone project selector; the
  App/Settings/lifecycle subset also passed (131 tests). TypeScript/production build and generated API checks passed. The existing
  bundle-size advisory remains.
- Slow installed-example generation passed after removing the entire authoring workspace.
- Wheel and source archive built; packaged example README bytes match the source inventory.
- Assembled an isolated Apple Silicon runtime. Relocated runtime verification passed checksum,
  isolated CLI/resources, empty example inventory, skills, pack/artifact operations, validation,
  checkpoint-enabled generation and native Mac generation/evaluation.
- A final relocated package probe used a test-only hardlinked example collection, installed it
  through the real first-run service and reopened it successfully. Workspace copies had one link
  and retained their examples project. The shipping collection remains empty.
- Ruff check/format and diff whitespace checks passed. Product version and generation behavior
  revision remain unchanged; no release or installer publication was performed.

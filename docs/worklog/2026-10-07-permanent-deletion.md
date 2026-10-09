# Permanent scenario/pack deletion and compact dependency warnings

## Accepted behavior

The user rejected recovery storage and its restore/browse/purge obligations. Delete now warns
that removal is permanent and cannot be undone, and tells users to export what they want to keep.
Scenario library/workspace menus delete scenarios. Packs are deleted separately through Packs;
Bundles and attached scenario views retain their existing bundle controls. No user data was
deleted while implementing or testing this change.

Scenario deletion defaults to the selected legacy YAML or exact managed draft/release closure.
An optional all-files choice also removes a dedicated legacy source folder, this scenario's
verified owned runs/evaluations, private captured inputs, scenario configuration and job files.
Other authored scenarios, releases, shared packs/configuration and outside imported bundles are
preserved. Retained runs remain discoverable through Bundles when optional cleanup is off.
Shared folders and output roots, foreign ownership, included sources, active work and symbolic
links prevent unsafe deletion. Full reviews fingerprint owned data and private reports using
file metadata, without reading potentially large generated datasets into memory.

Pack deletion warns about exact direct and indirect authored consumers, including scenarios
selecting an organization that depends on an industry pack. Accepting the reviewed warning
allows deletion; consumer references may subsequently need repair. Frozen self-contained
source closures and captured runs retain their inputs. Bundled engine packs are protected.

The affected list is initially collapsed with one small arrow. Expanding it shows plain category
headings and name/version rows: Industry packs, Organization packs, Scenarios. Each category
sorts alphabetically by name, then newest numeric version first. There are no nested disclosures
or main-library cards. The count and dependency warning remain visible while the names are hidden.

## File and interruption contracts

Shared `artifacts.removal` permanently removes reviewed source files without recovery copies.
The optional CLI `scenario delete` reviews and confirms the same operation; `--include-files`
selects a dedicated source folder and its contents. Ordinary shell removal remains supported.
No Studio database/helper/GUI is needed for CLI file operations. Canonical and installed native
chat skill references explain permanent removal and review/confirmation.

Small `.eforge/deletions/<uuid>.json` identity records retain only the selected source location,
artifact kind and exact retired release identity/digest. They contain no source, assets, notes,
logs or checkpoints. They reserve deleted release labels and reconcile interrupted SQLite index
cleanup. This is no restoration mechanism. Draft removal never allocates a release version.

Removal rechecks the accepted revision and shares the publication process lock. Studio serializes
new generation/evaluation admission and authoring against removal. Companions are removed before
the authored entrypoint so filesystem failures normally leave a selectable source for reviewed
retry. Errors report that some files may already be permanently gone; no rollback is claimed.
If source removal succeeds but index cleanup fails, refresh reconciles the deletion record.
The index record shape is unchanged, so no persisted Studio schema migration is required.

## Verification

Backend lifecycle, deletion, Studio service, canonical skill and installer regressions: 212 passed,
one slow test deselected. Cases include managed scenario/pack drafts and published releases,
retired labels, exact include/path/context consumers, indirect organization consumers, stale
source/run/report reviews, concurrent publication locking, large sparse data, partial filesystem
failure and retry, failed index cleanup, active work, shared run roots, foreign ownership, and
owned-run/private-input/evaluation/configuration cleanup. A published scenario still compiles
with identical digests after its installed industry pack is permanently removed.
Final error-handling and exact bundle-index cleanup checks passed again: 15 pack tests and
12 scenario tests, including preservation of outside imported bundles.

Frontend: all 242 tests in 21 files passed. Tests cover initially collapsed plain grouped lists,
numeric version ordering, omission of empty categories, dependency confirmation, both scenario
entry menus, scope changes, cancellation and refreshed reviews. API type checking, production
build, full Ruff check/format and diff whitespace checks passed. The existing frontend chunk-size
warning remains. Generation behavior revision 159 remains current with no output change.

Installed native skill conversions were refreshed. Apple Silicon standalone app was rebuilt at
unchanged application version 2.1.2; final runtime checksum, isolated CLI, bundled skills/references
and validation verification all passed. A live native dialog inspection was attempted but unavailable
because the Mac was locked; this follow-up's visual state is covered by interface tests, not an
additional live GUI acceptance session. The earlier Schema 3 native publication/run acceptance
is recorded separately. The user's running app/helper/state were not changed.

## Follow-up: built-in pack protection

Confirmed existing protection for both industry and organization packs: neither library nor
workspace menus offer Delete for bundled entries. The removal service accepts only exact
workspace pack locations; accepting dependency warnings cannot bypass that boundary.

Added backend regressions using a disposable copy of the bundled catalog. Direct review/API
deletion and direct service removal all reject bundled packs, preserve their index and every
catalog byte, and retain no deletion record. A separately copied workspace version remains
deletable without changing its bundled original, even with the same publisher/name/version.
Expanded both frontend pack-kind cases to check the bundled workspace menu as well as the
library menu. All 17 pack lifecycle tests and 99 App tests passed, along with full Ruff and
whitespace checks. This follow-up changed tests only; the verified delivered app already contains
the protection, so no additional app rebuild is needed. Actual installed built-in packs and
user data were untouched.

## Field-test clarification: Meridian's publisher label

The user showed a deletion dialog for
`evidenceforge:organization:meridian-healthcare-solutions@1.0.0`, believing it was bundled.
Read-only inspection of the live Studio index and authenticated helper confirmed that the exact
selected source is the workspace's
`.eforge/packs/evidenceforge/organization/meridian-healthcare-solutions/1.0.0/pack.yaml`.
Its current manifest says `publisher_display_name: "EvidenceForge Official"`, and the live
deletion review correctly accepts this workspace version. No deletion request was submitted.

Git commit `cbe9bd24` originally added Meridian under project-local `.eforge/packs/organization/`
for the iteration-test assessment; neither that package catalog nor the current bundled catalog
contains Meridian. The September quality-expansion worklog's phrase "packaged 1.0.0 release"
was imprecise. The publisher label is authored metadata, not installation provenance or
authenticated official authorship. Actual bundled sources remain protected, while workspace
packs with the same publisher label remain deletable. No policy, code, manifest, app or user
state changes were needed for this clarification.

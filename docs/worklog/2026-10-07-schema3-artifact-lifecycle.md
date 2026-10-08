# Schema 3 and portable artifact lifecycle

## Approved scope

Implement scenario and pack schema 3, independent drafts, immutable local publication,
exact ancestry, editable release notes, deterministic linked upgrades and portable archives.
All operations belong to shared file-based core services and the CLI. Studio and native chat
skills use those same services. No generated datasets or Git integration in this effort.

## Compatibility contracts

Identify the document family before schema detection. Scenario marker precedence is presence
of `schema_version`, then `scenario_version`, then `version`; invalid present markers fail.
Continue legacy scenarios 1/2, pack schema 2, resolved inputs, manifests and checkpoints.
Unadopted legacy workspaces remain unclassified. Never allocate release labels during editing.

## Execution context

Branch: `codex/schema3-artifact-lifecycle`, starting at clean `codex/studio-pack-lifecycle`.
The shared compiler and immutable resolved-run machinery are the foundation. Application version
remains unchanged. Studio persisted records require versioned migrations if their shape changes.

## Verification

Shared `schema` and `artifacts` packages now own identification, typed metadata, surgical YAML
upgrades, draft creation, notes, dependency promotion, frozen publication, portable receipts and
archives. CLI commands and Studio delegate to those services. Legacy file contracts remain
readable without adoption. Studio persisted record shapes are unchanged, so no database migration
is needed; computed lifecycle data is read from portable files. Existing backup/locking/scanner
paths are reused.

Focused backend acceptance and the CLI-only publication/import/generation/evaluation round trip
passed. The latter publishes both pack kinds, freezes an organization closure, removes original
sources/dependencies, generates and evaluates the portable scenario, and proves its logs match
the equivalent legacy definition byte for byte. Concurrent publication, interrupted publication,
notes/semantic identity, multiple editing sessions and tamper recovery have focused tests.

Routine full backend suite: 12,268 passed, 49 skipped, 2,176 deselected; five failures and one setup
error were native helper/socket/process-census restrictions in the sandbox. All seven tests in
the affected native groups passed on the authorized unsandboxed rerun. Later targeted checks
covered the final changes: 131 compatibility/lifecycle tests, 115 lifecycle/skill/installer tests,
123 lifecycle/Studio regression tests and five schema-adapter/repairable-upgrade tests passed.
The final CLI-only slow acceptance passed again (30 seconds), including byte-for-byte logs.
The explicit execution-seed override regression passed while preserving the release seal.

Frontend: 235 tests in 19 files passed. Generated API type checking and production build passed.
Native export route/atomic-save tests: three passed. Ruff check/format, diff whitespace and the
generation behavior manifest gate passed (revision 159, impact none). Existing frontend chunk-size
warning remains; the production build succeeds. The initial relevant legacy slow run had 59
passing tests and one missing historical input. The deleted archive was subsequently recovered
from Git into tracked test fixtures, preserving its exact bytes and the original assertions;
all 60 tests in that slow compatibility group now pass. See the historical fixture repair below
for provenance.

Native Apple Silicon app and isolated packaged CLI/resource/skill verification passed. The final
app is built under `build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/`.
Isolated GUI acceptance under `/private/tmp/eforge-schema3-native` confirmed anonymous pack drafts,
notes, publication, linked scenario upgrades, publication labels 1.0.0 then 1.0.1, portable native
save/import, generation and evaluation. Reopening 1.0.0 retained its completed run and saved
evaluation. Native acceptance found a missing save-route allowance; it was fixed and covered by
the Rust tests before repeat acceptance. No paid AI turn was submitted. The acceptance app and
its verified idle helper were stopped; the user's ordinary app/helper/state were untouched.

Canonical references and all installed skill conversions were refreshed. Roadmap/changelog record
the milestone without an application version bump. Changes remain on the feature branch and are
uncommitted for review. Git integration and generated-dataset storage remain future work.

## Historical fixture repair

User follow-up prompted a Git-history audit of
`test_iteration_pack_expansion_preserves_archived_assessment_lineage`. The original comparison
and archive path were added by `5e6e7c5e` on August 14, 2026; `b877a942` renamed/extended the
test on September 8. The archive was tracked, then removed by October 2 cleanup commit
`065bd9f2` without adjusting the test dependency. It was not a fixture omitted by the Schema 3
implementation, but leaving the failure unexplained was an incomplete verification step.

Recovered `scenario.yaml` and its referenced `email_corpus.yaml` byte-for-byte from
`db6a139a6a47611fb42cddd05db9ab13e03ad321` (the cleanup commit's parent) into
`tests/fixtures/scenarios/iteration-test-1_0/`. The adjacent README records source commit, Git
blob IDs and SHA-256 checksums. Changed only `_ITERATION_ARCHIVE` in the existing test to use
this permanent fixture location. The intentionally removed workspace scenario remains absent.
The original test passes with all assertions preserved. The complete related slow group passed:
60 tests in 21.64 seconds. Ruff check/format and diff whitespace checks also passed. No historical
fixture or validation gap remains from the missing archive.

## Field-test follow-up: scenario deletion

The initial recovery-storage design described below was superseded by the user's permanent
deletion decision. Current behavior and verification are recorded in the
[permanent deletion worklog](2026-10-07-permanent-deletion.md).

The user wanted an uncluttered scenario library for release tests and found only Clone/Hide.
History inspection found virtual-folder deletion in the retired Qt app, but no prior authored
scenario-file deletion. Studio had implemented conversation, bundle and pack-version deletion,
not scenario deletion.

Added Delete scenario to both the scenario library and workspace menus. The reviewed operation
belongs to shared `artifacts.removal` file services, with an optional `eforge scenario delete`
CLI interface. Ordinary shell file deletion remains supported; the extra command is a convenience,
not a prerequisite for working without Studio. Studio adds only index/conversation cleanup.

Retire the exact selected managed draft/release, or only the selected YAML for ordinary legacy
files, into `.eforge/deleted-scenarios/<operation>/`. Preserve other scenarios/versions, supporting
legacy files, Codex histories and captured generation/evaluation records. Retain a version-1
receipt with original paths; recovery is currently manual, with no GUI restore or automatic purge.
Removed published labels stay reserved. Includes, active authoring, changed reviews, foreign paths,
fragments, generated inputs and symlinks are guarded. Publication/import and removal coordinate
through the shared process lock. Failed durable rename or SQLite cleanup restores the source;
completed retirements reconcile interrupted index cleanup on refresh. No persisted record shape
changed, so no Studio database migration is needed.

Focused new tests cover both managed states, legacy companions/runs, include consumers, stale
reviews, publication locking, filesystem/index fault rollback, interrupted reconciliation,
CLI-only review/removal and preservation of captured run records. The final removal/skill suite
passed 79 tests; related existing service/pack/lifecycle regressions passed 125 tests. All 239
frontend tests passed, including both entry menus, Cancel, consumer refusal and stale-review
refresh. API types, production build, Ruff check/format and diff whitespace checks passed.
Canonical and installed skill references were refreshed. The native app was rebuilt for delivery;
no user scenario files or the user's running helper/app state were changed.

Final lifecycle regressions also passed (35 tests). The rebuilt Apple Silicon package verification
passed runtime checksum, isolated CLI, bundled skills/references and validation at unchanged app
version 2.1.2. Generation behavior manifest remains current at revision 159 with no output change.
New deletion dialogs were verified by frontend/API acceptance; no additional live native GUI
session or paid authoring turn was started for this follow-up.

## Field-test follow-up: publication after asset edits

The user added a stale account to a Meridian organization-pack draft, validated successfully,
then received `source changed after review; inspect it again` on publication. Studio's lifecycle
panel refreshed only when the manifest/entrypoint hash changed. Pack asset edits can change
separate model/catalog files while leaving that hash unchanged, so final publication submitted
the digest from before the edit. Pack validation had a separate review and did not update it.

The publish dialog now explicitly inspects the current full draft before enabling confirmation
and suggesting its unused version. It retains that publication review separately from background
overview refreshes. Later edits still fail the existing backend guard. An explicit Refresh review
action clears stale confirmation and warning acceptance, retains the selected release label and
requires another Publish click; no automatic retry or publication occurs. Failed inspection
keeps publication disabled. Refresh preserves unsaved note previews without saving them.
Core file/CLI contracts and optimistic digest checks remain unchanged.

Reproduced the stale digest in three frontend cases before the fix (scenario and both pack kinds).
A backend acceptance case adds a stale account through Assets, verifies the manifest bytes stay
unchanged, validates, rejects the old digest, reviews again and publishes the exact changed pack.
The authored draft stays editable and the released organization retains that stale account.
All six focused lifecycle API tests passed. Added frontend checks for a pending/failed review,
unsaved notes, edits after dialog opening, background refresh isolation, chosen-version retention
and explicit retry; all 248 interface tests passed. API types and production build passed.
Broader artifact, lifecycle, asset and pack regressions passed: 86 tests, one slow case deselected.
Full Ruff check/format, whitespace and unchanged generation behavior revision 159 passed.
Rebuilt the Apple Silicon standalone app at unchanged version 2.1.2. Final runtime checksum,
isolated CLI, bundled skills/references and validation verification passed. No additional live
native GUI acceptance or paid authoring turn was performed for this fix.
The user's pack, draft, live app and helper state were not changed by this investigation.

## Field-test follow-up: pack version grouping layout

The bundled Northstar Health 1.1.0 row was pushed sideways and its description truncated while
1.0.0 rendered normally. The identity heading for multi-version packs had been inserted as a
flex child inside the first version's horizontal row. Moved that heading into a separate block
above the version rows using a keyed fragment; exact row controls, sorting and drag targets
remain unchanged. The shared heading style now uses the existing muted-text token and wraps
long identities.

All 248 interface tests in 21 files passed, along with API type checks, production build, full
Ruff check/format and whitespace checks. An isolated browser preview rendered the actual three
bundled organization manifests with the real PackLibrary component and styles. Northstar 1.1.0,
1.0.0 and MetroLink names all aligned at x=112; the heading appeared above Northstar's versions.
The Northstar bundled menu retained Export/Clone/Hide with no Delete. No console errors or
warnings occurred. The disposable preview files, browser tab and server were removed afterward.
No user workspace, running app or helper state was changed.
Rebuilt the standalone Apple Silicon app at unchanged version 2.1.2. Packaged runtime checksum,
isolated CLI, bundled skills/references and validation verification passed. This small interface
fix was visually checked in the browser preview, not an additional live native app session.

## Field-test follow-up: publisher defaults and lineage grouping

Read-only inspection of the user's Studio database found the legacy `Test_scenario_1`, an
anonymous Schema 3 draft titled Maple Office - PowerShell Discovery, and its published 1.0.0
release under `davidjbianco`. The draft copied a missing publisher from the original, and only
publication applied configured identity. Studio grouped solely by publisher/name, splitting one
recorded lineage across anonymous and named headings. The original's displayed 2.0 is its schema,
not an earlier content release. macOS privacy blocked direct Documents-file inspection; the
database's indexed YAML and user publisher setting established the metadata sequence. A read-only
replay confirmed the legacy cached source digest matches both parent records and all three entries
resolve to one `davidjbianco/Test_scenario_1` library family with the new logic.

Shared draft creation now prefers an explicit publisher, then the source's publisher, then
configured project-over-user identity. New scaffolds use the configured identity when available;
anonymous drafts still work without configuration. Existing drafts are not silently assigned on
resume, settings changes or editing. Source bytes and historical parent ownership remain intact.
Pack execution still uses isolated draft-ID namespaces regardless of the authored publisher.

Added shared file-based lineage inspection/grouping and a supplementary snapshot-only Studio
projection used by scenario and both pack libraries. Exact legacy/release references and common
parents reconnect already-existing anonymous drafts, even with different display names or missing
ancestors. Mutable drafts retain groups through their stable IDs; publication stores their exact
finalized snapshot reference alongside existing ancestry and rechecks its complete digest before
installation. Named publisher forks, renamed identities, unrelated anonymous equal names and
ambiguous anonymous ancestors stay separate. Repairable or damaged documents remain discoverable.
No SQL/JSON persisted record shape changed; groups are recomputed on scan/restart, so no new Studio
database migration or user-data rewrite is needed. Canonical/native-client lifecycle references and
the scenario manual describe the same core behavior.

Verification:

- All 282 frontend tests pass across 26 files. The scenario original/draft/release family renders
  one heading despite different titles; filtered lists preserve full-workspace grouping; publisher
  forks remain separate; both pack kinds share the same group contract and exact row controls.
- 180 existing backend regressions and 90 final lifecycle/Studio/notes/title contracts pass.
  The final 87 lineage/skill/installer checks include project/user precedence, anonymous defaults,
  inherited/explicit publisher preservation, isolated draft pack namespaces, all three artifact
  kinds, exact publication snapshot parents, continued editing, pre-existing release ancestry,
  missing/changed/ambiguous ancestors, publisher/name forks and repairable semantic failures.
- Production build, generated API freshness, full Ruff check/format, whitespace and generation
  behavior revision 160 with the unchanged surface digest pass. No generation behavior changed
  and no paid AI calls were made. Canonical and installed native-client references were refreshed.
- Rebuilt the Apple Silicon standalone app at unchanged version 2.1.2. Runtime checksum, isolated
  packaged CLI, bundled skills/references, naming and configured publisher checks for scenario and
  both pack drafts/upgrades, legacy validation and checkpoint-enabled generation pass. This follow-up
  used interface/API tests and packaged CLI acceptance; no additional live native GUI session was
  started. The user's live app/helper, database and authored workspace were not changed.

Logs: `/private/tmp/eforge-publisher-frontend.log`,
`/private/tmp/eforge-publisher-regressions.log`,
`/private/tmp/eforge-publisher-lifecycle-final.log`,
`/private/tmp/eforge-publisher-lineage-skills-final.log`,
`/private/tmp/eforge-publisher-build.log`, `/private/tmp/eforge-publisher-types.log`,
`/private/tmp/eforge-publisher-macos-package.log`, `/private/tmp/eforge-publisher-macos-verify.log`.

## Dev integration

The user authorized pushing all cumulative work, opening a PR into `dev`, monitoring CI and
merging when green. Follow-up fixes during integration are limited to tests, documentation and
CI; changes to EvidenceForge or Studio behavior require a separate decision. Application version
remains 2.1.2. The branch includes the four earlier pack-release, bundled-identity, runtime-cleanup
and environment-link commits in addition to this lifecycle, naming and Properties effort.

Fresh integration checks passed full Ruff lint/format, generated API freshness, generation
behavior declarations, frontend production build and all 287 frontend tests. The default backend
suite is running with native socket/process access; GitHub's Linux/Windows engine gates and
macOS Studio/state-recovery gates will also run on the PR. Prior isolated native UI and packaged
CLI acceptance is recorded above and in the Properties worklog. No user data is part of the PR.

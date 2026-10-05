# Studio asset browsing and editing

## Accepted scope

The user accepted the October 5 standalone field polish and approved implementing the
Environment asset workflow after reviewing interactive mocks. Use expandable rows to match
the rest of Studio; no side inspector. Reuse existing First/Previous/numbered/Next/Last
pagination, with bounded pages, full-inventory search/filtering, category counts and recalled
view state. Origin badges are color-coded icons with hover/focus descriptions, with the
specific pack/file shown separately. Distinguish scenario, pack, pack with scenario overrides,
and configuration/default origins, including field-level origins inside expanded entries.

The scenario workspace may add/edit scenario-owned assets or customize inherited assets
through scenario-only overrides. It must never edit pack files. Pack editing belongs on the
Packs page and creates a new exact version automatically; preserve prior versions and existing
scenario selections. Existing reviewed `.efpack` import/export stays available.

## Implementation and verification

Inspect the shared compiler/provider merge contracts before extending Studio. Preserve
traditional CLI/skill workflows, immutable queued-run inputs, include ownership, configuration
scope selection and each family's existing merge rules. Search/pagination must return bounded
summaries; expanded details are loaded separately. Verify mixed origins and large inventories,
stale-input rejection, scenario-only writes, pack version creation and failure rollback.

## Implemented

- Shared the existing First/Previous/numbered/Next/Last pagination with declarations.
  Environment assets use 25/50/100 rows, default 50, with full-inventory search,
  origin/source filters, category totals, matching counts and recalled view state.
  Only one row expands; values/schema/field origins are requested on expansion.
- Added users, groups, systems, network identities, stale accounts, effective DNS,
  applications and per-platform processes to scenario Environment. Pack workspaces
  expose organization entities and their own six catalog families, with import/export
  actions using the existing reviewed `.efpack` flow.
- Blue document, purple package, amber package/pencil and gray configuration icons
  explain their origin on hover/keyboard focus. Source labels stay compact; expanded
  field sources retain exact file/pack details. Projection uses canonical compiler
  identity merges and the existing family-specific runtime overlay callbacks.
- Schema-derived inline editors review changes before saving. Included entities write
  their owning YAML. Inherited entities get sparse scenario-only overrides; DNS and
  applications use private, optional file-based configuration contexts. Preserve
  selected shared layers and their merge semantics. Validate staged sources/config,
  reject stale revisions, and roll back a failed context/file transaction.
- Pack saves suggest the next unused patch version and require a version greater than
  the original. The repository copies its captured semantic payload into staging,
  applies the revision and validates the closure before publication. Original packs
  and scenario selections stay unchanged; prior versions remain listed. The new
  version can be opened from Packs for further editing.
- Recorded generation behavior revision 157 with impact `none`: the guarded
  composition surface changed for pack authoring, while existing compilation and
  rendering remain unchanged. No product version bump on this feature branch.

## Verification and delivery

- 214 routine Studio, pack CLI and behavior-manifest tests passed. The 31 focused
  slow pack-lifecycle contracts passed with `--no-cov`. Eleven new backend tests cover
  1,205 rows, keyed mixed origins, included-file ownership, private configuration,
  stale revisions, auth/query bounds, version immutability, invalid references and
  rollback. The queued immutable-input generation contract also passed.
- 192 frontend tests passed, including four new asset tests for bounded pages,
  lazy expansion, accessible graphical badges, reviewed saves, versions and view
  recall. Stale expectations from the accepted October 5 polish were updated to
  visible validation findings, final imported-scenario checks and accepted-score
  history cleanup. Production TypeScript/frontend build and generated API type
  checks passed. Full Ruff check/format and Git whitespace checks passed.
- A real browser/API check with an isolated sample workspace saved a pack-derived
  user override and reopened it with scenario/pack field icons intact. The test
  tab, frontend and API servers were closed; temporary preview files were removed.
  No user Studio app/helper was stopped or launched. Screenshot:
  `/Users/dabianco/.codex/visualizations/2026/10/05/01a10c51-8b1e-77f0-a719-cf9aaddcedfb/studio-assets-implemented.jpg`.
- Native Apple Silicon macOS app and standard test DMG rebuilt. The previous image
  is preserved as `dist/macos/EvidenceForge-Studio-2.1.2-aarch64-before-assets.dmg`.
  Packaged CLI, bundled skills/references and validation passed with an isolated
  runtime and minimal PATH. The packaged asset modules match current source; DMG
  integrity and SHA256 verification passed.
  New image SHA256:
  `c4b7618096e6b67b36e6271f5ec83a5f9c506c925565a94e26f81d4c5212840d`.

## Current limits

Nested runtime configuration lists retain the existing append contract. Removing
or reordering inherited nested values requires a pack revision; Studio rejects a
save that cannot reproduce the reviewed effective value exactly. Complex fields
now use nested schema-derived forms and readable structured details.
Full effective origins for other configuration families remain broader workflow
work; these asset categories are covered by this implementation.

## Field-test repair: stale source helper

The October 5 field test showed `Error: Not Found` for scenarios with and without
packs. The live helper's OpenAPI document contained no asset routes, and every
asset request returned FastAPI's generic 404. This was an older source helper:
all source launches shared the literal runtime identity `source`, so the new
frontend silently reattached to old in-memory service code.

Source launches now fingerprint the backend Python files, checkout/interpreter
locations and dependency declarations. Each process retains its initial identity;
a new launch detects changes and uses the existing authenticated, idle-only
handoff. Readiness also requires the selected runtime identity, preventing a stale
descriptor from being returned during startup. Packaged runtime identities keep
their existing archive-digest contract.

Nineteen runtime/asset tests passed, including new source-change, unchanged-build
reuse, legacy-helper handoff and stale-startup-descriptor regressions. The actual
idle helper was replaced through the guarded handoff; all three indexed scenarios
returned HTTP 200 with populated asset categories, including the pack-based
`Test-1` (17 users, 24 systems) and standalone `Test_scenario_1` (6 users, 5 systems).
No scenario or pack content was modified. No new DMG was built, per user preference.
The additional 85 background/service tests passed; full Ruff check/format and Git
whitespace checks passed.

## Asset list and authoring polish

The October 5 user review requested first-column graphical origins, a more distinct
expanded panel, pickers for constrained choices, readable collection values, one
account list, structured application/process definitions and guidance when adding.

- Moved graphical origin badges into a narrow first column without a visible title.
  Expanded rows have a separate background, border and accent; the disclosure arrow
  follows expansion. Collection values render as tags or labeled nested values.
- Combined ordinary and stale accounts under Users, with Active/Disabled/Stale
  badges and an account-status filter. Stale accounts represent retired credentials
  that produce failed logons; disabled ordinary users produce no user activity.
  Detail/save dispatch preserves each account's existing model and YAML family.
- Added revision-checked, searchable reference vocabularies with bounded 50-choice
  pages. Systems, groups, members, personas and catalog references use pickers;
  enums use selectors. Permission/service labels offer existing suggestions and
  custom labels because their authoring models allow open vocabulary. Structured
  service definitions keep their own typed forms rather than becoming label pickers.
- Application/process platform dictionaries now have typed nested fields,
  Windows/Linux entry choices and deployment-type selectors. Advanced deployment,
  metadata, child-process and module sections expand on demand. Typed dictionary
  schemas retain pattern-constrained keys and structured entry values.
- Add Asset first explains the selected type and ownership, then initializes model
  defaults and marks required fields. Missing fields, enum/format/range constraints
  and invalid version spelling block review; saves still run canonical validation
  and the existing revision/rollback contracts. Before/after review is structured.

Verification: 119 related Studio/backend tests passed, then all 14 asset contracts
passed after final schema polish. All 195 frontend tests passed; the seven focused
asset browser contracts also passed after the final form changes. Production/native
builds and generated API type checks passed; full Ruff check/format and Git whitespace
checks passed. Real browser/API checks saved a scenario-only user change, reopened it,
searched system choices, inspected platform deployment fields and displayed stale
accounts alongside ordinary users in a disposable workspace. Preview servers/tab and
temporary frontend harnesses were removed. Screenshot:
`/Users/dabianco/.codex/visualizations/2026/10/05/01a10c51-8b1e-77f0-a719-cf9aaddcedfb/studio-assets-guided.png`.

Rebuilt the source-run macOS `.app` only; no DMG per the user's preference. The live
helper accepted its authenticated idle handoff and all three indexed scenarios
returned HTTP 200 for both account lists and system choices: Iteration-Test 9 accounts
/21 systems, Test-1 20 accounts/24 systems, Test_scenario_1 6 accounts/5 systems.
No real scenario or pack content was edited during verification.

## Restore inheritance and account semantics

The follow-up review asked about a third enabled state, multiple personas and
removing pack customizations. The engine's User model has one optional persona;
its resolved profile can contain many activities. StaleAccount is a distinct
failed-authentication noise model, and schema validation forbids sharing its
username with any ordinary User, including a disabled user. Converting an
ordinary account to stale therefore requires a retirement workflow that handles
references and inherited pack membership; a third boolean choice would be false
to the current engine contract. No generation/schema contract changed here.

- Renamed the ordinary user's Enabled control to Account status, with Active and
  Disabled choices and inline guidance about stale credentials and one persona.
- Detail responses retain the canonical inherited value and authored override
  paths. Organization defaults use the repository's qualified environment model;
  runtime defaults use the selected configuration layers without the scenario's
  private asset overlay. Explicit overrides remain detectable even if equal to
  inherited values. New scenario-owned assets have no inherited restore action.
- Added whole-asset Restore inherited values and per-field Restore inherited
  actions, including nested dictionaries and entire lists. Restores enter the
  existing review/save flow, remove authored overrides, preserve unrelated edits,
  and revalidate staged canonical inputs before publishing. Included owners,
  revision checks and transaction rollback stay in place; packs remain immutable.
  Restoring the last field removes the identity-only override entry and returns
  the asset to its inherited origin. Runtime empty patch containers are removed.
- Details and form fields show amber Customized markers; nested details identify
  the specific customized leaves. Pending restores show Restoring markers.
  Clear field now explicitly clears a value; Reset field default resets the
  model's declared default. Neither is labeled as restoring pack values. Editing
  a restored preview retains restoration of the other untouched fields.

Verification: 105 related backend tests passed and all 18 asset contracts passed
after final nested/path-reference checks. All 197 frontend tests passed, including
9 asset browser contracts for markers, explicit clearing, reviewed restoration and
editing after a whole-asset restore. Build/type-generation checks, full Ruff
check/format and whitespace checks passed. A real disposable browser/API sample
restored one user field while preserving other overrides, then restored the whole
asset and reopened it with the pack-only badge. Preview tab/servers and temporary
frontend harnesses were removed. Review screenshot:
`/Users/dabianco/.codex/visualizations/2026/10/05/01a10c51-8b1e-77f0-a719-cf9aaddcedfb/studio-assets-restore.png`.

Rebuilt only the source-run `.app`, with no DMG. The actual idle helper accepted
authenticated replacement, and all three real scenarios returned HTTP 200 with
the new inheritance/override metadata. Real scenario and pack files were not edited.


## Account conversion workflow

The user approved Mark as stale and Restore as user actions with a review step,
and asked whether engine validation would cover the new cases.

- Scenario Users rows now offer the matching conversion action. The guided form
  keeps the username fixed, collects retirement date/reason, or restores the saved
  user profile and lets the author choose Active or Disabled. A read-only preflight
  runs staged canonical validation before enabling Save. Review shows the status
  transition, affected directory links, and blocking findings. Saving revalidates
  and uses the existing source revision, include ownership and rollback contracts.
- Added optional portable authored `account_transitions` controls for Scenario 1.0
  and 2.0. The compiler validates unique case-insensitive identities, target kinds,
  matching target records and typed archived User details. It selects one effective
  account family and projects group memberships/system assignments inactive while
  stale. Raw source records/links remain available for restoration. Other references
  remain subject to canonical validation; storyline actors, storage, identity and
  email references are not silently rewritten. At least one regular user is required.
- Pack accounts convert through scenario controls only. Restoring retains sparse
  overrides and explicit existing pins rather than pinning all inherited fields.
  Mixed graphical origins retain pack lineage, and inherited field origins remain
  accurate. Group/system inherited defaults reflect current retirement controls so
  restoring their unrelated customizations still works. Pack files are unchanged.
- Resolved artifacts contain effective accounts/links rather than authoring history;
  existing generators need no new account logic. Declared behavior revision 158,
  impact none: opt-in authored controls, unchanged existing input/rendering behavior.
  The public scenario reference documents the contract; no feature-branch version bump.

Verification: 143 related routine backend contracts passed (142 in the combined
run and the corrected empty-category assertion rerun). This includes 33 asset
contracts for active/disabled retirement, standalone and inherited account
restoration, saved profiles and subsequent edits, include ownership, reversible
links, sparse pack origins, stale revision rejection, multi-file rollback,
service-account collisions, malformed controls, last-user guard and authoritative
resolved account equivalence. All 200 frontend tests passed; the 12 asset tests
passed again after final review polish. Type generation/checks, production/native
builds, full Ruff check/format and whitespace checks passed. The focused composition
slow suite passed 28 tests; its historical iteration archive lineage test could
not run because `scenarios/iteration-test-1_0/scenario.yaml` was already absent.
That archive was not restored or edited.

A real disposable browser/API check retired a pack-derived customized user,
restored it as Disabled with its saved name, groups, system and browsing settings,
and verified pack email/system origins plus the graphical mixed badge. Review
screenshot: `/Users/dabianco/.codex/visualizations/2026/10/05/01a10c51-8b1e-77f0-a719-cf9aaddcedfb/studio-account-conversion.png`.
Temporary preview tab/servers and frontend harnesses were removed. Rebuilt the
source-run `.app` only, with no DMG. The real helper accepted authenticated idle
replacement; read-only conversion drafts returned HTTP 200 for all three real
indexed scenarios. No real account or pack content was saved during verification.

# Optional artifact display names and shared naming contracts

Date: 2026-10-08. Branch: `codex/schema3-artifact-lifecycle`.
Related effort: [Schema 3 lifecycle](2026-10-07-schema3-artifact-lifecycle.md).

## Approved behavior

Add optional Schema 3 root `display_name` for authored scenarios and both pack kinds. Friendly
titles allow spaces, Unicode and punctuation; present values must be nonblank single-line text.
Omission falls back to the full logical `name`. Identifiers remain case-sensitive and retain their
existing syntax: scenarios accept ASCII letters, digits, underscores and hyphens; pack identifiers
remain lowercase letters/digits/hyphens with an initial letter or digit.

Remove Studio's additional scenario first-character rule and artifact-name length cap. Keep the
full identifier for exact references, deduplication, ordering and search. Titles never rename
files, identifiers or references. Legacy inputs remain usable without automatic adoption or
upgrade. Adding a title to legacy schemas requires the existing explicit linked Schema 3 upgrade.

## Implementation

`evidenceforge.naming` owns identifier rules, title validation and bounded case-distinct portable
storage components. Engine models and Studio API boundaries share its patterns; frontend naming
rules are generated from this contract and checked with the API type-generation gate. Logical
identifiers have no presentation length cap. Long storage components use a digest of the full
identifier; bounded export filename suggestions retain the complete identity inside the archive.

Scenario and pack Schema 3 envelope descriptions expose the optional title. Scenario compilation
keeps it in authored provenance and removes it from the generation model. Pack Schema 2 rejects
new metadata and preserves its historical serialized shape/digests. Titles are protected from
namespace rewriting and included in sealed authored source integrity, while excluded from
generation-relevant semantic identity. Compatibility revision 160 records this admission/metadata
change with impact `none`, preserving checkpoint history from revision 159 and earlier. Rendered
output is unchanged for equivalent definitions.

Shared lifecycle services accept optional titles when creating/forking drafts and expose atomic
draft title changes, including clear, with stale-review guards. Metadata edits preserve includes,
comments and permissions. Published releases require a new draft before editing. Archive
inspection reads title metadata from the sealed source graph without changing receipt formats.
CLI `scenario` and `pack` groups provide `new-draft`/`draft --display-name` and
`display-name --value`/`--clear`; they require no Studio state or publisher for draft work.

Studio creation forms collect optional titles. Its lifecycle panel edits or clears them on drafts.
Library rows, workspace headings, command search and deletion review titles use friendly titles
with exact identifier fallback. Search includes both title and full identifier. Pack versions stay
grouped by exact publisher/name before title sorting, even when releases have different titles.
Long visible names use existing wrapping/ellipsis and full tooltips without truncating stored IDs.

Studio catalog items add `display_name`; pre-authoring conversations add `draft_display_name`.
Database version 2 adds explicit null defaults through a new immutable migration and frozen v2
record readers. Historical v1 reader shapes/checksums remain untouched. Existing installations
use the reviewed state-upgrade/backup contract, including installations whose earlier v1 upgrade
already completed. Existing IDs, paths, project relationships, histories, runs and timestamps are
preserved. The user's installed database was not upgraded during this work.

## Authoring support

Canonical scenario, pack-management, industry-pack and organization-pack skills offer a title
during creation and edits when one is missing. It is optional: refusal never blocks authoring or
causes repeated prompts. Focused lifecycle/scenario/pack references explain ID syntax, exact case,
title metadata, legacy upgrades, immutable releases and CLI commands. Scenario skill size remains
within its compact contract: 164 lines and 1,319 words.

Refreshed project and global installed conversions with the supported installer for all native
clients. The existing custom assessment skill was left untouched. Standalone package acceptance
also installs bundled skills into a temporary workspace and checks the title guidance and refs.

## Verification and delivery

- Focused backend regression suite: 408 passed, 1 skipped, 146 deselected. Covers naming,
  lifecycle, import/export, semantic identity, Studio APIs, migrations, frozen state contracts,
  canonical skills and installed conversions. The skip is an existing platform-specific gate.
- Native process crash/recovery tier: 99 passed, 1 deselected, without coverage instrumentation.
- Naming/generation compatibility contracts: 44 passed after refreshing the behavior manifest.
  CLI-only slow publication/export/import/generation/evaluation acceptance also passed with titles
  on the scenario and both pack kinds; resulting logs match the equivalent legacy definition
  byte for byte after original authoring inputs disappear.
- Frontend suite: 252 tests passed across 22 files; generated API/naming contracts and production
  build passed. Existing Vite bundle-size advisory remains unchanged.
- Isolated browser preview used production forms, lifecycle panel and pack library with mock
  in-memory operations. A 301-character scenario ID beginning with `_` and a Unicode title were
  accepted intact. Long pack titles ellipsized without horizontal overflow at a 1,280px viewport;
  differently titled versions remained grouped and aligned. Preview source files/server and the
  active preview tab were removed.
- Rebuilt Apple Silicon standalone Studio at unchanged version 2.1.2. Relocated-runtime checksum,
  isolated CLI, bundled skills/references, legacy validation, artifact naming and checkpoint-enabled
  generation acceptance passed.
  The naming gate creates drafts with 300+ character IDs for a scenario and both pack kinds,
  inspects their full identity/title, edits the title and clears it through the bundled CLI.
  The generation gate upgrades the minimal legacy fixture into a titled draft, generates with
  hourly checkpoints, verifies nonempty output and confirms completed-run checkpoint cleanup.
- Full Ruff check/format and whitespace checks pass. No app version bump, commit or PR created.

The final generation compatibility gate caught the stale source-surface digest after the naming
refactor. Refreshed it and recorded revision 160 with no output impact before rebuilding the
delivered package; routine metadata tests alone had not exercised checkpoint fingerprint creation.

Logs: `/private/tmp/eforge-naming-backend.log`, `/private/tmp/eforge-naming-frontend.log`,
`/private/tmp/eforge-naming-native-crashes.log`, `/private/tmp/eforge-naming-macos-package.log`,
`/private/tmp/eforge-naming-macos-verify.log`, `/private/tmp/eforge-naming-generation-contracts.log`,
`/private/tmp/eforge-naming-cli-e2e.log`.

App: `build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/EvidenceForge Studio.app`.
The running user app/helper, user scenarios/packs and workspace data were not changed. UI
acceptance here used the isolated browser preview; no additional live native authoring session or
paid AI call was started. Quit/reopen the rebuilt app to use the new controls.

## Optional AI title suggestions

Added the requested small sparkle action beside empty display-name fields in scenario/pack
creation forms and Schema 3 draft workspaces. It proposes a concise title from the available
description, environment overview, organization-pack reference and storyline activities. Scenario
guidance prefers `Organization name - Scenario Type` when those details are known; sparse context
uses a humanized identifier. Pack guidance prefers the natural organization or industry name.

The response fills an editable, unsaved field. Save/Create remains the user's separate choice.
Manual typing remains available while a request is pending and takes precedence, even if the user
types and clears the field again. Changed source/context, failed requests and unmounted forms
discard delayed results. No automatic suggestions run during import. Existing published releases
require New draft, and legacy documents require a linked Schema 3 draft before adding metadata.

The authenticated Studio preview route captures and rechecks the draft digest and rejects existing
titles or non-drafts before calling AI. It never writes YAML, publishes, changes identifiers or
saves a conversation. Studio's configured Codex app-server runs a bounded ephemeral request from
a private temporary directory with read-only permissions. Hooks, apps, plugins, shell execution,
browser/computer tools and configured MCP servers are disabled for this request. The helper checks
the returned permission policy before starting a model turn, rejects approval/tool requests,
validates the structured single-line title, and closes its owned client on completion, failure,
timeout or cancellation. Unsupported clients leave manual naming available.

This optional service lives entirely under Studio. Core CLI/file operations and generation remain
deterministic. Updated canonical and installed native authoring skills/references explain how the
host chat client can propose the same editable suggestion and apply the user's choice through
the existing file/CLI title operation. No built-in CLI LLM command or GUI dependency was added.

Verification:

- Twenty new backend contracts pass, covering the notification-before-response race, tool denial,
  invalid/partial output, disconnects, timeout, cancellation, unsupported client policies, context
  selection, authentication, source changes and non-mutating previews for all three artifact kinds.
- Existing Studio lifecycle/service and installer contracts passed. The expanded scenario skill
  initially exceeded its compactness limit; shortened its dispatcher guidance and reran all twenty
  scenario-skill contracts successfully (165 lines, 1,323 words).
- Full frontend suite passes: 260 tests across 23 files, including suggestion-before-save/create,
  manual-edit precedence, changed context, AI unavailability and existing-title behavior.
- API/naming type freshness, production build, full Ruff check/format, whitespace and generation
  compatibility gates pass. Generation behavior remains revision 160 with the same surface digest.
- Read-only protocol smoke check with installed Codex 0.160.0 successfully created an ephemeral
  thread with `readOnly`, network access disabled and approvals set to `never`; all three configured
  MCP servers were disabled. No model turn or paid AI call was made for this check. Automated AI
  tests use simulated clients/responses rather than a paid account.
- Refreshed project and global native skill conversions. Rebuilt the standalone Apple Silicon
  app at unchanged version 2.1.2. Relocated runtime checksum, isolated CLI, bundled skills/references,
  artifact naming, legacy validation and checkpoint-enabled generation acceptance all passed.
  The user's running app/helper and workspace files were untouched.

Logs: `/private/tmp/eforge-title-backend.log`, `/private/tmp/eforge-title-additional.log`,
`/private/tmp/eforge-title-final-contracts.log`, `/private/tmp/eforge-title-frontend.log`,
`/private/tmp/eforge-title-frontend-build.log`, `/private/tmp/eforge-title-macos-package.log`,
`/private/tmp/eforge-title-macos-verify.log`.

## Consistent AI actions and release-note previews

Applied the requested sparkle convention to repair, configuration editing, pack selection,
scenario/pack creation and authoring-chat entry points. Named chat actions retain their existing
labels. Display names and release notes use small, accessible icon buttons. Ordinary manual
editing and deterministic validation/generation/evaluation keep their existing controls.

Replaced the release-notes chat launcher with an optional direct suggestion. A fresh inspection
captures all draft assets before the request. The proposed notes appear separately from the
manual editor, with an editable preview and comparison limitations. **Use suggestion** fills the
unsaved editor; **Save notes** remains separate. Dismissal, manual edits, source changes or leaving
the form discard the preview. Suggestions never save, publish or start an authoring conversation.

Moved the existing isolated one-shot AI transport into a shared Studio assistance module used
by both preview actions. It remains ephemeral, read-only, tool-free and bounded, with structured
output validation, timeout/cancellation cleanup and a 128 KiB context limit. Core file/CLI services
and deterministic generation have no new AI dependency.

Added a deterministic shared source-comparison helper outside Studio. It resolves recorded
release or independent draft parents, or accepts catalog candidates for legacy ancestors, and
checks exact identity and complete digest before using them. Missing or modified ancestors
remain unavailable. Includes and assets are compared; text diffs, file lists and parent counts
are bounded, and omitted large/binary contents are reported as partial. Multiple parents remain
separate comparisons. Imported archives must provide an authored source entrypoint rather than
having their containing directory treated as source material.

Canonical lifecycle references document the sparkle convention, preview review and separate
accept/save operations. Refreshed project and global native skill conversions; host chat clients
continue proposing notes through their own AI and applying reviewed text through the existing CLI.

Verification:

- Forty-four focused preview/lifecycle contracts passed, including 18 release-note contracts;
  180 existing lifecycle, Studio service, canonical-skill and installer contracts passed.
  Exact published/draft/legacy parents, forks, missing/modified ancestors, binary/truncated
  comparisons, authentication, draft-only guards, asset-only concurrent changes and unchanged
  source files are covered. Optional AI tests use simulated clients; no paid calls were made.
- Full frontend suite: 267 tests passed across 24 files. Preview editing, dismissal, use-before-save,
  fresh asset inspection, manual-edit precedence, source changes, unmounts and unavailable AI pass.
- Generated types, production build, full Ruff check/format, whitespace and generation compatibility
  gates pass. Existing Vite bundle-size advisory remains unchanged. Generation behavior stays at
  revision 160 with the same surface digest.
- Rebuilt the Apple Silicon standalone app at unchanged version 2.1.2. Relocated runtime checksum,
  isolated CLI, bundled skills/references, artifact naming, legacy validation and checkpoint-enabled
  generation acceptance passed. No live native authoring session or paid model turn was
  started, and the user's running app/helper and workspace files were untouched.

Logs: `/private/tmp/eforge-sparkle-backend.log`, `/private/tmp/eforge-sparkle-notes-final.log`,
`/private/tmp/eforge-sparkle-regression.log`, `/private/tmp/eforge-sparkle-frontend.log`,
`/private/tmp/eforge-sparkle-macos-package.log`, `/private/tmp/eforge-sparkle-macos-verify.log`.

## Workspace title editor

The workspace heading displayed the friendly title but still opened the original identifier
rename form. Replaced that control with one shared display-name editor for scenarios and both
pack kinds, including scenario authoring drafts that do not yet have a file. Clicking the title
prefills `display_name`, shows an optional small sparkle, and accepts spaces/punctuation. The
identifier is read-only in this editor. Clearing a title restores the identifier fallback.

Title suggestions can now be explicitly requested again for an existing title and previewed on
published or legacy sources. These requests remain read-only, isolated and digest-checked; they
never create a draft or accept a replacement. Opening the editor captures a fresh complete source
digest, and the sparkle refreshes that capture before requesting AI so asset-only changes are
included. Delayed suggestions still yield to manual typing and discard results after cancellation.

Saving a Schema 3 draft updates its title in place. For a published or legacy source, the header
explicitly explains that saving creates a linked Schema 3 draft. The authenticated lifecycle
facade delegates to existing shared `create_draft`/`set_display_name` services and opens that new
draft after indexing it. The original is untouched, notes/lineage/publisher identity are retained,
and no release version is allocated. This convenience requires a captured digest; ordinary title
mutation still rejects published sources unless the caller explicitly requests a draft.
CLI/native clients retain the existing create-draft-then-edit workflow.

Canonical and installed references explain direct workspace title editing and explicit replacement
suggestions. The new UI does not change identifier rename APIs, CLI rules or generation behavior.

Verification:

- 35 focused preview/title/lifecycle backend contracts and 110 related naming, release-note, skill
  and installer contracts passed. Coverage includes both pack types and scenarios, immutability,
  independent draft identity, missing/stale reviews, clearing published titles and legacy adoption.
- All 273 frontend tests pass across 25 files. The complete app regression starts with a published
  friendly title, clicks it, requests AI, saves and confirms the new draft heading. Isolated title
  tests cover current-value prefilling, cancellation, no-op saves, clearing and manual-edit priority.
- An isolated browser preview using the production editor verified focus, inline input/sparkle/save
  layout, suggestion-before-save, updated headings and reopening with the saved friendly title.
  Suggestions and saves in that preview used simulated data; its files, server and tab were removed.
- Generated type freshness, production build, full Ruff check/format, whitespace and generation
  compatibility checks pass. Existing Vite bundle-size advisory remains unchanged. Behavior remains
  revision 160 with the same digest; no paid AI calls were made.
- Rebuilt the standalone Apple Silicon app at unchanged version 2.1.2. Relocated runtime checksum,
  isolated CLI, bundled skills/references, artifact naming, legacy validation and checkpoint-enabled
  generation acceptance passed. The user's running app/helper and authored workspace data were untouched.

Logs: `/private/tmp/eforge-header-title-backend.log`, `/private/tmp/eforge-header-title-regression.log`,
`/private/tmp/eforge-header-title-frontend.log`, `/private/tmp/eforge-header-title-build.log`,
`/private/tmp/eforge-header-title-macos-package.log`, `/private/tmp/eforge-header-title-macos-verify.log`.

## Field assistance placement

Moved the release-notes sparkle from the far edge of the editor to immediately beside its label.
Display-name suggestions now use the same shared heading layout in creation forms, lifecycle
panels and workspace title editors for scenarios and both pack kinds. Icon buttons remain small,
accessible and six pixels from their labels at any field width. The display-name label uses a
unique input association, and the workspace save/cancel controls align with the input beneath
the heading. Named AI actions retain sparkles inside their existing buttons.

Only layout and label association changed; suggestion, preview, save and publication behavior
are unchanged. No core/CLI, schema, naming or generation changes were needed.

Verification:

- All 273 frontend tests pass across 25 files. Production build, generated type freshness,
  full Ruff check/format and whitespace checks pass; the existing bundle-size advisory remains.
- An isolated browser preview of production fields checked widths of 1,014 and 264 pixels and
  the workspace title editor. Every sparkle remained six pixels from its label on the same row.
  Simulated suggestions still filled display names and opened an editable release-notes preview.
  No paid AI calls were made. Temporary preview files, server and browser tab were removed.
- Rebuilt the standalone Apple Silicon app at unchanged version 2.1.2. Relocated runtime checksum,
  isolated CLI, bundled skills/references, artifact naming, legacy validation and checkpoint-enabled
  generation acceptance passed. The running Studio app/helper and user workspace files were untouched.

Logs: `/private/tmp/eforge-ai-placement-frontend.log`, `/private/tmp/eforge-ai-placement-build.log`,
`/private/tmp/eforge-ai-placement-types.log`, `/private/tmp/eforge-ai-placement-ruff.log`,
`/private/tmp/eforge-ai-placement-format.log`, `/private/tmp/eforge-ai-placement-macos-package.log`,
`/private/tmp/eforge-ai-placement-macos-verify.log`.

## Workspace names and run sizes

Removed the display-name editor and save action from Versions & Publication. Scenario and pack
workspace headings remain the editing entrypoint. Their editor presents the display name first
and a collapsed Change identifier section. Both field labels have nearby small sparkles. The
identifier sparkle derives a valid editable slug from the current title without a model call;
the UI uses the same assistance convention requested by the user. Suggestions never save names.
The shared full-identifier validator applies when an identifier actually changes, preserving
existing legacy identifiers during title-only edits and upgrades.

Added a shared file service for reviewed identifier/title edits and scenario/pack CLI `rename`
commands requiring an inspected digest. Existing drafts retain their IDs, notes, lineage and
locations. Draft pack catalog namespaces are remapped together with their manifest. Multiple
declaring includes retain comments and permissions; staged replacements restore original files
if an ordinary filesystem replacement fails. Published and legacy inputs create linked Schema 3
drafts with the new identity. Originals, consumers and existing captured runs are not rewritten.
Pack name editing requests the existing exact/indirect consumer inspection, including protected
bundled originals; affected items retain their collapsed, grouped disclosure. Deletion still
requires the original strict workspace guard. Canonical and installed native-client references
document the same CLI workflow.

The Runs header replaces the Forecast button with a clickable size. Latest uses the newest
completed run matching this workspace version and its captured source/dependency inputs. Forecast
uses the current estimate when no matching readable completed bundle exists; stale and partial
data do not become Latest. Labels, icons and colors distinguish them. Calculating/unavailable
states remain explicit. Both values open the existing complete forecast dialog, retaining its
refresh, generate and focus-return behavior. Forecasting remains automatic and deterministic.

Verification:

- All 278 frontend tests pass across 25 files, including identifier suggestions without requests,
  explicit saving, consumer review, name validation and current/older/partial/missing size cases.
- 58 naming, title and pack contracts and 36 lifecycle contracts pass. CLI-only renames cover
  all artifact kinds. Published immutability, stale reviews, exact consumers, namespace remapping,
  unchanged consumer files and split-include rollback/comments/permissions are covered. An existing
  legacy-name preservation test caught overly broad validation; validation now applies only to
  an explicitly supplied new identifier. Skill/installer and optional AI-preview regressions pass.
- An isolated browser preview of production workspace components checked both name fields,
  sparkle proximity, suggestion-before-save, saved identifier presentation, absence of the
  publication name editor, Latest-to-Forecast transition, and the existing forecast dialog.
  Simulated data was used; temporary preview files, server and browser tab were removed.
- Production build, generated type freshness, full Ruff check/format, whitespace and generation
  compatibility checks pass. Generation stays at revision 160 with the same surface digest;
  the existing frontend bundle-size advisory remains. No paid AI calls were made.
- Rebuilt the Apple Silicon standalone app at unchanged version 2.1.2. Relocated runtime checksum,
  isolated CLI, bundled skills/references, naming (including scenario and both pack rename commands),
  legacy validation and checkpoint-enabled generation acceptance passed. The running Studio app,
  helper and authored user workspace were untouched.

Logs: `/private/tmp/eforge-workspace-tweaks-frontend-final.log`,
`/private/tmp/eforge-workspace-tweaks-backend-final.log`,
`/private/tmp/eforge-workspace-tweaks-lifecycle-final.log`,
`/private/tmp/eforge-workspace-tweaks-rollback.log`,
`/private/tmp/eforge-workspace-tweaks-build.log`,
`/private/tmp/eforge-workspace-tweaks-types-check.log`,
`/private/tmp/eforge-workspace-tweaks-macos-package.log`,
`/private/tmp/eforge-workspace-tweaks-macos-verify.log`.

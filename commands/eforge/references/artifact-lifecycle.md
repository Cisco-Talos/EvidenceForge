---
description: "Schema 3 drafts, immutable local releases, ancestry and portable archives"
---

# Authored artifact lifecycle

Contents: [Removal](#remove-a-local-scenario), [Source and state](#select-the-source-and-state),
[Upgrades](#upgrade-deliberately), [Publication](#notes-ancestry-and-publication),
[Dependencies](#test-and-promote-dependencies), [Portable releases](#portable-releases-and-runs).

These operations work through files and the `eforge` CLI in any supported native chat client.
Studio is optional. Never require its database, a helper service, library registration, Codex,
or a running GUI. Generation remains deterministic and never calls an LLM.

## Remove a local scenario

Ordinary scenario files can be removed through the shell. As an optional reviewed operation,
run `eforge scenario delete <path-or-reference> --json` to review exact files and include consumers.
Explain that deletion is permanent and cannot be undone; export anything the user wants to keep.
After the user accepts that review, repeat with `--revision <review-revision>` to permanently
remove the selected source. Managed drafts/releases are removed as a unit; legacy removal deletes
only the selected YAML and preserves companion files. To remove its entire dedicated source folder
and data beneath it, include `--include-files` in both review and confirmation. Shared scenario
folders, includes, symbolic links, changed reviews and foreign paths prevent unsafe removal.
Other versions and shared packs remain available. No recovery copies are retained. A small local
identity record reserves removed published labels and permits interrupted index cleanup; it
contains no authored files, assets, notes or generated data.

Studio uses the same source operation and removes local conversations/index associations. Its
optional all-files choice also removes this exact scenario's verified owned runs, evaluations,
private input snapshots, configuration and job files. Active work blocks deletion. Retained runs
remain findable through Bundles when the all-files choice is off. External imported bundles are
not removed outside the selected scenario folder. CLI-generated data elsewhere can be removed
through the shell after reviewing its location; Studio registration is never required.

Delete shared packs separately through Packs, and bundles through Bundles or their attached
scenario. Pack deletion reviews exact direct and indirect consumers and allows explicit acceptance
of the dependency warning. Those consumers may need repair; captured inputs and self-contained
published releases remain usable. Bundled engine packs and other installed versions are protected.

## Select the source and state

Use `eforge scenario inspect <path-or-reference> --json` or
`eforge pack inspect-artifact <path-or-reference> --json` before editing. These commands expose
schema, lifecycle, notes, lineage and the digest needed for reviewed edits, including for portable
archives. `eforge pack inspect <archive> --json` retains the archive-validation contract:
`valid`, `root` and `members` on success; `valid: false`, an `error` and exit code 2 on failure.
Ordinary Scenario 1/2 and Pack Schema 2 workspace files remain usable and unclassified.
Do not infer publication from their version field. Generated resolved inputs and bundles are
not authored documents and must never be upgraded or edited.

New scenarios use `schema_version: "3.0"`. `scenario_version` now labels the published content,
not the schema. New pack manifests use `pack_schema_version: "3.0"` and retain `version` for
content releases. Existing schema markers are read by presence: `schema_version`, then
`scenario_version`, then `version`. A malformed or unsupported present marker is an error.

Use `scenario new-draft <name> --json`, or `pack new-draft <name> --kind industry|organization
--json`, for a new scaffold. Complete the authored fields using the dedicated authoring skill.
Keep the `draft_id` supplied by the CLI through every editing session. Drafts use an explicitly
selected publisher, otherwise retain their source's recorded publisher, otherwise use the
configured project-over-user publisher. Without any of those they may remain anonymous.
New scaffolds use the configured publisher when one is available. Creation never rewrites the
original or assigns publisher ownership to its historical parent references. Editing or resuming
an existing anonymous draft does not silently change its identity; publication can still use the
configured publisher. Changing settings does not rename existing drafts or releases.
Use `... resume <path> --json` to inspect the same draft again. No edit or resume allocates a
release number. Read `eforge schema scenario.envelope --json` and `eforge schema lifecycle --json`
for exact metadata fields.

To revise a release, run `... draft <source> --json` and edit the returned path. `--name` or
`--publisher` creates a new logical identity with retained ancestry. Independent drafts have
independent IDs, even when based on the same version. Never edit or reseal a published release.
Use `... draft <published-source> --recover --json` if external edits damaged one.

## Identifiers and friendly titles

`name` is the stable, case-sensitive identifier. Scenario identifiers allow ASCII letters,
digits, `_` and `-`, including in the first position. Pack identifiers allow lowercase ASCII
letters, digits and `-`, starting with a letter or digit. The engine, CLI and Studio use the
shared `evidenceforge.naming` contract. They have no 80-character artifact-name limit. Keep
full identifiers for equality, references, ordering and search. Portable managed folders encode
and, when necessary, hash long names; the YAML retains the complete identifier. Filesystem
limits still apply to user-selected directories and export filenames. Studio offers bounded
export filenames while retaining the full identifier in the archive. For scenario identifiers
starting with `-`, put CLI options first and use `-- -my-name` to end option parsing.

Optional Schema 3 root `display_name` is a nonblank, single-line Unicode title with spaces and
punctuation. Omit it or use null to fall back to `name`; Studio displays and sorts the full title,
truncating presentation only. Duplicate display names are allowed and never identify a release.
Publisher/name/version and draft IDs remain authoritative. `publisher_display_name` names the
publisher and is a different field.

Offer a display name during creation and, if missing, an edit/update. Accept an explicit refusal
without repeating the question in that conversation. Supplying one is never an authoring gate.
If the user wants help choosing a title, their native chat client can propose one from the
available descriptions. For scenarios, `Organization name - Scenario Type` is a useful pattern
when both are known; for packs, prefer the natural organization or industry name. With sparse
context, humanize the identifier rather than inventing details. Show an editable suggestion and
let the user choose whether to apply it. Replace an existing title only on an explicit request;
never apply suggestions automatically during imports. Studio's **Properties…** menu entry opens a
Settings-style popup; clicking a workspace title opens its General section. Draft display names and
descriptions are edited directly there. Published and legacy fields are read-only: explicitly create
a linked draft before editing. Adjacent sparkle buttons propose editable previews; **Use suggestion**
and **Save properties** are separate actions. Suggestions and cancelling never create drafts or publish.
Manual names and omission remain fully supported. The CLI contains no LLM title-generation operation.
The Identifier and Publisher **Change…** operation creates a separate linked draft with a new identity.
The identifier sparkle derives a suggestion from the display name without an AI call. Review the
identifier and affected pack consumers before creating the draft. Existing references are not rewritten.
Use `... new-draft <name> --display-name "Friendly Title"`, or `... draft <source> --display-name
"Friendly Title"`, to set one on creation. Use `eforge scenario display-name <draft> --value
"Friendly Title" --json` (or `eforge pack display-name`) to edit, and `--clear` to remove it.
Editing YAML directly is equally supported. Title changes never rename `name`, move files,
change publisher identity or allocate versions. Legacy files must be explicitly upgraded/adopted
into a separate draft to add this field. Published titles are immutable; create a draft to edit.

## Properties and validation provenance without Studio

Both artifact command groups support `properties <source> --json`, `edit-properties <draft>
--changes <changes.json> --expected-digest <digest> --json`, and `check <source> --json`.
Use the same file paths or exact portable references as other lifecycle operations. `--context`
is optional on inspection/checks; current working-directory and `--project-root` rules still apply.
The changes JSON contains only the properties to change: `display_name` (text or null),
`description`, and/or `release_notes`. The edit preserves comments and declaring include files,
requires a Schema 3 draft, and rejects a changed review. Identity, schema, UUIDs, digests and
captured paths are separate operations or read-only values. Native clients can draft optional
descriptions and notes from available authored context, show the proposed text, and apply only
the user's accepted edit. Never invoke AI during validation or generation.

`properties` includes available note history, exact parent comparisons, missing ancestors,
schema upgrade availability, dependencies and **Validated with**. Standard scenario and pack
validation retain successful exact-input engine records when the project is writable; `check`
explicitly requires retaining the record. Publication includes its validation engine record in
the immutable portable receipt. Edits or changed configuration/dependencies invalidate draft
records. Older artifacts without records remain usable and show no recorded validation;
never infer their validating engine from the installed application. This identifies the engine
that checked the inputs; it does not promise support on earlier engines or identical generation.
Existing `requires_evidenceforge` ranges remain advanced authored declarations, not inferred
feature compatibility or a field ordinary users must choose.

Studio keeps workspace publication controls compact; Properties' Versions & publication section
shows current notes, **View full history**, exact parents and comparison previews. Project assignment
is supplementary Studio grouping and never becomes authored identity. Generated bundles are
read-only captured runs. `eforge scenario bundle-properties <bundle-folder> --json` exposes their
generation provenance, captured format selections, concrete log types present, bytes/files under
`data/`, and total regular-file disk usage (including metadata/checkpoints), with no host inventory
or record scan. `formats` retains selected groups/filters; `log_types` identifies the recognized
data filenames actually present, and `unrecognized_data_files` counts other regular data files.
Selecting Windows enables Security and Sysmon, with eCAR separate; selecting Zeek enables its
supported sources without guaranteeing that every source produces a file. Present file types do
not prove record counts or every supported event kind. Partial bundles report their current data
sizes and types without inventing a completion manifest.

Titles are sealed in source-file integrity and survive portable export/import, while remaining
outside generation semantic identity and deterministic seeds. Changing only display metadata
therefore changes a release's integrity but preserves generation behavior.

To change an identifier, inspect the source and then use `eforge scenario rename <source> <name>
--expected-digest <digest> --json`, or `eforge pack rename`. Both use the same portable file service
as Studio. Existing drafts keep their draft IDs, lineage and file locations; pack catalog namespaces
are remapped consistently. Published or legacy sources create a linked Schema 3 draft under the new
identity, preserving the original and its references. The existing display name is retained unless
`--display-name` supplies a replacement. No operation allocates a release number. Renaming a draft
pack may require updating its consumers' draft references; validate those consumers afterward.

## Upgrade deliberately

Offer `... upgrade <source> --json` only when inspection reports `upgrade_available: true`.
It creates a separate linked Schema 3 draft and preserves original bytes, includes, assets and
comments. It does not infer historical content versions. Validate the returned draft and report
findings; unrelated semantic errors can be repaired there. An already-current schema has no
upgrade action.

## Notes, ancestry and publication

`description` explains the whole artifact. Optional root YAML `release_notes` explains changes
in this release. Keep notes editable in drafts. Use `... compare <parent> <draft> --json` to review
available sources. The host chat client may propose notes on the user's request; provide an
editable preview and let the user review it. Generating a note never accepts it or publishes.
Studio offers a small sparkle beside release notes. It compares exact available ancestors,
reports missing or partial comparisons, and presents an editable suggestion. **Use suggestion**
fills the draft editor; **Save notes** is a separate operation. Manual notes remain available
without AI. Sparkles identify assistance throughout Studio, including identifier suggestions;
chat actions retain their labels. Field-specific sparkles sit immediately beside their labels.
Record exact publisher/name/version/digest parents; multiple parents record lineage without
automatic merging. Add other exact parents with `... draft <source> --parent <other-source>`.
Missing ancestors do not block a self-contained release.
Legacy source parents record their schema and exact digest without a guessed release label.
Publication also records the exact draft ID, publisher (when assigned) and digest it finalized,
while preserving the draft's existing ancestry. The editable draft remains unchanged. If it is
edited afterward its new contents no longer match that publication snapshot.
Studio groups an unassigned source or draft with a same-name release only when exact recorded
ancestry links them to one unambiguous publisher. Different artifact kinds, renamed forks and
explicit publisher namespaces remain separate. Missing ancestors can be linked through shared
exact parent references. Legacy sources and releases must match their recorded digests; a mutable
draft remains in its group by its stable draft ID through further edits, while the release retains
the exact earlier snapshot digest. These library groups are supplementary
presentation and never rewrite the source publisher, immutable releases or ancestry. A shared
anonymous ancestor used by different publishers remains unassigned.
Use `... notes <draft> --file /absolute/reviewed-notes.txt --json` to accept a reviewed note.
Inspect shared metadata contracts with `eforge schema scenario.envelope --json`,
`eforge schema pack.envelope --json`, and `eforge schema lifecycle.parent --json`.

Publisher-qualified name/version identifies a release. Digests identify its exact contents.
Publisher namespaces are local labels, not authenticated authorship. Inspect configured identity
with `eforge pack publisher show --json`; publication requires explicit project/user configuration.
Never derive a publisher from the operating-system user, machine or repository.

Use `... drafts --json` to find repairable drafts and `... suggest-version <draft> --json`
to review an unused label without allocating it. Run canonical validation before publication.
`... publish <draft> --json` chooses an unused patch
label, starting at `1.0.0`. Users may select `--version X.Y.Z` or `--bump patch|minor|major`.
Review reported warnings, then explicitly acknowledge them with `--accept-warnings` if appropriate.
Generation and evaluation are optional checks, not publication gates. Partial organization packs
retain their existing validation semantics. Publication freezes sources, dependencies, selected
overlays and effective configuration; the draft remains independently editable.

## Test and promote dependencies

Scenario drafts can validate and generate against draft packs using `source: draft`, `draft_id`,
`name`, and a `path` to the pack directory. Omit publisher/version. Their catalog namespace is
`draft-<uuid>/<name>:<local-id>`. Organization drafts can use similarly identified industry drafts;
refresh the exact snapshot lock through `eforge pack lock <draft> --apply --json` after edits.

Publish dependencies first. Use `... promote-dependency <draft> <published-pack> --draft-id <uuid>
--json` to preview the exact reference and qualified catalog changes. After user review, repeat
with `--apply`. This is a reviewed conversion, not automatic merging. Published scenarios and
packs cannot depend on unfinished draft packs.

## Portable releases and runs

Use `... versions <publisher> <name> --json` (`--kind organization` for organization packs) to
inspect all exact local releases. A local scenario reference is
`project:<publisher>:scenario:<name>@X.Y.Z`. Use returned source paths or references with ordinary
`eforge validate`, `resolve`, `generate`, and run-based `eval`. Published runs use frozen
configuration; supported explicit execution overrides appear in run provenance. Draft test runs
capture their precise inputs and remain evaluable after subsequent edits.

`scenario export <release> /absolute/name.efscenario --json` or `pack export ... name.efpack`
creates a portable immutable archive. Logs and checkpoints are excluded. Import with
`scenario import-release <archive> --json` or `pack import-release ...`. Identical imports are
idempotent; conflicting contents under the same publisher/name/version are rejected. Older
`.efpack` build/inspect/import/hydrate operations remain available for existing releases.
Publication finalizes a local release. Export and distribution are separate actions.

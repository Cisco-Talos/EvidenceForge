# Studio starter drafts and publication error lifetime

## Cause and approved scope

After the managed-source recovery fix, the user's fresh Test Scenario 2 was a real but unauthored
scaffold. Publication failed strict schema validation, and cancelling retained that action's raw
Pydantic exception in the overview. Read-only lifecycle inspection itself succeeded. User approved
recognizing untouched scaffolds, authoring guidance/action gates, the missing baseline description,
separate inspection/publication errors and full macOS interaction testing.

## Implementation

- Shared scenario scaffold creation supplies `baseline_activity.description: ""`, preserving empty
  entities until authoring. A backward-compatible `scaffold_sha256` receipt field fingerprints its
  semantic authoring content. Metadata/title/identity edits do not make the scaffold runnable.
- Starter recognition requires the managed entrypoint and matching draft receipt/UUID. Earlier
  unmarked drafts must match the exact shared template (including the older omitted description).
  Empty inline entities alone never match; composition, includes or substantive source edits end
  the starter state. Missing/corrupt sources are not presented as untouched starters.
- Snapshot/event state shows Ready to author, continues the existing conversation, disables
  Generate/Publish and the forecast popup, and suppresses automatic forecasts. Server endpoints
  also check the current file, including queued forecast work. Explicit validation remains enabled.
- Publication inspection, other lifecycle actions and publication errors have independent UI state.
  Cancel/Escape clear publication errors/review; genuine inspection errors and explicit validation
  findings remain separate. Chained schema exceptions produce field-level publication/Properties
  findings without raw input values or Pydantic help URLs. CLI validation already provided structured
  fields and remains unchanged. Strict shared publication validation remains unchanged.

## macOS acceptance

Native debug `.app` built with `npm --prefix desktop-ui run build:native -- --debug --bundles app -- --locked`.
Used isolated state/workspace under `/private/tmp/eforge-starter-draft-acceptance/`; confirmed the
normal workspace had no active jobs/chats before closing it.

- Created starter-mac-test through the native UI, with real YAML/receipt before any authoring turn.
  Waited for lifecycle requests to settle: authoring guidance appeared, Generate/Publish/Forecast
  were disabled, and no raw error appeared. Explicit Validate produced two readable entity findings.
- Edited only the temporary source's environment description. After Refresh, the starter guidance
  disappeared and normal actions/automatic forecasting resumed. Publication of the incomplete
  draft failed with readable environment.users/environment.systems fields inside the dialog.
  Cancel removed that action error from the overview while keeping explicit validation findings.
- Replaced only temporary content with the minimal valid fixture, retaining its draft identity and
  receipt. Refresh produced a normal ~613.2 KB forecast with Generate/Publish enabled. Explicit
  validation completed successfully and cleared the earlier validation findings.

## Checks and remaining scope

All **296 frontend tests in 29 files** passed on the final code. Focused backend run passed **136
tests**, with one slow test excluded by the routine marker gate (Studio service, source recovery,
scaffolds and shared/Studio artifact lifecycle). After tightening malformed-receipt guards and
clearing component state when switching items, all **16 scaffold/recovery tests** and **113
App/lifecycle tests** passed again, followed by the full frontend run. Shared scaffold tests cover
markers, metadata edits, old receipts, pack composition and corrupt sources. Type generation,
TypeScript/Vite and native builds passed; final repo-wide Ruff lint/formatting (1021 files) and
`git diff --check` passed. Generation behavior remains revision 161 with digest
`bd9e13343c8fb72dfdbbb03a284357a3a0664d362c1b0503222bc76b2b6584d4`.

Reopened the user's normal macOS workspace with the final native build, confirming all five
entries and connected Codex status. Opened the existing Test Scenario 2: its older scaffold was
recognized without rewriting its YAML/receipt, the authoring guidance and disabled controls
appeared, and the earlier publication error was absent. Left that overview open for user review.
No Linux sync/build/state mutation, version bump, commit or release publication in this task.

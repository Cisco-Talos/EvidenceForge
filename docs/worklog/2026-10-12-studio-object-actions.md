# Studio object action requirements

## Purpose and scope

Studio should offer a consistent way to act on scenarios, packs, runs and other objects in
lists. The user requested a requirements conversation before implementation, with shared rules
that can be applied without specifying changes to each individual element.

This worklog records the October 12, 2026 decisions. The user approved implementation after reviewing the interaction preview. The shared menus and
shortcuts are now implemented in the current checkout. The user
confirmed that this pass includes asset tables and file lists, alongside scenarios, packs, runs,
bundles, conversations, projects and saved views.

## Agreed interaction rules

- The three dots menu is the complete action list for its object. Visible shortcut actions also
  appear in the appropriate menu, with the same name and behavior.
- The same object has the same menu wherever it appears: actions, labels, grouping, order and
  appearance. Availability follows the object's state and capabilities.
- Relevant unavailable actions remain visible and disabled, with an explanation. Each object
  type exposes its applicable actions.
- Keep useful shortcuts for the most common actions. One or two is a general guideline, with
  job controls available as appropriate to their state.
- Jobs retain visible Pause, Resume and Stop controls where applicable.
- Conversations retains Continue and New conversation shortcuts. Runs retains Forecast and
  Generate shortcuts.
- Shortcut buttons should use text. The conversation interpreted this as text-only ordinary
  shortcut buttons; the Environment refresh shortcut should read Refresh environment.
- Keep object actions and section actions scoped appropriately. The Conversations section can
  offer Continue and New conversation; an individual conversation has its own object menu.
- Preserve the information currently visible on collapsed rows and section headers. Status,
  generation progress, evaluation results, warnings, timestamps, sizes and other existing summaries
  must remain available without expanding each object. Review responsive layouts for the same
  information preservation.
- Preserve the size value inside the Runs forecast shortcut. Keep the existing Forecast · ~size
  display, measured Latest · size display for a completed bundle matching current inputs, and
  Awaiting authoring, Calculating and Unavailable states. Opening the shortcut still shows the
  full forecast. The associated menu action carries the same available size information.

## Agreed menu order

Use separators between applicable groups. Preserve action positions when disabled.

| Order | Purpose | Examples |
| --- | --- | --- |
| 1 | Open and inspect | Open, Properties |
| 2 | Main work | Continue, Validate, Forecast, Generate, Evaluate, job controls |
| 3 | Reuse and share | Clone, Export |
| 4 | Organize | Rename, Move to project, Hide |
| 5 | Remove | Remove from library, Delete |

## Removal and ellipsis rules

- Enabled Remove/Delete actions use red text and a red trash icon.
- Disabled Remove/Delete actions use grey text and a grey trash icon, retaining an explanation.
- Remove/Delete always opens confirmation, including removal of only a library or history entry
  while keeping files. The confirmation explains the actual consequences.
- Show a single applicable removal action for an object unless it supports distinct, meaningful
  removal operations. Do not add a disabled Delete action to an object whose files Studio does
  not own, or add history removal to an object without a job-history entry. Temporary unavailability
  remains disabled within the stable menu. Imported bundles have only Remove from Studio;
  authored artifacts have their applicable Delete action.
- Remove/Delete labels have no ellipsis. This is the user's explicit exception to the general
  ellipsis convention.
- Other commands can use an ellipsis when another step is required, such as entering a name or
  selecting export options or a destination. Apply the same label to menu items and shortcuts.
- The final confirmation button uses the action name without an ellipsis. Submenus use an arrow.

## Current UI inventory

| Surface | Current differences to reconcile |
| --- | --- |
| Scenario library | Move and bundle export are separate icon controls; other actions are in the menu. |
| Pack library | Move is a separate icon control; export and clone are in the menu. |
| Scenario and pack workspace | Title menu differs from library menus; lifecycle and section actions use buttons. |
| Runs and Job center | Properties is in the summary menu; most actions require expansion and use buttons; deletion uses a separate menu. |
| Imported bundles | Properties is in the summary menu; file viewing, export and removal use buttons. |
| Conversations and drafts | Menus have different coverage; active conversations and drafts disable deletion. |
| Projects | Edit and Delete have a separate small menu. |
| Saved views | Deletion uses a lone trash icon and currently acts immediately. |
| Asset tables | Edit, Customize, Restore and account conversion actions appear inside expanded details. |
| File browser | File rows select previews; Save a copy and path copying are separate controls. |

Existing generation jobs restrict deletion while running or queued. Existing active conversations
and authoring drafts disable deletion. These are concrete examples of valid disabled removal
states; the shared menus should preserve the owning service's restrictions.

## Reviewed scope decisions

- Reviewed a concrete action and shortcut inventory before implementation. Preserve the confirmed
  shortcuts and choose other shortcuts by usefulness rather than requiring element-by-element
  instructions from the user.
- Bulk history cleanup follows the same removal styling and confirmation convention.
- The user approved the shortcut selection and action inventory below using the interaction preview.

## Sparkle icon criteria and audit

The user wants the sparkle icon on actions that cause AI to do work or automatically compute a
useful task or suggestion. It should not mark ordinary navigation or conversation creation. The
user explicitly identified Continue and New conversation as incorrect uses. Keep labels accurate
about whether an action uses AI or computes a local suggestion. Adjacent suggestion controls are
purposeful exceptions to the ordinary text shortcut convention.

The source audit found 22 rendered sparkle placements across 15 components. The user decided
to remove the sparkle from Fix in chat because the action only prepares a request. Equivalent
Edit in chat and Prepare in chat actions use the same preparation path, so the same decision
applies to them. These dispositions are now implemented.

| Placement | Click behavior | Disposition |
| --- | --- | --- |
| DisplayNameField: Suggest display name | Calls AI to propose a display name. | Keep |
| ArtifactProperties: Suggest description | Calls AI to propose a description. | Keep |
| ReleaseNotesField: Suggest release notes | Calls AI to propose notes from exact inputs and available ancestry. | Keep |
| ArtifactTitle: Suggest identifier | Computes and fills an identifier from the display name locally. | Keep |
| ArtifactProperties: Suggest identifier | Computes and fills an identifier from the display name locally. | Keep |
| ScenarioWorkspace: Continue authoring | Opens an existing conversation or creates a conversation. | Remove |
| ScenarioWorkspace: Continue | Opens the preferred conversation. | Remove |
| ScenarioWorkspace: New conversation | Creates and opens a conversation; sends no AI request. | Remove |
| ScenarioWorkspace: conversation rail New conversation | Creates and opens a conversation; sends no AI request. | Remove |
| ScenarioLibrary: draft symbol | Represents a draft row that opens its conversation. | Remove |
| PackLibrary: draft symbol | Represents a draft row that opens its conversation. | Remove |
| ChatView: Select a conversation empty state | Decoration with no action. | Remove |
| ChatView: empty conversation welcome | Decoration with no action. | Remove |
| SettingsView: Authoring and tools tab | Selects a settings tab. | Remove |
| EnvironmentView: Choose packs | Opens the pack selection dialog. | Remove |
| ImportDialog: Create scenario | Creates a starter draft and opens its conversation; sends no AI request. | Remove |
| NewPackDialog: Create pack | Creates a draft; optional Details starts an AI turn immediately. | Show sparkle only when Details will start that turn |
| ScenarioWorkspace: Fix in chat | Creates a conversation and automatically fills a repair request; waits for Send. | Remove, by user decision |
| ValidationPanel in components: Fix in chat | Uses the same prepared-repair path as ScenarioWorkspace. | Remove |
| PackWorkflow: Fix in chat | Creates a conversation and fills a pack repair request; waits for Send. | Remove |
| ConfigurationLayers: Edit in chat | Creates a conversation and fills a configuration editing request; waits for Send. | Remove |
| EnvironmentView: Prepare in chat | Creates a conversation and fills a composition-change request from the selected packs; waits for Send. | Remove |

Result: keep five direct suggestion placements, remove sixteen navigation/decorative/request
preparation placements, and make Create pack's placement conditional on starting the initial AI
turn. No ambiguous sparkle cases remain after applying the user's criteria and decision.

## Proposed shortcut selection

The entries below are the concrete implementation proposal. All shortcut actions also appear in
the appropriate menu. Menus remain available on collapsed rows and section headers. Opening a
menu must not expand or collapse its row.

| Surface | Visible shortcuts |
| --- | --- |
| Scenario and pack library rows | Click the name to open; use the menu for management actions. |
| Conversations section | Continue, New conversation |
| Environment section | Refresh environment |
| Validation section | Validate; Fix in chat when findings are present |
| Runs section | Forecast with its size value and existing Latest size/state variations, Generate |
| Active or paused run | Applicable Pause, Resume, Stop controls |
| Completed run | Evaluate, View files |
| Imported bundle | View files, Export ZIP… |
| Pack assets section | Add asset… |
| Expanded editable asset | Edit… or Customize in scenario… |
| File preview | Save a copy… |
| Projects, conversations, saved view rows | Click the name to open/apply; use the menu for management actions. |

Keep compact, useful publication shortcuts such as New draft or Publish locally… when appropriate
to the artifact state; other lifecycle actions remain in the complete artifact menu. Shortcuts
must retain the same labels and availability rules as their menu actions.

## Proposed action inventory

Each row describes the complete coverage to implement, organized by the agreed action groups.
Actions are enabled according to existing capabilities, ownership, current inputs and lifecycle
state. A draft, published release or protected bundled artifact should retain stable relevant
actions with clear disabled reasons. Do not add operations unsupported by the file/service layer.

| Object or section | Action coverage |
| --- | --- |
| Scenario | Open, Properties, source and version inspection; Continue, New conversation, environment refresh, Validate, Fix in chat, Forecast, Generate and existing publication/schema actions; New draft, Clone, authored-release export, generated-bundle export and path copying; Move to project, Hide/Show; Delete scenario. |
| Pack | Open, Properties, source/version/asset inspection; Continue, New conversation, validation, Fix in chat, asset addition and existing publication/schema actions; New draft, Clone, pack-release export and path copying; Move to project, Hide/Show; Delete version. |
| Authoring draft with no authored source | Open/Continue; existing name editing and project assignment; Delete draft. Keep future source-dependent actions disabled wherever relevant to the same object type. |
| Studio generation run | Open details, Properties, View files, View scorecard, View log and log refresh; Pause, Resume, Stop where supported, Evaluate and Regenerate; full/partial ZIP export and path copying; Remove from history and Delete bundle as distinct actions. |
| Evaluation job | Open details, View scorecard, View files, View log, log refresh and source-generation navigation; existing supported job controls; path copying; Remove from history. |
| Imported bundle | Open details, Properties, View files; Export ZIP and Copy path; Remove from Studio. Existing external-file protections remain authoritative. |
| Conversation | Open, Rename; Remove/Delete conversation using the existing record-removal semantics. |
| Project | Open, Edit project; Delete project with the existing explanation that objects move to Ungrouped and files remain. |
| Saved view | Apply view; Delete saved view with confirmation. |
| Asset | View details; supported Edit/Customize, Restore inherited values and account-state conversion actions. Preserve ownership, inherited-source and immutable-release restrictions. |
| File | Open/view; applicable source/rendered preview actions; Copy path and Save a copy. |
| Section menus | Include the section's existing actions and every retained section shortcut. Give removal/clear-history actions their final separated group. |

Use explicit export labels to distinguish an authored scenario/pack release from generated bundle
data. Use Remove from history for the existing operation that clears a job-center entry while
keeping files and scorecards; keep Delete bundle for deleting run files and linked evaluations.
Studio-owned generation runs genuinely support both operations: the history route adds a Job
center visibility marker, and the bundle route removes owned files and associated records. Their
menu descriptions should make those different consequences clear. Remove from history becomes
disabled once its visibility marker already exists. Evaluate each object's actual ownership and
capabilities before including either action; the rule is based on the object, not the current view.

Bulk Clear completed/Clear finished history actions are proposed to follow the same removal
styling and confirmation rules, with no ellipsis. The confirmation states which records are
affected and that files and scorecards remain.

## Implementation direction to review

Use shared object action definitions and menu rendering so different views expose the same
actions and availability. Shortcuts invoke those same actions. Keep existing service protections,
publication reviews and file ownership semantics authoritative. Distinguish exports of authored
artifacts from exports of generated bundles in the final action inventory.

## Interaction preview verification

A conversation preview demonstrates Conversations, Environment and Runs section shortcuts plus
sample running, completed and paused rows. It uses local sample state and leaves Studio's actual
UI, services and user data unchanged. The preview is stored in this chat's visualization directory
as studio-object-actions.html; the requirements and proposed inventory above remain the durable
repository record.

Browser checks at 736 px and 320 px preserved the collapsed progress, evaluation, size, timestamp
and revision summaries without horizontal overflow. Opening menus retained collapsed row state.
Menu Pause and shortcut Resume updated the same sample state. Enabled removal actions had red
labels and one trash icon each; disabled removal actions retained a grey label and trash icon.
Delete bundle opened a confirmation with an action label without ellipsis. Escape closed the menu,
and the preview had no browser console errors. The temporary tab and viewport override were
cleaned up after inspection. Repository whitespace checks passed; application tests were not
needed for this documentation and preview work.

After the user's review, the preview restored Forecast · ~1.8 GB in both the shortcut and its menu
action. It also added an imported bundle with only Remove from Studio, and short consequence
descriptions for the two distinct Studio-owned run operations. Browser checks confirmed the
imported menu has no history-removal or bundle-deletion action, the sized forecast still opens
its detail dialog, and the revised layout fits at 736 px and 320 px without horizontal overflow.
The specification retains the actual application's measured Latest size and forecast availability
states; the sample preview displays an estimate because its completed run is an earlier revision.

## Implementation and verification

The shared `ObjectActions` renderer now supplies ordered groups, separators, submenus, disabled
reasons, text shortcuts and removal styling. Artifact menus use the same action definitions in
the library, workspace and environment references. Drafts, conversations, projects, saved views,
assets, configuration files, bundle files, runs and imported bundles use the shared controls.
Section menus include their retained shortcuts. Artifact lifecycle operations retain current-digest
reviews and publication safeguards. Pack validation and environment refresh state are shared with
their menus and section shortcuts.

Runs retain collapsed statuses, times, progress, evaluation results, revision warnings and sizes.
Live rows also expose the same controls while the Runs section is folded. Forecast retains its
estimate, measured Latest value and authoring/calculation/unavailable states. Imported and
unowned outputs omit bundle deletion. Owned runs expose distinct confirmed history removal and
bundle deletion, with deletion disabled while a linked evaluation is active. The service now
exposes output ownership and normalizes legacy unknown ownership to unowned.

The individual Stop route is authenticated, scoped to the current workspace and serialized
with the job cycle. It delegates process termination to the existing PID/creation-time ownership
checks, preserves files and queue-wide settings, and reports a conflict if the process is still
running. Existing generation/checkpoint and evaluation policies remain authoritative.

All sparkle audit dispositions above are implemented. Ordinary shortcuts use text; intentional
field suggestion controls retain their icons. Removal uses a trash icon in both enabled and
disabled states and always requires a consequence-specific confirmation.

Validation evidence:

- Full frontend gate: `npm test -- --reporter=dot` — 305 tests across 30 files passed.
- Subsequent focused checks of assets, runs and shared controls passed 30 tests; the final
  forecast/header refinements passed 105 App/resource-forecast tests.
- Service/job/controller/evaluation checks passed 115 tests. After adding ownership metadata
  and its legacy normalization regression, the final service/job checks passed 91 tests,
  including all nine new job-action tests.
- `npm run build`, generated API type checks, `ruff check .`, `ruff format --check .` and
  `git diff --check` passed. Vite retains its existing large-chunk advisory.
- Browser verification used the actual React App and components with isolated sample state,
  without opening the user's Studio database or changing their authored files. Checks at
  1280, 736 and 320 px confirmed readable collapsed summaries and wrapping controls. Long
  menus scroll within the viewport. Pointer and keyboard submenu selection work; menu actions
  close before opening dialogs or transferring focus.
- The sample Forecast · ~1.8 GB appeared in both shortcut and menu and opened its detailed
  forecast. The matching-current-run case displayed Latest · 1.9 GB. Enabled removal computed
  to red with one trash icon; disabled removal computed to grey with one trash icon. Imported
  bundle menus exposed only Remove from Studio, and its centered confirmation fit at 320 px.
  Menu Pause changed the selected sample job while leaving its row collapsed. No browser
  console errors remained after fixture setup. Temporary browser/server resources were cleaned
  up after verification.

The user authorized committing the completed refactor locally without pushing. No product
version or release was changed.
## Follow-up review: section scope and bundle families

The user reviewed the running app after the first local refactor commit (`27ccd099`) and
requested five refinements. This follow-up keeps the separate Codex-status change out of its
commit and does not push either effort.

- The conversation rail gives New conversation its own compact row beneath the heading and
  section menu, rather than squeezing all three controls onto one line.
- Expanded runs no longer duplicate View log and the log menu. View, Hide, Refresh and log-path
  copying remain in the run's complete menu; generator failure information remains in the body.
- Pack Validation & release exposes Validate and its section menu while collapsed. Expanding
  it reveals findings and dependency information without duplicating those header controls.
- Pack section menus are scoped explicitly. Conversations has Continue/New conversation;
  Assets has View assets/Add asset; Validation & release has validation, repair, version and
  publication commands. Properties, source inspection, cloning, project assignment, hiding and
  removal remain in the complete pack menu. Import stays in the pack library. Published or
  protected packs explain why adding an asset requires a new draft or workspace clone.
- Bundles groups related draft/release runs through canonical artifact families and retained
  source-path aliases. Imported runs join an unambiguous family. Different publishers remain
  distinct. Group menus provide latest-run/source navigation and disclosure commands, with each
  run retaining its complete operation menu.

The previous `source` heading was the parent-directory fallback for unmatched historical paths.
Runs now expose bounded, cached scenario identity from their verified immutable input or completion
manifest. Imported metadata also checks the registered manifest hash. The row shows the captured
release version, Draft, Legacy scenario or Version unknown, independent of later source edits.
Old source associations and captured names recover useful grouping after relocation or publication.
These are derived response fields; persisted job and bundle registration schemas are unchanged.

Verification: all 323 frontend tests passed, including section scoping and mixed-version bundle
grouping. Service/job/source checks covered 109 cases; the changed imported-bundle response
assertion passed its focused recheck. Production build, generated API types, Ruff and whitespace
checks passed. Browser inspection of the actual React App with isolated sample data verified
the conversation rail, full publication menu, asset menu, folded/expanded section headers, run-log
access and merged bundle rows. The shortcut fits its rail at 1280, 736 and 320 px; bundle version,
status, time, progress and size information remains available without horizontal page overflow.
Temporary browser tabs, viewport overrides and the sample server were cleaned up.

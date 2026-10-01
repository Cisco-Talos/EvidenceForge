# EvidenceForge Studio rebuild

The user approved replacing the Qt Widgets prototype with a Tauri, React, and Python service desktop app. Keep the Qt prototype available until the new app reaches core parity and passes review. There is no requirement to migrate prototype metadata; authored YAML and generated bundles remain authoritative.

## Agreed delivery order

1. Design and feasibility slice: scenario library and workspace, conversations, job center, compact settings, two simultaneous generations, close and reconnect.
2. Core prototype parity, including Codex authoring, libraries, job controls, quit behavior, and source-run macOS/Linux support. Pause for user review.
3. Seven workflow stages from the approved plan, one at a time with review after each.

## Current implementation

- `src/evidenceforge/studio/` contains platform paths, JSON settings, SQLite catalog, local authenticated FastAPI service, durable job adapter, and detached-service bootstrap.
- `desktop-ui/` contains the Tauri shell and a first React implementation of the scenario/pack libraries, workspace, job center, and settings.
- The macOS Tauri debug build and frontend production build pass. Focused service and React
  interaction checks cover the evolving Studio slice. The five screen review mockups are in
  `docs/design/studio/`, and a live in-app browser preview runs from disposable Studio metadata.
- The Qt prototype remains in place; existing user edits to prototype files are untouched.

## Design review checkpoint

The first Tauri test launched a native window on the user's desktop. Its close button and File →
Exit did not close it; that test process was stopped. The native close handler has since been
changed to bound the service handoff wait and offer a force-close path, but the rebuilt native
window has not yet been retested. The user reviewed the five screen mockups and asked to try the
app. Their first feedback was to show validation/generation/evaluation states since the latest
scenario edit, add per-conversation rename/delete, make generation concurrency a setting, and
allow run-specific scenario ZIP download from both library cards and scenario workspaces. They
also supplied the location of official logos and requested UI branding and a real app icon.

That feedback is implemented in the preview slice:

- Scenario operation states use distinct shapes and colors, tooltips, and the SHA-256 of the
  authored YAML to distinguish current from stale results. Validation results survive reopening.
  The active source hash does not yet cover pack or overlay changes.
- Conversation entries have rename/delete menus. Deletion is blocked while a turn is active.
- Settings includes a persisted maximum of one to 16 concurrent generations (default two), and
  the detached controller leaves excess work queued. Evaluations do not consume those slots.
- The library card and scenario workspace have Download bundle actions. A scenario with multiple
  completed runs offers a run picker. The ZIP contains one run's self-contained bundle, the
  current authored scenario YAML and companion notes, and any completed linked evaluation report.
  The resolved scenario inside the run is the authoritative generation input. Export is currently
  browser-Blob based; large-bundle streaming/save-location handling remains Stage 7 work.
- Repo copies of the official full-color dark/light logo were used for the sidebar, loading view,
  favicon, and Tauri icon set. The OneDrive source folder was inaccessible in the sandbox; the
  repo copies were sufficient. The preview CSS was corrected at narrow widths.
- Added `websockets` to the Studio dependency extra; before that, the preview service emitted
  repeated unsupported-WebSocket-upgrade warnings and did not support live event updates.

The in-app browser preview points at repository scenarios with a disposable Studio home under
`/private/tmp/eforge-studio-preview2`. A real CLI validation of `branch-office-example` was
confirmed visually: the persistent state icon and validation panel show one warning. No actual
generation was started in the repository workspace. Pause here for design feedback before
expanding core parity. The first-pass design is not accepted yet.

## Library and job-center feedback (September 30)

The next preview feedback led to four focused changes:

- Removed the topbar's constant “Local service” indicator. The Python controller is an
  implementation detail; the UI still reports connection failures when they occur.
- Moved validation, generation, and evaluation states to small icon-only controls alongside each
  scenario card's title, with keyboard focus and descriptive tooltips. Bundle download is an
  adjacent icon. The card no longer reserves a full footer row for status pills.
- Added **Fix in chat** to validation reports with findings. It creates a scenario-linked
  conversation and prepares a message with the saved findings, their paths, and suggested fixes.
  The request tells Codex to revalidate current authored files before making changes. The user
  reviews and sends the draft; it is never submitted automatically. A sent draft does not reappear
  when the conversation is reopened.
- The Job center now counts active Codex turns and lists working chats separately from chats
  waiting for approval/input. A row opens that scenario's conversation. Empty jobs use a compact
  panel, and Resume paused jobs appears only when a paused job exists. The service clears persisted
  active-turn flags after its owning Codex process has gone away on restart or disconnect, and
  clears outstanding approval cards on disconnect.

Focused verification: 11 React interaction tests, 14 Studio service tests, TypeScript/Vite build,
and Ruff checks pass. The compact card, validation action, and authoring activity list were reviewed
visually in the in-app browser preview. The preview's existing Codex turn remains marked active;
its history request did not answer within a short inspection timeout, so live Codex throughput
and approval handling still need the core-parity end-to-end review.

## Codex connection recovery (September 30)

The saved preview conversation exposed two causes of a history hang. The history endpoint first
called `thread/resume` before `thread/read`, although `thread/read` can inspect the stored thread
without resuming it. More critically, the real app-server's full history response exceeded
Python asyncio's default 64 KiB stream line limit. The reader task then exited while the
Codex process was still alive, leaving the chat disconnected. The endpoint now calls only
`thread/read`; the transport accepts protocol lines up to 64 MiB and processes RPC responses
independently of potentially slow event handlers. Codex calls have bounded timeouts, including
their write step.

The service now probes the Codex app-server every eight seconds, reconciles active turn flags,
and broadcasts `codex.health` transitions. A small topbar dot shows connected, checking/stalled,
or disconnected state, with a hover explanation and a manual reconnect action. Reconnecting
warns before interrupting active turns and preserves saved thread IDs. The Job center no longer
counts uncertain turns as working. Conversation history shows a recovery note if a turn was
interrupted; the note clears when a later history read confirms the turn actually completed.
The health probe must send an explicit empty `params` object to `thread/loaded/list`; the
real app-server rejects the call if that field is omitted.

The live saved Codex thread was read successfully through both the direct app-server bridge
and the Studio history route. The refreshed browser preview shows a green Codex indicator and
loads the saved user message, agent answer, and collapsed activity. The browser also detects
loss of the Studio event stream, marks the dot disconnected, and retries automatically rather
than leaving a stale green Codex status. Focused verification now has 18 Studio service tests
and 13 React interaction tests; TypeScript/Vite build and Ruff checks pass. The native Tauri
window and Linux smoke test remain part of the core-parity gate.

## New-thread history readiness (September 30)

A real first turn exposed an app-server race: `turn/start` succeeded and Codex began answering,
but an immediate `thread/read` found an empty rollout file and returned a thread-store error.
Studio previously treated this as a connection failure and showed an error even though the
turn was running. The bridge now classifies that exact empty-rollout response as transient.
The history route returns `history_pending` without changing connection health, and the active
turn health probe tolerates the same response. The chat keeps the submitted message visible,
retries saved history with bounded backoff, and offers a manual retry if it remains unavailable.
The browser no longer reads history immediately after a successful send; completion or a
history-read retry refreshes it. Backend and React regression tests cover the race and recovery.
The focused Studio suite now has 20 service tests and 15 React interaction tests; the
TypeScript/Vite build and full Ruff checks pass. The preview service and Vite connection were
refreshed after confirming no active Codex turns, and the saved user turn and answer reload.

## Viewport-sized conversations (September 30)

The conversation view used a fixed `100vh - 258px` height with a 540px minimum. A tall scenario
header made the window itself scroll, pushing the composer below shorter browser windows. The
conversation tab now uses the topbar breadcrumb for scenario context, fills the remaining app
height, and gives scrolling to the chat transcript and conversation rail. The composer stays
inside the viewport. New output follows the bottom while the user is there. If the user scrolls
up, incoming output and sends leave the transcript in place until they manually reach the exact
bottom again. Opening another conversation starts at its latest turn. A 712×724 browser review
confirmed the document and app shell are exactly
724px tall, with the composer ending at the viewport bottom and the transcript scrolled to its
latest message.

## Project grouping clarification

The approved workflow plan includes virtual folders, project-folder overviews, and a later
project-overlay area, but did not define a first-class Project record. The user wants projects
to group scenarios. The roadmap now calls for stable project identities inside a workspace,
project overview/navigation, and an Ungrouped view; group membership can initially live in
SQLite so existing scenario files do not move. Project overlays can attach to the same identity
in the environment stage. The first project grouping slice is implemented below; project
overlays remain part of the environment workflow stage.

## Projects slice (September 30)

Projects now have stable IDs and workspace-scoped, case-insensitive unique names in Studio's
SQLite catalog. Scenario membership is metadata on indexed items; rescanning preserves it and
does not move authored YAML or runs. A project can be created, renamed, described, and deleted.
Deletion returns its scenarios to Ungrouped. The service checks that both the project and the
scenario belong to the selected workspace before changing membership. Bootstrap and live events
include projects so the view survives a service restart and updates without reopening the app.

The scenario library has a compact project rail with All scenarios, project counts, and Ungrouped.
Selecting a project shows its description and scenarios. Scenario cards can be moved through a
menu or dragged by a visible grip onto a project or Ungrouped; the selected drop target is
highlighted. The scenario workspace has a project picker. The move menu remains the keyboard
path. At narrow widths the rail becomes horizontal and card status icons wrap below long names.

The disposable browser preview at `http://127.0.0.1:1420/` was refreshed only after confirming
no active Studio jobs or Codex turns. A "Studio review" project was created there and
`branch-office-example` assigned for user review. Creation, menu assignment, project counts,
project overview, and the scenario workspace picker were observed in the live browser. Browser
automation did not trigger native HTML drag events when dragging the grip, so physical drag and
drop still needs user testing in the preview; React interaction tests verify the drag/drop event
contract and both project and Ungrouped destinations. The project slice has 21 Studio service
tests and 20 React tests passing. This is the next feedback gate before further core parity.

## Follow-up turns in chat (September 30)

The chat could omit a submitted follow-up and append its answer to the preceding answer. React
stored only the latest WebSocket event, so a `conversation.updated` event arriving directly after
`turn/completed` could replace the completion before the chat rendered it. The chat also used one
live answer string across turns and waited for saved history before clearing it. Studio now sends
each event directly to chat subscribers. The chat keeps optimistic prompts and streamed answers
as separate turn records keyed by Codex turn ID, and removes a local turn only when the saved
terminal turn is available. It retries history reads when Codex has not yet persisted the turn.
Interaction tests cover back-to-back turns with stale history, and a hook test verifies both
completion and conversation update arrive when React batches them.

## Drafts, discovery, and library recall (September 30)

New scenario and pack actions now create durable draft conversations with stable target paths.
The draft appears in the library and can be resumed or deleted. The first Codex turn receives the
target path and authoring skill as context, and a rescan links the draft to the authored file once
the turn finishes. Scenario project membership carries across that handoff. Deleting a project
also returns its unfinished drafts to Ungrouped.

Library search now covers indexed YAML content as well as names and descriptions, with `name:`,
`description:`, and `yaml:` scopes. Items can be hidden from their menu and revealed through a
compact Show hidden control. Saved views store a search, selected project or Ungrouped, and the
hidden-item setting per workspace; the library can apply and delete them. The topbar command menu
opens with Cmd/Ctrl+K and searches pages, projects, and authored items. Completed evaluation jobs
read their saved quality reports into compact scorecards shown in the scenario overview and run
history.

The preview service was refreshed only after confirming zero active jobs and turns, and the saved
views and command menu were inspected in the 712 by 724 in-app browser. The draft chat was also
checked at that size with its composer visible. Deleting a project now changes any saved view
targeting it to Ungrouped. Focused checks: 25 Studio service tests and 27 React interaction tests
pass; TypeScript/Vite and Ruff checks pass. The macOS Tauri shell passes `cargo check --locked`.
These are incremental core parity changes, not the final acceptance review.

The `/v1/bootstrap` route now validates a typed Pydantic snapshot. `npm run types:generate`
generates the TypeScript API declarations from its OpenAPI schema in an isolated temporary Studio
home; `npm run types:check` detects stale generated declarations. The UI uses generated model
types for items, projects, saved views, conversations, settings, jobs, and validations. TypeScript
build, API type freshness, and UI tests pass after this change.

Flat virtual folders are now available as a secondary library filter for scenarios and packs.
The filter control contains create, rename, and delete actions; each item’s menu can move it to a
folder. Folder changes touch only SQLite organization metadata and preserve source files. Saved
views record the folder filter and follow folder renames or deletion. The Python service contract
test covers these relationships; React tests cover filtering, saving the filter, and creation.
The live browser preview was refreshed after checking zero active jobs and chats, and the compact
folder menu was visually inspected. The real CLI checkpoint/suspend/resume smoke suite passed on
macOS (both default and `sof-elk` targets).

CI now has a required Studio matrix on macOS and Linux. It runs the Studio service tests,
generated API type freshness check, React interaction tests, production frontend build, and
`cargo check --locked` for the Tauri shell. Linux installs the system packages listed in the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/). The workflow YAML was parsed
locally; the new CI lane has not yet run on GitHub.

## Generation progress and resume correction

A live preview run exposed three connected defects. The service emitted job updates for status
changes but did not broadcast appended CLI progress, so a running card could remain on its initial
“Queued” phase. Resume switched to a new JSONL file, hiding the progress recorded before the pause.
The controller also treated any `.eforge-generation` directory as proof of a usable checkpoint and
kept replaying a persisted Resume instruction. The inspected preview run had progress in its
original JSONL, but no recovery index or suspension record; repeated CLI attempts reported “no
generation checkpoint exists.” The first attempt had failed with “Deferred session process
projection has no unique transport endpoint” before its first checkpoint. Its authored files and
partial bundle were left intact.

Studio now watches progress file signatures and broadcasts updates without a status change,
retains earlier progress streams across resumes (including records created before this fix),
and labels queued, paused, and stopped cards according to job state. A pause is recorded only
after a durable suspension acknowledgement and recovery pointer exist. Resume is a one-shot
controller intent, and the UI/API reject a run that has no checkpoint to resume. Focused service
and controller tests cover appended progress, older saved progress streams, invalid checkpoint
state, and one-shot resume; React tests cover independent and preserved bars. The focused Python
suite, React suite, generated API type check, frontend build, and Ruff pass.

## Checkpoint, scenario creation, and stopped-run feedback (September 30)

Jobs settings now saves simulated hours between generation checkpoints, defaulting to the CLI's
24 hours. New GUI generations and regenerations use this setting unless a caller explicitly
overrides it. New scenarios ask for a name and optional project before opening chat. Unauthored
scenarios appear as ordinary library cards with a Draft marker, project assignment, rename, and
drag-and-drop. Their conversation metadata remains separate from the authored YAML. The first
Codex turn receives the chosen name as scenario context. The library indexer now accepts
Scenario 2.0's `scenario_version` field; this was why a fully authored preview scenario remained
in Drafts. Rescanning linked that existing YAML to its original conversation and displayed it
in the normal scenario library without changing the file.

Stopped/failed generations without a checkpoint now offer Regenerate and Delete incomplete
bundle. Regenerate creates a new run ID and output directory from the current authored scenario;
the original partial run stays until explicitly deleted. Deletion checks the app-owned job marker,
process identity, status, and absence of a completed manifest or linked evaluation before removing
the directory and job record. The browser preview's Open bundle action now displays an
authenticated file browser instead of calling the Tauri-only opener; the native window still
opens the folder directly. The user's existing stopped 73% run and partial files were preserved.

Verification: 33 Studio service tests, 32 React interaction tests, TypeScript/Vite build, generated
API type check, and full Ruff checks pass. The refreshed browser preview shows the authored
Scenario 2.0 card, the existing linked conversation, the stopped run's new actions, and the
browser bundle file list. The scenario creation dialog shows name and project fields.

## Run card names (September 30)

Generation cards previously used the parent directory of `scenario.yaml` as their title. New
scenarios authored through Studio live under `studio-<id>` directories, so their run cards showed
that internal ID instead of the authored scenario name. The React view now resolves each
generation's title from its indexed scenario, and evaluation cards follow their source
generation. Existing job records and bundle directories are unchanged. A React regression test
covers both card types. All 33 React interaction tests and the production frontend build pass;
the live Job Center shows the authored name for the existing generation and evaluation cards.

## Job Center layout feedback (September 30)

With two generations and one evaluation, the user found the cards hard to distinguish and their
positions unstable. They proposed compact job rows in collapsible sections by job type, ordered
oldest first. Job Center and scenario run history now use compact expandable rows in Generations
and Evaluations sections. Generation records carry an immutable `submitted_at` timestamp, because
`started_at` changes on resume. Existing records fall back to the output directory's timestamp,
then a stable ID tie-breaker. Each row keeps status and progress visible while its actions live in
the expanded detail. Evaluation rows identify and open their source generation, even when the
Generations section is collapsed. A multiple-generation UI test checks independent progress bars.

## Bundles and library simplification (September 30)

Projects now provide scenario organization, so the scenario library no longer exposes virtual
folder controls or folder filters. Pack folders remain available. The unlabeled eye icon is gone;
when hidden scenarios exist, a labeled Hidden count toggles their visibility so they can be
unhidden. Existing folder metadata was left in the service; authored files were not moved.

A peer Bundles page groups Studio generation records by scenario. It supports search and project
and completion filters, and rows for complete and incomplete runs. Completed ZIP exports include
the run, current authored scenario, and linked evaluation reports; inactive incomplete runs can
be exported as clearly labeled partial ZIPs. The delete action confirms the exact run path and
removes only output marked as created by that GUI job. Completed-bundle deletion also removes its
linked evaluation records; active linked evaluations block deletion. Imported or unmanaged
bundles are not indexed here yet. Bundle ZIP downloads use a one-use, 60-second ticket so the
browser streams the archive rather than buffering the whole file in JavaScript memory. ZIP
filenames use the scenario name and run ID; a live browser download was verified and its temporary
copy removed afterward.

View files now opens a read-only viewer with a file list, explicit per-file download, line numbers,
and lightweight JSON, YAML, Markdown, and email syntax highlighting. Preview requests are capped
at 256 KiB and 4,000 lines; binary files show a download prompt. The live browser preview was
visually reviewed at 712 × 724 and its idle service/Vite processes were refreshed to load the new
routes. Frontend interaction tests, production build, Studio service tests, and Ruff checks pass.

## Bundle, job, and settings follow-up (October 1)

The bundle file viewer now fills the available window up to 1320 px, with a narrower file list
beside the preview on wide windows and above it on narrow windows. The evaluation's source link
opens, focuses, scrolls to, and briefly highlights its generation row so the navigation is clear.
Settings Save is disabled until a field changes, returns to disabled after a successful save,
and shows a saved confirmation. Incoming service snapshots preserve unsaved edits.

The Bundles list now shows each run's uncompressed contents size beside its name. An authenticated,
on-demand service endpoint sums regular files without following symlinks; the Bundles page refreshes
sizes while generations are running rather than scanning run directories on every snapshot.
The live 712 px browser preview shows the wider viewer, a 1.4 MB bundle row, the highlighted
source generation, and the Settings save state. Verification: 38 React tests, 35 Studio service
tests, frontend build, generated API types check, and full Ruff check and format check pass.

## Copy displayed paths (October 1)

Displayed filesystem paths now have compact copy icons in the scenario and pack workspaces,
draft header, run history, Bundles viewer and delete dialog, sidebar workspace label, and
Settings. Editable workspace and output paths can also be copied. Shortened labels always copy
the full path. The icon changes to a check after success; clipboard failures appear in the app
notice. A React interaction test covers scenario and bundle paths. In the live browser preview,
copying the scenario path and pasting into search produced the exact full YAML path.
The path labels now size to their text, with a bounded width for long paths, so each copy icon
stays beside the visible label instead of drifting to the far edge of its row. The Bundles and
Settings layouts were visually reviewed in the live browser preview.

## Native save and export flow (October 1)

The Tauri window now uses a system Save dialog for all three existing download paths: the file
viewer, run ZIPs (including inactive partial runs), and completed scenario ZIPs. A Rust command
streams the authenticated local service response to a temporary file beside the selected
destination, reports byte progress, supports cancellation, and renames only after a complete
transfer. The browser preview keeps its existing download behavior. Native labels say **Save a
copy** for one file and **Export ZIP** for archives. The last successful destination folder is
remembered in SQLite per workspace and offered at the next Save dialog.

The service export-location route has an authorization and workspace isolation test. React tests
cover the native API call, folder persistence, cancellation, and existing download controls. Rust
tests cover allowed local routes and atomic handling of a truncated response. Linux smoke review
remains before cutover. Verification:
36 Studio service tests, 41 React tests, three Rust unit tests, frontend production build, generated
API type check, full Ruff check/format check, Cargo check/format check, and a macOS debug `.app`
bundle succeeded. The optional DMG bundling step failed in this environment; the app-only bundle
completed successfully.

A direct macOS launch found that Finder-style `.app` startup lacked the shell's Python environment.
The Tauri command now searches ancestor directories for the source checkout's `.venv` before using
the system Python; the rebuilt `.app` connected to the Studio service. The same launch reproduced
the prior red-close failure. Close handling now keeps one current listener instead of racing
snapshot-driven registrations, and a Rust exit command bounds process shutdown after the
service's quit policy handoff. Rebuilt `.app` smoke confirmed that the red close button exits.
The rebuilt macOS app was then launched with an isolated temporary Studio home and a disposable
completed run. Through the native window, **Save a copy** in the file viewer saved
`GROUND_TRUTH.md` byte-for-byte, **Export ZIP** in Bundles saved a valid run ZIP, and the scenario
library exported a valid scenario ZIP. The second Save dialog opened in the previously chosen
folder. The red close button exited the app. The isolated service and files were removed afterward.

## Outstanding core parity

- Review native Codex sign-in and one actual scenario-authoring turn with a real account. Studio
  service live-turn, recovery, and conversation tests already pass.
- Keep detailed pack editing, scenario/pack deletion, and imported incomplete bundles for their
  later workflow stages. Cloning, hiding, virtual organization, saved views, scorecard detail,
  and complete-bundle import now work in core parity.
- Complete native-window hands-on review on macOS and Linux smoke. The source-run guide and
  platform state paths are documented. Cut over `eforge-desktop` only after acceptance.

## Codex turn and account recovery (October 1)

The installed Codex app-server was probed directly for account, model, skill, and loaded-thread
methods. Its current schema confirms that `turn/start` returns a turn ID. Studio now returns that ID
with each turn submission, letting the chat bind its optimistic user message to the authoritative
turn even if `turn/started` is missed. A timeout after submission is reported as an uncertain
delivery rather than a failed send, so the user message stays visible while health and history
reconcile. Fast completion before the submission response is also handled without duplicating
messages or reactivating the conversation.

Codex status now reports a signed-out but connected process as available, allowing sign-in even
when model and skill listings require an account. Chat blocks sending while signed out. Settings
shows a waiting state and polls briefly after starting sign-in so the account identity appears
without a manual refresh. A timed-out turn with no immediate ID now reconciles against a newly
completed history turn without leaving a duplicate local message, even if its prompt matches an
earlier turn. The browser preview opens the authorization URL in a new tab; Tauri uses
its native opener. A failed notification callback no longer kills the app-server event dispatcher;
server requests receive an explicit error response if Studio cannot handle them.

Verification: 39 Studio service tests, 40 React tests, frontend build and generated API type check
passed, as did full Ruff check and formatting. A live app-server turn in a disposable workspace
returned its turn ID, emitted start and completion events, and produced a completed readable agent
message in history. A second live smoke used Studio's authenticated conversation routes with a
disposable scenario: the default scenario skill was handed to Codex, the submission returned its
turn ID, history showed one completed agent message, and the scenario file stayed untouched.
Native-window sign-in and an actual file-authoring turn remain review checks.

## Quit handoff and process ownership (October 1)

Studio's **Stop active turns** close choice is now part of the saved controller intent. Closing the
window returns after the intent is durable; a background task requests Codex interruption without
holding the native close handler. The eight-second service monitor retries interrupted requests
while the quit intent remains active. **Finish in background** leaves turns running and still waits
for user approval/input when Codex asks. A failed stop request appears as a conversation recovery
note rather than being lost when the window closes.

Process ownership checks now compare the recorded and live process creation times within 10 ms,
instead of the former two-second window, before terminating jobs or accepting the service/worker
identity. A process disappearing between ownership verification and POSIX group lookup no longer
breaks the controller tick. Tests cover a PID with a mismatched start time, that exit race, durable
authoring choices and prompt close handoff, checkpoint-disabled close choices, and Cancel close
from the waiting dialog. Verification: 61 Python service/desktop tests, 42 React tests, the
frontend build, and full Ruff check/format pass.

The browser preview helper and Vite server were restarted after confirming zero active jobs and
chats. The refreshed helper and preview responded on loopback; no authored files or run bundles
were changed by the restart.

## Run-linked scorecard detail (October 1)

The scenario overview's saved score now has a direct **View scorecard** action. It opens the
matching evaluation row in that scenario's run history and highlights it. The row loads a readable
projection of its saved quality report only when opened: overall result, flags, pillars and
subscores, acceptance checks, and record counts by source. The full report stays on disk, so
routine workspace snapshots remain small. The new authenticated route is scoped to the active
workspace and reads only its app-owned evaluation report path.

Service and React tests cover the exact run link, report rendering, authorization, workspace
isolation, and invalid reports. The disposable browser preview was restarted after confirming
zero active jobs and chats; opening the latest score for `lumenforge-drive-by-beacon` visibly
showed the matching evaluation and its saved detailed report. This improves core parity but is
not the Stage 6 evidence drill-down or comparison workflow. Verification: 75 focused Python
service/desktop tests, 42 React tests, generated API type check, frontend build, and full Ruff
check/format pass.

## Scenario and pack cloning (October 1)

The scenario library and scenario workspace can clone an authored scenario into a new workspace
folder. The clone copies companion files with the YAML, changes its top-level name, and keeps the
original's project assignment. It does not inherit conversations, validation, runs, or scores.
Cloning refuses source links, linked companion files, shared folders with multiple scenarios,
oversized folders, and an existing destination. The new file gets a fresh catalog identity.

Pack libraries and workspaces can clone an industry or organization pack with the existing
`eforge pack copy` command, keeping CLI validation and provenance rules authoritative. If no
publisher is configured, the dialog collects a publisher ID and display name and saves them as a
workspace publisher identity before copying. The clone preserves the pack's virtual folder and
gets a fresh catalog identity. Tests use the real CLI against a bundled sample pack in an isolated
workspace, plus browser interaction tests for both clone dialogs.

## External bundle library (October 1)

The Bundles page can import a complete preexisting CLI or earlier desktop generation folder, or
find complete bundles under the active workspace's `runs/` directory. Imported bundles get stable
workspace-scoped SQLite identities, search and status filtering, size and creation time, the same
readable file viewer, and ZIP export. They remain read-only: **Remove from Studio** deletes only
the index row, never external files. Studio rejects duplicate imports of its own managed jobs.

Import validates the authoritative generation manifest schema and resolved-scenario digest. Subsequent
file access checks both again and refuses changed paths; the file viewer bounds its listing and
does not follow links, while ZIP export refuses linked content. The native app offers a folder
picker, and browser preview accepts a local path. Disposable service tests cover authorization,
workspace isolation, import identity, discovery, file viewing, export, changed manifests,
changed resolved input, and safe removal. React tests cover import, discovery, grouping,
read-only removal, and the viewer route. Incomplete external bundles remain a roadmap item;
Studio-owned incomplete jobs already appear in the library.

The browser preview helper was restarted after confirming it had zero active jobs and chats. A
disposable external bundle was imported through the UI; its scenario group, exact size, read-only
row, and file viewer appeared as expected. The UI removed its index entry without deleting the
files. The test fixture was then removed. Visual review also replaced the imported row's opaque
Studio ID with its folder name and made the file viewer open ground truth first when present.
`eforge-studio` source-run setup and state locations are now documented in
`docs/studio-source-run.md` while the Qt entry point remains available for the review gate.

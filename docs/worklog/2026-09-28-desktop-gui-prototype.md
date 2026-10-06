# Desktop GUI prototype

**Date:** 2026-09-28

**Branch:** `codex/gui`

The first vertical slice uses PySide6 for a native window, Codex app-server for
skill-driven scenario chat, and detached `eforge` subprocesses for generation.
The app stores chat thread identifiers and job metadata in per-user app data.
Generation progress is a versioned JSONL side channel from the CLI's existing
engine callback, allowing the GUI to rebuild progress after a restart.

Important lifecycle choice: closing the window stops the Codex transport but
does not stop generation processes. Job reconciliation checks both PID and
creation time before claiming a process is still active. A completed bundle is
identified by `GENERATION_MANIFEST.json`; incomplete checkpoint workspaces can
be resumed.

Validation completed so far: a real minimal scenario generated a bundle and
19 progress events; a detached-process test confirmed rediscovery after its
launcher exited; a headless Qt startup/close smoke passed; a completed real
bundle restored its 9/9 hour bar on startup; 87 CLI and desktop tests passed.
Further acceptance
should exercise the actual chat authoring flow and a long generation with
suspend/resume from the visible UI.

## First user review

The initial Qt layout did not meet the desired visual quality and omitted several
expected workflows. Enter-to-send with modified-Enter newlines, a readable
validation summary, and an explicit output destination were added as usability
repairs. Scenario/data and pack libraries, scorecards, export, and the broader
navigation design still need a deliberate UI pass. Two design directions were
prepared for review: a library-first workspace and an authoring-first workspace.

The user prefers the **library-first** direction. Make Scenarios the landing view,
with a selected scenario's validation, saved evaluation, runs, and generation
destination visible together. Keep authoring chat as a workspace opened from a
scenario, with Packs and Runs in persistent navigation. Existing authored files
and bundle manifests should remain the source of truth for library entries.

## Library-first implementation

The desktop now opens on Scenarios with persistent navigation to Authoring,
Industry packs, Org packs, and Runs. Scenario entries come from authored YAML;
external files can be imported by reference. Pack entries come from bundled and
workspace pack catalogs. The selected scenario shows file metadata, app-launched
run status, a persisted evaluation scorecard, and its output destination. It routes to
authoring, readable validation, and the existing generation form. Clone and
hide actions are available for scenarios and packs. Hidden paths and imported
scenario references are saved in desktop state; authored files remain the source
of truth. A Refresh action picks up external edits. Completed app-launched runs
can be evaluated through the GUI with `eforge eval`; JSON reports are saved in
local app data, and the score persists across restarts. Evaluation processes are
concurrent while the app is open but stop on close. Archive export and
generation/evaluation pairing remain next steps.

New and existing packs route into the corresponding pack authoring skill;
pack catalog entries also support import, clone, hide, and opening the YAML.

## Scenario organization and search

Scenario folders are virtual, stored per workspace in desktop state, and do not
move authored files. Users can create, rename, delete, and assign folders from
the library. The UI filters by folder, scenario version, and latest run status;
its search covers name, description, and authored YAML text with quoted terms
and optional field scopes. Folder operations preserve source files, and cloned
scenarios inherit their source folder.

## Scenario tree and authoring tab cleanup

The separate folder and filter controls made the library feel crowded. The
scenario list is now a folder tree with a small add control, folder row menus,
scenario row menus and context menus, and drag-to-folder assignment. Search stays visible;
version, latest run status, and hidden-item controls moved into one filter
menu. Primary actions use icons with text, while secondary actions use icons
with tooltips. Authoring tabs now have a themed close icon. Closing a tab
interrupts an active turn, hides the tab, and retains its Codex conversation
in a Recent menu for reopening.
Offscreen Qt checks covered the scenario tree, pack list, menu actions, and
the authoring page. The desktop/CLI regression selection passed 98 tests;
14 tests were deselected by the project's default tier rules.

## Stage 0: Settings and job lifecycle

Added a sidebar Settings page and Cmd/Ctrl+Comma shortcut. Workspace and output
defaults, Codex account and skill actions, detected/configured tool paths, and a
default skill for new chats now live there. All agreed quit choices persist;
the user's Continue/full-pipeline answers are defaults. Existing desktop state
migrates without dropping chats, folders, run history, or scorecards.

Generation and evaluation records now live in atomic per-job files. A detached
local controller can start queued work, reconcile completion, and apply Continue,
Checkpoint and pause, or Kill after the window closes. Pause requests use the
CLI checkpoint/suspend contract. A wait-at-close mode shows a cancelable dialog;
request failures remain visible on job cards. Reopening a paused workspace does
not resume it until the user selects Resume paused jobs. Kill verifies recorded
PID creation time and, for app-created process groups, signals the group. Bundle
deletion requires an exact app-created marker and rejects completed or imported
bundles. The controller does not inspect or control terminal-launched jobs.

Offscreen macOS interaction and process tests cover preference persistence,
legacy migration, multiple independent run bars after restart, continued
generation and evaluation, pause and resume, checkpoint-disabled runs, each
evaluation quit policy, process identity, and deletion boundaries. The desktop
and CLI selection passed 113 tests (14 slow tests deselected), followed by a
passing real-CLI contract test for the app-created bundle marker and flags.
Added a dedicated
macOS/Linux desktop GUI CI matrix. Visual review used an offscreen 1350×840
render of Settings. Further review should include interactive keyboard and
visual checks on a visible macOS desktop.

## Stage 0 user review and settings refinement

The first Settings page was a long stack of large panels. Reworked it as a
three-category view (Workspace, Jobs, Authoring & tools) with compact rows and
individual hover help icons. The continuation checkbox now has a visible border
when unchecked and a high-contrast tick when checked. Removed the redundant
sidebar workspace button; the workspace name remains visible and switching is
available in Settings. Removed the global default-authoring-skill control and
migrated older state that contains it. A scenario chat attaches its scenario
skill for its first message, then returns to Automatic so later requests can
select a relevant skill; the per-message picker remains an explicit override.
The existing pack entry points still choose their corresponding pack skills.
The updated desktop/CLI selection passed 115 tests on macOS, with 14 slow tests
deselected; Ruff check and format passed. The category layout, checked and
unchecked controls, and tools page were reviewed in offscreen dark-theme renders.

## Stage 0 account and checkbox follow-up

The screenshot from user review showed the check glyph shifted right inside its
box. The custom painter now obtains Qt's checkbox indicator rectangle and centers
the glyph there, rather than centering it in the wider widget. The Codex account
row now shows the ChatGPT email returned by app-server `account/read` when
available. API key and Bedrock modes identify their authentication method and
state that a personal identity is unavailable through this protocol. The account
button changes between Sign in and Sign out. Sign out uses app-server
`account/logout` without params, then refreshes account state; the help text
explains that the local Codex CLI credentials may be shared with other clients.
The macOS desktop/CLI regression selection passed 117 tests (14 slow tests
deselected), and Ruff check and format passed. The checkbox and account row were
reviewed in offscreen dark-theme renders with a simulated ChatGPT identity.

## Stage 0 account and skill setup refinement

Combined the Codex identity and Sign in/Sign out control on one Settings row.
The separate EvidenceForge chat skills row now says whether this workspace has
copies, offers Install or Update as appropriate, and explains that it copies
bundled chat instructions into `.agents/skills` without installing the CLI.
The count refreshes on workspace change and after installation. A disposable
workspace interaction test verifies the copy and button transition. The
desktop/CLI regression selection passed 118 tests (14 slow deselected), Ruff
check and format passed, and an offscreen dark-theme render was reviewed.

## Stage 0 installer options follow-up

The initial chat-skills button only copied Codex skills into the current
workspace. Settings now persists the install location (user-wide or this
workspace) and agent target (both, Codex, or Claude Code), defaulting to the
user's requested user-wide installation for both agents. The destination paths
and selected-target status appear before the action. The GUI uses the same
installer functions and destination layout as `eforge install-skills`, continues
other selected targets if one fails, and reports partial failure. It refreshes
Codex's skill list when Codex skills are installed and flags preserved legacy
global Codex copies in the status bar.
The macOS desktop, CLI, and skill-installer selection passed 170 tests (14 slow
deselected); Ruff check and format passed. The default global/both-agent layout
was reviewed in an offscreen dark-theme render.

## Stage 1: Find and resume work

Scenario rows now show latest run state, saved score when available, and whether
the authored YAML changed after that run. The detail pane shows the YAML edit
time. Folder selection opens a project overview with active, completed, never
run, hidden, and attention counts plus clickable recently edited scenarios.
Search results show a source-labeled name, description, or YAML-line excerpt;
scenario text is cached by file identity to keep repeated searches responsive.

The library has built-in In progress, Needs attention, and Never run views and
supports named saved searches/filters with rename and delete. Saved views and
the last used view are workspace-scoped. Settings can disable last-view restore
while preserving named views; restore is enabled by default. Cmd/Ctrl+K opens a
searchable command menu for navigation, scenarios, folders, and recent chats.
Mac offscreen interaction tests cover status, snippets, folder navigation,
saved-view persistence and workspace isolation, and the actual keyboard
shortcut. The desktop/CLI/installer selection passed 173 tests (14 slow tests
deselected), followed by focused Stage 1 tests after the final UI refinements.
Ruff check and format passed; the library, folder overview, search results, and
command menu were reviewed in dark-theme renders. Linux and macOS desktop
interaction CI already covers the updated tests.

## Runs page space use

The original Runs view placed validation in a fixed 190-pixel-high text box above
full-width job cards, leaving most of a tall window empty with one run. The
validation findings and run history now share a resizable split area beneath
the run controls. Findings use the full available height, jobs remain scrollable,
and the split stacks vertically in narrow windows. When validation is empty,
the jobs area takes the full width. Job cards have a distinct surface and the
history area has a count and empty state. A disposable Qt layout test covers
wide and narrow windows and visibility changes; existing multi-job progress
tests remain in the desktop Settings suite. A dark-theme render was reviewed
at 1600×1000.

## Other pane space audit

Reviewed Scenarios, Industry packs, Org packs, Authoring, and all three Settings
categories at 1900×1200. Scenario and pack detail panes had large empty regions
between their metadata and bottom actions. They now show a bounded, read-only
YAML preview; its scroll position survives routine refreshes. Settings category
surfaces now fit their content and cap at 1100 pixels wide. The authoring
transcript already uses the available space for conversation. Offscreen renders
of the scenario, industry pack, and Workspace Settings views were inspected;
library and settings interaction tests cover preview visibility and compact
panel geometry. A richer pack contents inspector remains part of Stage 2.

## Authoring chat interaction review

Opening an existing scenario or pack now stores its path and kind on the chat
record, displays that context above the conversation, and leaves the composer
empty. The context is passed as thread-level Codex developer instructions when
the first user request starts the thread, so the first user message contains
only what the user typed. New pack chats likewise carry their pack kind as
context. Model and reasoning pickers are populated from app-server `model/list`,
saved per chat, and applied to future turns; effort options follow the selected
model. Tool, file-change, and reasoning items now appear as a single expandable
activity link per turn, with transient work status while a step runs. The
activity detail is rebuilt from stored thread history after reopening a chat.
Focused Qt tests cover context, picker persistence, turn parameters, activity
grouping, detail access, and history restoration. The 41 desktop tests passed
on macOS offscreen Qt; Ruff check passed. A 1350×840 dark-theme render of the
authoring view was inspected.

## Authoring conversation follow-up

Continue authoring now activates an existing open chat for the same scenario or
pack, or reopens the latest saved one when no tab is open. A per-context
Conversations menu lists saved chats and provides New conversation; tab labels
show stable conversation numbers when several exist. Older title-only chats are
associated with a scenario or pack only when that item name is unique across
the current libraries, avoiding an arbitrary match when names collide.

The model and reasoning pickers now show only the actual model and effort names
from the app-server catalog. A new chat selects the advertised default model and
that model's default effort. User messages align right with a blue accent;
Codex replies align left with a green accent. The macOS offscreen render of
multiple scenario conversations and the conversation transcript was reviewed.
The 46 desktop Qt tests passed, including reuse, reopen, legacy matching,
conversation switching, model/effort display, and message styling.

## Conversation identity and titles

Continue authoring now compares resolved scenario paths, so macOS aliases such
as `/var` and `/private/var` reuse the same saved chat. The library action uses
the item currently displayed in its detail pane. A click-through test covers
two existing scenario tabs with aliased paths.

Conversation labels now persist separately from scenario names. The first user
message supplies an immediate title; when the Codex model catalog offers a
Luna model, an ephemeral low-effort title turn refines it without changing the
authoring conversation. The app also reads an existing Codex thread name and
can load first-message titles for closed chats when their menu is opened.
Generated names are saved in desktop state and applied to the authoring thread
through `thread/name/set`. The complete desktop suite passed 48 tests on macOS;
Ruff check and format passed.

## Scenario-centered authoring navigation proposal

Conversation titles belong in the conversation history, not in the top-level
scenario tab label; tabs now show only the scenario name. The growing
Conversations dropdown and one tab per conversation should be replaced by a
scenario workspace with a persistent, searchable conversation list beside the
chat. The scenario library remains the entry point. Continue authoring selects
the scenario's last active conversation; New conversation creates another in
that scenario. Scenario and conversation rows should show active-turn status so
several authoring/validation turns can continue while the user switches views.
Drafts without a scenario file need their own section, and pack authoring should
use the same pattern within each pack's workspace. This navigation change is a
proposal for user review, not implemented in this pass. The tab-label change
passed 13 focused desktop chat tests and Ruff check/format.

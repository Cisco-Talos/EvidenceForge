# EvidenceForge desktop prototype

This is an experimental local Qt app for macOS and Linux. It runs Codex app-server
for skill-assisted authoring and the existing `eforge` CLI for validation and generation.
Generation itself remains deterministic. Windows has not been tested.

## Run it

1. Install the [Codex CLI](https://developers.openai.com/codex/cli/) and sign in with
   `codex login` if needed. The app also offers **Sign in** in Settings.
2. From the EvidenceForge checkout, run `uv sync --extra desktop --extra dev`.
3. Run `uv run --extra desktop eforge-desktop` from the checkout. The first launch uses
   the current directory as its EvidenceForge workspace. Use **Settings → Workspace**
   to change it.
4. Use **Settings → Install skills** if the skill picker is empty. Each authoring tab
   is a separate Codex thread, saved and resumed on the next app launch.

The app opens on **Scenarios**. This library reads authored YAML under the
workspace's `scenarios/` directory. **Import YAML…** adds a file elsewhere by
reference; **Refresh** picks up edits made outside the app. Select a scenario
to see its description, environment counts, latest app-launched run, saved
scorecard, and current output parent folder. **Continue authoring** opens a new Codex chat
with the scenario path prepared in the composer. **Validate** opens readable
CLI findings in Runs. **Generate…** takes you to Runs with that scenario already
selected, where you can choose the output folder before starting the job.
**Clone** creates a new scenario YAML in the workspace; **Hide** removes an
entry from the default list without deleting its file.
Scenario **Folders** are virtual and saved per workspace in local app data.
The scenario list is a folder tree. Use the add icon in its header to create a
folder, and a folder's menu or right-click menu to rename or delete it. Drag a
scenario onto a folder, or use its row menu (or right-click) and choose
**Move to folder**.
Creating a folder places the selected scenario in it; deleting a folder leaves
its files untouched. Search remains visible and matches every term
against the scenario name, description, and full authored YAML text, including
users and hostnames. Quoted phrases and `name:`, `description:`, or `yaml:`
scopes are supported. The **Filters** menu holds version, latest run status,
and hidden-item controls; its label shows the number of active filters.
For a completed app-launched run, **Evaluate latest run** starts `eforge eval`
and saves its JSON report in the local app data directory. Evaluations can run
in parallel and follow the configured quit policy. The latest saved score is
shown when the scenario is reopened.

**Industry packs** and **Org packs** list bundled packs and packs under the
workspace's `.eforge/packs/`. New packs can be authored through the corresponding
EvidenceForge skill. Existing packs can be imported from a version folder,
revised through the skill, opened as a file,
cloned into the local pack catalog, or hidden. The app does not yet
validate a cloned pack or offer a field-by-field pack editor.

In chat, **Enter** sends the message. **Shift+Enter** or **Option/Alt+Enter** inserts
a newline. Validation shows a compact result with findings and suggested fixes.
Close an authoring tab with its **×** icon; a running turn is interrupted. The
conversation stays in **Recent** and can be reopened from there.
In the Jobs view, **Save new runs in** selects the parent folder for future bundles;
the app remembers the last selected folder per workspace.

## Settings and quitting

Open Settings from the sidebar or with Cmd/Ctrl+Comma. Its category list separates
Workspace, Jobs, and Authoring & tools; each compact setting has a hover help icon.
Workspace holds the current workspace and its default output parent. Authoring &
tools shows the Codex account email when available, switches its action between
Sign in and Sign out, and holds skill installation plus optional
Codex/`eforge` executable paths. The sidebar shows the current workspace but
switching happens in Settings. New scenario chats start with the scenario skill;
the skill picker applies only to the next message and then returns to Automatic.
Codex can select a relevant installed skill for later requests, including validation.
Environment variables `EFORGE_DESKTOP_CODEX_BIN` and
`EFORGE_DESKTOP_EFORGE_BIN` override configured executable paths.

**Jobs → When I quit** offers three actions. **Continue background jobs** is the
default: queued generations keep starting and evaluations continue. You can instead
hold queued generations, hold evaluations for automatic restart on reopen, or stop
evaluations for manual restart. **Checkpoint and pause** freezes queued work and
requests a checkpoint from each active generation. By default the window closes
after the controller durably receives that request; an optional wait keeps it open
until the active generations have stopped, with **Cancel close** available.
Active evaluations can finish or stop for rerun when work resumes. Reopening a
paused workspace leaves its jobs paused until **Resume paused jobs** is selected
in Runs. Runs started while this quit mode is selected require checkpointing.
For a previously started run with checkpointing disabled, the close dialog offers
continue, stop while preserving files, or cancel close.

**Kill app-owned jobs** cancels queued work and stops active GUI-launched process
groups. It preserves incomplete bundles by default. Optional deletion requires
confirmation at close and applies only to incomplete bundles marked as created by
this app; completed and imported bundles are retained. Quit preferences are saved
locally and apply on the next quit. Pause request failures appear on the affected
run card after reopening.

The app needs a local `codex` executable on `PATH` or configured in Settings.
When launching outside the checkout, configure an installed `eforge` executable
in Settings. An installed development checkout uses its current Python
environment by default.

## Long running generation

**Generate** queues a separate CLI process for each run with the detached local
controller. Each run gets a unique
bundle under `<selected-output-folder>/<scenario-name>/` (by default,
`<workspace>/runs/<scenario-name>/`). App metadata, command logs,
and progress JSONL files live in the platform's application data directory.
On restart, the app loads durable per-job records, checks the saved PID and process start
time, and replays each progress file to restore all run bars. It polls once per second
while open. The CLI emits one flushed JSON object per engine progress event through
the new `--progress-jsonl` option; the existing Rich terminal display still works.
The app reconnects only to jobs it launched and recorded. It does not discover
unrelated `eforge` processes started in a terminal.

The hour bar counts warm-up and collection hours. A second bar appears when the
scenario emits storyline progress. Later phases show a descriptive status because
the engine does not currently report a measurable total for finalization and
ground-truth writing. **Suspend** asks the CLI to checkpoint at the end of the
current simulated hour; **Resume** uses a retained checkpoint.

Closing the app ends its Codex app-server connection and any active authoring
turns. Saved authoring threads can be reopened. The detached controller applies
the chosen quit policy to GUI-owned generation and evaluation jobs. **Suspend**
still allows a manual checkpoint request from an open Runs view.

## Prototype boundaries

The current app includes scenario and pack libraries, multiple authoring tabs,
skill selection, scenario validation, concurrent generation jobs, progress
bars, log/bundle opening, evaluation scorecards, and generation/evaluation restart
reconnection. Archive export, overlay editing, automatic generation/evaluation
pairing, detailed evaluation progress, and a distributable
macOS `.app` package remain to be built. App data is local to the user; Codex
authoring uses the user's configured Codex account and permissions.

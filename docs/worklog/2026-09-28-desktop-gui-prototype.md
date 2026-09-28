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

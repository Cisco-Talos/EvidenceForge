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

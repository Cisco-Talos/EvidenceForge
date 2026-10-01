# EvidenceForge Studio source-run guide

Studio is the local Tauri desktop app under review. It uses a React interface, a private Python
service on loopback, Codex app-server for authoring conversations, and the deterministic `eforge`
CLI for validation, generation, and evaluation. The Qt prototype remains available as
`eforge-desktop` until Studio's core-parity review is accepted.

## Run on macOS or Linux

1. Install Node.js, npm, Rust/Tauri's platform build prerequisites, `uv`, and the Codex CLI.
   Sign in to Codex before authoring or use Studio's **Settings → Authoring & tools → Sign in**.
2. In this checkout, run `uv sync --extra studio --extra dev`.
3. In `desktop-ui/`, run `npm ci` once to install the frontend dependencies.
4. From the checkout root, run `uv run eforge-studio`.

Studio starts or reconnects to one local service and opens its native window. The service binds
only to loopback on an ephemeral port and requires a private per-launch token. Closing the window
applies the configured job and authoring-turn quit policies; it does not stop a generation that
has been configured to continue in the background. Reopen Studio to reconnect to that work.
The source checkout, Python environment, Node.js, and Rust build tools are required for this
development release. A bundled standalone app is planned later.

On macOS, the helper runs as a transient user launchd service, independently of the window.
Its private `service-agent.plist` lives in Studio's state directory; the registration lasts for
the current login session and adds no login item. This keeps a closed Studio window from retaining
a macOS 27 background-process Dock entry. Linux uses a detached process. The helper currently
remains available after its tasks finish and exits on logout, reboot, or an explicit stop.

## Workspace and app data

The first launch creates a default workspace in the platform's Documents directory, named
`EvidenceForge`, or `~/EvidenceForge` on Linux when no distinct XDG Documents directory is
configured. The workspace holds authored `scenarios/`, generated `runs/`, and any project-local
packs or overlays. Open **Settings → Workspace** to choose another workspace. Studio never picks
its workspace from the shell's current directory.

Global settings and the SQLite library index live outside the workspace:

| Platform | Settings and library index | Logs and cache |
| --- | --- | --- |
| macOS | `~/Library/Application Support/EvidenceForge/settings.json` and `studio.sqlite` | `~/Library/Logs/EvidenceForge/` and `~/Library/Caches/EvidenceForge/` |
| Linux | `$XDG_CONFIG_HOME/evidenceforge/settings.json` and `$XDG_DATA_HOME/evidenceforge/studio.sqlite` | `$XDG_STATE_HOME/evidenceforge/` and `$XDG_CACHE_HOME/evidenceforge/` |
| Windows, later | `%LOCALAPPDATA%\EvidenceForge\settings.json` and `studio.sqlite` | `logs\` and `cache\` there |

Linux uses the standard XDG defaults under `~/.config`, `~/.local/share`, `~/.local/state`, and
`~/.cache` when those variables are unset. The SQLite file stores workspace-specific organization,
conversations, and jobs; scenario YAML, pack files, and bundle contents remain authoritative on
disk. Codex credentials stay in Codex's own storage. **Settings** has actions to open the active
workspace, app data folder, and logs.

## Current review scope

The scenario library groups scenarios into projects; pack libraries use virtual folders. Each
scenario workspace contains Overview, Conversations, Validation, Generation, and Scoring views.
Generation provides the output destination and run controls; Scoring lets you choose a completed
run to evaluate and view its saved scores. The job center shows all generation and evaluation rows
in stable order with independent
progress. The Bundles page groups Studio runs and read-only imported complete CLI bundles by
scenario. A bundle can be inspected with the file viewer or exported as a ZIP. Removing an
imported bundle from Studio removes its index entry and leaves its files in place. Studio can
clone scenarios and packs into the workspace; their existing conversations and runs stay linked
to the original. Native exports and file copies use Save dialogs.

This release is still in core-parity review. The planned workflow stages, including richer pack
editing, authoring diffs, preflight resource forecasts, generation setup, evaluation drill-down,
and delivery controls, follow after that review. Incomplete bundles from external CLI runs are
not yet importable; incomplete Studio-owned jobs already appear in the Bundles page.

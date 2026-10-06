# EvidenceForge Studio source-run guide

Studio is the local Tauri desktop app. It uses a React interface, a private Python
service on loopback, Codex app-server for authoring conversations, and the deterministic `eforge`
CLI for validation, generation, and evaluation. Its core-parity replacement was accepted on
October 2, 2026. `eforge-desktop` starts Studio; `eforge-studio` is an equivalent alias.
The Qt interface and dependency have been removed. Old prototype app-data files are untouched.

**Supported GUI platform: macOS only.** Linux and Windows implementations are exploratory;
GUI packaging, native acceptance and support on those platforms are deferred. The engine and CLI
retain their existing platform support. Current standalone testing targets Apple Silicon; see
[macOS package acceptance and limitations](studio-standalone-macos.md).

## Run on macOS

1. Install Node.js, npm, Rust/Tauri's platform build prerequisites, `uv`, and the Codex CLI.
   Sign in to Codex before authoring or use Studio's **Settings → Authoring & tools → Sign in**.
2. In this checkout, run `uv sync --extra studio --extra dev`.
3. In `desktop-ui/`, run `npm ci` once to install the frontend dependencies.
4. From the checkout root, run `uv run eforge-desktop`.

Studio starts or reconnects to one local service and opens its native window. The service binds
only to loopback on an ephemeral port and requires a private per-launch token. Closing the window
applies the configured job and authoring-turn quit policies; it does not stop a generation that
has been configured to continue in the background. Reopen Studio to reconnect to that work.
The source checkout, Python environment, Node.js, and Rust build tools are required for this
source-run development mode. A separate standalone Apple Silicon test package is available; see
[macOS package instructions](studio-standalone-macos.md).

On macOS, the helper runs as a transient user launchd service, independently of the window.
Its private `service-agent.plist` lives in Studio's state directory; the registration lasts for
the current login session and adds no login item. This keeps a closed Studio window from retaining
a macOS 27 background-process Dock entry. Linux uses a detached process. The helper currently
tracks each window separately. After the last window closes, it applies the configured quit
policies, waits for background jobs and authoring to finish, and exits after eight idle seconds.
Queued work configured to remain on hold does not prevent exit. Reopening during the grace period
reattaches; reopening after exit starts a helper. Window heartbeats also cover maintenance screens
and reconnects; an unannounced window exit expires after two minutes. Worker ownership uncertainty
prevents shutdown. Windows sharing the same data directory share settings, the selected workspace,
and one generation concurrency limit.

## Workspace and app data

The first launch creates a default workspace in the platform's Documents directory, named
`EvidenceForge`, or `~/EvidenceForge` on Linux when no distinct XDG Documents directory is
configured. The workspace holds authored `scenarios/`, generated `runs/`, and any project-local
packs or overlays. Open **Settings → Workspace** to choose another workspace. Studio never picks
its workspace from the shell's current directory.

Global settings and the SQLite library index live outside the workspace:

Each OS account has its own helper, settings, queue and generation limit. Multiple windows using
the same private data directory share that helper and limit. Studio checks the helper's actual
POSIX UID or Windows token SID, process start time, executable and launch command before sending
its connection token, and checks again before replacement. Window session IDs only track lifetime;
they never authorize access. HTTP and WebSocket access still require the private bearer token.

Private roots are checked before saved state or helper credentials are read. On macOS/Linux,
verified account-owned application defaults are tightened to directory mode `700`; a custom
`EFORGE_STUDIO_HOME` or nonstandard XDG location must already be private if it exists. A missing
custom directory is created privately. Foreign ownership, writable ancestry, links, reparse
points, aliased files and unverifiable helpers produce a refusal instead of another helper launch.
Credentials require file mode `600`. Windows uses native owner/SID and private DACL checks.
Studio does not take ownership of foreign directories or change permissions on system ancestors,
authored scenarios, packs or generated documents. An exited helper's stale discovery file is
recognized by process identity and can be replaced; malformed or newer discovery cannot be
silently discarded. The discovery format is transient and does not change saved-state versions.

The [account-isolation worklog](worklog/2026-10-06-studio-user-isolation.md) records simulated and
native testing separately. Real tests with separate OS accounts are explicitly deferred.

| Platform | Settings and library index | Logs and cache |
| --- | --- | --- |
| macOS | `~/Library/Application Support/EvidenceForge/settings.json` and `studio.sqlite` | `~/Library/Logs/EvidenceForge/` and `~/Library/Caches/EvidenceForge/` |
| Linux, exploratory | `$XDG_CONFIG_HOME/evidenceforge/settings.json` and `$XDG_DATA_HOME/evidenceforge/studio.sqlite` | `$XDG_STATE_HOME/evidenceforge/` and `$XDG_CACHE_HOME/evidenceforge/` |
| Windows, exploratory | `%LOCALAPPDATA%\EvidenceForge\settings.json` and `studio.sqlite` | `logs\` and `cache\` there |

Linux uses the standard XDG defaults under `~/.config`, `~/.local/share`, `~/.local/state`, and
`~/.cache` when those variables are unset. The SQLite file stores workspace-specific organization,
conversations, and jobs; scenario YAML, pack files, and bundle contents remain authoritative on
disk. Codex credentials stay in Codex's own storage. **Settings** has actions to open the active
workspace, app data folder, and logs.

Studio versions its database, saved JSON, settings and private/workspace conventions. Incompatible
upgrades keep their warning visible until you select **Continue with upgrade**, then create a
verified recovery backup before preparation. Completion uses the existing timed notification.
Failed or interrupted upgrades can be retried or restored before normal use resumes. See
[Studio state upgrades and recovery](studio-state-upgrades.md) for scope, recovery steps and tests.

## Current workflows

### Import scenarios and packs

Open **New scenario**, enter a valid scenario name and optional project, then use the arrow
beside **Create scenario** to select **Import scenario**. Choose an authored YAML file and
review its dependencies. Nothing is published until you confirm the review.

The import copies nested includes and referenced email corpora into
`scenarios/<name>/`, repairs their local paths, and offers nearby Markdown documents as
selectable supporting files. The root is saved as `scenario.yaml`; include fragments live in
`.sources/` so they do not appear as separate scenarios. Originals stay untouched.

Exact pack versions already in the active workspace are reused first. Add one or more
**Source workspaces for missing packs** to copy the required packs here. Organization path
dependencies are rebound to workspace packs; their industry lock digests stay intact. Review
shows any resulting organization digest change. An existing different pack with the same
publisher, type, name, and version is preserved. Source-workspace configuration overlays are
not imported; the scenario uses the destination workspace's `.eforge/config`.

**Validate prepared scenario** is optional. Its findings do not block scenario import. You may
also import with missing dependencies: the scenario workspace lists the exact requirements and
provides **Import packs** and a refresh icon. Generation remains unavailable until dependencies
resolve. Checks refresh after Studio imports and completed authoring turns, and during periodic
disk scans (about every ten seconds); use the icon for an immediate check after external edits.

In **Packs**, **Import packs** accepts an `.efpack` release or copies the packs from an explicit
source workspace. Additional workspaces can supply locked dependencies. The review lists exact
versions and publisher namespaces; conflicting releases cannot overwrite existing packs. Each
pack's menu has **Export pack…**, producing an `.efpack` with its locked closure and portable
references. Native mode uses the Save dialog; browser preview uses a download.

### Other current workflows

The scenario and pack libraries share projects. Scenario rows show their project, operation
status, and current bundle size or a clearly marked estimate. Search can find YAML content and
show matching excerpts; sorting and filters are remembered independently per workspace unless
you disable library recall in Settings. Each scenario workspace has collapsed Conversations, Environment, Validation and Runs sections
with summary information; conversations open a dedicated chat view.

Environment resolves the current files through `eforge resolve`, showing exact pack versions and
digests, declaring files, merge decisions, and the composed scenario model. **Choose packs**
prepares a request in a new conversation for you to review and send; it does not directly rewrite
the YAML. Workspace overlays can be inspected in the built-in viewer. Optional project-shared and
scenario-private patches are selected explicitly through portable configuration contexts, disabled
by default. CLI `--context` selects the same layers; ordinary CWD/`--project-root` behavior and
the workspace's `.eforge/config` remain unchanged when extra scopes are not selected.

Studio calculates a resource forecast through `eforge resources predict` after scenario,
include, pack, overlay, output-parent, or checkpoint-setting changes. Predictions run one at a
time in the background and are cached across restarts. Scenario rows show a clearly marked data
estimate before generation; a fresh completed run takes precedence with its measured bundle size.
The scenario workspace's **Runs → Forecast** action shows ranges, peak memory and disk,
capacity warnings, and a manual refresh icon. Refresh before a large run to recheck current
machine capacity. Predictions do not replace validation or reserve capacity for other jobs.

Generation uses the configured output parent and automatically constructs each run directory.
The **Runs** section lists generations and imported bundles newest first by original submission/import time,
with measured size, generation progress and the latest evaluation outcome on each row. Expand a
run to inspect/export/delete its bundle, operate its generation, and see its scores directly;
expand the score pillars for subscores or open the raw report. Only the latest valid saved
evaluation is retained for each run. A crashed, interrupted, or unreadable evaluation keeps the
previous score; a completed report replaces it even when the data fails required quality checks.
The job center shows generation and evaluation operations newest first with independent
progress. The Bundles
page groups Studio runs and read-only imported complete CLI bundles by
scenario, with the most recent groups and bundles first. Resuming a job does not change its order.
Conversations show the most recently updated first; Continue opens that conversation. Packs show
names A–Z, with the newest numeric version first within each name. A bundle can be inspected with
the file viewer or exported as a ZIP. Removing an
imported bundle from Studio removes its index entry and leaves its files in place. Studio can
clone scenarios and packs into the workspace; their existing conversations and runs stay linked
to the original. Native exports and file copies use Save dialogs.

Core replacement is accepted. Remaining workflow stages include guided pack/config editing,
authoring diffs, resource-aware scheduling, richer generation setup, evaluation drill-down,
and delivery presets. The current handoff distinguishes delivered foundations from remaining work. Incomplete bundles from external CLI runs are
not yet importable; incomplete Studio-owned jobs already appear in the Bundles page.

## Queued inputs and search excerpts

Each new generation captures a self-contained `RESOLVED_SCENARIO.yaml` in private app state
under `inputs/<job-id>/`. The worker reads this snapshot, including exact packs, includes,
overlays, and embedded corpora. Later authoring or pack edits affect new runs only. The saved
input digest is checked before launch. Checkpoint resume keeps the original run; Regenerate
creates a new run using the scenario's current inputs. The authored path remains the library
association, while source and dependency hashes identify the captured revision.

Search keeps case-insensitive substring matching, including YAML keys. **Settings → Workspace →
Search matches per item** controls the number of excerpts (five by default, up to fifty).
Excerpts identify the source file, line, and field, highlight matches, and count additional
matching fields. Names/descriptions rank first, YAML values next, then keys and comments;
word/prefix occurrences win within each group. This ranking is deterministic and uses no AI.

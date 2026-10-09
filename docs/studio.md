# EvidenceForge Studio guide

EvidenceForge Studio is a desktop workspace for authoring scenarios and packs, validating inputs,
generating logs, and reviewing evaluations. Existing CLI and native chat-skill workflows are still
supported. Studio is a supplement, not a replacement.

**The Studio app currently supports macOS only.** The standalone installer targets Apple Silicon;
Linux, Windows, and Intel macOS installers are not available. Engine and CLI platform support is
unchanged. The alpha field-test target is macOS 26; native local checks also ran on macOS 27.0.1.
Although the configured deployment floor is macOS 13, older systems have not been accepted.

The app bundles Python, the EvidenceForge engine, runtime dependencies, catalogs, templates,
and authoring skills. You do not need a source checkout, a separate Python installation, uv,
Node.js, or Rust to use it. Codex-assisted authoring requires you to install and sign in to Codex
yourself; Codex is not included with EvidenceForge. Validation, generation, evaluation, and bundle
viewing work without Codex.

## Install and open Studio

### macOS installation

1. Open [GitHub Releases](https://github.com/Cisco-Talos/EvidenceForge/releases) and select
   `v2.2.0a1`. Download `EvidenceForge-Studio-2.2.0a1-aarch64.dmg` and its `.dmg.sha256` file.
2. In the download folder, verify the image with:

   ```sh
   shasum -a 256 -c EvidenceForge-Studio-2.2.0a1-aarch64.dmg.sha256
   ```

3. Open the DMG and drag **EvidenceForge Studio.app** to **Applications**.
4. Eject the DMG and open Studio from Applications.
5. If macOS blocks the first launch, use **System Settings → Privacy & Security → Open Anyway**
   for this app, then confirm opening it. The current app has no Developer ID signature or
   notarization. See [Apple's instructions](https://support.apple.com/102445).

First launch expands the private bundled runtime; later launches reuse it. The app opens no
terminal and downloads no additional runtime. Application updates are manual; see
[updates and runtime retention](#updates-and-runtime-retention).

### Connect Codex for assisted authoring

Install and sign in to Codex before authoring, or use Studio's
**Settings → Authoring & tools → Sign in** after installing it. Studio uses Codex for its
scenario and pack conversations. Your Codex credentials remain in Codex's own storage.

Studio looks for `codex` on PATH, in common macOS CLI locations, and in Codex.app's bundled CLI.
Finder starts apps with a minimal PATH, so a terminal and Studio can discover different Codex
executables. Different Codex versions can expose different model catalogs for the same account.

To use the same executable in both, run `command -v codex` in your terminal and enter its absolute
path under **Settings → Authoring & tools → Codex executable**. Save, then click the Codex status
dot in the header and reconnect when authoring is idle.

## Start with a workspace

Studio creates a default workspace in your Documents directory named `EvidenceForge`.
Use **Settings → Workspace** to select another location. Workspace selection is independent of
where Studio was launched. Projects organize library entries within a workspace.

For a first run:

1. Import an existing scenario, or use **New scenario** to begin a Codex-assisted conversation.
2. Open its **Environment** section to inspect systems, users, configuration, and exact pack
   dependencies. Import any missing packs before generation.
3. Validate the scenario and review the resource forecast and available disk space.
4. Start generation from **Runs**, then monitor it there or in the job center.
5. Evaluate the completed run, inspect its scorecard and files, and export the bundle when ready.

Libraries support projects, search, filters, sorting, cloning, and remembered expanded/collapsed
views. Scenario conversations open a dedicated chat view. The **Properties…** menu exposes
scenario, pack, and bundle metadata, titles, notes, version history, and validation provenance.

## Import scenarios, packs, and bundles

### Scenarios and packs

In **New scenario**, use the arrow beside **Create scenario** to select **Import scenario**.
Choose an authored YAML file or portable `.efscenario` release and review the prepared import.
The YAML import copies nested includes and referenced email corpora, repairs local paths, and
offers supporting Markdown files for selection. The originals remain untouched.

Exact pack versions in the active workspace are reused first. **Source workspaces for missing
packs** can supply copies of required packs; they do not become live dependencies on those
workspaces. Review any changed organization digests or rebound paths before confirming.
Conflicting contents under an existing publisher/name/version cannot overwrite that release.

**Validate prepared scenario** is optional for import. You may import with missing dependencies,
but generation remains unavailable until they resolve. Use the scenario's **Import packs** action
or dependency refresh control after adding them. Source-workspace configuration overlays are not
implicitly copied; the destination workspace's selected configuration applies to YAML imports.

In **Packs**, **Import packs** accepts a portable `.efpack` or copies packs from a source workspace.
Review exact versions, publishers, and dependencies. Published portable releases retain their
frozen content and configuration rather than becoming editable workspace files.

### Generated bundles

The **Bundles** page can index complete bundles generated through the CLI or earlier desktop
versions. These imports are read-only: removing one from Studio's index leaves the external
files in place. Incomplete external bundles with checkpoints are not yet importable; Studio-owned
incomplete jobs already appear in Bundles.

## Author, revise, and share

Use conversations to create or revise scenario and pack content. **Packs → New** creates either
industry or organization content. **Assets** offers structured editing for supported categories;
Schema 3 draft edits retain the same draft identity. Use **Clone** for a separate identity.

**Environment** resolves the scenario's current files and shows exact pack versions, digests,
source declarations, merge decisions, and the composed environment. **Choose packs** prepares a
conversation request for you to review and send. Optional project-shared and scenario-private
configuration contexts are selected explicitly and are disabled by default. They also work
through the CLI; see [configuration contexts](reference/configuration-contexts.md).

### Drafts and local releases

New authored content uses Schema 3 drafts. Earlier scenario schemas 1/2 and pack schema 2 remain
readable. Use **Upgrade to latest schema** to prepare a separate upgraded draft, or **New draft**
to revise an existing release. Published originals are immutable.

**Publish locally…** validates a draft, lets you review its release version and warnings, and
freezes its sources, supporting assets, dependencies, and effective configuration. Publication
creates a release in the local workspace; it does not upload to GitHub or a remote registry.
Publish required pack dependencies before publishing a scenario that depends on them. If files
change after review, refresh the review before confirming.

**Export release…** creates an `.efscenario` or `.efpack` for import into another workspace.
These archives include authored content and its required closure, but exclude generated logs
and checkpoints. Use a bundle ZIP export when sharing generated evidence. The same operations
are available through the CLI and native chat skills; see the
[authored artifact lifecycle reference](../commands/eforge/references/artifact-lifecycle.md).

### Permanent deletion

Scenario and pack menus offer reviewed deletion. Inspect the selected source, files, and
relationships before confirming. Scenario deletion can optionally include its dedicated files,
verified owned runs, evaluations, and private job inputs. Shared packs are deleted separately.

**Delete version…** for a workspace pack lists its direct and indirect dependents. Accepting that
warning permits deletion and may leave consumers needing repair. Inspection errors or active
work can block removal; bundled engine packs are protected. A changed review must be refreshed.

Deletion is permanent and retains no recovery copy. Export or back up content first if you want
to retain it. Other versions, captured inputs, self-contained releases, and externally exported
files remain available unless explicitly included in the deletion review. Upgrade-recovery
backups do not provide an undo for deletion.

## Generate, evaluate, and inspect

Before a large run, open **Runs → Forecast** and refresh it to check current machine capacity.
Forecasts show estimated output size, peak memory/disk requirements, and warnings. They are
cached across restarts; they do not replace validation or reserve capacity for other jobs.

Queued generation captures self-contained resolved inputs, including exact packs, includes,
selected overlays, and embedded corpora. Later authoring affects new runs only. **Regenerate**
uses the current scenario; checkpoint resume continues the original captured run. Checkpoint
cadence defaults to 24 simulated hours and can be changed for new runs in Settings.

Runs and jobs are listed newest first by original submission time. Expand a run to monitor
progress, operate its generation, view files, evaluate it, or export its bundle as a ZIP.
Studio retains the latest valid completed evaluation report for each run. An interrupted or
unreadable evaluation preserves the previous score; a completed report replaces it even if
quality checks fail. Resource estimates and process completion are separate from quality scores.

Closing a window applies the configured job and authoring-turn policies. **Continue in
background** lets app-owned work proceed; reopening Studio reconnects to it. **Checkpoint and
pause** saves a recovery point for checkpoint-enabled generation, and evaluations follow their
configured finish/restart policy. Terminal CLI processes are not controlled by these policies.
Before copying data or replacing an app build, stop active authoring, hold queued work, and finish
or pause jobs rather than assuming that closing a window stops them.

## Workspace and saved Studio data

Authored YAML, packs, overlays, portable releases, and generated bundle contents remain files.
Studio's SQLite index records projects, library organization, conversation associations, and jobs.
Workspace content and private app data are both needed to preserve the full Studio experience.

| Data | Location or scope |
| --- | --- |
| Workspace | Your selected folder, including `scenarios/`, `runs/`, packs and hidden `.eforge/` content |
| Custom run destinations | Output folders selected outside the workspace; back these up separately |
| Settings and library/job database, macOS | `~/Library/Application Support/EvidenceForge/settings.json` and `studio.sqlite` |
| Private runtime and layout, macOS | `~/Library/Application Support/EvidenceForge/` |
| Captured generation inputs and helper state, macOS | `~/Library/Application Support/EvidenceForge/state/` |
| Upgrade-recovery packages, macOS | `~/Library/Application Support/EvidenceForge/studio-upgrades/` |
| Logs and disposable cache, macOS | `~/Library/Logs/EvidenceForge/` and `~/Library/Caches/EvidenceForge/` |

Settings has actions to open the workspace, app-data folder, and logs. A developer override such
as `EFORGE_STUDIO_HOME` changes the private locations; use the folders shown by the running app.
Each OS account has its own private data and helper. Multiple windows for one profile share its
settings, selected workspace, queue, and generation limit. Keep private data restricted to its
owning account. Codex owns conversation histories and authentication separately; Studio records
their associations and thread IDs.

## Backup and restore

### Make a routine backup

Use your normal filesystem backup process for both workspace content and private Studio data.
A portable authored release is useful for sharing, but does not contain conversations, Studio
settings, job records, generated logs, or checkpoints.

1. Finish or pause active generation, let evaluations finish or stop them, stop active authoring,
   and hold queued jobs. Also stop terminal processes that are writing the selected workspace.
2. Close all Studio windows and allow the idle helper to exit. Closing under **Continue in
   background** while work remains active does not make a consistent offline backup. Confirm
   the helper and its workers are no longer running before copying private state.
3. Copy the complete workspace, including hidden `.eforge/` directories and any checkpoint
   directories within run folders. Include custom output locations and referenced source files
   outside the workspace where applicable.
4. Copy the complete private app-data folder, preserving permissions. This includes settings,
   `studio.sqlite`, any accompanying SQLite WAL/SHM files, private input snapshots, layout markers,
   and `studio-upgrades/`. Keep related state together instead of copying only the database.
5. Record the app version and original workspace/output paths with the backup. Back up Codex's
   own data separately if you need its histories; do not include credentials in shared exports.

Logs can help diagnose a problem. Disposable caches and installed runtime copies are not
substitutes for workspace and Studio-state backups. There is no general filesystem-backup wizard
in Studio; these steps use your backup tool after application activity has stopped.

### Restore a routine backup

Stop Studio, its helper/workers, authoring, and other writers as for backup. Preserve the current
workspace and private profile separately before attempting a restore.

Restore matching workspace and private data from the same snapshot, using the same OS account
and original paths and preserving private permissions. Saved settings, jobs, and library entries
can contain absolute paths; moving a backup to another account or machine is not an automatic
migration. Use portable authored releases and bundle exports for transferring content between
workspaces instead of copying another account's private profile.

Restore complete directories rather than merging database/settings files from different dates.
Open the same or a compatible newer application and review any state-upgrade prompt. Inspect
restored runs and verify their checkpoints before resuming; a restored job record does not mean
its worker is still running. Do not open older applications against newer state they cannot read.
Keep the pre-restore copy until you have checked the workspace, library, and retained runs.

### Automatic upgrade backups and recovery

When a Studio state upgrade needs confirmation, **Continue with upgrade** creates and verifies
a recovery package before changing the affected state. Packages live in `studio-upgrades/`
beneath the private app-data directory. **View details** on the maintenance screen shows the
operation and recovery-package path.

These backups cover affected Studio database/settings/layout state. They preserve library,
project, conversation associations, and job metadata, but do not recursively copy scenarios,
packs, generated bundles, immutable run inputs, checkpoints, or Codex's own history. They are
upgrade-recovery packages, not full project backups. All unresolved packages and the newest three
completed packages are retained; already-current launches do not create another backup.

After a failed or interrupted upgrade, use **Retry upgrade** or, when offered,
**Restore previous UI state**. Restoration verifies the package and leaves Studio in maintenance
mode. You may retry preparation or close Studio and reopen a compatible previous app. Restoring
state does not install an older application. Active workers, authoring, or independently changed
files can prevent recovery until the reported conflict is resolved.

Built-in restoration is available before normal use resumes after a failed/interrupted upgrade.
It is not a rollback control after a successful upgrade and subsequent edits. For manual recovery
from an older package, retain its manifest/journal and follow the
[state upgrades and recovery reference](studio-state-upgrades.md#contracts-and-package-locations).

## Updates and runtime retention

Before replacing the app, finish or pause generations/evaluations, hold queued work, stop active
authoring, and close all windows. Replace the app in Applications and open the new build.
Workspaces and private data are stored outside the application bundle. Make a routine backup
before an update, and review any requested state upgrade before continuing.

Runtime cleanup runs after successful startup, after background work finishes, and hourly while
Studio is open. It keeps the current runtime and the previous successfully launched runtime for
30 days after replacement. Change **Settings → Workspace → Keep previous app runtime (days)**
to adjust the rollback period (0–3650 days); zero disables the extra retention period. Other
unused runtimes have a 24-hour grace period. Runtimes still used by a launcher, helper, worker,
or active Codex authoring are retained regardless of age.

If cleanup cannot prove that removing a runtime is safe, Studio keeps it and displays the folder
and reason. Cleanup retries automatically and does not stop processes. Authored/imported content,
conversations, bundles, and state-upgrade backups are outside runtime cleanup. Keeping an old
runtime does not undo a state migration or restore deleted content.

For launching or building from a checkout, see
[Studio development in CONTRIBUTING.md](../CONTRIBUTING.md#studio-development-on-macos).
Product release preparation and installer publication are documented separately in
[release instructions](releases.md).

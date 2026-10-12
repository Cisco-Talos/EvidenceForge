# EvidenceForge Studio guide

EvidenceForge Studio is a desktop workspace for authoring scenarios and packs, validating inputs,
generating logs, and reviewing evaluations. Existing CLI and native chat-skill workflows are still
supported. Studio is a supplement, not a replacement.

**The published Studio installer currently supports macOS only.** It targets Apple Silicon;
Linux ARM64 and x86_64 preview AppImage builders target Ubuntu 24.04. Linux x64 acceptance,
Windows, and Intel macOS installers have not been accepted. Engine and CLI platform support is
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

### Linux AppImage (local previews)

The `2.2.0a2` previews are built natively on Ubuntu 24.04 for ARM64 and x86_64. It includes a private Python
runtime, the engine/CLI, resources and skills; the source checkout and its virtual environment
are not needed to run the AppImage. It is not a published GitHub release.

Choose `aarch64` for an ARM64 desktop or `x86_64` for an x64 desktop; the images are not
interchangeable. The examples below use ARM64; substitute `x86_64` in every filename on x64.
Manual x64 acceptance is required before publication. Keep the AppImage and its adjacent checksum file in a
folder you intend to retain, then open a terminal in that folder:

```sh
chmod +x EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage
sha256sum -c EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage.sha256
./EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage
```

The builder baseline is glibc 2.39. Compatibility with other distributions is pending native
acceptance; building against newer libraries can exclude older hosts. Ordinary AppImage launch
uses FUSE 2 (`libfuse2t64` on Ubuntu 24.04). If FUSE is unavailable, use
`./EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage --appimage-extract-and-run`.
See [Tauri's AppImage limitations](https://v2.tauri.app/distribute/appimage/#limitations) and
[AppImage FUSE guidance](https://docs.appimage.org/user-guide/troubleshooting/fuse.html).

If ordinary launch reports that `libfuse.so.2` is missing, follow the
[AppImage launch prerequisites in CONTRIBUTING.md](../CONTRIBUTING.md#appimage-launch-prerequisites).

AppImage launch and runtime extraction do not require sudo. The image bundles its application
dependencies, including WebKitGTK's GStreamer plugins, but still depends on compatible host
system libraries and a working graphical desktop. Other distributions and desktop environments
have not yet completed acceptance.

First launch installs the checksum-verified bundled runtime under
`$XDG_DATA_HOME/evidenceforge/runtimes`, defaulting to `~/.local/share/evidenceforge/runtimes`.
The retained runtime permits Studio's service and jobs to outlive the temporary AppImage mount.
Codex remains a separate installation; its Linux sandbox prerequisites apply below.

An ordinary AppImage launch registers **EvidenceForge Studio** in your application menu with
the EvidenceForge logo. Its launcher is stored under
`$XDG_DATA_HOME/applications/evidenceforge-studio.desktop` (normally
`~/.local/share/applications/`), and its icon is retained under
`$XDG_DATA_HOME/evidenceforge/desktop/`. This lets GNOME identify the running window after the
temporary AppImage mount disappears. If you move the AppImage, launch it from its new location
once to refresh the managed launcher. A pre-existing custom launcher without the
`X-EvidenceForge-Managed=true` marker is preserved. Source and isolated acceptance launches
do not create this registration.

The AppImage also bundles GStreamer plugins required by WebKitGTK. If startup reports
`GStreamer element appsink not found` despite working system plugins, use a rebuilt preview:
the initial local `2.2.0a2` AppImage omitted those plugins. VM graphics warnings such as
`VMware: No 3D enabled` also occurred with the working source app; they alone do not establish
that Studio failed to launch.

### Connect Codex for assisted authoring

Codex installation and environment setup are maintained in
[CONTRIBUTING.md](../CONTRIBUTING.md#codex-authoring-and-linux-sandbox-tests).
After installation, use Studio's **Settings → Authoring & tools → Sign in**. Studio uses Codex for its
scenario and pack conversations. Your Codex credentials remain in Codex's own storage.

Studio looks for `codex` on PATH, in `~/.local/bin` on Linux, in common macOS CLI locations,
and in Codex.app's bundled CLI.
Finder starts apps with a minimal PATH, so a terminal and Studio can discover different Codex
executables. Different Codex versions can expose different model catalogs for the same account.

To use the same executable in both, run `command -v codex` in your terminal and enter its absolute
path under **Settings → Authoring & tools → Codex executable**. Save, then click the Codex status
dot in the header and reconnect when authoring is idle.

Studio installs missing bundled EvidenceForge Codex skills when a conversation needs them.
The installation location defaults to **Global** under **Settings → Authoring & tools**.
Existing skill directories and disabled skills are preserved; use **Install or update** to
explicitly update or repair an installation.

### Linux Codex sandbox setup and troubleshooting

Linux assisted authoring needs a working Codex command sandbox. Package installation,
Ubuntu AppArmor configuration, diagnostics and the sandbox smoke test are maintained in
[CONTRIBUTING.md](../CONTRIBUTING.md#codex-authoring-and-linux-sandbox-tests).

Studio surfaces relevant warnings from Codex's existing startup check. The notice identifies
a likely setup problem; it does not validate every sandbox operation or modify system settings.
After repairing the environment, reconnect through Studio's header status dot when authoring
is idle and retry the failed command.

## Start with a workspace

Studio creates a default workspace in your Documents directory named `EvidenceForge`.
On Linux it uses the Documents directory configured through XDG; if no distinct Documents
directory is configured, it uses `~/EvidenceForge`.
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

**New scenario** immediately creates a managed Schema 3 YAML scaffold and binds its conversation
to that source. Authoring and resumed conversations edit this exact draft in place. Keep its
`draft.json`, includes and companion files together; moving only the YAML can leave an orphaned
managed receipt.

An untouched scaffold shows **Ready to author** and **Continue authoring**. Generate and Publish
remain disabled, and automatic resource forecasts wait until its authored content changes.
This check uses the managed scaffold's content fingerprint, not its inline user/system counts:
pack-based scenarios can obtain their entities from dependencies. Existing unmodified scaffolds
from earlier Studio builds are recognized without rewriting their files. **Validate** remains
available when you want to see the fields still needed.

Publication failures stay inside the publication dialog. Schema failures identify the affected
fields; cancelling closes that review and clears its action error. Source inspection failures and
explicit validation findings remain available separately.

### Missing or moved scenario sources

Studio retains a missing source as **Source missing** instead of discarding its history.
Opening it offers **Locate source** and **Remove library entry…**. Locating requires the original
draft ID, or identical file bytes for a legacy scenario, and an authored YAML inside the current
workspace. Finish active chats and jobs before reconnecting or removing the entry.

Refresh automatically reconnects one missing Schema 3 draft to one live draft with the same UUID.
It keeps the original library ID, project assignment, conversations, and historical run paths.
Multiple candidates, conflicting project assignments, independent same-name drafts, and active
work require manual resolution. Files and captured generation inputs are never rewritten by
relinking. Draft editing remains distinct from cloning or creating an independent draft.

**Remove library entry…** archives the missing registration without deleting YAML, receipts,
generated bundles, saved conversations, or Codex threads. Runs remain in Job center. Conversations
stop appearing under the removed entry; restoring the same original source path and identity then
refreshing recovers its registration and conversation associations.

**Environment** resolves the scenario's current files and shows exact pack versions, digests,
source declarations, merge decisions, and the composed environment. **Choose packs** prepares a
conversation request for you to review and send. Optional project-shared and scenario-private
configuration contexts are selected explicitly and are disabled by default. They also work
through the CLI; see [configuration contexts](reference/configuration-contexts.md).

### Drafts and local releases

New authored content uses Schema 3 drafts. Earlier scenario schemas 1/2 and pack schema 2 remain
readable. Use **Upgrade to latest schema** to prepare a separate upgraded draft, or **New draft**
to revise an existing release. Published originals are immutable.

Studio checks publisher setup when it connects to the local helper. If no identity is
configured, a startup notice offers **Set up publisher** or **Later**. The same setup is
available under **Settings → Workspace**. Enter a publisher ID (lowercase letters,
numbers and hyphens) and a display name. **Global** is the default scope and is shared
with the CLI across your workspaces; **This workspace** saves an override for the
current workspace. Once configured, **Edit publisher** lets you revise the ID or
display name at either scope. Switching scope loads the identity saved there; a
workspace identity continues to override Global in that workspace. **Save changes**
updates the chosen scope, while **Cancel** discards your edits. Changes set the
default for new artifacts and drafts without a publisher. Drafts with an explicit
publisher and published releases keep their recorded identity. The identity is a
release namespace, not verified authorship. Creation, validation, generation and
evaluation remain available before setup, but publication requires it. This check
reads only the small local publisher configuration files on all platforms.

The publication dialog pre-fills the next unused patch version for the publisher and
artifact, starting at `1.0.0`. You can edit it before publishing; the label is not
reserved until publication succeeds.

**Publish locally…** validates a draft, lets you review its release version and warnings, and
freezes its sources, supporting assets, dependencies, and effective configuration. Publication
creates a release in the local workspace; it does not upload to GitHub or a remote registry.
The release replaces its completed draft in the library, keeping the same project assignment,
conversations and links to earlier runs. Use **New draft** on the release to revise it; publishing
that revision creates another immutable version. Independent drafts remain available. Libraries
show the latest published version by default; **Show previous versions** reveals older versions
without changing their files or dependency references.
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

If generation stops, expand the run in **Runs** or **Job center**. A recorded CLI error
appears in the run details; **View log** shows its captured output, and **Refresh log**
updates the preview. Long logs show their last 32 KiB with a copyable path to the full
file. A **Stopped** status means the process exited without a completed bundle; it
can result from an error or interruption. Studio cannot infer a cause when the process
left no error message. Validation checks the inputs; it cannot guarantee that the
installed runtime will finish generation. Preserve partial output and use **Resume**
when offered, or **Regenerate** for a new run after correcting the reported problem.

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
| Settings, Linux | `~/.config/evidenceforge/settings.json` |
| Library/job database and private runtimes, Linux | `~/.local/share/evidenceforge/studio.sqlite` and `~/.local/share/evidenceforge/runtimes/` |
| Captured generation inputs, helper state and logs, Linux | `~/.local/state/evidenceforge/`; helper log is `service.log` |
| Upgrade-recovery packages, Linux | `~/.local/share/evidenceforge/studio-upgrades/` |
| Disposable cache, Linux | `~/.cache/evidenceforge/` |

Linux paths above use the default XDG directories. `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
`XDG_STATE_HOME` and `XDG_CACHE_HOME` override their corresponding roots. For a complete Linux
profile backup, include its configuration, data and state directories as well as the workspace;
copying only the app-data folder omits separately stored settings and job inputs.

Settings has actions to open the workspace, app-data folder, and logs. A developer override such
as `EFORGE_STUDIO_HOME` changes the private locations; use the folders shown by the running app.
Each OS account has its own private data and helper. Multiple windows for one profile share its
settings, selected workspace, queue, and generation limit. Keep private data restricted to its
owning account. Codex owns conversation histories and authentication separately; Studio records
their associations and thread IDs.

### Closing Studio and helper lifetime

Quitting Studio explicitly notifies the helper that this application has detached. When the
last application exits, an idle helper exits promptly. Under **Continue in background**, it
finishes running jobs and eligible queued work, then exits automatically. Existing pause/stop
quit settings still control how jobs are handed off. Reopening Studio while work continues
reattaches to the helper and cancels its pending exit; the next quit starts that process again.
Native app process identity and renderer heartbeat leases provide fallback when an app crashes
or its exit notification cannot be delivered. Native identity includes process creation time
to prevent a reused PID from retaining ownership.

All desktop platforms use Studio's branded About window with the product version and build.
On Linux, choose **File → Quit EvidenceForge Studio** or press **Ctrl+Q** to quit; the window's
close button uses the same job handoff. On macOS, use the application menu or **Cmd+Q**.

The helper appears as a Python process, typically `python3.12` on Linux. Identify it by its
command line, which contains `-m evidenceforge.studio.bootstrap --serve`; a Python process name
alone does not distinguish it from unrelated tools. The native Studio executable is
`evidenceforge-studio`. Normally use Studio's Quit action and allow jobs to finish instead of
stopping the helper directly.

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
authoring, and close all windows. Allow the helper to exit before changing builds.

- On macOS, replace the app in Applications and open the new build.
- On Linux, verify the new AppImage's checksum, make it executable, and replace the old image
  or keep the new one in your chosen folder. Launch the new image directly once so its managed
  application-menu launcher points to that file. Existing dock/menu entries otherwise continue
  to open the old path.

Workspaces and private data are stored outside the application bundle or AppImage. Make a routine
backup before an update, and review any requested state upgrade before continuing.

Runtime cleanup runs after successful startup, after background work finishes, and hourly while
Studio is open. It keeps the current runtime and the previous successfully launched runtime for
30 days after replacement. Change **Settings → Workspace → Keep previous app runtime (days)**
to adjust the rollback period (0–3650 days); zero disables the extra retention period. Other
unused runtimes have a 24-hour grace period. Runtimes still used by a launcher, helper, worker,
or active Codex authoring are retained regardless of age.

If cleanup cannot prove that removing a runtime is safe, Studio keeps it and displays the folder
and reason, grouping folders that share the same problem. Cleanup retries at startup, after
background work finishes, hourly, and when retention settings are saved; it does not stop
processes. A persistent inspection or filesystem restriction must be resolved before retries
can succeed. Normal protected Linux session utilities do not require elevated access for cleanup;
unknown process ownership or insufficient evidence about a possible runtime user still prevents
removal. Authored/imported content,
conversations, bundles, and state-upgrade backups are outside runtime cleanup. Keeping an old
runtime does not undo a state migration or restore deleted content.

For launching or building from a checkout, see
[development setup and build/test instructions in CONTRIBUTING.md](../CONTRIBUTING.md#development-setup).
Product release preparation and installer publication are documented separately in
[release instructions](releases.md).

# Studio Linux build environment

## Decisions and authorization

October 9, 2026: prepare Linux Studio support with ARM64 first, then x64.
The first installer format is AppImage only. Ubuntu 24.04 LTS is the chosen
build and primary acceptance baseline. Homebrew is a future distribution channel;
no Linux implementation, version bump, release publication, or CI dispatch is
authorized by this dependency-installation task.

The user authorized installing the build dependencies on their Ubuntu VM and
requested a durable record of every setup change for future Linux build documentation.

## Initial VM state

- VMware guest, Ubuntu Desktop 24.04.5 LTS, `aarch64`, kernel `7.0.0-38-generic`.
- User reported a mostly stock desktop installation, followed by package updates
  and installation of the OpenSSH client/server. SSH and the display manager were active.
- Development account: `eforge`. Current private SSH endpoint: `192.168.191.129`.
  Credentials are not recorded in this file.
- Python 3.12.3, `file`, `wget`, `xz-utils`, CA certificates, `xdg-utils`, and
  `desktop-file-utils` were already present. Node/npm, uv, Rust, Git, curl, and
  the Tauri development dependencies were absent.

## Installed Ubuntu packages

Executed over SSH:

```bash
sudo apt-get update
sudo apt-get -o Dpkg::Use-Pty=0 install -y \
  build-essential curl git pkg-config ca-certificates file wget xz-utils \
  libwebkit2gtk-4.1-dev libxdo-dev libssl-dev \
  libayatana-appindicator3-dev librsvg2-dev libfuse2t64
```

APT installed 157 new packages, including transitive development dependencies;
it upgraded and removed none. Existing explicitly requested packages were marked
as manually installed. `libfuse2t64` provides compatibility for AppImage runtimes
that still require FUSE 2. No distribution upgrade was performed.

| Direct dependency | Installed package version |
| --- | --- |
| build-essential | 12.10ubuntu1 |
| curl | 8.5.0-2ubuntu10.15 |
| git | 1:2.43.0-1ubuntu7.3 |
| pkg-config | 1.8.1-2build1 |
| libwebkit2gtk-4.1-dev | 2.52.6-0ubuntu0.24.04.1 |
| libxdo-dev | 1:3.20160805.1-5build1 |
| libssl-dev | 3.0.13-0ubuntu3.16 |
| libayatana-appindicator3-dev | 0.5.93-1build3 |
| librsvg2-dev | 2.58.0+dfsg-1ubuntu0.1 |
| libfuse2t64 | 2.9.9-8.1build1 |

## AppImage build dependency follow-up

AppImage packaging follow-up on October 10 added `patchelf` **0.18.0-1.1build1** with
`sudo apt-get -o Dpkg::Use-Pty=0 install -y patchelf`. APT installed this one package and
upgraded/removed none. The GStreamer AppImage bundling plugin needs it to rewrite plugin/helper
library paths. `gstreamer1.0-plugins-base`, `gstreamer1.0-plugins-good` and `gstreamer1.0-tools`
were already installed; the host's `gst-inspect-1.0 appsink` worked before the fix. No system
GStreamer packages, graphics settings or security policies needed modification for this repair.
See `2026-10-09-studio-a2-local-installers.md` for the packaging defect and rebuilt artifact.

## User toolchains

Installed without sudo into the development account:

- Node.js **22.23.3**, npm **10.9.9**: selected the latest Node 22 release with
  a Linux ARM64 binary from `https://nodejs.org/dist/index.json`. Downloaded
  `https://nodejs.org/dist/v22.23.3/node-v22.23.3-linux-arm64.tar.xz` and verified
  its SHA256 against that release's official `SHASUMS256.txt` before extraction.
  SHA256: `a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f`.
  Installed under `~/.local/share/node/node-v22.23.3-linux-arm64` with `node`,
  `npm`, `npx`, and `corepack` symlinks in `~/.local/bin`.
- uv **0.12.24**: downloaded the versioned official installer at
  `https://astral.sh/uv/0.12.24/install.sh`, inspected it, then executed
  `UV_NO_MODIFY_PATH=1 sh ~/eforge-build-setup/uv-install.sh`.
  `uv` and `uvx` are installed in `~/.local/bin`. No pip installation was used.
- Rust/Cargo **1.99.0**, rustup **1.29.1**: downloaded and inspected
  `https://sh.rustup.rs`, then ran
  `sh ~/eforge-build-setup/rustup-install.sh -y --profile minimal --default-toolchain stable --no-modify-path`.
  Host target is `aarch64-unknown-linux-gnu`. Toolchains live under `~/.rustup`
  and executables under `~/.cargo/bin`. Stable resolved to Rust 1.99.0 in this session;
  an exact replay can select `--default-toolchain 1.99.0` instead of `stable`.

The stock Ubuntu `~/.profile` already adds `~/.local/bin` when it exists.
Added this block to `~/.profile` for Rust:

```sh
# Rust toolchain for EvidenceForge builds.
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
```

Verified tools in a fresh `bash -lc` login shell. For noninteractive SSH commands,
use a login shell or explicitly set
`PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"`.

## Verification and retained evidence

- Node/npm, uv, rustup, rustc, Cargo, Git, Python, and GCC version commands succeeded.
  GCC is 13.3.0; system Python remains 3.12.3.
- `pkg-config --modversion webkit2gtk-4.1 gtk+-3.0 openssl librsvg-2.0 ayatana-appindicator3-0.1`
  succeeded with versions 2.52.6, 3.24.41, 3.0.13, 2.58.0, and 0.5.90 respectively.
  The indicator pkg-config version differs from its Debian package version.
- VM directory `~/eforge-build-setup/` retains the before/after dpkg inventories,
  all 157 added packages and versions, APT installation output, downloaded official
  installers, the Node index/archive/checksum list, `install-tools.sh`, toolchain
  installation logs, and `verified-tool-versions.txt`.
- No EvidenceForge source checkout, project dependency sync, application build,
  test suite, or graphical acceptance was run during this setup task.

## Source checkout

In a subsequent October 9 request, the user authorized cloning EvidenceForge
under the VM's home directory and selecting `dev`:

```bash
git clone --branch dev https://github.com/Cisco-Talos/EvidenceForge.git "$HOME/EvidenceForge"
```

Checkout: `/home/eforge/EvidenceForge`. Branch `dev` tracks `origin/dev`; the
working tree was clean at `0aa8a2aee160334808159f6d34e11b2f1962ae67`
(`docs: record successful alpha installer smoke test`).

## First source build and storage pause

After the user's snapshot/reboot, synced locked project dependencies:

```bash
uv sync --frozen --extra studio --extra dev
npm --prefix desktop-ui ci
```

uv installed 57 packages into `.venv`; npm installed 312 packages. npm reported
one high-severity advisory for `source-map-js` (GHSA-68fv-2mgg-jv7q); retained
the audit JSON without changing the lockfile. CLI version output and
`scripts/sync_studio_version.py --check` succeeded at 2.2.0a1.

Started the following development build with limited parallelism and debug
symbols disabled because the root filesystem had only 6.4 GiB available:

```bash
CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 npm --prefix desktop-ui run tauri -- build --debug --no-bundle -- --locked
```

The frontend build succeeded. Rust compilation was interrupted when the user
asked to expand storage; no successful native build or packaged artifact is
claimed. No cargo, rustc, or node processes remained in the subsequent process
inspection. Sync, audit, and build logs are in `~/eforge-build-setup/`.

Read-only storage inspection found a 20 GiB `/dev/nvme0n1` disk with a 953 MiB
EFI partition (`p1`) followed by a 19.1 GiB ext4 root partition (`p2`). Root is
directly on the partition, without LVM. `/home` shares root; available space
after the partial build was 4.6 GiB. `growpart`, `parted`, and `resize2fs` are
already installed. No partition or filesystem changes have been made.

Recommended enlarging the existing virtual disk to approximately 100 GiB and
then growing partition 2 and its ext4 filesystem. Fusion snapshots prevent
disk enlargement, so preserving the snapshot via a powered-off VM backup or
choosing a second data disk needed resolution before proceeding.

## Expanded storage and successful source build

The user expanded the VMDK and Ubuntu partition/filesystem, then authorized
reconnecting and continuing. Verified `/dev/nvme0n1` is 100 GiB, partition 2
is 99.1 GiB, and `df -h /` initially reported a 98 GiB filesystem with 81 GiB
available. The Mac host had approximately 29 GiB available; guest capacity does
not represent host free space for the sparse VMDK.

Resumed the same build command to reuse prior compilation. It completed with
exit status 0, producing:

```text
/home/eforge/EvidenceForge/desktop-ui/src-tauri/target/debug/evidenceforge-studio
```

`file` identified an ARM aarch64 ELF executable; `ldd` reported no missing
libraries. The remote checkout remained clean on `dev`. The retained build log
is `~/eforge-build-setup/studio-linux-source-build-resumed.log`. This is a
development executable using the source checkout's `.venv`, without debug
symbols; it is not a standalone installer.

Started the normal detached Studio Python service through `connect_or_start()`.
An authenticated `/v1/health` request returned HTTP 200 with `status=ok` and
`ready=true`. Connection credentials were not printed or recorded. Linux XDG
paths resolved to `~/.config/evidenceforge`, `~/.local/share/evidenceforge`,
`~/.local/state/evidenceforge`, and `~/.cache/evidenceforge`.

At first launch inspection, only the GDM greeter and SSH session were active.
Asked the user to log into the Ubuntu desktop before launching the native GUI.

## First native GUI launch

After the user logged in, detected an `eforge` GNOME Wayland desktop session.
Read only the display/session variables from `systemctl --user show-environment`
and launched the built executable detached with `EFORGE_STUDIO_PYTHON` pointing
to `/home/eforge/EvidenceForge/.venv/bin/python`. This avoids rebuilding through
`eforge-desktop`/Tauri dev just to open the already-built source executable.
GUI output is retained in `~/eforge-build-setup/studio-linux-gui.log`.

Inspected the VM visually through VMware Fusion: the native window opened and
the Scenarios screen rendered with the sidebar, search, projects and empty
library. The process remained running and the remote source checkout remained
clean. No source patches or packaging changes were needed for this first launch.
Authenticated health, state-status and bootstrap endpoints all returned HTTP 200;
state was `ready`, the workspace was `/home/eforge/Documents/EvidenceForge`,
and bootstrap reported Codex disconnected because its CLI was not found.
This confirms startup/rendering only; import/export, native dialogs, generation,
restart/recovery and standalone packaging acceptance remain open.

At this first launch the VM had no `codex` executable on PATH, so authoring chat was not ready.
GUI diagnostics report Mesa/libEGL driver initialization failures and
`VMware: No 3D enabled`; the observed window still rendered. Record this VM
graphics condition when distinguishing VM behavior from application defects.

## Codex installation and relaunch

The user subsequently installed Codex and completed ChatGPT sign-in. Verified
`/home/eforge/.local/bin/codex`, `codex-cli 0.162.0`, and `codex login status`
reporting ChatGPT authentication. No account identity or credentials were recorded.
Relaunched the built Studio executable in the same GNOME Wayland session.
Visually confirmed the Scenarios screen and green status indicator; authenticated
bootstrap returned Codex health `connected` with detail `Codex is responding`.
No authoring turn was submitted as part of this connection check.

## Corporate certificate trust diagnosis

Settings then reported `Codex account/read: workspace routing discovery failed`
despite the local Codex transport being connected. Reproduced with Studio's
authenticated status endpoint and a separate `CodexClient` process. Local
`thread/loaded/list` worked while `account/read` failed using the documented
`refreshToken=false` request.

Unauthenticated curl to `https://chatgpt.com/` failed certificate validation
(TLS verification result 20). The presented chain was issued by Cisco Secure
Access, terminating at `Cisco Secure Access Root CA`. Exported the existing
public root certificate from the Mac Keychain, without accessing private keys:

```bash
security find-certificate -a -c 'Cisco Secure Access Root CA' -p
```

Root SHA256 fingerprint:
`5E:4B:0E:86:FC:DB:40:5D:15:5E:67:40:55:3B:56:DE:D9:C5:98:F9:BE:23:57:97:69:3A:B3:02:2E:26:82:82`.
Copied it to `~/eforge-build-setup/cisco-secure-access-root-ca.pem` on the VM.
Verified ChatGPT's chain using that CA (`Verify return code: 0`). Created
`~/eforge-build-setup/ca-bundle-with-cisco.pem` from Ubuntu's existing public CA
bundle plus the Cisco root. A temporary independent Codex process with
`CODEX_CA_CERTIFICATE` set to that bundle successfully returned a ChatGPT account
from `account/read`. No credentials or account identity were printed.

Automatic approval review rejected installing the root in Ubuntu's system trust
store because that persistent, system-wide trust change lacked explicit user
authorization. No global CA installation occurred. Asked the user to authorize
system installation or choose a Codex-process-only configuration. Studio's
existing helper still needs the chosen trust fix and a safe restart/reconnect.

The user explicitly authorized installing the Cisco CA into Ubuntu. Normalized
the Mac export to one PEM certificate with `openssl x509` (the export contained
multiple matching certificates), retained it as
`~/eforge-build-setup/cisco-secure-access-root-ca.crt`, then installed it:

```bash
sudo install -m 0644 ~/eforge-build-setup/cisco-secure-access-root-ca.crt /usr/local/share/ca-certificates/cisco-secure-access-root-ca.crt
sudo update-ca-certificates
```

Verified the normalized root has the recorded SHA256 fingerprint. Reconnected
through Studio's `/v1/codex/reconnect` with `interrupt_active=false`, preserving
the safeguard against interrupting active turns. Reconnect returned HTTP 200.
The normal `/v1/codex/status` request (without a custom CA environment override)
then returned `available=true`, `account_ready=true`, ChatGPT account type,
an account email, eight models, and no error. Account identity was not printed.
This confirms the routing-discovery failure was caused by missing corporate CA
trust, rather than Studio's account-read request parameters.
Rebuilt the embedded-frontend source executable with the previous build settings
and reopened Studio; the Scenarios screen rendered with a green status indicator.
The account status was verified through the normal service endpoint. Automated
VMware mouse input did not open Settings, so the account label was not visually
rechecked. The remote setup record also includes the certificate installation.

Separate diagnostic: Codex stderr also reports bubblewrap requires access to
create user namespaces. Ubuntu has `kernel.unprivileged_userns_clone=1` and
`kernel.apparmor_restrict_unprivileged_userns=1`. No namespace/security settings
were changed; actual sandbox acceptance remains open.

## Linux controls and automatic skill installation

The user reported unreadable Model, Reasoning and Skill selectors and a first-turn
failure because `eforge-scenario` was absent. The VMware screenshot showed pale
text over white native GTK controls. Implemented the fixes on
`codex/studio-linux-usability`, based on `0aa8a2ae`, in both the Mac checkout and
the VM checkout. Changes are uncommitted.

- Linux renderers mark the document before React mounts. Linux-only CSS removes
  native select appearance, retains Studio's existing dark backgrounds/text, and
  adds a chevron. The user asked to preserve accepted macOS styling; these CSS
  overrides do not apply on macOS.
- Turn preflight now installs missing bundled Codex skills using the saved scope,
  then requests `skills/list` with `forceReload=true` and continues with the
  discovered skill path. The shared installer has an optional `missing_only`
  mode; explicit CLI/Settings updates retain their existing behavior.
- Automatic installation preserves existing skill directories, customized files,
  and symbolic links. A discovered disabled skill remains disabled. Unrecognized
  third-party skills are not installed. Filesystem/discovery failures retain an
  actionable Settings repair message.
- Chat listens for `skills.installed` and refreshes its skill picker. Settings
  help explains the automatic installation and explicit update behavior.
- Verified `StudioSettings.skill_install_scope` already defaults to `global`, and
  the VM's saved setting is also `global`. No settings default change was needed.
  Automatic installation targets Codex's `~/.agents/skills` with that setting.

Rebuilt the native ARM64 source app with the existing command and debug settings;
TypeScript, Vite and Cargo completed successfully. Ruff passed on the two changed
Python files, and `git diff --check` passed. No automated test suites were added
or run. Reopened Studio and inspected Test 1: closed Model, Reasoning and Skill
controls are readable; expanded model/reasoning menus show readable entries
(native GTK popup menus retain their light background and dark text).
The user retried `Just say hi` in Test 1 and received `Hi!`, then submitted
`Let's make a new scenario`; Codex began the skill-assisted authoring response.
Confirmed all nine `eforge-*` skills appeared in `~/.agents/skills` through the
turn preflight. This exercises automatic installation and discovery through a
real user turn. The earlier unsent composer text was cleared by reopening;
the user resubmitted it. Actual tool-execution/sandbox acceptance remains separate
from the successful response and skill-installation checks.

Build evidence: `~/eforge-build-setup/studio-linux-usability-build.log` and
`~/eforge-build-setup/linux-usability.patch`. Source versions remain `2.2.0a1`.

## Ubuntu Codex sandbox prerequisite

The user's next authoring turn reached a command approval saying the sandbox
could not start the skill-read command. Kernel journal entries identify
`/usr/bin/bwrap` transitioning to `unprivileged_userns`, then being denied
`setpcap` and `net_admin` capabilities. This explains why direct model replies
worked while the first shell command requested an unsandboxed retry.

The VM already has Ubuntu `bubblewrap 0.9.0-1ubuntu0.3` and
`apparmor 4.0.1really4.0.1-0ubuntu0.24.04.8`. Neither an existing bwrap profile nor
`/usr/share/apparmor/extra-profiles/bwrap-userns-restrict` was found. Downloaded
the matching official `apparmor-profiles` package to `~/eforge-build-setup` and
read its extra profile without loading it. Its bwrap parent permits sandbox
setup capabilities; its child profile denies capabilities. Checked existing
AppArmor profile files for conflicting bwrap attachments; none were found.

[OpenAI's sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites)
document installing `apparmor-profiles apparmor-utils`, copying the extra
`bwrap-userns-restrict` profile into `/etc/apparmor.d`, and loading it with
`apparmor_parser -r` for Ubuntu 24.04. macOS instead uses its built-in Seatbelt
framework, which explains the different setup requirement.

Automatic approval review rejected the combined package-install/profile-load
command because this persistent AppArmor exception grants bubblewrap namespace,
capability and mount access, and diagnosing the sandbox did not explicitly
authorize that boundary change. The rejected command did not run. The user then
explicitly authorized installing and loading this exact Ubuntu profile.

Completed the documented setup:

```bash
sudo apt-get -o Dpkg::Use-Pty=0 install -y apparmor-profiles apparmor-utils
sudo install -m 0644 /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

APT added four packages: `apparmor-profiles`, `apparmor-utils`,
`python3-apparmor`, and `python3-libapparmor`, all version
`4.0.1really4.0.1-0ubuntu0.24.04.8`. The profile loaded without a reboot.
Both `kernel.apparmor_restrict_unprivileged_userns` and
`kernel.unprivileged_userns_clone` remain `1`.

Verified a fresh Codex sandbox command reads the installed skill successfully:

```bash
codex sandbox -- /usr/bin/head -n 3 /home/eforge/.agents/skills/eforge-scenario/SKILL.md
```

It returned the skill's YAML frontmatter with exit code 0. Codex 0.162.0 uses
`codex sandbox -- COMMAND` on this VM; the older `codex sandbox linux` spelling
tries to execute a command named `linux` and is not valid here. No sandbox mode
or pending Codex approval was changed. Asked the user to decline the already
pending unsandboxed fallback and request a new sandboxed skill-read attempt.
Studio's in-flight authoring retry remains a separate acceptance check.

## Documented sandbox setup and inexpensive Linux startup notice

The user requested `docs/studio.md` coverage by symptom as well as Ubuntu 24.04,
and a Linux-only startup advisory only if likely need could be detected quickly.
Added a Linux source-build section covering missing bubblewrap, sandbox-read
approval fallbacks, namespace/uid-map/loopback errors, AppArmor kernel denials,
the official Ubuntu profile commands, existing/conflicting policies, other
distributions, CLI syntax differences, verification and idle reconnect.

Chose to reuse Codex's existing sandbox startup warnings instead of starting a
second probe or scanning host policy files. Confirmed Codex 0.162.0's generated
app-server protocol has `warning` with a string `message` and optional `threadId`,
and `configWarning` with `summary` and optional `details`. Studio classifies
matching Linux warnings and stderr fallback lines into missing-bubblewrap or
restricted-user-namespace advisories. It stores only the notice code, never raw
stderr or arbitrary warning text in this new UI state.

The notice is Linux-only, deduplicated, included in bootstrap/event replay, and
reset when a fresh Codex process starts. A collapsed advisory shows manual
Ubuntu setup commands, distro-specific guidance and an external official help
link. Existing connection health remains separate. The notice is not a full
sandbox validation and depends on the installed Codex version reporting warnings.
No packages, profiles or system settings are changed automatically. macOS runs
no new preflight checks.

Measured classification on the ARM64 VM over 10,000 calls per sample: namespace
warning 0.84 microseconds/call, missing-bubblewrap warning 0.95 microseconds/call,
unrelated diagnostic 0.07 microseconds/call. These measure classification only;
an actual new notice also uses the existing asynchronous event persistence/UI
path. There is no new startup probe, subprocess, network request or blocking wait.

Generated TypeScript API declarations from the updated Python schema. Local
frontend compilation and Ruff checks passed, as did the ARM64 native source
build. No automated test suites were added or run. The VM had one active Codex
conversation, so its running GUI/helper were left alone; the new source and
executable are ready for its next idle relaunch. The repaired VM does not produce
a sandbox warning now, so visual acceptance of a positive notice remains open.
Build evidence: `~/eforge-build-setup/studio-linux-preflight-build.log`; protocol
inspection: `~/eforge-build-setup/codex-protocol/ServerNotification.json`.

## User workflow acceptance and publication version suggestion

The user reported successfully completing scenario creation, validation,
generation and evaluation in the Ubuntu VM. This is user-reported acceptance,
not an automated suite run. The current publication dialog showed a missing
publisher identity error; the fresh VM has no configured publisher namespace.
That requirement applies to all platforms, and publication remains pending.

The user clarified that the version should be a real default value rather
than a sparkle action or instructional placeholder. The dialog already used
the backend's deterministic next-unused patch suggestion when a publisher
namespace was available. Without an identity that suggestion was null, leaving
the clipped instruction-like placeholder visible. The input now uses `1.0.0`
as its initial fallback, and otherwise retains the exact namespace-aware
suggestion. Its value stays editable. Expanded the input to the dialog width,
replaced the placeholder with `X.Y.Z`, and added short explanatory help.
Refresh review preserves manually edited version text. No sparkle, model call,
dependency or new version calculation was added. The fallback does not reserve
a label; publication still checks identity and version availability.

Local frontend compilation and the Ubuntu ARM64 native source build passed
(`~/eforge-build-setup/studio-linux-publication-build.log`). No automated tests
were added or run. The helper reported zero active conversations and both jobs
completed before reopening Studio. The rebuilt GUI was reopened and the
publication dialog visibly showed an editable `1.0.0` value with separate help
text and no sparkle button. Left the dialog open without publishing.

## Publisher setup in startup readiness

The user requested default publisher setup as part of preflight. Studio now reads
project-over-user publisher configuration in the existing bootstrap snapshot on
all platforms. This reads only the small local identity files; no subprocess,
model or network lookup is added. An unreadable configuration becomes actionable
setup state rather than preventing the application from loading.

When identity is missing, a nonblocking startup notice offers setup or Later.
Settings → Workspace retains the same setup form and shows the effective identity
and scope once configured. The user explicitly supplies ID and display name;
Global (`user`) is the initial scope. Workspace (`project`) remains optional.
No identity is inferred from the OS username or Codex account, and no existing
identity is silently replaced. The new authenticated initial-setup endpoint uses
the existing file-based `set_publisher(..., force=False)` service under Studio's
asset lock, and publishes a state event. Publisher configuration remains owned by
the same files used by the CLI; no database migration or duplicate setting was
introduced. Publication errors now point to Settings instead of requiring a
terminal command. Other workflow stages remain available without setup.

Local frontend compilation, generated API schema checking and Ruff check/format
passed. The updated Ubuntu ARM64 source build also passed
(`~/eforge-build-setup/studio-linux-publisher-setup-build.log`). No automated
tests were added or run. The prior GUI/helper had been closed before deployment.
The fresh GUI showed the missing-publisher startup notice. Expanded setup and
visually confirmed readable ID/display-name fields, Global selected, and Save
disabled for empty values. Left the form ready for the user to choose their
identity; saving a real identity has not been exercised in this acceptance pass.

## Editable publisher settings

The user found that Settings displayed a configured publisher without an edit
action. Added Edit publisher, prefilled scoped ID/display name, Save changes,
Cancel and Refresh edit after a stale/error result. The selected scope defaults
to the effective identity's current scope. Changing scope reads the identity at
that exact scope (or offers the effective identity as a starting point if none
exists). Global edits clearly report when a workspace override still takes
precedence. The startup notice remains initial setup only.

Added a public single-scope reader to the existing publisher file service.
Studio's save request distinguishes initial setup from an explicit edit and
checks the reviewed target identity plus the originating workspace before using
`set_publisher(..., force=True)` for the selected scope. Initial setup continues
to preserve existing identities. A stale identity or changed workspace requires
review again. No existing artifact files, release identities or published
archives are rewritten. Changes affect defaults for new artifacts and drafts
without an explicit publisher. No version bump or publication is involved.

Frontend compilation, generated schema checking, Ruff check/format and the
Ubuntu ARM64 native source build passed
(`~/eforge-build-setup/studio-linux-publisher-edit-build.log`). No automated
tests were added or run. The VM helper reported zero active conversations and
both jobs completed before reopening. It still reported no configured identity,
so no actual publisher value was invented or changed for visual acceptance.

### Missing-publisher notice acceptance

The user requested removing the VM publisher identity to see the startup check.
The active workspace was `/home/eforge/Documents/EvidenceForge`; neither
`/home/eforge/.eforge/publisher.yaml` nor that workspace's
`.eforge/publisher.yaml` existed, and the effective identity was already absent.
No configuration was removed. After unlocking the guest, the native Studio
scenario library visibly showed the Publisher identity notice with **Set up
publisher** and **Later**. Left that notice visible for the user.

The user also requested resetting the Mac identity for their own acceptance.
The Mac workspace was `/Users/dabianco/Documents/EvidenceForge`, with only a
Global identity configured. Moved `/Users/dabianco/.eforge/publisher.yaml` to
`/Users/dabianco/.eforge/publisher.yaml.backup-20261009T194835Z-cccb9c56`.
Confirmed the effective identity is now absent. The backup preserves the exact
configuration for restoration; the user will verify the Mac startup notice.

## Repeatable source synchronization over SSH

Replaced manual tar/SCP source transfers with `scripts/sync_linux_vm.py`.
Run from the Mac:

```sh
uv run --no-sync python scripts/sync_linux_vm.py --dry-run \
  eforge@192.168.191.129 /home/eforge/EvidenceForge
uv run --no-sync python scripts/sync_linux_vm.py \
  eforge@192.168.191.129 /home/eforge/EvidenceForge
```

Both machines already have rsync installed. SSH uses the existing VM account;
the script contains no password or machine-specific defaults. It copies tracked
files and unignored new files from the Mac checkout, using checksums to detect
content differences. Git metadata, virtual environments, Node dependencies,
build outputs, caches, agent installations, dotenv files and AppleDouble files
are excluded. Source executable bits are synchronized while Linux permissions
and timestamps are retained for unchanged files.

Overwritten files are backed up outside the checkout in
`/home/eforge/EvidenceForge.sync-backups/<unique-run>/`, with their relative
paths preserved. Remote-only files are retained; locally deleted source files
need a separate reviewed cleanup. Git commits, branch changes, dependency
installation, builds and Studio restart remain separate operations. Keep both
checkouts on the same source baseline before syncing. The Mac is the source of
edits; remote source edits must be brought back before subsequent syncs.

Initial dry-run and actual sync succeeded. Of 1,758 source files (about 53 MB),
only the new sync script and updated worklog differed; 35,152 bytes of file
content were selected for transfer. The replaced worklog was retained under
`/home/eforge/EvidenceForge.sync-backups/20261009T195655Z-514ad9ae/`.
Ruff check and formatting passed for the script. No application tests or new
build were run for this workflow change. AppleDouble files from earlier tar
transfers remain on the VM and are excluded from future transfers.

## Duplicate scenario investigation — source moved after indexing

The user asked how the two Test 1 rows arose before any symptom cleanup.
Read-only VM SQLite, filesystem and conversation-event inspection established
the full sequence:

1. Studio conversation `32b9a8974272480296b4dd571b81b868` was created with a
   target under `scenarios/studio-<conversation-id>/scenario.yaml` (event 8).
2. During authoring, the agent invoked `eforge scenario new-draft Test-1`
   (completed command event 379). This created the managed Schema 3 scaffold at
   `.eforge/artifacts/drafts/scenario/%54est-1/44aecd66-79d2-472d-b6c3-2783efaf866a/source/scenario.yaml`.
   Event 461 recorded reading that actual YAML. Studio indexed it as item
   `9c03626f69f44187837a4b627070772b`, with zero users/systems/events.
3. The authoring agent then ran `mv` to Studio's preassigned conversation path
   (completed command event 548, exit 0), moving only `scenario.yaml`.
4. Studio bound the conversation to the new path/item at event 550. The agent
   wrote the full Cedar Grove Clinics scenario there, retaining the same
   `draft_id`. The current authored item is `c2f8aa85c46249aeafbcff583d1a0614`,
   with four users, six systems and eight events.
5. The original managed directory now contains only `draft.json`. Its YAML is
   absent, but the original indexed item remains in SQLite and bootstrap.

Root causes: Studio's draft conversation assigns a legacy target path while the
Schema 3 authoring workflow uses the CLI's canonical managed scaffold location.
The agent reconciled those two targets through an ordinary file move, leaving
the managed receipt behind. Catalog upsert identity is keyed by file path;
scan adds/updates discovered items but does not reconcile ordinary missing or
moved sources (explicitly retired sources are handled). Snapshot lists stored
items, so the old path persists as a second row with the same name/display name.

`catalog_source` rejects missing YAML before artifact operations, including the
scenario deletion-review route; deletion itself also requires an existing source
file. The stale item therefore lacks a supported remove-registration/relink
path. The library's `Not authored yet` fallback is based on an empty version,
not a source-presence check, further obscuring the state of Schema 3 drafts.

This is shared Studio/CLI workflow and catalog reconciliation behavior, not a
Linux-specific filesystem issue. Neither scenario, receipt nor VM database was
modified during this investigation. Prevention should align draft creation and
authoring around one canonical source; recovery needs explicit moved/missing
source handling that preserves associated conversations and runs rather than
blindly deleting catalog/history. No fix or test run was performed.

## Next work

Use this record to prepare the Linux developer setup section after the first
successful build. Extend native GUI acceptance beyond initial startup/rendering.
Linux standalone runtime/bootstrap and AppImage
packaging are still implementation work. Actual GUI acceptance should use the
VM desktop; SSH's `tty` session is not a graphical session.

References: [Tauri Linux prerequisites](https://v2.tauri.app/start/prerequisites/),
[uv installation](https://docs.astral.sh/uv/getting-started/installation/),
[Rust installation](https://rust-lang.org/tools/install/),
[AppImage FUSE guidance](https://docs.appimage.org/user-guide/troubleshooting/fuse.html).

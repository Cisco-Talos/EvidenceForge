# Studio 2.2.0a2 local installers

## Authorization and version

User approved bumping to `2.2.0a2`, syncing/building the Linux version and AppImage, and building
the new macOS DMG. The user explicitly said this is not a release yet. No tag, push, GitHub
publication or release CI dispatch is authorized by this build request.

Updated authoritative Python versions, regenerated `uv.lock` with `uv sync`, and synchronized
all npm/Tauri/Cargo versions to `2.2.0-alpha.2`. Added the unpublished changelog entry. The only
lockfile changes are the product versions; dependency pins remain unchanged. An initial offline
uv attempt lacked registry metadata; the ordinary online sync completed successfully.

## Packaging implementation

- Shared Unix standalone bootstrap now supports Linux: checksum-verified archive installation,
  atomic retained runtime caches and launch leases use the existing macOS contracts. Linux uses
  the same XDG data directory as its Python helper; macOS-only `/tmp` aliases remain macOS-only.
  Linux desktop subprocesses include the conventional `~/.local/bin` location for npm Codex/node.
- `scripts/package_studio_linux.py` uses shared payload assembly, a separate Linux interpreter
  lock, native Tauri AppImage bundling, architecture checks and product-versioned local filenames
  with SHA256 files. It builds on the native architecture; no cross-architecture build is claimed.
- Interpreter lock uses the same CPython 3.12.12 / python-build-standalone 20251028 release as
  macOS. Official GitHub release asset digests pin Linux GNU aarch64 and baseline x86_64 archives.
  Linux runtime assembly uses the project's frozen, hashed dependency export and product wheel.
- Publication automation and the released `2.2.0a1` assets remain unchanged. Linux distro and
  clean-machine GUI acceptance remain explicit; Ubuntu 24.04/glibc 2.39 is this builder baseline.

## Build environment and commands

Existing Ubuntu Desktop 24.04.5 ARM64 VM, `/home/eforge/EvidenceForge`, 5.8 GiB RAM, 3 GiB swap.
Guest disk had 75 GiB available at start. Mac host had approximately 22 GiB available. Reused
installed dependencies and compilation caches from the setup worklog. No system packages or
security policies were changed by the initial build commands.

Source synchronization retained replacement backups under
`/home/eforge/EvidenceForge.sync-backups/20261009T222935Z-719bc845/` and
`20261009T223043Z-2cb7748a/`, with final bootstrap/runtime files backed up separately.
Git metadata and private workspace/state were not synchronized. No VM GUI/helper was active
before the source build; the user's scenario files and SQLite state were not edited for building.

Maintained source and standalone installer build commands are in
[CONTRIBUTING.md](../../CONTRIBUTING.md#development-setup). This record retains the
native build environment, outputs and acceptance results rather than a second build recipe.

## Evidence and remaining work

Linux source executable, Linux standalone AppImage and macOS standalone app/DMG all built
successfully at version `2.2.0a2`. Copied the AppImage and checksum to the Mac's `dist/linux/`.

Original October 9 builds (the Linux image is superseded by the correction below):

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| `dist/linux/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage` | 124877320 | `8ddb070f3ee8e0bce3aad7ace59552e2a036a73325fee5796b4877ae1df0f77d` |
| `dist/macos/EvidenceForge-Studio-2.2.0a2-aarch64-test.dmg` | 37683551 | `26afe7707e51c99026b6941f5c581821f894efc3ec8f081928eadf8ccae7ad75` |

Both adjacent checksum files pass `shasum -a 256 -c`, including the copied AppImage. Extracted
the actual AppImage in a disposable VM directory without launching Studio. Its manifest and
packaged Python declaration both report `2.2.0a2`; its runtime archive matches the manifest
digest `ec208c1c7c012870f40ead58a41c1dc8a44ae7b40fade0b32d65ecfed9595f55`, and contains the
final Linux desktop PATH handling. The macOS app metadata reports `2.2.0-alpha.2`, its Python
declaration/manifest report `2.2.0a2`, and the runtime archive matches manifest digest
`b035bb042c2bcd70b3aef3bb5d91428fc8deec7c0c2a70d78b63c42d6d2a869a`.

The native source executable is
`/home/eforge/EvidenceForge/desktop-ui/src-tauri/target/debug/evidenceforge-studio`.
Both installers target ARM64: Apple Silicon on macOS and this Ubuntu ARM64 VM on Linux.
No x86_64 installer was built. Linux desktop launch and distro portability acceptance remain
pending; the AppImage's minimum builder baseline is Ubuntu 24.04/glibc 2.39. No release was
published, and no release tags or commits were created by this local build request.

Version synchronization, repository Ruff lint/format checks and `git diff --check` pass.
Build logs are retained under `/home/eforge/eforge-build-setup/studio-2.2.0a2-*.log`.
No automated test suites were added or run for this build request; earlier source usability
test evidence remains in the preceding focused worklogs. Build checks are not release acceptance.

## October 10: GStreamer startup packaging correction

The user's first AppImage launch reported `GStreamer element appsink not found` after the same
VMware/EGL warnings observed with the working source executable. Read-only host inspection
confirmed `gstreamer1.0-plugins-base` and `gstreamer1.0-tools` were installed and host
`gst-inspect-1.0 appsink` succeeded. The original AppImage contained `libgstapp-1.0.so.0` but
omitted the dynamically loaded `gstreamer-1.0/libgstapp.so` plugin and scanner. ELF dependency
collection had not bundled the plugins WebKitGTK needs at startup.

Enabled Tauri's `bundle.linux.appimage.bundleMediaFramework` in the Linux-only generated
standalone configuration; macOS packaging configuration remains unchanged. The first rebuild
failed in the GStreamer plugin because `patchelf` was absent. A verbose bundle-only retry
identified that exact failure. Installed Ubuntu `patchelf` 0.18.0-1.1build1 (one added package,
no upgrades/removals) and added an early actionable build-tool check to the Linux script.
No GStreamer system packages, graphics settings or security policies were changed.

The corrected AppImage built successfully and replaces the unpublished local installer at the
same VM and Mac paths. Old installers/checksums are retained in
`/home/eforge/eforge-build-setup/a2-appimage-before-gstreamer/` on the VM and
`/private/tmp/eforge-a2-appimage-before-gstreamer/` on the Mac. Source replacement backups are
under `EvidenceForge.sync-backups/a2-gstreamer*`. This is a local preview replacement, not a
published asset/tag replacement. Product version remains 2.2.0a2; the DMG was not changed.

- Corrected AppImage: **135047688 bytes (128.79 MiB)**.
- SHA256: `52ff0f667496d9c4dd481a1eca6323cbf3425d2f7a7784bafe204ad278b7a773`.
- Extracted the actual AppImage in a disposable directory. The bundled plugin and scanner both
  exist; `gst-inspect-1.0 appsink` with the extracted library/plugin/scanner paths and a fresh
  temporary registry exits 0 and reports the extracted `usr/lib/gstreamer-1.0/libgstapp.so`.
- Packaged manifest still reports 2.2.0a2; its runtime archive matches digest
  `92dd40410cf30c07ed1563f7dedf7ed0e6c57e64176dba8019769240d9798235`.
- The copied Mac installer passes its adjacent SHA256 file. Packaging-script Ruff lint/format,
  version synchronization and `git diff --check` pass. No automated tests were added or run;
  a successful plugin diagnostic does not establish full AppImage GUI acceptance.
- Logs: `studio-2.2.0a2-appimage-gstreamer-build.log`,
  `studio-2.2.0a2-gstreamer-bundle-verbose.log`,
  `studio-2.2.0a2-appimage-gstreamer-final.log` in the VM build-setup directory.

Documented required builder packages, the startup symptom and corrected local preview in the
Studio/release guides, setup record and unpublished changelog.

## October 10: generation guard failure from transfer metadata

The user reported generation stopping in the AppImage with declared surface digest `bd9e...`
and actual digest `992bb31bede4289ff79bba673e9e37776b3ab2100085f1f9d78709b8148d113c`.
The Mac source guard passed; the VM source guard reproduced the user's exact error. Compared
per-file behavior hashes: all 435 real files were byte-identical, with no missing files. The VM
had one extra behavior file, `composition/._publisher.py`. `file` and its AppleDouble magic
confirmed this was macOS transfer metadata left by earlier tar/SCP copying, not Python code.
The wheel had packaged this file plus three Studio AppleDouble companions.

Retained the four confirmed metadata files outside the source checkout under
`/home/eforge/EvidenceForge.sync-backups/a2-appledouble-source/`. The VM source guard then
passed unchanged at revision 161, digest
`bd9e13343c8fb72dfdbbb03a284357a3a0664d362c1b0503222bc76b2b6584d4`.
No generation algorithm or scenario changed, and no behavior revision bump was appropriate.
The rsync workflow already excludes `._*`; its deliberate retention of remote-only files had
preserved the earlier transfer metadata until this explicit reviewed cleanup.

Packaging safeguards now:

- Hatch wheel exclusions omit `**/._*` and `**/.DS_Store`.
- Shared payload assembly checks the source behavior declaration before building the wheel.
- Wheel inspection rejects any remaining macOS transfer metadata, including forced resources.
- Every installed runtime's generation surface must match its own manifest before archiving.
  This scans the target tree without executing foreign-architecture Python, so it also applies
  to macOS multi-architecture assembly.
- Linux local installer replacement uses a temporary file and atomic rename to preserve an
  existing mounted/running preview inode until that user session closes.

Rebuilt the local AppImage successfully. Prior images/checksums are retained under
`~/eforge-build-setup/a2-appimage-before-behavior-cleanup/` on the VM and
`/private/tmp/eforge-a2-appimage-before-behavior-cleanup/` on the Mac.

- Corrected AppImage: **135047688 bytes**; SHA256
  `b728c8c0eb38892acf95532aec24f16ca1afe9c08ce7ce89f7a0ff74604631ca`.
- Runtime archive SHA256: `c92249527ca01258ae48a714a8e4c2a4de8fe26cb2c139cbecebe8e141846ac6`.
- Extracted the actual AppImage and its runtime into disposable directories. Its own Python
  with `-I -B`, a clean PATH and no source environment passes
  `validate_generation_behavior_surface()` at revision 161 / `bd9e...`, and its CLI reports
  EvidenceForge 2.2.0a2. Bundled appsink/scanner diagnostic also still passes.
- The existing macOS standalone app's archived runtime passes the same guard using its own
  Python. Its DMG therefore does not need a rebuild for this Linux transfer contamination.
- Source guard, packaging-script Ruff lint/format, version synchronization and whitespace
  checks pass. Copied the corrected AppImage/checksum back to the Mac and verified the checksum.
- No user scenario, generated bundle, checkpoint, Studio database or running session was
  modified, and no generation retry or automated test suite was run. The user should close
  and reopen the AppImage to select the clean retained runtime before retrying generation.

Build log: `~/eforge-build-setup/studio-2.2.0a2-appimage-behavior-final.log`.
Version remains the unpublished 2.2.0a2 preview. No tag, push, commit or release publication.

## October 10: persistent Linux desktop branding

The AppImage already carried the EvidenceForge logo and a correctly named desktop entry,
but GNOME could not find them outside its temporary mount. Added Linux-only initialization
in `linux_desktop.rs`: set GLib's human application name before window creation, and on a
normal AppImage launch automatically retain the embedded logo and a managed per-user
`evidenceforge-studio.desktop` entry under the user's XDG data directory. The entry names
the application **EvidenceForge Studio** and matches the existing window identity.
This integration ships inside the AppImage; it is not a VM-specific installation step.
Source launches and isolated acceptance workspaces do not register launchers. Custom,
unmanaged entries are preserved, and moving/relaunching the image updates its managed path.
Registration failures report a warning without blocking startup.

Applied the same compiled Rust registration code directly on the VM while the user's
generation was active, avoiding a restart. A native screenshot subsequently showed the
EvidenceForge logo replacing the gear in the running application's dock. Desktop entry
validation succeeded, and Gio resolved the friendly name, persistent logo and correct
AppImage command. The user subsequently closed Studio; no app or generation was stopped
by this work.

Rebuilt the Linux source executable and AppImage successfully. The actual extracted image
passes its own bundled Python generation guard at revision 161 / `bd9e...`, reports product
version 2.2.0a2, and still loads the bundled appsink plugin using a fresh temporary registry.

- AppImage: **135318024 bytes (129.05 MiB)**; SHA256
  `b96277ea8a4b8ab47f2d3403645255f5188ec47d840521caf1b61c5804a7687b`.
- Runtime archive SHA256:
  `3a31d5eb5af191aa1d5147a8b359baced61e4c6316e2db69fc7e9a0f9524f174`.
- Logs: `studio-2.2.0a2-appimage-desktop.log` and
  `studio-2.2.0a2-source-desktop.log` in the VM's build-setup directory.
- Prior image/checksum retained under `~/eforge-build-setup/a2-appimage-before-desktop/`
  on the VM and `/private/tmp/eforge-a2-appimage-before-desktop/` on the Mac.
- Source backups: `~/EvidenceForge.sync-backups/a2-linux-desktop/`.
- Native compilation and Rust formatting passed. No automated tests were added or run.
  Clean-machine/distro acceptance remains pending. macOS code is unaffected by this
  Linux-only module, and its existing local DMG is unchanged.

Documented automatic registration in the Studio guide and unpublished changelog.
The rebuilt installer retains the same local preview path and version; no publication,
tag, push or commit was performed.

## October 10: explicit helper exit and shared menus

Both local installers and source executables were rebuilt again with proactive native app-exit
notification, job-draining/reconnect ownership, the shared branded About window and Linux Quit.
The current installer hashes and implementation handoff are in
[the exit/menu worklog](2026-10-10-studio-exit-and-menus.md). Version remains unpublished 2.2.0a2.

## October 10: responsive startup

Both installers were rebuilt with helper bootstrap/runtime installation and exit handoff on
workers, plus close handling during startup. Current hashes and manual macOS/Linux checks are
in [the startup worklog](2026-10-10-studio-startup-responsiveness.md). Diagnostic timings were
collected externally; no startup timing instrumentation ships in these installers.

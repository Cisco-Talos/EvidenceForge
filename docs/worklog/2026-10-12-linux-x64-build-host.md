# Native Linux x86_64 build host readiness

## Scope and authorization

The user provided `192.168.1.233` as the native x86_64 build/test VM and requested login
verification and a package/configuration readiness report before installation. The user then
explicitly authorized creating the shared `eforge-build` SSH key for both build VMs.
The user subsequently authorized building the latest x86_64 AppImage, including the documented
build prerequisites. No system trust or sandbox-policy change has been performed.
Passwords and private/public key contents are not recorded here.

## Verified host state

- Password login as `eforge` succeeds; the account belongs to the sudo group.
- VMware guest, Ubuntu Desktop 24.04.5 LTS, x86_64, glibc 2.39.
- Eight CPUs, 7.7 GiB RAM, 4 GiB swap and 36 GiB available on the 49 GiB root filesystem.
  These match the selected build baseline and permit the builder's default two Cargo jobs.
- Python 3.12.3, rsync, CA certificates, file, wget, xz, desktop-file-utils and xdg-utils exist.
- GStreamer base/good plugins and tools are installed; `appsink` inspection succeeds.
- The display manager is active and `eforge` has an active Wayland desktop session.
- User D-Bus, `wayland-0` and Xwayland display sockets exist for desktop testing.
- `/dev/fuse` exists, but the FUSE 2 library is absent.
- Verified HTTPS succeeds for PyPI, Node.js, Rust distribution downloads and GitHub.
  ChatGPT returns HTTP 403 to an anonymous HEAD request with valid TLS; this does not
  establish authenticated Codex access. No missing CA trust is observed.

## Readiness against contributor requirements

The maintained toolchain/package list, PATH configuration and sandbox diagnostics are in
[CONTRIBUTING.md](../../CONTRIBUTING.md#ubuntu-2404-prerequisites).
At this audit, the native compiler, uv/Node/Rust toolchains and Tauri development libraries
were absent. Codex was absent, the login profile did not source Rust's environment,
FUSE 2 was absent, and the bubblewrap namespace probe failed with
`setting up uid map: Permission denied`. Ubuntu's general namespace restriction was enabled;
no expected bubblewrap policy was found during the initial file check.

No prerequisites were installed and no source was copied during this audit. Package setup
and native acceptance remain separate from the authorized SSH key installation below.

## Shared SSH key setup

The ARM VM at `192.168.191.129` was temporarily unreachable, then responded on retry.
Password login confirmed `eforge`/aarch64 and no authorized public keys; key-based access
was not previously configured. The new x86_64 account likewise had no authorized keys.

Created a dedicated Ed25519 key at `~/.ssh/eforge-build` on the Mac, with private-key mode 0600.
Installed its public key once in each account using `ssh-copy-id`, preserving any existing
entries. Both remote `.ssh` directories have mode 0700 and `authorized_keys` mode 0600.
Both accounts report the same public-key fingerprint.

Added two narrowly scoped local SSH config entries:

- `eforge-arm` / `192.168.191.129`: user `eforge`, shared key, `IdentitiesOnly yes`.
- `eforge-x86_64` / `192.168.1.233`: user `eforge`, shared key, `IdentitiesOnly yes`.

The prior config is backed up at `~/.ssh/config.before-eforge-build`; existing host-key
records are retained, and the authenticated x86_64 host key is recorded. Strict-host-key,
batch-mode, public-key-only login succeeds to both aliases without a password.

## Authorized native build setup

Installed the prerequisites from
[CONTRIBUTING.md](../../CONTRIBUTING.md#ubuntu-2404-prerequisites), including the native
compiler, Tauri development libraries, patchelf and FUSE 2. Installed per-user toolchains
and added Rust's environment to the login profile. Verified the official Node archive's
SHA-256 before extraction. HTTPS verification remained enabled throughout.

Verified versions: Node 22.23.3, npm 10.9.9, uv 0.13.0, Rust/Cargo 1.99.0,
native target `x86_64-unknown-linux-gnu`, system Python 3.12.3 and uv-managed Python 3.12.15.
WebKitGTK is 2.52.6, GTK 3.24.41, OpenSSL 3.0.13, librsvg 2.58.0 and GStreamer 1.24.2.
FUSE 2 is `libfuse2t64` 2.9.9-8.1build1; patchelf is 0.18.0-1.1build1.
Native library discovery and GStreamer `appsink` inspection pass.

The first helper/state test run found the VM's default umask `0002` creates group-writable
fixture ancestry. Studio correctly refused those paths. Repeating with a process-local
umask `022` passed: 227 tests, one skipped and 145 slow tests deselected. The contributor
test guide now documents this requirement. The initial failure log is retained on the VM.
The user's login umask and Studio's ownership checks were not changed.

No Codex installation, account sign-in, CA trust change or AppArmor policy change was needed
for compilation or packaged-runtime verification. Interactive authoring and manual desktop
acceptance remain separate checks.

## Verified latest x86_64 preview

Built from exact `origin/dev` snapshot `57025df17ca61ccdc932044c8cc196fc7223784e` in a clean
native checkout at `/home/eforge/EvidenceForge`. Product version is `2.2.0a2`, with Studio
version `2.2.0-alpha.2`; this snapshot includes the approved issue #444 scheduling fix.

Validation completed successfully:

- Synchronized version metadata and generated frontend types.
- All 296 frontend tests, 227 Linux helper/state tests and 12 native Rust shell tests.
- Actual AppImage extraction and native x86_64 ELF identity.
- Private runtime checksum and generation behavior revision 162.
- Isolated CLI, bundled skills/references, pack inspection, artifact naming/properties,
  bundle data properties, scenario validation and checkpoint-enabled generation.
- GStreamer `appsink` loading from bundled plugins with the host plugin search disabled.
- Exact preview installer/checksum set and matching SHA-256 after copying to the Mac.

Artifact: `EvidenceForge-Studio-2.2.0a2-x86_64-test.AppImage`, executable mode 0755,
141,765,112 bytes (135.20 MiB).
SHA-256: `22faf4f62fbac9f18f26dfe7cdb963ec43f7a64f635e82409f82010f4e9a5da4`.

The VM retains the image and adjacent checksum under `/home/eforge/EvidenceForge/dist/linux/`.
The Mac copy is under `dist/linux/57025df1-vm/`, preserving previous same-version previews.
The VM's build log, source commit, exit status and initial umask failure log are retained
under `/home/eforge/eforge-build-setup/57025df1/`; final exit status is zero.
The toolchain installation log is under `/home/eforge/eforge-build-setup/`.

Manual desktop acceptance is pending the user's test. No GUI launch, release version bump,
tag creation or publication was performed. This worklog and the contributor umask note are
documentation recorded after the built snapshot; they do not change the packaged engine.

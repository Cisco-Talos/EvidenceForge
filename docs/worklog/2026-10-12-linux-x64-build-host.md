# Native Linux x86_64 build host readiness

## Scope and authorization

The user provided `192.168.1.233` as the native x86_64 build/test VM and requested login
verification and a package/configuration readiness report before installation. The user then
explicitly authorized creating the shared `eforge-build` SSH key for both build VMs.
No build-tool installation, system trust change or sandbox-policy change has been performed.
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

## Missing build tools and dependencies

User toolchains: uv, Node.js 22/npm and stable Rust/rustup/Cargo. Codex is absent and must
be installed and authenticated separately for assisted-authoring acceptance.
The stock login profile already supports `~/.local/bin`; it does not yet source
`~/.cargo/env`, so Rust's login-shell PATH setup remains to be added with its installation.

APT build and AppImage dependencies:

```text
build-essential curl git pkg-config
libwebkit2gtk-4.1-dev libxdo-dev libssl-dev
libayatana-appindicator3-dev librsvg2-dev
patchelf libfuse2t64
```

Bubblewrap 0.9.0 is installed, but the unprivileged namespace probe fails with
`setting up uid map: Permission denied`. Ubuntu's AppArmor user-namespace restriction is
enabled; neither expected bubblewrap profile file is present. Follow the existing approved
Ubuntu profile workflow when sandbox setup is authorized; retain the general restriction.
`apparmor-utils` is absent and would be useful for diagnosis, rather than a compiler prerequisite.

Source checkout synchronization and frozen Python/npm dependencies remain to be prepared
before a local build. No source was copied to the VM during this audit.

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

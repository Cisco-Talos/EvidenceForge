# How to Contribute

Thanks for your interest in contributing to EvidenceForge! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/Cisco-Talos/EvidenceForge/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Suggesting Features

Feature requests are welcome! Open a GitHub Issue with the **enhancement** label
and include:

- A clear description of the feature and the problem it solves
- Example usage or scenario where the feature would be helpful
- Any relevant references (e.g., log format specs, MITRE ATT&CK techniques)

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

Before submitting a feature or fix PR, follow [Development Setup](#development-setup), then
run the routine suite and lint/format checks in [Test Markers](#test-markers). Generation
changes also require the slow tier without coverage. Run relevant soak diagnostics only for
exceptional scale/duration changes. Coverage is a separate release-readiness gate.

Run optional third-party parser validation when touching emitted log formats
covered by an external parser harness. This lane requires Docker Compose v2 or
Podman Compose:

See [External Parser Validation](docs/external-parser-validation/README.md)
for the full-dataset runner command, SOF-ELK® harness architecture, coverage
matrix, ignored-tag policy, and failure report details.

If you add or change a log format that already has external parser support,
update the external-parser smoke lane for that format and run it. If you add a
new supported parser family, include discovery, staging, representative smoke
fixtures, validation checks, docs coverage, and any explicit tag-policy rules.
If there is no applicable third-party parser yet, update the coverage matrix
and keep discovery warnings/tests in place so the unsupported format is not
silently skipped.

For target-dependent parser support, add or update smoke fixtures for the
target that the parser expects. SOF-ELK checks for Windows/Sysmon, Linux syslog,
and Cisco ASA use `eforge generate --target sof-elk`; default-target output
must still be covered by normal generation/evaluation tests and should produce a
clear diagnostic in the external-parser runner. The developer-facing SOF-ELK
script requires `OUTPUT_TARGET.txt` to exist and contain `sof-elk`; legacy or
default-target datasets exit before parser discovery/staging.

Use the explicit 70% coverage gate in [Test Markers](#test-markers) before a `dev` → `main`
release PR. Measure the default non-slow suite; run slow/soak tiers separately without coverage.

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Prefix
your commit message with a type:

- `feat:` — new feature or capability
- `fix:` — bug fix
- `docs:` — documentation changes
- `test:` — adding or updating tests
- `refactor:` — code changes that neither fix a bug nor add a feature
- `chore:` — maintenance tasks (dependencies, CI, tooling)

Examples:
```
feat: add SMTP log emitter
fix: correct Zeek UID correlation for DNS queries
docs: update scenario reference with dhcp_lease event type
test: add integration tests for proxy emitter
```

### Pull Request Descriptions

Describe what changed and why. Reference any related issues (e.g.,
`Closes #42`). If the change affects log output or scenario schema, include
a brief example of the before/after behavior.

## Development Setup

This is the maintained setup and build/test guide. Studio and release documentation link here;
worklogs retain dated installation and acceptance evidence.

The engine/CLI routine suite runs on Python 3.12+ on Linux, macOS and native Windows. Studio
builds and desktop acceptance currently target these native hosts:

| Studio target | Build/test host | Native Rust target |
| --- | --- | --- |
| macOS Apple Silicon | macOS with Xcode command-line tools | `aarch64-apple-darwin` |
| Linux ARM64 | Ubuntu Desktop 24.04 LTS, `aarch64` | `aarch64-unknown-linux-gnu` |
| Linux x86_64 | Ubuntu Desktop 24.04 LTS, `x86_64` | `x86_64-unknown-linux-gnu` |

Linux AppImages use the Ubuntu 24.04/glibc 2.39 baseline. Build on the target architecture;
other distro/desktop acceptance and Windows/Intel macOS Studio installers remain outstanding.
Allow space for both debug/release Rust caches and the bundled runtime. For a VM, check the
host's backing-disk space as well as guest free space. Packaging defaults to two Cargo jobs.

### macOS prerequisites

Install Apple's command-line tools and finish any installation/license prompts:

```bash
xcode-select --install
```

Install Node.js **22** with npm using the [official Node.js 22 downloads](https://nodejs.org/en/download/archive/v22.23.3).
Then install uv and Rust as described below. A packaged Studio app can run without these tools;
they are needed for source development and installer builds.

### Ubuntu 24.04 prerequisites

The same packages apply to native ARM64 and x86_64. Install them before the toolchains:

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 build-essential curl git pkg-config ca-certificates file wget xz-utils rsync \
  libwebkit2gtk-4.1-dev libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev \
  patchelf libfuse2t64 gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
  gstreamer1.0-tools desktop-file-utils xdg-utils
```

The development libraries follow [Tauri's Linux prerequisites](https://v2.tauri.app/start/prerequisites/).
`patchelf` supports AppImage GStreamer bundling; `libfuse2t64` supports ordinary AppImage launch.
GStreamer plugins and their scanner are also bundled into the finished AppImage.
Engine/CLI-only development needs Python, uv and Git, rather than the Studio libraries.

For a fresh Linux host without Node 22, this installs the official, checksum-verified archive
into your account. The example uses the Node 22 release verified during Linux bring-up; an
existing Node 22 installation can be used instead.

```bash
(
  set -eu
  eforge_node_version=v22.23.3
  case "$(uname -m)" in
    aarch64) eforge_node_arch=arm64 ;;
    x86_64) eforge_node_arch=x64 ;;
    *) printf 'Use a native ARM64 or x86_64 build host.\n' >&2; exit 1 ;;
  esac
  eforge_node_archive="node-${eforge_node_version}-linux-${eforge_node_arch}.tar.xz"
  eforge_node_download="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/${eforge_node_version}/${eforge_node_archive}" \
    -o "$eforge_node_download/$eforge_node_archive"
  curl -fsSL "https://nodejs.org/dist/${eforge_node_version}/SHASUMS256.txt" \
    -o "$eforge_node_download/SHASUMS256.txt"
  (cd "$eforge_node_download" && sha256sum --check --ignore-missing SHASUMS256.txt)
  mkdir -p "$HOME/.local/share/node" "$HOME/.local/bin"
  tar -xJf "$eforge_node_download/$eforge_node_archive" -C "$HOME/.local/share/node"
  for eforge_node_tool in node npm npx corepack; do
    ln -sfn "$HOME/.local/share/node/node-${eforge_node_version}-linux-${eforge_node_arch}/bin/$eforge_node_tool" \
      "$HOME/.local/bin/$eforge_node_tool"
  done
)
```

### uv, Rust and login-shell PATH

Use [uv's standalone installer](https://docs.astral.sh/uv/getting-started/installation/) for
Python tooling. Studio also needs [stable Rust through rustup](https://rust-lang.org/tools/install/).
On macOS or Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | UV_NO_MODIFY_PATH=1 sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
  sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
```

Add this block once to your login profile (`~/.profile` on Ubuntu, `~/.zprofile` for macOS zsh),
unless equivalent configuration already exists, then open a fresh terminal:

```sh
export PATH="$HOME/.local/bin:$PATH"
if [ -f "$HOME/.cargo/env" ]; then
    . "$HOME/.cargo/env"
fi
```

Ubuntu's stock profile already adds `~/.local/bin` when it exists. Noninteractive SSH commands
should use a login shell or explicitly include `~/.local/bin` and `~/.cargo/bin` in PATH.
For native Windows engine/CLI development, install Git and use uv's documented PowerShell
installer; the common Python checkout/test steps below apply without the Studio toolchains.

Check discovery before building:

```bash
python3 --version
uv --version
node --version
npm --version
rustc --version
cargo --version
rustup target list --installed
```

On Ubuntu, also check the native libraries and GStreamer:

```bash
pkg-config --modversion webkit2gtk-4.1 gtk+-3.0 openssl librsvg-2.0 ayatana-appindicator3-0.1
gst-inspect-1.0 appsink
```

Downloads must pass HTTPS certificate verification. If a corporate proxy causes certificate
errors, configure your organization's supported CA trust on the test host before downloading
toolchains or signing in to Codex. An anonymous ChatGPT HTTP 403 with valid TLS does not by
itself establish that authenticated authoring will fail.

### Checkout and locked dependencies

Install the prerequisites first. Use `dev` for current Studio/prerelease development:

```bash
git clone --branch dev https://github.com/Cisco-Talos/EvidenceForge.git
cd EvidenceForge
uv python install 3.12
uv sync --frozen --all-extras --python 3.12
```

For Studio, also install the locked frontend dependencies and native Rust target:

```bash
npm --prefix desktop-ui ci
rustup toolchain install stable --profile minimal
```

Use `rustup target add aarch64-apple-darwin --toolchain stable` on Apple Silicon macOS,
`rustup target add aarch64-unknown-linux-gnu --toolchain stable` on Linux ARM64, or
`rustup target add x86_64-unknown-linux-gnu --toolchain stable` on Linux x86_64.
The product version comes from `pyproject.toml`; check all derived Studio metadata with
`uv run --no-sync python scripts/sync_studio_version.py --check`.

#### Remote VM source synchronization

Remote builds need SSH access to the build account and rsync on both machines. If the VM
needs an SSH server, install `openssh-server` there. A dedicated login key can be provisioned
from the controller; replace the account/host placeholders with your build VM. Reuse an
existing build key, or create one when absent:

```bash
if [ ! -e "$HOME/.ssh/eforge-build" ]; then
    ssh-keygen -t ed25519 -f "$HOME/.ssh/eforge-build" -C eforge-build
fi
ssh-copy-id -i "$HOME/.ssh/eforge-build.pub" build-user@BUILD_HOST
```

Add an entry for each VM to the controller's `~/.ssh/config`, then verify `ssh eforge-build-vm`:

```text
Host eforge-build-vm
    HostName BUILD_HOST
    User build-user
    IdentityFile ~/.ssh/eforge-build
    IdentitiesOnly yes
```

After preparing a checkout on the VM, the source-sync helper can copy the controller's tracked
and unignored files while retaining remote dependencies and replacement backups:

```bash
uv run --no-sync python scripts/sync_linux_vm.py --dry-run \
  eforge-build-vm /home/build-user/EvidenceForge
uv run --no-sync python scripts/sync_linux_vm.py \
  eforge-build-vm /home/build-user/EvidenceForge
```

The helper preserves remote Git metadata, virtual environments, build caches and private state.
It synchronizes working files, not commit history. Release builds still require checkout of the
exact validated source commit through the release workflow.

### Source launch and Studio tests

Launch from a terminal in the logged-in graphical desktop session:

```bash
uv run --no-sync eforge-desktop
```

SSH is sufficient for compilation and CLI/tests, but an SSH tty is not a desktop session.
Use the VM desktop for native GUI acceptance. Headless packaged-runtime verification alone
does not establish that native dialogs, menus, graphics, authoring and reconnect behavior work.

Run the [Python test tiers](#test-markers), then these checks for Studio/frontend changes:

```bash
npm --prefix desktop-ui test
npm --prefix desktop-ui run types:check
npm --prefix desktop-ui run build
CARGO_BUILD_JOBS=2 cargo +stable test --locked --manifest-path desktop-ui/src-tauri/Cargo.toml
```

State-upgrade, backup, recovery and persistence changes also require the native acceptance
contracts in [Studio state upgrades and recovery](docs/studio-state-upgrades.md).

### Studio development on macOS

After the common setup, build and verify the standalone Apple Silicon app and preview DMG:

```bash
uv run --no-sync python scripts/package_studio_macos.py --build-app
uv run --no-sync python scripts/verify_studio_macos.py \
  "build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/EvidenceForge Studio.app"
eforge_studio_version="$(uv run --no-sync python -c 'import evidenceforge; print(evidenceforge.__version__)')"
hdiutil verify "dist/macos/EvidenceForge-Studio-${eforge_studio_version}-aarch64-test.dmg"
```

The DMG and checksum are written to `dist/macos/` with a `-test` filename suffix.
Add `--skip-dmg` to build only the app. `--release` removes the filename suffix;
building does not publish. Signing/notarization remains separate release work.

### Studio development on Linux

After the common setup, build and verify the native AppImage. `uname -m` must be `aarch64`
or `x86_64`; Tauri's internal `amd64` bundle spelling is handled by the builder.

```bash
eforge_studio_arch="$(uname -m)"
uv run --no-sync python scripts/package_studio_linux.py --architecture "$eforge_studio_arch"
eforge_studio_version="$(uv run --no-sync python -c 'import evidenceforge; print(evidenceforge.__version__)')"
eforge_studio_image="dist/linux/EvidenceForge-Studio-${eforge_studio_version}-${eforge_studio_arch}-test.AppImage"
uv run --no-sync python scripts/verify_studio_linux.py "$eforge_studio_image"
(cd dist/linux && sha256sum -c "$(basename "$eforge_studio_image").sha256")
chmod +x "$eforge_studio_image"
"$eforge_studio_image"
```

Outputs go to `dist/linux/` with a SHA256 file. `--assemble-only` prepares only the runtime
payload. `--release` removes the `-test` suffix without uploading or publishing anything.
Use the corresponding filename without `-test` when verifying a release-named build.

The verifier extracts the actual AppImage without FUSE, checks its bundled runtime/resources
and GStreamer scanner/plugins, and exercises its private CLI in an isolated temporary home.
Test the chosen architecture's menus/dialogs, authoring, validation, generation, evaluation,
exit/reconnect and persistence in the desktop session before accepting an installer.

#### AppImage launch prerequisites

For testing a downloaded AppImage, a source checkout, uv, Node and Rust are unnecessary.
Ordinary launch on Ubuntu 24.04 needs the FUSE 2 compatibility library:

```bash
sudo apt-get install -y libfuse2t64
```

When FUSE is unavailable, use `APPIMAGE_PATH --appimage-extract-and-run` instead, replacing
`APPIMAGE_PATH` with the executable image's path. Both methods need a working graphical desktop
and compatible host libraries. See [AppImage's FUSE guidance](https://docs.appimage.org/user-guide/troubleshooting/fuse.html).

### Codex authoring and Linux sandbox tests

Codex is optional for engine/CLI tests and deterministic generation. Assisted-authoring
acceptance requires a separately installed Codex CLI and your own sign-in. One per-user
installation method, after Node/npm setup, is:

```bash
npm install --global --prefix "$HOME/.local" @openai/codex
codex --version
codex
```

Complete the sign-in offered by Codex, then use Studio's **Settings → Authoring & tools**
to select the executable and reconnect when authoring is idle. See the
[official Codex CLI setup](https://learn.chatgpt.com/docs/codex/cli).

Linux authoring needs `bubblewrap` and working unprivileged user namespaces:

```bash
sudo apt-get install -y bubblewrap
codex help sandbox
codex sandbox -- /usr/bin/true
```

The sandbox command should exit 0. The shown syntax is verified with Codex 0.162.0;
check your installed CLI's help if it differs. Startup warnings, sandbox skill-read failures,
`bwrap: setting up uid map: Permission denied` or network namespace errors need diagnosis even
when Codex can connect and answer simple messages.

On Ubuntu 24.04, inspect matching AppArmor denials and existing policy first:

```bash
sudo journalctl -k -b --no-pager --grep='apparmor|userns|bwrap'
sudo aa-status
```

If no existing profile covers `/usr/bin/bwrap`, install and load Ubuntu's extra profile:

```bash
sudo apt-get update
sudo apt-get install -y apparmor-profiles apparmor-utils
sudo install -m 0644 \
  /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
  /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

`apparmor-utils` supplies `aa-status`; if it is absent, install it before that diagnostic.
Repair an existing conflicting profile through the system administrator rather than adding
an overlapping attachment. Loading this application-specific profile preserves Ubuntu's general
namespace restriction and persists across boots. Retest the sandbox, reconnect idle Studio
authoring, and retry any previously failed command with fresh approval state.
Other distributions can package the profile differently. See
[OpenAI's sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites)
and [Ubuntu's namespace restriction notes](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).

### Build-only CI previews

If using GitHub Actions instead of a local builder, GitHub CLI is needed only on the machine
dispatching/downloading artifacts. The read-only installer workflow supports all three targets:

```bash
gh workflow run installers.yml --ref dev -f platform=all
gh run download RUN_ID --name preview-installer-linux-x86_64 --dir dist/linux/RUN_ID
```

Select `macos-aarch64`, `linux-aarch64` or `linux-x86_64` for one target; use its corresponding
`preview-installer-PLATFORM` artifact name. These jobs verify packaged runtimes and checksums;
they do not replace manual native desktop acceptance. For release gates, immutable tags and
publication, see [release instructions](docs/releases.md). For app installation and workflows,
see the [Studio guide](docs/studio.md).

### Test Markers

- `@pytest.mark.slow`: extended release-gate tests, excluded by default and run with
  `uv run pytest -m slow --no-cov`. This lane holds distinct expensive fault matrices,
  fresh-process determinism checks, and representative end-to-end generation.
- `@pytest.mark.soak`: exceptional million-entry, multi-week, exhaustive-matrix, or full-demo
  diagnostics,
  excluded by routine and release gates. Run only when relevant with
  `uv run pytest -m soak --no-cov`. Slow and soak are mutually exclusive tiers.
- `@pytest.mark.external_parser`: third-party parser container tests, skipped by default
  and normally run only in an explicitly opted-in local or CI lane

```bash
# Normal routine run
uv run pytest
uv run ruff check .
uv run ruff format --check .

# Slow comprehensive run
uv run pytest -m slow --no-cov --durations=20

# Exceptional scale/duration diagnostics, when relevant
uv run pytest -m soak --no-cov --durations=20

# External parser run
uv run pytest --include-external-parsers -m external_parser --no-cov

# Release coverage gate; do not combine with -m slow or -m soak
uv run pytest --cov=evidenceforge --cov-report=term-missing --cov-report=xml --cov-fail-under=70
```

## Code Style

EvidenceForge follows strict coding conventions documented in [AGENTS.md](/AGENTS.md). Key points:

- **Type hints everywhere** — all functions, methods, and variables
- **Pydantic v2** for all structured data
- **100 character** line length, **4 space** indentation, **double quotes**
- **Google-style docstrings** for public functions
- **`uv`** for all dependency management (never `pip`)
- **`pathlib.Path`** for all path handling (never string paths)

Linting is enforced via `ruff` with pycodestyle, pyflakes, isort, pep8-naming, pyupgrade, and flake8-bugbear rules.

## Adding a New Log Format

1. Create a format definition YAML in `src/evidenceforge/formats/definitions/`
2. Create an emitter class in `src/evidenceforge/generation/emitters/` inheriting from `LogEmitter`
3. Register the emitter in `src/evidenceforge/generation/emitters/__init__.py`
4. Add emitter initialization in the engine (`src/evidenceforge/generation/engine/emitter_setup.py`)
5. Create a parser in `src/evidenceforge/evaluation/parsers/` for eval support
6. Add tests for the emitter and parser
7. Document the format in `docs/reference/EVIDENCE_FORMATS.md`

## Adding a New Event Type

1. Add the event spec Pydantic model to `src/evidenceforge/models/scenario.py`
2. Add a handler in `ActivityGenerator` (`src/evidenceforge/generation/activity/generator.py`)
3. Add any needed context fields to `src/evidenceforge/events/contexts.py`
4. Implement `_render_{event_type}()` on relevant emitters
5. Update `src/evidenceforge/validation/schema.py` for cross-reference validation
6. Update `docs/reference/scenario-reference.md`
7. Add tests

## Other Ways to Contribute

We welcome anyone that wants to contribute to EvidenceForge to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review existing pull requests, and testing patches against EvidenceForge.
- Write a test, or add a missing test case to an existing test.
- Create new example scenarios for different attack types.
- Improve documentation or add tutorials.

Thanks again for your interest in contributing to EvidenceForge!

### Native Windows CI

Routine CI runs Python 3.12 on Ubuntu and native Windows, with `uv run pytest --no-cov`.
The routine suite includes a short real generation, checkpoint, cooperative suspension,
verification, and fresh-process resume comparison against uninterrupted output. The same test
runs during normal local macOS testing. Broad checkpoint fault/interruption tests remain in the
Linux slow release gate for PRs into main.

Native Windows uses an isolated local NTFS backend for protected output journals and checkpoints;
macOS and Linux retain their POSIX implementations. The routine timeout is 45 minutes on Windows
and 25 minutes on Linux. Small native API contracts run in the routine suite. A separate required
Windows checkpoint durability job runs focused slow simulated power-loss recovery tests with a
20-minute timeout. These tests validate the documented storage assumptions, not physical power-loss
certification. See the
[native Windows design](docs/design/native-windows-filesystem.md) for platform limits. Do not
blanket-skip portable failures or disable publication protections to make the job green.

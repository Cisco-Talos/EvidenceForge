# Standalone Studio for macOS

Studio currently supports **macOS only**. Linux and Windows GUI support is deferred for later
exploration. Engine and CLI platform support is unchanged.

## Install the test package

The first standalone package is for Apple Silicon. The intended field-test system
is macOS 26. It includes Python, EvidenceForge, runtime dependencies, catalogs,
templates, and skills; no checkout, Python installation, uv, Node, or Rust is needed.
Codex remains a separate installation for authoring.

1. Copy `EvidenceForge-Studio-2.1.2-aarch64-test.dmg` to the other Mac.
2. Open the DMG and drag **EvidenceForge Studio.app** to **Applications**.
3. Eject the DMG and open Studio from Applications.
4. If macOS blocks the first launch, use **System Settings → Privacy & Security →
   Open Anyway** for this app, then confirm opening it. This test package has no
   Developer ID signature or notarization. See [Apple's instructions](https://support.apple.com/102445).
5. Choose or create a workspace. Install/sign in to Codex separately to use authoring;
   validation, generation, evaluation, and bundle viewing work without authoring.

The companion `.dmg.sha256` file records the image checksum. In the folder containing
both files, `shasum -a 256 -c EvidenceForge-Studio-2.1.2-aarch64-test.dmg.sha256`
verifies the transferred copy.

## Codex executable and available models

Studio asks the selected Codex executable for its model catalog. Different Codex
versions can expose different models, even with the same signed-in account.
Automatic discovery uses `codex` on PATH, then common macOS CLI locations
(`/opt/homebrew/bin`, `/usr/local/bin`, `~/.local/bin`), then Codex.app's bundled CLI.
Finder has a minimal PATH, so these fallback locations matter for the standalone app.

To make terminal and standalone Studio use exactly the same executable, run
`command -v codex` in your terminal and enter that absolute path under
**Settings → Authoring & tools → Codex executable**. Save, then click the Codex
status dot in the header and reconnect when authoring is idle. Settings are shared
by both launch methods when they use the same app-data directory.

## Data and updates

Workspace scenarios, packs, and output stay in the chosen workspace. Studio keeps
its database and private runtimes under `~/Library/Application Support/EvidenceForge`,
helper state under `~/Library/Application Support/EvidenceForge/state`, and diagnostics
under `~/Library/Logs/EvidenceForge`. The first launch expands the bundled runtime;
later launches reuse it. The app opens no terminal and performs no runtime downloads.

Generation can continue after closing the window when the chosen quit policy permits
it. Reopening the same app reconnects to the retained helper. Moving the app or
replacing its files does not remove code used by existing jobs.

Before opening a different build, finish or pause active generations/evaluations,
stop active authoring, and close the old window. The new build authenticates and
replaces an idle helper, checking its PID, creation time, executable, and command.
An older source helper without the handoff API requires manual shutdown after its
work finishes. No unrelated process is stopped. Private runtime directories are
retained in this first package; automatic cleanup and updates are deferred.

## Field acceptance on the other Mac

Record the exact macOS revision and try an actual workspace:

- First launch and Codex detection/sign-in, then authoring using bundled skills/CLI.
- Import a scenario and its pack dependencies; validate and inspect the environment.
- Queue two generations, observe progress, close/reopen Studio, and inspect the results.
- Pause and resume a checkpoint-enabled generation; evaluate and export its bundle.
- Move the app, reopen it, and confirm the same workspace/jobs remain accessible.

Local native checks ran on Apple Silicon macOS 27.0.1 with isolated app data, a
minimal PATH, and app/workspace paths containing spaces and Unicode. These do not
replace acceptance on macOS 26. The configured deployment floor is macOS 13;
older systems have not been accepted. Intel delivery is deferred because the locked
`cryptography==50.0.1` has no macOS Intel wheel. Linux and Windows standalone packages
remain future work. Signing/notarization will be reconsidered for a distribution release.

## Build from source

On a macOS build machine with uv, Node/npm, stable Rust, and Xcode command-line tools:

```sh
uv sync --extra studio --extra dev
npm --prefix desktop-ui ci
rustup target add aarch64-apple-darwin --toolchain stable
uv run python scripts/package_studio_macos.py --build-app
uv run python scripts/verify_studio_macos.py \
  "build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/EvidenceForge Studio.app"
```

`desktop-ui/packaging/runtime-lock.json` pins upstream interpreter URLs and SHA256
digests. `uv.lock` supplies exact hashed Python dependencies. Assembly uses binary
wheels and generates stable runtime archives and a content identity. Cargo builds
with its lockfile. Developer ID signing and notarization are disabled for the test
artifact; normal compiler-generated ad hoc executable signatures remain.

For an app build without creating a DMG, add `--skip-dmg` to the packaging command. macOS Studio
CI uses that option, checks packaged CLI/resources on native Apple Silicon runners, and uploads
a ZIP of the app under `dist/macos/`. Manual DMG creation remains available when needed; DMGs are
not required for the migration or current PR gates.
Build outputs are ignored by Git. See the [implementation worklog](worklog/2026-10-03-studio-standalone-macos.md)
for detailed evidence and outstanding acceptance.

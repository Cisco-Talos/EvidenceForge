# EvidenceForge Studio

The Tauri/React frontend for EvidenceForge Studio. The local Python service owns
workspace data, Codex conversations, and generation jobs; `eforge` remains the
deterministic worker.

The GUI currently supports macOS only. Linux and Windows GUI builds and native
acceptance are deferred for later exploration; engine/CLI platform support is unchanged.

From the repository root, install the Python dependencies with
`uv sync --extra studio --extra dev`. Then run `npm ci` in this directory and
`uv run eforge-studio` from the repository root for the native window. For a
browser preview, run `uv run python -m evidenceforge.studio.bootstrap` to start
the local service, then set `VITE_STUDIO_URL` and `VITE_STUDIO_TOKEN` from its
connection output before running `npm run dev` in this directory.

Run `npm test`, `npm run build`, and `npm run types:check` in this directory for
frontend checks. Both `eforge-studio` and `eforge-desktop` launch Studio; the Qt
prototype has been retired.

For a source-run macOS `.app`, use `npm run build:native -- --debug --bundles app`.
The wrapper builds with Tauri, then applies the transparent official forge mark as
the `.app` file icon through AppKit. The running app applies the same artwork to
its Dock icon. This avoids macOS adding a rounded background to the legacy icon.
The bundled ICNS and other platform icons also contain the full mark with alpha;
the original full-color sidebar logos remain unchanged. This is a development
bundle. For the standalone Apple Silicon app/DMG, use the
[macOS packaging instructions](../docs/studio-standalone-macos.md).

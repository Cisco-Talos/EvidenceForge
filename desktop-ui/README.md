# EvidenceForge Studio

The Tauri/React frontend for EvidenceForge Studio. The local Python service owns
workspace data, Codex conversations, and generation jobs; `eforge` remains the
deterministic worker.

From the repository root, install the Python dependencies with
`uv sync --extra studio --extra dev`. Then run `npm ci` in this directory and
`uv run eforge-studio` from the repository root to start the service and browser
preview. Run `npm run tauri dev` here for the native window.

Run `npm test`, `npm run build`, and `npm run types:check` in this directory for
frontend checks. The current source-run preview is under development; the Qt
prototype remains the documented `eforge-desktop` entry point until cutover.

# EvidenceForge desktop prototype

This is an experimental local Qt app for macOS and Linux. It runs Codex app-server
for skill-assisted authoring and the existing `eforge` CLI for validation and generation.
Generation itself remains deterministic. Windows has not been tested.

## Run it

1. Install the [Codex CLI](https://developers.openai.com/codex/cli/) and sign in with
   `codex login` if needed. The app also offers a **Sign in** button.
2. From the EvidenceForge checkout, run `uv sync --extra desktop --extra dev`.
3. Run `uv run --extra desktop eforge-desktop` from the checkout. The first launch uses
   the current directory as its EvidenceForge workspace. Use **Workspace…** to change it.
4. Use **Install EvidenceForge skills** if the skill picker is empty. Each authoring tab
   is a separate Codex thread, saved and resumed on the next app launch.

In chat, **Enter** sends the message. **Shift+Enter** or **Option/Alt+Enter** inserts
a newline. Validation shows a compact result with findings and suggested fixes.
In the Jobs view, **Save new runs in** selects the parent folder for future bundles;
the app remembers the last selected folder.

The app needs a local `codex` executable on `PATH`. Set
`EFORGE_DESKTOP_CODEX_BIN` to its full path if it is installed elsewhere. When
launching outside the checkout, set `EFORGE_DESKTOP_EFORGE_BIN` to an installed
`eforge` executable. An installed development checkout uses its current Python
environment by default.

## Long running generation

**Generate** starts a separate CLI process for each run. The process is detached
from the window, so closing the app leaves it running. Each run gets a unique
bundle under `<selected-output-folder>/<scenario-name>/` (by default,
`<workspace>/runs/<scenario-name>/`). App metadata, command logs,
and progress JSONL files live in the platform's application data directory.
On restart, the app loads that metadata, checks the saved PID and process start
time, and replays the progress file to restore the bars. It polls once per second
while open. The CLI emits one flushed JSON object per engine progress event through
the new `--progress-jsonl` option; the existing Rich terminal display still works.
The app reconnects only to jobs it launched and recorded. It does not discover
unrelated `eforge` processes started in a terminal.

The hour bar counts warm-up and collection hours. A second bar appears when the
scenario emits storyline progress. Later phases show a descriptive status because
the engine does not currently report a measurable total for finalization and
ground-truth writing. **Suspend** asks the CLI to checkpoint at the end of the
current simulated hour; **Resume** uses a retained checkpoint.

Closing the app ends its Codex app-server connection and any active authoring
turns. Saved authoring threads can be reopened. A CLI generation run continues
independently, including while no GUI is open. Closing the app does not itself
create a checkpoint; use **Suspend** when a safe stopping point is needed.

## Prototype boundaries

The current app includes multiple authoring tabs, skill selection, scenario
validation, concurrent generation jobs, progress bars, log/bundle opening,
and restart reconnection. Scenario and pack libraries, evaluation scorecards,
archive download, overlay editing, and a distributable macOS `.app` package
remain to be built. App data is local to the user; Codex authoring uses the
user's configured Codex account and permissions.

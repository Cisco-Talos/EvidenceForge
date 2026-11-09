# Studio chat engine selection

During alpha-5 user acceptance, the source-launched Studio Validation button
reported four Mac profile errors for the saved MacOS-test draft. Fix in chat
instead reported zero errors and said its CLI lacked `configuration_context`.
The saved GUI report still selects native ES but declares macOS 26 on both Mac
hosts; the active generation profile requires macOS 27 arm64 workstations.

The user's launch command is `uv run eforge-desktop`. Studio validates through
`_eforge_command(controller_settings(settings))`, normally its running interpreter
with `-m evidenceforge`. Chat previously received an explicit CLI instruction only
when `EFORGE_STUDIO_RUNTIME_ROOT` was set for a packaged launch. A source-launched
chat could therefore use the unrelated global `eforge`, which on this machine is
the separately installed 2.2.0a4. Its validation does not establish that the current
Studio engine accepts the same scenario.

A second prompt defect could misleadingly suggest a version mismatch even on the
current CLI: `info configuration_context` is available only with an explicit
`--context` file, but Studio requested it even for `--project-root`. The prompt
now requests `info project_root` for root-only selection and retains
`info configuration_context` for an explicitly selected context file. The missing
field alone is therefore not proof of an old engine; the separately installed
global version was confirmed directly.

Studio now supplies the exact same selected CLI command prefix to both new and
resumed conversations, including source interpreter, packaged isolation flags,
settings override and environment override. Instructions explicitly override
generic skill command examples and prohibit switching installations when a command
fails or a capability is absent. Draft write boundaries remain unchanged.

Regression coverage exercises scenario and both pack conversation types across
all four command selections, including paths with spaces and Unicode. It checks
both first-turn and resumed-turn engine/context instructions while preserving the
original fast-completion and visible-message assertions. Existing private-runtime
and chat-protection tests remain applicable.

The user's managed draft has not been edited here. macOS denies direct reads of
its authored contents from this session. Restart Studio from this checkout to load
the fix, then repeat Fix in chat against the current GUI findings using the exact
selected engine. Reinstalling the global tool or skills is not required for this
engine-selection correction. Validation-provenance write restrictions are separate
from semantic validation; this change grants no broader write access.

Validation: Studio service/runtime/chat-permission checks pass 124 tests with one
platform skip. After the final context-inventory instruction correction, all twelve
conversation/CLI-selection regressions pass again. Whole-repository Ruff lint and
format checks and `git diff --check` pass. Running the selected checkout interpreter
from `/private/tmp` confirms the corrected `info project_root --project-root
/private/tmp --json` succeeds without relying on a source-checkout CWD.

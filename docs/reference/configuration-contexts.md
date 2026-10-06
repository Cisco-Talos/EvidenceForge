# Optional configuration contexts

Existing EvidenceForge usage is unchanged: CWD selects `.eforge/config` and `.eforge/packs`, or
`--project-root DIR` explicitly selects another root. Neither a scenario location nor a Studio
project assignment is discovered by the CLI. No database or running Studio service is needed.

To share a more specific selection between the CLI, native agent skills, and Studio, pass an
ordinary YAML context file explicitly:

```yaml
context_version: "1.0"
project_root: ..
overlays:
  - name: Healthcare project
    path: ../project-config
  - name: One exercise
    path: ../scenario-config
```

Paths are relative to this file. `project_root` selects the pack repository and the base
`.eforge/config` overlay. Each additional directory mirrors the supported package-relative paths,
such as `activity/dns_registry.yaml` and `personas/analyst.yaml`. Names are unique provenance
labels; directories must exist and cannot be selected twice. Missing selections fail with an
actionable error rather than falling back to another root.

## Commands

```bash
eforge info configuration_context --context contexts/clinic.yaml --json
eforge info dns_tags --context contexts/clinic.yaml --json
eforge validate-config --context contexts/clinic.yaml --json
eforge validate scenarios/example/scenario.yaml --context contexts/clinic.yaml --json
eforge resolve scenarios/example/scenario.yaml --context contexts/clinic.yaml -o resolved
eforge resources predict scenarios/example/scenario.yaml --context contexts/clinic.yaml --json
eforge generate scenarios/example/scenario.yaml --context contexts/clinic.yaml -o runs/example
```

Use `uv run eforge` in a source checkout. A matching `--project-root` may accompany a context;
a conflicting root is rejected. Pack management retains its existing `--project-root` option:
use the context's declared root for `eforge pack` commands.

The context only selects existing user-owned configuration families. It does not extend
configuration to engine safety, evaluator policy, output-format contracts, or resource calibration.
Inspect `eforge info config_families --json` and validate every edit in a fresh process.

## Merge rules and reproducibility

Apply package defaults and pack adapters as before, then the base overlay, then extra directories
in listed order. Each family keeps its existing merge function. Nested mappings, appended lists,
keyed `_replace` entries, and whole-section replacement retain their documented meaning. A later
layer does not universally replace earlier lists. Scenario fields keep their established ownership.

Resolved scenarios embed the ordered layer documents. Reproduction and checkpoint recovery use
that captured configuration, even if the original files are moved or removed:

```bash
eforge generate resolved/RESOLVED_SCENARIO.yaml -o runs/reproduced
eforge generate --resume -o runs/example
```

Omit `--context` for resolved inputs and implicit checkpoint recovery. To check changed authored
inputs against a checkpoint, explicitly supply the authored scenario and context with `--resume`;
the existing compatibility checks still apply. Legacy resolved documents and checkpoint inputs
remain readable. Without extra layers the existing effective-config serialization is unchanged.

Extra selections are bounded to 16 layers, 500 YAML files per layer, and 64 MiB of total YAML.
Extra layers reject links and unsupported paths. Read-only commands create no configuration files.

## Studio scope controls

In **Edit project**, enable **Use project configuration** to share a directory among its scenarios.
In a scenario's **Environment** tab, enable its private scenario layer. Both are off by default.
Workspace overlays continue to apply to all scenarios in that workspace.

Studio stores ordinary files:

```text
<workspace>/.eforge/config/                       # workspace base
<workspace>/.eforge/projects/<project-id>/config/ # optional shared project
<workspace>/.eforge/scenarios/<source-key>/config/# optional private scenario
<workspace>/.eforge/contexts/<source-key>.yaml    # explicit selection
```

The scenario key uses its workspace-relative source path. Project renaming does not move the
shared directory. Turning a layer off or deleting a virtual project preserves configuration files.
Cloning copies private scenario patches; project configuration remains shared. Moving between
configured projects requires confirmation because future validation, forecasts, and generation
use the new selection. Existing runs retain their captured inputs.

The Environment tab shows selected directories, configuration files, and a copyable CLI command.
Validation, forecasts, conversations, and queue snapshots receive the same explicit selection.
External edits refresh dependency freshness and invalidate results tied to older inputs.

## Imports and exports

Scenario import optionally accepts a **Configuration context**. The review lists the source base
and extra layers as private copies; the source root also supplies missing exact pack versions.
Copies apply after destination workspace/project configuration, so inspect the review and use the
optional validation sanity check. Source edits after review require a new review. Without this
explicit selection, source overlays are not silently copied or applied.

Completed bundle exports include the current authored context and selected layer files when
available. Imported copies never depend on the original source workspace. Exact pack dependencies
still undergo normal import review. The selected run's `RESOLVED_SCENARIO.yaml` remains its
authoritative reproducibility input; current authored content can differ from that run.

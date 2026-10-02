---
description: "Select EvidenceForge project context without broad filesystem discovery"
---

# EvidenceForge Project Context

EvidenceForge uses the current working directory for optional project-local inputs:

```text
./.eforge/config
./.eforge/packs
```

Run from the intended working directory and omit `--project-root`. The directory may be empty and
does not need `.eforge`; EvidenceForge locates installed defaults and package packs itself.

## Explicit override

Use `--project-root <absolute-root>` only when the user explicitly requests another directory or
explicitly identifies a different directory whose `.eforge` inputs must apply. Repeat that override
on related inspection, validation, resolution, and generation commands. Otherwise omit the option.

An authoritative resolved scenario is self-contained; do not pass a project root for it.

Never search parents, siblings, the home directory, an installed tool, or a source tree for
`.eforge`, scenario files, or a supposedly better project root. A scenario elsewhere on disk does
not implicitly select a neighboring or ancestor `.eforge`. The source checkout affects whether to
invoke `eforge` or `uv run eforge`; it does not affect project-root selection.

Never search an installed tool, package directory, or source tree for example scenarios, schemas,
packs, or configuration. Use installed skill references and project-dependent `eforge info`,
`eforge pack list`, or `eforge pack show` inventories instead.

Read-only commands must not create `.eforge`. Pack or config authoring may create it in the current
working directory, or under an explicitly overridden root, only when the user requested that write.

Non-default override example:

```bash
eforge pack list --json --project-root /explicitly/selected/project
```

## Optional named configuration contexts

Only when the user or calling application explicitly supplies a context, use `--context FILE`
instead of `--project-root`. No context is discovered automatically. Ordinary CWD usage stays the
same. A context is plain YAML, independent of Studio or its database:

```yaml
context_version: "1.0"
project_root: ..
overlays:
  - name: Clinic project
    path: ../project-config
  - name: One scenario
    path: ../scenario-config
```

Paths resolve relative to the context file, not CWD or the scenario. The declared root selects
`.eforge/packs` and the base `.eforge/config`. Additional directories contain the same supported
package-relative configuration paths. Apply the base first, then additional layers in listed order;
retain each family's existing merge rules, including appended lists, keyed `_replace`, and complete
section replacement. A later layer is not a universal replacement for every field or list.

Repeat the selection for `info`, `validate-config`, `validate`, `resolve`, `resources predict`, and
`generate`. Inspect it with `eforge info configuration_context --context FILE --json`. Pack
management uses its existing `--project-root`, with the context's declared root. Never search for
another root or silently fall back if a selected file or directory is missing.

A resolved scenario embeds its selected configuration, including ordered layers. Omit `--context`
when reproducing it or resuming a captured run. Contexts do not authorize editing package defaults,
engine policy, unrelated layers, or authored content. Import/export must carry selected layer files
or explicitly disclose missing dependencies; a display project name alone is not configuration.

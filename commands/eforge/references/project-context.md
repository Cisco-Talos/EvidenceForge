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

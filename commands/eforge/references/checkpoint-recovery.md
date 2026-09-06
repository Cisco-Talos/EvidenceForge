---
description: "Checkpoint inspection, drift verification, and safe resume reference"
---

# Checkpoint Recovery

Read this reference for interrupted generation, resume compatibility, environment drift, recovery
wheels, OOB authorization, or a verifier that appears idle.

## Preserve First

Stop the generator before copying or inspecting a bundle. Preserve a filesystem snapshot or backup
before recovery, especially for a large remote run. Never delete `.eforge-generation/`, edit its
manifests, or use `--overwrite` while a valid recovery may remain.

Use the bundle root—the parent of `data/`:

```bash
eforge checkpoint status <bundle-root> --verbose
eforge checkpoint verify <bundle-root> --verbose
eforge generate --output <bundle-root> --resume
```

Status is read-only static inspection. Verify authenticates all objects and hydrates every
participant into isolated scratch storage without changing the source. Large lifecycle and spool
restores can take minutes; human output reports integrity, initialization, participant `N/M`,
cleanup, and completion. JSON output has no progress text. `--verbose` adds bounded aged-out-parent
examples and detailed drift records.

## Interpret Compatibility

Resume reports three independent axes:

- `run_identity`: authoritative scenario/seed/formats/target/OOB inputs match or conflict.
- `loadability`: full participant hydration has not run, succeeded, or failed.
- `behavior_change`: `exact`, `none-declared`, `localized`, `material`, or `unknown`.

The backward summary remains `exact`, `load-compatible`, or `incompatible`. Any runtime drift makes
`output_equivalence` `not-guaranteed`, even when EvidenceForge declares no behavior change.

`--resume-policy compatible` is the default. Python/compiler/implementation, dependencies, OS,
architecture, cache tag, and byte order are attempted. Declared `none` or `localized` behavior
continues after successful hydration. Material or unknown behavior asks interactively and defaults
to no; noninteractive use stops with guidance.

`--resume-policy exact` requires the full original fingerprint and preserves the byte-equivalence
guarantee. `--resume-policy attempt` is explicit consent for material or unknown output drift. Do
not supply `attempt` unless the user explicitly accepts that risk. It never bypasses corruption,
unsafe ownership, missing objects/participants, unsupported schemas/decoders, conflicting explicit
run inputs, OOB authorization, or hydration failure.

Omitted scenario and ordinary options adopt the checkpoint's authoritative resolved values. Live
callbacks are different: a checkpoint never grants authorization. For any checkpoint with OOB
hosts, obtain current authorization and repeat every matching `--oob-host` on resume. Never add or
substitute hosts.

## Migration And Provenance

After successful non-exact hydration, resume atomically publishes a migration checkpoint at the
same cursor before another simulated hour. The selected pre-migration recovery remains fallback
until normal rotation. If pre-migration hydration or publication fails, the recovery index and
staged source are restored unchanged.

Subsequent checkpoints and the final manifest record originating/resuming builds, categorized
runtime drift, behavior risk and change IDs, accepted policy, confirmation status, cursor, and
bounded migration lineage. Exact evidence bytes are guaranteed only for exact resume.

## uv Tool Recovery Builds

Find the managed environment with:

```bash
uv tool list --show-paths
```

Install a trusted local recovery wheel into that existing tool environment in place, rather than
creating an unrelated environment:

```bash
EFORGE_TOOL_ENV=/absolute/environment/path/from-the-list
uv pip install --python "$EFORGE_TOOL_ENV/bin/python" --reinstall /absolute/path/to/recovery.whl
"$EFORGE_TOOL_ENV/bin/python" -m evidenceforge checkpoint verify <bundle-root>
```

Here `uv pip` installs into the selected uv-managed tool environment, not the project `.venv` or a
new global location. The `eforge` executable is in that environment's `bin` directory. Preserve the
wheel hash and build digest supplied with the recovery
instructions. Verify first, then resume on the computer holding the original generation. The
remote resume creates its own migration checkpoint; do not copy a locally migrated multi-gigabyte
bundle back.

When a recovery wheel is only an exact-behavior backport, keep using it for that interrupted run.
Do not replace its immutable release tag or infer that a displayed package version alone identifies
the source build; compare the recorded build digest.

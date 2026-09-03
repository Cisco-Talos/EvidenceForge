# Generation Checkpoints and Resume

`eforge generate` creates crash-safe recovery points every 24 completed simulated hours by
default. The cadence counts continuously across warm-up and collection. Override it with
`--checkpoint-hours N`, or pass `--checkpoint-hours 0` to disable new checkpoints.
`eforge validate` accepts the same option so its peak-disk forecast matches the intended run.

Checkpointing is cadence-only. Generation does not force recovery points after initialization, at
phase boundaries, or before finalization. If a run ends before its first cadence point, it has no
recovery point and must restart after interruption. Otherwise, recovery replays work after the
latest committed point, including tail work or finalization when necessary. Ctrl+C and process
termination do not attempt an emergency checkpoint; the last atomically published point remains
authoritative.

## Resume an interrupted run

Resume while rechecking the authored scenario:

```bash
eforge generate scenario.yaml --output ./bundle --resume
```

Resume solely from the authoritative resolved input stored with the checkpoint:

```bash
eforge generate --output ./bundle --resume
```

An unspecified resumed run retains its stored cadence. An explicit `--checkpoint-hours` overrides
that cadence; `0` resumes from the selected point but creates no later checkpoints. The complete
output root may be moved or copied before resume because checkpoint metadata contains only relative
paths and its resolved input and immutable segments are self-contained.

Interactive generation distinguishes a compatible incomplete run, an invalid or incompatible
checkpoint, and a completed bundle before offering valid actions. Scripts and redirected input
must choose explicitly with `--resume` or `--overwrite`. `--force` and `-f` remain deprecated
aliases for `--overwrite` for compatibility. Resume conflicts with overwrite.

## Workspace, safety, and final output

Recovery data lives under `.eforge-generation/` in the output root. It includes the staged bundle,
two recovery manifests and bounded live heads, shared content-addressed segments, resolved input,
and a single-run lock. The resource forecast reports this separately as `Projected checkpoint
workspace` and includes it once in projected peak working disk.

Checkpoint publication requires protected ownership, no symlinks or path traversal, atomic rename,
and durable file and directory synchronization. Preflight fails when the filesystem cannot provide
those guarantees; use another filesystem or explicitly pass `--checkpoint-hours 0`. A demonstrably
stale lock may be reclaimed, but concurrent generation against the same output root is rejected.

The newest corrupt recovery point produces a warning and falls back to the previous valid point.
Tampering, incompatible inputs or runtime fingerprints, unsupported schemas, and unsafe ownership
are rejected with an explanation. Checkpoints from unreleased development schemas are not migrated.

Successful generation publishes through the normal bundle replacement rules, preserves unrelated
files, and removes `.eforge-generation/`. The completed generation manifest contains no resume
history. Deterministic evidence, resolved input, ground truth, artifacts, and deterministic
sidecars are byte-identical to uninterrupted generation; `generation.log` and the time-bearing
generation manifest retain their established nondeterministic fields.

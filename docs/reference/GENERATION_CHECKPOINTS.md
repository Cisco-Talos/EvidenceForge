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
authoritative. On Ctrl+C or an ordinary failure, the CLI reports whether a recovery point exists,
its simulated hour and phase, and how to resume. A resumed run reports the selected recovery cursor
and effective cadence before continuing.

## Inspect or intentionally suspend a run

Thoroughly validate an output root without starting or hydrating the generator:

```bash
eforge checkpoint status ./bundle
eforge checkpoint status ./bundle --verbose
eforge checkpoint status ./bundle --json
```

The positional path is the bundle root—the directory that contains `data/`—not the `data/`
directory itself. When generation uses no explicit `--output`, the bundle root is the authored
scenario's parent directory. If `data/` is supplied by mistake, the command returns immediately
with the correct bundle-root command instead of scanning generated evidence.

The default human report shows the operational state, last recoverable phase-local hour, continuous
simulated-hour count, cadence, integrity and runtime compatibility, fallback warnings,
generated-data size, recovery overhead, total known managed working footprint, and the exact resume
command. For example, after a two-hour warm-up and one completed collection hour it reports
`collection hour 1 of 6 (3 total simulated hours completed)`. `--verbose` adds both recovery
generations, lock ownership, schema/run identities, participant and segment counts, fingerprint
components, detailed storage categories, and validation work. `--json` always emits the complete
structured report, independent of `--verbose`. Status is read-only and excludes unrelated files
from all managed totals. Checkpoint storage includes durable spool content already imported into
the hidden workspace.

For every checkpoint-enabled run, the hidden workspace and controller marker are created before
warm-up begins. Until the first cadence point commits, status reports
`Checkpoint state: active — no checkpoint yet`; an interruption in that interval still requires a
restart with `--overwrite`. A path with no checkpoint workspace reports
`Checkpoint state: no checkpoints found` without presenting zero-byte validation and storage
details as though they described a run.

Request a planned stop from another terminal:

```bash
eforge checkpoint suspend ./bundle
```

Suspension is cooperative, not immediate. The command returns after publishing the request and
reminds the operator that generation is still running. The generator finishes its current
simulated hour, reaches the normal quiescent barrier, publishes an explicit recovery point even
when that hour is off cadence, reports the suspended cursor, and exits successfully. An
off-cadence suspension does not move the cadence anchor: with a 24-hour cadence, suspending at hour
37 still leaves hour 48 as the next automatic checkpoint after resume. Repeating a pending request
is idempotent. Suspension requires an active checkpoint-enabled run; Ctrl+C remains the immediate
option and creates no emergency checkpoint. A request that arrives after the last hourly barrier,
while tail work or finalization is already running, cannot interrupt that unsafe region and the run
finishes normally.

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
paths and its resolved input and immutable segments are self-contained. Stop the generator before
copying the root; copying an active workspace can capture an inconsistent set of files.

Portability is path portability, not runtime migration. Resume requires the same compatible
EvidenceForge code/resources, Python implementation, version, and compiler, dependency versions,
operating system, architecture, byte order, effective options, and resolved-scenario fingerprint.
Resume an incomplete run before upgrading its environment. An incompatibility is reported rather
than bypassed because relaxing this check could change the supposedly deterministic continuation.

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

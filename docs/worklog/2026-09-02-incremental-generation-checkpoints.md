# Incremental Generation Checkpoints

## Objective

Implement cadence-only crash-safe generation checkpoints whose foreground work depends on changes
since the previous checkpoint plus bounded live state, not all historical generator state. Resume
must remain portable and byte-identical, and the selected default cadence must add no more than 5%
median wall time on every representative workload, including a 60-day scenario.

## Branch history

- This implementation starts from clean `dev` commit `a530d9d91` on
  `codex/generation-checkpoints`.
- The rejected full-snapshot experiment is preserved remotely on
  `origin/codex/generation-checkpoints-full-snapshot` at `c21eeeda5`.
- That experiment established the CLI/safety requirements and proved byte-identical recovery, but
  its full-history capture grew from 4.80 foreground seconds after simulated hour one to 13.69
  seconds after hour three. Its projected 60-day cost was unacceptable.

## Locked decisions

- Checkpoints occur only at positive cadence multiples across the continuous warm-up and
  collection hour count. There are no forced initialization, phase-boundary, tail, or
  pre-finalization checkpoints.
- `--checkpoint-hours 0` disables checkpoint creation. A run interrupted before its first cadence
  point has no resumable recovery point.
- Active emitter spools stay in their current locations. Checkpoints import only new immutable
  runs, append chunks, or logical SQLite rows and restore protected spools freshly.
- Recovery points share content-addressed immutable segments. A checkpoint captures bounded live
  heads and seals only the delta since its predecessor; it never reprocesses older segments.
- The stdlib packed representation is the baseline. A third-party codec or store is retained only
  if it reduces checkpoint-path work by at least 20% and worst-workload total overhead by at least
  three percentage points without regressing another representative workload.
- No project version bump occurs on this feature branch.

## Acceptance record

Record implementation commits, schema decisions, fault results, byte-identity comparisons,
checkpoint-time growth at simulated hours 6/24/168/720/1440, codec/store trials, resource forecast
calibration, and the final three-pair performance matrix here. Do not reconcile the durable TODO
until every correctness and performance gate passes.

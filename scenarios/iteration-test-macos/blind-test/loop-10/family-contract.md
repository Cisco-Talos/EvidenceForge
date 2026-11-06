# Loop 10 family contract

## Family: ordered eCAR exec transitions under lifecycle repair

- **Candidate owner:** `SourceTimingPlanner._apply_process_execution_constraints`, which owns source-visible process execution ordering after endpoint latency and process-create floors are applied.
- **Entry paths:** successive POSIX `process_exec` occurrences on macOS and Linux, across baseline, bootstrap, and typed storyline process activity.
- **Invariant:** when endpoint latency places multiple execution events at or before the same visible process-create frontier, each `process_exec` follows its prior execution epoch and remains distinct at eCAR millisecond precision. Repair jitter uses the prior execution's admitted time and is at least one millisecond, while un-repaired canonical source intervals keep their original timing.
- **Consumers / sibling risks:** eCAR PROCESS/MODIFY rows, process-image and parent-child pivots, native Endpoint Security comparisons, Linux exec evidence.
- **Layer rationale:** the planner owns causal process timing and event identity; per-execution scope without predecessor ordering did not prevent collapse in loop 9. Emitter offsets or host-specific patches would hide the missing transition edge.
- **Probe plan:** generate fresh output and compare every process execution epoch to its predecessor on both Macs; assert strict eCAR millisecond order for repaired transitions, then check same-PID Linux exec transitions and confirm no row falls before its process create.

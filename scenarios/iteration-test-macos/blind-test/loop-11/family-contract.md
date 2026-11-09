# Loop 11 family contract

## Family: eCAR millisecond-visible process execution order

- **Candidate owner:** `SourceTimingPlanner._apply_process_execution_constraints`, which owns causal source timing before eCAR timestamp serialization.
- **Entry paths:** repeated POSIX `process_exec` events on macOS and Linux, including process bootstrap, baseline activity, and typed storyline commands.
- **Invariant:** each visible eCAR exec transition must serialize to a strictly later millisecond than both its admitted process-create/fork predecessor and the previous execution epoch when source timing repair is needed. A timestamp that is later only at microsecond precision still collides after eCAR's integer-millisecond conversion and must be repaired.
- **Consumers / sibling risks:** eCAR process lineage/detection pivots, native Endpoint Security comparisons, Linux process lifecycle records, process-exec ordering constraints.
- **Layer rationale:** the planner knows the causal predecessor and the source renderer's millisecond precision. Per-execution jitter alone is insufficient when the un-repaired timestamp falls later than the exact floor but into the same serialized millisecond.
- **Probe plan:** compare eCAR `CREATE/fork` and `MODIFY/exec` sequences per PID on both Macs, require increasing serialized milliseconds for every execution epoch, and verify multiple Linux exec chains plus no process exec before its create.

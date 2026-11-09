# Loop 9 family contract

## Family: macOS process execution timestamps in eCAR

- **Candidate owner:** `SourceTimingPlanner`, which selects per-occurrence source timestamps and deterministic repair scopes before eCAR rendering.
- **Entry paths:** process forks and successive image-execution transitions produced by bootstrap, baseline, and storyline process execution on macOS; the same process-exec event model is also used on Linux.
- **Invariant:** separate process execution epochs for one PID retain distinct, causally ordered timestamps after endpoint source latency and lifecycle repair. A repair to the process-create frontier must not assign one shared timestamp to multiple exec transitions.
- **Consumers / sibling risks:** eCAR PROCESS/CREATE and PROCESS/MODIFY rows, native Endpoint Security event ordering, process tree and identity pivots, Linux process-exec rows.
- **Layer rationale:** the planner owns event-level timing scope and causal repairs. The eCAR renderer already consumes the finalized base event timestamp; output-only offsetting would hide the shared timing-key collision and make other consumers disagree.
- **Probe plan:** compare rendered eCAR fork/exec timestamps with native Endpoint Security transition times for multiple process executions, check strict order and non-collapse, then verify a second same-PID exec sequence on a different Mac and a Linux execution path in unit/integration coverage.

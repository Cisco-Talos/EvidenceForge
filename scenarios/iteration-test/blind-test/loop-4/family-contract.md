# eCAR process-transition collector timing family

Classification: family_level, sibling_defect of source-provider timing.

Owner: SourceTimingPlanner._endpoint_event_source_key and its coherent collector queue.
Canonical fork/exec/credential/job-control times already exist; eCAR serialization does
not own their elapsed intervals. A process-state transition must use the same source
collector queue as process creation, retaining per-occurrence residuals and existing
lifecycle ordering/close constraints. A short canonical interval must not collapse
systematically merely because its two records choose different collector profiles.

Entry inventory: local and remote POSIX process execution, Mac SSH PTY startup,
service/privilege/audit identity transitions, authored and baseline callers. They all
converge on endpoint source planning. Raw direct-emitter escape hatches remain outside
this contract. Consumers: eCAR PROCESS CREATE/EXEC/audit/credential/job-control rows,
process-dependent evidence and lifecycle finalization; native ES remains unchanged.

Root probe: 100 distinct 5–140 ms canonical fork/exec intervals at behavior 536 yield
86 observed intervals <=5 ms, median 1.7395 ms. Routing state transitions through the
existing process-create collector produces zero <=5 ms, median 73.882 ms and maximum
elapsed-error 2.192 ms. This is an isolated planner experiment, not reviewer evidence.
No arbitrary jitter or exact command/host exception is proposed.

Sibling risks: credential and job-control ordering, successive exec epochs, late
parents/session bootstrap floors, output cutoffs, dependency containment and process
termination still use existing constraints. Test all five state-transition routes,
several canonical intervals and multiple process/host scopes. Keep generic file/module
and network latency classes intact; they have their own semantic observations.

Next verification: focused source timing/process contract suites, rendered cross-source
fork/exec interval probe after regeneration, unchanged scenario/reviewer hashes, normal
lint/format/behavior gates. Describe any surviving parent/session floor effects as
residuals instead of hiding them with wider random noise.

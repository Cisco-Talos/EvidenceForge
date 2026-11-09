# Loop 19 family contract: macOS Unified Log clock projection

## Root cause and owning layer

`SourceTimingPlanner.plan_event()` routes Unified Log records through `source.macos_unified_log`. `_sample_source_time()` then applies the generic endpoint clock adjustment to the observation timestamp, while the native `machTimestamp` and boot UUID were already frozen from the canonical event time. The resulting JSON wall timestamp and native Mach clock disagree. The source timing planner owns this projection relationship; an emitter patch would only conceal one rendered symptom.

## Required invariant

For every modeled native macOS Unified Log observation, its wall timestamp must remain consistent with its boot-relative Mach timestamp and shared boot clock. Source projection cannot independently shift the wall timestamp while leaving `machTimestamp` unchanged. This must preserve SSH accepted-auth ordering relative to the receiver shell and workspace/policy observations that use the same native clock.

## Entry paths and consumers

Current native Unified Log entry paths include SSH accepted authentication and loginwindow workspace requests; policy refusal may also use the same host clock source. `prepare_unified_log_observation()` creates the canonical boot-clock/Mach-time pair. `SourceTimingPlanner` projects it, and the Unified Log emitter serializes it. Cover the source-time function with a host clock profile that has nonzero drift, and verify the exact native output pair after a full SSH bundle.

## Sibling risks and rationale

The fix applies only to `source.macos_unified_log`; eCAR, Endpoint Security, Linux syslog and network sensors retain their own clock semantics. The profile currently has zero extra source latency, matching native event-time semantics. Any future nonzero latency must move both wall time and Mach ticks together or be modeled as a separate collection timestamp.

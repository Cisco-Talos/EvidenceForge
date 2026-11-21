# Continuous source-observation delay precision

Finding: loop4 Host and all actual deliberators found 10/10 anacron startup
syslog messages exactly millisecond aligned versus0/40 follow-on and5/4080others.
Source hashes prove this predates loop4. Root is broader than anacron: its
scheduled canonical start is whole-second, and ObservationPolicy._sample_delay
uses randint(min_ms,max_ms). Subsequent canonical phases already have fractional
times, hiding the same millisecond-quantized delay. Do not add cosmetic jitter to
one message or alter the authored scenario.

Owner: shared SourceObservationPolicy. Its ms configuration fields define delay
bounds, not timestamp precision. For non-degenerate windows, sample a bounded
right-skew continuous microsecond delay through typed deterministic timing scope.
Keep complete/zero/fixed windows exact. Preserve source/lifecycle group identity
and exact-sensor identity so existing create/dependent/terminate and login/logoff
coherence and missingness decisions remain unchanged. Keep the existing special
coherent eCAR process curve. Raw escape-hatch behavior remains explicit and unchanged.

Entry inventory: legacy and exact-source decide/decide_projection; generic daemon
status, canonical host/auth/process/network source projection; raw decide_raw has
no automatic delay and stays unchanged. Consumers: dispatcher SourceTimingPlanner,
source windows/admission, collection provenance, endpoint/network source clocks,
source-local lifecycle closure and deterministic eval of saved observations.

Sibling verification: scheduled non-anacron source events at whole seconds,
source/lifecycle-coherent SSH/session/process pairs, exact sensor separation,
fixed/complete bounds, seed/scope determinism and no global RNG consumption,
configured upper close budgets, native syslog projection and source collection
records. Inspect older frozen receipt compatibility; do not weaken policy checks.
Do not edit production during generation5. This is a future family draft.

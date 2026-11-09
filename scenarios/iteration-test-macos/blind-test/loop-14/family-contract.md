# Loop 14 family contract — macOS authoritative process teardown cadence

## Owning layer

`ActivityGenerator._plan_generic_logoff_process_closes` owns process termination timestamps in
authoritative generic session shutdown plans. It currently divides one short shutdown span into
equal per-process slots and applies bounded jitter. That produces repeated near-uniform exit gaps
in native Endpoint Security and eCAR observations on both Macs.

## Invariant

For macOS authoritative session teardown, every process close must remain after its last dependent
activity and before its exact session end, with children closing before their owning parents when
the lifecycle graph requires it. Process close intervals must come from deterministic,
process/session-scoped timing samples, rather than equal timestamp slots. Independent sessions
must not reproduce the same cadence. The session end and transport ownership remain authoritative.

## Entry paths and consumers

Generic local interactive session logoff plans terminate process cohorts and the owning session.
The canonical close timestamps feed process lifecycle state, source-observation grouping,
Endpoint Security notifications, eCAR process-end records, and session logoff evidence. Bundle-owned
SSH and RDP terminal paths retain their own lifecycle owners and must remain unchanged.

## Sibling risks

Cover at least two macOS local interactive sessions with distinct identities, including the
paired-host case that exposed the repeated distribution. Preserve process/session ordering and
ensure Linux and Windows authoritative logoff scheduling is unchanged. Verify a process with a
dependent child and one close close to an exact session deadline.

## Why this layer owns the truth

The repeated cadence is created before source projection: the planner computes evenly spaced
canonical process-close times. Emitter or source-timing jitter would only disguise the pattern in
one output and risk separating Endpoint Security, eCAR, and lifecycle state. The planner has the
session identity, process graph, exact deadline, and per-process identity needed to create varied,
deterministic close times coherently.

# RDP readiness, negotiation and target bootstrap phases (draft)

Recurring panel4 target-specific transport/auth clusters and panel5 eleven RDP
smss→winlogon intervals at .499/.500 seconds are distribution_texture sibling
findings, not an unconditional native impossibility. Do not alter the scenario or
add independent source-specific jitter.

Owner: RdpSessionActionBundle canonical phase graph plus BaselineTimingPlanner.
The current target-logon sampled .9–1.6s negotiation is max-clamped by endpoint
clock separation and maximum FLOW delay, erasing its variation. Target bootstrap
also max-clamps a 1.5–8s smss lead by request+5s, then winlogon by smss+.5s.

Hypothesis/invariant: admitted transport/source readiness must precede sampled
negotiation, which must precede native target auth/bootstrap/foreground readiness;
retain source FLOW-before-auth under permitted clocks, mstsc owner/session alive
through close, exact continuation identity, reconnect frontier, deadline admission
and native source publication recovery. Existing stochastic phase work must not
collapse onto a deterministic safety floor. Choose causal phase relationships
rather than widening renderer residuals.

Entry inventory: typed storyline RDP, compatibility Windows Type10, baseline remote
admin/RDP, exact deferred materialization, reconnect/cached session continuation,
known Windows/Linux sources and external unknown sources. Consumers: source
process lifetime/session holds; canonical network/TCP/3389; target Security4624,
Sysmon/eCAR process/session telemetry; reconnect registry/terminal finalizers;
independent timing-receipt and lifecycle evaluators. Raw rows remain explicit.

Risks: conservative custom clock/headroom may need max negotiation reserved during
hard-end admission. Reconnect readiness must be applied before sampling the next
negotiation, not by a new fixed post-sample clamp. Source OS clocks must remain
correct for mixed-OS sources. Bootstrap stage availability/parentage must stay
compatible with session publication and prospective foreground actions. Runtime
sampling must stay scoped, deterministic, audited and compatible with prepared
planning. Do not infer empirical Windows timing calibration from chosen bounds.

Before editing: inspect exact field meanings (canonical session start versus
source-ready authentication); select one or two bounded target phases and test
unknown-source unchanged gap, modeled clocks, reconnect, hard-end, exact deferred,
source hold, prepared timing audit, native parent-child and auth row ordering.
Prototype /private/tmp/eforge-rdp-phase-probe.py exists for readiness/negotiation,
not target bootstrap, and is not production code.

Implementation contract chosen before production edits: one pure typed target
phase plan owns smss, winlogon, auth readiness, userinit, explorer and userinit
handoff times. Separate the legacy5s session-manager admission fence from bounded
sampled startup work. Do not max-clamp the work duration into the readiness floor.
Negotiation begins after source/reconnect readiness; clocks and existing modeled-
source visibility policy remain unchanged in this bounded repair. Mixed-OS source
clock admission is a separate unqualified lead, not silently changed here.

New RDP phase support belongs in timing_profiles.yaml; both sampling and pre-RNG
transport support read the same bounds. Expose the existing Windows user-manager/
desktop maximum from its owning BaselineTimingPlanner without duplicating numbers
or changing its draw IDs. Reserve userinit handoff retirement too. Plan/reject an
impossible complete target phase window before opening State materialization
reservations. Keep the authored transport fixed and protect its source client.
Bounds are modeled support, not measured Windows kernel calibration. Legacy,
known/unknown source, reconnect, custom-clock/deadline, prepared publication and
fresh-process checkpoint/native source siblings require verification. A104-case
in-memory prototype passed before production edits; it is not a native gate.

# Loop 34: partial capture packet/header partition

NetworkObservationPlanner now jointly partitions captured and lost payload, packets
and wire bytes. Both sides include at least 40 TCP/IPv4 header bytes per packet and
fit the modeled MTU. The partial-capture model retains one packet and positive payload;
whole-flow loss belongs to source-group observation. Insufficient/raw ledgers do not
authorize invented packet loss. The TCP test fixture's inherited UDP header values were
corrected; protocol/file completeness and persistent capture ledgers remain coherent.

41 focused tests pass. A separate 10,000-case math probe found 9824 compatible partial
partitions and 176 unchanged infeasible inputs. Ruff/format pass. Validation, generation
and eval pass at 96.0691, 135636 records and 117 files, identical counts/score to33.
Rendered clean-to-partial header-delta failures fell286 to0; data/zero history failures
remain0. Two independently lossy sensors need not represent nested packet sets, so
14 comparisons in the older318-count probe were overbroad. The valid historical32
clean/partial count was304; no historical scores were rewritten.

This fixes the physical loss model, not all sequence-derived conn byte semantics.
The captured ledger and file completeness remain distinct from Zeek's sequence-derived
stream byte fields; an explicit source-observation projection contract remains needed.
Packet partitions are aggregate modeled truth, not a claimed native packet capture.

New reviewer evidence: Network found whole-millisecond first-GET timing in both sensors
while CONNECT controls varied at microseconds. The owning canonical HTTP request planner
still computes12+seed%74 milliseconds; fix that shared phase planner, not per-source
rendering. Endpoint scores continue to emphasize authored Mac shell/inventory timings;
these are preserved. Scope correction and newly discovered timing texture explain
score movement; counts/eval and the direct physical probe support the selected fix.

Next priorities: P1 browser version binding (Detection30, repeated, canonical loaded
identity/client owner, medium risk, selected35); P1 fixed Linux health quotas and early
window saturation (Detection/Host33, repeated across11 hosts, baseline arrival owner,
medium risk); P1 HTTP request phase quantization (Network34, repeated, high leverage,
phase planner/config owner, low/medium risk). External RDP reconnect is a reproduced P0
architectural issue requiring allocation-free ACTIVE-session authority; lifecycle guards
remain intact. Original reviewer P0–P4 labels were not assigned.

Quantitative audit correction in42: overall96.0691was high, but the hard pivot-
linkability gate was79.8942below80 (151/189inferred edges); raw acceptance_passed
was false. Earlier PASS labels based only on overall score were wrong. Canonical
status is now REVIEW, without changing numbers, blind reports or scores. Examples
include inferred cross-track Web/Linux→Mac narrative links; these are heuristic
pivot shortfalls, not evidence of a new protocol impossibility. By35the metric was
161/189=85.1852and all hard gates passed;35–41remainpassing. No threshold or scenario
was changed to obtain that result.

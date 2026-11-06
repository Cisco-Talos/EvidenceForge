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


## Family contract

# Coherent partial TCP packet capture

Classification: sibling_defect; family_level. Owner: NetworkObservationPlanner directional loss projection. A partial observation partitions canonical packet/IP/payload counters into physically compatible retained and missing ledgers: each lost TCP/IPv4 packet includes at least40 header bytes, each retained packet has headers, both fit the1500-byte model. Sequence-unique missed bytes remain separate from wire overhead/retransmission. Preserve positive captured payload and one packet; whole-connection drops belong to group observation policy. Invalid/raw insufficient ledgers cannot authorize fabricated packet loss. Scope: all baseline/storyline TCP and persistent SMB observation/rebind, protocol/file completeness consumers; UDP/ICMP stay unmodified. Independent lossy sensors need not form nested packet sets; probes compare a clean sensor to a partial sensor only. Cover tiny/bulk, MTU-packed, retransmission-excess, deterministic replay and protocol-file companions. Medium risk; packet identities are aggregate modeled partitions, not an invented PCAP.


## Individual expert summaries

**Threat Hunter:** Synthetic; verdict confidence 86; synthetic-confidence score 67. The collection supports useful investigations across a mixed enterprise fleet, and the principal intrusion pivots generally have sensible host, account, transport and artifact relationships. My synthetic verdict is driven primarily by repeated exact fractional-second timing fingerprints in native macOS process records, supported by repeated baseline command texture and questionable direct process attribution for Linux transport activity; I did not establish an impossible intrusion timeline.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 42. The supplied telemetry is substantially compatible with a real detection pipeline: the Windows XML parses, native event fields are generally convincing, and the process identities I could join have coherent visible lifecycles. Repeated shell-command vocabulary and some very short TCP exchanges with bidirectional retransmission history raise distributional concerns, but I found no demonstrated hard contradiction sufficient to confidently classify the collection as synthetic.

**Network Forensics:** Synthetic; verdict confidence 86; synthetic-confidence score 65. The network records have substantial protocol and correlation realism, but a large subset of HTTP transactions exposes a precise timing lattice that is difficult to reconcile with ordinary packet-derived timestamps. My verdict rests on this measured, source-local distribution artifact rather than on suspicious activity, source completeness, sanitized destinations, or the neatness of any intrusion narrative. I did not demonstrate a hard protocol contradiction, which limits the score and confidence.

**Host Forensics:** Synthetic; verdict confidence 78; synthetic-confidence score 63. The endpoint evidence has substantial operational realism: process identities, parentage, executable hashes, session boundaries and source-specific timing generally hold together. I favor synthetic because independently launched macOS inventory processes repeatedly have exactly identical microsecond-resolution lifetimes, accompanied by repeated exact shell scheduling offsets; these are concrete timing fingerprints rather than a judgment about how the suspicious activity unfolds. I did not establish a hard contradiction, so the score remains near the lower end of the “likely synthetic” band.


## Scores and comparison

Automated eval 96.0691; standalone synthetic-confidence average 59.25 (mixed/inconclusive), prior loop 49.5. Lower is more production-like. Scores are standalone reviewer measurements; physical/semantic probe outcomes independently verify the selected family.

Facilitator-modeled deliberation averages 67.00; see deliberation.md. Modeled revised positions are excluded from standalone and rolling averages and are not reconvened expert votes.

## Quantitative acceptance

REVIEW: high overall score does not override failed hard criteria. 
- causality.pivot_linkability: 79.8942 < 80.0000.

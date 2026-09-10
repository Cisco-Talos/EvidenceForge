# Iteration Test Blind Assessment — Loop 58

## Outcome

The loop-58 packet and lifecycle contracts pass their rendered probes. All 3,255 matched
response-bearing UDP DNS transactions close between 0.075 and 9.462 ms after the response, with
no negative or over-12.001 ms tail. All 15 visible Type 10 `userinit.exe` starts have matching
terminations 1.150–3.408 seconds later. Automated evaluation passed at 96.2817 across 122,916
records.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 74 verdict confidence, 44 synthetic-confidence. The hunter found
the source mix, sensor skew, DHCP state, TLS identities, process trees, Security-log reset, and
end-to-end attack pivots production-like. Repeated Linux command vocabulary, generic SMB names,
and missing initiator-side process evidence weakened authenticity but did not initially outweigh
the broad lifecycle and environmental coherence.

**Detection Engineer:** Synthetic, 86 verdict confidence, 70 synthetic-confidence. The engineer
found five exact Security/Sysmon integrity disagreements, High-integrity 4688 token-elevation
semantics that never use Full tokens, and a zero-to-nonzero `LogonGuid` transition in all 15 Type
10 sessions. Fleet-wide Linux snap/IRQ reuse, CRON-only timestamp quantization, and missing TLS
certificate references reinforced the result, while schemas and most keyed correlations remained
strong.

**Network Forensics:** Synthetic, 97 verdict confidence, 91 synthetic-confidence. Exact SNI and
tunnel-byte matches showed proxy-origin TCP opening before the initiating CONNECT in 392 of 522
transactions, with outbound TLS also preceding CONNECT in 115. The analyst also found 122 full
TLS 1.2 ECDHE histories without mandatory `K`, 180 failed SSL-labeled flows without SSL records,
cross-sensor application timestamp drift, inconsistent file-analyzer provenance, and unstable
static URL content identity. DNS, topology, firewall lifecycles, sensor clocks, and scanning were
otherwise unusually convincing.

**Host/EDR Forensics:** Synthetic, 90 verdict confidence, 82 synthetic-confidence. The analyst
found one WinSxS suffix reused across three Windows builds, no sub-second lifetime among 781 paired
Windows processes, excessively long transient utilities, the repeated RDP `LogonGuid` gap, and
host-independent Linux snap and IRQ inventories. Strong process ancestry, 969/970 exact
Security/Sysmon joins, coherent SSH and file-transfer behavior, and correct Security-log clearing
were persuasive counterevidence.

## Deliberation Findings

Verdict disagreement and a 47-point score spread required deliberation. The facilitator preserved
the broad production-like strengths but found they could coexist with defects in a sophisticated
deterministic generator. Exact proxy causality, loss-free invalid TLS histories, exact process
integrity disagreements, and the process-lifetime floor changed the hunter's verdict. Final scores
were 80, 87, 91, and 89 synthetic-confidence (mean 86.75), unanimously Synthetic.

## Prioritized Improvements

### P0 — Restore proxy parent-before-child causality

The origin TCP and TLS children frequently precede the CONNECT request that identifies the target.
The proxy transaction owner must anchor destination-specific DNS, origin open, TLS detection, and
response phases after the observed request. A reusable preconnected transport may predate CONNECT,
but transaction-specific TLS cannot. Enforce this with exact tunnel-identity tests at volume.

### P0 — Canonicalize Windows process and session token identity

Security, Sysmon, and eCAR must render one process-owned integrity/token identity, and every RDP
bootstrap process must receive the canonical session `LogonGuid` before publication. Add exact
cross-source assertions for MandatoryLabel, Sysmon IntegrityLevel, elevation type, LogonId, and
LogonGuid across all Type 10 paths.

### P1 — Construct TLS and file-analysis evidence from protocol state

Full TLS 1.2 ECDHE histories require ServerKeyExchange unless coherent packet loss removes it.
Visible aborted handshakes need `established:false` SSL records or must not be labeled as observed
SSL. `files.analyzers` must identify hash, PE, and OCSP analyzers whenever their output exists.

### P1 — Replace process-duration floors with executable-class models

Bounded local utilities need a heavy sub-second tail, while blocking, remote, or interactive work
can retain longer distributions. Validate fleet quantiles and named transient executables so a
shared minimum cannot leak through sibling paths.

### P2 — Condition Linux background evidence on durable inventory

Snap refreshes should come from installed-package state and IRQ events from a persistent host
hardware map. Gold-image cohorts can share components, but server roles should not all inherit
MicroK8s, desktop integration, and exact mixed-device mappings without explicit configuration.

### P2 — Preserve packet-derived timing across sensors

HTTP, TLS, and file observations should begin from one canonical packet/event timestamp and add
stable sensor clock and propagation effects. Independent application-record jitter currently
breaks the otherwise credible sensor-clock relationship that DNS preserves.

### P3 — Correct build and content identity

Derive complete WinSxS paths from native component identity for each build. Reuse a stable object
identity for the same static URL within a publication epoch, and represent updates or CDN variants
with an explicit boundary rather than unrelated per-request content.

### P4 — Broaden human and file vocabulary

Make Linux commands and SMB filenames conditional on operator, role, and host history. This is
lower leverage than the causal and protocol contradictions because plausible operational
explanations remain for repetition.

## Priority Rationale

Proxy and Windows identity issues are first because they are high-volume, exact contradictions at
canonical owners and should lift multiple source families at once. TLS/file provenance and process
lifetimes follow because they expose protocol or fleet-wide fingerprints. Linux inventory and
sensor timing are broad but need more modeling surface. Vocabulary diversity remains last because
it is perceptual and weakly diagnostic until the hard contracts are repaired.

## Comparison with Quantitative Eval

The deterministic evaluator passed the bundle but fell from loop 57's 97.3622 to 96.2817, with
the largest movement in causality and timing after the canonical DNS duration change altered
thousands of flow intervals and downstream occupancy. It caught two orphan HTTP file references,
OCSP identity mismatches, two missing storyline events, and one unrecognized eCAR rename action,
which the panel did not emphasize. It did not detect the repaired DNS/RDP contracts or the new
proxy ordering, TLS history, process identity, process duration, inventory, and analyzer-provenance
findings; rendered probes and blind review remain authoritative for those families.

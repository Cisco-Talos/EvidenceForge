# Iteration Test Blind Assessment — Loop 71

## Outcome

Loop 71 preserved one canonical explicit-proxy HTTP authority and Referer across client, proxy,
and origin evidence. The automated evaluation scored 97.0496 PASS across 124,332 records. Initial
blind synthetic-confidence scores were 44, 97, 89, and 78 (mean 77.0). Verdict disagreement and a
53-point spread triggered deliberation; revised scores were 90, 98, 94, and 90 (mean 93.0), yielding
a unanimous Synthetic panel.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 78 verdict confidence, 44 synthetic-confidence. Strong lifecycle,
pivot, role-sensitive background, and sensor-independence evidence outweighed moderate Linux
cadence/PID texture and a Type 9 versus proxy identity gap before deliberation.

**Detection Engineer:** Synthetic, 95 verdict confidence, 97 synthetic-confidence. Future-dated
software releases, incompatible Teams product/path/version identity, mixed Windows build metadata,
and anonymous proxy policy transitions drove a highly confident verdict.

**Network Forensics:** Synthetic, 94 verdict confidence, 89 synthetic-confidence. The decisive
finding was 416 of 639 uniquely keyed CONNECT tunnels outliving their completed carrying TCP
sessions, including 262 cases with exact bidirectional byte equality. Repeated 600 ms proxy pacing
was a second strong indicator.

**Host/EDR Forensics:** Synthetic, 84 verdict confidence, 78 synthetic-confidence. A universal
one-to-three-frame Sysmon Event 10 trace ceiling, clustered hash/PE metadata omissions, arithmetic
ProcessAccess/retry timing, and awkward archive ordering outweighed excellent endpoint lifecycles.

## Deliberation Findings

Independent verification reproduced the CONNECT lifetime contradiction and proxy pacing counts.
The Threat Hunter moved from Inconclusive to Synthetic; all experts finished in the confidently
synthetic band. Final scores were Threat 90, Detection 98, Network 94, and Host 90 (mean 93.0).

## Fix Verification

- Ninety-seven rendered Zeek/proxy Referer joins had zero disagreements.
- Forty-five cleartext explicit-proxy client/origin HTTP leg joins had zero authority mismatches.
- The six loop-70 Microsoft/CloudFront Host mutations now preserve the client authority on the
  outbound request, and the support curl upload consistently omits its unowned Reddit Referer.
- Behavior revision 35 records surface digest
  `3a3042fa9936afb29d4c885dffe6b13c04a38866bcec70a2b0076fdfd81299ec`.
- The routine gate passed 8,404 tests with 5 skips and 2,009 deselections; repository-wide Ruff
  check and format check passed across 769 files.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The loop-70 proxy authority and Referer contradictions did not recur in any initial report.

## Prioritized Improvements

### P0 — Bound CONNECT tunnels by their carrying TCP lifecycle

Make the client-to-proxy TCP session the authoritative outer interval. Derive tunnel close,
connection close, proxy duration, and byte accounting from one lifecycle and enforce CONNECT setup
plus tunnel duration within the TCP interval.

### P0 — Enforce date- and host-coherent software identity

Compile date-valid per-host application inventories, model classic and new Teams as distinct
products, and keep Windows core binaries within the host's servicing lineage absent explicit
side-loading evidence.

### P1 — Remove the cross-client 600 ms proxy scheduler signature

Use session-level request dependencies, bounded parallelism, persistent reuse, and nonuniform
client/destination-specific delays. Validate run-length and interarrival distributions fleet-wide.

### P1 — Broaden source-native Sysmon enrichment

Vary ProcessAccess stack depth/modules by code path and OS build. Make hash and PE metadata gaps
arise from explicit, independently varying acquisition conditions rather than executable catalogs.

### P2 — Add durable proxy authentication and repair lower-weight contracts

Tie 403/407/200 outcomes to observable policy state and principal transitions. Keep same-sensor
HTTP FUID references atomic, order archive inspection after creation, and clarify Type 9 versus
proxy identity ownership.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.0496: 99.9992 parseability, 96.8577 plausibility, 97.1246
causality, and 92.7714 timing. It did not detect the CONNECT/TCP lifetime contradiction, 600 ms
pacing, future software metadata, shallow call traces, or catalog-shaped enrichment gaps identified
by the panel.

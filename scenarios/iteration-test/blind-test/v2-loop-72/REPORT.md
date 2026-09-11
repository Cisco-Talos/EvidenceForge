# Iteration Test Blind Assessment — Loop 72

## Outcome

Loop 72 bounded every successful explicit-proxy CONNECT tunnel by its exact carrying TCP
transport. The automated evaluation scored 97.0496 PASS across 124,332 records. Initial blind
synthetic-confidence scores were 66, 76, 34, and 32 (mean 52.0). Verdict disagreement and a
44-point spread triggered deliberation; revised scores were 72, 78, 52, and 42 (mean 61.0), leaving
two Synthetic, one Inconclusive, and one Real verdict.

## Individual Expert Summaries

**Threat Hunter:** Synthetic, 70 verdict confidence, 66 synthetic-confidence. Repeated
artifact-before-creation sequences, patterned SMB vocabulary, unexplained service-binary staging,
and one asymmetric SSH lifecycle outweighed strong role-shaped noise and cross-source pivots.

**Detection Engineer:** Synthetic, 88 verdict confidence, 76 synthetic-confidence. The decisive
finding was 120 of 214 nearby same-account/client Kerberos logons preceding their apparent AS
requests. Shallow Sysmon Event 10 stacks, an impossible-looking gzip sequence, literal ICMP history
sentinels, and inconsistent missing eCAR IPs reinforced the verdict.

**Network Forensics:** Real, 78 verdict confidence, 34 synthetic-confidence. Production-like tuple
ownership, DNS cache behavior, protocol timing, independent sensors, packet accounting, and traffic
mix outweighed a systematic success-only TLS analyzer boundary and a small number of dangling file
references.

**Host/EDR Forensics:** Real, 72 verdict confidence, 32 synthetic-confidence. Exact agreement across
971 Windows process starts and coherent Windows/Linux lifecycle evidence outweighed eCAR unlock
identity splits, overlapping local sessions, sparse process volume, and tightly bounded provider
timing.

## Deliberation Findings

Independent checks reproduced the Kerberos ordering split, Event 10 stack ceiling, ICMP sentinel,
TLS publication boundary, gzip sequence, and eCAR unlock identity split. Network moved from Real to
Inconclusive; Host retained Real with lower confidence. Final synthetic-confidence scores were
Threat 72, Detection 78, Network 52, and Host 42 (mean 61.0).

## Fix Verification

- All 642 successful tunnel summaries joined to a client-to-proxy TCP transport.
- Zero advertised tunnel durations exceeded their carrying TCP duration; the smallest remaining
  outer-transport margin was 79 milliseconds.
- Total CONNECT setup plus tunnel byte accounting exactly matched the outer transport in 276 cases,
  with no lifetime contradiction in that high-confidence subset.
- Behavior revision 36 records surface digest
  `315ed77f4389fbff1cd45c4d056eb5fbd930d281d437b9f46f6659c20f0355cf`.
- The routine gate passed 8,405 tests with 5 skips and 2,009 deselections; repository-wide Ruff
  check and format check passed across 769 files.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The Loop 71 CONNECT-overrun contradiction did not recur in any initial report.

## Prioritized Improvements

### P0 — Order fresh Kerberos acquisition before dependent activity

Bind each modeled fresh AS/TGS exchange and port-88 transport to the logon or service use it funds.
Apply source-specific timing without allowing 4768/4769 or the KDC transport to cross after the
successful 4624 or dependent LDAP/service connection. Keep cached-ticket paths distinct.

### P0 — Make artifact state precede successful consumption

Represent creation and compression before successful hash, size inspection, read, or transfer. If
a command intentionally probes an absent or stale path, render the failure or explicit pre-existing
state and preserve overwrite semantics.

### P1 — Broaden Sysmon ProcessAccess stack texture

Vary call-trace depth, module sequences, and offsets by source/target process, access mask, OS build,
and loaded-module state instead of imposing a fleet-wide three-frame ceiling.

### P1 — Model partial TLS analyzer visibility

Permit source-native `established:false` or partial-handshake SSL records for selected recognized
reset/partial flows. Make any analyzer filtering a coherent source-local policy rather than a clean
successful-connection boundary.

### P2 — Repair normalization and lower-weight contracts

Keep one durable eCAR session identity across login, unlock, and logout; omit unavailable JSON
values instead of writing text-log `-` sentinels; preserve HTTP FUID and SMB mapping references
atomically; and anchor operational storage vocabulary to the collection epoch.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.0496: 99.9992 parseability, 96.8577 plausibility, 97.1246
causality, and 92.7714 timing. It did not detect the Kerberos dependency inversions, shallow Event
10 stack grammar, artifact ordering, success-only TLS analyzer boundary, ICMP sentinel, or eCAR
unlock identity split identified by the panel.

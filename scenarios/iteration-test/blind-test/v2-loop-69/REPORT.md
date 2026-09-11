# Iteration Test Blind Assessment — Loop 69

## Outcome

Loop 69 made one continuing Linux session and shell retain the exact original-to-assigned
controlling-terminal route for its lifetime. The automated evaluation scored 97.0499 PASS across
124,332 records. Initial blind synthetic-confidence scores were 44, 76, 65, and 72 (mean 64.25).
Verdict disagreement and the 32-point spread triggered deliberation; revised scores were 68, 78,
72, and 77 (mean 73.75), with a unanimous Synthetic verdict.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive, 79 verdict confidence, 44 synthetic-confidence. The corpus had
strong independent sensor perspectives, disciplined process lifecycles, and credible Windows,
remote-execution, and proxy pivots. A SQL flow preceding its apparent process by 12.1 seconds and
two remote-service authentication/SMB source-port discontinuities prevented a Real verdict.

**Detection Engineer:** Synthetic, 86 verdict confidence, 76 synthetic-confidence. The strongest
findings were a foreign endpoint IP in a local Event 4648 runas chain, Server-2022-era evidence
paired with Event 4698 Version 0, and all 120 SMB tree mappings landing an exact integer number of
milliseconds after connection start. Bounded SSH and Windows-provider timing added support.

**Network Forensics:** Synthetic, 82 verdict confidence, 65 synthetic-confidence. Zeek state,
packet accounting, DNS, TLS, DHCP, proxy failure behavior, and sensor viewpoints were highly
credible. The verdict rested on 29 of 32 cleartext proxy leg pairs sharing the same microsecond end
time and 27 of 59 persistent-HTTP intervals clustering at exactly 600 milliseconds.

**Host/EDR Forensics:** Synthetic, 84 verdict confidence, 72 synthetic-confidence. The loop-68
multi-TTY shell contradiction was absent. Remaining findings included multi-hour reuse of
short-lived Postfix worker PIDs, repeated application/destination mismatches, fixed daemon quotas,
four-value SearchFilterHost arguments, and new eCAR session objects for Windows unlocks.

## Deliberation Findings

The facilitator discounted the SQL inversion as conclusive because its FLOW lacks process identity
and kept missing-companion findings low-weight. The independently verified SMB and HTTP timing
lattices, foreign Event 4648 address, and host state/distribution defects nevertheless moved the
Threat Hunter to Synthetic. Final scores were Threat 68, Detection 78, Network 72, and Host 77
(mean 73.75).

## Fix Verification

- A rendered eCAR/syslog probe correlated 78 sudo command rows across 18 continuing shells and 11
  hosts; every shell used exactly one `pts/*`, with zero violations.
- Two syslog sudo rows without an observed eCAR process-create companion were excluded rather than
  assigned speculative ownership.
- Requested-to-assigned TTY collisions now reuse the exact allocator request pair rather than
  treating the assigned terminal name as a new request.
- Production publication fails closed if one live session attempts to acquire a second controlling
  terminal, while separate concurrent sessions may retain distinct terminals.
- Behavior revision 33 records surface digest
  `a1de251c88268c81cd920a8d23ff49da1ca08eb36b1b35a8d9f6067c2f28f7ff`.
- The routine gate passed 8,402 tests with 5 skips and 2,009 deselections; repository-wide Ruff
  check and format check passed across 769 files.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.

## Prioritized Improvements

### P0 — Break the SMB tree-connect millisecond lattice

Derive each SMB mapping timestamp from source-native packet-stage timing with microsecond texture,
while retaining strict placement after transport establishment and inside the connection interval.
All 120 core mappings currently preserve the connection start's fractional-millisecond residue.

### P1 — Decouple proxy-leg and persistent-HTTP timing

Give proxy ingress and origin legs independent response-drain and FIN timing, and schedule browser
resource requests from dependency, object-size, RTT, cache, and connection-reuse state rather than
a fixed 600-millisecond cadence.

### P1 — Repair canonical Windows identity and session transitions

Populate Event 4648 network fields from the actual caller context and preserve one eCAR USER_SESSION
identity across login, lock, unlock, and logout. Select Event 4698 versions from modeled OS build
capabilities.

### P2 — Model process and daemon lifecycles with entity-scoped entropy

Bound Postfix smtp/smtpd worker reuse, derive SearchFilterHost runtime values from process/host state,
and drive Linux daemon records from role and workload rather than exact per-host quotas.

### P2 — Complete ambiguous transport and file ownership

Attach failed SQL flows to their actual initiating process, carry or explicitly distinguish the
authentication tuple for remote-service continuations, and make sparse FUID/STARTTLS/SMB companion
loss source-locally explainable.

## Comparison with Quantitative Eval

The deterministic evaluator scored 97.0499: 99.9992 parseability, 96.8587 plausibility, 97.1246
causality, and 92.7714 timing. It reflected the complete rendered TTY fix and broad lifecycle
quality, but did not detect the SMB, proxy, and HTTP timing lattices; cross-host Event 4648 ownership;
unlock object discontinuity; Event 4698 platform/schema mismatch; or Postfix and daemon population
texture found by the blind panel.

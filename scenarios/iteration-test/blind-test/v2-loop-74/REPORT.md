# Iteration Test Blind Assessment — Loop 74

## Outcome

Loop 74 made canonical Zeek file-analysis provenance agree with every rendered digest. The
automated evaluation scored 96.4776 PASS across 127,848 records. Initial blind
synthetic-confidence scores were 47, 74, 84, and 66 (mean 67.75). Verdict disagreement and a
37-point spread triggered deliberation; final scores were 69, 80, 82, and 74 (mean 76.25), with
all four experts converging on Synthetic.

## Individual Expert Summaries

**Threat Hunter:** Initially Inconclusive, 82 verdict confidence, 47 synthetic-confidence. Strong
attack ordering and cross-source lifecycles were offset by cloned Linux service texture,
MicroK8s/snapd activity across unrelated roles, broad unauthenticated Wget proxy traffic from the
log monitor, role-scaled Type 5 logons, and a fleet-wide sysstat lattice.

**Detection Engineer:** Synthetic, 86 verdict confidence, 74 synthetic-confidence. Two sub-1.2-ms
Windows lock/unlock cycles lacked the Type 7 logon present in normal unlocks. Durable resolver TCP
fallback state contradicted subsequent same-PID UDP DNS, and resolver messages appeared at an
exact four-per-host quota.

**Network Forensics:** Synthetic, 90 verdict confidence, 84 synthetic-confidence. The decisive
finding was repeated disagreement between inspected-proxy tunnel counters and same-tuple Zeek
payload, including 118 gross cases. Quantized client timing, CONNECT alerts without Zeek HTTP
analysis, and narrower file/certificate-reference gaps reinforced the verdict.

**Host/EDR Forensics:** Synthetic, 82 verdict confidence, 66 synthetic-confidence. The reviewer
independently found both impossible lock/unlock cycles, executable Crashpad helpers rendered as
module loads, seven in-window SSH sessions with only close-side syslog, and OpenSSH process/file
ownership errors.

## Deliberation

Direct review confirmed a cited zero-loss proxy/Zeek mismatch and the repeated Windows unlock
defect. It also found packet loss on all 39 TLS rows cited for missing certificate chains, reducing
that issue's weight. Final synthetic-confidence scores were Threat Hunter 69, Detection Engineer
80, Network Forensics 82, and Host/EDR 74. The final verdict was unanimously Synthetic.

## Fix Verification

- 2,097 Zeek file rows were checked; all 1,244 rows with a digest declared every corresponding
  analyzer, with zero provenance violations.
- Digest-bearing rows included 1,083 SSL, 97 SMB, 45 HTTP, and 19 SMTP observations.
- Behavior revision 38 records surface digest
  `830a3f817076b6db4edeb1b1234236b8d94a977494041326ea42adcf91598aed`.
- The routine gate passed 8,409 tests with 5 skips and 2,009 deselections; focused Zeek, SMB,
  storage, observation, and behavior-manifest tests and Ruff checks passed.
- Configuration validation passed all 92 files, and scenario validation retained only the existing
  24 informational pivot notes.
- The Loop 73 orphan-digest provenance defect did not recur in any expert report.

## Prioritized Improvements

### P0 — Reconcile inspected-proxy and transport byte accounting

Give the explicit-proxy tunnel and its client TCP transport one byte ledger. Define control,
decrypted request, tunneled payload, and framing scopes, then derive both proxy counters and Zeek
payload from that shared truth across reuse, observation, closure, and recovery paths.

### P0 — Make Windows lock/unlock one guarded lifecycle

Generate 4800, same-session Type 7 4624, and 4801 from one action bundle. Enforce a human-scale
locked interval and preserve the same LogonID and source-native ordering.

### P1 — Make resolver fallback state durable

Keep each host/resolver pair on TCP after a fallback transition until an explicit modeled recovery
or probe succeeds. Derive transition messages from actual DNS outcomes instead of fixed quotas.

### P1 — Correct endpoint ownership and SSH observation

Represent Crashpad as a child process, keep OpenSSH monitor and user process identities separate,
and make retained SSH open/auth/close observations lifecycle-coherent.

### P1 — Remove cloned and quantized background texture

Vary Linux daemons and schedules by installed role, reduce dominant repeated messages, tie
MicroK8s and Wget activity to observable workloads, and replace fixed resolver and client cadences
with stateful per-entity timing.

## Priority Rationale

The panel's strongest high-frequency cross-source defect was the inspected-proxy/Zeek byte
disagreement: 430 of 719 joined tunnels differed and 118 were gross mismatches. Loop 75 therefore
targets the shared proxy transport ledger before the lower-volume but independently corroborated
Windows unlock family.

## Comparison with Quantitative Eval

The deterministic evaluator scored 96.4776: 99.9992 parseability, 96.8531 plausibility, 94.4742
causality, and 93.2302 timing. It did not flag the proxy accounting conflict, sub-millisecond
unlock cycles, resolver-state contradiction, endpoint semantic errors, or cloned environmental
texture identified by the panel.

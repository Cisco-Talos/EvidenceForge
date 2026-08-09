# Loop 44 Assessment Report

Loop 44 generated 83,707 entirely new records after enforcing canonical reuse
of named Windows singleton services. Automated evaluation scored 96.0256 and
failed only pivot linkability. A lifecycle probe found 28 named `svchost`
creations across 28 distinct host/service pairs and zero overlapping live
instances; none of the fresh reviewers repeated Loop 43's singleton defect.

The initial blind panel was Real/Synthetic/Synthetic/Synthetic at 29/89/72/58,
average 62.0. Verdict disagreement and a 60-point spread triggered deliberation.
After checking the current evidence, all four converged on Synthetic at
88/94/91/92, average 91.25, with consensus verdict confidence 96.

## Individual Expert Summaries

The Threat Hunter initially assessed Real (76% verdict confidence,
synthetic-confidence 29). It found the audit-log reset, scan, SSH/SCP chain,
sensor variation, and role-shaped baseline exceptionally convincing; its
residual concerns were repeated Linux command texture and absent NTP.

The Detection Engineer assessed Synthetic (97%, 89). It found multiple software
versions that postdate the March 2024 evidence clock, different full hash sets
for nominally identical vendor builds installed under different usernames, and
all 325 Type 5 logons setting `WorkstationName` to the local host.

The Network analyst assessed Synthetic (80%, 72). It found no CNAME aliases in
any A/AAAA answer vector, near-metronomic per-client DHCP renewal cadence, and a
thin infrastructure UDP tail, while rating transport, TLS, proxy, firewall, and
dual-sensor correlation highly.

The Host/EDR analyst assessed Synthetic (84%, 58). It proved that
`WS-AJOHNSON-01` PID 5232 performs an explicit-credential operation more than
31 seconds after Security, Sysmon, and eCAR all terminate it without PID reuse.
Repeated desktop SSH launches and generic Linux `wget` ownership were
supporting texture.

## Deliberation Findings

The panel concluded that production-like correlation demonstrates substantial
generator sophistication but cannot outweigh three hard contradictions:
cross-vendor future versions, path-correlated same-build hashes including
IMPHASH, and dead-process credential ownership. The initial Real verdict changed
after these specialist findings were verified against the anonymous corpus.

## Prioritized Improvements

- **P0 — Derive hashes from canonical binary artifact identity.** The same
  product/build/architecture/language must retain the same byte-derived hashes
  regardless of username, host, or installation path.
- **P0 — Make software inventory time-aware.** Version selection and QA must
  reject builds whose release/signing date postdates the scenario clock.
- **P0 — Enforce caller-process liveness.** Credential and dependent events must
  precede canonical and rendered termination unless explicit PID reuse creates
  a new process identity.
- **P0 — Correct Type 5 logon field semantics.** Render workstation, network
  address, port, process, and authentication package from a source-native
  Event-ID/logon-type matrix.
- **P1 — Expand DNS, DHCP, and infrastructure texture.** Model CNAME chains,
  coherent T1/T2 renewals with realistic disturbance, and role-aware NTP and
  discovery traffic.

## Comparison with Quantitative Eval

Automated evaluation passed strict schema, format, IDS, field-agreement, intent,
and causal-ordering gates. It does not yet encode software release chronology,
binary-content identity, caller liveness across projected sources, or Type 5
field matrices. Its only acceptance failure remained pivot linkability at
51.6129, so the blind panel again found semantic defects outside the aggregate
quality score.

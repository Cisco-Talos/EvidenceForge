# Iterative assessment loop 12

## Outcome

Loop 12 repaired public TLS issuer selection at the data/configuration owner. Domain overrides
now obey event-time certificate-authority validity; an expired override falls back to the
currently valid weighted issuer pool. The `*.reddit.com` mapping now points to Let’s Encrypt YR1,
and the current YR1/YR2 and Root YR chain profiles are represented. Behavior revision 411 records
the change.

Focused issuer tests passed (60), including current Reddit selection and expired-override
fallback. `eforge validate-config` reported 0 errors and one pre-existing Chrome Helper catalog
warning. Ruff check and format and the behavior manifest check passed.

Fresh generation at `/private/tmp/eforge-iteration-test-macos-loop-12` produced 133,895 records
and passed one JSON evaluation at 96.664682 (parseability 100, plausibility 96.7813, causality
96.2893, timing 91.9852). Acceptance passed. All 115 data files matched their manifest SHA-256
in the read-only blind copy.

## Family probes

| TLS probe | Count |
|---|---:|
| SSL sessions with linked leaf | 623 |
| Leaf valid at SSL event time | 623 |
| SSL sessions with linked issuer | 564 |
| Issuer names matching leaf issuer | 564 |
| Linked issuer cert valid at SSL event time | 564 |
| Reddit SSL sessions | 3 |

All three Reddit sessions now identify the leaf issuer as YR1. Their observed times fall within
the leaf validity window. These three records do not export an intermediate FUID, so the chain
probe validates every issuer certificate that is present in output rather than inferring an
unobserved issuer record.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 67 | 48 |
| Detection Engineer | Inconclusive | 70 | 46 |
| Network Forensics | Inconclusive | 58 | 36 |
| Host/EDR Forensics | Inconclusive | 68 | 32 |
| **Mean** | **inconclusive** | **65.75** | **40.5** |

No deliberation trigger was met. The panel found broad cross-source coherence and no decisive
contradiction. New candidates are the DB root history that begins before the only visible root SSH
session, repeated external scans against one DMZ host, a sampled Windows Security 4688 without a
Sysmon Event 1 counterpart, and sparse Mac Unified Log coverage. Treat the first as unproven until
session ownership is traced; the others remain weak or collection-dependent signals.

## Prioritized findings

1. **P1 — Public TLS issuer was expired at event time (`schema_or_format`).** Fixed at issuer
   selection and configuration. The fresh family probe verifies all 564 linked issuer certs are
   valid at their SSL timestamps, with no issuer-name mismatch.
2. **P2 — Root history inspection commands precede the visible SSH root session (`contract_gap`).**
   The final `df -h /tmp` is 0.3 seconds before an SSH connection; prior root commands start about
   40 seconds earlier. A separate or pre-existing shell is plausible because shell history is
   user-scoped, so verify ownership before changing SSH or shell-history generation.
3. **P3 — Repeated DMZ scan concentration, one unmatched Windows 4688, and sparse Mac Unified Log
   rows.** These findings lack enough collection policy or lifecycle evidence for a safe root-cause
   fix in this loop.

The total count is 5.2% lower than loop 11, with a 0.216-point evaluation decrease; acceptance
still passes and each evaluator pillar remains above 90. The changes in the compiled effective
configuration are limited to TLS issuer/authority data, so this volume shift is recorded for
trend monitoring rather than treated as a confirmed defect.

Loop 12 is **complete**. Reports, the one evaluation, family probes, family contract, and scores
are saved under this directory.

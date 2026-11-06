# Loop 17 Expert Panel Deliberation

**Scope:** Facilitator review of the four saved independent reports and the bounded root-cause probe.

## Cross-examination

Threat Hunter and Detection Engineer were Inconclusive; Network and Host/EDR were Synthetic. Scores were 53, 27, 63 and 67 (mean 52.5; 40-point spread), so deliberation was required. The network and host reports describe distribution texture and environmental concerns; the threat report emphasizes coherent activity and treats the temp-file chain as a bounded concern. Detection found the bundle broadly usable and did not establish a contradiction.

The direct probe verifies one real issue: PowerShell `Test-Connection` and `Get-EventLog` processes are paired with generic temp writes. The loop-17 change only guarded baseline ambient file churn; generation still produced these rows through process-execution preflight. This is a confirmed incomplete root-cause fix, not reviewer variance. The fix must cover both selectors before the family can be called resolved.

## Modeled revised positions

| Expert | Initial verdict | Initial confidence | Initial score | Revised verdict | Revised confidence | Revised score |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 72 | 53 | Inconclusive | 70 | 55 |
| Detection Engineer | Inconclusive | 68 | 27 | Inconclusive | 68 | 35 |
| Network Forensics | Synthetic | 82 | 63 | Synthetic | 76 | 60 |
| Host/EDR Forensics | Synthetic | 82 | 67 | Synthetic | 76 | 58 |

Revisions acknowledge that cross-source process/file correlation is internally consistent while the generic PowerShell temp attribution remains semantically weak. These are facilitator-modeled positions, not additional blind submissions.

## Summary

The modeled revised mean synthetic-confidence is 52.0, with mean verdict confidence 72.5. Loop 18 must fix the shared process-side-effect admission and retain the baseline guard, then verify zero PowerShell temp writes for read-only command lines across all Windows hosts.

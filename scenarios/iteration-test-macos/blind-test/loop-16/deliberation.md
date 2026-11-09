# Loop 16 Expert Panel Deliberation

**Scope:** Facilitator review of the four saved blind reports. This does not independently re-score the generated bundle.

## Cross-examination

The reviewers disagree on whether the macOS process identity pattern is defective. The Detection Engineer calls changing `pidversion` across exec notifications a hard contradiction. Official Apple Endpoint Security documentation describes the exec event's process and target as before/after views of the same process and states that the audit token's `pidversion` is updated on exec. That claim is therefore not a confirmed defect and must not drive a fix. The other concrete concerns are the unexplained Windows PowerShell temporary-file write and repetitive macOS shell discovery activity, including `cat` use against office documents. Network review found no concrete contradiction.

The temp-file observation links a PowerShell `Test-Connection` process to a later write of a randomized `.tmp` file, with agreement between Sysmon and eCAR. It merits owner-level tracing, but the reports do not yet establish whether the process-to-file relationship is wrong or whether an intermediate action was omitted. Repeated Mac shell commands are a texture signal; they need a source trace to distinguish scenario-authored commands from baseline command pools.

## Modeled revised positions

| Expert | Initial verdict | Initial confidence | Initial score | Revised verdict | Revised confidence | Revised score |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Synthetic | 68 | 61 | Synthetic | 62 | 57 |
| Detection Engineer | Synthetic | 86 | 74 | Synthetic | 78 | 66 |
| Network Forensics | Inconclusive | 68 | 27 | Inconclusive | 68 | 33 |
| Host/EDR Forensics | Synthetic | 82 | 65 | Synthetic | 78 | 61 |

The facilitator modeled modest score reductions because the reported process identity concern is contradicted by Apple's event semantics, while retaining the Synthetic verdicts based on the separate temp-file and host-texture concerns. These are deliberation estimates, not new blind submissions.

## Summary

Initial mean synthetic-confidence was 56.75, verdict-confidence 76, and score spread 47; verdict disagreement and spread triggered deliberation. Revised mean synthetic-confidence is 54.25 and verdict-confidence 71.5. The panel remains mixed on evidentiary strength. The loop-17 target should come from canonical owner tracing of one of the independently described anomalies; do not alter macOS pidversion semantics based on the Detection Engineer report.

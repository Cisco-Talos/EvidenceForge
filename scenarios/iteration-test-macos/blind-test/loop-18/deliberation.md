# Loop 18 Expert Panel Deliberation

**Scope:** Facilitator review of the four saved independent reports and the bounded output probe.

## Cross-examination

Threat Hunter remains Inconclusive while the other three reviewers choose Synthetic. The main disagreements are about how much weight to assign to repeated macOS shell commands and timestamp clustering, thin Unified Log coverage, and a network schema pattern (DMZ Zeek `duration` and `service` omissions) that Detection did not establish as a source-native violation. The reviewers describe strong Windows process joins, Mac SSH tuple/authentication agreement, DNS/Zeek UID integrity, and realistic protocol variation.

The loop-17 PowerShell temp-file family is fixed in loop 18's fresh output: both the process-preflight side effect selector and baseline churn now reject generic temp effects for read-only PowerShell commands, while the output-command test preserves `Export-Csv` artifacts. This is supported by focused tests and a bundle-wide probe, not merely the reviewer sample.

Host/EDR's report flags a Mac SSH receiver shell event before the matching `Accepted publickey` Unified Log row and eCAR session login. This is a concrete ordering concern; the shell exec timestamp is 16:02:17.723Z, Unified Log acceptance 16:02:18.539Z, and eCAR login 16:02:19.207Z. The SSH action bundle owns receiver startup and authentication timing, so loop 19 will verify the canonical lifecycle and fix the common timing plan if it reproduces there.

## Modeled revised positions

| Expert | Initial verdict | Initial confidence | Initial score | Revised verdict | Revised confidence | Revised score |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 74 | 46 | Inconclusive | 72 | 50 |
| Detection Engineer | Synthetic | 80 | 56 | Synthetic | 76 | 59 |
| Network Forensics | Synthetic | 78 | 64 | Synthetic | 74 | 62 |
| Host/EDR Forensics | Synthetic | 84 | 69 | Synthetic | 76 | 71 |

These are modeled scores after cross-examination, not new blind submissions. Revised means are 60.5 synthetic-confidence and 74.5 verdict confidence.

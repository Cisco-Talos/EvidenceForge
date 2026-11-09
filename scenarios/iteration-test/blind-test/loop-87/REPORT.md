# Loop 87 — Authenticity Assessment

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive (verdict confidence 78; synthetic-confidence 34). Confirmed coherent endpoint/network paths for a support upload and a database export relay. Regular sysstat timing is weak and compatible with cron.
- **Detection Engineer:** Inconclusive (72; 34). Windows, Zeek and macOS structures appear plausible. All eCAR files are timestamp sorted, a weak signal also compatible with an ordered export; no source-format defect was found.
- **Network Forensics Analyst:** Inconclusive (70; 24). Zeek UID/tuple and timestamp relations are coherent. Repeated counts across core/DMZ paths remain uncertain without sensor-placement metadata.
- **Host/EDR Forensics Analyst:** Inconclusive (76; 26). Process IDs, parentage, LogonIds, Linux session lifecycle, and macOS SSH tuple/authentication align in examples. eCAR sorting is weak normalization texture, not a proven defect.

## Prioritized Improvements

- **P3 — eCAR chronological ordering.** Detection and Host/EDR observed nondecreasing timestamps in per-host streams. This can reflect an ordered export and neither reviewer found an impossible event relationship. Scope is dataset-wide but low leverage; verify intended source/export semantics before considering any latency or ordering change.
- **P3 — repeated core/DMZ paths.** Network reviewer noted near-equal counts for some internal paths. Overlapping vantage points may explain this; no tuple or protocol contradiction was identified. Resolve against sensor placement only if external provenance data is available.
- **P4 — scheduled sysstat cadence.** Threat Hunter found ten-minute repetitions compatible with the configured schedule. No generator change indicated.
- **P4 — Citrix installer download to DC-02.** Loop87's focused trace confirmed a complete proxy transfer and matching file hash, but found no endpoint execution record. Transfer alone is not installation or execution; no source gap is proven without a required endpoint-observation contract.

No P0–P2 family-level fix is supported.

## Priority Rationale

The eCAR ordering signal appeared in two independent reports, so it leads the list for source-semantic verification, but the evidence is weak and plausibly explained by normalized export. The other findings are isolated and do not demonstrate hard contradictions or impossible behavior.

## Comparison with Quantitative Eval

Evaluation remains **96.2810/100 PASS**, **148,787 records**, with parseability 100.00, plausibility 96.86, causality 95.03 and timing 91.54. Reviewers raised collection/export interpretation and repeated-path context that quantitative scoring does not directly adjudicate. No evaluator finding was disputed by the panel.

## Loop Decision

No generation or scenario change. The focused Citrix trace verified a complete 124,385,593-byte transfer across Zeek/proxy records, but no execution claim is established. Mean standalone synthetic-confidence was **29.50**, compared with 23.50 in Loop86 on the same output; this six-point increase is reviewer variance, not a data change. All four reviewers were Inconclusive, so deliberation was not triggered. Loop88 is the final requested fresh review and dashboard pass.

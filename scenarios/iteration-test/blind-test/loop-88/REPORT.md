# Loop 88 — Authenticity Assessment

## Individual Expert Summaries

- **Threat Hunter:** Synthetic (verdict confidence 78; synthetic-confidence 69). Cited aligned six-hour source bounds, concentrated DC account/service activity and login failures. No hard contradiction; cautioned against assigning SYSTEM actions to nearby users. One described 15:06 event as following 15:59 failures, but the Security XML confirms it precedes them.
- **Detection Engineer:** Synthetic (86; 68). Found plausible schemas and joined process/network/upload evidence, but judged the aligned collection window, high Windows network-event volume, and very explicit upload chain as synthetic texture. No impossible field or order was found.
- **Network Forensics Analyst:** Synthetic (78; 67). Identified concentration in DB MySQL flows and persistent external scans to one DMZ target. TCP states, counters, sensor views, DNS, HTTP and TLS were otherwise credible.
- **Host/EDR Forensics Analyst:** Synthetic (76; 64). Found Windows/Linux/macOS process, session and SSH correlations. Its strongest concern—reused macOS `traceID` values—was checked after the blind review and is a false positive: in this model `traceID` identifies a static logging callsite, not an occurrence/activity. Sparse Unified Log and dense Windows network events remain collection-profile questions.

## Deliberation Findings

Deliberation was not triggered. All four verdicts were Synthetic, mean verdict confidence was 79.5, and synthetic-confidence scores spanned five points.

## Prioritized Improvements

- **P3 — DC-01/DC-02 network and database concentration.** Network reviewer observed 291/478 DB flows on one MySQL source/destination pair and sustained DMZ probes against one host. This is distribution texture, not a hard contradiction. Compare with expected sensor placement and exposure/workload before changing source traffic profiles. Scope is specific sensor/target, leverage medium, owner is network activity/configuration, and fix risk medium.
- **P3 — Fleet-wide six-hour source window.** Threat and Detection reviewers flagged similar bounds across sources; a configured export window is a plausible alternative. Confirm whether this is expected benchmark collection scope before modeling per-source boundary jitter. Scope dataset-wide, leverage low-to-medium, owner is observation/collection profile, fix risk medium.
- **P4 — DC-01 privileged account/service activity and workstation failures.** Threat Hunter highlighted the account/service changes and failures as leads; visible records are coherent, and authorization is outside the logs. Retain for hunting context; no generation correction is supported.
- **P4 — Sparse Mac Unified Log and dense DC WFP/Sysmon network rows.** Host and Detection reviewers noted the coverage imbalance/event volume. These are compatible with source-specific filters and audit policy; verify against collection configuration before altering coverage.
- **False positive excluded — macOS callsite `traceID` reuse.** Host reviewer interpreted two repeated values as cross-host activity identity. Static callsite encoding means reuse is expected; this is not a contract gap.

No P0–P2 fix is supported. Reviewers did not assign original P0–P4 ratings; the priorities above are synthesis ratings.

## Priority Rationale

The DB-pair/DMZ-probe distribution is the strongest concrete texture observation and spans many rows, so it leads for contextual review. The common collection window and coverage imbalance may reflect collection design. The traceID concern is excluded after semantic verification. No reviewer found an impossible source-native event, and the threat report's “easy to pivot” impression is not counted by itself.

## Comparison with Quantitative Eval

Evaluation remains **96.2810/100 PASS** over **148,787 records** (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54). The expert panel emphasizes distribution texture, operational concentration and collection scope that the deterministic evaluator does not directly score. No parser or acceptance defect was raised.

## Loop Decision

No generation or scenario change. The final panel mean is **67.00**, up 37.50 points from Loop87 on a byte-identical dataset. The increase comes from reviewer interpretation of concentrated scans/database flows and shared collection bounds, not a data change. Loop88 closes the requested 20-loop assessment set; retain these as contextual investigation questions, not confirmed generator defects.

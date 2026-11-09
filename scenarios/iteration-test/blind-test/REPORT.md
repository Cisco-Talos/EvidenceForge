# Iteration-test assessment loops 69–88

Completed the requested 20 assessment loops. Loops 69–84 include targeted root-cause repairs with fresh validation/generation where behavior changed. Loops 85–88 reviewed unchanged, byte-identical output after probing candidate findings; no scenario changes were made. The final four panels' scores vary substantially on identical data, so standalone movement is reviewer variance rather than evidence of a repair effect.

## Past 10 Loops

Standalone reviewer scores are synthetic-confidence (lower is more production-like). The five-loop rolling average excludes deliberation scores.

| Loop | Eval | Threat | Detection | Network | Host/EDR | Avg blind | Interpretation | Deliberation | Rolling5 |
|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 79 | 96.56 | 34 | 69 | 24 | 78 | 51.25 | mixed/inconclusive | 51.00 | 45.75 |
| 80 | 96.56 | 78 | 68 | 54 | 48 | 62.00 | likely synthetic | 58.25 | 46.65 |
| 81 | 96.56 | 42 | 68 | 64 | 48 | 55.50 | mixed/inconclusive | 67.50 | 46.80 |
| 82 | 96.56 | 68 | 72 | 62 | 36 | 59.50 | mixed/inconclusive | 65.50 | 51.50 |
| 83 | 96.28 | 53 | 76 | 68 | 36 | 58.25 | mixed/inconclusive | 62.50 | 57.30 |
| 84 | 96.28 | 67 | 46 | 27 | 39 | 44.75 | mixed/inconclusive | 39.50 | 56.00 |
| 85 | 96.28 | 52 | 47 | 66 | 34 | 49.75 | mixed/inconclusive | 50.50 | 53.55 |
| 86 | 96.28 | 29 | 19 | 28 | 18 | 23.50 | mostly realistic | — | 47.15 |
| 87 | 96.28 | 34 | 34 | 24 | 26 | 29.50 | mostly realistic | — | 41.15 |
| 88 | 96.28 | 69 | 68 | 67 | 64 | 67.00 | likely synthetic | — | 42.90 |

Automated evaluation remained PASS for loops 79–88. The reviewed output in loops 85–88 is unchanged from loop84: 148,787 records, score 96.2810 (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54). The final standalone mean rose 37.50 points from loop87 to loop88 without a data change; expert interpretation of concentration and collection boundaries changed. The rolling five-loop average ends at 42.90.

## Final Findings and Recommendations

| Priority | Issue | Category | Original rating | Scope / next action |
|---|---|---|---|---|
| P2 | Concentrated DB MySQL pair and sustained probes to one DMZ host | distribution_texture | not labeled | Compare against intended DB workload, exposed services and sensor placement before changing traffic profiles. |
| P3 | Similar six-hour collection bounds across sources | environment_or_collection_plausibility | not labeled | Confirm whether this reflects the benchmark export window; model source-specific boundaries only if the collection contract requires them. |
| P3 | Windows network-event volume and sparse Mac Unified Log | distribution_texture | not labeled | Check against configured audit and collection profiles; absence/volume alone does not establish a defect. |
| P4 | DC-01 privileged account/service changes and workstation failures | weak_signal | not labeled | Retain as hunting leads; establish authorization from external context and avoid attribution by temporal proximity. |
| Excluded false positive | Reused macOS Unified Log `traceID` values | contract_gap | not labeled | `traceID` is a modeled static callsite/tracepoint identifier, not an occurrence/activity ID; reuse across hosts using the same executable callsite is expected. No code change. |

No P0–P1 generator defect was established in loops 85–88. The high-impact events are internally coherent but do not establish authorization. The large Citrix installer transfer to DC-02 is proven at the Zeek/proxy layer; execution is not. DC-01 WMI commands are attributed to SYSTEM and the authored scenario does not require a remote initiator. eCAR timestamp ordering is intentional chronological flat-file sorting.

## Assessment Effectiveness Dashboard

The chart uses standalone reviewer synthetic-confidence scores only. It shows reviewer-specific scores, a five-loop rolling average, heatmap, loop deltas, and reviewer disagreement band.

![Assessment effectiveness, loops 69–88](assessment-effectiveness-dashboard-last-20-loops.svg)

## Prior Artifacts

- [Loop worklog](../../../docs/worklog/2026-11-08-iteration-test-loops69-88.md)
- [Loop 88 final report](loop-88/REPORT.md)
- [Previous assessment report, loops 64–68](REPORT-loops64-68.md)
- [Scores and reviewer reports](loop-88/scores.json)

# Loop 84 — typed Linux pipeline parent lifecycle

Loop 84 completed validation, generation, quantitative evaluation, a family probe, and four independent blind reviews. The authoritative bundle contains **148,787 records** and scores **96.2810 PASS** (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54), unchanged from loop83. The final generated data and neutral review copy were recursively identical.

## Fix and verification

The selected family is typed Linux shell pipeline lifecycle. The owning layer is the typed storyline process-termination flush, using the existing pipeline group identity and each child’s canonical foreground finalizer. The invariant is that a shell parent cannot close before any still-running child in its exact `storyline-linux-pipeline:<host>:<shell-pid>:` group; unrelated children must not delay it. Typed storyline process expansion creates the group members; the deferred termination queue owns their close order; the process finalizer supplies dependent transport deadlines; eCAR, syslog, and process state consume the resolved timing. Baseline/catalog pipelines continue through their existing planner and are outside this typed adapter change.

Loop83 had confirmed the final Bash child owned the reverse callback FLOW and outlived it, while the outer shell closed first. The first loop84 implementation attempted to extend the parent finalizer during connection-hold propagation but rendered the same parent timestamp, so it was replaced before acceptance with a deadline check at queued parent-close time. The final probe now shows WEB-EXT-01 root PID 2702831 creates base64 PID 2702832 and final Bash PID 2702833; the callback FLOW belongs to 2702833 at 14:20:21.349Z; the final child closes at 14:20:35.700Z; the parent closes at 14:20:36.690Z (990 ms later). An unrelated non-pipeline child is explicitly excluded by the focused test.

This is a **family-level fix for typed storyline Linux pipeline parents**, adapted into the existing shared pipeline parser/finalizer. It does not alter shell pipelines from other activity sources. Revision 498 records `hold-typed-linux-pipeline-parent-through-dependent-child` in the generation behavior manifest.

## Blind panel

Standalone synthetic-confidence scores: Threat Hunter **67** (Synthetic, verdict confidence 73), Detection Engineer **46** (Inconclusive, 64), Network Forensics **27** (Real, 67), and Host/EDR Forensics **39** (Inconclusive, 63); mean **44.75**, spread **40**. The verdict split and spread triggered deliberation. Final deliberative mean was **39.50**, but the panel preserved all three verdicts; these revised scores are facilitator judgments, not re-measurements.

The Threat Hunter cited the high-impact `DB-PROD-01` clinical data export/hidden staging command and a rapid `DC-01` account creation/password reset/Domain Admin addition. These are plausible but consequential actions, not proven source-native contradictions. Detection and Host raised sparse Mac Unified Log coverage and high Windows Security/Sysmon matching; both remain ambiguous collection-shape observations under the review guidance. Network confirmed the subnet scan is owned by visible `nmap` process/FLOW evidence. Reports did not identify a concrete Kerberos reversal or any other impossible ordering. Loop83’s same-user/client-port 4769→4768 sample remains **unproven as a single transaction** without shared canonical transport identity, so no source-timing change was selected.

## Combined findings and next work

| Priority | Finding | Category | Reviewer(s) | Scope / status |
|---|---|---|---|---|
| P2 | Typed pipeline parent closed before transport-owning child | `contract_gap` | Loop83 Host/EDR probe; confirmed by implementation probe | Single family path; fixed and rendered probe verifies child-first closure |
| P3 | Clinical DB export and Domain Admin account sequence are unusually concentrated | `environment_or_collection_plausibility` | Threat Hunter | Scenario-correlated, technically possible; no generator change justified from this review |
| P4 | Mac Unified Log is sparse beside Endpoint Security | `environment_or_collection_plausibility` | Detection Engineer | Two hosts; could reflect filtering/retention; collection scope is undocumented in data |
| P4 | Near-complete Security 4688/Sysmon 1 pairing | `weak_signal` | Host/EDR | Dataset sample; correlation quality alone is not a defect |

The internal scan and near-complete source joins are not counted as synthetic tells: endpoint evidence identifies the `nmap` process and complete correlation alone is outside the scoring criteria. There is no consensus change request beyond the pipeline lifecycle repair. Keep the Kerberos family as a probe candidate only if the next review supplies a transaction-level match.

## Validation

- Scenario validation: valid; existing 28 advisory items remain.
- Focused typed-pipeline tests: **3 passed**.
- `ruff check .`: passed.
- `ruff format --check .`: passed after formatting the new test.
- Generation behavior manifest: current at revision 498 with digest `1f6ce29f7a60925737a9e9027c15062301066631c3cb2809c54c5fbda9669ce5`.
- Human-readable and JSON eval: **96.2810 PASS**, 148,787 records.
- Standalone review: four fresh reviewers on neutral data-only copy; output matches the generated data.
- Deliberation: triggered due to verdict disagreement and score spread; no forced consensus.
- A/B comparison: not run.

Artifacts: `family-contract.md`, `kerberos-timing-contract.md`, `pipeline-lifecycle-probe.json`, `eval-human.txt`, `eval_results.json`, `scores.json`, four reviewer reports, and `deliberation.md`.

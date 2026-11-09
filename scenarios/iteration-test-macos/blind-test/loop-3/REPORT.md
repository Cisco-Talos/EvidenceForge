# Loop 3 — Iterative assessment

## Results

| Measure | Result |
|---|---:|
| Automated eval | 96.29796 / PASS |
| Records | 138,383 |
| Threat Hunter synthetic-confidence score | 86 |
| Detection Engineer synthetic-confidence score | 48 |
| Network Forensics synthetic-confidence score | 72 |
| Host/EDR synthetic-confidence score | 48 |
| Average blind synthetic-confidence score | 63.5 — likely synthetic |
| Prior loop average | 79.5 |
| Change | −16.0 points; meaningful improvement, with reviewer disagreement |

All verdict confidences are separate from synthetic-confidence scores. The verdicts split: Threat Hunter and Network Forensics assessed Synthetic; Detection Engineer and Host/EDR assessed Inconclusive. Average verdict confidence was 73.75 and the synthetic-confidence range was 38 points, so the required deliberation ran. Its facilitator-proposed calibrated scores are documented separately and are not substituted for independent reviewer scores.

## Loop 3 fix and verification

### Authoritative macOS process-close cadence

- **Classification:** `family_level`.
- **Owner:** `ActivityGenerator._plan_generic_logoff_process_closes`, which creates canonical process termination times before native ES and eCAR projections.
- **Invariant:** independent process closes in authoritative Mac session shutdown plans receive deterministic, process-scoped bounded variation while every close remains after activity/dependencies, preserves parent/child ordering, respects connection holds, and precedes the exact session deadline.
- **Entry paths:** generic local Mac logoff from typed storyline and baseline/session finalizers; all consumers using the shared generic process-close planner.
- **Consumers:** canonical StateManager/lifecycle state, Endpoint Security exit rows, eCAR process termination, ground truth and evaluation chronology.
- **Why this layer owns the truth:** the repeated 100 ms staircase originated in the canonical planner; emitter-only timestamp changes would leave shared process state and sibling sources on the same cadence.
- **Change:** the Mac branch samples deterministic jitter from `timing_profiles.yaml`, capped at ±30 ms and 35% of the existing slot. Existing ordering/deadline constraints still apply. Behavior revision 401 records the change.
- **Verification:** focused test covers bounds, process-scoped variation and determinism; behavior-manifest and config validation pass; Ruff check/format pass; complete generation succeeds with main scenario Mac coverage. The generated two-host ES output has 94 process-exit rows and no adjacent exact-100 ms intervals. Reviewers still noticed short exit clusters near the visible boundary, which remain plausible shutdown behavior and may merit further bounded validation.
- **Residual risk:** the close span remains intentionally bounded by the existing authoritative shutdown window; review whether lifecycle evidence supports broadening it before changing that contract.

## Prioritized findings

| Priority | Finding and reviewer ratings | Classification | Scope and leverage | Owner / next action |
|---|---|---|---|---|
| P1 | Successful SMB write for `rpt_0318.sql.gz` is represented as a zero-byte Zeek transfer despite prior gzip creation and SCP read evidence (carried from loop 2; loop 3 Threat Hunter again noted the gzip/SCP sequence) | `sibling_defect`, pending confirmation of canonical artifact size across the transfer chain | One concrete artifact across multiple canonical transfer stages; high if size mismatch is confirmed | Inspect gzip artifact identity, SCP-to-APP transfer, SMB mutation and file-content context; fix the owning transfer contract if the source is non-empty. |
| P2 | Similar macOS inventory-command families recur across both user histories and ES events (Threat Hunter 86, Host 48) | `false_positive_or_unproven` as an engine defect; the visible routine is explicitly authored in the scenario | Two authored Mac histories, moderate distribution texture; no generator-owned discrepancy established | Do not alter generator pools or timing to mask authored command sequences. Keep as a scenario-authoring concern unless a separate generation family defect is demonstrated. |
| P3 | Core/DMZ Zeek flow pairs share tuples and frequently counters, with a ~114 ms median timestamp offset (Network 72) | `false_positive_or_unproven` after environment review | 4,919 matched pairs; large, but topology and configured timing model support shared cross-segment capture | The scenario places core/server and DMZ SPAN sensors on opposite segments; the timing profile explicitly models distributed taps observing shared flows with separate clocks. Preserve the native evidence and defer changes absent an independently supported contradiction. |
| P4 | Four Windows file creates share a millisecond timestamp (Detection 48) | `false_positive_or_unproven` | One PowerShell copy burst; low | Validate only if a source timestamp precision contract shows the millisecond simultaneity is impossible; no root fix justified from one sample. |
| P4 | Sparse Mac Unified Log selection and tightly grouped shutdown exits (Threat Hunter 86) | `weak_signal` / `sibling_defect` | Both Macs, low to moderate | Do not treat selection alone as a defect; the exact 100 ms cadence is removed. Retain lifecycle context and revisit if reviewers show impossible logout or process ordering. |

## Deliberation and score movement

The average blind synthetic-confidence score improved from 79.5 to 63.5. The loop removed the exact 100 ms canonical timing cadence, and the score improvement is consistent with reduced timing texture, but it cannot be attributed solely to that fix because the experts differed and their samples were independent. Deliberation maintained an informed split rather than forcing consensus. Its strongest additional point was the network report's large paired-flow pattern; inspection of the scenario topology and `network_sensor_observation` profile shows that core and DMZ SPAN sensors can observe the same routed transactions and that distributed taps intentionally use sensor-specific clocks. This does not establish that every matching counter is realistic, but it prevents treating the finding as a confirmed code defect from this report alone.

The initial low-level Mac findings also need calibrated interpretation. Host and Detection found plausible native process/PID-version and cross-source semantics. Threat and Host independently saw recurring Mac inventory routines; these are explicit scenario entries, so a generator edit would be the wrong owner. The remaining prior SMB-size finding is the strongest verifiable root-cause candidate for loop 4.

Automated evaluation remained unchanged at 96.29796 and PASS. Parseability, plausibility, causality and timing scored 100.0, 94.6091, 96.8384 and 92.1804. Pivot linkability remains 87, above its acceptance minimum of 80 and below aspiration 95. The evaluator's 10 sampled event/username and pivot/temporal mismatches are not treated as blind-review issues without a concrete generated contradiction.

## Artifacts

- `family-contract.md`
- `eval.txt`, `eval_results.json`
- `scores.json`
- `deliberation.md`
- Four independent reviewer reports
- Generated bundle: `/private/tmp/eforge-iteration-test-macos-loop-3`
- Neutral reviewer data: `/private/tmp/eforge-blind-loop3/data` (118 files verified against the authoritative generation manifest)

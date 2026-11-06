# Loop 4 — Iterative assessment

## Results

| Measure | Result |
|---|---:|
| Automated evaluation | 96.46905 / PASS |
| Records | 134,393 |
| Threat Hunter synthetic-confidence score | 64 |
| Detection Engineer synthetic-confidence score | 29 |
| Network Forensics synthetic-confidence score | 24 |
| Host/EDR synthetic-confidence score | 64 |
| Average blind synthetic-confidence score | 45.25 — mixed or inconclusive |
| Prior loop average | 63.5 |
| Change | −18.25 points; substantial improvement, with expert disagreement |

Verdict confidence is separate from synthetic-confidence. Threat Hunter and Host/EDR assessed
Synthetic; Detection Engineer and Network Forensics assessed Inconclusive. Average verdict
confidence was 73.25 and synthetic-confidence scores ranged by 40 points, so deliberation ran.
The facilitator recorded an informed disagreement and no fabricated expert revisions.

## Loop 4 fix and verification

### Canonical archive output size

- **Classification:** `family_level`.
- **Owner:** process-command effect planning and canonical runtime file-content identity publication
  in `ProcessPreflightPlanner` / `RuntimeContentIdentityManager`.
- **Invariant:** successful archive-producing commands publish a non-empty canonical file size;
  later SCP reads, SMB writes, Zeek files, and endpoint file observations preserve that same size.
- **Entry paths:** recognized gzip, tar, zip, and PowerShell `Compress-Archive` process effects.
- **Consumers:** canonical file state/content identity, eCAR and Syslog file observations, Zeek
  SMB/files records, and ground truth.
- **Why this layer owns the truth:** the earlier zero-byte symptom existed before downstream
  transfer/rendering. Assigning size at canonical effect publication prevents every consumer from
  independently guessing content size.
- **Change:** added bounded deterministic output-size profiles for supported archive commands and
  applied them when the canonical process-owned file mutation is prepared. Unprofiled commands and
  genuine empty files remain unaffected. Behavior manifest revision 402 records the behavior.
- **Verification:** scenario validation passes; effective config validation and behavior-manifest
  checks pass; six focused profile tests pass; Ruff checks pass on changed Python files; full
  generation succeeds. The formerly zero-byte gzip output is 45,760 bytes in ground truth,
  destination eCAR and Zeek SMB, and `zeek-core/files.json` reports matching seen/total bytes,
  zero missing bytes, and non-empty content hashes.
- **Residual risk:** profiles cover only the archive command families listed in the new config;
  other data-producing commands keep their existing size semantics.

## Prioritized findings

| Priority | Finding and reviewers | Classification | Scope and likely leverage | Owner / next action |
|---|---|---|---|---|
| P2 | Repeated ordered Mac inventory checklist across both hosts (Threat 64, Host 64; Detection/Network did not find a concrete defect) | `scenario_intent` | Repeated across both Mac histories and corresponding process telemetry; medium leverage | The authored storyline owns the command mix and timing. Loop 5 replaces later repeated surveys with supported engineering-workspace and system-maintenance activity while retaining initial inventory and all attack/session behavior. |
| P3 | `WS-AJOHNSON-01` copies a ZIP from its own `C$` share back onto the same workstation before upload (Threat Hunter) | `false_positive_or_unproven` | One authored transfer; low to medium | No cross-review confirmation. Leave unchanged unless later evidence establishes a concrete impossible behavior or intended owner. |
| P4 | Same compact ticket/archive labels recur across Linux and Windows operations (Threat Hunter) | `scenario_intent` / weak signal | Several authored actions; low | No generator fix is justified. Review task-specific names only if a later panel independently confirms a concrete pattern. |
| P4 | Thin macOS Unified Log sample (Detection Engineer) | `false_positive_or_unproven` | Two Macs; not a contradiction absent broader collection intent | Do not increase rows just to satisfy coverage preference; collection profile owns source selection. |

The loop 4 SMB/archive finding is resolved at its canonical owner. Reviewers found no source-native
network defect or hard cross-source contradiction after the fix. The recurring Mac command bundle is
scenario-authored, so changing generator command pools would be a symptom patch; it is the one
repeated, cross-review issue with a direct authoring owner and is the loop 5 target.

## Automated evaluation

The full scenario validates with zero errors, one retained low-baseline warning and 27 informational
notes. Full generation produced 134,393 records. Evaluation passes all hard acceptance criteria at
96.46905, with pillar scores of 100.0 parseability, 95.4040 plausibility, 96.7745 causality and
92.1221 timing. The evaluator's sampled storyline timing/trace items remain guardrails; they did not
identify a generation acceptance failure or supersede the concrete blind-review ownership analysis.

## Score movement and panel evidence

The average fell by 18.25 points from loop 3. Network and Detection both found the examined records
largely production-like and reported coherent protocol, schema, timestamp and correlation behavior.
Threat and Host independently identified repeated, nearly identical Mac survey routines, which is
directly supported by the authored task entries. No reviewer identified a hard contradiction.
The score movement reflects both this newly surfaced scenario-level distribution issue and
substantial reviewer disagreement; it is not attributed to archive sizing alone.

## Artifacts

- `family-contract.md`
- `validation.txt`, `eval.txt`, `eval_results.json`
- `scores.json`, `deliberation.md`
- Four independent reviewer reports
- Generated bundle: `/private/tmp/eforge-iteration-test-macos-loop-4`
- Neutral reviewer data: `/private/tmp/eforge-blind-loop4/data` (117 files; exact copy of generated
  log data verified by per-file SHA-256 comparison; no scenario, ground truth, manifest, report or
  evaluation files included)

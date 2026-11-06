# Loop 5 — Iterative assessment

## Results

| Measure | Result |
|---|---:|
| Automated evaluation | 96.88051 / PASS |
| Records | 141,187 |
| Threat Hunter synthetic-confidence score | 59 |
| Detection Engineer synthetic-confidence score | 24 |
| Network Forensics synthetic-confidence score | 23 |
| Host/EDR synthetic-confidence score | 74 |
| Average blind synthetic-confidence score | 45.0 — mixed or inconclusive |
| Prior loop average | 45.25 |
| Change | −0.25 points; no meaningful score movement, with high reviewer disagreement |

Verdict confidence is separate from synthetic-confidence. Threat Hunter and Host/EDR assessed
Synthetic; Detection Engineer and Network Forensics assessed Inconclusive. Average verdict
confidence was 74.5 and synthetic-confidence scores ranged by 51 points, so deliberation ran.
The facilitator preserved the independent positions and attributed no unsupported revisions.

## Loop 5 scenario-level adjustment and verification

### Repeated Mac terminal survey activity

- **Classification:** `scenario_intent`.
- **Owner:** the authored `mac-1-terminal-task-*` and `mac-2-terminal-task-*` process entries in
  `scenarios/iteration-test-macos/scenario.yaml`.
- **Invariant:** keep the initial OS/account inventory, but avoid repeating the same full
  system-survey command bundle seven times per host. Later user activity should have shorter,
  varied task groups without changing the attack, SSH, launch-job, session, or collection scope.
- **Entry paths:** typed process events in both Mac task families, including their authored
  command lines and explicit offsets.
- **Consumers:** canonical process/session state, Endpoint Security, eCAR, zsh history, and
  reviewer-visible user behavior.
- **Why this layer owns the truth:** reviewers found that ES/eCAR accurately represent commands
  explicitly authored in the scenario. Editing the generator would break that correlation and
  conceal authored input.
- **Change:** retained startup inventory checks and changed later groups to shorter, varied
  subsets of commands already covered by the Mac execution profile. Time slots and host/session
  boundaries remain unchanged.
- **Verification:** authored Scenario 2.0 validates with zero errors, one existing low-baseline
  warning, and 27 informational notes. Full generation succeeds with complete Mac fork/exec
  identity coverage; the neutral bundle's zsh histories contain the revised task set.
- **Residual risk:** Threat Hunter and Host/EDR still noticed recurring use of the same command
  pool across both systems. The score did not materially move, so a further scenario reduction
  should be considered only after the higher-severity native identity defect is fixed.

The first loop 5 draft added Git, launchctl, and plutil commands, but complete native coverage
correctly failed because these invocations lacked qualified metadata (`MAC-MROSS-01` exec census
45/51, `entitlements_unknown`). That failed output and checkpoint remain preserved at
`/private/tmp/eforge-iteration-test-macos-loop-5`. No acceptance gate was relaxed. The corrected
scenario uses existing qualified commands and was generated to
`/private/tmp/eforge-iteration-test-macos-loop-5b`.

## Prioritized findings

| Priority | Finding and reviewers | Classification | Scope and likely leverage | Owner / next action |
|---|---|---|---|---|
| P0 | Later Mac process births have lower PID-version values than earlier ES fork/exec target identities as native time advances (Host/EDR 74; other specialists did not inspect enough process identities to confirm or refute) | `sibling_defect`, recurring open issue from the initial round | Repeated across both Macs, with 15 and 39 visible reversals in the target identity stream; high leverage | StateManager/process timeline identity allocation. The state currently assigns versions in materialization order. Loop 6 should trace deferred/planned process-start order and allocate authoritative PID versions in canonical event-time order, preserving the same identity across fork/exec and retries/checkpoints. |
| P2 | Repeated ordered Mac inventory command pool remains visible across both hosts (Threat Hunter 59, Host/EDR 74) | `scenario_intent`, partially adjusted | Both Mac histories; medium leverage | Current task groups are shorter but still repetitive. Defer a further authoring change until the P0 identity issue is repaired and reassessed. |
| P3 | Compact support/archive labels appear across otherwise separate operations (Threat Hunter) | `false_positive_or_unproven` | A few authored actions; low | No defect established; no change recommended. |
| P4 | Sparse macOS Unified Log beside Endpoint Security (Detection Engineer) | `false_positive_or_unproven` | Two Mac hosts; collection intent not established | Do not infer missingness from selected row counts alone. |

The PID-version issue was a previously open initial-round finding and has not been fixed by loops
2–5. Loop 2–3 reviewers examined selected process chains and found local transitions coherent, but
the loop 5 Host/EDR specialist checked process births over the full six-hour view and reproduced
the chronology defect on both hosts. This is deeper issue surfacing, not a regression from the loop
5 scenario edit. The XNU source shows PID versions are allocated through a shared incrementing
counter for process creation; event-time inversions therefore need correction where canonical
process identities are planned, before native rendering. See Apple's [XNU fork/process source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_fork.c).

## Automated evaluation

The authored scenario validates with zero errors, one existing warning and 27 informational notes.
Full generation produced 141,187 records, and JSON evaluation passed all hard criteria at
96.88051. Pillars are 100.0 parseability, 96.7070 plausibility, 97.0009 causality and 92.2677
timing. The score rise from loop 4 is not attributed to the authored activity change alone; overall
record counts also varied across source families, and automated scoring remains a guardrail.

## Score movement and panel evidence

The mean blind score was effectively flat versus loop 4. Detection and Network found technically
coherent formats, tuples, and event ordering in their samples. Threat and Host continued to flag
Mac command texture; Host additionally identified a concrete PID-version chronology contradiction
across both endpoints. This P0 is the next root-cause target despite the small synthetic-confidence
spread movement.

## Artifacts

- `family-contract.md`, `validation.json`
- `eval.txt`, `eval_results.json`, `scores.json`, `deliberation.md`
- Four independent reviewer reports
- Successful generated bundle: `/private/tmp/eforge-iteration-test-macos-loop-5b`
- Preserved failed first attempt: `/private/tmp/eforge-iteration-test-macos-loop-5`
- Neutral reviewer data: `/private/tmp/eforge-blind-loop5/data` (120 files; per-file SHA-256
  comparison verified it exactly matches generated `data/`; no scenario, ground truth, manifest,
  report, or evaluation files included)

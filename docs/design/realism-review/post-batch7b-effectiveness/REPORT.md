# Post-Batch-7b P1 effectiveness assessment

## Outcome

The five requested P1 blocker families are implemented and verified at commit `2ab8e5e9`:

1. Linux PID allocation no longer exposes a direct wall-clock slope.
2. File/application/transport accounting and capture-loss ownership are reconciled before source
   rendering.
3. Inbound Windows 5156 projection uses the receiver's local PID/image pairing.
4. SSH source ordering accounts for eCAR process visibility and collection delay.
5. The SSH bundle owns source client, target shell, sshd, PAM/logind, and session closure.

The definitive output is not byte-identical to the pre-fix output. It contains 51,317 parsed
records and has relative data-tree digest
`994762e5995f822f6079e0ef7b17147d886602eebc25ff2387b965d4c6a79aae`; an independent repeat is
byte-identical to it. The expanded rendered-output probe reports zero findings.

The fixes improved the targeted contracts, but the definitive blind panel did **not** show an
aggregate realism improvement. Its average synthetic-origin confidence is **93.25** (lower is
better), versus **90.00** after Batch 7b and **91.75** in the original pre-fix assessment. The
panel now keys on different defects—primarily process-to-file/registry attribution, one-shot
Windows process lifetimes, source timestamp texture, IDS direction, and capture-loss texture.

## Frozen measurement

- Scenario: `/private/tmp/eforge-realism-review/branch-enterprise.yaml`, SHA-256
  `bf7eef77f0cb121bb0838cc4252ae19347e1a8c8304079c11426163806cc07ff`.
- Duration/profile: six hours under `enterprise_standard` observation.
- Primary output: `/private/tmp/eforge-post-batch7b-p1-fixed-v7/branch-enterprise`.
- Repeat output: `/private/tmp/eforge-post-batch7b-p1-fixed-v7/branch-enterprise-repeat`.
- Neutral review copy: `/private/tmp/case-p1-definitive.PUJqMs/data`.
- Automated evaluation: **95.3273** over 51,317 records; the only failed hard criterion remains
  `causality.pivot_linkability`.
- Verification: `5,243 passed, 41 skipped`; Ruff lint and format checks pass.

Generated datasets remain untracked.

## Scores

Blind synthetic-origin confidence is the comparison metric; lower means more realistic.

| Checkpoint | Threat | Detection | Network | Host/EDR | Panel average |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original pre-fix | 88 | 96 | 86 | 97 | **91.75** |
| Post-Batch-2 | 98 | 95 | 94 | 99 | **96.50** |
| Post-gate loop 3 | 72 | 74 | 84 | 85 | **78.75** |
| Final post-fix gate | 96 | 85 | 96 | 86 | **90.75** |
| Post-Batch-7b | 72 | 96 | 96 | 96 | **90.00** |
| Post-P1 blockers | 96 | 86 | 92 | 99 | **93.25** |

All four definitive reviewers returned Synthetic. Average verdict confidence was 93.5 and the
synthetic-score spread was 13, so none of the established deliberation triggers fired. The reports
are preserved under [`post-p1-blockers/final`](post-p1-blockers/final/).

The dashboard is available as an editable
[`SVG`](effectiveness-dashboard.svg) and rendered
[`PNG`](effectiveness-dashboard.png). Machine-readable inputs are in
[`comparison.json`](comparison.json), [`scores.json`](scores.json), and
[`post-p1-blockers/scores.json`](post-p1-blockers/scores.json).

## P1 dispositions

### Linux PID allocation — closed

`StateManager` now uses a deterministic per-host hidden-churn schedule with cached minute-prefix
lookups. Allocation remains fast and chronologically safe without encoding one exact
seconds-to-PID formula. Unit coverage exercises workload sensitivity, deterministic repeat,
out-of-order planning, and bounded retained state.

### File/transport/capture loss — closed

Canonical HTTP and SMB transactions now own complete application/file truth; the observation
planner alone introduces capture loss. HTTP methods/statuses that cannot carry a body remain
bodyless, file bytes plus framing fit inside the parent directional payload, and missing file bytes
require a compatible parent transport gap/history. The definitive network reviewer independently
confirmed exact file/UID linkage and byte arithmetic, while identifying loss *distribution* as a
separate realism concern.

### Inbound Windows WFP ownership — closed

Inbound 5156 records now use receiver-local process identity. The definitive panel did not
rediscover the prior local-image/remote-PID contradiction, and direction-specific unit coverage
passes.

### SSH source ordering — closed

All SSH paths use the source process-visibility guard with eCAR-to-later-source delay budgets. The
definitive probe has no syslog-before-process-create findings. Detection and Host/EDR reviewers
explicitly described SSH ordering as a realism strength.

### SSH closure ownership — closed

The bundle now terminates one-transport source SSH clients at transport close, closes the
bundle-owned target shell before logout, and then closes PAM/logind/session and responder sshd
state. Two preliminary blind passes exposed incomplete source-client and target-shell facets; both
were reproduced, fixed at the bundle owner, added to the probe, and excluded from the definitive
scores. The final Host/EDR reviewer confirmed source client termination immediately after remote
session closure.

## Validated follow-on findings

These are separate from the five closed P1 families and remain governed by the completed review's
dependency-ordered roadmap:

- **Process-to-artifact causality:** registry and file effects can be attached to unrelated live or
  newly created processes, corrupting ProcessGuid/PID pivots for MRU, Defender, WER, CBS, and
  user-shell artifacts.
- **Foreground process lifetimes:** some one-shot Windows commands survive until interactive
  session teardown rather than terminating according to executable semantics.
- **Network source-native texture:** proxy HTTP timestamps preserve the connection timestamp's
  microsecond residue through integer-millisecond offsets; capture gaps are overwhelmingly
  bidirectional; some IDS response signatures inherit request-side tuples.
- **Scenario/evidence bridge:** the central web-recon-to-SSH narrative is highly huntable but lacks
  a visible credential/exploitation prerequisite and the subsequent scan lacks endpoint actor
  ownership.

These findings were checked against rendered records and accepted as follow-on work. They do not
invalidate closure of the five requested contracts, and this assessment does not start another
blind-review-driven repair loop.

## Decision

The named five-blocker gate is closed. That does not by itself make the cumulative branch ready for
its PR: the remaining dependency-ordered review work and final package reconciliation still come
first. The honest effectiveness conclusion is narrower: the fixes made the targeted data
mechanically and semantically correct, but did not improve aggregate blind authenticity because
other realism defects dominate the current reviewer signal. Continue the original remediation plan
with those validated owner-level findings, then open the PR to `dev` when the rest is complete.

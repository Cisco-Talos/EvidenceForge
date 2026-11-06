# Iterative assessment loop 19

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive (verdict confidence 68; synthetic-confidence score 38). The multi-source web-shell pivot and Windows service lifecycles were coherent; a three-command same-second Mac history timestamp was weak texture evidence.
- **Detection Engineer:** Inconclusive (65; 54). Windows, eCAR, Zeek, and macOS event shapes and identities were credible; repeated Maya Ross shell inventories were the main distribution concern.
- **Network Forensics:** Synthetic (88; 82). Zeek, proxy, Snort, and ASA fields aligned, but the `.top` DGA-like cadence and near-equal 22/445/3306 scan counts from one host were strong distribution tells.
- **Host/EDR Forensics:** Synthetic (82; 76). Native process lifecycles and SSH correlation were plausible; repeated shell checklists and matching LaunchDaemon file lifecycles across both Macs looked templated.

## Deliberation Findings

Deliberation remained split: two Inconclusive, two Synthetic. The network sweep and recurring DGA-like DNS were the strongest distribution concerns; the web-shell and Windows service pivots were coherent. The Mac shell inventory repeated across hosts, but exact commands and some activity families are scenario-authored, so they do not justify a generator-side change by themselves.

## Prioritized Improvements

1. **P1 — Exact SMB FLOW-before-LOGIN ordering (`hard_contradiction`, Detection/eval):** DC-02 eCAR lines 1035–1036 contain the exact type-3 SMB tuple in both a successful LOGIN and inbound FLOW at the same millisecond, with LOGIN first. `SourceTimingPlanner` has an admitted exact-tuple SMB frontier but only consults it for SMB-marked auth contexts; loop 20 extends that owner to the generic type-3 SMB compatibility path.
2. **P2 — Concentrated network distribution (`distribution_texture`, Network):** One internal address produces both a roughly 760-attempt 22/445/3306 sweep over five seconds and 45 minutes of random-label `.top` DNS. These patterns are visible and high-volume, but the DGA family and scan are explicitly authored in the scenario; no renderer patch is warranted. Scenario changes are out of scope without a simple user-approved correction.
3. **P3 — Repeated Mac shell inventories (`distribution_texture`, Detection/Host):** Similar commands recur across both Maya Ross hosts and Endpoint Security. The commands are explicitly present in authored scenario events; retain the finding as scenario-specific rather than altering shared command generation.
4. **P4 — Same-second shell-history entries (`weak_signal`, Threat):** Three commands share a second in zsh history, whose output timestamps are second-resolution. No source-native contradiction was established.

## Priority Rationale

The exact tuple ordering defect is the only confirmed engine-owned contradiction and is fixed at the shared source-timing layer in loop 20. The remaining strongest observations are authored scenario behavior or plausible timestamp-resolution texture, so they are documented without engine changes.

## Comparison with Quantitative Eval

The JSON eval passed at 96.349141 with 132,196 records. It reported one causal-ordering failure: the exact remote SMB LOGIN preceded its inbound eCAR FLOW. That concrete failure is the loop 20 target; the evaluative guardrail otherwise remains healthy.

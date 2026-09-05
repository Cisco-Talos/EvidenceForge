# Iteration-Test Blind Assessment — Loop 45

## Outcome

- Initial verdicts were one Inconclusive and three Synthetic, with synthetic-confidence scores of
  43, 78, 72, and 84 (average 69.25; spread 41).
- Verdict disagreement and score spread triggered deliberation. All four revised verdicts were
  Synthetic, with scores of 87, 88, 85, and 89 (average 87.25).
- No reviewer repeated the direct `smbclient -c` lifetime defect.

## Deterministic Evaluation

- Overall score: 96.2822 across 123,124 records; all hard acceptance gates passed.
- Pillars: parseability 99.9259, plausibility 96.8425, causality 93.4343, timing 93.6761.

## Hard-Contract Result

The eCAR corpus contained 26 direct `smbclient -c` process lifecycles. Every process had exactly
one create and one terminate row, none exceeded 60 seconds, and the maximum lifetime was 43.018
seconds.

## Newly Prioritized Findings

- Unanswered one-packet ICMP scan flows carry positive durations, scan-only `service:icmp`, and
  independently varied payload sizes.
- Successful Windows Type 3 logons substitute the destination host for `WorkstationName` and leave
  several source-native authentication fields blank.
- RDP bootstraps contain invalid or unresolved Windows ancestry, including PID 4-parented
  `winlogon.exe` and absent visible parent images.
- Several workstations receive competing `services.exe -> explorer.exe` and normal interactive
  shell roots; one APP-INT-01 Java identity owns a flow after termination.

## Reports

- `threat-hunter-report.md`
- `detection-engineer-report.md`
- `network-forensics-report.md`
- `host-forensics-report.md`
- `deliberation.md`

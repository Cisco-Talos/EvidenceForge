# Iteration-Test Blind Assessment — Loop 48

## Outcome

- Initial verdicts were one Real, one Inconclusive, and two Synthetic.
- Initial synthetic-confidence scores were 29, 68, 38, and 69 (average 51; spread 40).
- Required deliberation produced four Synthetic verdicts and revised scores of 68, 74, 67, and
  75 (average 71).
- The prior same-channel Windows parent-before-child timing defect did not recur.

## Deterministic Evaluation

- Overall score: 96.2468 across 114,409 records; all hard acceptance gates passed.
- Pillars: parseability 99.9227, plausibility 96.9126, causality 93.3705, timing 93.4960.

## Hard-Contract Result

The hard probe joined 188 source-visible Windows Security parent/child process pairs and found zero
parent-after-child inversions.

## Newly Prioritized Findings

- 151 SMB Type 3 logons have empty source-native auth fields and receiver-owned workstation names.
- Four RDP logons change from an empty target SID at login to a concrete SID at logoff.
- Four RDP process chains lose parent identity and keep `userinit.exe` alive for session duration.
- UFW scan records rotate each stable source among exactly three nearly uniform TCP windows.
- One eCAR Teams process has module loads immediately after its visible termination.

## Reports

- `threat-hunter-report.md`
- `detection-engineer-report.md`
- `network-forensics-report.md`
- `host-forensics-report.md`
- `deliberation.md`


# Iteration-Test Blind Assessment — Loop 47

## Outcome

- Initial verdicts were one Inconclusive and three Synthetic.
- Initial synthetic-confidence scores were 52, 75, 62, and 74 (average 65.75; spread 23).
- Deliberation produced four Synthetic verdicts and revised scores of 73, 84, 77, and 80
  (average 78.5).
- The prior repeated desktop-shell defect did not recur.

## Deterministic Evaluation

- Overall score: 96.2468 across 114,409 records; all hard acceptance gates passed.
- Pillars: parseability 99.9227, plausibility 96.9126, causality 93.3705, timing 93.4960.

## Hard-Contract Result

Across the generated Windows process data, no Explorer was parented by `services.exe`; every
interactive session had at most one bare Explorer and one `userinit.exe` bootstrap.

## Newly Prioritized Findings

- One FILE-SRV-01 Security 4688 child visibly precedes its exact parent in the same channel.
- One successful explicit-proxy upload loses about 25.2 MB between its two network legs.
- Two TCP DNS rows claim normal `SF` closure with one packet per direction and UDP-like histories.
- Two SSH session commands precede and are not owned by their session shells.
- 151 Type-3 Windows logons share malformed empty fields and destination-as-workstation ownership.
- Ordinary Sysmon user processes overwhelmingly lose their session LogonGuid.

## Reports

- `threat-hunter-report.md`
- `detection-engineer-report.md`
- `network-forensics-report.md`
- `host-forensics-report.md`
- `deliberation.md`

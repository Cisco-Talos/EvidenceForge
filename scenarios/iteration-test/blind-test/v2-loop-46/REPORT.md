# Iteration-Test Blind Assessment — Loop 46

## Outcome

- All four reviewers classified the dataset as Synthetic.
- Synthetic-confidence scores were 64, 69, 68, and 76 (average 69.25; spread 12).
- No reviewer repeated the one-packet ICMP duration, ICMP service, or per-target sweep-size defects.
- Deliberation did not trigger because verdicts were unanimous, average verdict confidence was 83,
  and the score spread was 12 points.

## Deterministic Evaluation

- Overall score: 96.4266 across 120,631 records; all hard acceptance gates passed.
- Pillars: parseability 99.9239, plausibility 96.8857, causality 94.6259, timing 92.8578.

## Hard-Contract Result

Across 725 ICMP Zeek rows, all 489 one-packet observations omitted duration and every row omitted
an analyzer service. The 254-target nmap discovery sweep retained one 64-byte payload size across
507 sensor rows.

## Newly Prioritized Findings

- Seventeen ordinary user Explorers on five workstations are parented by `services.exe`; several
  unchanged logon IDs also receive repeated `userinit.exe`/Explorer bootstraps.
- Type 3 Windows logons still contain empty native fields and destination-as-workstation ownership.
- Consequential SSH pivots have rich receiver evidence but anonymous initiating endpoint flows.
- SMB baseline vocabulary includes future-year generic files and non-native SYSVOL/NETLOGON paths.

## Reports

- `threat-hunter-report.md`
- `detection-engineer-report.md`
- `network-forensics-report.md`
- `host-forensics-report.md`

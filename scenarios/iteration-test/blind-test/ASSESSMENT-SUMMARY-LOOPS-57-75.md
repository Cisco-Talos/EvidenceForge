# EvidenceForge Iteration-Test Assessment Summary — Loops 57–76

## Session Scope

- Branch: `codex/assess-20-loops-2026-09-10`, created from `dev` at `12988ce72`.
- Completed restarted loops: 57 through 76 (20 loops).
- The earlier wrong-model loop 57 and its fixes/results were discarded before this run.
- Loop 76 is a post-repair blind assessment of the four hard-contradiction fixes selected after
  loop 75; it used the same corrected reviewer model as the restarted session.
- Lower blind synthetic-confidence is more production-like; automated evaluation is higher-is-better.

## Score Ledger

| Loop | Automated | TH | DE | Network | Host/EDR | Initial mean | Deliberated mean |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 57 | 97.36 | 44 | 65 | 83 | 84 | 69.00 | 82.25 |
| 58 | 96.28 | 44 | 70 | 91 | 82 | 71.75 | 86.75 |
| 59 | 96.28 | 44 | 72 | 72 | 72 | 65.00 | 77.50 |
| 60 | 96.28 | 56 | 86 | 34 | 68 | 61.00 | 71.50 |
| 61 | 96.28 | 84 | 66 | 68 | 83 | 75.25 | N/A |
| 62 | 97.23 | 68 | 58 | 89 | 74 | 72.25 | 78.75 |
| 63 | 97.23 | 29 | 71 | 66 | 92 | 64.50 | 79.25 |
| 64 | 96.59 | 49 | 71 | 68 | 87 | 68.75 | 77.00 |
| 65 | 96.67 | 86 | 67 | 36 | 71 | 65.00 | 79.50 |
| 66 | 96.23 | 73 | 92 | 89 | 86 | 85.00 | 85.00 |
| 67 | 96.23 | 72 | 76 | 65 | 90 | 75.75 | 75.75 |
| 68 | 96.38 | 68 | 43 | 29 | 92 | 58.00 | 77.75 |
| 69 | 97.05 | 44 | 76 | 65 | 72 | 64.25 | 73.75 |
| 70 | 97.05 | 66 | 34 | 36 | 64 | 50.00 | 57.00 |
| 71 | 97.05 | 44 | 97 | 89 | 78 | 77.00 | 93.00 |
| 72 | 97.05 | 66 | 76 | 34 | 32 | 52.00 | 61.00 |
| 73 | 96.48 | 70 | 64 | 64 | 67 | 66.25 | N/A |
| 74 | 96.48 | 47 | 74 | 84 | 66 | 67.75 | 76.25 |
| 75 | 96.54 | 68 | 53 | 82 | 94 | 74.25 | 81.50 |
| 76 | 96.78 | 74 | 64 | 74 | 84 | 74.00 | N/A |

## Trend Summary

- Mean automated score: 96.68; range 96.23–97.36; final 96.78 PASS.
- Mean initial blind synthetic-confidence: 67.84; range 50.00–85.00.
- Initial blind mean moved from 69.00 in loop 57 to 74.00 in loop 76. Reviewer variance remained
  large, so this is not a monotonic realism trend despite repeated removal of exact defects.
- The five-loop rolling initial mean ended at 66.85.
- Loop 75's repaired proxy-byte family passed its exact rendered contract: zero gross mismatches
  and zero zero-loss mismatches across 455 joined transports.
- Loop 76's four post-assessment hard-contradiction probes all passed with zero violations, and all
  four blind reviewers explicitly found no decisive impossible timing or lifecycle contradiction.

## Family-Level Improvements Completed

The session repaired or strengthened DHCP phase timing and process-parent identity; UDP DNS packet
timing and identity; RDP initializer/session ordering; explicit-proxy phase, authority, lifecycle,
header, and byte contracts; Windows token, provider-thread, device-volume, PE build, and binary
identity; Linux PID, terminal, and systemd-logind lifecycle identity; KDC admission and ticket-use
ordering; SMB packet timing; and Zeek file-digest provenance.

## Loop 76 Post-Repair Disposition

- Process lifetime, software chronology, Samba directory operations, and Windows lock lifecycles
  passed targeted rendered-output probes with zero violations.
- Initial blind scores were Threat Hunter 74, Detection Engineer 64, Network Forensics 74, and
  Host/EDR 84 (mean 74.00). All verdicts were Synthetic; no deliberation was required.
- The score was effectively flat versus loop 75's initial mean (−0.25). Reviewers shifted to deeper
  process-population, PE metadata, network-duration/loss, Linux hardware/schedule, and host-role
  inventory textures rather than recurrence of the repaired contradictions.

## Highest-Impact Remaining Findings

1. Windows application process families and PE metadata need inventory-bound child populations,
   serviced file versions, and complete hashes.
2. TLS duration and sensor-loss populations retain broad shared modes that look generator-driven.
3. Linux hardware, resolver, and cron evidence needs persistent host-state and schedule ownership.
4. Client software and user agents need stronger infrastructure-host inventory/role constraints.
5. Zeek PE/file analyzer declarations, HTTP FUID retention, and build-specific Windows event
   versions need stronger source-native completeness contracts.

## Artifacts

- Final loop report: `v2-loop-75/REPORT.md`
- Post-repair blind report: `v2-loop-76/REPORT.md`
- Canonical score data: `v2-loop-76/scores.json`
- Targeted probes: `v2-loop-76/hard-probes.json`
- Dashboard: `assessment-effectiveness-dashboard-last-20-loops.svg`
- Detailed implementation and verification history:
  `docs/worklog/2026-09-10-iteration-test-20-loops.md`

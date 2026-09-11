# EvidenceForge Iteration-Test Assessment Summary — Loops 57–75

## Session Scope

- Branch: `codex/assess-20-loops-2026-09-10`, created from `dev` at `12988ce72`.
- Completed restarted loops: 57 through 75 (19 loops).
- The earlier wrong-model loop 57 and its fixes/results were discarded before this run.
- Loop 76 was not started because the user ended the run after loop 75.
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

## Trend Summary

- Mean automated score: 96.67; range 96.23–97.36; final 96.54 PASS.
- Mean initial blind synthetic-confidence: 67.51; range 50.00–85.00.
- Initial blind mean moved from 69.00 in loop 57 to 74.25 in loop 75. Reviewer variance remained
  large, so this is not a monotonic realism trend despite repeated removal of exact defects.
- The five-loop rolling initial mean ended at 67.45, up from 62.60 in loop 74.
- Loop 75's repaired proxy-byte family passed its exact rendered contract: zero gross mismatches
  and zero zero-loss mismatches across 455 joined transports.

## Family-Level Improvements Completed

The session repaired or strengthened DHCP phase timing and process-parent identity; UDP DNS packet
timing and identity; RDP initializer/session ordering; explicit-proxy phase, authority, lifecycle,
header, and byte contracts; Windows token, provider-thread, device-volume, PE build, and binary
identity; Linux PID, terminal, and systemd-logind lifecycle identity; KDC admission and ticket-use
ordering; SMB packet timing; and Zeek file-digest provenance.

## Highest-Impact Remaining Findings

1. Process-owned network/application activity can render after the owning process terminates.
2. Application versions and product generations need scenario-date validity constraints.
3. Browser HTTP and TLS populations retain exact timing modes that look generator-driven.
4. UDP syslog needs persistent sender sockets, stable source-port behavior, and packet-derived
   duration.
5. Samba object operations, workstation lock/unlock, and NTLM/Type 9 companion evidence need
   stronger source-semantic lifecycle contracts.
6. Linux background telemetry needs more host-state dependence and a broader source-local long tail.

## Artifacts

- Final loop report: `v2-loop-75/REPORT.md`
- Final deliberation: `v2-loop-75/deliberation.md`
- Canonical score data: `v2-loop-75/scores.json`
- Dashboard: `assessment-effectiveness-dashboard-last-19-loops.svg`
- Detailed implementation and verification history:
  `docs/worklog/2026-09-10-iteration-test-20-loops.md`

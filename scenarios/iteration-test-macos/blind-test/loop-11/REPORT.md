# Iterative assessment loop 11

## Outcome

Loop 11 completed the Mac process-exec timing family. The source timing planner now checks the
rendered millisecond bucket before accepting a preferred timestamp and repairs collisions with
minimum slack. Fresh output has zero fork/exec timestamp collisions: all 117 Mac exec rows are
strictly after their named predecessor in eCAR milliseconds.

Generation at `/private/tmp/eforge-iteration-test-macos-loop-11` produced 141,247 records and
passed one JSON evaluation at 96.880577. All 120 data files in the blind copy matched the
generation manifest. The source-timing tests passed (82), along with Ruff check and format.
Behavior revision 410 records the change.

## Family probes

| Mac host | Exec rows | Strictly later than predecessor | Same-ms collisions |
|---|---:|---:|---:|
| MAC-MROSS-01 | 52 | 52 | 0 |
| MAC-MROSS-02 | 65 | 65 | 0 |
| **Total** | **117** | **117** | **0** |

## Independent expert panel

| Expert | Initial verdict | Initial confidence | Initial synthetic score | Revised synthetic score |
|---|---|---:|---:|---:|
| Threat Hunter | Likely curated or synthetic | 68 | 58 | 70 |
| Detection Engineer | Likely synthetic | 82 | 78 | 64 |
| Network Forensics | Inconclusive, slight synthetic lean | 70 | 44 | 52 |
| Host/EDR Forensics | Indeterminate, slight synthetic lean | 56 | 55 | 72 |
| **Mean** | **mixed** | **69 initial / 73.5 revised** | **58.75 initial** | **64.5 revised** |

Initial score spread was 34 points, triggering deliberation. Reviewers agreed on strong host and
network correlation and raised the expired R3 chain and exact 30-minute sysstat cadence. The ES
notification payload remains a version-specific schema question; available evidence does not
justify treating it as a confirmed root cause.

## Prioritized findings

1. **P1 — Expired issuer chain in a current public TLS session (`schema_or_format`).** The linked
   `www.reddit.com` leaf was valid in November 2026, but its R3 issuer expired in September 2025.
   Trace issuer selection and validity configuration as the Loop 12 root-cause target.
2. **P1 — ES notification action payload semantics need exact version verification.** All 303 Mac
   ES records carry the same nested result shape. Apple documents `es_result_t` in the notify union,
   but exact source serialization remains unresolved.
3. **P2 — Repeated paired sysstat jobs at a 30-minute cadence across Linux hosts.** Could reflect
   shared cron configuration; verify whether timing owns this pattern before changing it.
4. **P3 — Concentration of investigation-ready activity.** Reviewers found coherent evidence, and
   did not establish a concrete scenario or cross-source defect.

Loop 11 is **complete** for the process-timing family. Full reviewer reports, deliberation,
automated evaluation, and root-cause probes are saved in this folder.

# Loop 77 — Linux PID scale and recurring host texture

The scenario validated and was generated at seed 42. The neutral data copy is identical to loop76:
all 113 files have matching SHA-256 digests. Evaluation therefore remained 96.3400 PASS for
135,966 records (parseability 100.00, plausibility 96.82, causality 95.90, timing 90.79).

## Family probes

The Linux PID probe found process-create PIDs over one million on 9 of 11 Linux hosts. Values are
unique in the sampled creates, below the configured 4,194,304 exclusive ceiling, and consistent
with the shared allocator's host-specific hidden-churn model. The exact `pwd` / `ls -ltr` /
`history | tail -15` trio cited by Detection was not present in the copied shell histories. Generic
`pwd` and `ls -ltr` commands occur in several histories, which is weak common-workflow texture.
No PID or history change is justified by these examples alone.

Threat Hunter identified a stronger repeated signal: `debian-sa1` runs twice per hour on nine
hosts, with stable host-specific phase offsets. The output contains paired `/bin/sh` and
`/usr/lib/sysstat/debian-sa1` process records near each scheduled point. This is a visible periodic
configuration, not an impossible event sequence. It remains a candidate for loop79 because the
exact half-hour interval recurs throughout the six-hour window and merits comparison with the
configured service semantics.

## Independent reviews

- **Threat Hunter — Synthetic, confidence 76, synthetic-confidence 64.** Flagged identical
  half-hourly Linux system-stat cadence across nine hosts; also found coherent cross-source incident
  pivots and no hard contradiction or contract gap.
- **Detection Engineer — Real/production-like, confidence 72, synthetic-confidence 22.** Found
  source-shaped records and strong endpoint/Zeek joins; 26,184 of 26,970 eCAR FLOW rows had exact
  Zeek tuple/time matches within three seconds. Sparse macOS Unified Log was noted but treated as a
  collection limitation.
- **Network Forensics — Inconclusive, confidence 74, synthetic-confidence 22.** Strong network
  tuple/UID relationships and plausible DNS/HTTP/TLS records; no decisive network defect.
- **Host/EDR Forensics — Inconclusive, confidence 78, synthetic-confidence 36.** No impossible
  visible process or session ordering; sparse macOS Unified Log was the main limitation.

The standalone mean is **36.00** (spread 42); verdict disagreement and spread triggered
deliberation. The deliberative mean is **39.25**, with the panel still split between one Synthetic
vote and three Inconclusive votes. Deliberation recognizes the nine-host `debian-sa1` recurrence as
the concrete synthetic-leaning observation, while noting that shared collection scheduling remains
a plausible alternative. The loop's PID/history probes do not support a code change. The recurring
statistics schedule is a separate candidate; assess its service semantics and sibling schedule
behavior before editing.

## Findings and priorities

| Priority | Finding | Category | Original reviewer rating | Leverage | Disposition |
|---|---|---|---|---|---|
| P2 | `debian-sa1` repeats every 30 minutes on nine hosts | `distribution_texture` | not labeled | Medium; recurring fleet-wide behavior | Verify source schedule semantics in loop79; avoid arbitrary per-row jitter. |
| P3 | Million-scale Linux PIDs on nine hosts | `distribution_texture` | not labeled | Low–medium; plausible under host runtime/churn | No change; allocator is host-scoped and values stay in range. |
| P4 | Sparse macOS Unified Log | `environment_or_collection_plausibility` | not labeled | Low without collection policy | Defer; no visible activity requires broader Unified Log coverage. |

No hard contradiction was reported. The main score split reflects different weighting of one
recurring periodic workload versus strong record shape and cross-source consistency. Deliberation
Artifacts: `linux-pid-history-probe.json`, `family-contract.md`, `automated-eval.json`, reviewer
reports, and `deliberation.md`.

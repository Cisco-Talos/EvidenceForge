# Loop 76 — Linux forwarding queue states

Validated and regenerated the canonical `iteration-test` scenario at seed 42. The four blind
reviewers examined only the neutral copy at `/private/tmp/log-study-loop76/dataset-ash/data`.
The loop's family question was whether changing rsyslog queue values and checkpoint counters are
attainable under the per-host asynchronous queue model.

## Automated evaluation

**96.3400 / 100, PASS**, covering 135,966 records. Parseability is 100.00, plausibility 96.82,
causality 95.90, and timing 90.79. The human and JSON evaluations agree with loop75; no dynamic
drop was observed.

The queue probe reports 75 updates across 11 hosts and 39 visible pending reports. Pending and
checkpoint transitions all fit their configured bounds; no transition violation or capacity
exceedance was found. Seven hosts exceed 1,000 pending and the maximum is 3,698, but those values
are reachable in the model's arrival/processing series. No generator change is justified by this
probe.

## Independent reviews

- **Threat Hunter — Synthetic, confidence 91, synthetic-confidence 84.** Found a compact,
  recurring DNS/IDS background palette and tidy coverage texture. Found credible support upload,
  database export/SMB movement, and PsExec traces; no hard contradiction.
- **Detection Engineer — Synthetic, confidence 84, synthetic-confidence 72.** Flagged million-scale
  Linux PIDs across hosts, repeated generic shell-history sequences, and aligned six-hour windows.
  Source-native formats and tuple correlations were strong; no hard contradiction.
- **Network Forensics — Realistic, confidence 78, synthetic-confidence 18.** Found strong tuple and
  UID linkage across endpoint flows, Zeek, Snort, web access, and ASA. The core/DMZ near-duplicate
  connection timestamp offset was a weak signal with a plausible sensor-skew explanation.
- **Host/EDR Forensics — Inconclusive, confidence 70, synthetic-confidence 45.** Found credible
  process identity and lifecycle alignment, while treating one possible shell-history/process
  coverage gap as unresolved without a collection contract.

Initial synthetic-confidence mean is **54.75** (spread 66); verdict disagreement and score spread
triggered deliberation. After cross-examination the mean is **54.00** (Threat 81, Detection 70,
Network 22, Host 43), with no consensus verdict. The two synthetic-leaning reviewers give most
weight to cross-host background texture; network and host reviewers see internally coherent
records and emphasize that these textures have plausible operational alternatives. No hard
contradiction or definite contract gap was established. Strong correlation demonstrates internal
coherence, not provenance by itself.

## Prioritized findings

| Priority | Finding | Category | Original reviewer rating | Scope / leverage | Next step |
|---|---|---|---|---|---|
| P2 | Repeated suspicious DNS/IDS background families and compact label/TLD palette | `distribution_texture` | not labeled | Recurs across sensors; medium | Inspect family frequency and source ownership before changing IDS/DNS generation. |
| P2 | Million-scale Linux PIDs and repeated generic shell-command trios | `distribution_texture` | not labeled | Cross-host; medium | Verify host-specific boot/runtime churn and command history pathways in loop77; avoid sample-specific edits. |
| P3 | Near-identical six-hour collection boundaries and ~0.11-second core/DMZ timestamp offset | `environment_or_collection_plausibility` / `weak_signal` | not labeled | Broad window / sensor pairs; low | Treat boundaries as study-window context; only alter sensor timing if a source-clock contract is contradicted. |
| P4 | One shell-history entry without a visible process companion | `environment_or_collection_plausibility` | not labeled | One sample; low | Defer absent process-coverage guarantee. |

## Next loop

Loop77 will verify the PID-scale and shell-history recurrence concerns against the allocator and
activity owners. The queue series itself is attainable, so no queue-model adjustment is planned.
Artifacts: `family-contract.md`, `queue-state-probe.json`, `automated-eval.json`, four blind
reports, `deliberation.md`, and `scores.json`.

# Loop 80 — Post-fix blind checkpoint

This independent checkpoint reviewed the byte-identical seed42 output from loop79; the 113 source
files and evaluation were reused after the generator fix. Scenario validation passed. Evaluation is
**96.5648 PASS**, 142,740 records (parseability 100.00, plausibility 96.93, causality 97.17,
timing 90.20).

## Independent reviews

- **Threat Hunter — Synthetic, confidence 78, synthetic-confidence 78.** Found broad process,
  session and network consistency, with no hard contradiction. Synthetic concerns were complete,
  cleanly aligned source families, tidy per-host footprints, and operational detail without much
  collection imperfection.
- **Detection Engineer — Synthetic, confidence 68, synthetic-confidence 68.** Again flagged all
  ten Linux hosts having exactly 36 `sysstat` CRON records at 600-second intervals. Found no
  impossible ordering, broken Zeek references, or malformed source files.
- **Network Forensics — Inconclusive, confidence 69, synthetic-confidence 54.** Found valid Zeek
  child UIDs and strong endpoint/proxy/ASA joins. A roughly 1,300-connection minute-level burst
  and a single unmatched proxy CONNECT were weak, plausibly explained concerns; no hard network
  contradiction.
- **Host/EDR Forensics — Inconclusive, confidence 65, synthetic-confidence 48.** Found clean
  process/session ordering and high Windows Sysmon/eCAR action/PID/image agreement. Sparse Mac
  Unified Log coverage remains an unverified collection-scope question, not a proven defect.

Standalone mean synthetic-confidence is **62.00** (likely synthetic). Verdict disagreement triggered
deliberation; the network and host reviewers remain inconclusive while threat and detection judge
the data synthetic. No hard contradiction or definite contract gap was reported. The repeated
sysstat cadence is still the clearest synthetic-looking texture, despite matching Debian package
behavior; this confirms reviewer sensitivity to an unusually complete fleet-wide schedule, not a
source-native error.

## Prioritized findings

| Priority | Finding | Category | Original reviewer rating | Scope / leverage | Disposition |
|---|---|---|---|---|---|
| P2 | Exact 36-entry ten-minute sysstat series on all ten Linux hosts | `distribution_texture` | not labeled | Fleet-wide; medium | Preserve the documented schedule. Do not add artificial missing jobs absent collection evidence; track it as a benchmark provenance cue. |
| P3 | Roughly 1,300 connections in one minute including an ICMP sweep | `distribution_texture` | not labeled | Concentrated burst; low–medium | Correlate with visible scan/process activity; network review did not establish an unexplained defect. |
| P4 | Two or three Mac Unified Log records per host | `environment_or_collection_plausibility` | not labeled | Two hosts; low without collection policy | Defer until collection scope is specified. |

No code change is selected for loop80. Next candidate: review another cross-source family from the
existing assessment backlog; retain the same authored scenario and seed. Artifacts include the
four reports, `family-contract.md`, evaluation, and `scores.json`.

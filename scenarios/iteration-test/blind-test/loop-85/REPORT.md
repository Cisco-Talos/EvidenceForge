# Loop 85 — independent post-fix checkpoint

Loop85 reused the byte-identical loop84 post-fix dataset; no generation code or scenario changed. The authoritative evaluation remains **96.2810 PASS**, 148,787 records (parseability 100.00, plausibility 96.86, causality 95.03, timing 91.54). This is an independent panel checkpoint, not a new generation pass.

## Blind panel

Standalone synthetic-confidence scores: Threat Hunter **52** (Inconclusive, verdict confidence 62), Detection Engineer **47** (Inconclusive, 78), Network Forensics **66** (Synthetic, 68), and Host/EDR Forensics **34** (Synthetic, 55). Mean **49.75**, spread **32**. The two-versus-two verdict split and spread triggered deliberation. The facilitator's revised mean was **50.50**, with all four positions Inconclusive; these are deliberation estimates, not new reviewer measurements.

This panel's average increased five points from loop84 on unchanged data. The change reflects reviewer variation and broader inspection of distribution texture, not a generation regression. It did not establish a hard contradiction.

## Findings and verification

| Priority | Finding | Category | Reviewer(s) | Classification / status |
|---|---|---|---|---|
| P2 candidate | Concentrated 14:30–14:45 UTC network surge | `distribution_texture` | Network Forensics | `false_positive_or_unproven`; internal probe attributes most rows to the authored Nmap sweep; no code change |
| P3 candidate | Mac eCAR has many flows to 10.10.3.20:8080 and a short repeated Jira URL cluster | `environment_or_collection_plausibility` | Detection Engineer | `false_positive_or_unproven`; host/port correspond to the visible PROXY-01 service path; no defect established |
| P3 candidate | DC-01 WMI/SYSTEM actions lack a visible initiating identity in the sampled records | `contract_gap` | Threat Hunter | Investigative attribution gap, not a proven generated-data contradiction; carry for source/effect verification |
| P4 | Near-complete Windows Security/Sysmon/eCAR process matching and sparse Mac Unified Log | `weak_signal` | Host/EDR, Detection | Correlation completeness and thin coverage are not scored absent an established collector contract or contradiction |

The surge probe counted 2,093 core and 2,029 DMZ connections in the flagged interval. Of those, 1,268 core and 1,271 DMZ rows matched the visible source `10.10.3.10`, target subnet `10.10.2.0/24`, and ports 22/80/443/445/3306. WEB-EXT-01 eCAR records two Nmap processes at 14:39:52Z and 14:40:04Z. This explains most of the synchronized burst; remaining activity is varied and no separate source-native issue was demonstrated.

The Mac proxy concentration is 288/371 FLOWs on MAC-MROSS-01 and 372/465 on MAC-MROSS-02 to 10.10.3.20:8080; the dataset includes PROXY-01's proxy access log. Those counts alone do not show misattribution or implausible traffic. The DC-01 account and WMI activity is consequential, but the Threat Hunter did not establish that its SYSTEM attribution violates the source contract. Do not add evidence based on unknown operator authorization.

No family-level code fix is selected from this checkpoint. Loop86's first candidate is a focused source/effect trace of the DC-01 WMI sequence if it reveals a reproducible companion or attribution contract violation; otherwise continue independent assessment without changing generation. Do not retarget the scan or proxy path solely from distribution counts.

## Validation and artifacts

- Output reused from loop84 and copied byte-identically into `/private/tmp/log-study-loop85/dataset-ember/data`; blind reviewers saw only that data directory.
- Automated eval remains 96.2810 PASS, 148,787 records; human and JSON results copied to this loop folder.
- Four independent reviewers completed reports. Their first submissions were corrected where their verdict labels or score headings did not match the required schema; final artifacts contain all five realism dimensions and numeric confidence scores.
- Deliberation triggered by the initial verdict split and score spread; dissent and score semantics were preserved.
- A/B comparison and generation were not run because there was no code or scenario change.

Artifacts: `network-distribution-probe.json`, `mac-proxy-flow-probe.json`, `eval-human.txt`, `eval_results.json`, `scores.json`, four blind reports, and `deliberation.md`.

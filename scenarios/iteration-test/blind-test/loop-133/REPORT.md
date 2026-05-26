# Loop 133 Assessment Report

## Score Summary

Loop 133 evaluated the regenerated iteration-test output from fix commit `b4ee3d7d` (`fix: model linux daemon syslog state`). Automated eval passed at `96.1304/100` across `75,833` records. Blind synthetic-confidence scores were Threat Hunter `72`, Detection Engineer `72`, Network Forensics `68`, and Host/EDR `72`, for an average synthetic-confidence score of `71.0`.

The previous Loop 132 Linux daemon identifier tell is fixed in the regenerated output: hard probes found `0` rsyslog file descriptors above `999`, `0` polkit `unix-session` IDs above `999`, `0` D-Bus `:1.N` bus IDs above `999`, and `0` eCAR ICMP records with zero string ports. Maximum observed values were fd `64`, unix-session `177`, and D-Bus suffix `821`.

## Rolling Last 10 Scores

| Loop | Automated Eval | Records | Threat Synthetic-Confidence | Detection Synthetic-Confidence | Network Synthetic-Confidence | Host Synthetic-Confidence | Avg Blind Synthetic-Confidence |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 124 | 96.4358 | 76,915 | 68 | 76 | 74 | 72 | 72.5 |
| 125 | 96.2858 | 76,915 | 74 | 72 | 68 | 72 | 71.5 |
| 126 | 96.3843 | 73,253 | 68 | 72 | 68 | 78 | 71.5 |
| 127 | 96.4343 | 73,253 | 78 | 74 | 67 | 82 | 75.25 |
| 128 | 96.2731 | 80,718 | 78 | 64 | 78 | 76 | 74.0 |
| 129 | 96.3773 | 78,080 | 68 | 67 | 72 | 72 | 69.75 |
| 130 | 96.4166 | 74,738 | 64 | 72 | 62 | 42 | 60.0 |
| 131 | 96.4166 | 74,738 | 64 | 78 | 82 | 76 | 75.0 |
| 132 | 95.5271 | 80,353 | 76 | 82 | 76 | 68 | 75.5 |
| 133 | 96.1304 | 75,833 | 72 | 72 | 68 | 72 | 71.0 |

## Individual Expert Summaries

Threat Hunter assessed synthetic at confidence `72`. The intrusion chain, background noise, and source-native fields were strong, but the reviewer matched `1,343/1,479` overlapping core/DMZ Zeek flows with identical duration, byte, packet, state, and history metrics, which looks like canonical rendering duplicated across sensors rather than independent observation.

Detection Engineer assessed synthetic at confidence `72`. Windows/Sysmon/Zeek field structure and cross-source timing were convincing, but the reviewer flagged fleet-wide Sysmon `ProcessGuid` embedded boot times clustered near exact noon UTC and short hex-like DKIM TXT payloads that do not resemble source-native RSA DKIM keys.

Network Forensics assessed synthetic at confidence `68`. The network corpus was coherent and source-native, especially proxy, ASA, TLS/X.509, and Zeek UID linkage, but suspicious DNS and web-scan behavior still read as generated from compact grammars with fixed response sizes and resolver/scanner role reuse.

Host/EDR assessed synthetic at confidence `72`. The Windows attack timeline was convincing, including PsExec, PowerShell, RDP, and Security log clearing, but Linux eCAR process IDs repeatedly moved backward in time on multiple hosts without wraparound, and shell-history mistakes looked decorative rather than naturally corrected.

## Prioritized Improvements

| Priority | Issue | Reviewer Original Rating(s) | Score Impact | Description |
|---|---|---|---|---|
| P1 | Duplicate multi-sensor Zeek metrics | not labeled | High | Threat Hunter matched `1,343/1,479` overlapping core/DMZ flows where independent UIDs had exactly identical connection metrics. Fix in the Zeek observation fan-out layer so per-sensor timestamps, duration, packet/byte counters, capture-loss fields, and histories vary within source-native bounds. |
| P1 | Linux eCAR PID time monotonicity | not labeled | High | Host/EDR found dozens of per-host Linux eCAR process PID inversions, such as `APP-INT-01` moving from PID `838581` to `838288` later in the visible window. Fix in the per-host Linux PID allocator/state layer so process IDs are mostly monotonic over time with realistic wrap/reuse only when justified. |
| P2 | Sysmon ProcessGuid boot-time regularity | not labeled | Medium | Detection decoded Sysmon `ProcessGuid` timestamps showing multiple Windows hosts with boot-era processes anchored at nearly exact noon UTC on different days. Fix host boot-time derivation so embedded ProcessGuid time words reflect organic uptime anchors rather than a uniform default. |
| P2 | DNS TXT/DKIM placeholder payloads | not labeled | Medium | Detection found DKIM TXT answers like `p=8c47226d...`, far too short and hex-like for RSA DKIM keys. Replace placeholder DNS TXT generation with source-native long base64 payloads and domain-class-specific record templates. |
| P2 | Suspicious DNS and scanner grammar | not labeled | Medium | Network found compact DGA-like domain grammar, scanner/resolver role reuse, missing follow-on behavior after suspicious answers, and fixed Nikto response sizes. Broaden red-herring pools, separate IP roles, and add selective follow-on/timeout behavior plus noisier web response sizes. |
| P3 | Authored attack and shell-history texture | not labeled | Medium | Threat and Host both noted clean artifact names, instructional attack cadence, decorative typos, and repeated broad diagnostic commands. This is lower than the source-native defects but remains a recurring score driver. |

## Comparison With Quantitative Eval

Automated eval passed all acceptance gates and improved from Loop 132 (`95.5271`) to Loop 133 (`96.1304`), mainly because the generated output no longer carries the Linux daemon identifier pathology flagged in Loop 132. The blind panel correctly moved on to deeper source-native and statistical tells that automated eval does not currently score: cross-sensor Zeek metric duplication, Sysmon `ProcessGuid` embedded boot-time morphology, DNS TXT payload semantics, and Linux PID monotonicity.

## Recommendations

Target Zeek multi-sensor observation variance first in Loop 134. It is dataset-wide, independently reproducible, and was the Threat Hunter's main basis for synthetic confidence. If the implementation risk is larger than expected, pivot to Linux eCAR PID monotonicity as the next high-leverage fix because Host/EDR supplied concrete per-host inversion counts.

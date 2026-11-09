# Loop 81 — Post-fix independent blind checkpoint

This fresh panel reviewed a neutral copy that is byte-identical to loop80’s 113 generated source files. No generation behavior changed. Reused scenario validation and authoritative evaluation: **96.5648 PASS**, 142,740 records (parseability 100.00, plausibility 96.93, causality 97.17, timing 90.20).

## Independent reviews

- **Threat Hunter — Inconclusive, confidence 66, synthetic-confidence 42.** Cross-source upload and database-transfer sequences were coherent. A concentrated perimeter scanner was a weak texture concern, not a contradiction.
- **Detection Engineer — Synthetic, confidence 82, synthetic-confidence 68.** Flagged ASA 302013/302014 connection lines as reversing proxy client/server tuples relative to Zeek and proxy records. Post-deliberation verification resolved the apparent reversal as source-native ASA output (see below).
- **Network Forensics — Synthetic, confidence 72, synthetic-confidence 64.** Flagged 209 short-cadence TXT lookups and 93 repeated `.top` queries as distribution texture, while acknowledging plausible malicious DNS explanations. No hard network contradiction reported.
- **Host/EDR Forensics — Inconclusive, confidence 68, synthetic-confidence 48.** Reported 962/963 Sysmon process events matching Security 4688 by PID and image, coherent Mac SSH/process events, and repeated inventory commands on two Macs as a weak texture signal.

Standalone mean synthetic-confidence is **55.50** (mixed/inconclusive), spread 26. Verdict disagreement triggered deliberation. No reviewer reported an impossible host lifecycle or hard contradiction.

## Findings and disposition

Cisco's ASA 302013 documentation states that `outbound` means the original connection was initiated from inside. Its official NAT example for an inside client to an outside server lists the outside server first and the inside client second. The loop's representative record follows that same convention: Zeek has `10.10.1.35:59155 -> 10.10.3.20:8080`, while ASA says `Built outbound ... dmz:10.10.3.20/8080 to inside:10.10.1.35/59155`. EvidenceForge's ASA emitter deliberately reverses responder/originator display order for outbound records. The apparent 2,308/2,354 reversal is therefore source-native formatting, not a cross-source contract gap. No generator change is warranted. This independent verification supersedes the panel's unverified direction-defect interpretation; deliberation scores remain the panel's calibrated opinions on the reports they were given.

| Priority | Finding | Category | Disposition |
|---|---|---|---|
| — | ASA outbound proxy-facing tuple orientation | `false_positive_or_unproven` | Resolved as valid ASA source-native orientation; preserve current emitter. See `asa-direction-probe.json`. |
| P3 | High-rate TXT-query series and repeated `.top` lookup cadence | `distribution_texture` | Preserve as possible malicious DNS behavior unless a source/config defect is demonstrated. |
| P4 | Repeated shell inventory commands on two Macs owned by the same user | `distribution_texture` | Weak signal; no change selected without a broader command-family defect. |
| P4 | 962/963 Windows Sysmon Event 1 rows match Security 4688 by PID/image | `weak_signal` | One unmatched row is not a demonstrated defect; no change selected. |

No code change is selected for loop81. Cisco documentation and the owning emitter establish that the ASA tuple ordering is source-native. The TXT/.top cadence and repeated Mac shell-command vocabulary remain weaker texture signals; no root-cause defect is established. Loop82 will provide another independent checkpoint on the same byte-identical output.

Artifacts: `scenarios/iteration-test/blind-test/loop-81/`.


## Post-deliberation source-semantic verification

The deliberation accepted a direction-reversal claim without examining ASA's native direction convention. Cisco's official [302013 syslog documentation](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html) defines outbound as initiated from inside; Cisco's [ASA NAT example](https://www.cisco.com/c/en/us/support/docs/security/adaptive-security-appliance-asa-software/118996-config-asa-00.html) shows that outbound message listing the outside server before the inside client. The emitter uses that same source-native ordering. Treat the Detection Engineer's apparent reversal and the deliberation's resulting Synthetic votes as a reviewer false positive, not a code defect. The `blind_initial` and `deliberation` values remain unchanged for auditability.

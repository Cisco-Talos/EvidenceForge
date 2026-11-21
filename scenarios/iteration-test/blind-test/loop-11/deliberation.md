# Deliberation Summary

This synthesis records the four experts' actual original reports and their actual deliberation responses. It adds no fifth assessment. All four ultimately selected **Synthetic**, with synthetic-confidence scores of 68–70; this is qualified agreement, not a claim of proven origin, an impossible lifecycle, or a generator identity leak. Verdict confidence and synthetic-confidence are separate measures.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 82 | 40 | Synthetic | 83 | 69 |
| Detection Engineer | Synthetic | 78 | 63 | Synthetic | 86 | 70 |
| Network Forensics | Synthetic | 74 | 62 | Synthetic | 82 | 68 |
| Host/EDR Forensics | Real | 64 | 31 | Synthetic | 80 | 68 |

The arithmetic mean of the four actual revised synthetic-confidence scores is **68.75/100**: `(69 + 70 + 68 + 68) / 4`. Their initial mean was 49.00. These descriptive means are not a calibrated probability of provenance.

### Round 1 — Original positions and distinctive observations

- **Threat Hunter:** Initially Inconclusive because SSH/RDP pivots, DB-to-SCP-to-SMB staging, and account-management effects were coherent. A distinctive positive was DC-01's Event 1102 with Security record numbering restarting at 1 after a visible clear command. Seven binary-document `cat` operations and fourteen RDP authentication delays confined to 7.50–9.65 seconds were weak reservations, with legitimate alternatives explicitly retained.
- **Detection Engineer:** Initially Synthetic primarily because ten of 61 shell-origin native macOS fork notifications formed three clusters retaining identical microsecond phases across independent launches on two Macs. A second, much smaller reservation concerned an extra `ProcessName` in 47 Windows Security 4658 version-0 payloads. Process GUID lifetimes, protocol timing bounds, and certificate/file identities otherwise passed the reported checks.
- **Network Forensics:** Initially Synthetic because repeated observations of the same HTTP transfers had substantially different file durations despite nearly identical enclosing transport durations and packet/byte counts. The broader check found 266 paired files, with 43 duration differences over 10 ms and 23 over 100 ms. Distinct sensor traffic roles, varied DNS responses, and TLS certificate/cipher semantics were credible positives.
- **Host/EDR Forensics:** Initially Real with moderate confidence, emphasizing all 919 visible Sysmon creations matching Security 4688 within two seconds, preserved parent/session identities, and native macOS fork/exec distinctions. Distinctive checks included coherent Linux kernel uptime and correct rejection of apparent same-millisecond normalized macOS ordering violations. Binary-document `cat`/`tee` operations remained weak, technically possible concerns.

### Round 3 — Actual revisions and their causes

- **Threat Hunter:** Inconclusive → Synthetic; verdict confidence 82 → 83; synthetic-confidence 40 → 69. Independently reproduced all three native fork clusters and the 266-pair network result, including both loss-free examples. The two stronger timing findings displaced the original weak behavioral reservations as the basis of the verdict.
- **Detection Engineer:** Synthetic retained; verdict confidence 78 → 86; synthetic-confidence 63 → 70. Confirmed exact whole-second fork relationships in `mach_time` as well as wall time, and directly adopted the two verified cross-sensor file examples as a second mechanism. Did not independently claim the entire 266-pair analysis.
- **Network Forensics:** Synthetic retained; verdict confidence 74 → 82; synthetic-confidence 62 → 68. Independently reproduced the macOS fork finding. Rechecked the network pairs with zero connection/file loss, zero overflow, and no timeout: 248 pairs remained, including 20 with file-duration disagreement exceeding 100 ms.
- **Host/EDR Forensics:** Real → Synthetic; verdict confidence 64 → 80; synthetic-confidence 31 → 68. Reproduced the native fork clusters and both network examples. The native phase artifact was the primary reason for changing position; prior lifecycle checks had not tested this distribution. Did not claim reproduction of the full network aggregate.

## Key Agreements

- All four revised assessments give weight to two distinct recurring timing mechanisms: native macOS fork phases and cross-sensor HTTP file intervals. Multiple reviewers reproducing one mechanism do not create multiple independent defects.
- The process/session graphs, account boundaries, native platform distinctions, protocol tuples, and much of the operational sequencing remain credible. These findings support practical hunting usefulness and survive the verdict changes.
- No expert established a hard impossibility or identity leak. All retained scheduling, transformation, observation, or analyzer alternatives and kept synthetic-confidence below 81.
- High correlation completeness, absent optional event families, thin Unified Log coverage, pre-window state, sanitized domains, and suspicious narrative shape were not treated as synthetic defects.
- Binary-document shell operations and the narrow RDP delay range remain weak findings; neither is necessary for the revised consensus.

## Key Disagreements

The initial split was chiefly about evidentiary weight, not contradictory measurements. Host/EDR's correct lifecycles and the Threat Hunter's coherent operational pivots did not measure the finer timestamp distributions found by Detection and Network. Both changed verdict after independently checking those findings. There is no remaining verdict disagreement in the actual revised responses, but important qualifications remain:

- **Primary weight:** Detection and Host/EDR emphasize native fork timing; Network's original primary concern is repeated file intervals. Threat Hunter relies on both. Successful broad lifecycle checks remain positive evidence, without excluding either timing issue.
- **4658 schema claim:** Detection retains a small native-format reservation. The other three do not add material independent score weight because the native version-specific manifest was not established in their permitted rechecks and collector enrichment could explain the field. Its presence is observed; a proven source-schema violation is not panel consensus.
- **Residual explanations:** No report supplies collector settings or packet captures that settle the HTTP interval semantics, or evidence establishing a timestamp transformation for macOS. The panel favors synthetic origin while leaving those alternatives open.

## Most Convincing Evidence

The ranking below reflects the emphasis and adoption in the actual responses; the experts did not conduct a separate numerical ranking vote.

1. **Synthetic — repeated exact native fork phases (`distribution_texture`).** Three clusters across two Macs cover ten of 61 shell-origin forks. On MAC-MROSS-01, lines 35/38/41/44 retain `.198588000` through 27-, 35-, and 19-second gaps; lines 53/56/59 retain `.487145000`. MAC-MROSS-02 lines 83/86/89 retain `.965208000`. Different children and commands are involved, adjacent exec times vary, and monotonic clock differences preserve whole-second relationships. All four reproduced the native observation. This is one timing mechanism, not separate wall-clock/monotonic-clock defects.
2. **Synthetic — common HTTP file intervals disagree across sensors (`contract_gap`).** The 1,572,864-byte upload on `10.10.1.21:34585 -> 10.10.3.20:8080` has core/DMZ file durations 9.723180/10.994234 seconds, a 1.271054-second difference, versus only 0.000159 seconds for the connection durations. The 151,293,700-byte response with SHA1 `b4a620828cdc65e254de3f32355f9150de6cb9d5` differs by 0.551917 seconds in file duration versus 0.000249 seconds in connection duration. All four checked these examples; Network's stricter loss-free aggregate and Threat Hunter's full pairing reproduction reinforce recurrence.
3. **Realism-supporting — stable process and session ownership.** Host/EDR's 919 matched creations, Detection's process lifetime checks, preserved macOS successive-exec identities, and correct lock/unlock reuse support coherent endpoint semantics. These are genuine positive checks, not proof of real provenance.
4. **Realism-supporting — operational and protocol relationships.** Threat Hunter's actual staging writes and native log-clear reset complement Network's varied DNS/TLS/state behavior and Detection's stable certificate/content identities. The revised reports retain this support for production-like behavior despite the narrower timing defects.

## Most Debated Points

- **Script scheduling versus observed kernel timing:** Whole-second command intent is legitimate. The concern is preservation of all six microsecond digits across separate native forks, including corresponding monotonic intervals, while exec observations vary. This differs from normalized eCAR millisecond ties, which remain excluded. A transformation of both native clock fields remains possible, so the finding is texture rather than impossible causality.
- **Sensor clocks versus file-analyzer semantics:** A constant clock offset cannot explain interval-length disagreement; a clock-rate explanation would also need to account for the tightly matching connection durations. Matching tuples/directions distinguish the examples from different proxy legs, and loss-free filtering retains the issue. Analyzer buffering, processing, or export semantics still prevent a physical-impossibility claim.
- **Correct lifecycles versus provenance:** Structural coherence and fine timing defects can coexist. This distinction, rather than dismissal of earlier positive checks, explains both verdict changes.
- **Weak behaviors and enrichment:** `cat`/`tee` on binary documents can perform valid byte inspection or collection, and the records expose neither stdin nor resulting contents. Shared RDP access behavior can explain a narrow delay range. The 4658 enrichment alternative likewise limits its weight.

## Improvement Recommendations (Consensus)

1. **Separate command intent from native observation timing.** Model scheduling/system-call variation for actual independent forks so planned whole-second offsets do not propagate identical microsecond phases into native fork and child-start observations. Keep wall and monotonic clocks coherent and preserve valid exec/process identities and ordering. All four actual responses support this change if the data is synthetic.
2. **Use a common physical transfer timeline for repeated sensor observations.** Derive file first/last-byte intervals and enclosing transport evidence from shared transfer truth, then apply coherent sensor observation/clock semantics. Validate same-transfer pairs using tuple, direction, byte count and available hashes, explicitly separating proxy legs. Retain the two verified examples and the loss-free paired population as checks. All four support this recommendation.
3. **Explain deliberate timing transformations.** If production export or collector behavior accounts for either pattern, retain relevant transformation and file-analyzer semantics. Do not assume an unrecorded collection explanation or add arbitrary noise. This is explicit in Detection, Network and Threat Hunter's responses and compatible with Host/EDR's qualifications.
4. **Preserve the existing working relationships.** Timing changes should retain account ownership, process/exec identity, session continuity, native effects, and transport-before-authentication order. All four explicitly recommend preserving already credible structure.

Lower-support follow-ups are not promoted to panel consensus: Threat Hunter and Host/EDR recommend application-driven document access when normal document work is intended, while preserving valid shell inspection; Detection recommends keeping deliberate 4658 enrichment separate from raw native payloads. No expert recommends arbitrary perturbation merely to make the records appear less neat.

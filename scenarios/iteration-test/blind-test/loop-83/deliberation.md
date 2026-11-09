# Deliberation Summary

This synthesis uses only the four expert reports. Final positions below are facilitated post-cross-examination assessments; revised scores reflect the panel evidence considered together, not new record-level analysis. Verdict confidence measures confidence in the stated verdict, while synthetic-confidence estimates likelihood of synthetic origin.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 62 | 53 | Inconclusive | 68 | 60 |
| Detection Engineer | Synthetic | 85 | 76 | Synthetic | 84 | 75 |
| Network Forensics Analyst | Synthetic | 74 | 68 | Synthetic | 77 | 70 |
| Host/EDR Forensics Analyst | Inconclusive | 58 | 36 | Inconclusive | 63 | 45 |

## Key Agreements

- The sampled sources are generally well-formed and correlate plausibly. Experts cited consistent process identities across Windows Security, Sysmon, and eCAR; credible macOS process transitions; Zeek protocol rows joining to connection UIDs; and plausible SSH transport/authentication ordering.
- The main reservations are patterned timing or distribution, not broad schema failure: Kerberos event order, the concentrated internal scan, the shared six-hour observation boundary, and tight Windows process-event offsets.
- Every expert identified credible alternatives to at least some synthetic-looking patterns. A bounded export may explain common start/end times; a scheduled or authorized scan may explain the sweep; a collection/normalization pipeline may explain close Windows event offsets. Those alternatives reduce certainty but do not erase the patterns.
- Specialty observations: the Threat Hunter emphasized cross-platform pivots and shared collection-window texture; the Detection Engineer identified a repeated Kerberos sequence defect across both domain controllers; the Network Forensics Analyst characterized the subnet-wide scan and its replication across two sensor views; the Host/EDR Analyst tested process/session identity and lifecycle consistency across endpoint sources.

## Key Disagreements

- The panel divides between two Synthetic verdicts and two Inconclusive verdicts; no report concludes Real. The key difference is evidentiary weight: the Detection Engineer treats 142 same-account/client/port 4769-before-4768 pairs as a repeated protocol-order contradiction, while the Threat Hunter and Host/EDR reports emphasize their checked pivots and do not identify that defect. Their silence is a scope gap, not contrary evidence that the sequence is valid.
- The network sweep is a strong regularity signal, but its meaning is unresolved. The Network Analyst notes the nearly complete destination/port matrix, one-way probes, and matching tuples in core and DMZ views. A real scanner and mirrored or overlapping sensor visibility could produce this; the reports do not establish scanner authorization or sensor topology.
- The six-hour boundary is dataset-wide texture, but not a demonstrated event-level contradiction. The Threat Hunter considers bounded export plausible, and the other reports describe a broadly similar observed interval without establishing whether collection began or ended at those boundaries.
- The Host/EDR Analyst regards the repeated subsecond 4688/Sysmon pairing as weak evidence because a shared timing or normalization pipeline could explain it. The near-matches also support cross-source identity consistency, so this pattern has competing interpretations.

## Most Convincing Evidence

- **Kerberos sequence:** The Detection Engineer reports 62 matching 4769→4768 inversions on DC-01 and 80 on DC-02, within 100 ms and sharing account, client, and source port. This is the panel's strongest synthetic indicator because its repeated ordering conflicts with the reported TGT-before-service-ticket sequence. The other reports do not independently validate or refute these pairs.
- **Concentrated scan:** The Network Analyst reports that `10.10.3.10` probes nearly all of `10.10.2.0/24` across five protocol/port groups in roughly 20 seconds, mostly as unanswered one-packet attempts, with highly overlapping tuples in two sensor views. The matrix's regularity is persuasive; authorization and sensor placement remain plausible alternatives.
- **Cross-source identity and lifecycle agreement:** The Host/EDR Analyst reports 964 of 968 Windows Security 4688 records matched to Sysmon event 1 by PID and image, with eCAR agreement on sampled process context. The Threat Hunter and Detection Engineer also report aligned SSH, DNS/network, and Kerberos-related pivots. This is meaningful realism evidence, although correlation alone cannot settle provenance.
- **Shared observation window:** The Threat Hunter notes many independent feeds begin near 13:00 UTC and end near 19:00 UTC. It is a broad distribution signal, but less decisive than the Kerberos ordering because a deliberately bounded export can explain it.

## Most Debated Points

- **Does the Kerberos pattern control the verdict?** For the Detection Engineer, recurrence across both DCs makes ordinary log-delivery delay unlikely. For the inconclusive reports, the issue was not examined in their stated pivots; therefore the panel cannot treat their non-reporting as a rebuttal. A remaining alternative is that the candidate pair grouping joined separate exchanges despite matching account, client, and port, though the Detection Engineer's repeated short-gap pattern makes that explanation less compelling.
- **Is the scan evidence of authored data or real operations?** The full, rapid matrix is unusual, and duplication across two views may reflect a generated pattern. A production inventory scan crossing both sensors remains viable. The reports do not provide the scanner inventory or topology needed to choose between those explanations.
- **How much should broad regularity count?** Similar six-hour file windows and narrow endpoint timestamp offsets could arise from synthetic generation, but also from shared collection/export and normalization. These are supporting texture signals, not proofs on their own.
- **Do strong formats and joins offset behavioral defects?** The reports consistently find native-looking formats and successful UID, tuple, PID, and session joins. Those features establish internal coherence in sampled evidence, but they do not neutralize a repeated causal inversion if the Kerberos pairing is correct.

## Improvement Recommendations (Consensus)

- Review the reported same-account/client/port Kerberos pairs and ensure each genuine exchange emits the 4768 TGT record before its 4769 service-ticket record. Preserve natural timing gaps and avoid grouping unrelated exchanges solely by proximity.
- If the scan is intended synthetic activity, vary its timing, target coverage, and port set, and include a less uniform mix of responsive, filtered, and closed destinations while retaining valid sensor joins. If it represents real activity, document scanner authorization and whether both sensors would observe it.
- If the six-hour scope is an export boundary, make source-specific observation windows clear. If it is generated activity, vary source starts and stops while retaining shared timestamps for records describing the same event.
- Preserve the cross-source identity and protocol joins that the panel found convincing. Any changes to timing texture should keep the existing process, tuple, UID, and session relationships intact.

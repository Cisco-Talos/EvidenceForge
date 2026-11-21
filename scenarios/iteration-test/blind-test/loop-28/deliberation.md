# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 74 | 61 | Synthetic | 77 | 63 |
| Detection Engineer | Inconclusive | 75 | 28 | Synthetic | 78 | 63 |
| Network Forensics | Real | 65 | 29 | Synthetic | 73 | 61 |
| Host/EDR Forensics | Synthetic | 79 | 64 | Synthetic | 81 | 64 |

The arithmetic mean of the four actual revised synthetic-confidence scores is **(63 + 63 + 61 + 64) / 4 = 62.75/100**. This averages synthetic-confidence scores, not verdict confidence; it is not an additional reviewer judgment or a calibrated probability.

This summary uses the four original reports and four actual deliberation responses. The facilitator performed no additional data recheck and supplies no fifth expert position. The responses address the original reports; references within individual responses to another reviewer's Real or Inconclusive position concern those initial positions, not a continuing final vote.

The Threat Hunter initially favored Synthetic because three native Mac fork clusters retained exact microsecond phases and corresponding monotonic intervals, while credible SSH, database-transfer, and Windows privilege-change pivots supported investigative realism. After reporting a recheck of the Host/EDR reviewer's weaker Windows timing corroboration, the hunter retained Synthetic, raising verdict confidence 74→77 and synthetic-confidence 61→63. Independent agreement on the already-known Mac records was explicitly not counted as additional evidence.

The Detection Engineer initially chose Inconclusive with low synthetic-confidence: native schemas, process/session identities, and visible lifecycles were convincing; repeated Mac administrative vocabulary was weak because the same operator used both machines. Source-specific observations included Event 1102's distinct UserData schema, Mac exec-generation handling, and unresolved Zeek references excluded from scoring. The engineer changed to Synthetic after reporting reproduction of the Mac fork/exec and monotonic-clock pattern, with modest Windows corroboration: verdict confidence 75→78 and synthetic-confidence 28→63.

Network Forensics initially preferred Real based on checked protocol-to-connection tuples and intervals, TLS key/certificate compatibility, file accounting, sensor roles, and explicit-proxy semantics. Approximately one-second HTTP lifetimes and short successful TCP syslog connections were weak reservations. The reviewer changed to Synthetic after reporting independent verification of the native endpoint timing evidence, while retaining the positive network findings: verdict confidence 65→73 and synthetic-confidence 29→61.

Host/EDR Forensics initially favored Synthetic because of the Mac timing clusters and weaker Windows process-time corroboration, alongside coherent endpoint lifecycles, SSH sessions, and native fork/exec distinctions. Specialty checks also found stable examined Mac file metadata and consistent Windows process identities. The reviewer retained Synthetic after reporting verification of the hunter's monotonic-clock comparison: verdict confidence 79→81, with synthetic-confidence unchanged at 64 because the same narrow timing concern remained decisive.

## Key Agreements

- All four actual final responses favor a **qualified Synthetic** verdict. The shared principal indicator is one related `distribution_texture` concern: ten native Mac fork observations in three clusters across two hosts retain exact fractional phases through irregular whole-second gaps. Matching monotonic deltas strengthen the timing interpretation without constituting an independent defect class.
- The records otherwise demonstrate substantial technical coherence in the checks reported. Native Windows/macOS distinctions, process identities and visible lifecycles, SSH transport/authentication/session relationships, and network protocol/accounting relationships remain positive evidence. Successful joins are not themselves evidence of synthesis.
- No reviewer demonstrated a hard contradiction or impossible visible lifecycle that would justify the highest synthetic-confidence band. The low-end likely-synthetic scores reflect this limit.
- The Windows millisecond pattern is materially weaker corroboration of the same concern. Shared command vocabulary, HTTP-duration concentration, and short syslog sessions receive little additional weight.
- Missing pre-window initiators, absent optional sources, 13 unresolved HTTP FUID references, and the single unresolved SMB connection reference are not scored as synthetic without a collection-completeness guarantee. A MeetingAssist policy message is not treated as proof of successful execution.

## Key Disagreements

There is no final categorical verdict split in the submitted responses. The original disagreement concerned how much a localized timing pattern should outweigh technically plausible records. Detection Engineering's initial Inconclusive and Network Forensics' initial Real positions changed after their reported endpoint rechecks; their schema, lifecycle, and network findings were not withdrawn.

The final responses retain differences in evidentiary weight and certainty: synthetic-confidence ranges from 61 to 64 and verdict confidence from 73 to 81. Host/EDR retains the strongest stated confidence, while Network Forensics remains most cautious. These differences do not establish a dispute over the reproduced timestamps.

All retain alternatives rather than claiming proof of origin: paced automation, a replay mechanism, or a timestamp-transforming collector/sanitizer could produce real-origin telemetry with such phases. Ordinary scheduling explains intended whole-second offsets more readily than exact native microsecond fork observations; however, the records cannot exclude a mechanism transforming both wall and monotonic representations. The absence of a visible orchestrator is not proof that none existed.

## Most Convincing Evidence

The ordering below reflects the reviewers' expressed weights, not a separate ranked panel vote.

1. **Mac fork phase retention — primary synthetic indicator.** MAC-MROSS-01 ES lines 35/38/41/44 share `.198588000` through 27/35/19-second gaps; lines 55/58/61 share `.487145000` through 38/29-second gaps. MAC-MROSS-02 lines 86/89/92 share `.965208000` through 22/41-second gaps. These are distinct children from persistent zsh parents, with subsequent exec fractions varying. The responses reconcile the scope as ten affected observations among 56 shell-parent forks; the narrower zsh count is 54.
2. **Corresponding monotonic-clock spacing — strengthens the same indicator.** Reported `mach_time` differences preserve the exact gaps at 24,000,000 ticks per second, making a wall-clock-string-only explanation less persuasive. Both clocks come from the same source; coherent transformation remains possible, and this is not scored as a second independent defect.
3. **Native identity and lifecycle coherence — substantial positive evidence.** Reported eCAR and Sysmon checks found no demonstrated visible process use-before-create or use-after-termination defects. Distinct fork/exec generations, Windows event shapes, and SSH session ordering remain credible. This limits synthetic-confidence rather than proving real origin.
4. **Network/protocol consistency — substantial positive evidence.** Checked tuples, intervals, TLS certificate/key relationships, file bounds, proxy-control versus tunnel accounting, and varied sensor/service behavior remain intact. These support production plausibility while being compatible with a localized endpoint timing artifact.
5. **WS-MCHEN retained process-time milliseconds — modest corroboration.** Sysmon Event 1 process times `14:45:35.733`, `14:46:18.733`, and `14:47:17.733` span distinct commands and retain `.733`. Reviewers explicitly assign less weight because millisecond collisions and selection effects are easier explanations than repeated microsecond phases.

## Most Debated Points

- **Timing construction versus operational automation or collection transformation.** Native forks, separate commands, irregular gaps, varying exec fractions, and matching monotonic intervals make the pattern more specific than repetitive shell history. A real scheduling/transform mechanism remains possible; the panel does not resolve provenance from these records alone.
- **Technical validity versus provenance.** Correct schemas and causal ordering do not refute constructed timing. Conversely, a timing concern does not invalidate the checked schemas, identities, network records, or hunting pivots. This distinction drove the two actual verdict changes.
- **Independent reviewers versus independent defects.** Multiple reviewers reproduced the same Mac observations. That corroborates the observation without multiplying the number of underlying defect classes. Windows corroboration is also related and lower-weight.
- **Network texture and incomplete joins.** The reported 989/2,565 core HTTP-service durations at 0.9–1.2 seconds and 88 core/16 database successful syslog sessions below six seconds may reflect explicit-proxy/client policy or batching. Unresolved FUID/UID joins may reflect selective collection. None becomes a hard contradiction because the endpoint finding is stronger.

## Improvement Recommendations (Consensus)

- **If synthetic, resolve each command's actual fork/process-creation time through its own execution scheduling and launch latency.** Recheck the three identified Mac clusters and the WS-MCHEN process-time cluster. Avoid carrying a common subsecond phase unchanged through integer-second offsets; preserve causal dependencies, meaningful fork-to-exec delays, and coherent wall/monotonic clocks.
- **If deliberate orchestration or transformation explains the timing, retain its provenance separately.** Document the mechanism sufficiently to assess its native timing semantics; where the existing process collection would capture execution machinery, represent it consistently. Do not treat absent machinery as proof of its absence or add unrelated log products to address this finding.
- **Preserve the relationships already judged credible.** Keep source-native event shapes, PID/exec generations, process/session ownership, transport ordering, proxy accounting, and source-specific observation timing. Arbitrary noise, command failures, or broken correlations would not fix the identified fingerprint.
- **Validate the network duration modes against the intended deployment before changing them.** Model HTTP/proxy connection lifetime and TCP syslog reuse according to actual client/proxy/forwarder behavior; batching remains a legitimate explanation for short forwarding connections.
- **Make collection assumptions available when assessing unresolved joins.** Reconcile dangling file/connection references only if complete relevant collection is required; otherwise preserve legitimate filtering/loss assumptions rather than treating the gaps as mandatory defects.

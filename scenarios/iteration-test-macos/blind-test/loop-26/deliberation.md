# Deliberation Summary

## Scope and status

This is a facilitator synthesis of the four supplied reports, not a fifth forensic review. Only `threat.md`, `detection.md`, `network.md`, `host.md`, and the deliberation instructions were consulted. No underlying records, code, scenario, or assessment history were inspected. All observations below are report-attributed and have not been independently rechecked.

The revised positions and final scores are **facilitator-modeled**, not actual new reviewer turns, reviewer-approved revisions, or measured consensus. “Agreement” describes compatibility among the initial reports; recommendations synthesize those reports. Scores express synthetic confidence, not defect percentages or calibrated provenance probabilities. Verdict confidence is distinct from synthetic confidence.

## Round 1 — Initial positions

- **Threat Hunter:** Inconclusive; verdict confidence 78; synthetic confidence 43. Practical web, database/export, SSH-transfer, and proxy-upload pivots work. Its strongest adverse observation is the receiver session identifier disagreement: syslog session `378852` versus eCAR `378837`, with matching root account, sshd PID, and source tuple. The report found only one disagreement among 71 uniquely matched Linux starts. Its distinctive contribution is following operational activity across host and network evidence while separating shell redirection from child argv.
- **Detection Engineer:** Synthetic; verdict confidence 80; synthetic confidence 64. It reports 18/20 selected macOS command intervals within 20 ms of whole seconds and 901/901 matched Windows Security process creations later than Sysmon, with similar host-level timing ranges. It also reports coherent XML, PID conversion, file-handle lifecycles, and protocol joins. Its distinctive contribution is cross-host timing-distribution analysis.
- **Network Forensics:** Inconclusive; verdict confidence 78; synthetic confidence 24. It reports coherent same-sensor tuples and intervals, TLS visibility, proxy routing, certificate identities, and credible remote-session durations. Two small aggregate extracted-content/transport accounting excesses and TTL-30 concentration remain weak questions, with explicit decoding, capture-gap, and resolver alternatives. Its distinctive contribution is distinguishing sensor observations and content bytes from unique activities and transport bytes.
- **Host/EDR Forensics:** Synthetic; verdict confidence 82; synthetic confidence 68. Its strongest finding is exact repeated microsecond fractions in macOS fork notifications, including 31 non-browser notifications in 13 groups and identical browser startup offsets on both Macs. Four exact 1 ms transitions add little independent weight. Windows identities, hashes, and sampled lifecycles and Linux activity are otherwise coherent. Its distinctive contribution is distinguishing native fork timing from exec timing, shell history, and normalized telemetry.

## Round 2 — Cross-examination

### Mac timing: corroboration with limited independence

Detection's near-integer exec spacing and Host's exact fork-fraction repetitions are compatible views of the same timing family. The fork observation is more precise than the exec observation: it locates repeated anchors before the small variable fork-to-exec deltas. This strengthens the timing-template interpretation, but the two findings must not be counted as two independent families. The browser offsets and 1 ms boundaries are further manifestations, not separate proof.

Scripts, macros, workload replay, timestamp reconstruction, and export normalization remain alternatives. Both Macs share a user according to Detection, reducing independence. A shell parent does not establish that commands were manually entered; a report's suggestion of think-time variation does not establish authored intent. The reports do not demonstrate which timestamp transformations occurred or whether automation was intended. The absence of declared automation cannot itself establish fabrication. These qualifications cap the strength of the finding without erasing the observed repetition.

### Broad operational coherence versus local statistical evidence

Threat's workable activity and Network's strong consistency do not refute Host's macOS texture: coherent semantics and artificial-looking timing can coexist. Conversely, the timing finding should not invalidate otherwise coherent network or Windows identities. The strongest adverse evidence is concentrated in two small Mac exports; the reports establish no impossible fleet-wide lifecycle.

Threat and Network could reasonably raise their overall synthetic scores after seeing the endpoint evidence, while retaining inconclusive verdicts because their own source families remain largely production-like. This is a modeled weighting change, not newly discovered evidence.

### Windows source timing requires provider/export context

Detection reports a universal positive Security-minus-Sysmon offset across 901 pairs. That is a repeated distribution, not a demonstrated impossible ordering. Host's identity agreement and lifecycle checks neither explain nor contradict it. Event creation, provider publication, export/reconstruction, and ingestion are different concepts; the reported `TimeCreated` fields alone do not validate a specific source-timing model. Shared software or collection behavior could yield similar offsets across hosts.

The finding remains secondary until representative native captures and collection metadata establish an expected distribution. The synthesis does not recommend forcing offsets to change sign or adding jitter solely to defeat the statistic.

### SSH identifier discrepancy: localized correlation issue

Threat's single mismatch is more specific than a distribution concern, but its provenance implications remain uncertain. Distinct identifier namespaces or a normalization defect can occur in collected real data. The 70 agreements among other matched starts make a universal separate-namespace explanation less straightforward, but do not rule out a local transformation error. Host's plausible sampled Linux SSH sequences do not cover or refute this exact receiver discrepancy. No report establishes the underlying namespace contract, so the result is a localized unresolved correlation issue, not proof of synthetic origin.

### Network byte accounting is not a contradiction between reports

Detection's absence of individually oversized files does not contradict Network's small aggregate `seen_bytes` excesses for two connections. Individual-file bounds and sums across extracted content answer different questions. Compression/decoding, file extraction semantics, and capture gaps require metadata before a transport-byte invariant can be asserted. Network explicitly withholds a hard-contradiction claim. TTL concentration likewise remains weak in the presence of plausible resolver policy and reported cache aging. Neither issue supports a large score increase.

## Round 3 — Facilitator-modeled revised positions

These are proposed revisions for reporting purposes only; no expert was reconvened.

- **Threat Hunter:** Inconclusive; verdict confidence **76**; synthetic confidence **52** (from 43). The exact native fork repetitions add a stronger adverse family beyond its localized session mismatch. Working pivots, automation/export alternatives, and the small Mac scope still prevent a confident provenance verdict.
- **Detection Engineer:** Synthetic; verdict confidence **80**; synthetic confidence **65** (from 64). Host's fork evidence sharpens the timing interpretation, with only a small adjustment because it overlaps Detection's original command-spacing evidence. Source timing and shared-user alternatives limit escalation.
- **Network Forensics:** Inconclusive; verdict confidence **75**; synthetic confidence **35** (from 24). Host's endpoint timing changes the whole-bundle balance while its network-specific conclusions remain intact. No new network defect is inferred, and the score remains below 50 because its strongest own checks are coherent.
- **Host/EDR Forensics:** Synthetic; verdict confidence **82**; synthetic confidence **68** (unchanged). Detection corroborates the same timing family; Threat and Network add operational counterweight. Neither is a reason to double-count or substantially increase this score.

## Panel Composition

All final columns below are facilitator-modeled.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Modeled Final Verdict | Modeled Final Verdict Confidence | Modeled Final Synthetic-Confidence |
|---|---|---:|---:|---|---:|---:|
| Threat Hunter | Inconclusive | 78 | 43 | Inconclusive | 76 | 52 |
| Detection Engineer | Synthetic | 80 | 64 | Synthetic | 80 | 65 |
| Network Forensics | Inconclusive | 78 | 24 | Inconclusive | 75 | 35 |
| Host/EDR Forensics | Synthetic | 82 | 68 | Synthetic | 82 | 68 |

Initial unweighted mean: **49.75**. Facilitator-modeled final unweighted mean: **55.00 / 100** (`(52 + 65 + 35 + 68) / 4`). The mean is descriptive; it is not an additional expert verdict or measured consensus. Two modeled verdicts remain inconclusive and two remain synthetic. The synthesis supports mixed evidence with a modest synthetic lean, concentrated in macOS timing, rather than agreement on provenance.

## Key Agreements

The reports broadly support usable parsing and practical correlation, credible process/session identity, and no demonstrated impossible lifecycle in their bounded checks. They distinguish native evidence from normalized views and refuse to treat missing unselected families, out-of-window boundaries, sanitized names, narrative clarity, or correlation completeness as independent fabrication indicators. Detection and Host identify compatible macOS timing texture. No report establishes raw packet provenance or exhaustive source-native schema validity.

## Key Disagreements

The main difference is evidentiary weighting: Detection and Host favor a synthetic interpretation of timing regularity; Threat and Network give more weight to coherent operational/source relationships and alternative transformations. Network's low initial score is source-scoped counterweight, not a rebuttal to Mac fork evidence. The reports leave unresolved whether Mac timing reflects scheduling, automation, or exported timestamp treatment; whether Windows offsets reflect providers/collection; and whether the SSH identifier difference is a local mapping defect or separate namespace.

## Most Convincing Evidence

Ranked for provenance discrimination within these reports, rather than counted as independent defects:

1. **Exact macOS fork-fraction repetition across command groups**, strengthened by matching browser offsets. Most specific adverse texture; still compatible with automation or timestamp transformation.
2. **Localized SCP receiver identifier mismatch**, with unusually strong tuple/PID/account linkage and a 70/71 agreement comparison. A correlation issue whose generation versus normalization origin remains unresolved.
3. **Windows Security/Sysmon timing distribution across 901 matches.** Broad statistical observation with substantial provider/export uncertainty; no invalid individual pair demonstrated.
4. **Operational and lifecycle coherence across endpoints, Linux administration, proxy paths, and network protocol joins.** Strong counterweight against broad construction failures, with limited ability to prove real provenance.

The two HTTP accounting questions and TTL concentration remain below these findings in weight.

## Most Debated Points

- Exact native timestamp repetition versus scripts, replay, or export reconstruction; no inferred manual-entry intent.
- Whether source timing distributions are suspicious without calibrated provider/collection metadata.
- Different session identifier namespaces versus a localized normalization/correlation defect.
- Aggregate extracted-content accounting versus individual-file bounds and decoded transport content.
- How far small endpoint timing samples should move an otherwise coherent multi-source assessment.

## Improvement Recommendations (Synthesis; Not Measured Consensus)

1. **Resolve Mac timing semantics first.** Determine whether exported fork timestamps preserve native occurrence times or are reconstructed. If independent command execution is intended, represent actual per-occurrence timing rather than reusing a fractional anchor; if scripted or replayed activity is intended, preserve the appropriate invocation/parent and timing semantics when that evidence belongs to selected collection. Do not invent automation or manual intent based on these reports. Preserve fork/exec/exit ordering and shared process identities.
2. **Calibrate Windows source relationships against the applicable providers and export path.** Keep occurrence/publication/ingestion metadata distinct where available, and compare representative native distributions before changing timing. Do not require random sign reversals or arbitrary host jitter.
3. **Reconcile the receiver's logind/eCAR session mapping.** Establish the identifier namespace, then trace root, sshd PID `2983988`, and source `10.10.4.10:45342` through login, transfer, and logout. Use one identity if that is the contract; expose the mapping if namespaces legitimately differ. Retain the reported valid transport/authentication/execution ordering.
4. **Make the two HTTP accounting cases auditable.** Retain relevant encoding/transfer and gap metadata where the collection supports it, distinguish decoded content from TCP payload, and check aggregate extraction semantics. Do not clamp file sizes to transport totals without establishing the right invariant.
5. **Preserve demonstrated strengths.** Keep canonical identities, file-handle lifecycles, sensor-local tuple/UID consistency, TLS visibility, certificate stability, and cache aging. Verify resolver TTL policy before changing repeated TTLs. The reports provide no basis for arbitrary extra failures, traffic volume, event families, or unrelated narrative complexity.

# Deliberation Summary

This is a facilitator synthesis of four submitted reports, not a fifth authenticity assessment or a transcript of an interactive discussion. Only those reports and the supplied deliberation instructions were read. No new expert responses, revised votes, or independent data checks were obtained. All original verdicts, verdict confidences, and synthetic-confidence scores remain unchanged. The unweighted original synthetic-confidence mean is **24.75/100**: (20 + 20 + 24 + 35) / 4. This descriptive mean is not a calibrated probability of origin.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 75 | 20 | Inconclusive; original retained | 75 | 20 |
| Detection Engineer | Inconclusive | 78 | 20 | Inconclusive; original retained | 78 | 20 |
| Network Forensics | Real | 64 | 24 | Real; original retained | 64 | 24 |
| Host/EDR Forensics | Inconclusive | 82 | 35 | Inconclusive; original retained | 82 | 35 |

The final columns document preservation, not a post-discussion re-vote.

## Round 1 — Reported Positions

- **Threat Hunter:** Production-like evidence without sufficient origin attribution. The exact Mac-to-Linux SSH tuple preserves transport-before-authentication ordering; the support-upload pivot preserves explicit-proxy addressing and distinct body/wire byte measurements. Mac fork/exec distinctions and routine mixed-fleet activity support plausible observations. Scheduled-command recurrence was examined and excluded as a demonstrated indicator.
- **Detection Engineer:** Production-like parsing, native fields, and exact joins warrant low observed synthetic confidence, while bounded coverage leaves origin inconclusive. Windows PID 5180 and parent 4356 agree across Security, Sysmon, and eCAR after hexadecimal conversion. The exact TLS UID falls inside its connection lifetime. A suspected Windows path-escaping issue was explicitly tested in parsed values and rejected.
- **Network Forensics:** Tentative Real at confidence 64, explicitly allowing a well-modeled synthetic alternative. Exact CONNECT/TCP and resumed-TLS/TCP joins work; DNS outcomes, TTLs, RTTs, failure states, and sensor-specific populations show plausible variation. Similar dominant successful-TCP history proportions receive only slight synthetic weight.
- **Host/EDR Forensics:** Inconclusive despite coherent Windows, Linux SSH, and Mac execution identities. FILE-SRV-01's concentrated WMI/taskhost vocabulary and recurring short workstation commands leave weak templating uncertainty. Role-specific logon mixtures and different Linux shell vocabulary across hosts provide counterweight.

## Round 2 — Cross-Examination of the Submitted Evidence

### Real versus Inconclusive

The principal disagreement concerns what coherent observations justify about origin, rather than a conflicting reading of the same record. Network Forensics gives a tentative Real verdict based on plausible protocol populations and exact network joins; the other reviewers reserve origin judgment despite similarly favorable observations. The Network report itself acknowledges that synthesis could reproduce those properties. Conversely, the three Inconclusive verdicts do not assert synthetic origin or poor realism. Low synthetic-confidence scores and high confidence in an inconclusive verdict answer different questions and can coexist.

These reports support agreement that the examined telemetry looks production-like. They do not support unanimous Real, a provenance certification, or a synthetic verdict. Neither the mean score nor the vote split resolves that epistemic limit.

### Resolved path-escaping suspicion

Detection Engineer tested parsed paths rather than presentation escaping: zero doubled separators in 263 Security 4688 path pairs, 263 Sysmon process-create images, and 3,102 eCAR records with C:-prefixed image paths across the three examined hosts. This specific suspicion is resolved against a defect within that scope. It must not be retained as an improvement target or inferred elsewhere from escaped textual displays. The result does not claim every path in the collection was checked.

### Windows service vocabulary

Host/EDR reports 51/97 FILE-SRV-01 process creations using three WMI/taskhost command strings: 21 WmiPrvSE, 17 bare taskhostw, and 13 taskhostw /Run. Repeated workstation PowerShell/cmd/taskhost strings add a weaker observation. These are measurable concentrations, but the report establishes neither implausible rates nor an operation whose necessary arguments are missing. Recurrent service and management workloads remain a credible explanation. The other reviewers' coherent identity joins do not disprove limited vocabulary; limited vocabulary likewise does not invalidate those joins. This is a conditional workload-check target, not an established generator defect.

### Successful-TCP history texture

Network Forensics finds ShADadfF in 65.8% of core, 67.1% of DMZ, and 59.5% of database TCP SF connections, with explicit denominators. Similar dominant shapes can motivate comparison by service and TCP stack, but common stacks and overlapping sensor observations can explain similarity. The remaining histories vary. Nothing in the reports demonstrates an impossible history, packet-accounting relationship, or required missing companion. Arbitrarily randomizing histories would not follow from the evidence.

### Strength and scope limits

The Windows process pivot and TLS pivot are independently described by multiple reports, but they reuse the same identities; they are corroborated interpretations, not additional independent sampled transactions. Other cited SSH and upload pivots widen the examples without establishing universal correctness. Full native-version compliance, all parent lifecycles, every remote-session continuation, and long-period temporal behavior remain untested. These are limits on inference, not defects. A roughly six-hour slice does not require visible pre-window creators, post-window terminations, or equal lifecycle totals. Resumed TLS does not necessarily require a new certificate record. A policy message does not prove successful execution. No narrative, source-completeness, sanitization, or complete-join penalty is justified.

## Round 3 — Revised Positions

No reviewers were reconvened, so no revisions are asserted. The original positions and scores remain exactly as submitted. Cross-report evidence can contextualize the differences, but the facilitator cannot claim that an expert changed their confidence or accepted another expert's recommendation.

## Key Agreements

- Exact identities, tuples, ownership, and source-specific timing work in the cited Windows, SSH, TLS, proxy, and Mac examples.
- No report establishes a hard contradiction, required-companion gap, verified native-schema defect, or impossible observed lifecycle.
- Source-specific byte semantics and execution semantics require interpretation before judging apparent discrepancies.
- Coverage is bounded; favorable examples do not certify collection-wide correctness or production provenance.

## Most Convincing Evidence

Ranked by directness and cross-report support, not as a new vote:

1. **Windows process identity:** Security record 129968, Sysmon record 30326, and eCAR line 17 on WS-AJOHNSON-01 agree on PID 5180, parent 4356, image, command, SYSTEM ownership, and logon context, with plausible subsecond observation differences.
2. **Transport/application timing:** Zeek UID CJFbfoEDBNNxzdqDm1 has a TLS observation 132.230 ms after transport open within its 901.012 ms lifetime. The reported sensor-wide TLS boundary checks add bounded aggregate support.
3. **Linux SSH lifecycle:** APP-INT-01 syslog lines 58–60 and 76, with exact eCAR session IDs, preserve connection, accepted authentication, PAM open, and close for source port 38780. The separate Threat Hunter Mac SSH pivot also preserves transport-before-authentication ordering.
4. **Proxy protocol boundaries:** The upload's 1,573,258-byte body versus 1,573,700 client wire bytes and its 96-byte response body versus 306 server wire bytes are compatible measurements, not a mismatch. CONNECT body lengths likewise need not equal tunnel payload.
5. **Mac lifetime versus execution identity:** Stable PID/start time and object identity coexist with changed executable images and execution identifiers. Fork, exec, exit, and policy observations are not interchangeable events.

These observations support realism within scope; none independently authenticates origin.

## Improvement Recommendations

There is **no demonstrated defect requiring correction**, and no unanimous corrective recommendation was elicited. The supported follow-up targets are conditional:

- Validate FILE-SRV-01's service-command concentration against its intended workload, including service identity, rates, and timing. Preserve repetition when supported; change behavior only if that comparison establishes a mismatch. Short command lines alone do not warrant invented arguments or arbitrary variety.
- Compare dominant TCP histories by distinct service population and endpoint stack, accounting for overlapping sensors. Change history modeling only if packet/lifecycle evidence supports a discrepancy, preserving valid states and byte/packet relationships.
- Retain the demonstrated identity ownership, source observation timing, native/normalized execution distinctions, explicit-proxy addressing, and body-versus-wire accounting. Do not add source families, forced lifecycle closures, retries, or narrative obscurity solely for appearance.

The DB scp and privileged PowerShell records remain optional hunt-validation leads in the Threat Hunter report, not substantiated corrective targets. The path-escaping concern is closed within its tested scope.

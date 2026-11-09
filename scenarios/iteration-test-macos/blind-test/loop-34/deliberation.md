# Deliberation Summary

This is a facilitated synthesis of four submitted independent reports, using only those reports. No experts were reconvened, no underlying logs were re-examined, and no new measurements were made. All revised positions and consensus statements below are **facilitator-modeled**, not reconvened votes. Reported counts and line references retain their original reviewers' scope and qualifications. Synthetic-confidence scores describe perceived synthetic origin; verdict confidence describes confidence in the stated classification.

## Round 1 — Present Findings

### Threat Hunter

- **Initial position:** Synthetic; verdict confidence **86**; synthetic-confidence **67**.
- **Strongest evidence:** Native macOS command groups retain identical fractional timestamps across distinct forks: 32 of 57 zsh forks in 13 groups across two hosts. Linux normalized FLOW attribution also assigns a reverse-shell socket to an outer pipeline Bash and an scp transport socket to scp itself, without the expected child process records; this is conditional on collector attribution semantics. Fleet-wide sudo activity is concentrated before 14:30, with overlapping maintenance vocabulary.
- **Unique contribution:** Verified useful intrusion pivots and qualified their interpretation. The web upload, outbound shell tuple, database transfer session and receiver artifact, Windows netonly identity, and inspected-proxy exfiltration align. The concern is authenticity texture and precise process ownership, not an impossible intrusion narrative. Repeated cat/tee handling of office binaries adds modest behavioral texture evidence.

### Detection Engineer

- **Initial position:** Inconclusive; verdict confidence **78**; synthetic-confidence **42**.
- **Strongest concerns:** Repeated macOS discovery/status argument vectors may reflect small command pools. Two tiny DNS/TCP exchanges finish in under 9 ms yet carry bidirectional retransmission history. Both concerns admit ordinary explanations, including troubleshooting habits and duplicate capture.
- **Strongest counterevidence:** Windows event distinctions, Sysmon process identity and session joins are coherent; Zeek companions match sensor-local connections; native Mac fork/exec/exit identity handling is credible.
- **Unique contribution:** Separates source-native compatibility from provenance and explicitly rejects simplistic payload/header subtraction, missing-source requirements, and an unsupported interpretation of the Mac policy message as a completed denial.

### Network Forensics

- **Initial position:** Synthetic; verdict confidence **86**; synthetic-confidence **65**.
- **Strongest evidence:** First GET request timestamps sit on an exact integer-millisecond offset from their connection start for 124/182 core and 224/346 DMZ rows, across 19 and 71 client addresses. GET/POST are affected while CONNECT and core SSL largely are not. These are two views of one timing-family finding, not two independent defects.
- **Strongest counterevidence:** Protocol ordering, tuples, certificate identity, connection states, DNS diversity and proxy accounting are coherent.
- **Unique contribution:** A measured same-sensor comparison population weakens global clock-rounding explanations. Seven HTTP body/connection byte discrepancies remain explicitly unscored because encoding, partial observation and byte-accounting semantics are unresolved.

### Host/EDR Forensics

- **Initial position:** Synthetic; verdict confidence **78**; synthetic-confidence **63**.
- **Strongest evidence:** Six native macOS inventory processes have exactly 2.000000-second fork-to-exit lifetimes across two hosts, despite variable intermediate exec delays. Four shell handoffs occur exactly 0.001000 seconds after the previous child exits. One no-argument id runtime is nearly 85 seconds, but this is only a weak signal.
- **Strongest counterevidence:** Durable process lifetimes, parentage, executable hashes, Windows session ownership and platform-native rendering generally hold together.
- **Unique contribution:** Distinguishes invariant fork-anchored lifetime from the final executable's runtime, and distinguishes queued shell execution itself from repeated exact latency increments.

## Round 2 — Cross-Examination

### Timing texture versus actual contradictions

The central friction is evidentiary weight, not contradictory observations. Detection's coherent lifecycles and the other reviewers' suspicious timing distributions can both be true: valid ordering and identity joins do not establish natural temporal variation. Conversely, exact offsets do not establish impossible ordering or a protocol violation. None of the reports demonstrates a hard contradiction.

The HTTP result has the strongest reported internal control: most first GETs preserve the fractional remainder after an integer-millisecond addition, whereas CONNECT and core SSL generally do not. Same-sensor comparisons remove inter-sensor clock skew as an explanation. The numerous client addresses weaken a single monitoring application's timer as an explanation. A method-specific export transformation remains possible; without provenance it cannot be eliminated. The GET/POST effect and CONNECT contrast strengthen one finding and must not be scored as separate independent failures. Duplicate sensor views likewise do not increase the independent sample count.

Host's six identical inventory lifetimes and Threat's repeated fork fractions concern different timing relationships in the same native source population. Together they support suspicion of constructed timing, but their shared source and possible common processing mechanism limit independence. Scheduled inventory is normal; identical six-decimal lifetimes across varying exec delays are the specific concern. A controlled wrapper or export treatment could explain this, but the reports do not establish one. Four exact shell handoffs are weaker supporting evidence because queued execution is normal and the sample is small. The long id runtime remains weak: a stall or pause is possible and no contradictory process activity was demonstrated.

### Detection's blind spot and the burden of a synthetic verdict

Detection reported repeated command vocabulary but did not report the exact inventory lifetimes, repeated fractional fork anchors, or method-specific HTTP offset measurements. These are material additional findings from other specialists. A lack of hard contradictions can reasonably limit confidence without requiring an inconclusive verdict when measured distribution evidence accumulates. The modeled revision therefore increases Detection's score, while preserving its objection to treating plausible anomalies as impossibilities.

Threat, Network and Host should also absorb Detection's positive controls. All four reports describe credible source-native and correlation behavior. Those checks prevent a near-certain synthetic conclusion and keep small behavioral anomalies from outweighing coherent process/session/protocol relationships.

### Direct socket actor versus initiating-command attribution

Threat's Bash and scp examples challenge precise endpoint ownership, not the existence of the network session. Standard scp delegation and pipeline execution make the expected child distinction meaningful. Detection and Host's valid visible lifetimes do not resolve this: a wrong actor can still remain alive throughout the flow, and absent children alone do not prove a defect in a selected export.

If FLOW PID means the direct socket-owning process, these examples support a semantic contract gap. If the collector intentionally attributes to an initiating ancestor, the inference weakens substantially. No report establishes that collector contract. The two examples are grouped as one qualified concern, with no added assertion of impossible transport or universally missing process telemetry.

### Qualified byte interpretations

Network's seven HTTP body totals exceeding connection responder bytes remain ambiguous and contribute **zero** added synthetic weight. Its example also includes missed bytes and partial-file accounting, and the reports do not resolve encoding or accounting definitions. Detection's caution about subtracting unique payload bytes from IP bytes is compatible with Network's minimum-header checks: retransmissions can enlarge the difference without invalidating accounting. Neither observation establishes an impossible byte count.

Threat's proxy/client byte correspondence is a positive investigative join, not proof that unrelated body-byte discrepancies are resolved. CONNECT control bytes, tunnel bytes and inspected HTTP content must retain their different meanings. No report supports conflating zero CONNECT response-body size with an empty subsequent tunnel.

### Retransmissions, workload repetition and collection boundaries

Short retransmission-bearing exchanges are unusual but remain weak because capture duplication or other observation effects could produce the history without a retransmission timer delay. Network did not report a contradictory header or connection-state finding that would remove this alternative. Mirrored sensors do not make these independent observations.

Shared maintenance vocabulary and early sudo concentration can arise from coordinated work; repeated Mac commands can reflect the same user's habits. cat/tee on office formats is possible. These are bounded behavioral texture concerns and retain lower weight than the measured timing distributions. None warrants demanding absent GUI telemetry, pre-window process starts, post-window exits or additional native source families. All reviewers' restraint about the Mac policy message remains intact: the quoted wording establishes neither completed denial nor successful execution.

## Round 3 — Revised Positions

**Every position below is facilitator-modeled, not an actual revised expert statement.** No reviewer was asked to cast another vote.

- **Threat Hunter:** Retain Synthetic; verdict confidence **86 → 87**, synthetic-confidence **67 → 70**. Network's method-selective HTTP timing and Host's invariant inventory lifetimes reinforce the existing timing interpretation. Keep Bash/scp attribution conditional and avoid multiplying related timing symptoms into independent high-weight penalties.
- **Detection Engineer:** Revise Inconclusive to Synthetic; verdict confidence **78 → 76**, synthetic-confidence **42 → 62**. The new exact native and network timing measurements are materially stronger than repeated vocabulary alone and support a narrow likely-synthetic position. Confidence in the new verdict is slightly lower because provenance/export explanations remain open and no hard contradiction is demonstrated.
- **Network Forensics:** Retain Synthetic; verdict confidence **86 → 87**, synthetic-confidence **65 → 68**. Host and Threat supply endpoint timing evidence outside the network source. Preserve the network report's narrow finding and leave ambiguous byte discrepancies unscored.
- **Host/EDR Forensics:** Retain Synthetic; verdict confidence **78 → 82**, synthetic-confidence **63 → 68**. Network's controlled GET/CONNECT comparison and Threat's wider repeated-fraction count support construction beyond the six inventory examples. Detection's identity checks reinforce that the concern is timing texture, not broken lifecycle semantics.

## Round 4 — Consensus Summary

### Panel Composition

Final columns are **facilitator-modeled positions**, not reconvened votes.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 86 | 67 | Synthetic | 87 | 70 |
| Detection Engineer | Inconclusive | 78 | 42 | Synthetic | 76 | 62 |
| Network Forensics | Synthetic | 86 | 65 | Synthetic | 87 | 68 |
| Host/EDR Forensics | Synthetic | 78 | 63 | Synthetic | 82 | 68 |

**Final modeled synthetic-confidence scores: 70, 62, 68, 68. Arithmetic mean: 67.0/100.** The initial mean was 59.25/100. The final mean is a descriptive summary of judgments, not a calibrated probability or four independent votes.

### Key Agreements

- The collection supports coherent investigation, with convincing source-native fields and useful process, session, tuple and artifact relationships.
- No submitted report demonstrates a hard contradiction, generator identity leak or obligatory missing source family.
- Exact native process timings and method-selective HTTP offset distributions are stronger authenticity signals than repeated command vocabulary, suspicious behavior or a narratable intrusion.
- Valid cross-source correlation should be preserved; it does not need to be deliberately damaged to improve authenticity.
- Ambiguous byte differences, short retransmission histories and the Mac policy wording do not justify hard-contradiction claims.

### Key Disagreements

The original reports disagree most about how much distributional evidence is sufficient: Detection initially stays inconclusive, while the other three favor synthetic. The modeled convergence depends on accepting their reported exact timing measurements, without independent remeasurement. Export transformation or controlled execution remain unresolved alternative explanations.

Direct Linux socket ownership is also unresolved. Threat identifies plausible process-attribution gaps, while the other reports' lifecycle checks neither confirm nor refute the collector's direct-actor contract. Fleet maintenance concentration and repetitive file/command recipes have plausible operational explanations and remain supporting concerns only.

### Most Convincing Evidence

1. **HTTP first-request timing lattice:** High reported prevalence, many clients, same-sensor UID matching, and the GET/CONNECT/SSL contrast make this the best-controlled distribution finding. It remains timing texture rather than a protocol contradiction.
2. **Six exact native inventory lifetimes:** Identical 2.000000-second fork-to-exit durations across two hosts despite varying exec delays strongly suggest a shared timing rule, subject to controlled-execution/export alternatives.
3. **Repeated native fork fractional anchors:** Thirteen groups affecting 32/57 zsh forks provide broader corroborating texture. Exact one-millisecond handoffs are weaker supporting detail in the same family.
4. **Coherent identity and protocol semantics:** Independent specialty checks report no visible impossible process/session use or protocol-before-transport ordering. This is the strongest counterweight to a high synthetic-confidence score.
5. **Qualified Linux transport attribution:** Potentially meaningful if FLOW PID is the direct socket actor; materially weaker without that documented contract. It is not established as a hard contradiction.

### Most Debated Points

- Whether precise timing distributions can outweigh strong native-schema and lifecycle compatibility without a hard contradiction.
- Whether family-specific export transformations or controlled process wrappers explain the timing fingerprints.
- How much independent weight to give related Mac timing measurements and duplicated network sensor views.
- Whether Linux FLOW attributes the direct socket owner or an initiating ancestor.
- Why unresolved HTTP byte accounting and capture-sensitive retransmission histories should remain excluded or weak despite appearing suspicious.

### Improvement Recommendations (Consensus)

These are facilitator-modeled areas of convergence from the submitted recommendations, not reconvened agreement.

1. Derive HTTP request offsets from realistic transport/application timing with submillisecond variation; verify distributions by method, client role and sensor, including the CONNECT/SSL comparison populations. Preserve same-UID ordering and coherent duplicate sensor views.
2. Give native inventory processes executable-appropriate, variable fork/exec/exit lifetimes. Vary shell continuation latency with queued versus interactive input behavior while preserving foreground blocking, durable identities and legitimate bursts. Avoid mechanically retaining one fractional timestamp across whole command groups.
3. Clarify direct-process versus initiating-ancestor attribution. If direct socket ownership is intended, represent the Bash payload child and scp's SSH transport child with their proper lifecycles, rather than assigning their sockets to an initiating command.
4. Tie privileged maintenance and interactive command choices to host role, user task and schedule. Broaden office-file handling by application and file type; reserve cat/tee on office binaries for supported diagnostic or shell workflows.
5. Validate retransmission histories against exchange duration, counters and capture assumptions, while retaining plausible duplicate-capture explanations. Resolve byte-accounting definitions before treating HTTP body/connection totals as defects; the current reports do not justify changing those counts solely to force equality.
6. Preserve the currently convincing process/session identity integrity, OS-native semantics, TLS visibility limits, certificate stability, proxy distinctions and connection/protocol lifecycle relationships while improving timing and workload texture.

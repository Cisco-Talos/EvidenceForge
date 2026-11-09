# Deliberation Summary

## Panel Composition

The four independent assessments disagree on the overall verdict. The synthetic-confidence scores span 42 points (24–66), while verdict confidence is more tightly grouped (62–72). These are distinct measures: verdict confidence describes confidence in the chosen verdict; synthetic-confidence describes how likely the data is synthetic. They should not be read as interchangeable or forced into a common scale.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 72/100 | 57/100 | Inconclusive* | 72/100* | 57/100* |
| Detection Engineer | Synthetic | 72/100 | 66/100 | Synthetic* | 72/100* | 66/100* |
| Network Forensics | Real | 62/100 | 24/100 | Real* | 62/100* | 24/100* |
| Host/EDR Forensics | Inconclusive (slice leans production-like) | 62/100 | 34/100 | Inconclusive* | 62/100* | 34/100* |

\* No expert supplied a post-discussion revision. These final columns carry forward the only positions actually reported; they are not newly elicited or inferred revisions.

## Round 1 — Independent Positions

- **Threat Hunter — Inconclusive; verdict confidence 72, synthetic-confidence 57.** Strongest evidence for authenticity is the specific support-upload chain from `WS-LNGUYEN-01`: shell history, eCAR process/file activity, authenticated proxy POST, Zeek HTTP/DNS and matching tuple/body metadata, plus ASA connection evidence. The main contrary finding is strictly increasing Linux eCAR process PIDs across hosts, with large gaps relative to visible creates. Its unique contribution is treating those gaps as a distribution concern while explicitly allowing filtering, source scope, or prior uptime as explanations.
- **Detection Engineer — Synthetic; verdict confidence 72, synthetic-confidence 66.** The strongest synthetic signal is the same `debian-sa1 1 1` cron command appearing exactly 12 times at half-hour intervals on each of ten Linux hosts, with stable host-specific minute offsets and very small execution jitter. Against that, the report cites strong Windows, Zeek, eCAR, SMB, and macOS joins, including a Windows DNS/Kerberos sequence and matching macOS SSH observations. Its specialist contribution is the fleet-wide scheduled-event cadence, which it rates as high-weight distribution texture rather than a schema or correlation defect.
- **Network Forensics — Real; verdict confidence 62, synthetic-confidence 24.** Its strongest evidence is complete source-local Zeek DNS/HTTP/SSL UID joins with plausible timestamps, mixed connection states and DNS outcomes, and role-specific core/database/DMZ traffic. It also cites matching DB/DMZ MySQL tuple and counters with a small sensor timing offset. Its unique contribution is detailed sensor-scope analysis; it finds no strong network contradiction and treats CONNECT concentration and uneven TLS visibility as explainable but configuration-dependent.
- **Host/EDR Forensics — Inconclusive, with the host slice leaning production-like; verdict confidence 62, synthetic-confidence 34.** Strong evidence includes a Windows updater process matching across Sysmon, Security, and eCAR; plausible macOS fork/exec identity progression; and Linux sudo/PAM session pairs. Its unique caution is the tightly aligned six-hour Windows collection envelope and small macOS lifecycle count differences, both judged weak and compatible with bounded collection. It found no concrete host-level contradiction.

## Round 2 — Cross-Examination

### Linux regularities: scheduled telemetry and PID progression

The most consequential friction is between the Detection Engineer's fleet-wide scheduled-telemetry finding and the Threat Hunter's Linux PID progression finding. They concern different measurements: one is the repeated timing and content of a sysstat cron record; the other is the relation between visible process-create counts and increasing PIDs. They can coexist and do not directly contradict each other.

The Detection Engineer's evidence is more specifically quantified across the fleet: ten hosts, twelve exact half-hour slots per host, with host-specific minute phase and sub-second jitter. The Threat Hunter independently notes large monotonic PID advances on multiple Linux hosts, but explicitly cannot distinguish generated PID assignment from filtering, high unobserved process churn, or pre-window uptime. The Host/EDR report adds that its Linux examples have plausible sudo/PAM boundaries and does not establish a PID defect; this is not a direct rebuttal because those checks address command/session lifecycle, not fleet-wide PID allocation or schedule distributions. The Network report's favorable verdict does not weigh in on either Linux endpoint signal because it is scoped to network telemetry.

Alternative explanations remain live. A shared sysstat policy with host-specific scheduler phase could produce regular half-hour records; the reports do not provide configuration or a longer baseline to establish whether it did. Filtering or sampling could account for sparse process creates beside large PID advances. Conversely, the exact repeated run count and cadence across different Linux roles make the scheduled pattern a stronger tell than the mere fact that sysstat runs every 30 minutes. The reports support investigating both findings against collection policy and a wider time window; they do not establish either as a hard contradiction.

### Strong joins versus source-native regularity

The Threat Hunter and Detection Engineer emphasize the detailed support-upload and Windows/Zeek/eCAR joins; the Host/EDR analyst likewise highlights process identity and timing agreement across independent endpoint representations. The Network analyst independently finds strong Zeek-local joins and plausible multi-sensor MySQL observations. These are concrete positive observations, but their existence does not settle whether some fleet-level distributions look modeled. In particular, a coherent support upload demonstrates that those records correlate; the reports do not claim it alone proves provenance for the whole bundle.

The network review found the HTTP CONNECT concentration, overlapping core/DMZ HTTP/TLS distributions, and relatively sparse core SSL view noteworthy but explainable by proxy path and sensor placement. These are weaker than its source-local UID and timing checks, and it explicitly did not perform a complete alert-to-flow reconciliation. That scope limit means its Real verdict is a network-slice conclusion, not a refutation of the Linux host signals.

### Collection-window and coverage concerns

The Threat Hunter, Detection Engineer, and Host/EDR analyst all describe a bounded six-hour collection window, though they assign it little or no independent synthetic weight. The Host/EDR analyst's Windows host intervals are closely aligned, while the network and threat-hunting reports describe a common overall envelope. A deliberate export boundary is a straightforward explanation; without collection configuration or longer retention, the reports do not establish that it is artificial.

The Host/EDR analyst's macOS count differences are small and compatible with boundary effects. The Threat Hunter specifically treats sparse Unified Log coverage as thin coverage, not proof of missing or fabricated activity. These observations therefore do not outweigh the stronger Linux cadence question.

## Round 3 — Revised Positions

The completed reports contain no revised verdicts, confidence values, synthetic-confidence scores, or statements that one expert changed their mind after hearing another. No revisions can be attributed without inventing positions. The disagreements therefore remain as reported: Detection Engineer says Synthetic; Network Forensics says Real; Threat Hunter and Host/EDR Forensics say Inconclusive.

## Round 4 — Consensus Summary

### Key Agreements

- The reviewed records contain substantial source-native structure and meaningful cross-source agreement; no report identified a hard format or causal contradiction in its reviewed scope.
- The Linux scheduled sysstat cadence is a concrete distribution-texture concern, especially in the Detection Engineer's fleet-wide accounting. The reports do not establish whether it reflects fleet policy or modeling.
- The Linux PID progression deserves clarification against collection scope and host history, but the Threat Hunter expressly treats it as ambiguous rather than proof of fabrication.
- The shared bounded observation window is not, by itself, decisive evidence of synthetic origin.
- Longer baselines and collection/sensor configuration would materially improve interpretation of the disputed texture and visibility patterns.

### Key Disagreements

- The overall verdict remains unresolved. The Detection Engineer gives the Linux scheduled cadence enough weight for Synthetic; Network Forensics judges its reviewed network evidence Real; the two broader host-focused assessments remain Inconclusive.
- The experts differ in scope and evidentiary weight. The network assessment establishes credible network structure and joins, but does not assess Linux endpoint cadence. The Host/EDR assessment establishes plausible endpoint lifecycles but does not test whether sysstat records are distributed realistically across a fleet. Neither settles the other's principal concern.
- Positive cross-source joins are strong evidence of internal coherence, while their weight as evidence of real-world provenance is disputed. No report says those joins eliminate the possibility of synthetic data.

### Most Convincing Evidence

1. **Fleet-wide Linux sysstat rhythm (synthetic-leaning):** ten Linux hosts each show twelve identical records at exact 30-minute spacing with stable host-specific offsets and very small execution jitter. It is the most specifically repeated cross-host distribution finding, though its production-policy alternative is untested.
2. **Support-upload multi-source chain (realism-leaning):** shell history, eCAR process and file events, proxy identity and byte count, Zeek URL/tuple/body metadata, DNS, and ASA path align around one technically plausible operation. It strongly demonstrates coherent evidence construction but does not independently establish provenance.
3. **Linux PID progression (synthetic-leaning, ambiguous):** multiple hosts show strictly increasing PIDs with large gaps relative to visible create counts. Filtering and unobserved process churn remain plausible alternatives, so this is weaker than a contradiction.
4. **Native process and protocol joins (realism-leaning):** sampled Windows process/network/authentication records, Zeek companion UIDs, macOS fork/exec identities, and SSH/SMB observations retain source-appropriate fields and plausible ordering across the reviewed sources.
5. **Bounded, aligned collection windows (weak synthetic texture):** several reports observe the same six-hour envelope. Each treats a deliberate capture/export boundary as plausible, so this ranks below the Linux-specific distribution findings.

### Most Debated Points

- Whether the repeated `debian-sa1` schedule reflects an actual common fleet policy or an over-regular dataset-wide pattern.
- Whether large Linux PID gaps are normal for the source's collection/filtering scope or indicate overly clean generated PID progression.
- How much strong correlation across selected events should influence a whole-bundle authenticity verdict when a separate fleet-level distribution looks unusually regular.
- Whether sensor differences (CONNECT-heavy HTTP, overlapping core/DMZ views, sparse core SSL) are explained by real collection topology; the network report considers them plausible but asks for configuration evidence.

### Improvement Recommendations (Consensus)

- **Document and validate Linux collection policy.** Compare the half-hour `debian-sa1` schedule and per-host phase offsets with the intended fleet configuration. If it is a modeled schedule, introduce realistic missed or delayed runs and host variation only where the target policy warrants it; if it is a production policy, retain that configuration as provenance context.
- **Clarify Linux process visibility.** Record whether eCAR process creates are complete, filtered, or sampled, and compare the observed PID range with host uptime and PID allocation history. Use longer host-native baselines before treating the gaps as a realism defect.
- **Retain the strong canonical joins.** Preserve source-native process, identity, tuple, timestamp, and byte fields in the support-upload, Windows, Zeek, SMB, and macOS examples; the reviewers consistently found these relationships useful and coherent.
- **Add context for bounded windows and sensor visibility.** When available, keep collection-window metadata and Zeek sensor/proxy placement details so reviewers can distinguish capture boundaries, path overlap, and source-specific gaps from distribution artifacts.

The panel does not reach an overall authenticity consensus. Its strongest shared conclusion is narrower: the evidence is internally coherent across several sources, while Linux scheduled telemetry and PID distribution require collection-context checks before the conflicting Real and Synthetic verdicts can be reconciled.

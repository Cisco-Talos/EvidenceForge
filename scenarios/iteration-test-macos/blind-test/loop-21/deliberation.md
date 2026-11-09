# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Mixed / broadly production-like; persistence concern | 82/100 | 32/100 | Mixed / material network realism concern | 84/100 | 46/100 |
| Detection Engineer | Plausible; no hard contradiction in reviewed records | 84/100 | 28/100 | Mixed; sampled host evidence plausible, dataset-level scan is a strong concern | 86/100 | 48/100 |
| Network Forensics | Mostly synthetic / materially non-production-like | 95/100 | 88/100 | Synthetic-leaning; strong scan-matrix concern | 95/100 | 88/100 |
| Host/EDR Forensics | Mostly coherent; moderate ordering inconsistency and weak failure cadence | 86/100 | 50/100 | Mostly coherent host telemetry; dataset-level network concern remains | 87/100 | 55/100 |

Scores are the reviewers' synthetic-confidence scores, where lower means more production-like. Host/EDR's original score of 5/10 is normalized to 50/100. The revised positions account for each other's reports; they do not represent a new independent data review.

## Round 1 — Independent Findings

- **Threat Hunter:** Mixed, broadly production-like activity (82% confidence; 32/100). Strongest evidence was coherent inbound and outbound SSH lifecycles, signed ordinary applications and user activity, and the root-owned LaunchDaemon plist create/delete sequence. The plist operation is a persistence lead, but activation is not established by the reviewed artifacts.
- **Detection Engineer:** Plausible (84%; 28/100). The two macOS SSH sessions align across eCAR transport/login, Unified Log authentication, and Endpoint Security process lineage. It found no confirmed schema or hard ordering defect in its reviewed samples; sparse Unified Log coverage was treated as neutral.
- **Network Forensics:** Mostly synthetic (95%; 88/100). Its strongest finding was a 1,521-row Zeek matrix from one source covering 254 subnet addresses on six ports in about 27 seconds, including port 0 against nearly every address. It also reported varied ordinary service traffic, plausible proxy/TLS vantage points, and matching DNS/connection UIDs.
- **Host/EDR Forensics:** Mostly coherent (86%; 50/100). It identified a few-second gap between Endpoint Security SSH process events and the eCAR projection, with the eCAR login preceding its child-process rows by 1–15 ms, plus four local failures at roughly 6, 6, and 12 second gaps. It considered source delay plausible and neither issue a confirmed impossibility.

## Round 2 — Cross-Examination

### Scope explains most of the apparent disagreement

The Network finding is a positive, dataset-level observation with a precise file range, host/port counts, and timing. The other three reviews emphasized endpoint, SSH, and representative format samples. Their absence of a host-side hard contradiction does not rebut the network matrix; it indicates that the network observation was not in their reviewed focus. The matrix therefore deserves independent weight rather than being averaged away by the three lower scores.

### Scan-matrix strength and alternative explanation

An intentionally scripted scan can be real, and the Network reviewer explicitly did not claim the activity was technically impossible. The combination of exact subnet breadth, repeated six-port set, port-0 sweep, and very short completion window is still a strong distribution-pattern indicator. The ordinary network traffic and sensor correlations make the rest of the network data more credible, but they do not explain that concentrated matrix.

### Host-side observations remain narrower and less decisive

Threat Hunter, Detection Engineer, and Host/EDR all found credible SSH identity and lifecycle correlation. Host/EDR's eCAR-versus-Endpoint Security offset could reflect source observation or publication delay; the report does not establish that the rendered times must represent identical clocks or capture moments. The small bad-password sequence is possible user behavior and remains a weak regularity signal.

Threat Hunter's LaunchDaemon plist create/delete activity is concrete and unusual, but the report found no activation, launch, or child process attributable to it. That leaves a valid investigation lead without establishing successful persistence or an impossible lifecycle.

## Round 3 — Revised Positions

- **Threat Hunter:** Retains a mixed verdict, raising synthetic-confidence from 32 to 46 and confidence from 82% to 84%. The exhaustive matrix is stronger direct evidence of synthetic-looking distribution than the plist lifecycle alone; the latter remains unproven as persistence.
- **Detection Engineer:** Revises from plausible to mixed at the dataset level, raising synthetic-confidence from 28 to 48 and confidence from 84% to 86%. The initial SSH and schema observations remain valid, but the detailed matrix was outside its primary sample and materially changes a bundle-wide assessment.
- **Network Forensics:** Retains its synthetic-leaning conclusion and score of 88, with confidence 95%. No report offered evidence that explains the matrix's breadth and regularity. Realistic ordinary traffic tempers, but does not remove, the scan concern.
- **Host/EDR Forensics:** Keeps a mostly coherent host verdict, raising synthetic-confidence from 50 to 55 and confidence from 86% to 87%. The network matrix is a dataset-level concern, while the SSH process/session evidence remains coherent. Its ordering and login-failure findings stay moderate and weak, respectively.

## Round 4 — Consensus Summary

### Key Agreements

- The observed SSH tuples, identities, and session/process evidence are substantially coherent across eCAR, Unified Log, and Endpoint Security.
- The network bundle contains realistic protocol diversity, connection-state and byte variation, DNS/connection UID correlation, and plausible proxy/TLS sensor layering.
- The LaunchDaemon plist create/delete sequence does not, by itself, prove activation or execution.
- The internal subnet/port matrix is the strongest dataset-level synthetic indicator; no other review invalidated its direct counts or timing.

### Key Disagreements

- Network Forensics judged the scan matrix decisive for a synthetic verdict. The other reviewers' original lower scores reflected narrower host-oriented or representative samples; after seeing the network report, they raised their dataset-level scores but did not discard their valid host findings.
- The panel does not establish whether the matrix represents a deliberate scanner in a particular environment or generated regularity. The realism concern is the exhaustive, symmetric pattern and port-0 cohort, not the mere presence of scanning.
- The eCAR/Endpoint Security timing gap may indicate a source-timing contract issue, but source delay remains a plausible explanation. The current reports do not establish a hard contradiction.

### Most Convincing Evidence

1. **Strong synthetic indicator:** 1,521 connection attempts cover 254 addresses with nearly the same six ports in about 27 seconds; port 0 is included across nearly the entire subnet. The exact breadth and timing make this more than a generic “suspicious activity” observation.
2. **Strong realism evidence:** SSH transport, authentication, user identity, process lineage, and session closure correlate across multiple host/network sources on the reviewed sessions.
3. **Moderate host-timeline concern:** On one Mac, the eCAR login row precedes its eCAR child-process rows by milliseconds while Endpoint Security has the process chain earlier. A consistent source-timing model should preserve or explicitly explain this projection.
4. **Unresolved investigation lead:** A root process creates and later deletes a LaunchDaemon plist, but reviewed records do not show registration or execution. Treat activation as unknown.
5. **Positive network realism:** DNS/connection identity and proxy/TLS observations align across their respective sensor vantage points, with varied ordinary connection states and payload sizes.

### Most Debated Points

- Whether the exact subnet/port matrix could be explained by an unusually scripted but genuine discovery run. The reviewers agree it is possible operationally; the dispute is its production-like distribution, not technical feasibility.
- Whether the eCAR/Endpoint Security timestamp offset is an occurrence-order defect or a representation of collection delay. The available reports favor caution over calling it impossible.
- Whether the root-owned plist operation is benign inventory maintenance or attempted persistence. The reviewed evidence supports neither conclusion; file creation and deletion do not establish launchd activation.

### Improvement Recommendations (Consensus)

1. Make modeled scan behavior use a bounded, irregular target set and realistic service-port selection. Avoid applying an identical port list to essentially every subnet address in one short pass, and keep port 0 out of ordinary service-discovery sweeps unless a small, explicit probe requires it.
2. Preserve the strong SSH lifecycle contracts across transport, authentication, process startup, and session close. For eCAR projections, keep occurrence ordering consistent with process events or represent source observation delay explicitly.
3. Keep LaunchDaemon persistence semantics explicit: distinguish file staging from registration, activation, service execution, unload, and cleanup. Do not imply successful persistence through a create/delete pair alone.
4. Retain the observed DNS UID links and sensor-specific proxy/TLS vantage points; reviewers regarded these as credible network evidence.
5. If modeling repeated local authentication failures, vary retry spacing within a plausible attempt sequence; the four-event 6/6/12-second rhythm was a weak, not decisive, tell.

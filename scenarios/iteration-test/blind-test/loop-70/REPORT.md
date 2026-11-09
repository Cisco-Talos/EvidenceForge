# Mac-inclusive loop 70: assessment and root-cause repair

Loop 70 repaired UDP firewall state expiry after loop 69's generated sample reproduced the UDP/514 ASA/Zeek lifecycle issue from earlier network review. The authored scenario, seed, and six inputs were unchanged. The standalone panel completed with four independent reviewers; conflicting verdicts triggered a facilitator report that preserved the disagreement.

## Selected family and repair

The loop 69 probe found 11 ASA UDP/514 build/teardown pairs with `duration 0:00:00`; corresponding Zeek rows were one-way `S0` without `duration`, including multi-packet examples. The source-observation planner had placed ASA datagram teardown only 83–8,500 microseconds after the observed close. ASA prints seconds, so both lifecycle rows appeared in the same second.

Loop 70 added a data-driven `source.firewall.datagram_teardown` timing relationship with a right-skewed 1-second to 2-minute idle interval. Firewall state expiry now sits after the last observed datagram independently of Zeek's transport-close semantics. The Zeek one-way UDP `S0` rows remain durationless.

The targeted tests passed: 39 network-observation tests and 71 ASA emitter tests. Scenario validation passed with the existing noise-to-signal warning and pivot notices. Config validation passed for all 101 files; Ruff and the behavior manifest checks passed at revision 490. The full routine pytest suite was not run.

## Quantitative evaluation

Automated evaluation passed at **96.7911** across **135,860 records**. Pillars: parseability **100.00**, plausibility **96.85**, causality **97.66**, and timing **90.82**. All applicable hard acceptance checks passed.

## Focused rendered-output verification

The fixed-seed sample retained **33** Zeek DMZ UDP/514 `S0` observations, none with a Zeek `duration` field; eight had multiple originator packets. Eleven ASA UDP/514 pairs matched by connection ID. Displayed teardown durations were **7–78 seconds**, with **zero** zero-duration pairs. This verifies the targeted rendered defect for this sample; the upper bound still needs comparison against a qualified firewall policy/source profile.

## Independent expert panel

| Expert | Verdict | Verdict confidence | Synthetic-confidence score | Main finding |
|---|---|---:|---:|---|
| Threat Hunter | Inconclusive | 72 | 57 | Broadly coherent support-upload chain; Linux eCAR PIDs rise monotonically with large gaps relative to visible process creates, though collection filtering or unseen churn may explain them. |
| Detection Engineer | Synthetic | 72 | 66 | Ten Linux hosts each show 12 `debian-sa1` cron records at exact half-hour slots with per-host phase and little timing variation; source formats and joins were otherwise strong. |
| Network Forensics | Real | 62 | 24 | Sensor-specific Zeek views, UID joins, DNS outcomes, states, and traffic paths look plausible; no strong network contradiction was found. |
| Host/EDR Forensics | Inconclusive | 62 | 34 | Windows, macOS, and Linux host relationships looked source-native; aligned capture windows and small Mac lifecycle-count differences were weak signals. |

Mean standalone synthetic-confidence score was **45.25** (mixed/inconclusive), mean verdict confidence **67**, and score spread **42**. Deliberation was triggered for verdict disagreement and score spread. No reviewers supplied revised positions, so the facilitator preserved the original positions instead of inventing new votes. The facilitator highlighted the Linux scheduled cadence and PID progression as unresolved context-dependent findings and the coherent source-native joins as positive evidence.

## Prioritized improvements

| Priority | Finding | Category | Reviewer rating | Scope / likely leverage | Owner and disposition |
|---|---|---|---|---|---|
| P2 | Half-hour `debian-sa1` rhythm repeats 12 times on ten Linux hosts with fixed per-host phase | `distribution_texture` | Detection: not labeled | Fleet-wide; medium to high | Review modeled schedule against likely fleet policy. If varying the schedule, preserve cron semantics and model justified missed/delayed runs; prior host reviews considered regular cron plausible, so do not add arbitrary jitter without evidence. |
| P2 | Linux eCAR PIDs rise monotonically by thousands across hosts despite far fewer visible create records | `distribution_texture` | Threat Hunter: not labeled | Multiple Linux hosts; medium | Check collector completeness, filtering, uptime, PID allocation, and hidden process churn. Treat as unresolved until a source-qualified progression probe establishes an inconsistency. |
| P3 | Windows endpoint files share a tightly aligned six-hour collection interval | `environment_or_collection_plausibility` | Host: not labeled | Nine Windows hosts; low | Keep the intentional bounded-window possibility; qualify only against the collection profile. |
| P3 | Core and DMZ HTTP/CONNECT and TLS distributions differ in visibility | `weak_signal` | Network: not labeled | Two sensor views; low | Compare with sensor/proxy placement before changing the network model. |

The loop 70 firewall fix is verified for the selected fixed seed and retained as a separate source-observation lifecycle. Next assessment priority should favor remaining independently evidenced source-ownership/lifecycle defects over speculative changes to a valid-looking cron policy or PID model.

## Artifacts

- [Family contract](family-contract.md)
- [Canonical scores](scores.json)
- [Blinded reviewer reports](.)
- [Facilitator deliberation](deliberation.md)
- [Automated evaluation JSON](automated-eval.json)
- [UDP lifecycle probe](udp-lifecycle-probe.json)
- [Generation provenance and file hashes](provenance.json)
- [Validation and test evidence](test-evidence.json)

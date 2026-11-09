# Mac-inclusive loop 69: assessment and root-cause repair

Completed scenario validation, generation, quantitative evaluation, a focused rendered-output
probe, and four independent standalone expert reviews. This is the first loop in the requested
20-loop continuation (69–88). The six authored benchmark inputs and seed remain unchanged.

## Selected family and repair

The selected family was Linux foreground task and think-time distribution. The owner is the
shared `baseline.foreground_think` relationship, sampled after the canonical foreground
process lifetime and before another Linux shell command may run. Its upper bound increased
from 18 seconds to 180 seconds; the existing 800 ms minimum, process lifetime, shell wakeup,
and bash/eCAR event construction remain in their owning layers. The behavior manifest records
material revision 489.

This timing profile is shared across baseline Linux command activity and authored shell work
that uses the same foreground-process owner. Bash history and eCAR process telemetry consume
the resulting times. The fix is family-level and data-driven; it does not change source-local
timestamps or edit the scenario.

The focused timing-profile suite passes **11 tests**, `eforge validate-config` passes all **101
files**, Ruff lint and format checks pass for the touched test, and the generation behavior
manifest is current at revision 489. The normal full pytest suite was not run. Initial
`uv run` could not fetch `hatchling` because network DNS is unavailable; the existing local
`.venv` commands completed successfully.

The rendered-output probe found **15** developer commands and **14** inter-command gaps on
`WS-LNGUYEN-01`; **zero** gaps fall between 94 and 98 seconds. Gaps span 85.525 seconds to
56.414 minutes. The same output contains bash history and eCAR command observations. This is
evidence that the cited seed-specific cadence is absent after the repair, not a general
measurement of Linux human timing. The broad long-tail change still needs independent
realism review, which the standalone panel did not specifically call out.

## Quantitative evaluation

Automated score: **96.7911**, **PASS**, across **135,860 records**. All applicable hard
acceptance criteria pass. Pillars: parseability **100.00**, plausibility **96.85**, causality
**97.66**, timing **90.82**. The evaluator does not measure the specific foreground think-time
distribution well; it remains a parseability and canonical-invariant guardrail.

## Standalone expert summaries

- **Threat Hunter:** Inconclusive, verdict confidence **68**, synthetic-confidence score
  **51**. Strong SSH tuple/auth joins and host-to-proxy activity were convincing. The reviewer
  raised weak concerns about the thin macOS Unified Log sample and high DC network-event
  counts, while recognizing both could reflect collection policy and workload.
- **Detection Engineer:** Inconclusive, verdict confidence **68**, synthetic-confidence score
  **56**. Sampled Windows, Zeek, macOS ES/Unified Log, eCAR and syslog formats and joins were
  credible. Weak concerns included thin macOS Unified Log, high DC network telemetry and one
  plausible but high sequential Linux PID pair.
- **Network Forensics:** Inconclusive, verdict confidence **64**, synthetic-confidence score
  **34**. Protocol states, DNS, TLS/X.509, proxy legs, and UIDs were coherent. The six-hour
  daytime boundary and shared hourly volume peak were weak signals without longer baseline
  context.
- **Host/EDR Forensics:** Inconclusive, verdict confidence **58**, synthetic-confidence score
  **53**. Windows process trees, Linux SSH/PAM lifecycles and macOS process identity evidence
  were convincing. Repeated generic Linux diagnostics and sparse macOS Unified Log were weak
  texture/collection concerns, not contradictions.

No reviewer reported an impossible visible lifecycle or decisive native-format contradiction.
No deliberation was triggered: verdicts agree, mean verdict confidence is **64.5**, and the
synthetic-confidence spread is **22** points.

## Prioritized improvements

There is no verified P0 or P1 defect in this loop. Priorities below are coordinator ratings;
reviewers did not assign original P0–P4 labels.

| Priority | Finding | Category | Reviewer original rating | Scope / score leverage | Owner, risk, and disposition |
|---|---|---|---|---|---|
| P2 | Sparse macOS Unified Log sample beside Endpoint Security/eCAR | environment_or_collection_plausibility | Threat, Detection, Host: not labeled | Repeated across two Macs; weak to medium | Source observation/collection profile; high scope risk because additional native source families remain gated. Check the accepted collection contract before changing coverage. Defer pending qualified source evidence. |
| P2 | High Windows Filtering Platform / Sysmon network-event volume on DCs | distribution_texture | Threat, Detection: not labeled | Two domain controllers; weak | Observation/filtering profile and host-role traffic; medium risk. Compare family counts with a qualified collection baseline before changing generation. |
| P2 | Similar generic Linux diagnostic commands recur across unlike hosts | distribution_texture | Host: not labeled | Several hosts/accounts; weak | Host activity profile and command catalog; medium risk. Verify host-specific command selection and role binding before changing vocabularies. |
| P3 | Bounded daytime network window and shared hour-14 peak | weak_signal / distribution_texture | Network: not labeled | Three Zeek sensor views; low | Scenario collection window and network activity scheduling; low risk. A six-hour slice explains the boundary; longer context would be needed to diagnose the peak. |
| P3 | Sequential high Linux PIDs in one cron process pair | weak_signal | Detection: not labeled | One APP-INT-01 pair; low | Linux PID allocator and uptime model; medium risk. Treat as unproven until a broader progression probe contradicts host churn expectations. |

The prior 95–96-second editor cadence is **fixed and verified for this generated sample**. It
was not rediscovered by the standalone panel. The mean standalone synthetic-confidence score
rose from **36.0** in loop 68 to **48.5** in loop 69 (+12.5); the current reviewers instead
surfaced weak cues in collection scope, volume and command distribution. This is not evidence
that the cadence repair regressed. Because the standalone shift is not paired and the reports
focused on different weak cues, a neutral A/B comparison was run to separate reviewer variance
from broader realism movement. Two reviewers tied the sets, one slightly preferred loop 69,
and one slightly preferred loop 68. All four called both datasets inconclusive; comparative
confidence was modest or low. The small preferences came from localized cues (a plausible ES
sequence gap and HTTP 400 mix for loop 69; public versus private WEB-EXT client addresses for
loop 68), with no decisive contradiction. The comparison therefore does not confirm a broader
improvement or regression and is consistent with reviewer variance. The loop 69 timing fix
remains supported by its focused rendered-output probe; A/B reviewers did not identify it as a
differentiator. Comparative scores are preserved separately and are not included in the loop
trend.

## Comparison with quantitative evaluation

The quantitative evaluator passed all hard criteria and scored 96.79, while experts focused on
collection shape and activity distributions. Those concerns are not acceptance failures and
should be verified at their owning observation, host-activity or timing layer before code
changes. Automated eval did not assess the sparse macOS Unified Log question or Linux command
texture as a synthetic discriminator.

## Artifacts

- [Family contract](family-contract.md)
- [Canonical scores](scores.json)
- [Raw automated evaluation](automated-eval.json)
- [Readable automated evaluation](automated-eval.txt)
- [Rendered timing probe](hard_probe_foreground_timing.json)
- [UDP firewall/Zeek lifecycle probe](udp-lifecycle-probe.json)
- [Generation provenance and data hashes](provenance.json)
- [Validation and focused tests](test-evidence.json)
- [Blinded A/B synthesis](ab-01/synthesis.md)

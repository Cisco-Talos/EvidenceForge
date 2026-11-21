# Deliberation Summary

This is a facilitation of the four original reports and four actual reviewer deliberation responses in this study. The final positions below are the reviewers' submitted revisions, not facilitator-assigned votes. No new independent log review was performed for this synthesis.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 80 | 65 | Synthetic | 88 | 73 |
| Detection Engineer | Inconclusive | 88 | 46 | Synthetic | 79 | 67 |
| Network Forensics | Inconclusive | 82 | 38 | Synthetic | 80 | 65 |
| Host/EDR Forensics | Synthetic | 84 | 66 | Synthetic | 88 | 72 |

Verdict confidence and synthetic-confidence are separate measures. In particular, the Detection Engineer and Network analyst changed verdict while decreasing verdict confidence; their higher synthetic-confidence scores do not imply increased certainty in every disputed interpretation.

## Round 1 — Findings Presented

- **Threat Hunter:** Initially Synthetic, confidence 80, synthetic-confidence 65. The strongest finding was a repeated Windows/Linux curl command, file-writer, socket-owner and inspected-request split. The initial report also gave small weight to seven slow mounted binary-document `cat` reads. Positive pivots included coherent SSH/scp relationships, process lifetimes, differentiated traffic and correct Windows Security log-clear structure and record numbering. The endpoint-to-proxy request interpretation was this review's distinctive contribution.
- **Detection Engineer:** Initially Inconclusive, confidence 88, synthetic-confidence 46. Two triplets of native macOS forks preserved exact microsecond phase and matching integral-second monotonic intervals. Against this, the checked XML/JSON parsed, process GUIDs and visible lifetimes were coherent, and tested protocol/connection joins worked. Eight unresolved file-enrichment references were explicitly an operational caveat, not scored provenance evidence. The source/schema and broad reference checks bounded the timing finding's significance.
- **Network Forensics:** Initially Inconclusive, confidence 82, synthetic-confidence 38. Packet accounting with capture-loss allowances, TLS/certificate semantics, protocol intervals, proxy legs and compatible sensor offsets supported network plausibility. One unresolved SMB mapping UID initially received only minor provenance weight. Endpoint semantic ownership was outside the original review's substantive scope. The distinction between passive TLS visibility, separate proxy legs and sensor-specific clocks was its distinctive contribution.
- **Host/EDR Forensics:** Initially Synthetic, confidence 84, synthetic-confidence 66. Eleven RDP-associated `smss.exe` to `winlogon.exe` creation delays across five hosts measured 0.499–0.500 seconds. The same two Mac fork triplets found by Detection added a separate native timing family. Strong process/image/hash consistency, session semantics and differentiated platform execution chains remained counterweight. The RDP bootstrap distribution was this review's distinctive contribution.

## Round 2 — Cross-Examination

### Correlation strength versus semantic ownership

All four actual responses resolve the apparent conflict as a difference in scope. A valid process GUID and a flow inside that process's lifetime establish neither that its command requested the observed resource nor that it wrote the transferred file. Likewise, coherent Zeek/proxy tuples and egress legs do not settle endpoint command intent. The Detection Engineer's and Network analyst's initial positive findings therefore survive their revised verdicts.

The Threat Hunter retained the curl concern with a narrower formulation; the other three accepted it after their reported rechecks. On WS-MCHEN-01, PID 7704 requests the executable path and creates its output file, while PID 7712 requests the site's root through the proxy and owns port 57407. The inspected request on that port/tunnel is the executable path. WS-LNGUYEN-01 repeats this with PIDs 2959192/2959193 and port 39161. Native Windows Sysmon/WFP corroboration was directly checked by the Threat Hunter, Detection Engineer and Host analyst; the Network analyst explicitly relies on their documented native corroboration rather than claiming that recheck personally.

The accepted category is **contract_gap**, not **hard_contradiction**. File CREATE does not prove completed content or which socket supplied it; an absent downloader FLOW does not prove no transfer occurred. Configuration, additional effective URLs, request overrides, misleading command telemetry, instrumentation or selective observations remain possible explanations. The repeated positive command-to-inspected-request discrepancy carries the weight. The Linux processes have different visible parents; the Windows sibling relationship is not generalized to Linux.

### RDP transport variability versus bootstrap concentration

The Host analyst's near-half-second bootstrap population does not conflict with the Network analyst's varied RDP transport durations: these measure different intervals. The Threat Hunter, Detection Engineer and Network analyst report reproducing the eleven numerical parent/child intervals: eight at 0.500 seconds, three at 0.499, compared with six other visible pairs at 0.363, 0.420, 0.709, 0.859, 1.173 and 1.225 seconds. Detection additionally checked subsequent Type 10 logons; Network distinguishes its numerical/parentage recheck from Host's RDP association.

All accept **distribution_texture** with varying weight. A genuine fixed implementation timer, collection transformation and millisecond representation remain alternatives. No reviewer calls half a second intrinsically impossible or claims reversed causality.

### Native Mac timing versus scheduled activity

All responses retain the two three-fork clusters: `.487145000Z` across 38/29-second offsets on MAC-MROSS-01, and `.965208000Z` across 22/41-second offsets on MAC-MROSS-02. Matching monotonic intervals weaken display-only rounding as an explanation. Detection's original denominator remains material: the hosts have 47/58 forks and 45/56 distinct fractions, respectively, with only one triplicate on each; exec and exit timing remains varied.

Automation and upstream timestamp transformation are still possible. These six rows do not prove dataset-wide synthesis. The panel treats them as one recurring **distribution_texture** family; two original reviewers finding the same rows does not create two independent defects.

### Weak findings challenged or withdrawn

The Threat Hunter reduces the already small weight assigned to mounted `cat`/`ls` durations. All four responses give these no separate material upward adjustment: mounted-storage latency, scripts and output backpressure are concrete alternatives. The Network analyst expressly withdraws the initial minor provenance weight for the missing SMB UID. All reviewers exclude that omission and the eight unresolved FUID references from revised scoring without an incompatible collection contract.

Narrative neatness, ease of hunting, comprehensive matching, missing optional event families, pre/post-window lifecycle evidence and sanitized domains are excluded from provenance reasoning. Policy messages and plist file operations are not promoted into proof of successful execution or activation.

## Round 3 — Actual Revised Positions

- **Threat Hunter:** Synthetic remains; verdict confidence **80 → 88**, synthetic-confidence **65 → 73**. The newly rechecked RDP and Mac timing findings strengthen the original curl concern. Mounted-file texture is reduced and receives no separate upward adjustment.
- **Detection Engineer:** **Inconclusive → Synthetic**; verdict confidence **88 → 79**, synthetic-confidence **46 → 67**. Rechecked RDP concentration and the repeated curl semantic gap add substantive findings beyond the original Mac timing artifact. Existing parsing/lifecycle results remain intact; the lower verdict confidence preserves uncertainty in the new classification.
- **Network Forensics:** **Inconclusive → Synthetic**; verdict confidence **82 → 80**, synthetic-confidence **38 → 65**. Rechecked endpoint/proxy semantics and both native timing patterns expand the original network-limited evidence. The analyst retains the network strengths and withdraws SMB-omission provenance weight.
- **Host/EDR Forensics:** Synthetic remains; verdict confidence **84 → 88**, synthetic-confidence **66 → 72**. Directly rechecked curl records add a repeated semantic ownership concern to the original two timing families. The Mac agreement is corroboration, not an extra independent defect.

## Key Agreements

- All four actual final verdicts are Synthetic, with scores in the likely-synthetic range, **65–73**. None claims a demonstrated unconditional hard contradiction, native impossibility or generator identity leak.
- Three substantive concern families survive: the repeated curl semantic contract gap, RDP bootstrap timing concentration, and Mac fork phase preservation.
- Checked native structures, process/session identities, lifetimes, transport-before-auth ordering, protocol accounting, TLS observation limits and compatible sensor clocks remain substantial strengths. Technical coherence supports operational realism but does not establish provenance.
- Missing companions and polished narrative shape are not grounds for raising the revised scores.

## Key Disagreements

There is no final verdict split. Evidentiary weight and remaining alternatives differ: Threat Hunter/Host place the scores at 73/72, while Detection/Network remain at 67/65. The Network analyst calls the Windows timing evidence moderate and retains a credible real-timer explanation; Detection emphasizes bounded distributions and uncertain effective command inputs. Host and Threat Hunter place more weight on convergence across distinct timing and ownership relationships. No response eliminates configuration, collection/transformation or genuine scheduling mechanisms as explanations.

## Most Convincing Evidence

This ordering reflects the material weight and revisions expressed in the responses; the reviewers did not submit a formal ranked ballot.

1. **Repeated endpoint-to-proxy command/request gap — contract_gap.** Accepted by all four and material to the three reviewers newly considering it; stronger than missing network evidence because the attributed socket has a positively different visible request intent.
2. **Eleven RDP bootstrap delays confined to 499–500 ms — distribution_texture.** Material new evidence for the two initially inconclusive reviewers and Threat Hunter; broader comparison pairs undermine a source-wide quantization explanation, while real timers remain possible.
3. **Two microsecond-exact fork triplets with matching monotonic intervals — distribution_texture.** Retained by all, bounded to six forks and counted once across reviewers.
4. **Coherent native and network relationships — realism counterweight.** All retain this evidence and use it to limit the severity of the synthetic conclusion. It is neither proof of real origin nor suspicious merely because relationships match.

## Most Debated Points

- Whether curl configuration or observation limitations can reconcile visible command intent with the inspected request; the panel retains a bounded gap rather than asserting impossible file transfer.
- Whether the RDP mode reflects a real implementation timer, and how to distinguish planned command schedules from native realized fork occurrence times.
- Whether broad correlation correctness rebuts a narrower semantic defect; all responses conclude that these are compatible findings.
- Whether slow mounted commands or unresolved references warrant provenance weight; their revised weight is negligible or withdrawn.

## Improvement Recommendations (Consensus)

These three changes are explicitly supported by all four actual responses:

1. **Bind each download to one coherent transfer lifecycle.** Carry effective requested URL, process UUID/PID, transport tuple, inspected proxy resource and output-file ownership together. Where configuration, helpers, redirects or separate transfers explain a difference, represent that mechanism and its relationships explicitly.
2. **Separate Mac scheduling intent from realized fork occurrence.** Apply modeled dispatch/execution latency before deriving wall-clock and monotonic native timestamps, while retaining fork-to-exec identity and ordering.
3. **Evaluate RDP bootstrap distributions across hosts and sessions.** Derive realized smss-to-winlogon timing from host/session execution conditions, or an explicitly justified timer, while preserving parent-before-child and transport-before-auth ordering. Check the population distribution as well as individual causality.

All four also endorse preserving the demonstrated identity, lifecycle and source-specific/network strengths. Missing optional companions may be documented for enrichment usability, but universal collection completeness is not a realism requirement. Mounted-file behavior remains a lower-priority investigation rather than a consensus driver of the final result.

# Deliberation Summary

This facilitation synthesizes the four original reports and four actual individual deliberation responses. The reviewers read the original reports and submitted their own revisions; this document does not represent a live exchange or attribute knowledge of others' revised positions to them. No new findings are introduced. The facilitator did not inspect data or provenance materials.

**Final assessment: all four reviewers individually favor Synthetic. Mean revised synthetic-confidence: 63.25/100**, calculated as `(67 + 62 + 62 + 62) / 4`. This arithmetic mean is a summary of the four revised scores, not a calibrated probability of synthetic provenance or a measure of independent evidentiary replication. Verdict confidence is a separate quantity.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 76 | 64 | Synthetic | 78 | 67 |
| Detection Engineer | Inconclusive | 78 | 32 | Synthetic | 74 | 62 |
| Network Forensics | Inconclusive | 80 | 38 | Synthetic | 73 | 62 |
| Host/EDR Forensics | Inconclusive | 80 | 33 | Synthetic | 74 | 62 |

## Round 1 — Presented Findings

- **Threat Hunter:** Initially Synthetic / 76 / 64. The strongest concern was three native macOS command groups whose distinct forks retain group-identical microsecond fractions, affecting 10 of 54 zsh-parent forks across two hosts. A narrow Linux sudo working-directory vocabulary was weak support. Hunting pivots were credible: Type 9 local/outbound account separation, all eight checked RDP logons within successful transport intervals, SSH transfer stages, and proxy CONNECT/request accounting. The distinctive contribution was fine-grained timing texture beyond basic lifecycle ordering.
- **Detection Engineer:** Initially Inconclusive / 78 / 32. The principal negative observation was one SMB mapping with no supplied connection companion, despite a visibly new in-window client. Strong counterevidence included meaningful Windows event-specific metadata, stable process GUID relationships, and successful sensor-local DNS/HTTP/SSL/SMTP/SMB-file joins. The specialty contribution was separating a concrete missing reference from unsupported claims of generally missing coverage.
- **Network Forensics:** Initially Inconclusive / 80 / 38. The main concern was 99 browser transactions using only three exact Windows browser strings, within 101 external-origin HTTP transactions from 99 source IPs. Connection/application timing, DNS variety, TLS relationships, and network accounting otherwise held up. All 147 direction-level apparent packet-byte deficits had capture-gap evidence. The distinctive contribution was explaining these apparent anomalies through network observation semantics rather than treating them as impossible traffic.
- **Host/EDR Forensics:** Initially Inconclusive / 80 / 33. All 927 checked Sysmon process creations paired with Security 4688 records without disagreement on normalized executable, command, or parent executable. Visible process/session lifecycles and native macOS fork/exec identity were coherent. Weak concerns were Linux hardware-daemon weighting, including 130/195 DB-PROD-01 syslog records, and overlapping Windows VPN/browser software. The specialty contribution was distinguishing actual process birth, image replacement, unlock continuation, and GUI launch from stronger lifecycle or routing claims.

## Key Agreements

- All four individual revisions identify the native macOS fork-time pattern as the primary reason to favor synthetic origin. Each response reports independently reproducing the cited pattern. This is repeated verification of one finding, not four independent defects.
- The timing observation is **distribution_texture**, not a hard contradiction, native-schema failure, or proof that the commands were typed manually. Exact whole-second differences also appear in the reported monotonic clock values; that corroborates the same occurrence timing and is not a second independent indicator.
- Broad technical coherence survives the revisions. Process and session identities, native fork/exec distinctions, account boundaries, transport-before-authentication order, and most protocol joins remain credible. Correct correlations can coexist with localized distribution artifacts and are valuable for hunting.
- The external HTTP vocabulary measurement is reproducible and adds limited supporting weight. Distinct source IPs do not establish distinct human users, and the browser versions themselves were not shown to be invalid.
- The SMB mapping UID `C4bqaKVpaYQLPkuTrz` lacks a supplied connection companion. Its short-lived in-window client weakens a collection-boundary explanation; independent export loss or filtering remains credible.
- No reviewer established a hard contradiction. Linux daemon rates, working-directory pools, and software overlap remain weak, context-dependent signals. Missing optional sources, sanitized names, narrative completeness, and successful cross-source matching were not treated as synthetic evidence.

## Key Disagreements

The original 1–3 verdict split becomes four independently submitted Synthetic verdicts. There is no remaining final-verdict dissent in the actual responses. There are still differences in evidentiary weight and unresolved alternative explanations:

- **SMB gap weight:** The Threat Hunter accepts a small contribution; Network calls its weight modest; Host gives it minor influence. Detection explicitly reduces it to negligible influence on the revised verdict because source completeness is not established. All accept the missing join; they do not agree that it meaningfully identifies origin. Network explicitly withdraws the original pre-window explanation, and the Threat Hunter corrects the earlier broad dismissal based on the collection window.
- **Timing interpretation:** All favor synthesis after rechecking, while retaining automation, specialized replay/scheduling, or timestamp reconstruction as possible explanations. The Threat Hunter explicitly says Inconclusive remains defensible if those alternatives receive more weight. None establishes such an alternative from the supplied records or rules it out conclusively.
- **Supporting distributions:** The Threat Hunter finishes at 67, above the other three at 62, with modest upward movement from HTTP vocabulary and the in-window SMB evidence. The others place the main weight on newly considered native timing. Weak background observations are not promoted into independent strong defects merely because several exist.

## Most Convincing Evidence

The following ranking reflects the convergence and relative emphasis in the actual responses, not a separately conducted panel vote:

1. **Synthetic-leaning: repeated fine-grained native fork timing.** MAC-MROSS-01 ES lines 35/38/41/44 retain `.198588` across 27/35/19-second gaps; lines 55/58/61 retain `.487145` across 38/29-second gaps. MAC-MROSS-02 lines 86/89/92 retain `.965208` across 22/41-second gaps. Distinct child PIDs and varying adjacent exec fractions distinguish this from duplicated fields or global export rounding. The responses report matching whole-second monotonic deltas. This single timing pattern drives all final verdicts.
2. **Production-compatible counterweight: coherent endpoint and network relationships.** The 927 Windows process-source pairs, bounded lifecycle checks, netonly identities, RDP/SSH ordering, source-local protocol joins, capture-gap-aware packet accounting, and TLS relationships remain persuasive positive evidence. They limit how strongly the reviewers infer synthetic origin without proving production provenance.
3. **Synthetic-leaning, secondary: restricted external HTTP browser vocabulary.** The three exact browser strings occur 36/33/30 times, with two additional AhrefsBot records. The reviewers retain specialized audiences, spoofed headers, normalization, selected extraction, and distributed automation as credible alternatives. No one treats the near balance as statistical proof.
4. **Observed reference limitation, weak origin evidence: the isolated SMB orphan.** Core `smb_mapping.json:93` describes `10.10.1.22:59392 -> 10.10.2.20:445` at 17:35:24.871449 UTC. Endpoint records create smbclient at 17:35:20.133, observe its matching FLOW at 17:35:24.430, and terminate it at 17:35:29.396. This supports a missing in-window join, while leaving record loss/filtering unresolved.

## Most Debated Points

These are the principal issues challenged in the written responses, rather than a transcript of discussion:

- **Coherent lifecycles versus fine-grained timing texture:** Originally favorable temporal findings tested order and ownership. They did not test whether distinct launches inherit identical fractions. The reviewers find these conclusions compatible; this closes a blind spot rather than overturning the successful lifecycle checks.
- **Intentional scheduling versus occurrence timestamps:** Whole-second intended spacing can be automated. The stronger concern is retaining identical observed fractions through separate native forks while neighboring exec times vary. Reconstruction could explain that, but no supplied explanation establishes it. Equal-millisecond normalized records are a different issue and remain unscored as contradictions.
- **A missing reference versus impossible activity:** Endpoint evidence displaces a routine pre-window explanation for the SMB case. It does not displace independent connection-record loss. Detection's reduced weight and Network's withdrawn boundary explanation show movement in both directions, without claiming a generation defect.
- **Constrained vocabulary versus legitimate population selection:** HTTP client profiles, Linux daemon verbosity, shared administration, fleet images, migrations, and partner VPN requirements can all shape a real export. Launching multiple VPN GUIs does not demonstrate simultaneous tunnels; seven working directories do not prove an ownership error.

## Round 3 — Actual Revised Positions

- **Threat Hunter:** Synthetic remains Synthetic; verdict confidence **76 → 78**, synthetic-confidence **64 → 67**. Reproduced HTTP concentration and Detection's in-window SMB evidence add modest support. Host findings reinforce technical coherence; weak background concerns do not drive the increase.
- **Detection Engineer:** Inconclusive becomes Synthetic; verdict confidence **78 → 74**, synthetic-confidence **32 → 62**. Independently reproduced native fork timing is decisive for the change, with HTTP texture secondary. The SMB gap receives less origin weight after considering Network's collection-loss challenge.
- **Network Forensics:** Inconclusive becomes Synthetic; verdict confidence **80 → 73**, synthetic-confidence **38 → 62**. Native timing supplies a stronger discriminator than the original browser finding. Endpoint evidence removes the pre-window SMB explanation, while export loss remains possible. Confidence falls because choosing an origin is a stronger inference than the initial inconclusive judgment.
- **Host/EDR Forensics:** Inconclusive becomes Synthetic; verdict confidence **80 → 74**, synthetic-confidence **33 → 62**. Independently verified native timing drives the revision; external HTTP vocabulary and the SMB gap are subordinate. Original lifecycle strengths and credible operational alternatives remain intact.

## Improvement Recommendations (Consensus)

These recommendations have support from all four individual responses unless otherwise qualified. They are conditional on synthetic origin and do not assert knowledge of an implementation.

1. **Resolve each distinct native process occurrence at realistic high resolution.** Preserve intentional command spacing, fork/exec identity, and causal order while avoiding inherited group-identical launch fractions. Recheck the ten cited forks. Keep wall-clock and monotonic values derived coherently from the resolved occurrence; altering only display fractions would leave or introduce clock inconsistencies.
2. **Broaden the measured external HTTP population through stable client profiles.** Add plausible browser, OS, device, and version diversity consistent with the intended audience. Retain justified bots and specialized populations; avoid independently randomizing headers on every request.
3. **Resolve or document the exact SMB companion gap.** Preserve the connection companion for the cited UID/tuple or represent intentional observation loss coherently. For a real export, document filtering/loss. Do not explain this visibly new client by inventing pre-window initiation, or add unrelated endpoint evidence to compensate.
4. **Preserve existing identity and lifecycle strengths during changes.** Retain process/session ownership, local versus outbound credential boundaries, successful transport intervals, transport/authentication order, and source-specific proxy byte semantics.

A further recommendation has explicit support from Network and Host: document any deliberate timestamp reconstruction/transformation in collection context, because that would materially affect interpretation. Reviewing Linux daemon weighting and working-directory behavior is also supported as a lower-priority, context-dependent calibration step in the original Host and Threat Hunter recommendations and subsequent responses; it is not a unanimously established defect or a basis for mechanically deleting legitimate software/noise.

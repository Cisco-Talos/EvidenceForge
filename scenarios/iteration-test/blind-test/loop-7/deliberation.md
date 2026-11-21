# Deliberation Summary

This is a facilitator's synthesis of the four original reports and the four actual individual deliberation responses. It records the reviewers' submitted positions; it does not supply a fifth assessment, infer votes, or invent a live discussion. The initial and final numbers below are transcribed from those submissions. Verdict confidence and synthetic-confidence are different measures and are kept separate.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 74 | 62 | Synthetic | 83 | 68 |
| Detection Engineer | Inconclusive | 78 | 35 | Synthetic | 76 | 64 |
| Network Forensics | Real | 64 | 30 | Synthetic | 78 | 65 |
| Host/EDR Forensics | Synthetic | 83 | 66 | Synthetic | 83 | 66 |

All four submitted final assessments are Synthetic. All four nevertheless retain substantial technical-realism evidence, plausible alternative explanations, and the absence of an established hard contradiction. Their final synthetic-confidence scores remain 64–68, in the likely-synthetic band described by the reviewers. Agreement on this qualified lean does not establish provenance, eliminate sanitization explanations, or turn the scores into calibrated probabilities. No aggregate score or extra panel vote is assigned here.

## Round 1 — Present Findings

### Threat Hunter

The initial position was Synthetic, verdict confidence 74, synthetic-confidence 62. Its leading reservation was the SYSVOL/NETLOGON corpus: 15 of 51 size-bearing observations exceeded 1 MiB, including an 8,700,366-byte `User/registry.ini`, 9,890,978-byte `Preferences/2026/policy.ps1`, and 2,803,606-byte `Scripts/2026/startup.bat`. A second reservation was seven native ES execs using `/bin/cat` for PDF, DOCX, and XLSX paths on MAC-MROSS-02. Neither was claimed impossible.

The specialty-specific positive evidence was practical hunting feasibility: coherent Mac SSH pivots, an explicit-proxy download followed by script execution, a database dump/gzip/scp sequence with receiver SSH evidence, and Windows account/group/task operations with corresponding audit observations. The analyst explicitly distinguished those pivots from proof of malicious intent or synthetic origin.

### Detection Engineer

The initial position was Inconclusive, verdict confidence 78, synthetic-confidence 35. Its strongest evidence favored technical realism: all 20 Windows XML files parsed; broad GUID-based checks found no demonstrated process-identity/lifecycle contradiction; 397 matched non-well-known logon/logoff identifiers were ordered correctly; and 13,404 checked protocol rows joined to same-sensor connections with matching tuples and acceptable timing.

Distinctive observations included correct passive TLS 1.3 certificate visibility and Unix fork/exec identity handling. Its localized reservation was the same seven Mac document commands, including 3.251–18.454-second normalized exec-to-read intervals and 12.736–22.664-second lifetimes. It treated those timing and tool-choice observations as related weak signals, with unknown storage/output behavior.

### Network Forensics

The initial position was Real, verdict confidence 64, synthetic-confidence 30. Its strongest observations were sensor-specific connection-state/service mixtures, coherent payload/file byte budgets and TLS certificate relationships, and explicit-proxy control bytes that accounted for the difference between client-side and upstream traffic. Sampled IDS/DNS and SSH transport/authentication relationships also agreed.

Unique reservations were first DHCP renewal observations near collection start and a platform-dependent browser-version split. Both were explicitly weak: workday startup, maintenance, managed images, update policy, and repeated HTTP transactions could explain them. One unmatched SMB mapping and nearby DNS responses after connection opening were explicitly unscored.

### Host/EDR Forensics

The initial position was Synthetic, verdict confidence 83, synthetic-confidence 66. Its primary finding was one cross-host Linux PID distribution artifact: ten hosts supplied 36 recurring sysstat CRON observations each, yielding 350 successive within-host PROCID differences; none was below 940, 67 were exactly 940, and no other individual difference occurred more than twice. Arithmetic runs illustrated this same finding rather than adding separate defects.

Its smaller reservation was the Mac document-command cluster, including a `tee` DOCX write. Strong counterevidence included 933 Sysmon process starts with matching Security 4688 counterparts, stable identities/hashes, coherent SSH/PAM/logind progression, and platform-specific macOS fork/exec transitions. The analyst distinguished type-7 unlock from first session creation and pre-window state from missing prerequisites.

## Round 2 — Cross-Examination

### Technical consistency versus population plausibility

The initial disagreement was principally about scope and evidentiary weight, not contradictory measurements. Detection and Network checked source relationships and transport semantics successfully; Host measured an allocation-distribution property those checks did not address; Threat Hunter assessed background file-purpose and workflow plausibility. All four actual responses accept that technically valid identities, protocol rendering, and lifecycle joins can coexist with an artificial-looking population distribution.

Network explicitly reconsidered having placed too much provenance weight on the absence of transport contradictions. Detection identified its initial schema/lifecycle focus as a blind spot for the PID measurement. Conversely, none withdrew successful transport, schema, or lifecycle checks when adopting the distribution finding. Complete joins were not recast as a synthetic indicator.

### Linux PID growth: strongest revised influence, with live alternatives

Threat Hunter, Detection, and Network each report independently reproducing Host's PID count after seeing the original reports; Host reports reproducing it again. The shared result is 67/350 exact-940 differences (19.1%), no smaller difference, and at least five exact-940 differences on every included host. DB-PROD-01 lacked the matching CRON sample and was excluded without a missingness penalty.

The panel's concern is the common sharp floor and concentration across differing host roles. The ten-minute sysstat schedule itself is legitimate and unpenalized. Repeated reproduction strengthens confidence in the measurement; it remains one underlying distribution observation, not four independent defects.

All preserve alternatives: homogeneous managed images, shared scheduled tasks or monitoring agents, a centrally imposed workload with fixed process consumption, and deliberate PID privacy remapping. The supplied process records do not account for all kernel PID allocations and therefore cannot exclude an unseen common workload. No reviewer establishes a mathematically impossible sequence, a particular generator, or a formal likelihood ratio. Host remains open to revising if sanitization or common churn is demonstrated; Detection says an established remapping/workload explanation would move it back toward Inconclusive.

### Policy-share sizes: semantic concern rather than invalid carriage

Detection, Network, and Host report reproducing Threat Hunter's 15/51 count. They accept a modest or moderate file-population reservation while retaining Network's successful carrier-byte checks. Large files fit the transport; their purpose and frequency are what looked generic.

The denominator counts accesses, not unique files. Network additionally reports 48 distinct `(share path, file name)` pairs overall and 14 among the 15 large observations, so repetition alone does not explain that result. Those are path/name distinctions, not independently established unique contents. Repeated accesses, specialized deployment use, embedded content, large preferences/policies, unconventional share use, and a nonrepresentative access sample remain possible. Contents were unavailable; no reviewer proves malformed INI, PS1, BAT, XML, or POL content. Detection explicitly says this finding alone would not change its verdict to Synthetic, and Host accepts modest corroboration without raising its score.

### Mac document workflow: corroborated but reduced in strength

Three original reports described the same seven `/bin/cat` reads. Their agreement is reproducibility of one cluster rather than independent evidence families. Native ES arguments establish the tool/path choices, while normalized eCAR supplies the file-read observations; this selection of native ES families is not a direct native file-access audit.

Threat Hunter explicitly lowers its original behavioral reservation to a weak signal. All retain scripted byte probing, automation, redirection/output blocking, mounted-storage latency, and source selection as alternatives. Detection's measured delays remain observations, but no reviewer establishes an impossible read or exit time. Host's additional `tee` write belongs to this workflow concern. Missing `/Volumes/` shell-history entries remain unscored; selected history cannot establish a missing required companion or absence of application activity.

### Apparent protocol disagreement resolved by check scope

Detection's 13,404-row successful join result included SMB-file records, not SMB-mapping rows. Network's single mapping UID without a local conn match therefore does not contradict that result. All adopting reviewers retain the possibility of a transport spanning the collection boundary and assign no absence penalty. Likewise, a nearby DNS response after a connection opens can coexist with cached addresses, concurrent refresh, or another resolution path; it was not promoted to a causal contradiction.

## Round 3 — Actual Revised Positions

| Expert | Verdict change | Verdict-confidence change | Synthetic-confidence change | Submitted reason |
|--------|----------------|---------------------------|-----------------------------|------------------|
| Threat Hunter | Synthetic → Synthetic | 74 → 83 | 62 → 68 | Independently reproduced Host's PID distribution; made it primary, retained policy sizes as secondary, and reduced the Mac cluster's weight. |
| Detection Engineer | Inconclusive → Synthetic | 78 → 76 | 35 → 64 | Independently reproduced PID and policy-size findings. PID supplied substantial new evidence outside initial checks; confidence fell slightly because the revised origin inference remained statistical. |
| Network Forensics | Real → Synthetic | 64 → 78 | 30 → 65 | Independently reproduced PID and policy-size findings; reconsidered the provenance weight of passing transport checks while preserving every technical success. |
| Host/EDR Forensics | Synthetic → Synthetic | 83 → 83 | 66 → 66 | Reconfirmed PID finding; accepted policy sizes as modest corroboration and broader network checks as positive evidence. Neither changed the balance enough for a numerical revision. |

These are the experts' actual final submissions. Higher synthetic-confidence does not imply higher verdict confidence: Detection's separate measures moved in opposite directions. No subsequent response or negotiated score is implied.

## Round 4 — Consensus Assessment

## Key Agreements

- All four final responses give the cross-host PID floor substantial weight and treat it as distribution texture, not a hard contradiction. It was the principal reason for both changed verdicts and Threat Hunter's strengthened lean.
- All accept the policy-share size count as a qualified, separate background-population reservation. Its corroborating weight differs; no one calls it invalid SMB accounting.
- The Mac tool-choice cluster is a small, explainable concern; its timing and repeated reporting do not create additional strong indicators.
- Source-native structures, process/session relationships, selected protocol joins, explicit-proxy accounting, passive TLS visibility, and sampled SSH transport-before-authentication remain convincing in the checks performed.
- No reviewer established a source-native impossibility, impossible lifecycle, generator identity leak, or other hard contradiction. No final synthetic-confidence score enters their 81–100 confidently-synthetic band.

## Key Disagreements

No final verdict disagreement remains in the submitted responses. Initial Real/Inconclusive/Synthetic differences were resolved by the newly shared distribution measurements, especially PID growth, rather than by invalidating the positive findings.

Residual uncertainty concerns how strongly those distributions distinguish generated data from real data transformed by sanitization or shaped by common hidden workloads. All retain those alternatives, with no agreed probability for them. Policy-file semantics and Mac command interpretation likewise remain underdetermined. Final scores of 64–68 express differing qualified weights; they are not evidence that the panel settled the provenance question or that small numerical differences are significant.

## Most Convincing Evidence

The ordering below reflects the relative importance expressed in the submitted responses, not a separate panel ranking ballot. Positive and negative observations answer different questions and are not assigned a combined numerical weight.

1. **Toward synthetic: the shared Linux PID-growth floor.** The exact-940 concentration and common minimum across ten hosts are the primary final indicator for all four reviewers. Common workloads and PID remapping remain unresolved alternatives.
2. **Toward synthetic: the policy-share file-size population.** Fifteen of 51 observations above 1 MiB across several text/configuration/script extensions provide qualified corroboration; missing contents and access sampling limit interpretation.
3. **Toward technical realism: coherent source/protocol semantics.** Detection's 13,404 checked protocol joins, Network's byte budgets and explicit-proxy example, and correct passive TLS 1.3 visibility withstand the described checks. These constrain overconfident synthetic claims without proving real origin.
4. **Toward technical realism: process/session integrity and useful hunting pivots.** Host's Windows joins and fork/exec distinctions, plus the reviewed SSH and administrative-operation sequences, show practical correlation and plausible lifecycle ordering within the visible slice.
5. **Weakly toward synthetic: the Mac binary-document shell workflow.** Seven `cat` reads and related shell activity suggest narrow behavior selection, but executable/scripted explanations and unknown storage/output conditions prevent a strong conclusion.

## Most Debated Points

- Whether a common managed workload or PID transformation can account for the exact common floor. This is the most consequential unresolved explanation; legitimate cron regularity is not the disputed feature.
- How much absence of a protocol contradiction says about provenance. Detection and Network's revisions distinguish technically correct evidence from natural population distributions.
- Whether large policy/share artifacts reflect generic sizing or genuine deployment practice. Counts are reproducible; purpose and content are not established.
- Whether repeated Mac commands reflect a generic workflow or a selected scripted task. Tool choice is visible, but file semantics, output destination, latency, and complete application coverage are not.

## Withdrawn, Downgraded, and Unscored Evidence

No individual deliberation retracts the central PID or policy-size measurements. Threat Hunter explicitly downgrades the Mac pattern from a substantial behavioral reservation to a weak signal. Detection's Mac timing measurements are retained with limited interpretation, not withdrawn or promoted to impossible timing. Network's DHCP-phase and browser-version observations remain weak and are not principal revised-score drivers.

The final synthesis preserves the reviewers' exclusions: the unmatched SMB mapping; first-visible DNS after transport opening; partial shell-history omissions; pre-window initiators and post-window endings; selected Sysmon/ES families and sparse Unified Log exports; sensor clock offsets; sanitized names/domains; and strong joins/completeness are not scored defects. Nor are suspicious activity being compact, linear, narratable, or huntable. MeetingAssist policy wording does not establish final execution success/denial; plist creation/deletion does not establish activation, unload, or process termination. A type-7 unlock is not a newly created session.

## Improvement Recommendations (Consensus)

These conditional recommendations are supported by all four final submissions if the data were synthetic; they do not claim its actual implementation is known.

1. **Remove the cross-host PID floor through host-specific process churn.** Make allocated identities reflect the host's intervening workload/process-thread allocation behavior while preserving existing PID/GUID references, cross-source joins, and lifecycle order. Keep the legitimate ten-minute sysstat schedule; timestamp jitter alone does not address the identity pattern.
2. **Condition policy/share sizes on artifact format and purpose.** Review the multi-megabyte INI/BAT/XML/PS1/POL population against the actual intended content and deployment workflow. Retain justified large artifacts rather than imposing a blanket size ban, and distinguish repeated accesses from distinct path/content populations.
3. **Give Mac document access an explicit workflow.** Use application-owned access for ordinary document work, or retain shell lineage with a justified byte-oriented probe/write task. Ground read/exit timing in storage and output behavior rather than assigning generic delays; preserve justified latency and fork/exec identity.
4. **Preserve successful technical contracts.** Retain proxy control/tunnel byte separation, passive TLS certificate visibility, gap-aware accounting, platform-specific process transitions, source-specific timestamps, and transport-before-authentication. Do not add arbitrary missingness, retries, broken joins, uncollected families, or forced in-window lifecycle endpoints to make the data look less complete.

Network's additional suggestions to initialize DHCP phases from prior lease histories and bind user agents to host/application inventories remain specialty-specific, lower-priority proposals. Other responses do not elevate those weak observations into shared major defects; a legitimate startup cohort or managed version split may remain.

## Methodological Limitations

This synthesis uses only `deliberation-instructions.md`, the four `*-report.md` files, and the four submitted individual `*-deliberation.md` responses. The facilitator did not inspect raw data, repository material, scenarios, ground truth, parent directories, or outside sources, and supplies no new forensic finding. Counts and rechecks above are attributed to the reviewers' submissions rather than independently verified here.

The original reviews were independent; the deliberation responses were written after reading all four original reports. Their reproduced counts are stronger measurement support but not independent blinded rediscoveries, and the final verdicts share the same principal evidence. They are four actual opinions, not four independent samples of the origin hypothesis. This record does not establish a later live cross-examination of one another's revised responses.

The approximately six-hour selected collection cannot rule out cached state, unobserved workloads, prior sessions/leases, omitted sources, or deliberate transformations. File contents, command output destinations, storage conditions, full kernel allocation history, and documented sanitization are unavailable. Parser/internal-consistency checks are bounded by the reviewers' tolerances and scope; they are not vendor conformance certification, commercial SIEM acceptance testing, or independent proof that public certificates/domains are real. The panel's final agreement is therefore a qualified likely-synthetic assessment with strong retained technical realism, not confirmed origin.

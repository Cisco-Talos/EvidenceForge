# Deliberation Summary

## Facilitator Scope and Method

This record synthesizes the four original `*-report.md` files and the four actual role-specific `*-deliberation.md` responses under the supplied deliberation instructions. It is a facilitator's account, not a fifth expert assessment. Final positions below are transcribed from each expert's own response; no expert position, score, or revision has been inferred. The experts reconsidered independently after reading the original reports; this document does not imply a live exchange or that they saw each other's deliberation responses.

The facilitator used only those study documents and made no additional evidence checks. Source locations below refer to the supplied `data/` directory. The reviewers' record checks are attributed to them. No repository, scenario, earlier study, external provenance, or outside context was consulted. The original reports remain the record of the initial assessments.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 64 | 31 | Synthetic | 77 | 62 |
| Detection Engineer | Inconclusive | 80 | 32 | Synthetic | 76 | 62 |
| Network Forensics | Real | 65 | 32 | Synthetic | 75 | 61 |
| Host/EDR Forensics | Synthetic | 80 | 64 | Synthetic | 76 | 60 |

These are distinct measures: verdict confidence expresses confidence in the stated assessment; synthetic-confidence expresses how synthetic the visible evidence appears under the reviewers' rubric. Neither is a fraction of defective rows. No panel-average score or new facilitator score is assigned. The final scores of 61–62 are near the lower boundary of the likely-synthetic band; Host/EDR explicitly places 60 at the upper boundary of the mixed band while retaining a Synthetic verdict. That qualification must not be erased by the common verdict label. The evidence does not support the 81–100 band in these responses.

## Round 1 — Present Findings

### Threat Hunter

Initially **Real**, verdict confidence **64**, synthetic-confidence **31**. The strongest evidence was (1) the web execution/reverse-shell pivot used raw TCP on port 8443 and closed before its shell owner terminated; (2) the DB-to-APP SCP pivot preserved source tuple, receiver account, file path, and transport/process compatibility; and (3) the upload proxy explicitly declared TLS inspection, explaining visibility of an HTTPS path. These were usable investigative pivots, not proof of production origin.

The specialty contribution was tracing the suspicious activity through endpoint, network, receiver, and proxy observations while testing actor and process-owned transport lifetimes. Initial concerns about Mac diagnostic vocabulary and a gzip history/endpoint gap were expressly weak. The original five `sw_vers` executions per Mac counted all such executions, rather than only the three inventory invocations identified by Detection Engineering.

### Detection Engineer

Initially **Inconclusive**, verdict confidence **80**, synthetic-confidence **32**. The strongest evidence was (1) successful parsing of 76,568 JSON/NDJSON records and Windows XML with distinct source-specific fields; (2) coherent Windows LUID/PID/ProcessGuid and visible create/dependent/terminate relationships; and (3) resolving Zeek UID/FUID references and bounded protocol timestamps, including credible TLS certificate visibility. The reviewer did not claim exhaustive native-schema certification or that successful ingestion established origin.

The specialty contribution was source-specific field validation, including Windows event versions and field capitalization, together with detection-stack joins. Three root/launchd-parented, argument-free `sw_vers` executions on each Mac were initially a weak command-recipe concern, with shared inventory software already a plausible explanation.

### Network Forensics

Initially **Real**, verdict confidence **65**, synthetic-confidence **32**. The strongest evidence was (1) coherent TCP states, histories, packet/payload accounting, and protocol intervals; (2) correct separation of zero-body successful CONNECT control messages from tunneled bytes, with compatible TLS/certificate identities; and (3) cross-sensor byte differences accompanied by capture-gap evidence. A cited LDAP observation's 19-byte shortfall matched its `missed_bytes=19`, rather than contradicting a clean observation at another sensor.

The specialty contribution was distinguishing source-local observations and sensor clocks from network-wide truth. The two original concerns were deliberately limited: six irregular ICMP payload sizes in about 0.58 seconds could be diagnostics, and 331 short/reset-heavy MySQL observations could represent a non-pooled or unstable application. No pooling requirement or invalid ICMP grouping was established.

### Host/EDR Forensics

Initially **Synthetic**, verdict confidence **80**, synthetic-confidence **64**. The strongest synthetic-origin observation was two native Mac fork triples with exactly preserved microsecond fractions at integer-second offsets, while subsequent exec fractions varied. Supporting concerns were seven `cat`-based Office/PDF regular-file reads on MAC-MROSS-02 and prominent IRQ/snap message populations on Linux. Those secondary observations already had scripting, selection, and verbosity alternatives.

The specialty contribution was identifying a timestamp-distribution pattern that the others' ordering checks had not tested. Host/EDR also found substantial strengths: all 873 visible Sysmon process creations matched Security 4688 process semantics, tested endpoint lifecycles held, and native Mac fork/exec identities were distinct. The original review did not establish a hard contradiction.

## Round 2 — Cross-Examination

### Apparent contradiction: coherent telemetry versus synthetic timing

The reviewers resolve this as a difference in the question tested. Correct process/session identities, protocol accounting, and usable hunt pivots show that the records can describe plausible activity. They do not establish that the observations originated in live production execution. A localized distribution artifact can coexist with those strengths. Conversely, that artifact does not invalidate the successful checks or make the dataset broadly unusable.

This was the main blind spot exposed by the original Host/EDR report: three reviewers had checked lifecycle feasibility but had not tested the repeated fractional-time groups. Threat Hunter, Detection Engineering, and Network Forensics each explicitly report independently confirming the fork finding in their deliberation responses. Their revisions follow that newly examined evidence, rather than a vote against their initial positions.

### Strength challenge: what exactly repeats, and what can explain it?

The experts identify distinct fork notifications in `macos_endpoint_security.ndjson`, using event-envelope times rather than a parent's stable start time:

| Host | Native ES lines | Fork times on 2026-11-02, UTC | Child PIDs | Successive gaps |
|------|-----------------|--------------------------------|------------|-----------------|
| MAC-MROSS-01.meridianhcs.local | 56, 59, 62 | 14:37:50.487145000; 14:38:28.487145000; 14:38:57.487145000 | 34639, 34723, 34771 | Exactly 38 and 29 seconds |
| MAC-MROSS-02.meridianhcs.local | 89, 92, 95 | 15:30:55.965208000; 15:31:17.965208000; 15:31:58.965208000 | 13190, 13236, 13310 | Exactly 22 and 41 seconds |

The reviewers report 47 and 55 fork notifications respectively, with these the only repeated-fraction groups among the 102. Subsequent exec fractions vary: `.504588/.502088/.502372` on the first Mac and `.974238/.972569/.968948` on the second. The associated `mach_time` increments preserve the same whole-second gaps under the observed 24-million-ticks-per-second relationship. The wall and monotonic values describe one timing pattern; they are not independent defects, and four experts confirming the same rows does not create four separate artifacts.

The reviewers find ordinary formatter rounding less explanatory because the phase reuse is localized and neighboring observations vary. Intended integer-second command schedules are possible, but their concern is exact microsecond preservation in purported observations of separate forks, where actual dispatch variability would ordinarily remain. This is their distributional inference, not a proven kernel, schema, or exporter impossibility.

All retain alternatives: controlled replay, unusual scheduled collection, selective timestamp reconstruction or sanitization of real activity, and chance/selection effects. The transformation policy is unknown. Detection Engineering notes that a simple fixed time shift alone would preserve existing fractions rather than create these triples; more specialized retiming remains possible. No formal collision probability is assigned, because the pattern was found after inspection and independence assumptions are unproven. These limits keep confidence moderate and scores close to the band boundary.

### Count disagreement resolved: five versus three `sw_vers` executions

These counts refer to different subsets. Threat Hunter counted five total executions on each Mac; Detection Engineering described three root/launchd inventory invocations. Host/EDR's actual deliberation adds a concrete operational explanation: preceding xpcproxy executions name `com.meridianhcs.endpoint-inventory` for all three on each host. This evidence undercuts the initial suggestion that the inventory ownership remained unexplained. The facilitator therefore records the lineage as present, rather than recommending that an absent lineage be invented. Host/EDR assigns these inventory invocations no additional synthetic weight; other reviewers already treated shared inventory as an adequate alternative.

### Strength challenge: document reads, Linux verbosity, and network texture

Threat Hunter and Detection Engineering independently confirm the seven non-directory FILE/READ observations using `cat` on PDF/XLSX/DOCX paths. They retain modest or slight support for repetitive command texture. Host/EDR reduces its own finding to a weak signal with negligible independent scoring weight because scripting, collection, testing, and selected coverage can explain it. Network Forensics treats the reported pattern as qualified support and does not claim an independent full file-access check. No reviewer establishes ordinary graphical document consumption as the intended workflow.

IRQ/snap prominence is descriptive evidence without a conflicting collection policy. Host/EDR removes it as a material reason for the revised score; the other responses retain at most limited context. Expected sysstat cron periodicity is not a synthetic tell. Likewise, the ICMP burst's sizes—64, 1472, 1242, 32, 813, and 1125 bytes—remain compatible with diagnostic probes; missing identifier/command detail prevents a justified grouping allegation. Short/reset-heavy MySQL sessions remain compatible with non-pooled clients, health checks, or genuine instability. These concerns do not become stronger merely because the Mac timing shifts the verdict.

### Strength challenge: absent gzip versus a demonstrated broken chain

The DB root history records `gzip -9 /tmp/rpt_0318.sql`, while the reviewed eCAR stream lacks the corresponding process/output observation. A history entry does not prove successful execution, the compressed file could preexist, and collection completeness is unspecified. All responses resist elevating this to a lifecycle contract gap. Threat Hunter expressly withdraws its scoring contribution. The uncertainty can remain investigative without counting as affirmative evidence of synthesis.

### Source interpretation correction

Host/EDR corrects its original description of the MeetingAssist policy message as a “rejected executable.” The message says policy “would not allow” it; it establishes neither actual denial nor execution. No matching successful exec was found in the inspected evidence. The correction changes no score because the message was not used as a synthetic indicator. No missing child/effect is inferred from that warning.

## Round 3 — Revised Positions

| Expert | Actual revision and direction | Evidence influencing the revision |
|--------|-------------------------------|----------------------------------|
| Threat Hunter | Real → Synthetic; verdict confidence 64 → 77; synthetic-confidence 31 → 62 | Independently confirmed Host/EDR's fork groups. Retains operational pivot findings, gives modest weight to confirmed document-read repetition, and withdraws gzip scoring. |
| Detection Engineer | Inconclusive → Synthetic; verdict confidence 80 → 76; synthetic-confidence 32 → 62 | Independently confirmed fork groups outside the original lifecycle/schema tests. Slight supporting texture remains. Confidence falls because a confident unresolved assessment becomes an origin judgment with credible alternatives. |
| Network Forensics | Real → Synthetic; verdict confidence 65 → 75; synthetic-confidence 32 → 61 | Independently confirmed native endpoint timing evidence more discriminating than its qualified network concerns. Network checks and their limited concerns remain substantially unchanged. |
| Host/EDR Forensics | Synthetic retained; verdict confidence 80 → 76; synthetic-confidence 64 → 60 | Reconsideration reduces document-read weight, removes Linux verbosity as a material scoring reason, and credits others' production-like findings. Fork timing remains principal. Temporal category realism is revised from 6 to 7 to avoid overgeneralizing the localized issue. |

The first three changed verdicts; the initial Synthetic reviewer became more cautious. This is convergence on a verdict with different residual weighting, rather than uniform escalation of suspicion.

## Round 4 — Consensus Summary

### Key Agreements

- All four actual final verdicts are **Synthetic**, principally because of the same localized Mac fork-timestamp distribution finding. Every reviewer retains meaningful uncertainty about origin.
- Tested source-native fields, process/session identities, lifecycle relationships, protocol intervals/accounting, and operational pivots are substantially coherent. Correct correlation supports quality and usability but does not prove production origin.
- No reviewer establishes a hard contradiction, verified native-schema error, generator identity leak, or proven lifecycle contract gap. The central indicator remains `distribution_texture`.
- Window boundaries, selected source coverage, domain sanitization, complete matching, and compact suspicious activity must not themselves be penalized. Missing pre-window creations or post-window terminations are not automatic defects.
- Automation, collection selection, retiming, and real operational variation limit secondary concerns. Those concerns should not be accumulated into high confidence through repetition.

### Key Disagreements

There is no remaining split in the final verdict labels. The material residual disagreement concerns weight and calibration. Host/EDR's 60 explicitly remains in the mixed band; the other experts' 61–62 enter likely synthetic. Host/EDR gives negligible independent weight to raw document reads and no material weight to Linux verbosity; Threat Hunter and Detection Engineering retain modest/slight document-read support, and Network Forensics keeps qualified reported texture without claiming full independent verification. All give the fork timing primary weight.

The origin mechanism remains unresolved for everyone: carefully synthesized timing and real activity subject to selective replay/reconstruction can both explain the visible records. The experts find the former more persuasive overall, but none demonstrates the transformation history. Network Forensics explicitly acknowledges that stronger weight on undocumented reconstruction could justify an Inconclusive position; that is a stated alternative, not any expert's actual final verdict.

### Most Convincing Evidence

The ranking below reflects the common emphasis across the responses, without creating a fifth assessment or presenting a formally voted ranking.

1. **Toward synthetic origin: two exact-fraction native Mac fork triples.** Distinct children, integer-second phase preservation, varying subsequent exec fractions, and the localized extent make this the principal discriminator for all four. It is one distribution finding with credible alternatives, not a hard contradiction or multiple independent defects.
2. **Toward production-like quality: endpoint process/session semantics.** Host/EDR's 873 matching Sysmon/Security process creations, Detection Engineering's visible LUID/ProcessGuid checks, and the endpoint actor-lifecycle checks support substantial technical fidelity across source families. They do not settle origin.
3. **Toward production-like quality: concrete network contracts.** Zero successful CONNECT response bodies with separate tunnel totals, TLS/certificate relationships, and explicit sensor-gap accounting withstand the reported checks. These are stronger fidelity evidence than impressions of neatness.
4. **Toward production-like quality: usable cross-source hunt pivots.** Raw-TCP reverse-shell behavior, sender/network/receiver SCP correspondence, and explicitly inspected proxy visibility retain coherent operational meaning after revision.
5. **Weak and disputed support toward synthetic: repeated `cat` document reads.** Seven regular-file reads are confirmed by Host/EDR, Threat Hunter, and Detection Engineering, but their intended workflow and capture selection are unknown. Its influence ranges from negligible to modest. Inventory repetition, Linux verbosity, ICMP sizes, MySQL churn, and gzip absence are not promoted to stronger evidence here.

### Most Debated Points

- **Scheduled intent versus native observation time:** a command schedule can be integer-spaced, while exact microsecond-phase preservation in separate fork notifications needs a more specific explanation. Selective replay/retiming remains plausible.
- **Authenticity versus technical fitness:** the initial Real/Inconclusive positions emphasized successful invariant checks; the revised responses recognize that those strengths coexist with an origin-sensitive distribution artifact.
- **What collection omissions and unusual workflows prove:** gzip absence and `cat` document reads lack a complete-capture or ordinary-user-workflow contract. Linux daemon proportions and MySQL session lifetimes likewise need operational context.
- **Evidence independence and calibration:** monotonic/wall times, multiple expert confirmations, and overlapping command-texture observations must not be counted as unrelated defects. This helps explain the narrow final range and Host/EDR's downward revision.

### Improvement Recommendations (Consensus)

1. **Prioritize the native fork-time model if the data is synthetic.** Derive each native fork observation from its own modeled execution/dispatch timing rather than copying a command batch's fractional second through integer-second offsets. Preserve real automation cadence, fork-before-exec order, execution identity, and coherent wall/monotonic clocks. All four recommend addressing the underlying timing behavior; arbitrary cosmetic jitter is not the remedy.
2. **Make any intentional timestamp reconstruction reviewable.** Network Forensics explicitly recommends collection metadata describing deliberate phase-preserving reconstruction; the others retain such transformation as a live alternative. This is a conditional clarification, not evidence that such a policy exists or a unanimously requested new log source.
3. **Tie secondary behavior to its actual workflow and collection model before changing it.** For ordinary document work, use access behavior appropriate to the application/task; retain `cat` when scripted collection or terminal inspection is intended. Preserve the already observed named inventory-job lineage. Relate verbose daemon messages to actual states/verbosity, ICMP sizes to the diagnostic client, and DB lifetimes to pooling, checks, or failures. These are conditional model checks supported across responses, not consensus declarations that those behaviors are defective or need broader histograms.
4. **Resolve gzip coverage only under a supported capture contract.** Establish whether attempted commands/processes/files should be observed before requiring companion records. If comprehensive capture is intended, represent the attempted process and actual success/failure/output lifecycle consistently; otherwise retain an explainable collection policy. Threat Hunter's scoring withdrawal must be preserved.
5. **Preserve the validated strengths.** Keep source-specific event shapes and timing, native fork/exec distinctions, account/process/session ownership, raw TCP semantics, SSH/SCP and proxy relationships, TLS/CONNECT accounting, sensor-local identifiers and gap evidence, and window-boundary behavior. Every expert opposes arbitrary missingness, broken joins, impossible ordering, or removal of legitimate fleet automation merely to make the data appear less tidy.

The final record is unanimous in verdict label, cautious in strength, and explicit about unresolved provenance alternatives. It contains no finding that all hosts share the timing artifact or that the otherwise coherent dataset is unsuitable for investigation.

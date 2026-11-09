# Deliberation Summary

**FACILITATOR-MODELED — not reconvened expert votes.** This document structures the four supplied independent reports. No expert was reconvened, and revised positions, convergence, and recommendations below are modeled by the facilitator rather than statements subsequently approved by the reviewers. Only the deliberation instructions and panel reports were read. The underlying records were not independently rechecked here. Scores describe modeled synthetic-origin confidence, not measured probabilities or data-quality percentages.

## Panel Composition

All final columns are **FACILITATOR-MODELED**.

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 76 | 40 | Inconclusive | 78 | 58 |
| Detection Engineer | Inconclusive | 83 | 38 | Inconclusive | 81 | 56 |
| Network Forensics | Synthetic | 77 | 62 | Synthetic | 80 | 65 |
| Host/EDR Forensics | Synthetic | 88 | 69 | Synthetic | 88 | 70 |

**Modeled final synthetic-confidence mean: 62.25/100.** Initial mean: 52.25/100. The aggregate preserves disagreement; it does not convert the two inconclusive positions into synthetic votes.

## Round 1 — Independent Findings

- **Threat Hunter:** Inconclusive, verdict confidence 76, synthetic-confidence 40. The strongest concern was repeated Mac shell gaps across both hosts, qualified by their shared user. The strongest positive evidence was a workable web-process/network pivot and a database-to-SCP-to-SMB staging chain with coherent process, receiver, tuple, and file identities. Unique contribution: careful separation of local versus outbound credentials, unrelated root sessions, and intrusion narrative from demonstrated causality.
- **Detection Engineer:** Inconclusive, verdict confidence 83, synthetic-confidence 38. A small native-shape deviation appears in all 38 Event 4658 v0 records: an added `ProcessName` field. Nine Mac `cat` invocations, five against normally binary document extensions, provide weak behavioral concern. Broad parser, lifecycle, UID/tuple, blocked-flow-state and accounting checks otherwise passed. Unique contribution: correct Event 1102 provider/UserData handling and rejection of false session-collision or Mac authorization allegations.
- **Network Forensics:** Synthetic, verdict confidence 77, synthetic-confidence 62. One TCP DNS answer cannot fit inside its reported responder payload; this is the principal hard contradiction. Sensor-specific losses, service durations, proxy topology, connection states, DNS variety and TLS chains otherwise look plausible. Unique contribution: protocol-content lower bounds, including a domain-independent bound, distinguish this row from loss-qualified HTTP byte differences.
- **Host/EDR Forensics:** Synthetic, verdict confidence 88, synthetic-confidence 69. Six Mac inventory processes last exactly 2.000000 seconds from fork; both Macs repeat command-gap sequences; a Linux developer repeatedly launches different editors on an approximately 96-second grid. Lifecycle, hashes, platform-specific process lineage and session semantics remain credible. Unique contribution: microsecond-level duration repetition and a separate Linux timing pattern beyond the Mac history observation.

## Round 2 — Cross-Examination

### Proven contradiction within the reported evidence

**DNS content versus transport accounting:** `zeek-core/dns.json:2174` reports a successful TCP A answer for UID `CRkx67bXuEAx6OIOJY`; `conn.json:9826` gives only 25 responder payload bytes, zero missed bytes, and no gap marker. The network report derives a 29-byte absolute minimum: 12-byte DNS header, at least 15 bytes for one IPv4 resource record, and two TCP framing bytes. This remains too large even without an echoed question or the supplied hostname. The ordinary named response estimate is 59 bytes, but that stronger assumption is unnecessary.

This is a **reported, bounded hard contradiction**, not a fresh facilitator verification. Its proof concerns the mutually incompatible recorded facts under their stated semantics. It does not by itself prove synthetic origin: faulty export, transformation, collector accounting, or post-processing of authentic data remains a provenance alternative. No evidence in the supplied reports establishes one of those alternatives for this UID. It merits more weight than regular timing while remaining localized to one exchange.

**Apparent disagreement resolved:** The Detection Engineer's passed packet/IP-byte and file-payload checks do not refute the Network Analyst's DNS-content minimum. A connection can satisfy broad packet-accounting bounds while still reporting too few application bytes for a decoded answer. Similarly, the hunter's successful SSH/SMB pivots do not test this DNS exchange. The findings are compatible and expose different check coverage, rather than an expert reporting the same test with an opposite result.

### Qualified distribution and behavioral texture

**Exact Mac inventory durations:** Six distinct lifetimes, on two hosts, retain precisely 2.000000-second fork-to-exit intervals despite varied exec delays. This is stronger texture than a generally regular background schedule. Fixed inventory automation or a collection transformation could still explain it; it is not an impossible execution. The reports provide no statistical reference population or proof that this inventory workflow cannot be timed.

**Shared Mac shell cadence:** The hunter's and host analyst's observations concern overlapping records and must be counted once. The host report extends the history-level finding with exact ES anchors and later 44/51-second pairs. Different commands repeating a sequence of gaps supports shared scheduling more than vocabulary overlap does. The common user, a checklist, or automation weakens an inference of synthetic origin; visible interactive shells do not exclude scripts.

**Linux editor grid:** Repeated 95–97-second intervals across multiple editors and project paths add a host/activity family beyond the Mac evidence. The repeated intervals are observed; task-slot generation is an interpretation. Timed automation, demonstration activity, or an unusual real workflow could also produce them. The short collection does not support a population-wide behavioral claim.

These timing manifestations provide converging concern, but they are neither three hard contradictions nor necessarily three independent causes. The modeled discussion retains substantial host concern while preventing that concern from becoming certainty.

### Native-shape deviation and weak behavior

**Event 4658 enrichment:** The supplied report identifies `ProcessName=System` as an extra field in all 38 v0 payloads. That is a concrete deviation from the native event shape as described by the Detection Engineer. Collector enrichment or reconstructed XML is a plausible alternative to fabricated underlying activity. The provenance distinction matters: a normalized enriched record and an untouched native XML export have different expectations. Keep its score contribution small without evidence of the export contract.

**Binary-document `cat`:** Extensions alone do not establish actual content or intended consumption. Shell inspection, automation, collection, or malicious reads are possible. The unusual repeated choice is weak support for limited command vocabulary, not a native-format defect or impossible file access. It does not justify requiring office applications to appear in this collection.

### Unsupported collection expectations — excluded

No score increase is warranted for missing boot events, out-of-window termination, omitted Sysmon families, sparse Mac Unified Log rows, absent Linux PAM on macOS, a short daytime collection lacking night/weekend behavior, or additional collectors not supplied. Nor do an easy-to-follow intrusion, high correlation coverage, stable hashes, sanitized naming, sensor overlap, unlock LogonID reuse, or source timestamp offsets demonstrate synthetic origin.

The Mac policy message saying a process “would not allow” is not established denial followed by execution. HTTP body differences on a connection with missed bytes remain ambiguous. Encrypted SSH byte totals need not equal the transferred file's size. These expectations and interpretations are not promoted into defects or recommendations to add telemetry.

## Round 3 — Revised Positions: FACILITATOR-MODELED

- **Threat Hunter: 40 → 58; remains Inconclusive; verdict confidence 76 → 78.** The network content/accounting contradiction adds stronger negative evidence than the hunter's initial Mac texture. The exact inventory runtimes and Linux editor cadence broaden the timing concern. Coherent attack pivots and the provenance alternatives still support an inconclusive verdict. The modeled increase does not imply the successful hunting chains are invalid.
- **Detection Engineer: 38 → 56; remains Inconclusive; verdict confidence 83 → 81.** The DNS content bound identifies an untested consistency dimension beyond the broad checks that passed. Host timing findings increase concern beyond the extra 4658 field and `cat` choices. The slight drop in verdict confidence reflects less confidence that an inconclusive position adequately captures the stronger combined negatives, while enrichment and real-data transformation remain unresolved explanations.
- **Network Forensics: 62 → 65; remains Synthetic; verdict confidence 77 → 80.** Host observations add qualified support from a different domain. The DNS contradiction remains the primary basis; timing does not become proof. Broad successful network checks and the single-row scope keep the increase modest.
- **Host/EDR Forensics: 69 → 70; remains Synthetic; verdict confidence unchanged at 88.** The DNS contradiction reinforces the direction of the existing assessment. Cross-examination also emphasizes shared-automation alternatives and overlap between Mac reports, limiting the increase. No new endpoint impossibility was established.

## Key Agreements

**Modeled convergence from the written reports:**

- The data supports useful cross-source hunting and retains many credible platform, session, process, tuple, and certificate relationships.
- Bounded checks found no visible actor use before matching creation or after matching termination; this is positive evidence for inspected relationships, not universal lifecycle proof.
- The TCP DNS byte contradiction is the strongest individual defect once surfaced to the full modeled panel.
- Repeated endpoint timing is observable and merits attention, while automation alternatives prevent treating it as impossible behavior.
- Native-source assumptions and collector scope must be established before assigning penalties for enrichment, missing rows, or source-specific semantics.

## Key Disagreements

The unresolved difference is how much a localized internal contradiction plus qualified behavioral texture establishes synthetic origin. The modeled Network and Host positions favor synthetic; the modeled Hunter and Detection positions remain inconclusive because authentic-but-transformed or scripted records can contain these artifacts. None of the reports supplies independent provenance evidence resolving that distinction.

The host analyst gives repeated timing greater weight than the hunter initially did. Exact fork/exit durations and the Linux grid expand the concern, but shared Mac user/workflow and the absence of a real-world reference distribution preserve a legitimate weighting disagreement.

## Most Convincing Evidence

Ranked by modeled evidentiary weight, rather than number of reviewers citing it:

1. **Hard contradiction:** TCP DNS UID `CRkx67bXuEAx6OIOJY`, core DNS line 2174 / connection line 9826: one decoded A answer requires at least 29 responder TCP payload bytes; only 25 are reported with no loss. Narrow scope, strong internal conflict.
2. **Strong qualified texture:** All six Mac inventory fork-to-exit intervals equal 2.000000 seconds despite varied exec latency. Compatible with a fixed workflow, but unusually exact across distinct instances.
3. **Qualified texture:** Both Mac histories/ES repeat the same gap sequence with different commands and shifted anchors. The hunter and host citations corroborate the observation; they are not independent samples.
4. **Qualified texture:** Linux developer editor launches repeatedly recur on an approximately 96-second grid while changing editors and projects. Independent activity family, still compatible with automation.
5. **Positive realism evidence:** Preserved process/session ownership and workable web/SCP/SMB pivots, together with broad sensor-local UID/tuple and TLS checks. These constrain claims of pervasive inconsistency; they do not identify provenance.

The 4658 field is a smaller source-shape concern with a strong enrichment alternative; binary-document `cat` remains weak.

## Most Debated Points

- Whether a protocol contradiction identifies synthetic data or erroneous reconstruction of authentic data. It establishes inconsistent evidence, while provenance stays unresolved.
- Whether exact timing comes from a generator or legitimate automation. Separate precise duration repetition from human-behavior assumptions; avoid treating a shared user as independent operators.
- Whether broad successful checks negate a specialized failing check. They do not: content-size feasibility and generic packet accounting test different constraints.
- Whether a native-field extension should be penalized without an export contract. Retain it as qualified shape evidence, not a hard authenticity verdict.

## Improvement Recommendations — FACILITATOR-MODELED CONVERGENCE

These recommendations synthesize the written reports; they were not ratified by reconvened experts.

1. **Repair shared DNS/transport accounting for the concrete failing UID.** Derive response payload size from the same decoded response content, including TCP framing, and preserve sufficient bytes when representing partial closes. Add a focused check for decoded answers whose minimum feasible response size exceeds available responder payload without an applicable loss explanation. Include unusual close states; do not rewrite unrelated successful DNS rows.
2. **Make inventory lifetime reflect execution semantics.** Check why six fork/exit pairs are exactly two seconds. If the inventory workflow intentionally enforces a fixed duration, preserve that causal behavior and any genuinely collected evidence explaining it. Otherwise use plausible execution/runtime variation that remains consistent with fork/exec/exit ordering. Random noise alone is not the goal.
3. **Give interactive work task-driven timing and persistent preferences.** Avoid reusing the same command-gap sequence across the two Macs or cycling developer editors on a near-fixed grid unless shared automation is intended. Preserve dependencies, identities, and genuine periodic automation; distinguish them from human think time and longer editing work.
4. **Keep native and enriched Windows representations explicit.** For an untouched native 4658 v0 export, keep its native EventData shape; place resolved process names in a declared enrichment/normalized representation. If enrichment already explains the field, document that representation instead of inventing compensating events.
5. **Tie file access to intended behavior and available content.** Review repeated mounted-document `cat` selection. Keep it where shell inspection or collection is intended; represent application-driven reading when that is the actual activity. Do not infer required applications from filename extensions alone or add telemetry beyond the collector's real scope.
6. **Preserve the successful relationships.** Retain transport/auth separation, process/GUID lifecycles, stable hashes, platform-specific lineage, sensor-local observation differences, and credential/session distinctions while correcting the targeted issues.

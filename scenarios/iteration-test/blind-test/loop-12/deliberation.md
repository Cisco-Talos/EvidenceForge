# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 76 | 47 | Inconclusive | 80 | 47 |
| Detection Engineer | Real | 65 | 34 | Inconclusive | 78 | 45 |
| Network Forensics | Real | 64 | 24 | Real | 57 | 36 |
| Host/EDR Forensics | Inconclusive | 80 | 48 | Inconclusive | 82 | 46 |

Values above reproduce the four actual individual deliberation responses. Verdict confidence describes confidence in the selected assessment; it is distinct from synthetic-confidence. The panel finishes with three Inconclusive assessments and one moderate-to-weak Real preference, not a unanimous attribution.

The Threat Hunter initially emphasized viable reverse-shell ancestry, database dump/SCP boundaries, multipart support-upload semantics and transport-before-authentication ordering. The seven binary-document shell reads on one Mac remained the principal reservation. Broader native and network checks reinforced the decision to withhold attribution: the verdict and synthetic-confidence score remain unchanged, while verdict confidence rises from 76 to 80.

The Detection Engineer initially favored Real on native field structures, process/session identities, loss-aware file and transport accounting, and macOS fork/exec semantics. The distinctive concern was 18 similarly shaped Dovecot session identifiers. Independently reproducing the Mac command-selection pattern identified by the endpoint reviewers changed the assessment to Inconclusive and raised synthetic-confidence from 34 to 45. The original technical findings were retained; their ability to distinguish provenance was reassessed.

Network Forensics initially gave the strongest production-like assessment, supported by protocol/connection bounds, authoritative DNS TTL behavior, proxy transaction semantics and TLS certificate visibility. Platform-separated browser versions were only a weak reservation. The analyst accepted the Mac and mail findings after rechecking them, raised synthetic-confidence from 24 to 36 and reduced verdict confidence from 64 to 57, while retaining Real.

Host/EDR Forensics initially balanced matching Windows process identities, stable hashes, credible Linux sessions and distinct Mac terminal/process models against binary-document shell reads and service-authentication frequency. The final response downweights service-volume concerns and reports endpoint software metadata corroborating browser-version families. Together with the other reviewers' positive network checks, this lowers synthetic-confidence from 48 to 46; Inconclusive remains, with confidence increasing from 80 to 82.

## Key Agreements

- No reviewer established a hard contradiction, impossible visible lifecycle, or verified source-native schema defect. This conclusion concerns the supplied checks and collection slice; it does not establish production provenance.
- All four actual responses accept the same localized Mac behavioral concern: seven of nine visible FILE/READ rows on MAC-MROSS-02 are `/bin/cat` reads of two PDFs, one XLSX and four DOCX files. Corresponding native Endpoint Security exec records confirm literal command execution. The two other rows are directory reads associated with `ls`. Independent reproduction strengthens this one finding; it does not create multiple independent defects.
- All four accept limited identifier-texture concern in the Dovecot records: 13 MAIL-EDGE and five MAIL-CLIN session values are ten characters long and start `AAAA`. None verifies the deployed implementation or export transformation sufficiently to call the values invalid.
- The native endpoint and network evidence remains substantially coherent. Checked process identities and lifetimes, session ownership, protocol tuples and intervals, capture-loss accounting, file sizes and certificate relationships survive review.
- Type 5 service-authentication counts are reproducible but weak evidence. DC-01 has 155 and MAIL-FIN 66 successes over the six-hour slice, with a similar built-in-account mix. Shared hosting and credential activity prevent requiring one new process per authentication; unavailable System-channel records are not evidence of a defect.
- Complete source matching is neither proof of production origin nor a synthetic clue. Selected source coverage, isolated unmatched references, legitimate unlock identifier reuse and out-of-window lifecycle boundaries must not be promoted into contradictions without additional visible evidence.

## Key Disagreements

The remaining disagreement concerns evidential weight, rather than incompatible observations. Network Forensics retains a Real lean because the added concerns are localized and technically possible, while extensive source-specific protocol checks remain convincing. The analyst explicitly considers an Inconclusive assessment defensible. The other three reviewers judge that those same consistency checks, despite their practical value, do not discriminate provenance strongly enough to resolve the behavioral concerns.

The Detection Engineer's actual change is the clearest deliberation outcome: native ES corroboration removed the explanation that the Mac reads were merely generic EDR labels for GUI activity. This recurring behavior had not been evaluated by the initial schema and correlation review. The analyst moved from Real to Inconclusive without retracting the positive technical findings. The Network analyst accepted the same evidence but did not cross that attribution boundary.

No reviewer treats raw binary reads as impossible. Scripts, redirected streaming, diagnostics or shell inspection remain viable. Nor does any reviewer promote the Dovecot prefix into a schema violation. Thus the panel agrees on the observations and their limits while retaining different overall judgments.

## Most Convincing Evidence

The ordering below reflects the emphasis and cross-review acceptance in the submitted responses, rather than an additional expert investigation or a formal panel ranking vote.

1. **Synthetic-leaning: repeated binary-document `cat` activity, corroborated natively.** Seven paths across multiple shares and more than five hours use the same raw streaming utility. For example, native ES line 108 executes `/bin/cat` against `service-review.xlsx` at `16:05:48.676562Z`; eCAR line 294 records its read at `16:05:57.353Z`. All four accept localized `distribution_texture` weight. This finding principally drove the Detection Engineer's verdict change and the Network analyst's upward score revision. It remains a possible real workflow, not a contradiction.
2. **Production-like: coherent endpoint identities and lifecycle semantics.** The host review matches all 873 visible Windows Sysmon process creations to Security 4688 identity fields; the detection and host reviews find no demonstrated dependent-event lifetime violation within their stated checks. Mac exec transitions preserve process lifetimes while advancing PID versions, and fork creates distinct child lifetimes. These source-aware relationships survive deliberation, while their provenance-discriminating strength remains disputed.
3. **Production-like: protocol timing and loss-aware accounting.** The network review links 4,237 DNS, 5,180 HTTP and 3,433 SSL observations to same-sensor connections with matching tuples and viable intervals, and repeats that check in deliberation. The detection review independently supports the treatment of capture gaps and file-byte accounting. Stable authoritative TTLs, proxy control/tunnel separation and TLS 1.3 certificate opacity add source-specific plausibility.
4. **Synthetic-leaning, limited: constrained Dovecot identifiers across two hosts.** All 18 visible values share the ten-character length and `AAAA` prefix; examples include `AAAABM3KZv` and `AAAAA0bXJS`. All four retain some texture concern. Unknown source construction or transformation limits its strength, and structured identifiers need not be uniformly random.
5. **Production-like: viable operational chains across sources.** The Threat Hunter traces the Apache-owned reverse shell, database dump/SCP transfer, multipart diagnostics upload and Mac SSH pivot through compatible command, account, tuple and timing relationships. Other reviewers cite these findings as complementary to their own consistency checks. They establish investigative feasibility and operational plausibility, not independent proof of origin.

## Most Debated Points

- **What does native corroboration resolve?** Actual `cat` exec targets defeat the GUI-normalization explanation. They do not reveal all shell redirections, inherited descriptors or user intent. The denominator is the selected visible read population, not every document access on the host. The panel therefore keeps the concern localized.
- **How much does technical coherence establish?** The Detection Engineer revised the interpretation of successful schema and lifecycle checks; the Network analyst retained more positive attribution weight. All agree the data can support credible investigation and that careful construction could also satisfy these relationships.
- **Are the mail identifiers malformed or structured?** Repeated length and prefix are observed, but the implementation is unverified. Reviewers recommend checking actual construction before changing the identifiers, rather than assuming random strings are correct.
- **Does service-authentication volume require matching process churn?** No reviewer establishes a one-to-one requirement. The host analyst substantially reduces this concern's weight after deliberation. Its numeric premise survives; a missing-companion allegation does not.
- **Do browser versions indicate stock profiles?** Initial Windows/Linux Chrome 120 versus macOS Chrome 155 clustering raises little adverse weight. The host response adds native Windows version metadata matching observed HTTP families on WS-MCHEN and WS-DRAMIREZ, weakening any endpoint/network inconsistency interpretation. Managed or retained software and user-agent substitution remain viable; fleet patch-policy realism is unresolved.

## Improvement Recommendations (Consensus)

These are conditional recommendations supported by all or most individual responses if the data is synthetic; they do not assert that its origin was established.

1. **Make document access follow the intended task.** Review the seven Mac binary-document reads individually. Use appropriate applications for viewing, meaningful extraction tools for extraction, and explicit shell-processing or raw-streaming workflows where those actions are intended. Preserve legitimate `cat` usage; changing commands merely for variety would not address the concern.
2. **Validate Dovecot identifiers against the intended implementation.** Compare the observed length, encoding and changing components with captures from the intended deployed version and any export transformation. Preserve authentic structured components; do not replace the `AAAA` prefix with arbitrary randomness without verifying source behavior.
3. **Derive Type 5 activity from service and credential operations.** Relate authentication cadence and account mix to the intended services, while allowing shared service hosts and existing processes. Establish whether the cited volumes are actually inconsistent before changing them. Do not fabricate extra process or System-channel records to satisfy an unsupported one-to-one count.
4. **Preserve the source-aware relationships that withstand review.** Retain process-versus-exec distinctions, stable identities, transport-before-authentication ordering, multipart transfer semantics, capture-loss accounting, proxy control/tunnel separation, authoritative TTL stability and version-appropriate TLS visibility. Do not weaken correlations or manufacture collection gaps to make the data appear less consistent.

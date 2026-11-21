# Deliberation Summary

This facilitation synthesizes only the four original `*-report.md` files and the four actual `*-deliberation.md` responses in this study, using `deliberation-instructions.md`. It adds no independent inspection, expert vote, or revised score. All four reviewers ultimately report **Inconclusive**, while retaining different evidentiary weights and synthetic-confidence scores. Agreement on that classification does not establish provenance.

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Inconclusive | 78 | 45 | Inconclusive | 84 | 56 |
| Detection Engineer | Real | 71 | 18 | Inconclusive | 85 | 46 |
| Network Forensics | Inconclusive | 83 | 47 | Inconclusive | 86 | 51 |
| Host/EDR Forensics | Inconclusive | 84 | 54 | Inconclusive | 87 | 57 |

Verdict confidence measures confidence in the stated classification; it is distinct from synthetic-confidence. No panel probability or aggregate vote is substituted for these submitted positions.

## Round 1 — Original Findings

- **Threat Hunter:** Initially Inconclusive, confidence 78, synthetic-confidence 45. The strongest positive evidence was the distinction between Aisha's local NewCredentials identity and Marcus's outbound credentials, transport-before-authentication in sampled SSH sessions, and a compatible Linux dump/SCP/SMB transfer sequence. The main concern was seven Mac `cat` executions targeting document-format filenames. Repeated discovery commands and generic SMB filenames carried little independent weight. The distinctive contribution was validating whether important account, session, process, and transport pivots actually supported the observed actions.
- **Detection Engineer:** Initially Real, confidence 71, synthetic-confidence 18. Correct Event 1102 provider/payload and channel-record reset, 935 matched Security 4688/Sysmon process creations with agreeing fields, and coherent protocol joins/TLS-version visibility drove this position. Native macOS fork/exec identity handling added support. Two orphan SMB mapping UIDs remained unscored collection caveats. The distinctive contribution was testing ingestible native field contracts and identifier/lifecycle relationships.
- **Network Forensics:** Initially Inconclusive, confidence 83, synthetic-confidence 47. The principal concern was an exact association between final TCP state and SSL companion availability across three sensor views, corroborated by HTTP. Concrete proxy DNS/transport ordering and byte scopes, stable certificate relationships, and TLS-version-sensitive visibility supported realism. The distinctive contribution was testing the population of connections lacking protocol observations, alongside the correctness of existing observations.
- **Host/EDR Forensics:** Initially Inconclusive, confidence 84, synthetic-confidence 54. Twelve Linux editor launches rotating among three tools and seven Mac `cat` document-path reads were localized behavioral concerns. Windows identities, hashes, paired process fields, and macOS fork/exec/audit relationships remained coherent. Long shared-volume command runtimes had only weak supporting weight. The distinctive contribution was the Linux user's editor/project distribution and detailed endpoint identity review.

## Round 2 — Cross-Examination

### Present-record integrity versus protocol-record availability

The initial Real assessment and the network concern tested different properties. Valid tuples and timing for existing application rows do not resolve a systematic pattern among connections without such rows. Equally, that pattern does not invalidate the valid rows or endpoint identities. All four actual deliberation responses distinguish these questions; the Detection Engineer explicitly identifies the population test missing from the original review.

The reviewers report reproducing this same-sensor SSL UID cross-tab, restricted to connections classified `service=ssl`:

| Sensor | SF with SSL companion / total | S1 with companion / total | Other states with companion / total |
|--------|--------------------------------|----------------------------|-------------------------------------|
| Core | 363 / 363 | 4 / 4 | 0 / 55 |
| DMZ | 3,139 / 3,139 | 9 / 9 | 0 / 117 |
| Database | 29 / 29 | 0 / 0 | 0 / 5 |

That is 3,531 SF and 13 S1 observations with companions, versus 177 other-state observations without them; 172 of the latter record zero missed bytes. The database `RSTO` example `CtTmhQbKXdbYqsQsp0` records 2,436/20,416 directional payload bytes, and core `S2` example `CyCfqQR7ouC5IoVJr` records 4,076/12,706. The cited examples end inside the slice. DMZ HTTP adds 2,870 companions among 2,882 SF observations, versus none among 17 non-SF observations; ten of those 17 have response payload and no recorded gaps.

The accepted concern is **distribution_texture**: exact conditioning by final state deserves an explanation. The accepted strength challenge is that service classification, aggregate payload, and zero recorded missed bytes do not prove a parseable handshake/transaction or complete export. A common query/export filter could create this distribution in production. Sensor observations can overlap, and HTTP corroborates the same possible mechanism; neither supplies a separate independent proof. No reviewer elevates this to a hard contradiction or established collection-contract violation.

### Endpoint workflow concerns and their alternative explanations

The actual responses reproduce twelve editor launches among 89 Lina-attributed process creations: four nano, three vim, and five Emacs. Recombination of tools, repositories, and filenames supports the Host/EDR concern, but legitimate tool switching and absent personal/task context remain alternatives. The reported processes do not establish impossible ordering. The Detection Engineer gives this less weight than the network evidence; the Threat Hunter and Host/EDR reviewer retain moderate localized concern.

All four responses accept the seven native Mac `cat` executions targeting PDF/XLSX/DOCX filenames and the corresponding seven of nine normalized FILE/READ observations. Cross-examination narrows the claim: extensions do not establish actual contents, and exec arguments do not establish stdout's destination or consumer. The Network reviewer specifically challenges a confirmed terminal-display interpretation; the Threat Hunter narrows the original binary-document wording. Scripts, copying, testing, or deliberate byte inspection remain possible. This is one localized tool/file distribution concern, counted once despite multiple reviewers reproducing it.

The 10.624–29.761-second `cat` lifetimes and other long shared-volume commands remain weak supporting context. Storage latency, file size, and output blocking are unresolved alternatives. No response establishes impossible runtime or supports counting duration as another major defect.

### Positive semantics survive the challenge

The distinctive Windows clear sequence remains positive evidence: record ID 28260865 before Event 1102, ID 1 on 1102, then ID 6, with the Eventlog provider and `UserData/LogFileCleared` payload. The Host/EDR response reports directly rechecking it; the Network reviewer explicitly accepts the reported finding without claiming to rerun the Windows review. The Host/EDR reviewer also reports verifying Aisha's local Type 9 identity and Marcus's separate outbound identity. These source-specific findings support technical quality without proving real origin. No response withdraws the checked native identity, lifecycle, TLS visibility, proxy accounting, or sampled SSH phase-separation results.

## Round 3 — Actual Revised Positions

- **Threat Hunter:** Inconclusive retained; confidence **78 → 84**, synthetic-confidence **45 → 56**. Reproduced network distribution and Linux editor evidence add concern. The Mac finding survives with narrower wording. Strong credential/lifecycle results and credible filtering/workflow alternatives prevent a Synthetic assessment.
- **Detection Engineer:** **Real → Inconclusive**; confidence **71 → 85**, synthetic-confidence **18 → 46**. This is the only classification change. Independently confirmed state-conditioned protocol availability and both endpoint distributions changed the position. The reviewer explicitly says the original score overweighted successful technical checks without testing these distributions. Native integrity results stand; export policies and unusual workflows remain plausible.
- **Network Forensics:** Inconclusive retained; confidence **83 → 86**, synthetic-confidence **47 → 51**. Reproduced endpoint patterns add modest independent concern. The network result is unchanged, terminal-output claims are narrowed, and shared-storage/runtime alternatives remain open.
- **Host/EDR Forensics:** Inconclusive retained; confidence **84 → 87**, synthetic-confidence **54 → 57**. Reproduced network distribution adds a small upward adjustment. The verified Windows clear and NewCredentials semantics reinforce technical quality. Editor and Mac access patterns remain moderate localized concerns rather than ownership/lifecycle defects.

## Key Agreements

- The checked source-native identities and visible lifecycles are technically convincing. No report or actual response establishes an impossible visible ordering, conflicting stable process identity, or hard source-native contradiction.
- Three distinguishable distribution concerns remain: state-conditioned protocol observation availability, Linux editor/project combinations, and Mac `cat`/document-path choices. Each has a credible production explanation.
- Correct technical relationships constrain synthetic-confidence but do not establish provenance. Behavioral distribution concerns can matter without a schema failure.
- Reproduced observations are corroboration, not additional defect families. Sensor overlap, SSL/HTTP mechanism overlap, and repeated reporting of the same seven Mac commands must not multiply evidentiary weight.
- The final classification is Inconclusive for every reviewer, with submitted synthetic-confidence scores spanning 46–57.

## Key Disagreements

The original classification split closes after the Detection Engineer revises, but weighting differences remain. Detection Engineering retains the lowest synthetic-confidence, 46; Network is 51; Threat Hunting and Host/EDR are 56 and 57. The engineer weighs the editor finding below the network concern, while the endpoint-focused reviewers retain more concern about command/file combinations. These differences are preserved rather than averaged away.

The cause of the network partition remains unresolved between collection/export behavior and generation behavior. Likewise, no supplied workflow or file-content evidence resolves the endpoint patterns. These are shared unresolved alternatives, not a documented factual disagreement over the reproduced counts.

## Most Convincing Evidence

The following ordering reflects the emphasis in the submitted responses, not an additional panel ranking ballot:

1. **Exact TCP-state conditioning of SSL availability, with HTTP corroboration — synthetic-leaning distribution evidence.** All four responses reproduce or reconfirm it, and it drives the largest actual score/classification change. An export filter remains a sufficient alternative explanation.
2. **Windows native channel/identity semantics and process joins — positive technical-realism evidence.** Event 1102's reset/provider/payload, agreeing paired process fields, and local-versus-outbound credentials are concrete distinctions rather than impressions of narrative quality.
3. **Protocol-specific network truth — positive technical-realism evidence.** The reported proxy byte scopes, resolution-before-upstream-open example, stable certificates, and TLS-version visibility survive deliberation.
4. **Seven Mac `cat`/document-path accesses — localized synthetic-leaning distribution evidence.** Reproduced by reviewers, but neither contents nor terminal display is established, and scripts/byte-stream work remain plausible.
5. **Twelve Linux editor/project combinations — localized synthetic-leaning distribution evidence.** Reproduced counts support the observation; valid multi-editor workflows and missing task context limit its weight.

## Most Debated Points

- Whether correct existing protocol joins answer a population-level availability concern: the actual responses conclude they test different properties.
- Whether the exact state split proves synthesis: the responses retain a filtering alternative and reject a hard-contradiction claim.
- Whether `cat` arguments prove visual reading of binary documents: the revised wording confines the observation to filename extensions, commands, and associated reads.
- Whether successful native checks justify Real: the Detection Engineer revises that inference while retaining the checks themselves.
- Whether long shared-volume runtimes or repeated vocabulary add independent evidence: runtime remains weak context; discovery/share vocabulary carries little or no meaningful extra weight.

## Improvement Recommendations (Consensus)

These are recommendations explicitly supported by all or most actual responses, conditional on the data being synthetic where appropriate:

1. **Tie protocol observations to visible protocol progress and parsing outcomes.** Preserve supported partial TLS/HTTP observations on reset or half-closed flows; do not decide availability solely from final TCP teardown state. If an intentional real export/filter rule explains this exact partition, document that rule instead of manufacturing companion records.
2. **Bind file-access tools to the intended task.** Preserve `cat` for genuine byte-stream operations; avoid using it as an interchangeable stand-in for document consumption. Review the seven observed choices against the intended workflow and actual file contents, without demanding extra GUI/source coverage.
3. **Persist individual editor and project preferences.** Address the repeated tool/root/filename recombination while permitting legitimate editor changes and task-driven exceptions; no response supports a mandatory one-editor rule.
4. **Preserve demonstrated native correctness.** Retain channel-clear semantics, process/audit identities, local/outbound credential separation, lifecycle ordering, TLS visibility, and proxy byte scopes while changing distribution texture.
5. **Investigate shared-volume runtimes conditionally.** Most responses support checking file size, storage behavior, and output blocking before treating these durations as a defect. Runtime should follow the operation rather than assumed human reading time; the present evidence does not establish a required timing correction.

## Excluded Inferences and Limits

No conclusion here scores a complete, linear, compact, or easily narrated intrusion as synthetic. No score is increased for thin Unified Log coverage, missing event families, sanitized domains, two orphan SMB mappings, unmatched pre-/post-window lifecycle state, or absent GUI reads. The responses do not establish successful MeetingAssist execution after a proven denial; notification results and plist creation/removal do not prove authorization, launch activation, or unloading. Technical consistency is positive evidence without being proof of production provenance, and collection completeness is not assumed. The original reports and actual reviewer responses remain unchanged.

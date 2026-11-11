# Loop 92 — Authenticity assessment

Corrected authored email verification to distinguish requested To/Cc/Bcc headers from expanded distribution-group mailboxes. Reused unchanged loop91 source data for evaluation and four fresh independent blind reviews.

## Individual Expert Summaries

- **Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 30. The reviewed telemetry is mostly operationally plausible, with useful exact pivots between endpoint activity, proxy transactions, network transfers, and server-side file writes. I did not establish a hard contradiction or a defensible high-impact synthetic indicator in this bounded review; the data could be real or a capable synthetic collection, and successful correlation alone cannot distinguish those possibilities.

- **Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 20. The bounded sample would support ordinary SIEM ingestion and correlation: Windows XML, Zeek JSON, Linux syslog, normalized eCAR, and the sampled macOS exports have usable source-specific structures. Two exact correlations agree on identities and event meaning, and this review found no demonstrated contradiction or defensible synthetic indicator. These records look production-like, but a deliberately high-fidelity collection could produce the same observations, so provenance remains inconclusive.

- **Network Forensics Analyst:** Inconclusive; verdict confidence 80; synthetic-confidence score 25. The network telemetry is mostly production-like in the bounded sample, with coherent connection/protocol identities, plausible differentiated sensor traffic, and credible loss/retransmission texture. I found no demonstrated hard contradiction; these observations do not establish real provenance because a sufficiently capable synthetic dataset could exhibit the same properties.

- **Host/EDR Forensics Analyst:** Inconclusive; verdict confidence 80; synthetic-confidence score 32. The bounded endpoint review is mostly production-like: the two exact identity pivots preserve Windows process ownership and macOS fork/exec/credential transitions, with plausible differences in observation timestamps. I found no demonstrated impossible lifecycle or source-native contradiction; a small amount of potentially generic administrative command vocabulary is too weak to determine provenance.

## Prioritized Improvements

- **Fixed P2 — Distribution-group alias versus mailbox comparison.** Automated evaluator, one cleared action mismatch, medium correctness leverage and low risk. Compare requested channel identities after native header parsing, then independently expand typed one-level groups.
- **Open P1 — Mail provenance crosses independent actions.** Automated follow-up, four authored actions contain eight distinct unrelated messages, high provenance leverage and medium-to-high journal/recovery risk. Owner: canonical GroundTruthLedger inheritance through persistent process/action identities; keep failures visible pending a message/action ownership contract.
- **Open P1 — Other schema-v5 source requirements.** Automated failure families include missing evidence, native-fact differences and capability/timing decisions. Separate real absent evidence from faulty source-native expectations before changing generator or grader.
- **P3 — Package-like journalctl units and small SMB observation offsets.** Host/Threat (original rating:not labeled), weak signals, low leverage. Exact lifecycle and tuple joins remain coherent; no correction supported.

## Priority Rationale

Requested versus expanded recipients are independently meaningful facts; the fix strengthens Bcc/channel and expansion checks without forgiving unrelated messages. A clean blind panel does not resolve independent provenance failures.

## Family Contract and Verification

family_level evaluator semantics. _email_recipients_match independently compares all three authored channels, parses native display/angle-bracket addresses and resolves typed distribution-group members. Focused controls cover groups/direct addresses, missing expanded members, wrong group and Bcc moved into To;34 repair tests pass. No source records, thresholds, collection policy or scenario changed. Remaining four email errors reveal real ownership disagreement rather than another case to suppress.

## Comparison with Quantitative Eval

Automated evaluation: **94.4825/100 FAIL**, 147,759 records. Ground-truth agreement88.0920→88.0955; authored_email_outcome_disagreement5→4. Overall94.4825 FAIL,147,759 records. The small correct score change is not a blind-realism optimization target.

## Score Movement and Next Loop

Mean26.75 versus27.25 in loop91 (-0.50), on byte-identical source data; reviewer variance. All four verdicts Inconclusive, confidence80–82 and score spread12; no deliberation trigger. Loop93 qualifies the eight-message provenance family before attempting journal changes.

Reviewer reports are preserved verbatim. Priorities, false-positive classifications and implementation decisions above are coordinator synthesis.

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Synthetic | 78 | 66 | Synthetic | 84 | 72 |
| Detection Engineer | Inconclusive | 82 | 43 | Synthetic | 74 | 64 |
| Network Forensics | Inconclusive | 78 | 38 | Synthetic | 72 | 62 |
| Host/EDR Forensics | Synthetic | 74 | 63 | Synthetic | 78 | 67 |

These final positions come from the four actual revised responses. Verdict confidence and synthetic-confidence are distinct; no scores have been averaged or inferred. All four finish with a qualified Synthetic judgment, with synthetic-confidence scores ranging from 62 to 72. None reports a demonstrated hard contradiction or certain origin identification.

The Threat Hunter initially emphasized recombined policy-share vocabulary and repeated Mac binary-document reads, alongside credible SSH, staging, and upload pivots. Reproducing the Host/EDR expert's Mac metadata findings raises the hunter's final score from 66 to 72. The Detection Engineer initially emphasized successful parsing and broad identity/lifecycle checks, with only modest concern about the document reads. Rechecked DC-share vocabulary and Mac metadata move that assessment from Inconclusive to Synthetic; verdict confidence falls from 82 to 74 because the revised directional judgment is more qualified than the initial finding of unresolved origin.

Network Forensics initially found transport, DNS, TLS, certificate, and observation-path consistency, offset by short proxy TLS lifetimes and narrow browser-version vocabulary. Rechecking the share distribution, document operations, and Mac metadata moves that assessment from Inconclusive to Synthetic, while its original network checks remain intact. Host/EDR initially emphasized compact Mac process-version and executable-inode distributions despite strong endpoint consistency. Confirming the other reviewers' document and policy-share observations modestly raises its score from 63 to 67.

## Key Agreements

- **The strongest doubts concern distributions and routine behavior.** All four revised responses accept the repeated SYSVOL/NETLOGON vocabulary, compact Mac identity patterns, and seven binary-document `cat` executions as bounded indicators. They do not classify these as impossible actions or verified native-schema violations.
- **The tested technical relationships remain credible.** Windows process/session identities, Linux administrative ownership, Mac fork/exec distinctions, and network tuple/protocol relationships withstand the reported checks. The Threat Hunter's concrete SSH, archive-transfer, SMB, and proxy pivots remain usable. Complete cross-source matching is positive consistency evidence, not a synthetic tell.
- **Alternative explanations materially limit certainty.** Identifier sanitization could explain both Mac metadata patterns; custom administrative repositories could explain unusual share contents; explicit byte-processing workflows could explain `cat`; and proxy policy could explain short TLS lifetimes.
- **Repeated reporting is not independent evidence.** The same seven commands count once. Generic filenames and `tee` to a DOCX are supporting texture. Process-version and inode compression could share one remapping explanation and should not be treated as independent statistical trials.
- **Collection boundaries remain relevant.** An unmatched SMB mapping UID, out-of-window lifecycle partners, selected event coverage, and capture-gap-related arithmetic do not become defects through deliberation. No reviewer advocates introducing errors or weakening existing correlations to make the data appear real.

## Key Disagreements

The initial split in verdicts resolves in the actual revisions; there is no remaining categorical disagreement. Differences in evidentiary weight remain. The Threat Hunter finishes most persuaded of synthetic origin at 72, Host/EDR at 67, Detection at 64, and Network at 62. The latter two retain especially strong positive findings within their original specialties; their changes arise from broader background and metadata evidence, not overturned parser or transport results.

The importance of network-only texture remains limited and uneven. Network retains proxy lifetimes as a small supporting indicator, and Detection independently confirms the distribution with low weight. Threat Hunter gives it little additional weight; Host/EDR says it does not independently move its score. Managed browser-version cohorts are weaker still and do not materially drive the revisions.

The panel cannot resolve whether native identifier remapping explains the Mac metadata. The reviewers agree it could, but none establishes that remapping occurred. Similarly, they do not establish whether the share contents and binary reads reflect custom production workflows. Their common final inference favors constructed data while preserving these production/sanitization alternatives.

## Most Convincing Evidence

The following order synthesizes emphasis in the written responses; the experts did not submit a shared numerical ranking.

1. **Similarly initialized, uninterrupted Mac process-version ranges.** The newly represented identity ranges cover every integer from 12–112 on Mac 01 and 12–132 on Mac 02, despite launchd start dates of October 21 and October 6 and a November 2 observation window. The Host/EDR finding was reproduced by the other reviewers and materially influenced revisions. Pre-existing versions also appear: these are not the complete sets of all tokens, nor proof that earlier host activity was absent. Sanitization remains a substantial alternative.
2. **Recombined administrative share-object vocabulary.** The Threat Hunter's 52 SYSVOL/NETLOGON opens out of 122 SMB file opens were independently confirmed. Examples include `Policies\\logon-review.ini`, `Scripts\\gpt-draft.ps1`, and `Preferences\\registry-approved.bat`. The recurring folder/name/suffix/extension combinations across clients and both DCs matter more than any individual unconventional path. Custom repositories remain possible; missing conventional GPO hierarchy is not itself a contract failure.
3. **Compact executable-inode neighborhoods on both Macs.** The 29 and 32 represented executable paths occupy spans of only 95 and 107 inode numbers, respectively, across system utilities and third-party software with varied birth dates. Rechecks retained device identity, avoiding a comparison across unrelated devices. Reviewers regard this as suspicious catalog-like texture, tempered by deployment and remapping explanations and possible dependence on the first finding.
4. **Strong tested lifecycle and protocol consistency, favoring realism.** Detection's broad Windows and Mac checks, Host/EDR's process/session ownership checks, Network's UID/tuple/TLS checks, and Threat Hunter's operational pivots reinforce each other. They provide the principal counterweight to the synthetic inference and keep every final score below the hard-contradiction band.
5. **Repeated binary-document reads through `cat`.** All seven visible `cat` execs on Mac 02 target PDF, DOCX, or XLSX paths across several hours. Native argument arrays support the observation. Network's comparison with Mac 01's text/configuration reads adds context. Every revised response keeps the weight modest because binary byte reads, testing, and redirection remain possible.

## Most Debated Points

- **Consistency versus origin:** The original Inconclusive positions emphasized valid native fields and coherent lifecycles; the Synthetic positions emphasized background vocabulary and identity populations. Revisions treat these as compatible findings. Correct correlations demonstrate quality without establishing production provenance.
- **Native metadata versus sanitization:** Collector sequence fields are distinct from process audit identity, so collector resets alone do not answer the finding. Consistent privacy remapping could, and the reviewers explicitly retain that alternative rather than alleging impossible kernel behavior.
- **Unusual versus impossible workflows:** Neither `cat` on binary documents nor custom SYSVOL/NETLOGON content is forbidden. The cumulative repetition across objects and hosts drives the concern. The hunter explicitly narrows the original share interpretation and avoids demanding a GPO hierarchy for custom content.
- **Proxy lifetime policy:** Network reports 1,786 of 2,264 established proxy TLS sessions in the 0.8–5-second range and none outside the approximate 0.8–120-second bounds; Detection reproduces the concentration. A real upstream connection policy remains plausible, so this finding receives limited weight.

## Improvement Recommendations (Consensus)

- **Use persistent, purpose-specific share inventories.** Define stable SYSVOL/NETLOGON objects and access purposes, distinguish actual Group Policy processing from custom script repositories, and reuse those objects across clients rather than freely recombining folders, names, suffixes, and extensions. All four support this.
- **Make document workflows reflect file type and intent.** Use application behavior for ordinary Office/PDF consumption; preserve shell reads for explicit text inspection or byte-processing purposes. Keep process, file, SMB, and session correlations intact. All four support this.
- **Ground native identities in host history and inventory.** Preserve pre-window process identity history and stable executable identities tied to each host's filesystem/software inventory. Keep process identities separate from collector sequences. Do not repair compactness through arbitrary per-record randomization or gaps. All four support this direction.
- **Document actual sanitization transformations.** If these are production exports, state whether process-version, inode, and relevant filename fields were remapped. Identifier-remapping provenance could materially weaken the central metadata findings without requiring additional telemetry coverage. All four identify this as consequential.
- **Preserve demonstrated semantic strengths.** Retain native field distinctions, Windows session semantics, Mac fork/exec behavior, Linux privilege ownership, SSH transport/authentication ordering, and coherent DNS/TLS/proxy observations. Reviewers consistently regard these as strengths to retain.

Proxy reuse/lifetime policy is a qualified secondary recommendation supported by Network and Detection, with limited additional weight from Threat Hunter and no independent score movement for Host/EDR: tie connection behavior to explicit policy, application, and destination rather than assuming a common bounded duration distribution. Browser-version expansion does not have comparable panel support as a priority.

# Deliberation Summary

## Panel Composition

| Expert | Initial Verdict | Initial Verdict Confidence | Initial Synthetic-Confidence | Final Verdict | Final Verdict Confidence | Final Synthetic-Confidence |
|--------|----------------|----------------------------|------------------------------|---------------|--------------------------|----------------------------|
| Threat Hunter | Real | 64 | 30 | Synthetic | 71 | 61 |
| Detection Engineer | Real | 64 | 31 | Synthetic | 72 | 63 |
| Network Forensics | Real | 64 | 28 | Inconclusive | 78 | 50 |
| Host/EDR Forensics | Synthetic | 76 | 62 | Inconclusive | 80 | 55 |

**Arithmetic mean of actual final synthetic-confidence scores: (61 + 63 + 50 + 55) / 4 = 57.25.** Verdict confidence is distinct from synthetic-confidence. The mean is a descriptive aggregate, not a unanimous verdict, a calibrated probability of provenance, or a percentage of defective records. The final panel is split between two Synthetic assessments and two Inconclusive assessments.

This summary draws on the four original reports and four actual deliberation responses. Each reviewer reconsidered the original reports and rechecked supplied records; the responses do not represent a further live discussion or mutual acceptance of the others' revisions. No additional independent finding is introduced here.

The original positions and actual changes were:

- **Threat Hunter:** Initially emphasized the upload-to-shell-to-transport pivot, elevated Windows credential-access evidence, local-versus-outbound netonly credentials, and multipart/proxy byte accounting. The unique reservation was 48 accepted privileged diagnostic commands concentrated early across five Linux servers. Rechecking the Host/EDR getty/login finding changed Real to Synthetic: verdict confidence increased by 7 and synthetic-confidence by 31. The hunter explicitly distinguishes temporally valid references from correct executable-transition semantics; the original positive pivots remain supported.
- **Detection Engineer:** Initially emphasized successful parsing, GUID/LUID/UID lifecycle checks, stable file/certificate identities, and source-specific schemas. Distinctive observations included proper Event 1102 UserData handling and the executable-versus-loaded-DLL hash distinction. A four-message irqbalance vocabulary was the main original concern. Rechecking getty/login relationships changed Real to Synthetic: verdict confidence increased by 8 and synthetic-confidence by 32. Identifier consistency had not tested whether the process graph represented ordinary Linux exec semantics.
- **Network Forensics:** Initially emphasized coherent connection intervals/states, TLS certificate visibility, DNS answer/cache relationships, proxy CONNECT and SMTP STARTTLS boundaries, and DHCP renewal ownership. Repeated browser versions were a weak reservation. The endpoint concern changed the dataset-wide verdict from Real to Inconclusive: verdict confidence increased by 14 and synthetic-confidence by 22. Network conclusions remain substantially unchanged; undocumented normalization or customized supervision limits the endpoint finding's force.
- **Host/EDR Forensics:** Initially leaned Synthetic because of reusable getty parents and native console-close asymmetry, balanced against coherent Windows lifetimes/hashes and distinct macOS Terminal/iTerm execution chains. The reviewer retained the getty concern but withdrew the implication that missing native console closes demonstrated a cross-source contract failure. That observation became a low-weight weak signal because neither graceful cleanup nor complete collection was established. Independent positive checks reinforced the existing counterevidence. The final verdict changed to Inconclusive: verdict confidence increased by 4 while synthetic-confidence decreased by 7.

## Key Agreements

- **All four responses retain the Linux console process model as the strongest synthetic concern.** Ten `/bin/login` creations on six hosts name `/sbin/agetty` as a different direct parent; some reuse the exact parent PID and UUID. All accept a conditional `contract_gap` interpretation rather than an unconditional native impossibility.
- **All retain substantial production-like evidence elsewhere.** Checked Windows process/session identities, macOS executable transitions, SSH sequencing, network lifecycles, and protocol visibility remain credible. A localized console concern does not reverse those successful checks; successful checks also do not prove real provenance.
- **All reproduce the console-close asymmetry but recognize alternative explanations.** Ten named-user native opens have no named-user native closes; five corresponding login processes visibly terminate. Five native console closes are all root. Termination does not establish graceful PAM cleanup, and the supplied collection has no completeness guarantee.
- **All treat daemon repetition and early privileged administration as limited texture evidence.** Each inspected irqbalance host has four exact message texts. Early accepted sudo activity can reflect shared maintenance. Repeated command vocabulary and its timing should not be multiplied into independent strong defects.
- Browser-version repetition remains weak where addressed. Managed software deployment is a credible alternative, and arbitrary version variation would not improve fidelity.

## Key Disagreements

The remaining disagreement concerns evidentiary weight and classification, rather than the principal record counts.

**Getty interpretation:** The Threat Hunter and Detection Engineer judge the repeated direct-parent/PID model sufficient for a modest Synthetic lean. The Network and Host/EDR reviewers judge it meaningful but insufficient to resolve origin because the observer's ancestry transformation rules and actual software customization are unknown. Native PAM corroborates the child login PIDs, not the normalized PPID or parent executable. All four recognize that limitation; they differ in how much uncertainty it leaves.

**Console-close classification:** The Host/EDR reviewer explicitly downgrades this to a weak signal and withdraws a demonstrated-contract-failure implication. The other three retain conditional contract-gap or collection-consistency language with secondary weight; the Network reviewer calls it small to moderate. No response establishes complete native collection or graceful exit, and no response treats absence alone as decisive.

The actual final split is therefore **Synthetic / Synthetic / Inconclusive / Inconclusive**. There is no unanimous synthetic verdict, and the mean of 57.25 must not erase that disagreement.

## Most Convincing Evidence

The ordering below summarizes emphasis in the actual responses; reviewers did not jointly vote on a formal ranking.

1. **Reusable direct getty parents with separately numbered login processes — strongest shared synthetic concern.** APP-INT login PIDs 3374484 and 3376990 share getty PPID 36047 and its exact parent UUID. DB-PROD login PIDs 1366445 and 1373719 share getty PPID 29350; their lifetimes overlap. All four rechecked the repeated structure. They contrast it with ordinary same-PID exec handoff while retaining customization/normalization alternatives.
2. **Preserved source-specific semantics — strongest shared counterweight to a high synthetic score.** Network TLS 1.3 omits passively unavailable certificate chains; TLS 1.2 chains preserve identities; CONNECT and STARTTLS constrain content visibility. Windows local/outbound credential distinctions, visible lifetimes and hashes, plus macOS fork/exec identities, survive review. Reviewers retain these as meaningful bounded successes.
3. **Console-close account-class asymmetry — corroborated but disputed in strength.** The named-user/root split and five visible named-user terminations reproduce. Its weight is limited by unproven cleanup and observation completeness; the original reporting expert explicitly lowers its classification.
4. **Narrow daemon vocabulary and front-loaded diagnostics — weak supporting texture.** MAIL-EDGE, LOG-MON, APP-INT and WEB-EXT have respectively 55, 70, 67 and 155 irqbalance rows, each with four exact texts. Across five servers, the 48 accepted sudo commands end by approximately 14:27 while collection continues toward 19:00. Repetitive software diagnostics and coordinated maintenance remain plausible explanations.

## Most Debated Points

- **Consistency versus semantics:** Clean joins and valid lifetimes do not establish that a named executable has the represented parent/exec relationship. This blind spot drove the Threat Hunter's and Detection Engineer's reversals and the Network reviewer's move to Inconclusive.
- **Normalized versus native evidence:** Distinct native login PIDs strengthen the child-identity observation, but cannot certify the eCAR parent assertion. This prevents any reviewer from labeling the finding an unconditional native contradiction.
- **Missing cleanup versus missing collection:** The Host/EDR reviewer materially revised the original weighting after separating a visible exit from proof of graceful PAM cleanup. Other reviewers retain secondary concern without claiming guaranteed logging.
- **Operational regularity versus a small message pool:** Four-form daemon output and early maintenance can occur naturally. Denied sudo attempts explain raw counts of 14 rather than 13 on WEB-EXT and PROXY; reviewers reconcile that counting issue rather than treating it as conflicting evidence.
- **Localized defect versus dataset-wide origin:** All preserve the successful Windows, Mac and network results, but differ over whether the console concern outweighs them enough for a Synthetic verdict.

## Improvement Recommendations (Consensus)

These recommendations summarize support across the actual responses; they are conditional on the data being synthetic and do not constitute proof of origin.

1. **Correct console execution identity at its owner.** Represent ordinary agetty-to-login handoff as a same-OS-PID executable transition with the actual parent. If custom supervision or ancestry rewriting is intentional, make the representation and interpretation explicit rather than presenting a reusable getty object as ordinary direct-parent truth. All four support this priority.
2. **Derive console closes from actual lifecycle and observation decisions.** For normally completed sessions, coordinate normalized logout/process termination with native PAM/logind cleanup. Represent abrupt termination and collection filtering distinctly, applying coherent rules across account classes. All four support reviewing this relationship; the Host/EDR response specifically cautions against adding closes merely to fill an apparent gap.
3. **Tie background texture to service and administrator state.** Review irqbalance output against device/configuration state and repetition behavior; derive privileged diagnostics from host roles, administrator sessions and any intended shared maintenance period. All four recognize these as bounded review targets. Do not add random vocabulary or spread commands uniformly simply to conceal repetition.
4. **Preserve the relationships already supported by the reviews.** Retain source-specific process/credential identities, macOS execution transitions, SSH ordering, multipart/transport accounting, proxy legs, certificate ownership and protocol visibility boundaries while addressing the localized console family. All four retain these positive findings; none supports indiscriminate source or traffic inflation.

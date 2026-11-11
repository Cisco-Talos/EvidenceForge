# Deliberation Summary

## Basis and panel composition

This is a facilitator synthesis of the four submitted reports, not a fifth authenticity assessment. Only the expert-deliberation instructions and those reports were consulted. No new raw-record inspection, expert responses, revisions, or re-votes occurred. The original positions below remain the authoritative positions; there are no separately elicited final scores.

| Expert | Original verdict | Verdict confidence | Synthetic-confidence score | Revision status |
|---|---|---:|---:|---|
| Threat Hunter | Real | 58 | 20 | No revision elicited; original retained |
| Detection Engineer | Inconclusive | 80 | 28 | No revision elicited; original retained |
| Network Forensics | Inconclusive | 78 | 29 | No revision elicited; original retained |
| Host/EDR Forensics | Inconclusive | 75 | 20 | No revision elicited; original retained |

The original mean synthetic-confidence score is **24.25/100**, calculated as `(20 + 28 + 29 + 20) / 4`. This descriptive mean is neither a calibrated probability of synthetic origin nor an independently agreed consensus verdict. Three reports are Inconclusive; one slightly favors Real.

## Round 1 — Original findings

- **Threat Hunter:** Two exact four-component SSH tuples between MAC-MROSS-01 and MAC-MROSS-02 join endpoint FLOW/LOGIN observations to Zeek transport, with transport preceding authentication by approximately 6.960 and 9.027 seconds. The 2,447 visibly paired eCAR terminations do not precede their matching object creates. The distinctive caveat is repeated sysstat vocabulary: 360 direct `debian-sa1 1 1` invocations, exactly 36 per Linux host, with roughly ten-minute spacing. The reviewer expressly accepts ordinary fleet scheduling as an adequate explanation and gives this negligible weight.
- **Detection Engineer:** The Windows taskhostw PID 7208 pivot preserves parent PID 5904, SYSTEM identity, and logon ID across Sysmon/eCAR. The DNS UID `ClnAf4xMznbwm13HlN` preserves tuple, timing, and packet accounting. Unique ingestion details include consistent Windows versioned field families, stable populated executable hashes, and the macOS distinction between pre-exec actor and post-exec target. No qualifying contradiction is asserted.
- **Network Forensics:** CONNECT UID `CCNiAm1f7JPR2ix29e` preserves control-plus-tunnel byte accounting; TLS UID `CG295AL9K2PwDjLsPO` preserves transport/handshake order and visible certificate-chain identity. State-dependent omissions, an unanswered SYN, and an answerless NXDOMAIN are plausible. The proxy attribution has a narrower key than the Zeek pivot because the native proxy line lacks UID and source port. Packet contents and certificate signatures were not validated.
- **Host/EDR Forensics:** The Windows process pivot extends to Security 4688 record 948728 and matches the Sysmon/eCAR process identities. The Windows DNS tuple/process attribution is coherent across Security, Sysmon, and eCAR. The macOS PID 41136 fork/exec transition preserves process lifetime while advancing pidversion 12 to 13; normalized eCAR uses one object and MODIFY for exec. Linux SSH public-key acceptance and PAM open/close share sshd PID 2696510 and user aisha.johnson. The review leaves native macOS release/exporter semantics unverified.

## Round 2 — Cross-examination and evidence limits

### Real versus Inconclusive

The disagreement is principally about the inference from plausible records to authenticity, not conflicting observations. The Threat Hunter slightly favors Real while explicitly recognizing that nineteen inspected records and targeted aggregates cannot exclude sophisticated synthetic generation. The other three withhold a provenance verdict for the same general reason. The Host/EDR reviewer and Threat Hunter both score synthetic confidence 20 while assigning different verdicts, directly illustrating that the verdict labels and numerical scores need not encode identical decision thresholds.

Successful identity joins, plausible timing, and native field structure support production-like appearance and hunt feasibility. They do not authenticate where the collection originated. Conversely, unknown provenance and bounded inspection are not affirmative evidence of synthetic origin. The reports provide no basis to convert the three Inconclusive verdicts to Real or to raise their scores for uncertainty alone.

### Alternative explanations and apparent friction

- **Scheduler repetition:** The fixed ten-minute sysstat workload is the sole explicitly labeled weak signal. A homogeneous system scheduler is a specific ordinary explanation. The reports do not show that this schedule was assigned to human activity or otherwise violated its task semantics. No timing repair follows.
- **SSH timestamp differences:** The host report's normalized Linux LOGIN is about 443 ms before syslog public-key acceptance. It treats different observation semantics as insufficient for an impossible-ordering finding. The Threat Hunter's separate macOS tuples have network transport before endpoint authentication. These are different sessions and source comparisons; they do not contradict each other. A broader causal conclusion would require the exact observation contracts and identities.
- **macOS semantics:** The host and detection reports independently describe actor/target separation and pidversion changes as plausible. Both reserve judgment on the exact version/export contract. That reserved judgment cannot become a schema defect without verification. A policy message or sparse Unified Log export cannot establish denial or missing lifecycle evidence by itself.
- **Cross-source consistency:** Some reviewers inspected the same Windows process and macOS fork/exec examples. Their agreement strengthens interpretation of those examples but does not multiply the amount of independently sampled activity. Aggregate passes also test only their stated predicates; they do not establish every lifecycle or protocol contract.

## Round 3 — Position status

No expert was asked to revise after reading the other reports. All original verdicts, confidence values, and scores are preserved. The synthesis identifies shared evidence and differing inference thresholds without attributing a changed mind, new agreement, or re-vote to any expert.

## Most convincing reported evidence

Ranked here by specificity and cross-source diagnostic value, not as a new expert vote:

1. Exact Windows process ownership across Sysmon, Security, and eCAR: matching PID, parent, image, principal, logon, and compatible observation times.
2. Exact SSH transport tuples with transport-before-authentication ordering in the two independently selected macOS sessions.
3. CONNECT control/tunnel byte sums and TLS transport/handshake/certificate identity compatibility, with the native proxy match's narrower identity scope retained.
4. The macOS fork/exec actor-target distinction and persistent normalized process object across an image transition.
5. Source-native state-dependent behavior in the inspected unanswered SYN and NXDOMAIN, supported by bounded population checks.

All support plausible construction. None independently establishes real provenance. No report establishes a hard contradiction, contract gap, or schema/format defect.

## Recommendations and supported next target

**No concrete data or generation correction is justified by these four reports.** Each explicitly declines defect-specific repair. Preserve the demonstrated ownership, transport ordering, stable binary identity, source-specific timestamps, and network accounting.

The clearest supported next bounded target is **exact SSH close relationships** for already identified sessions: follow the same tuple/session identity through available endpoint, native SSH, and transport termination observations, then assess timing against their source semantics. The Threat Hunter expressly leaves closure unverified. This is a validation target, not an allegation that closure is missing. A defect should be asserted only if the inspected identities and applicable contracts establish an incompatibility.

Other explicit follow-up limits are the visible support-upload result and the exact macOS exporter/release contract before policy or launch-lifecycle judgments. Do not claim a successful transfer from command syntax, impose unavailable collection products, penalize window-boundary endpoints, demand complete DNS coverage, or treat an easily narrated sequence or lack of retries as authenticity evidence. The reports justify further bounded inspection, not additional noise, forced incompleteness, or a longer intrusion narrative.

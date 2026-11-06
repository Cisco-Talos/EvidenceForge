# Loop25 — Mac installed-file precision

# Loop25 canonical installed-file clock precision

Classification: family_level. Owner: MacosInstalledProvisioning, not ES serialization. Model package-preserved build timestamps separately from host-local install/change/access times; local timestamps should use filesystem nanosecond precision rather than tiny tails after whole seconds. Keep original content/build identity shared across hosts, installation metadata host-scoped, stable object IDs, release availability and modified<=born<=accessed chronology. Entry paths: scenario/deployment registry compilation, native installed ES preparation, checkpoint rebuild; consumers: every ES stat projection and canonical filesystem observations. YAML probability controls whole-second package time preservation, with schema validation. Verify two hosts and multiple executables plus reconstruction tests.

Recovery checks exposed the pre-existing stale _macos_audit_pid_allocations declaration, absent from StateManager. Reconcile checkpoint inventory/capture/restore with actual runtime ownership; retain schema readers and native PID-version semantics. This repairs an earlier incomplete assessment change required for installed-metadata reconstruction tests.

## Verification

Revision421.83focused tests, config validation0errors, Ruff/format pass. Eval96.341564PASS;133351records;120identicalfiles. Of260stat timestamps,181nonzero and none in artificial1–999ns band. Whole-second package values retained. Stale checkpoint owner declaration reconciled with runtime.

## Individual Expert Summaries

**Threat Hunter:** Inconclusive; verdict confidence 79; synthetic-confidence score 47. The sampled intrusion and administrative activity supports practical hunting across endpoint, authentication, network, and file evidence, with generally coherent process and session lifecycles. One reproducible Linux session-identity discrepancy and a weaker Windows authentication-to-transport pivot gap raise authenticity concerns, but this bounded review did not establish a source-native impossibility or a broad generator fingerprint.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 28. The inspected records are mostly production-like and would support ordinary SIEM parsing and correlation. I found no demonstrated impossible ordering or source-native contradiction in the bounded checks; the principal reservation is a small, repetitive macOS command vocabulary, which is also compatible with administrative or diagnostic activity and cannot establish provenance.

**Network Forensics:** Inconclusive; verdict confidence 80; synthetic-confidence score 44. The visible network evidence is substantially production-like: protocol records have coherent parent flows, TLS authentication types agree with referenced certificate keys, and the explicit proxy path explains much of the HTTP traffic. A pervasive connection-history texture warrants scrutiny: every observed content-gap marker appears at the end of its history, usually after connection termination markers, with many very small gaps. This is a distribution concern rather than a demonstrated impossible network event; capture and reassembly behavior could explain it.

**Host Forensics:** Inconclusive; verdict confidence 80; synthetic-confidence score 25. The sampled endpoint evidence is largely production-like, with coherent process identities, plausible process lifetimes, stable binary hashes, and sensible Windows and Linux session relationships. I did not substantiate an impossible visible lifecycle or a source-native contradiction in the bounded checks; a small amount of repetitive command texture is insufficient to distinguish a carefully constructed dataset from collected operational activity.

## Deliberation Findings

No trigger: allInconclusive;confidence mean79.25;spread22. Scores47/28/44/25 mean36.0. Small movement versus35.25 is reviewer variance; direct metadata probes show repair.

## Prioritized Improvements

P1 contract_gap: Threat verified syslog378852 vs eCAR378837 for root SCP receiver10.10.4.10:45342, PID2983988. Fix canonical temporal allocator and source identity preservation; repeated SSH/SCP family, high leverage, moderate risk. P1 shared packet accounting: loop26 directly clears85clean TCP word-alignment failures. P2 role placement: verify root desktop tracker eligibility on servers; shared catalog/world capabilities, medium leverage. P3 network content-gap suffix texture remains unproven because teardown reporting is plausible. P4 sw_vers repetition is low leverage; explicit scenario timings are preserved.

## Quantitative Comparison and Priority Rationale

Eval/counts matchloop24; no hard acceptance regression. New session-ID disagreement and native timestamp texture are not covered by existing deterministic checks. Prioritize canonical contradictions over qualified source texture. No scenario edits or commits.

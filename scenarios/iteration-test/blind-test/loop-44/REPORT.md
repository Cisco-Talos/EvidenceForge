# Mac-series loop44: ASA security-side projection

**Completed fresh validation → generation → authoritative evaluation → four fresh
blind reviewers → triggered facilitator-modeled deliberation.** This is the first
of the requested twenty continuation loops44–63. The accumulated work was committed
and pushed as `e30c1875` before this loop started. The authored canonical benchmark,
seed42, observation/coverage controls and baseline-warning policy remain fixed.

Automated evaluation **96.3094**, all hard criteria PASS. Initial average
**synthetic-confidence score57.25** (mixed/inconclusive; lower is more production-like).
Threat54 / Detection28 / Network83 / Host64, versus32/54/68/62 (mean54.00) in43.
The rolling-five average is54.25. The3.25 increase is dominated by different reviewer
coverage of unchanged stream-accounting and upload-timing defects, not objective
regression in the selected ASA repair. Only the ASA data file changed; all116 other
data files match43 byte-for-byte. Standalone scores are not a controlled causal
estimate of the fix or a model-capability comparison.

## Selected family and root ownership

[Family contract](family-contract.md) defines invariants, entry paths, consumers,
classification and residual risks. The topology layer supplies native interfaces;
the network observation planner freezes teardown reasons using a shared ASA
security-side helper. The emitter owns native foreign/local endpoint ordering and
keeps each real/mapped NAT pair intact. The compatibility path uses the same helper.
The parser adapts to native endpoint roles and infers transport orig/resp for a
teardown only from a matching build's hostname, ID, protocol and endpoint tuple.

Classification: `family_level` for shared security semantics/observation ownership;
`source_native_single_schema` for ASA ordering, which is native serialization;
`adapter_to_family_model` for compatibility and parser consumers. No hostname,
user, timestamp or sample-specific generation branch was added. Packet accounting,
transport identity/close timing, raw escape hatches, NAT translation and Deny roles
retain their existing owners. Source definitions and qualification are in
[source semantics](source-semantics.md).

## Verification

| Check | Before43 | Fresh44 |
|---|---:|---:|
| Qualified native interface-order errors |4,501 cross-interface outbound TCP plus7 UDP;27 same-interface unqualified|0 across8,519 builds;27 equal-security unqualified|
| Qualified reset-side mismatches |60 verified DMZ/external pairs|0 of179 qualified reset comparisons across directions|
| Changed data files |—|1 ASA;116 unchanged|
| Complete native Mac forks/execs/expected exits |89/89;107/107;87/87|89/89;107/107;87/87|
| Aggregate Mac births |0|0|
| Mounted helper native exits |4/4|4/4|
| Repeated same-fraction shell-fork groups |0|0|
| Six inventory lifetimes |six distinct0.309048–0.624703s|identical to43|

The reset denominators use different scopes; they are not a matched A/B population.
The current probe requires qualified conventional relative interface levels, an
exact real tuple and unanimous state across matching sensor rows. Equal-security,
unknown and ambiguous cases do not manufacture an I/O reset label. Midstream
checksum gaps alone no longer claim a reset. Focused tests cover inbound/outbound
TCP/UDP, source PAT/destination NAT, configured custom interfaces, reset variants,
non-reset OTH, unmatched closes, exact publication/recovery and source timing.

**198 focused tests pass**, plus the explicitly selected slow teardown-timing
contract. Ruff check/format and behavior-surface validation pass at revision443,
digest`5520bbe3dcee12936783ad231c13033473b54bf2647880bdfac72e9c5b33725c`.
No additional full routine suite was run for this loop; the pre-push routine run
and reconciliation are documented in the worklog. This loop is not committed yet.

The fresh authoritative bundle is
`/private/tmp/eforge-iteration-test-loop44-qbgiwj95/bundle`, with136,813 records in117
data files. Pillars remain Parseability100, Plausibility96.7836, Causality95.7488,
Timing90.8812. Flags are empty. The unchanged score exceeds the dynamic guardrail;
no acceptance or parse failure is hidden. Readable eval is rendered from the single
saved JSON eval. The low-baseline warning remains intentionally deferred as P1.

Probes: [ASA](asa-native-probe.json), [change scope](data-change-scope.json),
[Mac timing](mac-timing-probe.json), [native census](native-coverage-probe.json),
[mounted exits](mounted-helper-exit-probe.json), [Windows runtimes](windows-runtime-probe.json)
and [carried residual contracts](residual-contract-probes.json).

## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 54. The records support practical hunts across Windows, Linux, macOS, network sensors and an explicit web proxy, with substantial baseline traffic and generally coherent visible process lifecycles. A multipart upload has two notable timing problems: its curl process exits before the observed response and upload completion, and the proxy's outbound file finishes before the corresponding inbound file on the same sensor. Those findings make the data appear mixed, but they are concentrated in one transaction and do not justify calling the entire collection confidently synthetic.

**Detection Engineer:** Real; verdict confidence 62; synthetic-confidence score 28. The supplied telemetry is production-like from a detection-engineering perspective: the parsed Windows, endpoint, and network evidence preserves the identities and source-specific relationships needed for practical SIEM correlation. I did not establish a hard contradiction, malformed selected event family, or required-companion failure; the principal reservation is a small and repetitive macOS command vocabulary, which is weak evidence because the same user operates both endpoints. “Real” is a modest-confidence likelihood judgment, not a claim that coherent logs establish provenance.

**Network Forensics:** Synthetic; verdict confidence 91; synthetic-confidence score 83. The network data is broadly convincing at the protocol, topology, and activity levels, but repeated cross-sensor TCP accounting contradicts the source-native meaning of Zeek's payload-byte fields. Completed flows retain their handshake and both FINs while their reported sequence-space payload totals are reduced by exactly the sensor's `missed_bytes`; this occurs across HTTP, TLS, SSH, MySQL, and other services, making synthetic capture-loss modeling the strongest explanation.

**Host Forensics:** Synthetic; verdict confidence 74; synthetic-confidence score 64. The endpoint evidence is substantially coherent, including Windows process identities, Linux SSH sessions, and macOS fork/exec relationships. My synthetic verdict rests mainly on an estate-wide process-duration boundary in the Windows telemetry, with a secondary concern about the repeated console-host parent model; I did not establish an impossible same-identity lifetime or a generator identity leak. These are moderate-strength distribution and environmental findings, not grounds for the highest synthetic-confidence band.


## Deliberation and score interpretation

The initial verdict split (one Real, one Inconclusive, two Synthetic) and55-point
score spread triggered a fresh facilitator. Its modeled positions72/58/83/76 average
72.25. These are **not reconvened votes** and are excluded from initial/rolling
trends. Detection retains an Inconclusive modeled position. The full
[deliberation](deliberation.md) preserves custom-export, lifetime-filter and
interface-timing alternatives and does not count specialist findings as four
independent confirmations.

All four reviewers find strong usable identities and source relationships. Network's
83 comes from the unchanged TCP stream/capture defect across protocols. Threat's54
comes from a newly examined unchanged multipart transaction. Host's64 comes mainly
from the broad Windows runtime boundary. Detection's28 reflects extensive passing
schema/identity checks but does not independently test the other specialists'
critical invariants. These are coverage differences, not conflicting facts about
whether the ASA output was repaired. No reviewer independently reports a new native
Mac schema or impossible Mac lifecycle defect.

## Prioritized reported issues

Priorities/classifications are coordinator synthesis; reviewers assigned categories,
not P0–P4 labels. Their original severity is therefore shown as not labeled.
Coordinator-only carried probes are distinguished from fresh independent findings.

| Priority | Issue | Category / classification | Original reviewer rating | Score leverage | Ownership, scope, risk and next action |
|---|---|---|---|---|---|
| P0 | TCP stream extent versus capture bytes | hard_contradiction / sibling_defect | Network44: not labeled; carried Network41 | High | Source-observation accounting conflates captured payload with sequence-derived stream totals. Network independently reproduces412 core–DMZ,10 core–DB and47 DMZ–DB conservative affected pairs (overlapping populations); the broader coordinator scope finds514+56 comparisons. High architectural risk: separate stream extent from physical packet/capture and file/application ledgers. First target for loop45. |
| P1 | Multipart relay and client completion | contract_gap / sibling_defect | Threat44: not labeled | Medium–high | One named gzip upload completes upstream0.890498s before ingress on the same sensor; its curl exits4.302877s before the observed response start. These are related facets of one transaction, not two broad independent defects. Action bundle and source timing own shared byte availability, response completion and client lifetime. Buffering, termination cause, content identity and interface-clock alternatives remain qualified. Medium–high fix risk; verify and repair after the broad stream contract. |
| P1 | Windows and Linux command runtime support | distribution_texture / sibling_defect | Host44 / Host43: not labeled | Medium–high | Fresh native Windows probe confirms733 joined lifetimes, minimum3.004s, none below3s and26 in[3,3.25). Prior Linux small-stage bounds remain in unchanged files. Execution lifecycle and data-driven runtime profiles own family-specific durations plus dependency protection. Medium risk; do not add arbitrary source timestamp jitter or invent a collection filter. |
| P1 | URL fragments in HTTP request targets | hard_contradiction / sibling_defect | Detection42: not labeled; coordinator43–44 | High locally | Thirteen fresh proxy requests retain literal client-side fragments. Canonical HTTP/proxy construction owns request-target normalization; preserve encoded%23, query strings, navigation intent and CONNECT authority form. Medium risk; next bounded repair after stream accounting. |
| P2 | Console-host parent concentration | environment_or_collection_plausibility / false_positive_or_unproven | Host44: not labeled | Medium, qualified |105/106 conhost creates use csrss across four Windows versions. This is a population concern, not proof every parent is impossible. World/process planning owns version-, session- and token-aware console bootstrap. High risk until native reference evidence qualifies supported variants; validate before rewriting. |
| P2 | Storage roles/vocabulary and Mac allocation blocks | environment_or_collection_plausibility / false_positive_or_unproven | Host43 / Threat43 / Detection43: not labeled | Medium–low, qualified | These carried leads remain in byte-identical non-ASA files; the current panel does not independently demonstrate them as defects. Custom organization automation and native allocation semantics remain plausible. Inspect world/storage and native identity owners before changing either; avoid emitter concealment. |
| P4 | Repeated Mac command vocabulary | weak_signal / false_positive_or_unproven | Detection44: not labeled | Low | The same user repeats id/sw_vers/find/ps across two Macs. Repeated diagnostics and automation explain this. Retain justified repetition; task-specific long-tail expansion may help only when supported by behavior intent. No schema or lifecycle defect is established. |


## Recommendations and next loop

Target the shared stream-extent/capture distinction in loop45, with canonical
observation truth consumed by native renderers. Preserve physical packet/header
partitions and source-local application/file loss. Inventory persistent-channel
rebinding and checkpoint serialization before changing the model; an emitter-only
counter rewrite would leave the owning contract unresolved. Then normalize HTTP
request targets, coordinate proxy multipart byte availability/client completion,
and revise runtime-family duration support without weakening causality.

Keep the fixed scenario and complete Mac coverage. Do not replace an unexplained
runtime floor with undocumented filtering, change console parents without native
qualification, or randomize one user's legitimate repeated diagnostics. The current
ASA family is verified; score variance alone does not justify undoing it.

## Past ten Mac-series loops

Loop43 marks the authored timing/promotion boundary. Earlier canonical v2-loop results
belong to another series and are excluded.

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 35 | 96.71 | 48 | 77 | 42 | 43 | 52.50 | mixed/inconclusive | 66.25 | 57.95 |
| 36 | 96.09 | 57 | 18 | 62 | 65 | 50.50 | mixed/inconclusive | 64.50 | 55.90 |
| 37 | 96.09 | 43 | 32 | 34 | 68 | 44.25 | mixed/inconclusive | 56.25 | 51.20 |
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.


## Artifacts and audit

[Scores](scores.json), [raw quantitative eval](automated-eval.json),
[readable eval](automated-eval.txt), [provenance](provenance.json),
[generation metadata](generation-summary.json) and [artifact audit](artifact-audit.json)
retain the result. Raw reviewer reports are preserved verbatim. The audit verifies
score fields/means, triggered modeled deliberation, all117 data hashes across the
authoritative/loop/neutral copies, unchanged authored inputs and complete native
coverage. [Worklog](../../../../docs/worklog/2026-11-05-iteration-test-loops44-63.md)
records the push and continuation. The final twenty-loop dashboard will be rendered
after63, not after intermediate loops.

### Reviewer input audit

A retrospective [input audit](review-isolation-audit.json) records all four reviewers'
self-reported actual reads: neutral instructions/data plus, where applicable, their
own new report for format checks. None reports reading project files, TODO, scenarios
or prior results. Generic project/AGENTS instructions were inherited by the harness;
that is a limitation on strict origin blinding. They were not log-visible evidence
or supplied prior findings. This is an input-scope audit, not OS-enforced isolation;
initial scores remain unchanged.

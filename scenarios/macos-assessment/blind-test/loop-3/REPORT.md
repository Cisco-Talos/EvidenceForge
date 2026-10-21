# Mixed-fleet macOS assessment, loop 3

The planned benchmark, supported-source baseline, bounded native-fork integration,
assessment-driven repair and post-fix assessment sequence is complete. Revision
330 (`23e7e13e`) passes deterministic acceptance at **89.2567**, with **10,870
records**, 100% parseability and causality. Both targeted probes have
zero failures. This is bounded engineering acceptance, **not an authenticity
pass**: the fresh blind mean is **66.75**, and new broader quality findings remain.
Native exec/exit and Gatekeeper denial stay gated by the user's explicit decision.

## Reproducibility and review isolation

The official bundle is
`/private/tmp/eforge-macos-assessment-20261021-loop3-330`, generated after the
implementation commit and push, with hourly checkpoints. Its 24 data files total
5,626,515 bytes and match the final verification bundle byte for byte. The frozen
`02-native` scenario was not edited. Input, implementation, manifest and every
data-file hash are retained in `provenance.json`.

Four new reviewers received only a neutral copy of `data/`, the complete current
assessment briefing and their own complete persona. They received no scenario,
ground truth, evaluator output, implementation, prior reports, web access or parent
context. The submitted reports are unchanged; their hashes and isolation record
are in `review_provenance.json`.

| Reviewer | Verdict | Verdict confidence | Synthetic-confidence score | Format / timing / correlation / behavior / environment |
| --- | --- | ---: | ---: | --- |
| Threat Hunter | Synthetic | 80 | 64 | 8 / 5 / 7 / 7 / 7 |
| Detection Engineer | Synthetic | 82 | 67 | 7 / 6 / 9 / 7 / 8 |
| Network Forensics | Synthetic | 86 | 68 | 7 / 9 / 9 / 8 / 8 |
| Host/EDR | Synthetic | 82 | 68 | 8 / 5 / 9 / 6 / 8 |

Mean synthetic-confidence is **66.75** (likely synthetic; lower is better), versus
66.5 in loop 2 and 83 in loop 1. Mean verdict confidence is 82.5; the synthetic
score spread is four. Unanimity, confidence above 60 and spread below 30 mean no
deliberation trigger fires. No revised or deliberated scores are invented.

The 0.25-point increase from loop 2 is effectively flat. The selected defects
cleared, but the new panel assigned weight to previously unreported network
semantics and Windows timing. Standalone panels cannot establish the causal
effect of each fix, and this result does not support claiming another realism
score improvement. The three-loop mean is 72.0833.

## Completed repair contracts

| Family / owning layer | Fresh evidence and preserved invariant |
| --- | --- |
| Mac visible birth and dependent ordering / source timing | Original lifecycle probe remains at zero failures; parent and execution identities stay canonical. |
| Mac GUI population / catalog and session owner | Maximum concurrent main instance is one for each selected singleton application/session, including Terminal reused by shell bootstrap. |
| History / shared session source timing | All ten represented Mac commands match their execution times; both history files remain monotonic. Source delivery does not rewrite embedded command time. |
| Linux journal / engine machine identity and file-effect templates | One represented journal directory carries the complete canonical machine ID; no independent temporary-hex identity is invented. |
| Mac executable effects / process preflight and explicit artifact owners | Zero self-image creates. The authored curl manifest download still has its actual FILE/CREATE. |
| Browser identity / loaded executable content | Request identity consumes the loaded release rather than resolving a replacement path; CLI runtime owners require explicit transport intent. |
| SMB credential use / committed transport interval | Auth, close and caller retention consume the resolved connection interval. Existing mixed-platform and recovery gates pass. |
| HTTP transport floor / physical transport owner | OCSP duration range grows from 0.014675 to 0.974040 seconds; reused application requests retain the admitted parent interval. |
| Local red-herring placement / WorldModel | Actor and host are selected together from the actor's activity systems. Mac users are not moved to unrelated Windows hosts. |
| Runtime-backed Mac catalog / deployment and process owners | Five additional bounded module/runtime variants; all 67 original IDs audited, 48 prefilled. Missing evidence stays unavailable. |

`family_probe.json` retains the original guard, including three complete native
fork/v10 rows. `review_family_probe.json` has **zero findings, down from 18** in
the loop-2 bundle. These probes cover named contracts; they do not establish that
all possible source-native contradictions are absent.

## Reported issues and remaining quality backlog

Priorities below are synthesis priorities. None of the four reviewers assigned
P0–P4 labels, so their original ratings are recorded as **not labeled**. These
are new or residual quality items, separate from the completed bounded Mac
implementation sequence and from the user-deferred native reference gates.

| Priority | Issue / category | Original reviewer rating | Score impact and evidence | Family classification / owner / next verification |
| --- | --- | --- | --- | --- |
| P0 | Gap-marked TCP packet/history inconsistency / hard_contradiction | not labeled | High: Network reports 16 affected rows. A conservative independent check confirms two even without FIN/reset assumptions: `ShADadrGg` with two originator packets and `DdAG` with one. | sibling_defect; shared network observation loss owner. Model observed packet classes and counters together; HTTP, TLS, SMB and partial/closed flows are sibling consumers. |
| P1 | Windows process birth pileup / distribution_texture | not labeled | High: all three endpoint reviewers identify 14 creations across two adjacent Sysmon milliseconds, 13 in one, across eight images and five parents. Startup restoration remains a plausible alternative. | sibling_defect; canonical activity readiness and source timing. Reproduce the shared floor before changing scheduling or latency; preserve parent readiness and service bootstrap. |
| P1 | SMB share name in service-type field / schema_or_format | not labeled | Medium–high: Detection finds all 49 mappings use `Engineering` as `service`. The native field describes resource type; custom exporter transformation remains a qualification. | source_native_single_schema; canonical SMB mapping facts and native projection. Keep UNC share identity separate from optional protocol service type; cover SMB1/2 and disk/IPC. |
| P2 | Stratum-2 NTP reference ID / schema_or_format | not labeled | Medium: all 12 records pair stratum 2 with `.GOOG.`. Protocol and Zeek references support upstream-address/hash semantics above stratum 1. | source_native_single_schema; NTP server identity and protocol projection. Verify the declared exporter profile and IPv4/IPv6/primary-clock cases together. |
| P2 | Simple Mac utility lifetimes / distribution_texture | not labeled | Medium: Host reports recurring 13–42 second lifetimes, including local identity/version/SDK queries. Share and directory-service delays explain some individual cases. | new_family; command/activity lifetime policy. Separate local query work from network, cold-runtime and interactive work; retain actual close ownership and observation delays. |
| P2 | Browser-like Windows HTTP owned by svchost / environment_or_collection_plausibility | not labeled | Medium, qualified: all ten Windows Chrome-style HTTP requests map to one NETWORK SERVICE process. Service mediation or a configurable UA could be legitimate. | sibling_defect lead; shared request intent and socket owner. Trace the request family before inferring browser ownership from its UA. |
| P3 | Windows Type 3 tuples lack supplied transport / contract_gap | not labeled | Medium–low, qualified: Hunter finds 17/17 without exact supplied FLOW/connection pivots despite some inbound visibility. Filtering or pre-window persistent transports remain alternatives. | false_positive_or_unproven; auth bundle and collection visibility. Establish the collection/transport contract before adding companion evidence. |
| P3 | Repeated Mac group/session 1 / environment_or_collection_plausibility | not labeled | Low: Hunter finds 43/68 CREATE rows with those explicit values. launchd inheritance and normalized semantics prevent treating this as a native impossibility. | false_positive_or_unproven; spawning/session owner. Verify each activity's actual inherited membership; do not replace legitimate launchd values for appearance. |
| P4 | Module names and retry fractional phases / weak_signal | not labeled | Low: Host notes DBeaver/Postman DLL vocabulary and a five-attempt fixed-phase retry burst. Package evidence and an actual retry mechanism are not supplied. | false_positive_or_unproven; catalog/package identity and retry timing. Acquire qualifying public package references before changing native module facts; automated retries may legitimately retain a phase. |

The two packet/history contradictions are retained in
`network_history_verification.json`. The loss routine
`NetworkObservationPlanner._lose_direction` subtracts observed packet counts
independently of retained packet-history classes. Its exact method is unchanged
from branch base `5ce84103`: this is a pre-existing shared network issue exposed
by the benchmark, not a regression introduced by the Mac catalog/terminal fixes.
It needs a packet-aware observation contract rather than a renderer-local count
padding patch. The reported 16-row extension includes FIN/reset interpretation;
only the two conservative cases are independently asserted here.

Primary checks performed after the blind reports: [Zeek history semantics](https://docs.zeek.org/en/v6.1.1/scripts/base/protocols/conn/main.zeek.html) distinguish
pure ACK and data observations; [SMB TreeInfo](https://docs.zeek.org/en/lts/scripts/base/protocols/smb/main.zeek.html) defines
service as resource type; [Zeek NTP](https://docs.zeek.org/en/lts/scripts/base/protocols/ntp/main.zeek.html) and
[RFC 5905 §7.3](https://www.rfc-editor.org/rfc/rfc5905.html#section-7.3) define
stratum-dependent reference identity. These checks were not supplied to reviewers
and do not modify their scores.

Earlier loop-2 TLS companion/closure partitioning remains an investigation lead;
it was not independently promoted to a hard finding in loop 3. Valid padded IPv6
spelling remains unproven without a declared exporter version. Neither is repaired
by introducing arbitrary incompleteness or changing valid address text.

## Validation and completion boundary

Both human and JSON evaluation exit 0. Console padding/trailing whitespace is
trimmed in the retained text output; JSON and all reviewer reports are unchanged. Parseability and causality are 100;
plausibility is 89.5470 and timing 59.3496. The sub-90 aggregate and approximately
0.51-point movement from loop 2 were investigated: distribution fit, anomaly-rate,
system-regularity and small-window volume diagnostics explain the score. No
deterministic acceptance criterion fails; the evaluator was not tuned to raise it.
The newly verified packet/history contradictions show a gap in those checks.

The final source passes all **40 relevant extended tests**, covering native fork
CLI/exact recovery, fresh-process mixed-fleet determinism, filtering, SSH, root
persistence and SMB. The complete routine run finished with **16,192 passed, 50
skipped, 2,301 deselected and two stale fixture failures**. Both fixture contracts
were repaired and **92 affected tests pass**; production source was unchanged.
This is full-run plus focused-repair evidence, not a successful original full-suite
exit. Ruff check/format and all 99 configuration validations pass.

This closes the agreed finite implementation/assessment sequence with its evidence
and limitations recorded. Broad analyst-indistinguishability is not achieved; the
next quality effort should start with shared capture accounting and the repeated
Windows birth floor, followed by the native SMB/NTP field contracts and bounded
Mac query lifetimes. Native ES exec/exit (ES-R1) and Gatekeeper denial (GK-R1)
remain deferred, with no capture approval pending. No existing local logs,
personal inventories or host services were inspected or changed during this work.

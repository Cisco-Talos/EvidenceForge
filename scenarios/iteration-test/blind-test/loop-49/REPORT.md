# Mac-series loop49: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop6 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.4549**, 136,811 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat46 / Detection82 / Network56 / Host82**, mean **66.50** (likely synthetic); lower is more production-like. Prior mean49.00; current rolling5 **53.45**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **83.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root repair and rendered proof

[Contract](family-contract.md) names the physical source-observation packet partition as owner. A shared canonical history helper supplies directional minimum retained packets from Zeek's exclusive SYN/SYNACK, pure-ACK, data, FIN, RST and multi-flag categories. Capture selection reserves that budget before choosing a whole-packet loss partition; no feasible partition means no invented gap. Typed observations, persistent scalar/fast admission and checkpoint restoration reject impossible explicit counts. Classification `family_level` with persistent/codec adapters. No source-local counter inflation, history erasure, sample-specific UID rule, canonical wire change or scenario edit.

[Rendered proof](capture-history-repair-probe.json) covers15,032 TCP sensor observations:13 conservative three-category contradictions→0;312 broader exclusive-category lower-bound failures→0. Gap-marked observations remain1,113 (prior1,386), proving capture loss was not globally disabled. Small flows with no spare whole packet keep intact capture; larger flows retain real partial loss. Complete sequence extents remain independent of captured HTTP/file content; cross-sensor stream contradiction stayszero. Counts overlap across sensors.

245 owner/checkpoint tests,115 projection/protocol tests and95 selected slow network-timing tests pass (455 total). Ruff check/format and behavior validation pass at revision448, digest `06715290c671e3f5f6c399c1df9de5a55d72e9145b91cb2f11399a4de01b4dbe`. Several fixtures previously claimed complete TCP history with only1–3 packets; they now supply enough physical packets while preserving the original timing/NAT/restore assertions. A timing spy accepts the new history input. No full routine suite was repeated for this uncommitted loop; pre-push gate/reconciliation remains in the worklog.

Only8 network/firewall files change;109 files match48, including all endpoint, native Mac, task XML and X.509 records. Counts remain136,811 records/117files. All hard acceptance passes at96.4549. Native Mac89/89 forks,107/107 execs,87/87 expected exits,0 aggregate births; mounted exits4/4 and fraction/inventory timing unchanged. ASA qualified order/reset checks and HTTP fragment repair remain clean. ICMP state remains723 nonnative observations, and the Mac audit allocation probe retains4 fork reversals/53 below-high-water assignments. Those are explicitly unresolved.

## Fresh findings and score interpretation

Initial mean49.00→66.50 reflects new tests of unchanged families: Detection82 finds invalid embedded Task Scheduler XML, Host82 repeats the unchanged native Mac counter, Network56 finds a public-certificate policy cohort, and Threat46 identifies two exact-tuple browser identity mismatches. Neither the hard Windows/Mac findings nor public certificate lifetimes were introduced by this capture repair: their source files are byte-identical. The panel does not independently certify the full packet-minimum repair; coordinator probes provide that proof. Standalone score movement is not a controlled causal effect estimate and does not justify undoing the verified family improvement.

## Prioritized findings

Coordinator priorities/classifications. Original reviewer P0–P4 ratings were not provided; their categories and caveats remain in raw reports.

| Priority | Finding / classification | Reporter / original rating | Scope / leverage | Owner, risk and action |
|---|---|---|---|---|
| P0 | Native Mac audit counter chronology / sibling_defect | Host49 independently repeats46/47, not labeled |Four new-fork reversals on Mac02; high |Canonical/native chronological identity owner. Planning-order reservations cannot represent kernel allocation order. High architecture risk across immutable/proof/parent/responsible/exit/eCAR references; remains explicitly deferred. No emitter-local renumbering or timestamp edits. |
| P0 | Invalid successful Task Scheduler definition / new_family | Detection49, not labeled |One4698 embedsLogonType ServiceAccount; high locally |Shared task-definition builder/native schema. COM SERVICE_ACCOUNT enum is not an allowed XML logonType string. SYSTEM principal is legitimate; render its supported registration/XML semantics. Low–medium risk; verify domain/local/service-account siblings. |
| P0 | Native ICMP conn fields / sibling_defect | Network47/48 carried, not labeled; fresh coordinator49 |723 observations; high |Source-native projection overrides already-correct canonicalOTH withSF/S0 and invents data history.50 repair prepared from pinned upstream branches. Low–medium risk, preserve echo counters/tuples and UDP/TCP histories. |
| P1 | Public certificate validity policy / new_family | Network49, not labeled |71 distinct external leaves/263 DMZ rows,71 of189 external leaves; medium–high |Canonical certificate issuance/rotation and policy catalog. Post2026-03-15 public issuance maximum200days; observed395/377/387day examples. Actual issuance/public trust/date sanitization remain caveats. Medium risk; use modeled issuance date, preserve pre-policy certificates, private/enterprise and CA lifetimes, chain and OCSP coherence. Primary current policy verified by coordinator. |
| P1 | Browser family identity and profile ownership / sibling_defect | Threat49 new exact tuples; Detection46 root overlap; not labeled |Two activities/four sensor UA mismatches among1,658 matches; plus prior durable root pairs; high/medium |World/application/process/HTTP identity owner. Chrome NetworkService owns Safari and Edge UA tuples; explicit UA overrides are legitimate alternatives. Bind automatic UA and actual application once; preserve authored spoofing/separate profiles. Medium–high risk. |
| P1 | Security4672 membership and4738 delta / carried families | Detection46/48, not labeled |271/408 privileges; one2-bit delta/one token; medium–high/medium |Auth data/loader and account-state transition/native delta projection. Keep token grants, distinguish SAM/LDAP flags and derive textual/native masks consistently. Medium/low–medium risk. |
| P1 | Runtime support and multipart timing / sibling_defects | Prior specialists, not labeled |733 Windows pairs min3.004s; one upload timing case; medium–high |Workload lifecycle and action byte availability/client ownership. Verify actual source-observation dependency floors, file-analysis semantics and termination causes; no arbitrary jitter. Medium–high risk. |
| P1 | Plain connect-scan payload / new_family carried | Network48, not labeled |12 client-payload tuples among1,256 scan FLOWs; medium–high |Scan/network intent contract. Preserve server banners and explicit probing modes; no application bytes for plain connect-only intent. Medium risk. |
| P2 | Nikto test identity / carried new_family | Threat46, not labeled |315 IDs/316 requests,40 paths; medium |Scanner catalog/test/variant owner. Custom/spoofed activity remains possible; verify primary patterns before repair. Low–medium risk. |
| P3 | Linux shell socket attribution and role/parent leads / false_positive_or_unproven | Prior specialists, not labeled |Qualified leads; low–medium |Require socket-owner versus ancestor contract and native role evidence before changing process trees. |
| P4 | Repeated Mac diagnostics, slow id,1ms pairs,anacron onset / false_positive_or_unproven | Threat49 and prior specialists, not labeled |One88.128s id and weak population texture; low |Directory-service delay, user habits, scheduling and collection policy remain plausible. Do not invent timing noise or environmental causes merely to mask a tell. |

## Next action

Complete50's bounded native ICMP projection. Then target verified native Task XML/account-state semantics and public-leaf issuance policy, followed by shared browser identity/ownership and the remaining high-frequency families. Mac allocation remains the most severe architectural residual and must stay explicit even when a fresh reviewer misses it. Preserve the fixed benchmark, warning deferral and all repaired capture/stream/session/HTTP/ASA contracts.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 46. The data supports useful, technically coherent hunts across Windows, Linux, macOS, network sensors, and an explicit proxy. Two independently identifiable Chrome network processes nevertheless carry Safari or Edge identities on their exact network tuples; these are concrete correlation discrepancies, but user-agent overrides provide a real-world alternative explanation. I found no demonstrated impossible same-identity lifecycle ordering, so the evidence supports a mixed assessment rather than a confident synthetic verdict.

**Detection Engineer:** Synthetic; verdict confidence 88; synthetic-confidence score 82. The data is highly usable for detection engineering: the inspected source envelopes, identity relationships, and network joins are mostly convincing. The decisive contrary evidence is a successful Windows task-creation audit containing a principal logon type that is invalid in Task Scheduler XML; that specific native-content contradiction drives the synthetic verdict, rather than the completeness or narrative shape of the activity.

**Network Forensics:** Synthetic; verdict confidence 75; synthetic-confidence score 56. The network data is convincing at the connection, DNS, proxy and TLS visibility layers, with varied failures and substantial source-native consistency. I lean synthetic because a broad cohort of externally presented certificates combines post-March-2026 validity starts with lifetimes exceeding the applicable public TLS certificate limit; this is a material environmental inconsistency, although timestamp transformation or private trust arrangements could explain it. The score remains in the mixed band because I found no demonstrated impossible same-identity protocol ordering or broken UID/tuple relationship in the tested network records.

**Host Forensics:** Synthetic; verdict confidence 93; synthetic-confidence score 82. Most endpoint relationships are credible: Windows process identities correlate across sources, Linux SSH sessions have ordered authentication and session evidence, and macOS records distinguish forks from successive executable images. However, four reversals in newly allocated macOS process audit-token versions conflict with the native kernel allocation semantics; this concrete identity/timing contradiction drives the synthetic verdict, rather than the completeness or narrative of the activity.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

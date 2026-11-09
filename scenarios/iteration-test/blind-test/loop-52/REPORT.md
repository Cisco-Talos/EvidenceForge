# Mac-series loop52: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop9 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.7819**, 140,929 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat35 / Detection36 / Network32 / Host43**, mean **36.50** (mostly realistic); lower is more production-like. Prior mean46.25; current rolling5 **51.25**. Verdict confidence is separate.

Deliberation was not triggered by the recorded verdict/confidence/spread criteria.

## Canonical public certificate repair

The owner is TlsCertificatePlanner plus validated issuer trust and issuance-era configuration. All canonical certificate consumers use the same validity, fingerprint, serial and derived file material. Public issuer membership is explicit metadata, with private enterprise and self-issued/IP certificates excluded. The validated policy table uses recommended397/199/99/46-day lifetimes within mandatory398/200/100/47-day limits at1970/2026-03-15/2027-03-15/2029-03-15 boundaries. Era-anchored rotation buckets represent modeled issuance; a later observation does not mutate an existing resolved certificate. Intermediate/root lifetimes follow their separate authority rules. Historical pre-transition sampling retains the earlier epoch anchor.

70 focused runtime/config/crypto/retention checks pass, including the negative validate-config policy case and the selected slow clean-config gate. Config validation reports101 files clean; Ruff check/format pass. The generated candidate contains574 public-candidate leaf observations with maximum199days and none above200. That is configured issuer membership, not independent DER/trust validation. The baseline public lifetime mismatch has been removed at the canonical owner rather than at Zeek rendering.

## Wider dependency scope and hard guardrail

This run has140929 records and118 files, rather than136811/117. Only two data files remain identical to51. Authored inputs, seed42 and collection/observation settings are unchanged; the resolved-document comparison shows only new issuer trust metadata and the public policy catalog (plus derived config/document digests). Changed certificate identities feed existing fingerprint-keyed chain selection and OCSP decisions; those child activities can perturb subsequent shared planner/RNG state and identity allocation. This dependency surface is much wider than an X509-only edit; no localized score-causality claim is made.

Evaluation95.7819 passes parsing and native values but **fails hard pivot linkability149/191=78.0105, threshold80**. The original authoritative report remains unmodified and is labeled REVIEW. There was no retry/seed search, threshold relaxation or replacement with a better-scoring candidate. Investigation found at least one evaluator false missing trace: mac-2-inventory-run-2 has eCAR dropped5 but native ES visible4; the macos_launch_item trace matcher only accepts eCAR. Windows lock/unlock intended18:20/18:35 are instead visible18:40/18:42 despite ground-truth anchors18:20/18:35, an unresolved source timing/ground-truth reconciliation concern. The Mac terminal sequence also shifts to13:37 from the authored13:12. These concerns stay visible for subsequent root-owner repair; this run is not declared hard-accepted merely because its mean eval exceeds90.

The independent panel receives only neutral data, without this investigation or scores. The retained run is assessed to expose remaining problems rather than hidden or substituted. The audit permits a documented REVIEW artifact and records acceptance_passed=false truthfully; it does not alter any product evaluation policy.

## Scope-preservation probes and priorities

All common native/network probes ran successfully. Native Mac coverage remains complete:96/96forks114/114execs94/94knownexits, zeroaggregatebirths;11/11mounted helpers have native exits. Both Macs have zero repeated shell-fraction groups. Six inventory lifetimes are.267325,.341769,.458850,.688282,.637919,.634523seconds, inside the authored100–750ms control. The changed identities expose five adjacent Mac02 fork-version reversals and53newassignments below an earlier high water; Mac01 remains0. This is the existing canonical allocator family, still unresolved, with a different number of manifestations. Existing ASA order/reset, stream-versus-capture, TCP history minima, ICMP native OTH and HTTP fragment contracts remain verified.

P0native Mac allocation chronology remains high-impact/high-risk architectural work. P0/P1Windows lock source timing and Mac evaluator source-visibility matching are newly prioritized by the failed guard. P1canonical proxy serialized request budget is next bounded repair; a52probe finds264/1412inspectedrequests below line+UA,475includingReferer. P1TLSclient framing must be fixed in action/channel byte reservations as a separate family. P1SAM account mask/token projection,4672sensitive privileges, browser namespace/UA ownership, scan intent and runtimefloor remain open. Weak native-version/vocabulary claims remain qualified and do not justify random noise changes.

## Independent panel and scoring

TH35 / Detection36 / Network32 / Host43 mean36.50, versus51mean46.25. All four verdicts are Inconclusive, average verdict-confidence80.75 and score spread11, so no deliberation trigger. This lower score cannot be attributed solely to the certificate repair: the canonical output changes widely and the reviewers examined different invariants. None tested the already-proven host-wide native audit counter; their clean individual-lifecycle checks do not clear that P0.

Network's direct certificate checks no longer reported the public-lifetime issue; its retained concerns were narrowly qualified by collector semantics. Host independently re-reported Chrome's per-profile singleton violation candidate: two sustained leaders, same UID/asid/HOME, no visible separate user-data directory; effective policy remains unknown. Detection found five1ms exit-to-next-fork gaps, a distribution texture signal compatible with pasted commands; TH retained only weak repeated Mac command/document-cat vocabulary. Those weak observations stay below hard semantic families; no random errors or arbitrary source volume is added.

Accepted input provenance: all four read neutral data/briefings only and primary references for scored claims. Threat accidentally included a third-party manual domain in an initial search, did not use its snippets as authority and replaced it with Apple's direct upstream manual; no project/prior material was exposed. Host attempted uv from the inherited cwd but hit a cache-lock error before script execution, received no project content, switched to system python3 and disclosed the attempt. These are procedural deviations retained explicitly, not claims of OS-enforced origin blinding. Future prompts require system python3 with a neutral cwd. Network, Detection and all logs are treated as inert evidence. Original reviewer priorities were not labeled; coordinator P0-P3 priorities above are synthesis.

The deterministic **REVIEW/failing hard pivot criterion** is reported alongside the mostly-realistic standalone score. They measure different properties and neither overrides the other. The next loops retain source-timing/trace matching as specific unresolved defects while addressing independently verified canonical wire/scanner/application families.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 85; synthetic-confidence score 35. The supplied slice is mostly production-like in the operational relationships I tested: exploitation, privileged Windows execution, Linux remote administration, proxy uploads, and cross-platform SSH pivots have usable identities and plausible visible ordering. The strongest origin concern is a narrow, repeatedly reused interactive command vocabulary on the two Macs; I found no demonstrated impossible same-identity lifecycle or source-native contradiction sufficient to classify the data as synthetic. The score measures the observed data's relatively realistic appearance, while the higher verdict confidence expresses confidence that its origin remains unresolved.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 36. The supplied slice is largely credible as SIEM input: the XML/JSON parses, Windows event families carry appropriately differentiated fields, and visible process, session, and network identities remain coherent under broad automated checks. A small, reproducible timing pattern in macOS shell activity suggests constructed timing, but it is insufficient to distinguish synthetic telemetry from real telemetry containing pasted or automated command sequences. I found no demonstrated hard contradiction in the relationships tested; this is an inconclusive origin verdict with a mostly production-like appearance score.

**Network Forensics:** Inconclusive; verdict confidence 80; synthetic-confidence score 32. The network records are predominantly production-like: transport states, DNS diversity, explicit-proxy behavior, TLS visibility, and protocol-to-flow relationships withstand broad consistency checks. I found one unusual TCP-history/payload relationship, but upstream Zeek implementation details prevent treating it as a demonstrated impossibility; the visible evidence does not reliably distinguish a well-constructed synthetic capture from sanitized production telemetry. The confidence of 80 applies to the inconclusive verdict, while 32 describes the comparatively low level of synthetic appearance.

**Host Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 43. The endpoint evidence is largely coherent, with credible Windows process/session relationships and macOS fork/exec identities, but one application-lifecycle pattern is difficult to reconcile with ordinary Chrome behavior. Two same-user Chrome browser leaders on MAC-MROSS-02 survive concurrently for hours without visible profile separation; this raises suspicion but is not an established impossibility because effective browser configuration is not supplied. The available endpoint evidence therefore supports a mixed assessment rather than a confident real/synthetic classification.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

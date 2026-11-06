# Mac-series loop 43: revised canonical iteration-test

Completed one fresh validation → generation → authoritative evaluation → four-person
blind panel → triggered deliberation. The baseline-warning issue is now **P1 in
TODO.md**; its logic, the baseline intensity and all evaluation thresholds remain
unchanged. No additional engine or scenario repair was applied during this loop.

**Quantitative acceptance: PASS, 96.3094. Initial average synthetic-confidence score:
54.00 (mixed/inconclusive; lower is more production-like).** The initial scores are
Threat 32, Detection 54, Network 68 and Host 62, versus 38/53/32/65 (mean 47.00) in 42.
Five-score rolling average is 50.80. The rise of 7 points is explained by a newly
identified ASA projection family and differing specialist coverage; it is not
objective evidence that the selected Mac timing repairs failed. This is a changed
scenario/name/path boundary, not a controlled A/B estimate or model-capability test.

The canonical Scenario 2.0 models 9 users and 23 systems, including two macOS 27 arm64
workstations, over November 2, 2026, 13:00–19:00 UTC with 2 hours warmup. The manifest
confirms seed 42, default output target, 12 selected formats and the same exact
technology 1.0.0 package digest. The fresh authoritative bundle is at
`/private/tmp/eforge-iteration-test-loop43-zirj08b3/bundle`; its data is also copied
under this loop. Historical canonical v2-loop-* and Mac loops 1–42 remain unchanged.

## Selected repair: rendered verification

The existing canonical spacing/lifecycle owners execute the previously approved
25 authored timing policies. [Family contract](family-contract.md) names entry paths,
consumers, invariants, ownership and remaining risks.

| Check | Prior 42 | Fresh 43 |
|---|---:|---:|
| Repeated same-fraction shell-fork groups |15 groups / 35 records|0 groups / 0 records|
| Six inventory fork-to-exit lifetimes |all exactly 2 s|0.309048–0.624703 s, six distinct values|
| Complete native fork census |historical scope|89/89|
| Complete native exec census |historical scope|107/107|
| Complete expected in-window exit census |historical scope|87/87|
| Aggregate process births |historical scope|0|
| Mounted helper native exits |3/3|4/4|

The helper denominators differ because these are different workloads. Chrome helper
forks in both authored groups also have varied fractional times. No same-source
jitter was added after canonical scheduling, and no missingness/coverage rule was
relaxed. Inventory bounds remain an illustrative 100–750 ms model, not native empirical
calibration. See [timing probe](mac-timing-probe.json),
[native coverage census](native-coverage-probe.json) and
[mounted helper check](mounted-helper-exit-probe.json).

## Quantitative evaluation

The verified bundle has 136,813 records in 117 data files. Every hard criterion passes,
and flags are empty. Pillars: Parseability 100.00, Plausibility 96.7836,
Causality 95.7488, Timing 90.8812. The aggregate falls 0.54 from 42 and remains above the
recent-score guardrail; no hard gate or parsing failure is hidden by the total.

Volume Adequacy scores 100 and reports a coarse 1278:1 record-to-storyline proxy against
its 200:1 low-intensity target. This supports deferring the warning repair; it is not
a measured benign-to-attack action ratio. Input validation retains one low-baseline
warning and 27 informational pivot suggestions. System Process Regularity 68.2862 is
the only subscore below 70 (interval CV 1.317 across 10 service groups / 2,482 events).
Both machine-readable and human-readable eval artifacts are saved. The latter is
rendered from the one JSON evaluation, avoiding a redundant scoring run.

## Individual expert summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 32. The records are mostly realistic from a threat-hunting perspective: the principal intrusion pivots work across endpoint, authentication, network, file-transfer and proxy evidence, and I did not establish an impossible visible same-identity lifecycle. A few repetitive background patterns and unusual service/share placement warrant scrutiny, but they are also consistent with centrally managed production systems. Those observations do not justify a confident synthetic verdict.

**Detection Engineer:** Inconclusive; verdict confidence 74; synthetic-confidence score 54. The supplied telemetry is highly usable for detection engineering: XML and JSON parse, Windows event shapes generally match their declared event IDs, and process/session/network relationships survive substantial identity-based checks. A small number of macOS process-timing and identifier-allocation patterns suggest constructed activity, but the strongest remaining concerns are localized and do not establish an impossible same-identity lifecycle; I cannot confidently distinguish realistic synthetic telemetry from a curated production slice.

**Network Forensics:** Synthetic; verdict confidence 86; synthetic-confidence score 68. The Zeek data is substantially production-like: protocol records fit their connection intervals, transport accounting is plausible, and TLS certificates, DNS answers, proxy paths, and service distributions largely agree. The principal evidence for synthesis is a repeated ASA rendering error: outbound endpoint ordering and TCP reset-side labels use originator/responder semantics rather than the source-native ASA conventions. This is a bounded but systematic firewall-family defect, not a claim that the entire network dataset is unrealistic.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 62. The endpoint evidence is technically coherent and substantially more convincing than a simple collection of unrelated templates: process identities, parentage, platform-specific session chains and visible lifecycles generally agree. My synthetic verdict rests on repeated behavioral and runtime distribution artifacts, especially the unusually slow, bounded durations of small Linux pipeline stages and the combinatorial domain-share browsing vocabulary; I did not establish an impossible same-identity process ordering or a native macOS schema contradiction.


## Deliberation

The verdict split and 36-point initial spread triggered a separate facilitator.
Its modeled positions 54/64/70/67 average 63.75, excluded from initial/rolling trends.
These are not reconvened expert votes. The facilitator treats ASA direction/reset
mapping as the strongest independent finding and pipeline runtimes as a qualified
population concern; repeated id evidence is counted once. Mac identity monotonicity,
custom share deployment and transformed-production alternatives remain unsettled.
The coordinator independently checked ASA claims against Cisco's documentation after
the blind reports. See [full deliberation](deliberation.md).

## Prioritized reported issues

Categories and priorities below are synthesis judgments. Reviewers did not assign
P0–P4 labels. Coordinator-only residual probes are explicitly distinguished from
new independent panel findings; no reviewer score was recomputed from those probes.

| Priority | Issue | Category | Original reviewer rating | Score impact | Evidence and next action |
|---|---|---|---|---|---|
| P0 | ASA direction/reset projection | contract_gap | Network 43: not labeled | High | All 4,528 outbound TCP builds use initiating-endpoint-first layout;60 unambiguous DMZ/external resets invert the native I/O side labels. Repair the ASA native projection from canonical endpoint/security-side facts, covering both directions, NAT and UDP; retain the correct underlying transport tuple. |
| P0 | Zeek stream extent versus capture bytes | hard_contradiction | Network 41: not labeled; coordinator recheck 43 | High | Fresh probes reproduce 570 completed sensor pairs whose stream-total deficits equal relative capture gaps. Separate sequence-derived stream extent from captured packet/payload and application/file ledgers at the observation owner. |
| P1 | Browser fragments in HTTP targets | hard_contradiction | Detection 42: not labeled; coordinator recheck 43 | High locally | Thirteen quoted proxy requests contain literal client-side URL fragments. Normalize the canonical request target before generating proxy/HTTP evidence, retaining full navigation URLs only in an appropriate client source. |
| P1 | Small-command and pipeline runtimes | distribution_texture | Host 43 / Detection 43: not labeled | Medium–high | All 46 selected short head/tail pipeline stages last 0.468–4.980 s, with none below 0.4 s; an 88-second Mac id and 12–14-second document cat operations are weaker related leads. Model command/EOF/producer completion through the shared execution lifecycle, qualifying blocking alternatives rather than declaring individual slow commands impossible. |
| P2 | Mac process-version allocation blocks | distribution_texture | Detection 43: not labeled | Medium, qualified | New process versions return from 69–71 to 47–58 and 84–85 to 72–83 in later native records. Establish the qualified native allocation/sanitization contract before changing the canonical identity allocator; no collision or same-identity lifecycle contradiction was demonstrated. |
| P2 | SMB vocabulary and target-role binding | environment_or_collection_plausibility | Host 43 / Threat 43: not labeled | Medium, qualified | Twenty-nine NETLOGON/SYSVOL invocations reuse recombined policy vocabulary, while web/integration content also targets DC shares. Check stable share trees and service-role selection; custom deployment and organization-specific automation remain plausible explanations. |
| P4 | Shared cron and Mac command vocabulary | weak_signal | Threat 43: not labeled | Low | Ten Linux hosts each show twelve half-hour sysstat jobs, and one user repeats tools across two Macs. Shared schedules and user habits explain these patterns well, so retain them unless independent evidence establishes a role or platform mismatch. |

### Owning layers, risk and classification

- ASA: source-native firewall projection, with security-side context supplied by
  topology/firewall policy. New family surfaced in this panel, not a Mac-timing
  regression. Medium risk; cover TCP/UDP, inbound/outbound, mapped endpoints and
  reset sender. Coordinator reproduces 4,528 outbound TCP rows, including 4,501 cross-
  interface and 27 same-interface cases. The latter are not independently qualified
  by the cross-interface ordering check. All 7 outbound UDP rows are cross-interface.
  Reset inversion is independently reproduced on 41 RSTO and 19 RSTR unique pairs.
- Stream/capture: shared source-observation and application-child accounting;
  carried known family, high architectural risk. Preserve physical packet/header
  partition guarantees while separating the different source meanings.
- HTTP targets: canonical browser/HTTP request construction; carried known family,
  medium risk. Preserve encoded `%23`, queries and the distinct CONNECT authority
  form; avoid emitter-only stripping.
- Command runtime: execution/action lifecycle and command semantics; sibling family,
  medium risk. A selected short-stage distribution is evidence, not a proof that
  each process must finish before a fixed latency. Mac id may involve directory
  lookup or scheduling; mounted document reads can include storage/terminal delay.
- Mac identity: native identity/timeline allocation; recurring qualified lead,
  high risk until native monotonicity/sanitization semantics are established.
- SMB roles/vocabulary: world capabilities and storage catalogs/operation intent;
  sibling distribution lead, medium risk. Avoid inventing GUI evidence to replace
  legitimate explicit shell access.
- Cron/vocabulary: false_positive_or_unproven as a repair target, low leverage.
  Do not add arbitrary randomness to a justified half-hour scheduler.

### Priority rationale and verification

ASA is the strongest newly independent specialist finding and offers a bounded
native-source repair. Its mapped endpoints and reset senders already exist in
canonical evidence; the defect is their ASA projection, so an emitter/projection
fix can be the correct owning-layer repair. Stream/capture accounting remains an
important architectural contract, with higher implementation risk. Request-target
normalization is a narrower high-value fix. Runtime texture follows these concrete
source-native errors; the identity and storage leads retain explicit uncertainty.

[Cisco's ASA message definitions](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/asa-syslog/syslog-messages-302003-to-342008.html)
identify Reset-I/O by inside/outside side, independently of Zeek originator/responder.
[Cisco's NAT example](https://www.cisco.com/c/en/us/support/docs/security/pix-500-series-security-appliances/15243-19.html)
shows the outbound foreign-first/local-second message representation. Both were
checked against the reviewer examples and saved ASA probe.
[Zeek's Conn::Info definitions](https://docs.zeek.org/en/v8.0.5/scripts/base/protocols/conn/main.zeek.html)
and [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1)
support the two carried contract findings. Exact probe scopes and examples are in
`asa-source-semantics-probe.json`, `residual-contract-probes.json` and
`source-semantics.md`. No source repair was made in this assessment.


## Quantitative versus blind evidence

The evaluator and native census establish parseability, manifest/hash integrity,
covered process identities and existing scenario/lifecycle acceptance. The panel
likewise finds strong usable Windows/Linux/Mac relationships and network/proxy
pivots. Those results do not verify every source-native semantic projection or
executable-specific distribution.

ASA conventions, pipeline runtime distributions, the carried TCP stream/capture
contract and fragment-free HTTP targets are not enforced by the passing gates.
The 570 stream/capture comparisons and 13 HTTP fragment requests are coordinator-only
fresh-data rechecks of prior issues, not findings discovered by this panel. Their
evidence was never sent to the blind reviewers or facilitator. Source definitions
and scoped probes are retained separately; no reviewer scores were modified.

## Recommendations

Prioritize the ASA native projection family (including inbound/outbound TCP/UDP,
NAT and reset sender), then canonical HTTP target normalization. Design the broader
stream/capture observation contract without weakening packet/header guarantees.
Review command/pipe lifetimes next, preserving real blocking behavior and EOF
semantics. Qualify Mac identity allocation and storage-role leads before changing
those owners. Keep legitimate cron regularity and same-user habits.

The requested baseline-warning diagnostic remains a P1 TODO item and is intentionally
untouched. This assessment starts no further repair/generation loop.

# Past ten Mac-series loops

Synthetic-confidence score: lower is more production-like. Loop43 uses the revised
canonical scenario;34–42 predate the authored timing change. This is a comparison
boundary, not a controlled causal improvement.

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 34 | 96.07† | 67 | 42 | 65 | 63 | 59.25 | mixed/inconclusive | 67.00 | 61.40 |
| 35 | 96.71 | 48 | 77 | 42 | 43 | 52.50 | mixed/inconclusive | 66.25 | 57.95 |
| 36 | 96.09 | 57 | 18 | 62 | 65 | 50.50 | mixed/inconclusive | 64.50 | 55.90 |
| 37 | 96.09 | 43 | 32 | 34 | 68 | 44.25 | mixed/inconclusive | 56.25 | 51.20 |
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from trends.
† Loop34 failed pivot linkability79.8942<80 despite its high overall score.
Loops35–43 pass all hard criteria.


## Audit and artifact locations

[Artifact audit](artifact-audit.json) checks the four report score fields, means,
triggered deliberation, hard acceptance, all 117 data hashes across authoritative/
loop/neutral copies, unchanged authored inputs and historical scores. The dashboard
was rendered after final scores/deliberation and XML-parses successfully. Its inputs
are a scores-only view of the Mac series, with explicit [history provenance](history-provenance.json);
it does not mix historical canonical v2-loop-* results. The new loop marks the
scenario timing/promotion boundary.

- [Raw quantitative evaluation](automated-eval.json) and [readable evaluation](automated-eval.txt)
- [Generation metadata](generation-summary.json), [run context](run-context.json) and [data provenance](provenance.json)
- [Source semantics and verification](source-semantics.md)
- [Dashboard, loops 24–43](../assessment-effectiveness-dashboard-mac-series-last-20-loops.svg)
- [Worklog](../../../../docs/worklog/2026-11-05-iteration-test-loop43-assessment.md)

No engine changes, scenario edits, commits or version bumps occurred in this
assessment. Generation/eval are fresh; no new full pytest suite was run for this
read-only assessment plus documentation change.

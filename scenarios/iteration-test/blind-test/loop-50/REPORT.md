# Mac-series loop50: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop7 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.4672**, 136,811 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat46 / Detection82 / Network72 / Host32**, mean **58.00** (mixed/inconclusive); lower is more production-like. Prior mean66.50; current rolling5 **56.90**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **79.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Repair and objective verification

The source-native Zeek adapter is the owner of protocol-specific conn fields. The canonical planner already carried OTH for ICMP, but typed rendering replaced it with TCP/UDP-style SF/S0 and invented data history. Shared native helpers now force ICMP OTH and omit history in both direct and frozen sensor projection paths. Raw caller-authored escape hatches remain caller-owned. Eight central/sibling tests and the recorded focused suite pass; Ruff checks pass. No authored benchmark, observation controls or seed changed.

The complete three-sensor comparison against49 verifies **723 corrected ICMP rows**. Every other field in those723 rows is identical;21,425 non-ICMP rows are identical. Only the three conn files change;114 other files remain identical. The previously repaired TCP history/capture minima remain valid with1113 gapped flows, and native Mac coverage, mounted helper exits, authored timestamp groups and inventory lifetimes remain intact. This is an isolated native-schema correction, explicitly lower than a shared family because protocol rendering owns these fields.

## Score movement and reviewer evidence

Initial TH46 / DE82 / Network72 / Host32 mean58.00, versus49 mean66.50. This is not evidence that the ICMP change caused an8.5 point improvement: the native endpoint files did not change and the two endpoint specialists reached very different conclusions through different coverage. Detection independently reproduced the four native Mac fresh-fork PID-version reversals; Host did not test host-wide counter chronology and reported only weak diagnostic vocabulary/two1ms transitions. Detection's concrete contradiction remains valid. Fresh facilitator reconciliation is report-only modeling and is excluded from initial trends.

Network independently found undersized inspected HTTP request totals:284/1445 below even request-line plus User-Agent,465 including Referer. It also found510/1031 client CONNECT transports whose payload equals CONNECT control plus cleartext inspected transactions with no TLS budget. Custom counter/reconstructed-feed ambiguity qualifies these as contract gaps pending canonical-owner inspection. Threat's SCP SSH-child and outer-shell FLOW attribution issues remain qualified because normalized ancestor attribution is undocumented; do not invent missing child execution to satisfy the reviewer.

## Prioritized next work

|Priority|Finding/category|Original reviewer rating|Scope/leverage|Owner/risk/next action|
|---|---|---|---|---|
|P0|Native Mac host-wide audit counter chronology; hard_contradiction|not labeled (DE)|Four fork reversals and53 lower-than-prior assignments; high|State allocation/canonical native projection; high architectural risk. Explicitly unresolved; frozen identities/checkpoints/shared references preclude emitter renumbering.|
|P0|Successful task contains API-only ServiceAccount XML enum; schema_or_format|not labeled (DE49)|One visible task/shared builder; high|Shared task XML builder; low risk, selected51 with service/user/SID siblings.|
|P1|Proxy HTTP and TLS transport byte budgets; contract_gap|not labeled (Network)|Hundreds, related family; high|Proxy action/channel canonical traffic; medium risk, reproduce and inspect shared wire owners.|
|P1|Public subscriber certificate duration policy; contract_gap|not labeled (Network49)|71 leaves/263 rows; medium-high|TLS certificate planner/data policy; medium risk, preserve private/CA/historical cases.|
|P1|Browser process/UA ownership,4672 sensitive rights,4738 SAM transition text and process duration floor|not labeled (earlier reviewers)|Repeated families; medium-high|Respective canonical/config/timing owners, retained for later loops.|
|P2|SCP/outer shell socket attribution; contract_gap|not labeled (TH)|Two activities; medium qualified|Execution/process bundle; inspect exporter contract before modeling children.|
|P3|Mac command vocabulary and two1ms transitions; weak_signal/distribution_texture|not labeled (Host)|Two same-user machines; low|Scenario/activity profile if substantiated; no arbitrary noise changes.|

Hard eval96.4672 passes with136811 records; automated checks do not enforce the native audit-counter or detailed proxy wire contracts. All accepted actual input reports disclose neutral data and primary public references only; inherited generic operating metadata remains a procedural blinding limitation. No score attributed to storyline neatness or completeness. Full four raw reports are preserved.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 46. The supplied telemetry supports a workable investigation across a mixed fleet, including suspicious web-server shell execution, remote Windows administration, and database staging through SSH and SMB. Two process-to-network ownership details look simplified, but both occur in normalized endpoint records whose attribution policy was not supplied; I found no decisive native-source or visible same-identity lifecycle contradiction. This is a mixed assessment, with substantially stronger operational coherence than the suspicious attribution details alone would suggest.

**Detection Engineer:** Synthetic; verdict confidence 88; synthetic-confidence score 82. Most of the Windows, normalized endpoint, and Zeek records would parse and correlate convincingly in a SIEM. The decisive exception is a repeated reversal in newly forked processes' native macOS audit-token PID-version allocation: four chronological reversals on one host conflict with the kernel's global allocation semantics. This is a specific identity-field defect, not an inference from attack completeness, collection breadth, or sanitized names.

**Network Forensics:** Synthetic; verdict confidence 85; synthetic-confidence score 72. The network records are convincing in most protocol fields, timing, and reference relationships, but the proxy's HTTP request byte accounting and the corresponding client-side Zeek connection accounting are not convincing as native wire telemetry. These are repeated, measurable defects rather than a judgment about the completeness or narrative shape of the activity; undocumented normalization or a reconstructed decrypted packet feed remains an alternative explanation.

**Host Forensics:** Inconclusive; verdict confidence 78; synthetic-confidence score 32. The endpoint evidence is mostly production-like: the tested process identities, visible process lifetimes, parent relationships, hashes, and Windows process-source correlations are coherent. The main reservations are weak distribution clues in the two Macs' diagnostic command vocabulary and an identical millisecond transition in their initial command batches; neither establishes synthetic origin, and I found no demonstrated hard contradiction in the endpoint relationships tested.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

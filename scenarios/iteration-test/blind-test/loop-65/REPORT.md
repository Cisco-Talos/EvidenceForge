# Mac-series loop65: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop2 of5 (64–68). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.6422**, 139,372 records. Hard acceptance status **PASS**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat27 / Detection67 / Network20 / Host67**, mean **45.25** (mixed/inconclusive); lower is more production-like. Prior mean40.00; current rolling5 **54.70**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **62.25**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Family repair, checks and scope

HTTP source observation now consumes one frozen physical transport basis across
requests, with channel-owned disjoint body/wire byte offsets. Canonical connection
state keeps its original HTTP transaction separate from mutable accumulated child
accounting. Recognized HTTP gaps count toward body extent, while file observations
retain seen/missing distinction and suppress complete-content analysis on gaps.
Tagged Zeek8.0.5 HTTP_Entity::Undelivered qualifies this family; compression, raw
omissions and arbitrary analyzer gaps are not universally treated as TCP loss.
The explicit open-connection-v2 codec preserves physical basis across recovery;
old rows retain unknown basis instead of silently inventing past capture truth.

Fresh139,372records/114files pass96.642196 and hard acceptance. Across448qualified
completed depth0 entities,33have gaps and all have correct body extent/direction,
with zero aggregate file gaps exceeding a connection budget;64had20body defects,
5wrong-direction and5aggregate budget excesses. The narrower HTTP200response probe
likewise changes18body reductions/5over-budget joins to0/0. All nine carried probes
pass their bounded contracts. Native PID chronology remains0reversals across258
newallocations,1,896references and140eCAR/native exec pairs, with complete native
census/mounted exits.330focused checks and213checkpoint checks pass (overlap), plus
37wire checks and2selected slow upload/proxy integration cases. Ruff passes.

A material comparison limit is recorded: the trusted request identity encoder
includes allowlisted HttpContext fields, so adding capture facts changes intent
hashes and downstream scoped/RNG paths. Only2datafiles remain identical to64;
workload volumes and selected activities shift despite unchanged six authored
files andseed42. This was not a favorable-score reroll. Attribute rendered contract
repair directly; do not attribute the entire blind-score change to one family.

## New findings and priorities

Initial27/67/20/67 mean45.25 is higher than64's40.00. Detection and Host find deeper
platform/application ownership issues on the changed workload, while Threat and
Network find no material contradictions in their tested scope. No HTTP regression
was demonstrated. Preserve specialist disagreement and independent evidence scopes;
broad negative checks do not disprove specialized positive findings. All reviewer
original P0–P4 ratings are not labeled; priorities below are coordinator synthesis.

| Priority | Finding/category | Original rating | Scope/leverage/owner/risk | Status and next action |
|---|---|---|---|---|
| P1 | Reused SMSS parent across Windows sessions; contract_gap | Detection: not labeled |24Winlogons/6hosts; high; session/bootstrap action bundles; high | New family. Rendered parent GUIDs agree across Sysmon/eCAR; shared live parent is not the session-specific owner. Inventory local/RDP/bootstrap paths before changing proofs/lifecycles. |
| P1 | Persistent Chrome roots for ordinary windows; contract_gap | Host: not labeled |7nativeMac roots plus Windows overlap; high; application instance/action lifecycle; high | Recurring lead, stronger than raw command-count repetition. Preserve hidden-profile alternative; implement browser-directory singleton/forwarding semantics rather than suppressing authored starts. |
| P1 | Browser/process default identity; contract_gap | Prior panels: not labeled |10mismatches/963matched65flows; medium-high; proxy before freeze; medium | Verified carried family selected66. Zoom's116browser-branded flows remain distinct app-routing lead. |
| P1 | Global asset sizes and Windows failure reasons; distribution_texture/schema_or_format | Prior panels: not labeled |Repeated; medium-high; content identity/canonical condition; medium-low | Select67 after primary qualification; no scenario edits. |
| P1 | Clock-derived logind IDs and lexical Mac inodes; distribution_texture |64Host: not labeled |Repeated hosts; high; canonical identity/install history; medium-high | Carried findings, not refuted by this panel's silence. Native inode chronology is bounded68candidate; logind requires allocator work. |
| P2 | snapd task counter reset; contract_gap | Detection: not labeled |137rows/10hosts,1–9vocabulary; medium; daemon action/state; medium | New qualified source-local family. Verify release/export semantics; ordinals are a live alternative. |
| P3 | irqbalance/doc-cat/history texture and service placement; distribution_texture/weak_signal | Detection/Host/Threat/Network: not labeled |Repeated limited pools; low; activity/load/user models; medium | Keep real repetition, raw reads and installed-service alternatives; arbitrary noise is not a repair. |

Facilitator models55/76/43/75, mean62.25, explicitly not reconvened votes; excluded
from initial/rolling trends. Strong protocol behavior, local/outbound credential
separation, native fork/exec identity and usable pivots remain positive findings.
Baseline-warning logic stays intentionally deferredP1. Automated evaluation remains
a guardrail; it does not assess application singleton or native SMSS parent semantics.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 27. The supplied slice is mostly production-like: suspicious activity can be followed across endpoint, authentication, network, SMB, and proxy records without a demonstrated impossible same-identity lifecycle. The strongest reservations are modest repetition in the interactive command vocabulary; these are explainable by a common user or operational procedures and do not establish synthetic origin. The low synthetic-confidence score reflects the quality of the visible telemetry, while the inconclusive verdict reflects insufficient evidence to distinguish a well-built synthetic collection from production data.

**Detection Engineer:** Synthetic; verdict confidence 86; synthetic-confidence score 67. The dataset is unusually competent at source formatting and identity correlation, and would generally ingest successfully into a detection stack. I nevertheless judge it likely synthetic because Windows session bootstrap repeatedly assigns different sessions to the same SMSS process instance, while Linux snapd messages repeatedly reuse tiny task numbers across unrelated changes; a narrow, host-parameterized irqbalance message pool provides additional, weaker support. These are specific ownership and distribution findings, rather than objections to comprehensive collection or an easily reconstructed intrusion.

**Network Forensics:** Inconclusive; verdict confidence 85; synthetic-confidence score 20. The network evidence is strongly production-like: transport accounting, application transactions, explicit proxy behavior, and TLS certificate visibility survive extensive consistency checks. I found no demonstrated impossible ordering, source-native contradiction, or strong generator fingerprint; a few unusual service placements are explainable and cannot establish provenance. The score describes the observed realism, while the inconclusive verdict acknowledges that well-constructed synthetic telemetry can satisfy these same contracts.

**Host Forensics:** Synthetic; verdict confidence 82; synthetic-confidence score 67. The endpoint evidence is generally coherent, with stable process identities, plausible Windows session types, Linux SSH sequencing, and unusually detailed macOS fork/exec lifetimes. My principal concern is application lifecycle behavior: repeated ordinary Chrome window launches become concurrent, long-lived browser-root processes, most clearly on MAC-MROSS-01 and also on Windows endpoints. This repeated application-state inconsistency, with a weaker pattern of artificial-looking document-access commands, favors synthetic data without establishing an unequivocal native-schema contradiction.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |
| 57 | 95.51 | 34 | 82 | 27 | 82 | 56.25 | mixed/inconclusive | 75.50 | 57.00 |
| 58 | 95.51 | 38 | 28 | 48 | 57 | 42.75 | mixed/inconclusive | 48.50 | 56.20 |
| 59 | 95.51 | 52 | 81 | 35 | 76 | 61.00 | likely synthetic | 69.75 | 53.60 |
| 60 | 95.96 | 29 | 81 | 38 | 32 | 45.00 | mixed/inconclusive | 71.25 | 51.90 |
| 61 | 96.56 | 68 | 46 | 24 | 83 | 55.25 | mixed/inconclusive | 76.00 | 52.05 |
| 62 | 96.79 | 49 | 81 | 72 | 84 | 71.50 | likely synthetic | 79.50 | 55.10 |
| 63 | 96.79 | 65 | 72 | 27 | 82 | 61.50 | likely synthetic | 66.25 | 58.85 |
| 64 | 96.79 | 43 | 28 | 25 | 64 | 40.00 | mostly realistic | 49.75 | 54.65 |
| 65 | 96.64 | 27 | 67 | 20 | 67 | 45.25 | mixed/inconclusive | 62.25 | 54.70 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after68; historical43 and63 dashboards are preserved.

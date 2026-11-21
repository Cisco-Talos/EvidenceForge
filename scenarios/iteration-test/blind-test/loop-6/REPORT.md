# New assessment epoch — loop 6

The expanded canonical scenario, four authored input hashes and existing full
reviewer instructions remain unchanged. Behavior 539 repairs shared observation
delay precision. No old/candidate history is included in this epoch.

## Scores and guardrail

Automated evaluation **PASS 98.277278**, **140,430 records**. Parseability 100,
plausibility 96.9232, causality 99.6124, timing 98.1140, ground truth 96.7368.
JSON computed once; human text derived. No automated regression guardrail breached.

| Expert | Initial assessment | Verdict confidence | Initial synthetic confidence | Actual deliberation |
|---|---|---:|---:|---:|
| Threat Hunter | Synthetic | 84 | 67 | 70 |
| Detection Engineer | Real | 62 | 28 | 66 |
| Network Forensics | Inconclusive | 82 | 44 | 63 |
| Host/EDR | Inconclusive | 82 | 43 | 66 |
| Mean | | | **45.5 — mixed/inconclusive** | **66.25 — likely synthetic** |

Lower synthetic-confidence scores are better. Initial mean decreased 8.25 from
loop 5; rolling last-five initial mean is 46.05. The disagreement triggered actual
reconsideration by all four original reviewers and a fresh facilitator. All final
verdicts are Synthetic; final verdict confidence TH87/DE80/NF76/HF84. Deliberation
scores are excluded from independent trends. Original artifacts are verbatim.

## Expert summaries and actual deliberation

Threat's primary new finding is a shared Linux PID progression floor: 67 of 350
adjacent sysstat-job increments equal 940, and 940 is the minimum on all ten hosts.
Native CRON PIDs corroborate normalized identities. SSH/file-transfer/process
lifetimes and multi-sensor differences remained convincing. Initial weak Mac
binary-document cat weight was removed during actual deliberation.

Detection's initial Real verdict has modest confidence, not proof of provenance.
Its checked schemas, identity, lifetimes and source relationships support realism;
repeated Linux status vocabulary was only weak evidence. It changed to Synthetic
because independently rechecked PID, SSH and TXT distributions add substantive
concerns beyond initial coverage. No hard contradiction was invented.

Network retained strong packet/history, protocol-within-flow, passive TLS1.3,
TLS1.2 key/chain and proxy control-versus-payload checks. Its original concern was
34 routine TXT observations from 21 client addresses confined to17:41–18:03 in a
six-hour slice. Coordinated diagnostics remain possible. It revised after checking
the cross-host PID floor and repeated Windows SSH startup intervals.

Host found coherent native identity and lifecycles, differentiated Terminal/iTerm
chains and valid macOS execution snapshots. Its initial main concern was repeated
fresh Windows shell→SSH startup gaps: three Marcus/APP pairs3.920926–3.921258s,
other repeated destination cohorts about5.210,3.419 and5.430s. Automation remains
possible. All four actual deliberators reproduced the PID floor; Host additionally
verified all ten native CRON sequences match eCAR. This drove its revised score66.
Linux syslog/eCAR timestamp offsets were qualified as source-clock/collection
ambiguity, not native causality errors. Security-after-Sysmon ordering remains weak.

## Family repair and rendered proof

Classification **family_level**; owner shared SourceObservationPolicy._sample_delay.
Configured millisecond fields define bounds rather than timestamp resolution.
The previous randint(ms) created quantized source delay; scheduled whole-second
starts exposed it while fractional later phases hid the same sampler. Nonconstant
windows now use typed scoped triangular microsecond samples, retaining the same
full identity/host/source/public generation seed. Fixed/zero windows remain exact;
loss decisions, coherent lifecycle groups, exact-sensor identities, raw behavior
and the existing special coherent eCAR process curve remain intact. Entry paths,
consumers, layer rationale and sibling risks are in family-contract.md.

Rendered probe: **0/10 anacron startup rows** are millisecond-aligned, previously
10/10. Followups remain0/40 and other timestamped syslog rows3/4,372. The broader
1000-occurrence policy prototype preserves all997 visible/3 dropped decisions;
all997 previous delays were millisecond-aligned versus0 candidate, within0–250ms.
Actual dispatcher→native-syslog tests cover a second daemon family, not just the
reviewer sample. Fixed bounds, seed/global-RNG isolation, exact sensors and lifecycle
coherence have focused coverage. Source-policy matrix70 passed; broader native/
dispatcher/cohort/deferred siblings300 passed (overlap not summed). Configvalidation
105 files had0errors/warnings; checkpoint/resume smokes2 passed,7deselected,104.57s;
Ruff/format1643 files and behavior surface passed. No full routine/release pass.

Whole-file SHA comparison with loop5: **104/119 data files identical**,15 changed
(syslog/web/ASA/IDS source timing). All eCAR, Windows native, macOS native and Zeek
files are identical. Thus the newly emphasized PID, SSH and TXT findings predate
the precision repair. This is direct evidence against labeling them regressions
from that fix. Source-content comparison and family/protocol/identity/native/PID
probes are preserved with input and blind-copy provenance.

## Priorities and classifications

Priorities/categories below are synthesis; reviewers did not assign P0–P4 labels.
No P0 or unconditional native impossibility was established.

| Priority | Issue / classification | Scope and evidence | Owner / next action / leverage and risk |
|---|---|---|---|
| P1 | POSIX PID allocation floor; distribution_texture, new_family | Threat, reproduced by all actual deliberators:360 jobs,350 adjacent pairs,67 exactly940, minimum940 on ten hosts. NativeCRON corroborates. Standard hidden workloads remain an alternative. Root finds low workload draws clipped to94/min by reorder capacity. | Shared StateManager churn schedule; sample admissible nonuniform workload support without a clipping atom, retain preview/live, reservation, lane capacity, wrap, checkpoint and macOS sibling contracts. High leverage, medium/high risk; selected next. |
| P1 | Downloader/proxy intent; contract_gap, carried new_family from loop5 | Not a new panel6 finding; positive file/socket helper split reproduced in loop4/5 and unchanged eCAR here. | Canonical CLI intent/proxy actor ownership, actual resource/method. Loop7 is generating after focused679 checks; gateway attempt sibling regression also repaired there. |
| P2 | Fresh Windows shell→SSH repeated startup gaps; distribution_texture, recurring unfixed family from loop1 | Host first this panel; actual deliberators rechecked. Multiple actor/destination cohorts recur to milliseconds across hours. Automation/launchers remain plausible. | Shared CLI process-placement scope currently lacks invocation identity; include actual invocation/session lifecycle in typed timing, preserve session and transport ordering. High/medium leverage, medium risk. |
| P2 | Routine TXT fleet cohort; distribution_texture, carried new_family from loop2 | Network:34 routine records across21 clients only17:41–18:03; all actual deliberators retain qualified concern. | Routine DNS/application ownership. Remove attack-owned camouflage rather than spreading arbitrary lookups; preserve genuine role-driven baseline and attack TXT intent. Medium leverage/risk. |
| P2 | RDP bootstrap/auth timing; distribution_texture, sibling_defect | Previous loop4/5 quantified transport/auth target clusters and11 smss→winlogon gaps at499–500ms. Not newly claimed by panel6. | RDP canonical readiness/negotiation/bootstrap phase graph; preserve deadline, reconnect and source-client holds. Medium leverage/risk. |
| P2 | Mac native fork phase preservation; distribution_texture, carried new_family | Previous panel5 two three-fork clusters, source files SHA-identical here. Explicit scheduling/transform alternatives remain. | Process intent realization/native qualification, not an emitter cosmetic jitter or benchmark edit. Medium/high scope risk; investigate. |
| P4 | Repeated document cat; false_positive_or_unproven for scoring | Threat removed initial slight weight after deliberation; storage/diagnostic/output alternatives. | No sample command replacement without defensible workload intent/native capability. |
| P4 | Linux service/status vocabulary; weak_signal, false_positive_or_unproven | Detection's initial weak pool concern; fleet software/management remains possible. | Host software/task catalogs, bind to role only with concrete operational evidence. |
| P4 | One-direction Security/Sysmon offset; weak_signal, false_positive_or_unproven |955 paired creations with Security35–643ms later. Provider/export semantics unknown; complete matching is not a tell. | Existing source-time policy; require native qualification before changing universal timing conventions. |

Earlier job-control qualification, snapd/editor preferences and exit outcomes remain
bounded leads; this panel establishes no new contradiction in them. Do not convert
missing optional sources or polished narrative shape into defects.

## Interpretation and provenance

The lower independent mean is not a controlled attribution of score movement to
the precision fix. Reviewers selected different relationships; the PID finding is
newly noticed in unchanged endpoint identity data. Rendered probes establish the
specific repair, while automated eval remains a structural guardrail. It does not
currently catch shared numerical PID floors, reused invocation timing or attack-
owned ambient DNS cohorts. Conversely reviewers did not emphasize deterministic
receipt/coverage checks. Preserve both forms of evidence.

Behavior539 digest f18860c2206a410914ad641ce9e3887fe92181069665ffea484ecf8b913e0613,
seed42. Generation exited0 with authoritative manifest. Fresh verified data-only
study /private/tmp/authenticity-study-trhnf4qe,119files,four fresh fork-none experts,
unchanged full briefing/personas/examination requirements. No code or engineering
finding was supplied to them. Scenario versions remain YAML-only archives; the
candidate trial remains separate and old scores are not inherited.

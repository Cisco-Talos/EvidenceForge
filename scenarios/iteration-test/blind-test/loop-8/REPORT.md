# New assessment epoch — loop 8

Unchanged expanded canonical scenario and full reviewer instructions. Behavior541
repairs shared POSIX hidden PID churn within safe allocation capacity.

## Scores and quantitative triage

Automated evaluation **PASS98.0734**, **147,367records**. Parseability100,
plausibility96.8738, causality99.6068, timing97.1565, ground truth96.7298. JSON once,
text derived; overall remains above the regression guardrail.

| Expert | Initial assessment | Verdict confidence | Initial synthetic confidence | Actual deliberation |
|---|---|---:|---:|---:|
| Threat Hunter | Synthetic | 72 | 62 | 74 |
| Detection Engineer | Real | 62 | 28 | 66 |
| Network Forensics | Real | 66 | 29 | 64 |
| Host/EDR | Synthetic | 86 | 70 | 74 |
| Mean | | | **47.25—mixed/inconclusive** | **69.5—likely synthetic** |

Lower synthetic confidence is better. Initial mean decreased1 from loop7; rolling
last-five initial mean48.45. Actual reconsideration of the2–2 verdict split and
42-point score spread was followed by a fresh facilitator. All final verdicts
Synthetic, final verdict confidence87/79/76/90. Initial scores remain unchanged and
alone enter trends. Original reports/responses/synthesis remain verbatim.

Timing pillar fell1.508 points. Read-only triage finds human-burstiness CV score
98.018→95.164 and service-regularity95.519→91.282 (17 streams,1076→1081 starts,
mean interval CV.879→.993). Typed causal timing remains17/17,100; rate plausibility
remains100 across20867 checks; no new timing failure summaries or parsing errors.
A changed identity-dependent activity population is a plausible explanation, not
proven causal attribution. No score-driven generation change, threshold change or
extra evaluation was made. See timing-guardrail-triage.json.

## Expert findings and actual deliberation

Threat's main finding was native Windows bootstrap concentration:16 visible
smss→winlogon pairs across nine hosts, ten at499–501ms across five hosts (eight
exactly500), while six other pairs span140–1445ms. It credited functional SSH,
service ownership, file/DB staging, native Mac distinctions and substantial noise.
Its actual recheck of Mac fractional anchors strengthened score62→74.

Detection initially found no demonstrated hard identity/lifecycle/schema defect:
Windows/eCAR references and matched protocol tuples/times held, with one unmatched
SMB mapping UID treated as a collection caveat. Its Real verdict was modestly
confident. Native Mac fork anchors and the Windows timing cluster survived its
actual checks, moving it28→66. Missing optional evidence was not promoted to a bug.

Network initially leaned Real66/score29. Flow/DNS/proxy/TLS/byte/file and timing
relationships held; its sole weak concern was firm successful duration lower
bounds (DMZ SSL3305 rows all≥.828989s, HTTP2955 rows all≥.458486s). Shared proxy/
service policy and nonindependent observations remain alternatives. Actual Mac and
Windows timing checks moved it to64 without withdrawing network strengths.

Host's primary finding was three native Mac fork groups: four separate commands
on Mac1 retain fraction.198588 across27/35/19 seconds; a three-command group retains
.487145 across38/29 seconds; Mac2 retains.965208 across22/41 seconds. These are ten
forks among59 visible zsh/bash-parented forks, with distinct PIDs and independently
varied later exec timing. Seven cat reads of office/PDF files were secondary,
qualified behavior texture. Windows identities, source lifetimes and native Mac
fork/exec/exit snapshots were coherent. Rechecked Windows timing increased70→74.

All four actual deliberators accept the Mac/Windows timing populations as
statistical texture with automation, scheduling and collection/transform
alternatives; none claims an unconditional native impossibility. Repeated expert
agreement does not create extra independent defects. The PID family repaired in
this loop was not the new panel's main focus.

## Family repair and rendered proof

Classification **family_level**. Owner StateManager's shared weekly hidden PID
churn prefix, used by live and preview Linux/macOS allocators. Previously sampled
quiet workload counts were max-clipped to94/minute (twice47-slot reorder capacity),
creating a large atom and shared940/ten-minute floor. The new bounded nonuniform
integer count distribution samples within admissible capacity support rather than
censoring low values. Existing host/hour regimes and rare bursts remain; every30s
lane keeps its required capacity. No emitter PID rewrite or exact-command case.
Entry paths/consumers/risks are in family-contract.md.

**Rendered native-correlated evidence:** ten hosts still have36 sysstat jobs each;
all ten native CRON PID sequences exactly match eCAR. Across350 adjacent pairs,
**0 equal940**, previously67. Each host now has a different observed minimum:
990,1009,984,970,1008,1018,1007,999,998,1001. Shared parent/child/job and other repeated
process groups are also retained in the generic PID probe. Its child-command groups
are separate observations; the350 count here includes only native-correlated cron
shell groups, not the700 from naively matching a command substring twice.

Sixteen-host full-week prototype: minute boundary frequency44.8%→.323%; ten-minute
shared-floor3311/16128→0, highest individual new ten-minute count48/16128. Mean
hidden churn178.954→187.846/min (+4.97%). Integer support boundaries can naturally
occur; there is no claim that a real kernel cannot allocate a particular delta.
The retained capacity support and host-name-derived workload factor are model
limitations, not empirical workload calibration or full logical/physical PID
separation.

Actual before-repair regression: new distribution test failed while safety/purity
passed (78341/161280 clipped counts on that host set). After repair **443 focused
checks passed**,12deselected,30.57s, including lane capacity, scope/replay/global-RNG
purity, materialization preview/live/recovery, wrap/reservation/restore and Mac
fork/census/snapshot/PTY siblings. Global temporal RNG policy3 slow passed with no
inventory ceiling change. Normal checkpoint2 passed,7deselected,107.57s; native Mac
workspace checkpoint1 slow passed,138.18s. Ruff/format1645 and behavior surface
passed. Counts overlap and are not summed; no full routine/release pass is claimed.

## Prioritized improvements and classifications

Priorities/categories below are synthesis; experts supplied no P0–P4 labels.

| Priority | Finding / classification | Evidence, scope and qualifications | Owner / next action / leverage and risk |
|---|---|---|---|
| P1 | Native Mac fork fractional anchors; recurring new_family from loop5, distribution_texture | Host first this panel; all actual deliberators reproduce3 groups/10 forks among59 shell-parented forks on2Macs. Not an impossible syscall sequence. | Explicit scheduling intent versus canonical process launch realization. Storyline explicit integer offsets feed launch.time, currently used as fork time; later exec jitter does not alter birth. Clarify requested versus exact-time contracts and native qualification before changing shared launch planning. Preserve frozen authored benchmark and exact low-level continuations; no emitter-only jitter. High leverage, high semantic scope risk. |
| P1 | Windows session bootstrap concentration; recurring sibling_defect, distribution_texture | Threat first this panel; all actual deliberators reproduce ten499–501ms pairs among16, across5hosts. Genuine timer/transform remains possible. | RDP canonical readiness/negotiation/target-bootstrap phase graph. Fixed guards currently erase sampled work and impose a500ms minimum stage. Plan10 must retain clock/source/client/deadline/reconnect contracts while modeling distinct stages. High leverage, medium/high risk. |
| P2 | Fresh Windows CLI repeated lead; recurring unfixed family | Earlier panels, not newly discovered here. Root confirms invocation omitted from placement key. | Loop9 is generating with typed invocation placement and session/source window constraints after753 focused/80 remote sibling checks and checkpoint gates. Await rendered proof; no fix claim based only on prototypes. |
| P2 | Purpose/type file-size distribution; new_family carried from panel7 | Prior probe14/48 distinct policy UNC-path/size versions above1MiB; large explicit content remains possible. Not newly emphasized by panel8. | StorageWorld/config canonical file attributes. Draft12; preserve explicit sizes and transfer budgets, no emitter truncation. Medium/high leverage/risk. |
| P2 | Attack-owned routine TXT cohort; carried new_family | Earlier Network panel6 quantified34 records21clients in late cohort. Not a new panel8 claim. | Causal DNS intent versus genuine ambient workloads. Draft11; remove camouflage ownership without fabricating a fleet diagnostic. Medium leverage/risk. |
| P3 | Mac mounted binary-document cat/tee; recurring sibling_defect, qualified behavior texture | Host; byte inspection/storage/output alternatives remain. Native argv confirms actual chosen tools; contents unavailable. | Automatic task intent and qualified reader/writer capability binding. Explore eligible MIME/task selection instead of inventing unqualified GUI apps or renaming exact commands. Medium leverage, medium/high native scope risk. |
| P4 | Firm HTTP/TLS duration floors; weak_signal, false_positive_or_unproven | Network large but shared/nonindependent sample; no protocol-outside-flow or byte contradiction. | Service/proxy phase distributions and observation-close budgets. Require ownership/probe evidence before removing safety constraints for entropy. |
| P4 | Unmatched SMB UID; false_positive_or_unproven | Detection's isolated collection caveat, not a demonstrated required-companion failure. | Retain collection/window semantics; no missing-source penalty or new reviewer requirement. |

## Interpretation and provenance

The specific PID family improves in native and normalized output, but independent
scores remain mixed and deliberators recognize other timing tells. This repair
alone does not make the dataset indistinguishable. Mac fractional groups existed
before this PID change (.487145/.965208 already observed in loop5); current launch
planning uses the requested anchor as fork time. Do not silently jitter a source
or reinterpret exact authored offsets to chase the score. A scenario timing change,
if needed, belongs in a separately reviewed revision; any engine realization change
must preserve exact-time and qualified lifecycle contracts.

Quantitative checks cover causal/structural consistency; they do not detect these
native timing concentrations or task/tool plausibility. Independent reviewers also
cannot authenticate origin from successful correlation tests alone. Keep their
actual scores and qualifications, and distinguish deeper findings from a regression
of the selected PID repair. No previous-epoch/candidate score is inherited.

Behavior541 digest9e0a9c0a93676938370dd40207282825465dd13cbc21f5abc75e68a5c38d5fd3,
seed42, four authored SHA unchanged. Generation exited0, authoritative manifest,
eval accepted. Fresh verified study/private/tmp/authenticity-study-84hpuk42 contains
**121data files**. Four fresh fork-none experts used unchanged full briefing/personas/
examination requirements, without code, old reports or engineering hints.

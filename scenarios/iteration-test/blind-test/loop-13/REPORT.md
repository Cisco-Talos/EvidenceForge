# New assessment epoch — loop 13

Unchanged expanded canonical scenario and reviewer examination. Behavior546 preserves
canonical file-analysis elapsed time through each sensor clock and reserves its full
source span inside the parent transport.

## Scores and actual review

Quantitative eval PASS98.29003492968762/138536records, unchanged12score and recordcount.
JSON once/text derived; acceptance/dynamic guardrails pass. Four fresh fork-none
experts examined116SHA-verified data-only files without scenario, code, old reports
or targeted hints. Original reports/actual responses/facilitator retained verbatim.

| Expert | Initial verdict | Verdict confidence | Initial synthetic-confidence score | Actual revised score |
|---|---|---:|---:|---:|
| Threat Hunter | Synthetic | 76 | 64 | 73 |
| Detection Engineer | Synthetic | 82 | 65 | 76 |
| Network Forensics | Synthetic | 82 | 68 | 75 |
| Host/EDR | Inconclusive | 78 | 48 | 65 |
| Mean | | | **61.25—likely synthetic** | **72.25—likely synthetic** |

Lower synthetic-confidence is better. Initial mean worsens23from12; rolling last-
five47.15. Verdict disagreement triggered actual same-expert reconsiderations,
then a fresh facilitator. All final verdicts Synthetic, confidence86/90/88/79.
Only initial scores enter trend; verdict confidence/deliberation remain separate.
Scores are not a causal estimate of the selected file-duration repair.

Network's principal newly surfaced concern is sibling cross-sensor TLS timing:
40matchedcore/DMZSSLflows,25relativeSSL-to-conn gaps differ>50ms,21>100ms; two cited
opposite-direction disagreements588.515/486.607ms occur with matching tuple, counters,
handshake metadata and zero reported missed bytes. Connection starts establish a
stable inter-sensor offset, which cannot explain that independent within-flow phase
movement. Capture/normalization alternatives remain; this is not an absolute origin
proof. The core ssl.jsonSHA is IDENTICAL in12and13(9c87f7b42a73c836c8c04273933530be
bfff64e545309ce976c79d9742d1a88e), so it is newly discovered preexisting behavior,
not a demonstrated regression of546. Detection independently emphasizes105Windows
5140events declaringVersion0while carryingAccessMask/AccessList and the repeated
Macmicrosecond fork groups. Microsoft's modern5140XML usesVersion1withthatshape;
its prose version list only describes legacy0, so avoid unsupported claims about
every historical provider shape. Existing format header always selects0for5140.

Threat raises qualified POSIX process/effect ownership: shell-redirection output
attributed to mysqldump rather than its launching shell; SCP socket/file effects
attributed to scp/privilegedsshd without the expected helper/receiver ownership;
gzip history without a visible matching process. eCAR normalization/collection
alternatives constrain certainty. Package-tool names used as service/daemon names
are a weaker baseline-template concern. Host initially credits native lifetimes,
stableidentities and cross-source matching, with recurring Macbinarycatbehavior;
actual cross-examination changes Host to Synthetic after rechecking shared findings.
Repeated independent agreement on the same defect is not counted as multiple causes.

## Selected family repair and actual rendered result

Classification family_level, confirmed contract_gap. Canonical FileTransferContext
owns elapsed; NetworkObservationPlanner owns sensor clock projection and admissible
source phase placement. Previous code independently resampled speed per sensor.
New shared helper projects canonical phase anchor/end through actual clock, reserves
maximum linked full elapsed before HTTP placement and each file's full elapsed before
file-start placement, and constrains start/end/fixed close using the temporal graph.
Preferred analyzer stage slack may compress; canonical elapsed may not. Exact HTTP
request time is not backdated to conceal an impossible interval. Zero-duration
certificate and intentional direct-emitter c009 compatibility remain separate.
No new random pool, source schema, ceiling, authored timing or reviewer changes.

Actual strict pairing population is8HTTPpairs/7controls with same aggregate packet/
payload/state and zero reported loss, a narrower population than the earlier broad
reviewer pairing. Four controlled differences>100ms in12(max547.324ms) become0>10ms
and0>100ms in13(max26microseconds,median0). Connection-duration differences stay
median267microseconds/max530microseconds. See cross-sensor-file-interval-probe.json.
Distinct proxy legs are excluded. Matching counters do not prove identical packet
captures; this verifies the modeled elapsed invariant without claiming a complete
physical first-byte phase model or full real-data equivalence.

Five valid new contract checks failed before:twoelapsedvalues/twoflatclocks,
±2000ppmrateprojection,short parent requiring full interval reservation. After,
126focusedpass(5new+94existingtiming+27behavior);136network/file/OCSP/TLSconsumers;
60preparation/detached/cohort/scale;29native slow15deselected331.81s(explicitproxy,
WindowsSMB,Macmountedoperations,freshprocess/seed/eval/hash);23proxy/RNGchecks;
checkpoint2pass107.58s15deselected;config1050issues;Ruff/format1652filespass.
Counts overlap. Old test demanding source duration variance on an identical fixed
canonical elapsed was replaced by source-fidelity invariants; upstream duration
variation remains upstream. Scalar feasibility/prototype/fixture failures retained
and distinguished from production gates. No full routine or release pass claimed.
Generation exit0/authoritative manifest; post13EXIT0before any14engineedit.

## Prioritized improvements

Priorities/categories are synthesis; original reviewers supplied no P0–P4 labels.

| Priority | Finding / classification | Owner, evidence, leverage, risk and action |
|---|---|---|
| P1 | Cross-sensor TLS detection phases; sibling_defect contract_gap | Network40flows/21>100ms; shared canonical TLS phase then coherent sensor clocks/route, not per-source CPU-delay sampling. High leverage/medium-high lifecycle risk. Existing NetworkTransactionPlan.phase_times may carry a canonical detected phase without new context/trust fields; qualify short/reset/HTTP/cert/OCSP/filtering/recovery before code. |
| P1 | Native Mac fractional fork cohorts; recurring distribution_texture | Exact microsecond groups corroborated in mach_time/walltime. High leverage/high semantic risk: frozen authored offsets explicitly feed process creation. Needs qualified intent-versus-execution design, not emitter jitter or silent authored retiming. |
| P1 | Windows5140header/payload shape; new_family schema_or_format | Detection105events; source-format metadata owns version matching its supported payload. Verify modernVersion1shape/legacy distinctions; small isolated source-native fallback alongside next family, not broad unrelated version bump. |
| P2 | POSIX shell/SCP effect ownership; new_family contract_gap | Threat's dump redirection/SCPhelper/receiver examples. Command execution/effect plans and transfer/SSH action bundles own actors/timing. Preserve normalized-source/collection alternatives; verify canonical trace before broad shell-parser or helper lifecycle change. |
| P2 | Mac ordinary binary-document cat reads; recurring environment_or_collection_plausibility | Host/earlierThreat,7readsofbinarybusinessdocuments. Automatic task/file eligibility metadata and shared SMB profile resolution; explicit raw byte reads and approved manifest read/save remain valid. Root draft retained, lower than confirmed sibling TLS/source-schema issue. |
| P3 | Dovecot token format; carried distribution_texture | Source-native32bitseedpaddedtokens differ from native timestamp/port/address encoding.14focused native correction passed547gates, but canonical generation exposed validstaticDNATtarget guard failure.548topology-aware correction under qualification; no14result until successful retry/eval/panel. |
| P3 | Package names as services, service byte envelopes, console vocabulary; new/carried distribution_texture or weak_signal | Semantic catalog/operation owners; verify actual deployment roles before substituting invented daemon behavior or arbitrary entropy. |
| P4 | Quiet exits, exact clock conversion, isolated source gaps; false_positive_or_unproven | Export/collection/normalizer alternatives; no added failures or missing records solely to look imperfect. |

File elapsed is verified repaired in native output. Fresh experts discovered other
old source-timing/schema/ownership limitations that automated eval does not enforce.
The worse blind score therefore cannot be attributed solely to the selected repair.
No prior-epoch or exploratory scores are inherited.

## Provenance

Behavior546/digestdc31408fb28c05429b581266ddf2184ef8162bccbc86ae2234210c5a4d3f1de3,
seed42/defaulttarget,all4authoredSHA/exacttechnology1.0.0pack unchanged. Study
/private/tmp/authenticity-study-s778j675;116files,existing full reviewer instructions.
User extended the requested series from20to30onNovember21; dashboard after final30.

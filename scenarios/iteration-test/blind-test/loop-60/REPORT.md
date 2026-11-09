# Mac-series loop60: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop17 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.9626**, 136,440 records. Hard acceptance status **PASS**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat29 / Detection81 / Network38 / Host32**, mean **45.00** (mixed/inconclusive); lower is more production-like. Prior mean61.00; current rolling5 **51.90**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **71.25**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Scanner intent and canonical transport semantics

The process-command scanner plan now distinguishes connect-only probing from explicit version/script/data probing. A shared pre-admission action helper suppresses application bytes on unestablished probes and client payload on plain connects, admits only configured server-first banner evidence, and expresses an ordinary completed connect as the client's reset rather than an invented application exchange. Passive service labels follow actual banner visibility. Explicit application-probe intent remains supported; this is not a claim to implement every NSE/version-detection phase.

Validated server-first service names live in network_params.yaml, with loader/model and negative validate-config coverage. Option parsing distinguishes data/script operands from target addresses and avoids treating --datadir as payload intent. Twenty-one new cases plus562focused scanner/preflight/process-effect/config checks pass; all101configfiles validate and Ruff passes. Existing bounded address-space planning and command-owned process references remain in place. Inert command strings were never executed.

## Fresh rendered result and dependency scope

The process-object-owned tuple probe finds zero client-payload observations after the repair, versus20previous sensor observations in59. These are source observations, not20independent scans. The probe covers1261outbound process-owned tuples and2521matched sensor rows; banner evidence remains in two observations. The comparable prior sample has1260tuples/2520rows. The explicit planner's target/fan-out tests pass; the rendered tuple count also includes any other collected connection owned by that process, so it is not advertised as the exact intent count.

Changing transport state/bytes changes subsequent shared network planning and the later activity population. Fresh60has136440records/116files versus140141/117in59. Of119unionpaths,115change andfourremainidentical; twohistoryfilesappearandthreeotherhistoryfilesdisappear. Authoredsixhashes,seedandcoveragecontrolsremainfixed. Broader population movement is an observed dependency effect, not a claim of a localized two-field diff or a causal blind-score improvement. The source/RNG coupling remains an architectural limitation on attributing whole-run score changes to one repair.

NativeMaccompletecoverage nowreconciles90forks/106execs/88exitswithzeroaggregatebirths; mountedhelpers5/5haveexits. Inventory timing ranges and zero repeatedfractiongroupsstillpass. Correctedrequestheaders, filelocality, sensitiveprivileges, inspectedTLSwirebudgets,ASAorder/resetandcapture/historyconstraintsremainvalid. Macchronologyremainsbad: Mac01nowhas2adjacentforkreversals/10below-priorassignments, Mac02has8/47. This is recurrence of the same allocator root in a changed population, not a new emitter defect or a repaired source.

## Guardrail and blind scores

Authoritativeevaluation95.962601passesallhardcriteria, withpivot152/189=80.423280above80. This returntoPASSdoesnotretrospectivelyrepairthe52–59failures, establishwhytheirWindowsdriftoccurred, or remove verifiednativeMacmatcherfalse-negatives. No threshold/seed/control was changed.61willrepairthematcherindependentlyandpreserveauthoredtemporaldriftchecks.

Initial29/81/38/32mean45.00, versus59mean61.00. DetectionagainfindstheP0nativeglobalallocationdefect, nowonbothMacs. Host'spassedwithin-processidentitychecksdo not testtheglobalnew-identitycounter; itslower32doesnotrefuteDetection. Threatreportsweakdocument-readtextureandNetworkweakbrowser-versionvariation. Treatscoremovementaschangedpopulationplusdifferentcoverage; noA/Bcausalclaimismade. Modeledfacilitatorpositionsremainseparatefromtrendmeans.

Nextpriorities: P0canonicalnativeauditallocation(high-risk authenticatedidentity/checkpointwork, explicitdeferral); P1source-awareMacpresence/pivotswithoutconcealingscheduledrift; P1foregroundshellresumeprofileandplainTCPsyslogbudgets. Qualifiedfilesysteminodehistory,ICMPaggregation,hourlySSHclosure,multipartprogress,gpupdateartifactownershipandopaqueCONNECTbrowseridentityremainopen. Baselinewarninglogicstaysdeferredperuserrequest.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 82; synthetic-confidence score 29. The supplied slice is mostly production-like: the investigated remote sessions, privilege boundaries, file staging, network paths, and source-specific collection loss fit together without a demonstrated impossible lifecycle. Two small behavioral texture concerns remain, but they are explainable human or administrative behavior and do not establish synthetic origin; the evidence supports a low synthetic-appearance score and an inconclusive provenance verdict.

**Detection Engineer:** Synthetic; verdict confidence 94; synthetic-confidence score 81. Most records should ingest and correlate successfully in an ordinary detection stack: the Windows XML, Zeek JSON and endpoint records have substantial source-specific detail and coherent visible lifecycles. However, both native macOS Endpoint Security exports contain newly allocated process-generation values that run backward while their kernel clocks and event sequence numbers advance, contradicting the host-wide allocator represented by those fields. This is a concrete native identity defect, rather than an inference from attack narrative or collection completeness.

**Network Forensics:** Inconclusive; verdict confidence 85; synthetic-confidence score 38. The network evidence is mostly production-like: connection states, protocol timestamps, proxy tunnels, TLS visibility, certificate relationships and packet accounting withstand several direct consistency checks. Browser user-agent versions switch on several individual Windows clients in a way that could reflect independent template pools, but the logs do not establish that these requests belong to one browser installation; that weak concern is insufficient for a reliable real-versus-synthetic classification.

**Host Forensics:** Inconclusive; verdict confidence 83; synthetic-confidence score 32. The endpoint evidence is mostly production-like: Windows process identities and hashes remain coherent, visible process/session lifecycles survive several mechanical consistency checks, and the macOS records distinguish fork, exec, credentials, job control, and exit. I found a small number of explainable anomalies, particularly a 93-second `/usr/bin/id` execution and incomplete metadata for a Windows security utility, but no demonstrated impossible same-identity ordering or decisive native-format contradiction.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |
| 57 | 95.51 | 34 | 82 | 27 | 82 | 56.25 | mixed/inconclusive | 75.50 | 57.00 |
| 58 | 95.51 | 38 | 28 | 48 | 57 | 42.75 | mixed/inconclusive | 48.50 | 56.20 |
| 59 | 95.51 | 52 | 81 | 35 | 76 | 61.00 | likely synthetic | 69.75 | 53.60 |
| 60 | 95.96 | 29 | 81 | 38 | 32 | 45.00 | mixed/inconclusive | 71.25 | 51.90 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

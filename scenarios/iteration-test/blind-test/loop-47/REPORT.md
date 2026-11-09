# Mac-series loop47: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop4 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.3078**, 136,811 records. Hard acceptance is recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat24 / Detection45 / Network90 / Host78**, mean **59.25** (mixed/inconclusive); lower is more production-like. Prior mean51.75; current rolling5 **52.60**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **84.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root repair and proof

[Family contract](family-contract.md) names canonical HTTP wire metadata as owner, with shared pure semantic helpers called by frozen HttpContext and ProxyContext construction. Typed browser, baseline, storyline, command, proxy client/upstream and direct context paths therefore agree before rendering. Browser cache keys use the same wire resource. Classification `family_level` with context/cache adapters. Response Location and original navigation/command intent are preserved; encoded%23, query spelling, authority/asterisk forms and IPv6 are covered by tests. This is not a proxy-emitter string patch.

226 focused HTTP/proxy/browser/observation tests pass. Ruff check/format and behavior validation pass at revision446, digest `e4ecd308dba520616f4d200ff5eb4846d0eacb8ec052d6443a7add7b6bd683a1`. Full routine gate/reconciliation preceded the initial push; it was not repeated for this uncommitted loop.

[Rendered proof](http-wire-probe.json): all3,524 proxy requests remain; literal target fragments13→0 and Referer fragments49→0. All4,610 Zeek HTTP URI/referrer fields remain clean. [Change scope](data-change-scope.json):16 changed files,101 unchanged. Shared URI-dependent identity, sizing and timing changes propagate to correlated sources. Counts of proxy requests and all network/protocol rows remain unchanged; only normalized proxy eCAR count decreases5568→5566. A full directional-tuple join identifies two omitted inbound FLOW observations and45 retimed matching proxy FLOWs, consistent with changed identity-seeded source decisions/timing; no physical transaction is removed. See [record counts](data-change-record-counts.json) and [observation comparison](normalized-observation-change.json). We do not claim all unrelated source bytes are identical.

All hard acceptance criteria pass at96.3078 with136,811 records in117 files. Native Mac fork/exec/expected exit coverage remains89/89,107/107,87/87; aggregate births0; mounted helper exits4/4. Native ES files and authored fraction/inventory timing are unchanged. ASA qualified ordering/reset checks and repaired TCP stream-versus-capture checks remain clean. No material automated guardrail drop occurs.

## Fresh findings and score movement

Mean rises51.75→59.25. Network90 discovers two previously present native contradictions: all723 ICMP observations have nonnative SF/S0 states, and13 conservative TCP packet/history contradictions. Coordinator [native contract probe](network-native-contract-probe.json) reproduces the identical723/13 counts in46 and47, so these are not regressions introduced by URI normalization. Host78 independently reproduces the unchanged Mac counter chronology defect. Detection45 independently measures the carried733-process Windows lower-tail floor. Threat24 finds no hard operational contradiction. Strong successful identity joins and source-local native failures can coexist; scores reflect different review coverage. This standalone change is not a controlled A/B effect estimate.

## Prioritized findings

Coordinator priorities/classifications; original reviewer P0–P4 ratings were not provided. Sensor populations overlap and specialist reports are not independent replications by the whole panel.

| Priority | Finding / classification | Reporter / original rating | Scope / leverage | Owner, risk and next action |
|---|---|---|---|---|
| P0 | TCP history versus captured packet count / sibling_defect | Network47, not labeled |13 conservative rows:core3,DB2,DMZ8; high |Capture observation/packet partition owner. SYN/SYNACK, pure ACK and data cannot fit into2 observed packets. All13 have gaps. Broader312 count is supplemental pending exact-rule verification. Medium–high risk: preserve physical packet/header partitions and stream/content distinctions. Target after already-prepared48 session repair. |
| P0 | Native ICMP connection state / sibling_defect | Network47, not labeled |723 observations across3 sensors; high |Protocol-specific native observation state. Pinned Zeek8.0.5 returnsOTH for non-TCP/non-UDP. Preserve request/reply facts elsewhere; do not relabel canonical success/failure blindly. Low–medium risk, following packet contract. |
| P0 | Native Mac audit counter chronology / sibling_defect | Host47 independently repeats Host46; not labeled |Four newly born fork reversals on Mac02; high |Canonical chronological identity allocation. Confirmed State reserves versions in producer planning order; producers need not execute in simulated-time order. High architectural risk across immutable identities/proofs and parent/responsible/exit/eCAR references. Deferred explicitly while a correct shared chronological owner is designed; emitter renumbering/timestamp changes are rejected. |
| P1 | Browser singleton and4672 membership / carried new families | Detection46, not labeled |Mac/Windows profile roots;271/408 privilege rows; high/medium–high |Application lifecycle owner and auth catalog/loader/native projection, respectively. Not independently retested by47. Preserve explicit separate profiles and real token grants. Medium–high/medium risk; remain queued. |
| P1 | Windows and Linux runtime support / sibling_defect | Detection47, Host43/44; not labeled |733 Windows pairs minimum3.004s, command utilities included; medium–high |Workload runtime/lifecycle owner. Distribution evidence, not impossible individual lifetime. Filtering/overhead alternatives retained. Medium risk; preserve dependencies and source timing. |
| P1 | Multipart client/relay timing / sibling_defect | Threat44 carried, not labeled |One related upload case; qualified medium–high |Action bundle byte availability/client lifetime. Threat46 qualified file-analysis endpoints as exact commit times. Verify transport, same-content and termination semantics before changing timing. Medium–high risk. |
| P2 | Normalized remote-session closure observation / contract_gap | Detection45 carried, not labeled |One Mac SSH omission with native closure; medium |Observation grouping excludes logoff from remote tuple fate.48 bounded owner repair is prepared; tests cover Mac/Linux SSH and Windows RDP. It preserves actual missingness rather than forcing visibility. |
| P2 | Nikto labels / new_family carried | Threat46, not labeled |315 identifiers on316 requests across40 paths; medium |Scanner test/variant identity catalog. Custom/spoofed user agent remains plausible; low–medium risk after primary verification. |
| P3 | Shell FLOW ownership and console/storage leads / false_positive_or_unproven | Prior specialists, not labeled |Qualified carried leads; low–medium |Require actual socket-owner/ancestor contract and native platform references. No arbitrary parent changes or invented descendants. |
| P4 | Mac diagnostic palette and isolated1ms scheduling / false_positive_or_unproven | Threat47/Detection47, not labeled |Same-user39 commands; one1ms exit/fork perhost; low |Task/scheduling context explains repetition and individual coincidence. No timestamp randomization to conceal them; neither establishes a hard defect. |

## Next action

Complete the48 remote-session observation contract already selected from the reproducible carried omission. Then repair the newly proven captured-packet/history class and native ICMP state, retaining the stream-extent distinction from45. Continue canonical Mac identity allocation design as the highest-severity architectural issue, with explicit residual status. Keep the fixed scenario and warning deferral. Prefer concrete source contracts over vocabulary noise or unsupported source-completeness changes.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 24. The supplied slice is mostly production-like from a threat-hunting perspective: I could follow suspicious activity through process, authentication, network, and file evidence without establishing an impossible visible same-identity lifecycle. A limited repeated-command texture on the two Macs is a weak synthetic clue, but shared-user administration can explain it; the observable evidence does not reliably distinguish real collection from a capable simulation. The score describes appearance, not an estimated probability of synthetic origin.

**Detection Engineer:** Inconclusive; verdict confidence 78; synthetic-confidence score 45. The records are highly usable as detection telemetry: the sampled Windows event shapes, network tuples, process identities and visible lifecycle ordering mostly withstand direct checks. A notable Windows process-duration floor and a small repeated macOS timing interval suggest modeled timing, but I found no demonstrated impossible same-identity ordering or native-schema contradiction sufficient for a confident synthetic verdict.

**Network Forensics:** Synthetic; verdict confidence 95; synthetic-confidence score 90. The network dataset has credible protocol diversity, proxy behavior, certificate relationships, and connection/protocol correlation, but two reproducible source-native contradictions strongly favor synthetic data. ICMP records systematically use TCP/UDP-style connection states instead of standard Zeek ICMP semantics, and several TCP records claim fewer observed packets than their own recorded history requires.

**Host Forensics:** Synthetic; verdict confidence 87; synthetic-confidence score 78. Most endpoint evidence has convincing process, session, platform and source-correlation semantics. My synthetic verdict rests chiefly on four reversals of the native macOS fork identity-version allocation sequence on one host, while substantial Windows and Linux lifecycle checks passed; this is a localized identity-field problem rather than a dataset-wide failure of behavioral realism.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 38 | 96.09 | 40 | 38 | 62 | 69 | 52.25 | mixed/inconclusive | 62.25 | 51.75 |
| 39 | 96.09 | 44 | 20 | 30 | 66 | 40.00 | mostly realistic | 49.50 | 47.90 |
| 40 | 96.09 | 43 | 35 | 56 | 44 | 44.50 | mixed/inconclusive | 49.50 | 46.30 |
| 41 | 96.09 | 64 | 63 | 84 | 63 | 68.50 | likely synthetic | — | 49.90 |
| 42 | 96.85 | 38 | 53 | 32 | 65 | 47.00 | mixed/inconclusive | 59.00 | 50.45 |
| 43 | 96.31 | 32 | 54 | 68 | 62 | 54.00 | mixed/inconclusive | 63.75 | 50.80 |
| 44 | 96.31 | 54 | 28 | 83 | 64 | 57.25 | mixed/inconclusive | 72.25 | 54.25 |
| 45 | 96.31 | 35 | 34 | 65 | 29 | 40.75 | mixed/inconclusive | 49.50 | 53.50 |
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all117 data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

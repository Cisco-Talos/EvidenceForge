# Mac-series loop61: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop18 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **96.5587**, 136,440 records. Hard acceptance status **PASS**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat68 / Detection46 / Network24 / Host83**, mean **55.25** (mixed/inconclusive); lower is more production-like. Prior mean45.00; current rolling5 **52.05**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **76.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Native Mac evidence presence and authored timing

The causality evaluator now searches authoritative emitted Mac process/launch occurrence times while retaining each authored ResolvedEvent.time. Native ES exec matching requires trusted source-host provenance, exact canonical PID, executable, arguments and occurrence neighborhood. Exit matching requires the same stage's activated object identity/path. Parse errors and wrong host/PID/image/argv/time/stage fail. Cross-step unloads or later image changes without adequate exit facts remain conservative unmatched cases. This is bounded process/inventory support, not universal ES coverage.

Native parser fields remain native. Existing source_host provenance supplies a host pivot; the evaluator does not invent a username from an audit UID. Normalized file/object identity checks and policy-refusal ULF matching remain separate. Twelve new cases and224focused checks pass, including delayed execution at20/40minutes that is found but still scoreszero for authored temporal integrity. A direct-method fixture initially omitted pivot lookup maps normally installed by score(); corrected fixture and full checks passed before evaluation. Generation had already started during that test-fixture correction; no product code changed mid-run. Ruff passes and generation behavior remainsrevision459.

Fresh61has136440records/116files, every file byte-identicalto60. Common and carried repair probes pass; native90forks/106execs/88exits remaincomplete, mounted exits5/5. Mac native identity reversals remain unchanged.

Evaluation improves95.962601→96.558723. Expected-visible presence96/100→100/100, unchanged7contract exemptions; pivot152/189→170/189 (80.423280→89.947090); indicator1280/1298→1318/1336. Temporal90/100→91/100 reflects one newly found correctly timed trace; nine expected-visible steps still fail timing/order. Search anchors never become accepted authored-time anchors. Format-trace coverage stays134/142. Both60/61passhardgates; historical52–59REVIEWresults remain untouched.

Blind-score differences reflect different inspection of identical logs, not generation improvement. P0host-globalMacpidversion chronology remains open (Mac01twofork reversals,Mac02eight), requiring authenticated canonical identity/proof/checkpoint work; emitter renumbering is rejected. Next62targets simplex syslog route budgets and OS-aware forwarding hints;63targets canonical shell resume timing. Inode history, ICMPaggregation, hourlySSHclosures, multipartprogress, gpupdateartifact ownership and opaqueCONNECTbrowser-version identity remain qualified follow-ups. Baseline warning logic remains deferred by user request.


## Independent reviewer summaries

**Threat Hunter:** Synthetic; verdict confidence 82; synthetic-confidence score 68. The strongest synthetic evidence is repeated web-content texture across otherwise unrelated destinations: every successful full favicon response has exactly the same body length, and generic logos repeat the same path and length across many sites. Operational pivots through Linux SSH, database extraction, SMB staging, Windows collection, and proxy upload are substantially coherent; I found no demonstrated impossible same-process ordering in the checks performed. The verdict rests on measured baseline distributions, with weaker client-identity and command-vocabulary concerns, rather than the suspicious activity's completeness or narratability.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 46. The supplied logs are broadly credible and would support substantial SIEM parsing and correlation: the tested process identities, network tuples, certificate identities and visible lifecycles held together. A repeated Windows failure-reason mismatch and a smaller metadata-quality concern prevent an unqualified production verdict, but the demonstrated problems are too localized to establish that the whole dataset is synthetic.

**Network Forensics:** Real; verdict confidence 66; synthetic-confidence score 24. The network records are mostly production-like: transport states, protocol byte budgets, proxy topology, TLS certificate visibility, and source-local UID relationships withstand detailed checks. I found no demonstrated impossible network relationship; the main reservation is a narrowly timed appearance of ordinary TXT-query activity across many hosts, which is explainable and carries little weight.

**Host Forensics:** Synthetic; verdict confidence 94; synthetic-confidence score 83. The endpoint records have convincing process trees, stable binary hashes, source-specific timestamps, and coherent visible lifecycles. Nevertheless, both native macOS Endpoint Security exports repeatedly assign newer process births lower kernel identity versions than earlier births, while their wall clocks, monotonic clocks, and process start times all advance; this is a concrete native identity contradiction rather than an objection to collection completeness.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |
| 57 | 95.51 | 34 | 82 | 27 | 82 | 56.25 | mixed/inconclusive | 75.50 | 57.00 |
| 58 | 95.51 | 38 | 28 | 48 | 57 | 42.75 | mixed/inconclusive | 48.50 | 56.20 |
| 59 | 95.51 | 52 | 81 | 35 | 76 | 61.00 | likely synthetic | 69.75 | 53.60 |
| 60 | 95.96 | 29 | 81 | 38 | 32 | 45.00 | mixed/inconclusive | 71.25 | 51.90 |
| 61 | 96.56 | 68 | 46 | 24 | 83 | 55.25 | mixed/inconclusive | 76.00 | 52.05 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

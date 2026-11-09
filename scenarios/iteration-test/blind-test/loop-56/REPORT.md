# Mac-series loop56: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop13 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.5090**, 140,141 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat48 / Detection64 / Network43 / Host63**, mean **54.50** (mixed/inconclusive); lower is more production-like. Prior mean53.50; current rolling5 **53.05**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **64.25**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root-cause repair and exact scope

Zeek Files::Info.local_orig describes the actual file sender. The canonical network plan already contains originator and responder locality, while the file context owns sender direction. The typed file emitter and common sensor projection had both substituted the transport originator's locality. Revision455 combines the existing canonical facts through one shared native projection: choose local_orig for is_orig=true, local_resp otherwise. General HTTP/application transfers and TLS certificate chains use the same helper. The common sensor adapter uses its own frozen observation's endpoint locality; no IP-prefix guess, scenario edit or topology re-resolution was added.

Twenty-six new cases exercise direction, true/false/unknown locality, direct emission, differing sensor views, TLS certificate siblings and canonical immutability. Focused protocol/observation/TLS tests112 pass. The initial test omitted files routing, so the fixture was corrected to provide explicit sensor_formats; no production routing was loosened. Ruff passes.

Fresh output has140141records/117files. Only zeek-core/files.json and zeek-dmz/files.json changed;115 other data files are byte-identical to55. Every2434comparable single-connection file observation now agrees with the actual sender's endpoint locality in its own sensor conn row: zero mismatches, versus1417 in54/55. Connection identities, packet/byte ledgers, protocol times and all endpoint evidence remain unchanged. Common probes and inspected-client TLS wire-budget controls pass. Native Mac census remains95forks/111execs/93exits complete with zero aggregate starts; mounted exits remain11/11.

## Acceptance, remaining priorities and score interpretation

Automated evaluation remains95.509009 and the hard pivot criterion remains139/191=72.774869 below80. The run stays REVIEW, with the failing criterion retained separately in guardrail-review.json. This localized source projection repair cannot explain or repair canonical scheduling drift, native Mac matching false negatives or the Mac audit identity allocation order. Neither observation coverage nor thresholds changed. Baseline warning logic remains explicitly deferred by the user.

The next root target is a different shared request ownership leak: a nested client-side network plan can replace the proxy action's already-budgeted User-Agent using a process default. The independently reproduced57–59request discrepancies justify a planner/action boundary repair. Preserve pre-freeze process defaults and service/explicit caller intent, then require the frozen header to survive downstream unchanged. Highest unresolved P0 remains Mac host-wide audit pidversion chronology; counter renumbering in one emitter is unsafe because all frozen identity references, retained authenticated proofs, checkpoint and rollback semantics must agree. That architecture is explicitly deferred from the bounded locality repair, not claimed fixed by sorted source delivery.

Blind reviewer score movement must be read against this very narrow two-file change. Repeated findings in byte-identical endpoint or proxy files are recurrence/coverage evidence, not regressions introduced by file locality. Reports below preserve each reviewer's actual checks and any qualified alternative export/collection explanations.

## Fresh blind findings

Initial48/64/43/63 mean54.50, compared with55mean53.50. Detection independently verifies the4738SAM delta/token contradiction, a hard source-local inconsistency and next58target. Host focuses on seven exact1ms shell handoffs and a1us cleanup chain; its alternative caution about pidversion did not test the shared new-fork/exec allocator against fork/exec kernel implementation and does not refute the existing P0 proof. Network newly measures22/50longSSHflows closing within two minutes after clock-hour boundaries; inspect required-until and bootstrap lifetime ownership rather than add arbitrary jitter. Threat preserves the qualified multipart two-leg completion lead and a weak mobile-UA distribution concern. None of these families changed in56; treat them as persistent/deeper coverage, not locality regressions. Reviewer originals do not assign P0–P4 labels; synthesis priority labels are coordinator-added.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 48. The data supports practical investigations across a mixed enterprise fleet, with strong process/session ownership and generally coherent network pivots. I found a significant apparent timing inconsistency in a multipart upload and a weaker client-platform distribution anomaly, but neither establishes synthetic origin beyond reasonable collection or application explanations. Most of the examined operational chains work together, so this is a mixed assessment rather than a finding of broadly defective telemetry.

**Detection Engineer:** Synthetic; verdict confidence 83; synthetic-confidence score 64. The supplied logs are broadly usable by a detection stack: XML/JSON parsing, common Windows event shapes, process identities, and the tested Zeek joins are convincing. My synthetic verdict rests primarily on a narrowly scoped but concrete inconsistency inside an account-change audit record, with a repeated nonstandard Defender executable placement as supporting evidence; it does not rest on attack completeness, source completeness, or thin macOS coverage.

**Network Forensics:** Inconclusive; verdict confidence 83; synthetic-confidence score 43. The network records are substantially production-like: protocol state, byte accounting, TLS visibility, proxy behavior, and sensor-local references withstand several concrete consistency checks. The strongest concern is a measurable concentration of long SSH connections closing immediately after clock-hour boundaries across different clients and servers; this looks like a scheduling artifact, although a centrally enforced administrative policy could also produce it. I found no demonstrated impossible protocol ordering or certificate identity contradiction, so the evidence does not justify a confident synthetic verdict.

**Host Forensics:** Synthetic; verdict confidence 78; synthetic-confidence score 63. The endpoint data is substantially realistic: Windows process identities and executable metadata agree across sources, visible process lifetimes are internally consistent, and Linux authentication includes credible transport/authentication/session stages. My synthetic verdict rests primarily on a reproducible timing fingerprint in the native-looking macOS Endpoint Security stream: seven successive-command transitions land exactly 1,000 microseconds after a preceding child exit, followed by a shutdown chain spaced at exactly one microsecond. This is a localized distribution artifact, not a demonstrated impossible lifecycle; the strong Windows/Linux consistency limits the score and confidence.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

# Mac-series loop55: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop12 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.5090**, 140,141 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat58 / Detection34 / Network43 / Host79**, mean **53.50** (mixed/inconclusive); lower is more production-like. Prior mean74.00; current rolling5 **51.40**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **68.00**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Root owner and verified repair

The canonical lock/unlock action bundle and source timing planner already own dwell, reauthentication and immutable source timestamps. Windows legacy admission-order repair nevertheless changed a protected sibling when producers arrived out of simulated-time order. Revision454 makes both in-memory/raw normalization and spooled post-normalization honor the actual frozen-timing marker. Raw escape-hatch correction remains available. This is an adapter ownership repair, not new timing jitter or a replacement session planner.

Five focused cases cover reversed valid cycles, later raw state, mixed raw/frozen siblings and final memory/spool output. Together131 emitter tests,126 timing/cohort tests and163 selected slow exact-publication/finalization checks pass (420). Fixture corrections distinguish real trusted internal markers from old nonmatching test labels. The historical ICMP fixture now reflects the already-owned loop50 OTH/no-history contract. Ruff passes.

## Fresh output and hard guardrail

The fresh run contains140141 records in117 data files. Every data file is byte-identical to54. This objectively refutes the working hypothesis that the protected-timing adapter caused the benchmark's failed pivot gate. Do not claim the benchmark lock drift is repaired or attribute any score movement to changed endpoint evidence. The protected-timing regression is independently reproduced by tests, but its benchmark applicability is zero in this run.

Authoritative evaluation remains95.509009, with pivot-linkability139/191=72.774869 below80. Status stays REVIEW and hard acceptance false; no threshold, seed, authored baseline, scenario or observation coverage was changed. guardrail-review.json records the unresolved failure. Further investigation must reconcile actual canonical scheduling/source rows and distinguish native Mac matcher false negatives from genuine missing evidence and authored scheduling drift. In particular, a visible native ES launch with dropped normalized eCAR is not correctly supported by the current launch-item matcher. Preserve temporal drift findings even when correcting trace presence.

## Independent evidence and score interpretation

Threat55 independently reproduces57 unique proxy/client-side HTTP User-Agent disagreements across eight clients; repeat observations from a second sensor are not additional defects. Host55 reproduces eight newly allocated Mac audit identity version decreases plus seven exact1ms shell handoffs. These repeated concrete findings persist in unchanged output; their reappearance is stronger evidence than the variable standalone score. Network55 instead emphasizes a qualified TLS duration lower tail and responder application bytes on plain TCP syslog; label those as distribution/contract leads, not proven packet-level impossibilities. Full raw reports preserve collection alternatives and limitations.

Priorities remain P0 canonical Mac native identity chronology (repeated, high leverage, high-risk authenticated identity/checkpoint work); P1 shared request attribution/header truth (repeated, independently observed, medium-risk planner/bundle repair); P1 native file sender locality (high-frequency, source projection owner, low-risk); P1 failed pivot acceptance (actual failure, parser/matcher and canonical timing investigation). Qualified runtime/syslog texture follows verified contradictions. The baseline warning remains deferred as requested. The next loop targets the pinned, independently verified file-locality contract while preserving connection-locality semantics and all traffic/identity ledgers.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 80; synthetic-confidence score 58. This is operationally coherent mixed-fleet telemetry with usable process, authentication, network, and file pivots, but a repeated disagreement over client HTTP User-Agent values raises a substantive authenticity concern. Most lifecycle and transport checks passed, and apparent differences in HTTP body sizes were supported by explicitly recorded capture loss, so I cannot justify calling the dataset confidently synthetic from the supplied evidence.

**Detection Engineer:** Inconclusive; verdict confidence 80; synthetic-confidence score 34. The records are mostly production-like and would support practical detections, with plausible Windows schemas, usable process/session identities, and coherent network companions. The principal reservation is a Zeek certificate export that combines legacy FUID references with newer fields, rather than matching the modern stock schema; a custom export could explain it. I did not establish an impossible same-identity lifecycle or another hard contradiction, so the evidence does not justify a confident synthetic verdict.

**Network Forensics:** Inconclusive; verdict confidence 82; synthetic-confidence score 43. The network records are largely convincing: protocol references, TLS visibility, proxy byte accounting, DNS behavior, and independent sensor observations generally agree. A conspicuous lower tail in TLS flow durations and application payload returning on some nominally simplex TCP syslog sessions warrant suspicion, but I did not establish an impossible same-identity chronology or another decisive authenticity contradiction.

**Host Forensics:** Synthetic; verdict confidence 90; synthetic-confidence score 79. Most endpoint evidence is convincing: Windows process identities, binary hashes, user sessions, Linux authentication, and macOS fork/exec distinctions generally hold together. The strongest contrary evidence is localized to MAC-MROSS-02: newly allocated macOS audit-token identity versions repeatedly run backward despite increasing native event time and process start time, accompanied by seven exactly 1-millisecond shell-child handoffs. These are concrete native identity/timing defects rather than a judgment about how narratable the activity is.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 46 | 96.31 | 38 | 67 | 20 | 82 | 51.75 | mixed/inconclusive | 76.25 | 50.15 |
| 47 | 96.31 | 24 | 45 | 90 | 78 | 59.25 | mixed/inconclusive | 84.00 | 52.60 |
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

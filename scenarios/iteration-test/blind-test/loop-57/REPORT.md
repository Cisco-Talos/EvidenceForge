# Mac-series loop57: assessment and root-cause repair

Completed fresh validation, generation, authoritative evaluation and four independent data-only reviewers. Continuation loop14 of20 (44–63). Scenario, seed and observation/coverage controls remain fixed. Baseline-warning logic is intentionally deferred as user-requested P1 backlog.

Automated evaluation **95.5090**, 140,141 records. Hard acceptance status **REVIEW**; criteria are recorded in [authoritative eval](automated-eval.json) and [audit](artifact-audit.json). Initial synthetic-confidence scores **Threat34 / Detection82 / Network27 / Host82**, mean **56.25** (mixed/inconclusive); lower is more production-like. Prior mean54.50; current rolling5 **57.00**. Verdict confidence is separate.

Verdict/confidence/spread trigger required a fresh facilitator. Facilitator-modeled reconciliation mean **75.50**; [full report](deliberation.md). These are not reconvened votes and are excluded from initial/rolling trends.

## Shared request ownership repair

Proxy preparation already finalizes the actual HTTP header before source request-byte accounting, tunnel affinity and client-leg construction. A nested network planner nevertheless rebound that header to its browser process, producing different HTTP and proxy observations for the same request. Revision456 passes the existing supplied ProxyContext boundary into process-UA binding: bundle-finalized headers and known absence survive unchanged, while existing pre-freeze executable-version defaults remain. Transparent proxy evidence now uses the canonical HTTP request header instead of independently choosing another domain policy value after HTTP truth exists. This is a planner/action ownership repair; emitters still render existing contexts.

Fourteen new cases include browser, tool, service and custom finalized headers over GET/POST/CONNECT, plus known absence and unspecified process defaults.241focused network/proxy/Mac/TLS checks pass; Ruff passes. The first broader implementation preserved every nonempty browser hint, but two established executable-version contracts failed. It was narrowed to the actual finalized ownership boundary, and both unchanged tests now pass. This is not a new model of explicit browser spoofing provenance; that separate authoring distinction remains outside the bounded change.

## Fresh rendered proof and scope

All117freshdatafiles were compared with56. Only core/http.json and dmz/http.json change, leaving115files identical, including all proxy access, connection byte ledgers, file evidence and endpoints. The qualified unique client/UTCsecond/method/full-target comparison now finds zero header disagreements across1718core,1575DMZ and7DBmatches. The baseline55/56contains56distinct discrepant proxy requests under this probe's absent-header normalization; the threat reviewer counted57 under its own raw-string comparison. Sensor repetitions are not independent defects. The probe requires over1000baselinecorematches to prevent a vacuous-pass join and records the proxy's missing source-port limitation. Neither count is advertised as packet-level proof.

Proxy request-header lower bounds remain valid, and inspected-client TLS transport budgets still cover handshake and record overhead. File sender-locality mismatches remainzero; native census, mounted exits, fractional timing controls, ASA native order/reset and physical capture/history checks pass. Native Mac allocations remainchronologically defective: that P0 is not repaired by this HTTP projection change.

## Acceptance and review interpretation

Fresh140141records evaluate95.509009; pivot139/191=72.774869 remainsbelow80. Hardacceptance staysREVIEW with an explicit guardrail record, unchanged thresholds, authored inputs, seed and coverage. Since only two HTTPfiles change, endpoint reviewer findings/scores must be interpreted as differing investigative coverage, not endpoint regression or repair. A final request header can legitimately describe a service or custom application differently from browser inventory; preserving one actual header is distinct from claiming every header proves executable attribution.

Next58 targets the independently repeated Windows4738SAM mask/token contradiction at the account-change owner, removing contradictory text from both storyline and causal callers and deriving descriptions once. P0 canonical Mac counter chronology remains high leverage/high risk and explicitly deferred pending an authenticated output-selection-independent identity projection with recovery/rollback coverage. Further bounded targets include native sensitive-privilege membership, connect-only scan payload, source-aware Mac evaluator matching and ordinary simplex syslog accounting. Preserve qualified multipart completion and absolute-hour SSH timing leads for their correct canonical owners rather than altering rendered timestamps.


## Independent reviewer summaries

**Threat Hunter:** Inconclusive; verdict confidence 78; synthetic-confidence score 34. This is mostly convincing telemetry: the suspicious activity supports practical pivots between endpoint identity, remote sessions, network transports, and file movement, and the visible lifecycle checks did not produce a hard contradiction. There are mild signs of small activity vocabularies and generic administrative-command substitution, but these are explainable in real data and do not establish synthetic origin. The score reflects mostly realistic data with limited behavioral texture concerns, not certainty about its provenance.

**Detection Engineer:** Synthetic; verdict confidence 92; synthetic-confidence score 82. Most of this dataset should ingest successfully into a detection stack: the Windows event shapes, network protocol references, and visible process lifecycles are unusually well preserved, without being suspicious merely for matching. The strongest authenticity defect is in MAC-MROSS-02's native Endpoint Security process identity: newly created process versions repeatedly move backward across minutes of increasing event time and uninterrupted ES sequence numbers, contradicting XNU's shared identity allocation counter.

**Network Forensics:** Real; verdict confidence 62; synthetic-confidence score 27. The network evidence is mostly production-like: multiple observation points have plausible clock offsets, protocol records agree with their flow identities and visible intervals, and DNS, TLS, proxy, and transport behavior have meaningful variation. I lean real with limited confidence; the strongest adverse finding is a single in-window SMB conversation whose protocol records lack a corresponding same-sensor connection record, which could also result from collection or filtering.

**Host Forensics:** Synthetic; verdict confidence 95; synthetic-confidence score 82. Most of the Windows and Linux endpoint evidence is coherent, and the macOS evidence carefully distinguishes process lifetimes from successive executable images. However, one Mac's native Endpoint Security export repeatedly assigns newly forked children process-generation values that go backward in time, and the same export contains repeated exact one-millisecond exit-to-next-fork intervals. These concrete native identity and timing artifacts outweigh the substantial realistic detail elsewhere.


## Past ten Mac-series loops

| Loop | Eval | Threat | Detection | Network | Host | Average synthetic-confidence score | Interpretation | Deliberation* | Rolling5 |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 48 | 96.45 | 30 | 54 | 74 | 38 | 49.00 | mixed/inconclusive | 64.75 | 51.60 |
| 49 | 96.45 | 46 | 82 | 56 | 82 | 66.50 | likely synthetic | 83.00 | 53.45 |
| 50 | 96.47 | 46 | 82 | 72 | 32 | 58.00 | mixed/inconclusive | 79.00 | 56.90 |
| 51 | 96.47 | 67 | 28 | 58 | 32 | 46.25 | mixed/inconclusive | 58.75 | 55.80 |
| 52 | 95.78 | 35 | 36 | 32 | 43 | 36.50 | mostly realistic | — | 51.25 |
| 53 | 95.78 | 28 | 34 | 82 | 43 | 46.75 | mixed/inconclusive | 71.50 | 50.80 |
| 54 | 95.51 | 62 | 84 | 66 | 84 | 74.00 | likely synthetic | — | 52.30 |
| 55 | 95.51 | 58 | 34 | 43 | 79 | 53.50 | mixed/inconclusive | 68.00 | 51.40 |
| 56 | 95.51 | 48 | 64 | 43 | 63 | 54.50 | mixed/inconclusive | 64.25 | 53.05 |
| 57 | 95.51 | 34 | 82 | 27 | 82 | 56.25 | mixed/inconclusive | 75.50 | 57.00 |

* Facilitator-modeled reconciliation, not reconvened votes; excluded from initial and rolling trends.

## Artifacts and input limits

[Family contract](family-contract.md), [scores](scores.json), [readable eval](automated-eval.txt), [provenance](provenance.json), [test evidence](test-evidence.json), [artifact audit](artifact-audit.json). All four raw reports remain verbatim. The audit verifies score arithmetic, all recorded data hashes across authoritative/loop/neutral copies and unchanged authored inputs. Native Mac census, mounted exits and timing probes retain their separate evidence.

Accepted reviewers were delegated external data-only roles: neutral briefing/data and permitted primary public references; no scenario, source, TODO/worklog or prior reports. Generic inherited operating instructions remain an environmental limitation on strict origin blinding. Input audits rely on reported actual reads, not OS-enforced isolation. Suspicious commands were analyzed as inert log evidence. Final20-loop dashboard is due after63; historical43 dashboard is preserved.

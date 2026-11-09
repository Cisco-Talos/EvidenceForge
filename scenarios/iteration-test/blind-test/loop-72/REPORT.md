# Loop 72 — Browser root ownership verification

## Score summary

| Loop | Automated eval | Threat synthetic-confidence | Detection synthetic-confidence | Network synthetic-confidence | Host synthetic-confidence | Average synthetic-confidence | Interpretation | Deliberation | Rolling5 |
|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| 72 | 96.1181 PASS | 52 | 24 | 38 | 48 | 40.50 | mostly realistic | 40.50 | 43.75 |

Average verdict confidence is 66.0. The verdicts disagree (Threat: Inconclusive; Detection: Real; Network: Inconclusive; Host: Inconclusive), so the expert deliberation was triggered. The synthetic-confidence spread is 28.0; that trigger was not met.

## Selected family and outcome

The selected family was profile-scoped browser root ownership, retained by the loop65/68 panels and prioritized after session-specific SMSS was repaired in loop71. The owner is the shared canonical process state and browser-instance identity/reuse policy. The required invariant is one reusable live browser root per host, user, executable and resolved user-data directory for ordinary requests, while explicit independent profiles remain distinct and native lifecycle records follow the canonical process lifetime.

Current code already includes this shared identity/reuse model. On the unchanged fixed-seed benchmark, the Mac native output has exactly one visible Chrome main-root exec on each Mac host, with separate helper processes; both roots have visible exits in the six-hour slice. Windows Sysmon process intervals show at most one concurrent Chrome root per observed host/user; WS-PPATEL-01's two roots are sequential. These results verify the earlier browser-root finding is not present in this current candidate. Classification: `false_positive_or_unproven` for current output, not a new code fix. The 12 focused browser-instance tests passed.

## Evaluation and generation

Scenario validation and generation completed using the unchanged benchmark and seed 42. The validator reported the existing low-baseline warning and storyline pivot notices only. The authoritative bundle has 141,745 records across 115 data files. Automated evaluation is 96.1181 PASS: parseability 100, plausibility 96.8680, causality 95.7186, timing 89.8573. This is the same score and record count as loop71; no automated-eval regression is indicated.

The neutral reviewer copy contains only the 115 `data/` files and is byte-identical to the authoritative data. Scenario, environment, ground truth, evaluation output, code, and prior reports were not copied into the reviewers' directory.

## Independent panel and deliberation

The four standalone scores are Threat 52, Detection 24, Network 38 and Host 48, averaging 40.50. Three reviewers assessed the data Inconclusive; Detection assessed it Real. No reviewer reported a hard contradiction. Threat and Network independently noted repeated activity from `10.10.3.10`: randomized `.top` DNS queries and unanswered internal S0 probes to `10.10.2.30:8080/443`. Both treated it as ambiguous and potentially consistent with beaconing, monitoring, or unavailable services. Detection noted a compact Linux administrative command burst and Security Event 1102 on DC-01; neither was established as a synthetic-only defect. Host noted concentrated incident-like behavior but found no impossible ordering; concentration alone is not used as an authenticity indicator.

Loop68's mean was 36.00 and loop69–71 were 48.50, 45.25 and 48.50. The loop72 mean is down eight points from loop71; this loop made no code changes, so the movement is reviewer/sample variance rather than a measured fix effect. The five-loop rolling mean is 43.75. The standalone assessments are not a paired experiment.

### Individual expert summaries

**Threat Hunter — Inconclusive, confidence 62, synthetic-confidence 52.** The DB-to-application-host SSH transfer and Nikto scan had plausible multi-source corroboration. The repeated randomized `.top` queries from `10.10.3.10` raised distribution questions, but the analyst found no impossible ordering.

**Detection Engineer — Real, confidence 68, synthetic-confidence 24.** Native event schemas, process lifecycles, Zeek UID references and eCAR/Zeek joins were coherent. A compact Linux `sudo` burst and DC-01 Security Event 1102 were flagged for context, not as proven synthetic defects.

**Network Forensics — Inconclusive, confidence 68, synthetic-confidence 38.** Flow states, payload accounting, DNS/TLS timing and certificate references appeared coherent. The repeated unanswered probes from `10.10.3.10` to `10.10.2.30:8080/443` were ambiguous and may be monitoring or an unavailable backend.

**Host/EDR Forensics — Inconclusive, confidence 66, synthetic-confidence 48.** Windows, Linux and macOS process/session lifecycles and sampled cross-source joins were plausible. The concentration of several incident-like behaviors in one slice was noted as weak distribution evidence, with no hard contradiction found.

### Deliberation findings

The deliberation retained the verdict split and all initial scores because no reviewer submitted a revised position. The panel agreed that no hard contradiction or schema defect was established; it left the DNS/probe pattern and Event 1102 as contextual leads. Its consensus recommendation is to retain DNS/proxy/process and backend health-check context for `10.10.3.10` and `10.10.2.30`, rather than alter generation based on suspicion alone.

## Comparison with quantitative evaluation

Automated evaluation passed with the same overall score and record count as loop71. Its parseability, canonical cross-source invariants and schema checks do not assess whether the `10.10.3.10` query/probe pattern is an intended threat activity, a health check, or unrealistic distribution texture. The expert panel did not identify a parseability, event-shape or join defect that would contradict the quantitative result.

## Reported issues and next priority

| Priority | Issue | Category | Reviewer original rating | Score impact / scope | Owning layer and next action |
|---|---|---|---|---|---|
| P2 | Repeated web-host-origin DNS and unanswered internal probes | `environment_or_collection_plausibility` | not labeled (Threat, Network) | Medium / recurring across the six-hour view; weak and ambiguous | Qualify the shared web-host network activity owner and destination role before editing. Preserve deliberate threat activity and plausible health checks; seek a concrete source-visible lifecycle or distribution defect. |
| P3 | Compact Linux administrative command burst | `distribution_texture` | not labeled (Detection) | Low / one host and short window | Check workflow/action timing only if the same burst recurs independently and has a generator-level cadence fingerprint. |
| P3 | DC-01 Security Event 1102 logged by SYSTEM | `environment_or_collection_plausibility` | not labeled (Detection) | Low / one event | Treat as operationally suspicious, not a synthetic defect; no realism change is supported. |

The loop72 deliberation is saved separately. The next loop should investigate the repeated 10.10.3.10 network behavior from the owner’s perspective. Do not change data based only on its suspicious appearance: reviewers explicitly considered genuine beaconing, monitoring, and unavailable-backend explanations, and the authored storyline may intentionally contain threat activity.

## Artifacts

Family contract, raw reviewer reports, deliberation, automated eval, browser-root probe, test evidence, provenance and data hash manifest are stored in this directory. Fixed-seed data is at `/private/tmp/eforge-iteration-test-loop72/bundle`; the data-only blind copy is at `/private/tmp/log-study-loop72/dataset-lake`.

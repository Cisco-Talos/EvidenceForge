# New assessment epoch — loop 5

The expanded canonical scenario and existing full reviewer instructions are unchanged.
Behavior 538 fixes shared protocol progress across TCP teardown states. This loop
contains no scenario changes and no score comparison with prior epochs.

## Scores

Automated evaluation **PASS 98.2773**, **140,430 records**. Parseability 100,
plausibility 96.9232, causality 99.6124, timing 98.1141, ground truth 96.7368.
No automated regression guardrail breached; JSON computed once, text derived.

| Expert | Initial assessment | Verdict confidence | Initial synthetic confidence | Actual deliberation |
|---|---|---:|---:|---:|
| Threat Hunter | Synthetic | 80 | 65 | 73 |
| Detection Engineer | Inconclusive | 88 | 46 | 67 |
| Network Forensics | Inconclusive | 82 | 38 | 65 |
| Host/EDR | Synthetic | 84 | 66 | 72 |
| Mean | | | **53.75 — mixed/inconclusive** | **69.25 — likely synthetic** |

Lower synthetic confidence is better. Initial mean rose 6.25 from loop 4; rolling
five-initial-score mean is 48.1. Deliberation scores do not enter that trend.
Different initial verdicts triggered actual reconsiderations from all four original
reviewers, followed by a fresh facilitator; all final verdicts are Synthetic.
Original reports/responses/synthesis remain verbatim. No unconditional native
impossibility was established.

## Family repair and proof

Classification **family_level**; owner NetworkTransactionPlanner and shared TCP
application-progress/accounting helpers. See family-contract.md for entry paths,
consumers, invariants and sibling risks. HTTP/TLS success is no longer conditional
on a final SF conn_state. Eligible bidirectional reset/half-close flows can carry
application evidence, preserving the actual teardown state and coherent payload,
history, packets and timing. OTH fragments, unanswered probes, raw/suppressed and
partial failed TLS do not acquire invented fresh completed exchanges. Persistent
HTTP channel reuse remains SF-only. Baseline HTTP duration budgeting adapts to
the existing shared completed-exchange bound.

Rendered protocol probes find **187 SSL observations** in reset/half-close states
with SSL evidence (core 42, DB 5, DMZ 140), and **13 DMZ HTTP non-SF observations**
with HTTP companions. These are not matched pre/post flows: changed planning/RNG
changes the population. OTH fragments retain distinct treatment. Focused canonical,
native, byte/history/close-budget checks passed (197), plus proxy/identity/lease/
terminal/IDS siblings (137); Ruff/format passed. Broad routine suite has not
completed and no release-readiness claim is made.

## Findings and priorities

Priorities/categories below are synthesis, not labels assigned by reviewers.

| Priority | Finding and classification | Reviewers, scope, alternatives | Owner / next action / risk |
|---|---|---|---|
| P1 | Downloader command/file/socket ownership; contract_gap, new_family | Threat first, all actual deliberators confirmed. Windows PID 7704 writes connector-check.exe but helper 7712 owns request port 57407; Linux 2959192/2959193 repeats. Helper root URL disagrees with inspected tools path. Configuration/telemetry alternatives prevent unconditional impossibility. | Canonical proxy caller attribution and command intent. Reuse compatible original downloader and actual target URL; preserve method/body/session/lifetime checks. High leverage, medium risk. |
| P2 | RDP smss→winlogon concentration; distribution_texture, sibling_defect | Host first, all deliberators reproduce eleven pairs: eight .500 s, three .499 s across five hosts. Other interactive pairs span .363–1.225 s. Genuine timer/collection transform possible. | RDP bootstrap phase graph, preserving transport/auth/client-lifetime/deadline contracts. Medium leverage/risk. |
| P2 | Mac native fork fractional phases; distribution_texture, new_family | Detection and Host independently; all deliberators. Two three-fork clusters retain exact microsecond phase and integer monotonic intervals, among 47/58 forks with 45/56 distinct fractions. Scheduling/transform alternatives remain. | Canonical process intent realization versus authored scheduler anchors; investigate supported phase timing, never emitter-only jitter. Medium leverage/risk. |
| P2 | Anacron startup precision; distribution_texture, sibling_defect from loop 4 | Root probe still 10/10 aligned, 0/40 followups, 3/4,372 others. Not newly discovered by panel 5. | Shared source observation delay sampler; loop 6 targets integer-ms quantization without changing loss decisions. |
| P3 | RDP target authentication lag; distribution_texture, sibling_defect | Earlier panel/root probes retain target-specific clusters; not a new panel-5 finding. | RDP negotiation versus source visibility readiness. Inspect independently of bootstrap timer. |
| P4 | Mounted cat/document runtimes; false_positive_or_unproven at present | Threat reduced weight during actual deliberation; storage/output backpressure plausible, no new command-only impossibility. | Workload intent/native capability. Do not invent GUI behavior or tune exact samples. |
| P4 | Missing SMB UID/FUID enrichment; false_positive_or_unproven | Network expressly withdrew minor initial SMB provenance weight during deliberation. Detection did not score eight FUID gaps. No demonstrated collection-completeness contract. | Record usability caveat; absence alone is not synthetic evidence. Preserve actual initial score rather than rewriting it. |

Threat's strongest contribution is request intent rather than mere matching IDs;
Detection's parsing/identity/lifetime successes remain valid alongside native timing
texture; Network retains realistic TLS visibility, packet accounting and sensor
clocks; Host adds a distinct RDP bootstrap distribution. Deliberation explicitly
separates correlation from semantic ownership, and numerical rechecks from reliance
on another expert's source corroboration. Native Mac job-control qualification,
editor/snapd habits, exit outcomes and ambient DNS remain separate bounded leads.

## Interpretation and provenance

Higher initial scores reflect new semantic/timing findings and differing coverage;
the rendered protocol family demonstrably improves. No evidence establishes those
new concerns as caused by the protocol fix. Do not roll back a canonical repair
merely because fresh reviewers noticed another family. Continue shared source
precision (loop 6), then the repeated proxy intent contract gap.

Behavior 538 digest 044399841629e73f6d7168bfca424efc6e7b93e386288c2e527bff5b651ebcd7,
seed 42, unchanged four authored input hashes. Generation exited 0 with authoritative
manifest. Fresh verified data-only study /private/tmp/authenticity-study-i5fgenre,
four fresh fork-none reviewers, unchanged briefing/personas/examination requirements.
No engine change or prior finding was supplied to reviewers. Candidate trial remains
separate; previous scenario YAML versions remain preserved.

Post-panel recurrence probe: the same positive downloader/file-versus-helper/socket
split is visible in frozen loop 4 too (Windows 8064 versus 8076; Linux 2959192 versus
2959114). This establishes that the newly noticed ownership gap predates behavior
538, rather than being introduced by the TCP teardown repair. Evidence is saved in
loop-7/prior-download-ownership-probe.json and this loop's download-ownership-probe.json.

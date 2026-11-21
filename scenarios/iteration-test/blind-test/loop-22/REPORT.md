# Loop 22 — Windows close clocks and Linux console admission

Epoch:2026-11-20-realism. This is actual new-epoch loop22 of30, using the same
four authored scenario/input hashes as loop1. No previous epoch or candidate
scores are inherited. Existing reviewer instructions were unchanged.

## Results

| Independent reviewer | Verdict | Verdict confidence | Synthetic-confidence |
|---|---|---:|---:|
| Threat Hunter | Inconclusive | 85 | 31 |
| Detection Engineer | Real | 68 | 18 |
| Network Forensics | Real | 64 | 29 |
| Host/EDR Forensics | Real | 61 | 28 |

Initial mean26.50/100, mostly realistic; lower is better. Change from21 is−32.75.
Five-loop initial mean44.40. Initial scores alone enter the trend. Deliberation
was triggered by differing verdict labels; actual four revised scores29/27/30/34
produce mean30.0, mostly realistic. The hunter retained Inconclusive, the other
three retained qualified Real. Verdict confidence is not synthetic-confidence.
See the four original reports, actual responses and fresh facilitator summary.

Automated eval98.29981680873311, PASS/accepted,144765records. JSON evaluated
once and human-readable text derived from that same report. Parseability100;
plausibility96.8271556913692;causality99.4979737345429;timing98.34262551730511;
ground-truth96.8313291004483. This is unchanged from21 and above the dynamic
regression guardrail. One already-completed RDPcloseacknowledgment still lacks
a separate canonical occurrence for the closing intent, although the native
close exists under its opening intent; keep the diagnostic visible. No evaluator
weakening or fabricated duplicate close was used.

## Selected families and owner contract

Classification: adapter_to_family_model. Two callers incorrectly clamped
canonical Windows close against a future source-create admission headroom.
SourceTimingPlanner already owns source-local lifecycle containment. Windows
process user/system termination now retain canonical execution time and defer
source containment to that existing owner. Real activity, children, transport
holds and authoritative session deadlines remain enforced. The fix does not
shrink command lifetime policy or host clock offsets, invent short rows or patch
Sysmon timestamps. Both process execution termination and system-process close
entry paths are covered. Consumers are Security, Sysmon, eCAR, process/session
lifecycle and foreground readiness. Generic nonauthoritative session cleanup
retains its separate actual-source floor; no whole-session redesign is claimed.

Second adapter: the new Linux console planner from21 now reserves a newly
activated getty early enough for existing Linux source-create headroom, then
checks the complete activation-to-login interval for terminal occupancy. The
400ms configured lead alone was insufficient on some hosts. The pure planner
checks bounded retained closed processes as well as live/future reservations;
no new StateManager fields, runtime cache, quotas or retention increases.
Already-idle getty, GDM, SSH and frozen legacy child paths remain distinct.
The policy owner remains the common console plan and source timing profile.

## Verification and native output

Before fixes, four controlled Windows500ms cases failed under two observation
profiles for both user/system paths; a console400ms case and two retained
terminal-interval controls also failed against frozen558. After fixes:379owner/
manifest cases passed10.30s;98native consumer cases passed259.70s; dedicated
console publicCLI/checkpoint case passed73.68s; two Windows default/sof generation
cases passed107.60s. Global RNG census3passed7.70s unchanged; validate-config105
files zero issues; Ruff check/format1678files passed. Earlier overly broad
checkpoint selection was interrupted after its first console PASS; do not
claim its seven unexecuted Mac matrix variants passed. No full routine or
release gate is claimed.

Actual runner56458 completed generation and post-processing EXIT0 before any
next engine edit. Revision559 digest030736207347c6b782c54d35316c2f1c75131e2381bcc5908d678671fad5f3a5.
GENERATION_MANIFEST exists; seed42/default. All four authored hashes remain fixed.
A neutral118-file data-only SHA-verified copy was independently reviewed by four
fresh agents; they received no scenario, GT, evaluator, code, prior findings or
targeted examination additions. A fresh facilitator read four actual independent
responses rather than inventing a discussion.

Native Windows lifetimes:754Sysmon pairs,min1.409s,25under3s;755Securitypairs,
min1.234483s,30under3s;749eCARpairs,min1.234s,29under3s. All have zero negative
and zero subsecond lifetimes. Before21Sysmonminimum3.029s/noneunder3s. The
controlled500ms cases prove that such completions are supported; the benchmark
need not contain a subsecond instance. Console output retains10same-lifetime
getty→login execs rather than separate children. All118nativefile SHA compared
21vs22: only30Windows files changed, same byte lengths; all88otherfiles are
byte-identical. This is a file scope check, not a parsed-field-only claim.

## Score interpretation

The two selected fixes remove controlled owner/admission defects. They cannot
explain the entire32.75-point blind decrease: the proxy/network/Linux/Mac output
reviewed here is byte-identical to21, yet reviewers selected substantially
different concerns. In particular, no22reviewer raised the prior opaque proxy
stream accounting gap. Its absence from a report does not establish a repair.
The movement is principally reviewer attention/threshold variance combined with
a concrete Windows duration correction. No causal score-improvement guarantee
or statistically calibrated provenance probability is claimed. A repeat frozen
engine assessment can quantify this uncertainty without changing the scenario.

## Findings and next priorities

Original reviewer severities are not labeled; the reports use weak_signal. The
priorities below are synthesis, not a replacement for original reviewer scores.

| Priority | Finding / classification | Reviewer and scope | Leverage / owner / risk / disposition |
|---|---|---|---|
| P1 | Opaque CONNECT paired stream budget mismatch; sibling_defect from21, not rediscovered22 | Prior NF/DE, controlled18request recheck | High; paired proxy/network/TLS precommit planning; high risk; deferred explicit contract23, no access-log patch |
| P2 | Direct finite vmstat completion differs from sudo; new_family | TH and all four deliberation rechecks; two direct3.054/3.518s vs four sudo5.706–6.124s | Medium; shared command runtime policy; bounded risk; selected24 after primary syntax qualification, cancellation remains possible |
| P2 | Same-path curl UA7.88.1→7.81.0; false_positive_or_unproven as engine defect | TH; same host/user/shell, two operations; all four rechecked | Medium; authored request intent vs installed tool/header owner; defer because support connection explicitly authors UA, do not change frozen scenario |
| P2 | Default scheduled Defender placement/product release; new_family from21 | Prior Host,12launches/all10Windows hosts | Medium; installed deployment compiler/catalog; medium risk; separate candidate24, path-only change would retain wrongOSbuild version |
| P3 | Four near900s Windows worker lifetimes; false_positive_or_unproven | Host, four/754pairs; taskhostw and conhost on two DCs | Low; role-specific timeout/lifetime policy; preserve plausible shared timeout pending evidence, no arbitrary jitter |
| P3 | TLS short tail; false_positive_or_unproven | NF;3234DMZ443SSL,12over60s | Low; application/proxy workload and export semantics; do not add arbitrary long flows based solely on SNI |
| P3 | One SMB mapping UID absent from conn; false_positive_or_unproven | NF weak, DE no score;1/145; cross-checked by all | Low; export/window/observation contract; visible client terminates17:35 so postwindow client explanation is not established; row loss/filtering still possible |
| P3 | CUPS discovery bare numeric endpoint; source_native_single_schema | Prior DE11rows/3hosts, unchanged here | Low; existing correlated named syslog profile; bounded23adapter, no claim of complete CUPS package/collector fidelity |
| P4 | Fixed authored Mac command phases and inode population | Earlier Host recurrence, not raised22 | Benchmark timing is frozen; coherent installed-filesystem snapshot is architectural follow-up; no output-clock jitter |

The prior4658ProcessName allegation was false: Microsoft nativeVersion0XML
contains that field. It is excluded from repair priorities and original reports
remain untouched. NativeMac equal-millisecond eCAR parent/child serialization
concern was independently resolved against earlier ES parent exec and child fork.
No narrative completeness, source completeness, absent event family, domain
resolvability or filesystem copy timestamp was scored as a defect.

## Residual limits

Native Linux console policy remains bounded, not a complete idle-getty supervisor
or every PAM close/configuration contract. Existing source providers and Mac
qualified process families retain their documented bounds. No quotas, census
limits, output filtering or reviewer requirements were relaxed. Follow-up should
address demonstrated shared ownership gaps and preserve legitimate timeouts,
interruption and partial observation rather than manufacture variety.

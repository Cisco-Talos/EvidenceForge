# New assessment epoch — loop 4

Unchanged expanded canonical scenario and reviewer instructions. Behavior 537
repairs eCAR process-transition collector timing; the independent evaluator's
receipt-policy compatibility correction is documented separately. Generation and
native source content remain frozen; behavior 538 belongs to loop 5.

## Scores

Corrected automated evaluation **PASS 98.5941**, **144,150 records**. Parseability
100, plausibility 96.8911, causality 99.7544, timing 98.9927, ground truth 97.3324.
The first failed evaluation and reason for reevaluation are preserved below.

| Expert | Initial assessment | Verdict confidence | Synthetic-confidence score | Actual deliberation score |
|---|---|---:|---:|---:|
| Threat Hunter | Inconclusive | 80 | 44 | 63 |
| Detection Engineer | Inconclusive | 76 | 40 | 64 |
| Network Forensics | Inconclusive | 82 | 44 | 65 |
| Host/EDR Forensics | Synthetic | 74 | 62 | 66 |
| Mean | | | **47.5 — mixed/inconclusive** | **64.5 — likely synthetic** |

Lower synthetic-confidence scores are better. Initial mean increased 6.5 points
from loop 3; five-score rolling mean is 46.6875 (n=4). Only initial independent
scores enter trends. No previous-epoch/candidate scores are included.

## Individual expert summaries

Threat Hunter verified the approved download/execute/subsequent-command paths,
Mac manifest read/save, SSH transport/authentication separation and Windows/Linux
credential/transfer pivots. Its main concern remained seven cat reads of office-
format filenames and related longer runtimes; it qualified storage/output delay
and an unscored mysqldump output-ownership ambiguity.

Detection Engineer found convincing schemas, identity/lifecycle relationships,
TLS visibility and source-specific field encoding. All-zero Security 4689 and
native Mac exit statuses were a mild distribution concern; five Unified Log
records' round sender offsets were weak. Nonzero NTLM LogonGuids were explicitly
not declared impossible. Initial score 40, confidence 76.

Network Forensics found no hard network contradiction. Thirteen RDP transport to
logon intervals cluster by target: DC-02's four span 27.954 ms and FILE-SRV-01's
three span 14.012 ms despite separate sessions/principals. DNS queries recurring
inside positive TTLs were weak because resolver/cache policy is unknown. Initial
score 44, confidence 82.

Host/EDR's main finding was message-dependent precision: all ten anacron startup
syslog timestamps end in three fractional zeroes, versus none of forty follow-on
messages and five of 4,080 other rows. It treated common maintenance scheduling
as a possible explanation for clustering, not the precision boundary itself.
Windows/native Mac identity and lifecycle checks remained convincing. Initial
score 62, confidence 74.

## Deliberation

Different initial verdicts triggered the existing procedure. All four actual
reviewers reproduced the anacron precision boundary and rechecked RDP timing,
including native Security 4624 timestamps. Final actual scores were 63/64/65/66,
all Synthetic with moderate confidence and explicit collector/workflow
alternatives. Original reports, four individual responses and fresh facilitator
synthesis remain verbatim. No hard contradiction was established; deliberation
scores are excluded from the independent trend.

## Family repair and verification

Classification `family_level`; owner SourceTimingPlanner's shared endpoint
collector queue. Canonical native intervals already existed, but process birth
used the 8–950-ms collector profile while exec/audit/credential/job-control used
an unrelated 1–35-ms profile. The order repair then compressed short intervals.
All five state transitions now share the birth collector's coherent queue with
independent residuals; generic file/module/network profiles and lifecycle/close
constraints remain separate. Full invariant, entry paths, consumers and sibling
risks are in family-contract.md.

Rendered first CREATE/exec pairs: **25/98** now have gaps <=5 ms, versus **98/98**
in loop 3; native ES has 19/98. Median absolute elapsed difference from native ES
is **0.516 / 0.482 ms** on the two Macs, previously 7.405 / 5.957 ms. Native ES
files are SHA-identical before/after. Maximum elapsed differences remain about
11 ms around other constrained source/credential stages; exact cross-source
clock equality is not required or claimed. All data files except the two Mac
eCAR files are SHA-identical to loop 3 (source-content-comparison.json).

Focused producer checks: **102 source-timing tests**, **532 sibling tests**
(22 deselected), including SSH PTY, native publication and audit bindings. Ruff,
format and behavior surface checks passed. Broad routine suite has not completed;
no full-suite/release-readiness pass is claimed.

## Evaluation guardrail investigation

The first evaluation returned **FAIL 96.5294**, ground truth 87.0088, with 153
process timing policy identity errors and three extra unjustified-time findings.
Other pillars and native data were unchanged. The independent receipt verifier
still required only the historical dependent profile for the five transition
phases; the producer correctly recorded the shared creation collector it used.

The evaluator now permits only the known historical/current policy choices for
those five phases and uses the validated chosen profile's bound. Phase, identity,
native time, independent predecessor existence/order and delay checks remain
active, and unknown policies still fail. This consumer update is
`adapter_to_family_model`, preserving historical frozen receipts. New tests cover
both policies, invalid policy/time/anchor controls and actual producer-receipt
round trips for all five phases: **64 unit tests passed**; the broader related
unit/integration set **87 passed**, including 28 reconciliation integrations.
Those counts overlap and are not summed as independent tests.

The failed JSON/text are retained as before-proof-policy-*. The evaluator change
justified one new evaluation, now PASS 98.5941 with the same remaining failure
counts as loop 3. No generated data was rewritten or regenerated for this
correction. Details are in evaluator-policy-repair.md.

## Prioritized reported issues

Reviewers supplied no P0–P4 labels; priorities/categories/recurrence below are
synthesis. No P0 source-native contradiction was established.

| Priority | Issue/category | Classification, reviewers and scope | Original rating | Leverage / owner / risk / next action |
|---|---|---|---|---|
| P1 | State-conditioned TLS/HTTP availability; distribution_texture | `new_family` carried from loop 3; Network and all actual deliberators there. Root probe confirms it remains here; no new claim by panel 4. | not labeled | High/medium; canonical network protocol progress and TCP accounting. Medium risk. Loop 5 targets supported exchanges across resets/half-closes while retaining true partial/probe evidence and close budgets. |
| P1 | Anacron startup precision boundary; distribution_texture | `new_family`; Host, independently reproduced by all during deliberation and root probe. 10/10 startup rows millisecond-aligned, 0/40 followers, 5/4,080 others. | not labeled | High/medium; canonical daemon startup and source-time precision ownership. Low/medium risk after identifying why lifecycle onset is quantized. Verify siblings; do not add one-message cosmetic jitter. |
| P2 | RDP target-specific authentication lag; distribution_texture | `new_family`; Network and all actual deliberators, including native 4624 checks. Small per-target samples; stable clocks/auth infrastructure remain alternatives. | not labeled | Medium; RDP action timing versus source clock offsets. Medium risk. Separate real negotiation variation from host clock skew, retain transport-before-auth and source-client lifetime. |
| P2 | Mac tool/document binding; distribution_texture | `sibling_defect`; Threat. Same seven office-format cat reads and 10–30-s runtimes; storage/terminal alternatives remain. | not labeled | Medium; actual file-access intent, SMB client workload and qualified application capability. Medium/high risk. Do not invent GUI opens or infer contents solely from extension. |
| P3 | All-zero endpoint exit statuses; distribution_texture with weak causal support | `new_family`; Detection, rechecked in deliberation. 795 Security 4689 statuses and 102 Mac native wait statuses are zero. No visible failed command is proven inconsistent. | not labeled | Low/modest; canonical termination outcomes and qualified native projection. Medium/high scope risk. Retain real modeled failures where supported; do not inject arbitrary errors or unqualified native outcomes for entropy. |
| P4 | Within-TTL repeated DNS; weak_signal | `false_positive_or_unproven`; Network. 84 client/name pairs; direct resolver queries, bypass and invalidation can explain them. | not labeled | Low; resolver ownership/cache semantics. Verify mechanism before treating every repeat as an OS-cache violation. |
| P4 | Round Unified Log sender offsets; weak_signal | `false_positive_or_unproven`; Detection. Five records/three offsets. Binary call-site reuse and small scope limit inference. | not labeled | Low; qualified source-native call-site profile. Require representative native evidence before inventing offsets. |
| P4 | Narrow inventory vocabulary and mysqldump writer ambiguity; weak/unscored | `false_positive_or_unproven`; Threat. Valid support commands and shell-redirection attribution alternatives remain. | not labeled | Low; task/workflow and process/file ownership. No exact-sample command renames or extra source requirements. |

Earlier Mac job-control qualification, Linux editor preferences, snapd texture
and ambient TXT investigations remain separate leads. This panel did not newly
establish those findings. Existing good credential, proxy, native identity and
protocol visibility contracts must survive future changes.

## Score movement, priorities and limits

The higher initial mean reflects new findings and different reviewer coverage,
not evidence that the source repair caused anacron/RDP/exit artifacts: all of
those native/network files are byte-identical to loop 3. The targeted Mac timing
probe improves substantially. Continue with the verified shared protocol owner,
then investigate the new multi-reviewer timing families. Do not roll back a
verified owner fix merely because independent reviewers noticed other tells.

Automated eval remains a structural/causal guardrail. Its initial failure exposed
a real validator/producer contract mismatch and was investigated and repaired;
it did not justify hiding data or lowering acceptance thresholds. The anacron,
RDP and tool-selection findings remain outside its principal checks.

## Provenance

Behavior 537, digest 101ae72d399f6a468788c604af9f57e545de6afdf0c8816f70d2a59e581edfb1,
seed 42. All four authored input hashes match loop 1; validation reuse is recorded.
Generation exited 0 with authoritative manifest. Four fresh fork-none reviewers
used `/private/tmp/authenticity-study-ds7oo6xe/data`, a verified neutral copy;
briefing/persona and examination requirements remained unchanged. Neither the
evaluator repair nor prior findings were supplied to reviewers.

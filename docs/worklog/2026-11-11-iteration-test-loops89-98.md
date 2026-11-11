# Iteration test loops 89–98

## Current handoff

All ten requested loops 89–98 and 40 independent blind reviews are complete. Final standalone mean
synthetic-confidence is 20.75; rolling-five mean is 24.70. Final authoritative bundle is
`scenarios/iteration-test/blind-test/loop-95/bundle` (seed 42, default target, behavior 509), with
147,759 records and 118 data files. Current automated evaluation is 94.6124 FAIL: ground-truth
agreement 88.3573 remains below 95. Six owning-layer repair families are documented below; the
scenario and product version are unchanged. After assessment completion, the user requested
committing and pushing this work to the existing `dev` branch; no release was requested.

The final report and XML-verified last-20-loop SVG are in `scenarios/iteration-test/blind-test/`.
Focused validation passes 255 tests plus 1 targeted RDP slow test. The complete routine suite
validates 20,185 unique cases with 50 skipped: 20,179 pass in the sandbox, and six native
Studio helper/census cases pass in capability-appropriate reruns. The sandbox run records
five failures and one fixture error; no code/test changes or waivers were used to resolve them. Remaining
durable work is source-expectation reconciliation and the shared Linux PID capacity floor, both
now in TODO.md. Raw data are byte-identical across loops 91/94/95, so later blind movement is
reviewer/sample variance rather than another source-data improvement.

User requested ten assessment loops, continuing the canonical mixed-fleet benchmark after loop88.
Keep authored scenario, seed42, output target and collection scope unchanged. No commits or release
actions requested. Worktree was clean at start on dev. Use fresh data-only neutral copies and four
independent reviewers per loop; keep deliberation separate from standalone scores.

## Starting evidence and family hypotheses

Loop88 reports no supported P0–P2 defect. Primary candidate is concentrated database/perimeter
activity, owned by world/topology/activity configuration. Invariant: network evidence must reflect
the modeled application roles, service placement, routes and intentional scan activity; concentration
alone cannot justify invented traffic. Entry paths: baseline application traffic, modeled scanners,
storyline connections and red herrings. Consumers: canonical transport, Zeek sensor views, endpoint
FLOW and ASA. Sibling risk: changing shared traffic profiles could erase legitimate authored activity
or break process/software attribution. Inspect current rendered evidence before choosing a fix.

Other latest hypotheses (collection bounds, sparse Unified Log, Windows network-audit volume) need
collection-policy evidence. Reused Mac traceID is a static-callsite property and was ruled out.
Previous reports showed large score variance on byte-identical output; do not claim a fix effect
without changed data and targeted evidence.

## Execution

Fresh validation and generation started for loop89 on current dev. Use uv --no-cache run --offline
--no-sync because the default uv cache lies outside the writable sandbox. Validation succeeded
with the retained low-baseline warning and source-coverage advisories.

### Loop89 — fresh current-dev baseline

Generation succeeded: seed42, default target, technology@1.0.0, no OOB hosts; 117 data files.
Authoritative integrity verification passed. Evaluation: 91.0221 FAIL, 148,961 records; new
schema-v5 ground-truth agreement71.5965 fails95, while parseability100, plausibility95.6298,
causality97.5371 and timing90.3473. This is a new acceptance metric; older96.28 scores did not
include this same contract. Failure diagnostics include 239 process timing identity errors,
2,038 missing evidence and855 factual disagreements. Four independent reviews completed; results follow below.

#### Loop90 candidate contract — final source timing proof

Owner: evaluation/source_timing_proof.py, consuming SourceTimingPlanner's final visible receipt.
Invariant: a receipt's native_time equals the finalized envelope expected_time; collection delay
has already been applied by runtime-owned endpoint planning. Do not subtract the delay twice.
Entry paths: process start/fork/exec/credential/job transitions/terminate through shared runtime.
Consumers: ground-truth acceptance verification; generated native logs are already finalized.
Sibling coverage: positive delayed fork and exec/terminate proofs, negative altered-clock control.
Layer rationale: source planner documents and records the final visible dependent frontier;
verification currently assumes a pre-delay timestamp. No output timing changes are justified.
Remaining timing dependency/identity findings require separate exact evidence, not relaxed bounds.

#### Loop91 candidate contract — pipeline submission protocol intent

Loop89 Threat Hunter independently joined Bash /dev/tcp to established TLS/certificate rows on
10.10.3.10:56738→45.33.32.30:8443, UID CgR5Lvle5WdWRKjoSq. Confirmed root: typed pipeline
expansion correctly transfers socket ownership to the final child (`bash`), but network protocol
selection sees only that child's argv and loses the encoded parent submission. The existing raw
TCP detector consequently misses its intended override.

Owner: typed Linux pipeline adapter into canonical network-request construction. Invariant: when
an exact pipeline child owns a following connection, protocol semantics retain the originating
submission while process attribution remains on the actual child. Entry paths: direct shell and
encoded bash-c pipelines; consumers: canonical connection/protocol planner, Zeek conn/SSL/x509/files,
endpoint FLOW and firewall. Verify sibling raw endpoints and prevent unrelated parent-command reuse.
Classification: adapter_to_family_model; reuse existing raw endpoint decoder and network planner,
never remove TLS only inside one renderer. Residual: unmodeled encryption intermediaries and arbitrary
command interpreters are outside this bounded semantic adapter.

### Loop89 — completed

Fresh current-dev generation, quantitative evaluation and four independent blind reviews completed. No generation fix in this baseline round; selected concrete evidence for the following repairs.

Automated evaluation 91.0221 FAIL, 148,961 records. Standalone synthetic-confidence scores 76 / 57 / 24 / 34; mean47.75. Mean standalone synthetic-confidence47.75 versus67.00 in loop88. This combines fresh current-dev data with new independent sampling; do not attribute the change to a completed realism fix. Loop90 tests only the verifier repair on unchanged source data; pipeline protocol repair is targeted for loop91.

Loop91 first generation candidate failed at authored evt-014 after a disconnected RDP generation;
no recovery point or successful manifest exists. Preserve `loop-91/bundle` and console log. The
protocol correction changes downstream RNG-sensitive scheduling, exposing an existing reconnect
admission inconsistency: ActivityGenerator rejects `prepared.source_system is None`, while the exact
RDP bundle explicitly supports an unmodeled source retaining its authenticated source-address
identity. Do not change the scenario, weaken completion, or fabricate source-host telemetry.

Additional owner contract: shared storyline RDP admission must allow an exact disconnected session
with its original unmodeled controller; modeled controllers still require an available interactive
source session. CONNECTED/LOGGED_OUT and exact generation/journal checks stay intact. Entry paths:
typed process and credential-spillage process admission; consumer is existing exact RDP reconnect
publication. Test modeled/unmodeled available cases plus unavailable modeled source refusal.

### Loop90 — completed

Repaired final source-timing verification and reevaluated the unchanged authoritative bundle, followed by four fresh independent reviews. Generation data remain byte-identical to loop89.

Automated evaluation 94.3457 FAIL, 148,961 records. Standalone synthetic-confidence scores 28 / 18 / 19 / 42; mean26.75. Standalone mean26.75, down21.00 from loop89 on byte-identical source data: reviewer/sampling variance. Deliberation preserved the original positions. Next loop verifies pipeline protocol repair; its initial generation exposed unmodeled-controller RDP reconnect admission, now under owner-level repair with focused controls.

#### Loop92 candidate contract — requested versus expanded mail recipients

Loop91's evaluation still fails ground-truth agreement88.0920 (overall94.4818;147,759 records).
A confirmed verifier error compares authored distribution-group addresses directly with expanded
mailbox recipients. Example: requested finance@meridianhcs.com correctly expands to Diego's mailbox;
original headers retain `<finance@meridianhcs.com>`. This is five false authored-email outcomes.
Owner: independent authored-intent evaluator, using typed one-level distribution-group configuration.
Invariant: To/Cc/Bcc match their requested mailboxes after native header-address parsing, while
expanded_rcptto independently matches the scenario's group expansion. Never conflate header intent
with transport delivery recipients. Entry paths: internal/external/group/Bcc delivery and rejection;
consumers: authored-email ground-truth score. Sibling controls: direct address, display-name formatting,
missing expanded member, wrong requested group, and moving Bcc into To. No generator/output changes.

### Loop91 — completed

Repaired typed pipeline protocol intent and exact RDP reconnect admission for unmodeled controllers; generated a fresh successful seed42 bundle and ran four independent reviews. Preserved the failed initial candidate separately.

Automated evaluation 94.4818 FAIL, 147,759 records. Standalone synthetic-confidence scores 30 / 30 / 24 / 25; mean27.25. Mean27.25 versus26.75 in loop90 (+0.50). The hard rendered invariant improved, while this small blind movement is consistent with reviewer variance; do not infer a realism regression. Loop92 verifies requested-vs-expanded email recipient semantics on unchanged source data.

### Loop92 — completed

Corrected authored email verification to distinguish requested To/Cc/Bcc headers from expanded distribution-group mailboxes. Reused unchanged loop91 source data for evaluation and four fresh independent blind reviews.

Automated evaluation 94.4825 FAIL, 147,759 records. Standalone synthetic-confidence scores 30 / 20 / 25 / 32; mean26.75. Mean26.75 versus27.25 in loop91 (-0.50), on byte-identical source data; reviewer variance. All four verdicts Inconclusive, confidence80–82 and score spread12; no deliberation trigger. Loop93 qualifies the eight-message provenance family before attempting journal changes.

#### Loop94 candidate contract — message-owned deferred mail provenance

Loop93 probe identifies eight distinct auto-named mail artifacts attached to four unrelated authored
email intents through reused process/action ownership. Owner: GroundTruthLedger.record. Invariant:
background mail declaring no storyline origin must not become an authored consequence solely by
borrowing a persistent process or action. An already-owned message identity must still retain its
late SMTP companions, including after the active authored scope ends. Explicit intent always wins.
Entry paths: authored inbound/internal/outbound messages, automatic background email and delayed
SMTP companions. Consumers: canonical event stream, recipient relationships, source expectations,
authored-intent evaluation and incremental ownership-table recovery. Retain process ownership for
non-mail evidence and known message ownership for deferred mail; do not filter reports or alter logs.
The existing disk-backed ownership table owns message IDs without schema/checkpoint format changes.
Sibling controls: separate background message reusing both process and action, same-message late
hop with a new action, and explicit authored scope overriding a background-looking context.

### Loop93 — completed

Qualified the remaining mail provenance failure against canonical occurrence and artifact identities, then ran a fresh independent panel on unchanged loop91 data. No output change in this checkpoint.

Automated evaluation 94.4825 FAIL, 147,759 records. Standalone synthetic-confidence scores 20 / 28 / 29 / 20; mean24.25. Standalone mean24.25 versus26.75 in loop92 (-2.50) on byte-identical data; sampling/reviewer variance. Deliberation preserved original scores. Loop94 will verify message-owned provenance with fresh generation and late-hop/checkpoint controls.

#### Loop95 candidate contract — Zeek-native ICMP identity fields

A remaining factual-disagreement sample expects canonical scan transport port0 in Zeek id.orig_p,
while Zeek correctly reports echo-request type8. The native contract also needs ICMP conn_stateOTH
rather than TCP-style transport outcome. Owner: shared source-native evidence rules, consumed by
conn serialization and native requirement construction. Invariant: ICMP tuple slots represent
native type/code; zero canonical type defaults to echo-request8, and native state isOTH. TCP/UDP
ports/state remain unchanged. Entry paths: scanner, storyline and ordinary network occurrences,
with direct and sensor-observed views; consumers: Zeek conn and immutable source requirements.
Classification: source_native_single_schema, because already-correct native rendering and its
verification contract use different field semantics; no cross-source transport truth changes.
Move existing pure native state/history helpers into source-rule ownership and share port shaping,
then regenerate frozen source requirements. Test zero/default and explicit ICMP types, answered and
unanswered traffic, sensor/direct paths and non-ICMP preservation. Do not relax field comparisons.

### Loop94 — completed

Implemented message-owned deferred mail provenance and regenerated the full fixed-seed scenario. Fresh raw logs are byte-identical to loop91; truth metadata now excludes unrelated background messages. Four fresh blind reviews completed.

Automated evaluation 94.4923 FAIL, 147,759 records. Standalone synthetic-confidence scores 20 / 20 / 30 / 25; mean23.75. Mean23.75 versus24.25 in loop93 (-0.50) on byte-identical raw data; reviewer variance. Deliberation kept both Real and Inconclusive positions and all original scores. Loop95 will align ICMP native projection with its required-fact contract.

### Loop95 — completed

Aligned Zeek-native ICMP state/type/code projection and immutable required-fact construction, then regenerated source expectations and ran four independent reviews. All118 source files remain byte-identical to loop94.

Automated evaluation 94.6124 FAIL, 147,759 records. Standalone synthetic-confidence scores 20 / 20 / 24 / 35; mean24.75. Mean24.75 versus23.75 in loop94 (+1.00) on byte-identical raw data; reviewer variance. Deliberation retained original positions and cleared the path-escaping suspicion. Loop96 qualifies allocator texture on the same fixed snapshot.

### Loop96 — completed

Qualified the shared Linux PID increment fingerprint at its canonical allocator owner and ran a fresh four-expert panel on the fixed loop95 snapshot. No generator or scenario change in this checkpoint.

Automated evaluation 94.6124 FAIL, 147,759 records. Standalone synthetic-confidence scores 30 / 18 / 30 / 24; mean25.50. Mean25.50 versus24.75 in loop95 (+0.75), unchanged raw data: reviewer variance. Deliberation retained original scores. Loop97 will qualify remaining source-expectation failures and independently check the fixed snapshot.

### Loop97 — completed

Inventoried the unresolved schema-v5 acceptance families against exact-source ownership boundaries and ran another independent blind panel on the unchanged loop95 snapshot. No code or scenario change.

Automated evaluation 94.6124 FAIL, 147,759 records. Standalone synthetic-confidence scores 35 / 20 / 28 / 32; mean28.75. Mean28.75 versus25.50 in loop96 (+3.25), unchanged data: reviewer variance and weak Mac population emphasis. All four verdicts Inconclusive, confidence78–85, spread15; no deliberation trigger. Loop98 is the final requested independent checkpoint with early/middle/late sampling and final dashboard.

### Loop98 — completed

Completed the tenth requested assessment: fresh four-expert early/middle/late-window review, authoritative reevaluation, final synthesis and score artifact on the fixed loop95 snapshot. No additional generator or scenario change.

Automated evaluation 94.6124 FAIL, 147,759 records. Standalone synthetic-confidence scores 25 / 20 / 18 / 20; mean20.75. Mean20.75 versus28.75 in loop97 (-8.00), unchanged data: reviewer/sample variance. Five-score rolling average24.70. All ten requested rounds89–98 and40 independent reviews are complete. Maintain the final dashboard over the last20 loops and carry the two durable backlog items forward.

## Final validation and handoff

All ten loops and final dashboard are complete. The final related selection passes255 tests
(9 deselected); the targeted RDP slow gate passes1. Complete routine execution selected20,235
cases:20,179 passed,50 skipped,5 failed and1 setup error in2,096.90 seconds. All six affected
cases are native Studio helper/readiness/census checks under the managed sandbox. The process
census rerun passes1 outside the sandbox; the full native helper/ownership file rerun passes6
(including one already-passing case). Thus20,185 unique routine cases validate with the
required native capabilities. No source changes, test skips, threshold changes or approval
waivers resolved these failures. Native fixtures use disposable state and terminate owned children.

Ruff check and formatting pass,102 configuration files validate, behavior509/digest
`e1d994159bab8d835bd79b70d4aa74da7310beed351e1382af783f2708e2d503` is current,
and git diff checks pass. All40 reviewer reports and10 score artifacts validate; dashboard SVG
parses as XML (1600×1760). Detailed validation is `loop-98/validation.json`.

Final standalone mean20.75; rolling5 mean24.70. Automated dataset acceptance remainsFAIL at
94.6124 overall and88.3573 agreement against95, despite implementation test success. Retain
that distinction. Next work: exact source-expectation reconciliation, then a recovery-safe PID
workload/capacity redesign. No additional assessment rounds, commits, scenario edits, version
bumps, tags or release actions are implied. The subsequent user request authorizes committing
and pushing the completed work, including this assessment record and dashboard, to `origin/dev`.

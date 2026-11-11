# Ground-truth reconciliation

Approved scope: deterministic schema-v4 canonical occurrence capture, authored intent and
source observation reconciliation, DNS answer/use relationships, prevention semantics,
process-download infrastructure coverage, and explicit HTTP outcome preservation. Work is on
`codex/ground-truth-reconciliation`, based on fetched `origin/dev` at session start.

Temporary diagnostics reproduced a process-download destination missing from both ground-truth
files, authored blocked prose alongside GET 200, and an authored 403 overwritten by a public
HTTP redirect. CONNECT 200 followed by inspected-request denial is a valid separate control.

## Implementation

The generation engine now journals committed canonical occurrences and exact source decisions
to an owned SQLite spool. The dispatcher hooks run after canonical commit, including exact
action-cohort, deferred-session, state-neutral, and persistent-SMB publication paths; staged
source projections cannot become ground truth. Failed metadata capture fences both successful
completion and checkpoint publication. Incremental checkpoint deltas preserve journal identities,
observations, intent outcomes, DNS consumption, and ownership without retaining detailed history
in Python lists. Unrelated background occurrences are counted and deduplicated on disk.

Schema 4 adds the streamed schema-1 `GROUND_TRUTH_EVENTS.jsonl` and binds its count/hash in the
compact summary and bundle manifest. The existing `events` array remains the compatibility
authored-action summary. Per-occurrence prevention, ordinary failure, partial outcomes,
source-instance observations/reasons, process/network ownership, DNS answer/use/cache relations,
proxy request/transport, pre/post-NAT tuples, and requested/expanded/attempted recipients remain
distinct. Canonical facts drive IOC sections. Markdown labels scenario descriptions as intent.

The DNS/cache owner records actual resolution consumption, rather than inferring use from
matching answers. A returned answer set can contain unused addresses or aliases. Connections
reference the earlier answer, resolver, client, selected address, and lookup/cache mode. A static
connection with a compatible answer does not acquire a fabricated lookup relationship.

Authored connection/beacon statuses survive automatic redirect defaults, including status-only
events and per-tick beacon sequences. Genuine proxy enforcement still owns its result; CONNECT
200 and inspected-request denial remain separate phases. Firewall outcomes use modeled topology
for enforcer identity; ambiguous or unavailable enforcement identity stays unknown. Existing DNS
REFUSED indicates resolver refusal without inventing its underlying policy.

Evaluation verifies stream schema/order/integrity and independently matches observed Zeek
DNS/HTTP/transport and eCAR/Windows Security/Sysmon process lifecycle facts against parsed output.
Deleted or contradictory consequences fail intent reconciliation. Schema-3 evaluation remains
supported. Interrupted required intents retain partial stream/diagnostics and cannot produce a
successful completion manifest. Legitimate no-ops remain separate from actual occurrences.

Documentation: [ground-truth contract](../reference/ground-truth.md). Internal generation
behavior revision is 501; the product version is unchanged. Explicit story-role labels remain
deferred to the approved P2 roadmap item. No additional prevention simulator or LLM calls were added.

## Validation

Final checks on the implementation: **1,127 focused/routine/extended/recovery tests passed**.
Generation-heavy checks used `--no-cov`; no release coverage gate or full release suite was run.

- 146 ground-truth/schema/behavior tests across `test_ground_truth_ledger.py`,
  `test_ground_truth_reconciliation.py`, `test_generation_behavior_manifest.py`,
  `test_ground_truth.py`, and `test_ground_truth_outcomes.py` passed (97.49 seconds).
  These include process-download IP/domain/DNS/UID/HTTP joins; authored prose versus 200;
  ordinary/beacon/sequence/status-only HTTP outcomes; default redirects; proxy enforcement
  including CONNECT; firewall drop/reject placement; resolver/cache consumption; source-loss
  reasons; NAT/recipient relationships; v3 compatibility; digest tampering; independent missing/
  contradictory consequence rejection; staging fences; and journal restore equivalence.
- 889 related unit/recovery tests passed (14.30 seconds): intent ledgers, incremental checkpoints,
  explicit proxy/referrer, firewall storylines, evaluation integrity/acceptance, collection
  deployment, command-triggered networking, spillage, action cohorts/exact projection recovery,
  deferred sessions, and persistent-SMB projection/activation contracts.
- 88 selected slow composition/engine/spillage tests passed (60.25 seconds), including full
  engine finalization, bundle corruption/integrity, partial-output handling and human-report
  spillage redaction. Existing mocked engine fixtures now publish valid canonical occurrences
  instead of silently bypassing the new intent completion guard.
- Default and SOF-ELK® CLI suspend/resume tests passed (2 tests, 59.48 seconds), comparing all
  deterministic bundle files including the new JSONL sidecar against uninterrupted controls.
- Native Mac denied-launch and failed-exec checkpoint/resume tests passed (2 tests, 51.97
  seconds). These verify prevention/ordinary-failure recovery without inventing successful starts.
- The two proxy journal cases were rerun with explicit authored HTTP-200 preservation enabled;
  actual proxy denial still wins, while a successful CONNECT remains 200 (1.11 seconds).
- `ruff check .`, `ruff format --check .` (1,524 files), `git diff --check`, and
  `scripts/check_generation_behavior.py --base-ref origin/dev` passed. Revision 501 binds
  behavior digest `51488e79ece99ffec48164ba40dcbbc1bb48c2b44c52f306ded7da53394f98d8`.

Commands used the project's uv environment with `uv --no-cache run --offline --no-sync`.
All product-version declarations and lockfiles remain unchanged.

## Scope limits

The original reporter's exact scenario/output is unavailable, so its exact causes remain
unconfirmed. Reproduced process-download, prose-blocked/200, and redirect-overwrite cases provide
concrete regression targets. Schema-3 bundles cannot gain historical occurrence facts, and a
checkpoint from a runtime without this journal cannot reconstruct omitted history. Existing
source-native/cross-source gates retain responsibility for formats beyond the new independent
process/network joins. No product version bump, commit, push, PR, or release was performed.

## Temporary alpha-6 comparison

User requested an evidence-based before/after comparison after implementation. Temporary artifacts
are at `/private/tmp/eforge-gt-compare-20261110-hp8ze_dp/`; `comparison.html` links the inputs,
unmodified ground-truth files, JSONL streams, evaluations and machine-readable `comparison.json`.
No engine code or permanent tests changed during this study.

Six authored diagnostic inputs (one 14-action core and five collection/enforcement variants)
were validated/generated under tagged `v2.2.0a6`, unmodified `origin/dev`, and a frozen copy of
the feature working tree: 18 bundles, seed 42, default target, shared Python 3.12.12 environment.
All three compiled-input hashes match per case. Alpha 6 and the base produced byte-identical
data and ground truth for all six cases, isolating the feature changes from release metadata.

Observed gains: process-download IP `142.250.191.242` is absent from both old truth files and
present in both new summaries; authored HTTP statuses match 0/5 old versus 5/5 fixed emitted
transactions; the fixed core adds 59 canonical occurrences to 14 compatible action summaries;
DNS answer sets, actual lookup/cache consumption, prevention/failure and no-op reasons are explicit.
The manual two-answer DNS transaction was not consumed: later beacons performed their own
one-address lookup and then reused that cache. The new ledger correctly keeps those distinct.

All 18 evaluations completed and verified bundle integrity. Per engine, only the two firewall
cases pass full acceptance; core fails existing indicator/timing criteria and three visibility
cases fail indicator accuracy. Both old/new intent scores are 100. Thus broad score (core
89.41 -> 90.20) is not the ground-truth improvement metric. Independent in-memory negative
controls accept intact fixed data and reject either deletion or status corruption of the
process-download HTTP record, identifying the exact originating intent; bundles remain untouched.

Remaining qualitative gaps exposed by the study: a valid no-sensor fixture must omit Zeek
output and receives `output_filtering` without separately representing undeployment; topology
exclusion can use format-level placeholders and does not enumerate the excluded downstream
sensor on a prevented firewall occurrence. Most detailed DNS/source reasons require JSONL
drill-down rather than appearing directly in Markdown. These findings are reported, not silently
fixed or hidden by fixture tuning. Proxy/CONNECT, NAT/recipient relationships, recovery and
unexpected prerequisites were outside this temporary comparison's scope.

## Source-aware evaluation and visibility

Approved second plan continues on the same feature branch. Ground-truth schema 5/stream 2
replace wire-level observation claims with exact source expectations. Captured inputs include
configured source inventory, native Sysmon filters, source timing windows, loss identity/sample,
source-local tuple/file identities, and sensor capture receipts. Sensor receipts are stored
once per occurrence/source rather than duplicated in every format expectation. The SQLite
journal's expectations and metadata tables participate in the existing checkpoint spool.
No product version or emitted simulation policy was changed.

New evaluator modules separate native projection contracts, independent grouping/loss-policy
checks, disk-backed relationship reconciliation, and the fifth pillar. All five schema-5
pillars are weighted 20%; schemas 3/4 keep the original four weights and an explicit limitation.
The numeric boundary, equal action weighting, no optional-field dilution, source isolation,
false loss explanations, deleted expectations, mutually consistent authored-status corruption,
duplicate records, and legitimate zero-check cases passed focused tests. Evidence agreement
now contributes to the numeric fifth pillar; independent authored accounting and integrity/schema
gates remain separate. Final validation and comparison results are recorded below.

Preflight adds typed HTTP/DNS/DHCP/transport/authentication/SMTP fact coverage alongside the existing
host behavior contracts. It reports certain exclusions as warnings, probabilistic loss and
optional gaps as information, and conditional routing/timing explicitly. Generic sensor notes
are informational. CLI and Studio now expose ground-truth counts and bounded diagnostics.

The default `distributed_taps` capture profile already models occasional packet loss even
when the source observation profile is `complete`. This differs from dropping an entire
source record. It can change file byte counts or suppress PE/X.509 analysis. The new capture
receipts and independent packet/file accounting are necessary to reconcile these legitimate
native differences without calling the generator or renderer as an evaluation oracle.


The extended family checks now exercise delivered/rejected/attachment-stripped mail and
successful/denied/high-audit SMB reads. Source-native eligibility distinguishes sparse audit
policy from missing capabilities. SMB observations bind phase, path and operation rather than
borrowing a mapping or another file phase. Native hash spelling is normalized. Session logout
uses the declared source timing bounds. Canonical storage outcomes and required operation
consequences are reconciled independently of the recorded source expectations.

The comparison and extra registry case exposed two matching problems: adjacent Sysmon A/AAAA/
lookaside DNS queries needed their frozen native envelope time, and repeated registry writes to
the same process/key needed native clock identity. Module binary identity alone is insufficient
because several processes can load the same DLL; module matching now includes the process.
Empty Sysmon DNS results normalize from `-`, and QueryStatus is checked against canonical rcode.
Expected absence matches transaction identity independently of required factual values, so an
unexpected HTTP record cannot evade the check by carrying an incorrect status.


### Source-aware verification results

- The broad routine selection passed **754 tests** (216.16 seconds): evaluation pillars/parsers/
  thresholds/acceptance, source deployment, typed visibility, ground-truth schema/outcomes,
  canonical journal/reconciliation, source agreement and Studio backend. The subsequent registry
  clock variant and final attribution/absence refinements passed **29 agreement tests** (43.21
  seconds). Earlier stale four-pillar weight and legacy standalone-document fixtures were updated
  to declare their intended contract.
- **171 dispatcher/intent/cohort/exact-publication recovery tests** passed (5.51 seconds).
- The final **6 extended mail/storage cases** passed (59.25 seconds, `--no-cov`): delivery,
  rejection, attachment stripping, sparse auditing, authorization denial and high auditing.
- The final manifest/report/engine/visibility plus default/SOF-ELK suspend/resume selection
  passed **69 tests** (63.11 seconds). The deterministic bundle comparison includes the JSONL
  stream and all new metadata. Mac denied-launch and failed-exec recovery also passed (2 tests,
  54.56 seconds). Generation-heavy checks used `--no-cov`; no release coverage gate was run.
- Studio TypeScript compilation, generated API type checking and **117 UI tests** across App,
  native coverage and the new ground-truth scorecard passed. Tests verify that a passing 95%
  score still exposes source diagnostics and that legacy reports state their coverage limit.
- Ruff checks, formatting checks (1,536 Python files), behavior-manifest validation and
  `git diff --check` passed. Internal behavior revision **502** binds digest
  `b463860bd49edc2b9a7457940ff630fddb79957d2f6d0a1721a5cc93046dc548`.
  Product Python/Studio versions and lockfiles are unchanged.

### Source-aware comparison results

Final frozen artifacts are at `/private/tmp/eforge-ground-truth-results-ln177v6s/`.
`comparison.md`, `comparison.html` and `comparison.json` link the exact inputs, native evidence,
compact JSON, Markdown, occurrence streams and evaluation reports. `snapshot-sha256.json` binds
all source files; `versions.json` identifies the engines and `REUSED_BASELINES.json` identifies
exact reused historical baseline artifacts. All ten feature bundles and all thirty evaluations
were regenerated with the final feature snapshot. Snapshot hashes were verified after execution.

The original six cases were retained. Two corrected firewall variants place the second sensor
on the destination's actual external CIDR; the original variants only demonstrated an off-path
sensor. Registry consequences and a storage read add two more activity families. All **10/10**
feature runs score **100% agreement and pass overall acceptance**. Every emitted source data file
is byte-identical between schema 4 and schema 5 in these ten cases. Core canonical occurrences
remain 59; schema 5 adds 143 required source checks and 35 neutral expected absences.
Alpha 6 preserves 0/5 explicitly authored HTTP statuses, compared with 5/5 in both fixed snapshots;
process infrastructure appears in the fixed Markdown/stream. Prose-only blocked activity remains
HTTP 200 and is labeled authored intent rather than modeled enforcement.

Read-only fault controls operate on parsed records/copied truth after authoritative bundle
integrity validation. Deleting one projection, deleting both its expectation and evidence,
claiming false loss, and changing native/ground-truth HTTP values consistently against an authored
403 each produce one incorrect projection and a **99.642857%** mean with retained diagnostics.
Removing every observation for one authored action produces **92.857143%**, below the default
95% minimum. Full action counts and examples are in `negative-controls.json`. Original bundles
remain intact; independent integrity/schema rejection remains covered by permanent tests.

Remaining scope limits: the original reporter's exact cause is unconfirmed; preflight reports
conditional runtime coverage; schemas 3/4 retain legacy scoring and cannot gain missing historical
facts; raw source-local normalizations without an independent contract are reported as contract
disagreements; and detailed sidecars are larger. Core JSON grows from 40,239 to 48,702 bytes and
its streamed detail from 152,784 to 457,304 bytes. Explicit story-role labels remain deferred.
No product version bump, commit, push, PR, release or LLM integration was performed.


### Live Studio evaluation failure diagnosis

Read-only inspection of the user's latest two failed Studio evaluations found that
`INC001-Ransomware` (October 13 bundle) passed authoritative bundle verification. The CLI then
rejected its 864,106,704-byte corpus against the pre-existing 536,870,912-byte default limit.
Stdout was empty; Studio exposed a secondary QualityReport JSON EOF error instead of the CLI
capacity diagnostic. These limits originated in `03401ad0` (August 7), before this feature.
The CLI already exposes `--allow-large-evaluation`, which bypasses byte/file/record guards;
Studio currently does not expose that option. The evaluator still retains all parsed records
in memory. No limit was raised and the user's bundle/state were not modified.

The desktop controller now preserves a bounded terminal CLI error from stderr when a report
cannot be read. Studio derives the same explanation for historical failed jobs without
rewriting state and does not attempt to parse an unfinished report while evaluation runs.
The GUI identifies the attempt as `Evaluation failed` and retains the underlying reason.
Focused controller/Studio job tests passed (24 tests, 13.31 seconds), including the actual
capacity-error shape, pending output, fallback diagnostics and unchanged historical state.
Read-only projection of the actual failed job now returns the capacity error.

The original resource-hardening rationale is documented in
`docs/worklog/2026-08-07-input-safety-budgets.md`: isolated retained-eCAR probes measured
2,958.62 bytes of RSS growth per record, projecting about 1.48 GB at 500,000 records before
scorer headroom. This is historical capacity evidence, not a format-independent memory estimate
for the user's bundle. The immediate override bypasses corpus limits but retains full-corpus
in-memory parsing. Larger-scale bounded-memory evaluation is separate implementation work.
Studio summary/ScenarioRuns UI regressions passed (38 tests, 1.55 seconds), as did TypeScript,
Ruff/format checks (1,537 files), whitespace checks and the unchanged behavior manifest.

User requested a P1 backlog item for full evaluation without fixed corpus-size caps and
explicitly limited further scope on this branch. Added the durable roadmap item; no evaluator
limits or Studio settings were changed. Recommended interim UX is an `Allow large evaluations`
setting enabled by default with a memory-use explanation, rather than a repeated confirmation
dialog. That setting remains a recommendation, not an implemented or approved requirement.


### Approved interim large-evaluation setting

After user confirmation, implemented **Settings → Jobs → Allow large evaluations**, enabled by
default with a visible memory-use explanation. Newly queued Studio evaluations capture
`--allow-large-evaluation`; opt-out omits it and retains the CLI's default limits. Existing
queued/running commands remain unchanged. The direct CLI and legacy controller defaults are
unchanged; the Studio queue supplies the explicit option.

Settings schema 3 adds a frozen reader and an appended 2→3 migration, preserving all existing
preferences through the normal verified-backup/recovery workflow. Historical readers and
released migration declarations remain unchanged. New/default preferences enable the option;
saving false persists across reload and is honored when queuing the next evaluation.
The P1 streaming/bounded-memory evaluator remains future work. No user state or bundle was
modified and no large evaluation was launched as part of implementing this setting.

Validation: the full Studio service selection passed (104 tests, 74.69 seconds); settings UI/App
tests passed (118 tests, 11.07 seconds); frozen contracts/queue behavior passed (28 tests,
1.53 seconds). TypeScript compilation, generated API types and final Ruff/manifest checks
are also covered. Source-launched Studio must restart to load the new backend/settings reader.

The broader state upgrade/migration/edge/contract/job selection passed **184 tests** with one
platform skip (18.24 seconds). Recovery and historical inventory checks preserve existing
settings, IDs, timestamps and engine-owned files across the new preference migration.


### Full live MacOS-test evaluation audit (read-only)

User requested classification of all findings from Studio evaluation
`80fe12360a3b4064997efa406f73e042`, completed generation
`7a2c2530941f4f368fe07e3290ad6e08`. Preserve the distinction between actual data/truth
issues, contracts/expectations, evaluator errors and reporting limitations. No evaluator,
generator, scenario, original bundle, thresholds or user state was changed in this audit.

Direct Documents reads failed macOS privacy checks, including outside the sandbox. Used
Studio's existing authenticated loopback GET bundle-file API to copy 38 files / 78,523,282
bytes into `/private/tmp/eforge-macos-eval-review-hyj8pe9a/bundle`. Authoritative bundle
hash verification and resolved compiled digest comparison passed. Parsed all 232,945 records
and replayed only agreement evaluation with its detail cap removed in temporary memory.
Score **76.84463722106652**, per-action results, 1,059 correct / 311 incorrect checks and
all rule counts exactly match the saved report. Recovered all **547 overlapping rule
findings**; the saved first 100 examples represented only 64 distinct checks. 89/109 actions
have an incorrect check. Original report has only one failed hard gate (agreement).

Working primary classification of all 311 checks:

- **253 evaluator/parser integration:** 97 history host-bucket errors (93 zsh, four Bash),
  131 ASA UTC-versus-scenario-local interpretation errors, 24 broad exec-cardinality errors,
  and one literal comparison of semantically equivalent shell quoting.
- **49 contract/expectation gaps:** 29 process modifications omit operation selectors,
  16 additional process timing checks exceed a blanket two-second bound, two Linux SSH
  logoff projections are missing SYSLOG in the canonical consumer inventory, and two
  legitimate launch-item `job_control` outcomes are omitted from authored consequence kinds.
  Timing ownership remains provisional: validate inherited readiness floors independently,
  rather than merely enlarging the tolerance. There are 18 timing findings in total; two
  overlap cardinality checks and are not counted twice here.
- **Eight data/truth inconsistencies:** two DNS/UDP flows retain 52-byte canonical overhead
  while Zeek renders 28-byte overhead; six intra-office scan failures become firewall-policy
  prevention by an off-path TAP gateway with expected ASA evidence but no matching records
  or captured ASA views. Scan closed/unresponsive profiles currently reuse a `denied` Boolean
  that creates FirewallContext without an actual policy decision. Source-side inference then
  attributes an enforcer without proving the original path.
- **One unresolved DNS cache provenance:** connection starts 161.375171 seconds after an
  answer with TTL 161. Exported relationships lack the exact cache-consumption time/window,
  so an expired cache lookup versus later connection scheduling cannot yet be distinguished.

Temporary controls find exactly one command for every history expectation when indexing the
already-parsed hostname, and exactly one ASA record per required phase for 131 checks when
interpreting the rendered clock as UTC. All 24 exec failures have one required image/command
match among multiple distinct execs. Each of the 29 other process-modification candidate
groups contains exactly one intended operation; the contract omitted that operation.
These controls are diagnoses, not production fixes or a corrected score.

Reporting gaps: the detail cap omits whole failure families; `[{}]` hides command `contains`
predicates; candidate/match/cardinality counts, clock deltas and inherited timing constraints
are missing; semantic failure details may be null. Improve visibility without weakening checks.
Other pillars include the same two launch-item steps in event-presence/pivot diagnostics and
234 missing projections in trace coverage. Distribution/anomaly/burstiness and four large
attack-chain gaps are separate heuristic realism diagnostics, not established truth defects.
The 68 expected absences and 589 coverage gaps are not errors.

Full explanation and per-check artifacts are in the temporary audit directory: `REVIEW.md`,
`classification.json`, `uncapped-agreement.json`, `projection-diagnostics.json`,
`history-attribution-control.json`, `asa-clock-control.json` and `phase-diagnostics.json`.
No corrected score, permanent tests, commit, push or release was produced. Next work should
fix confirmed evaluator errors, complete independently verifiable contracts, repair real
canonical inconsistencies, and settle cache-consumption provenance without scenario tuning.


### Approved reconciliation repairs — implementation and verification

Implemented the approved repair plan on the existing feature branch. Ground-truth schema 5
and occurrence schema 2 were revised in place; no product version, release, commit or push
was made. DNS cache-consumption/expiry provenance remains deferred. Its original finding
remains present when evaluating the preserved run.

Root fixes:

- History ownership follows recognized host/user routes and parser metadata, with contradictory
  attribution recorded as a parse defect. Generated ASA timestamps are explicitly UTC.
- Canonical process facts retain execution identities and operation-specific before/after
  credentials, images, commands and job control. Matching separates immutable occurrence
  identity/native precision from mutable factual requirements. History uses command/user
  identity, preventing neighboring commands from becoming false duplicates. Literal POSIX
  comparison accepts quoting equivalence while preserving shell/expansion distinctions.
- Finalized source projections retain bounded timing receipts. Verification distinguishes
  preferred clock candidates from emitted observations, process-owned/direct-child frontiers,
  session login readiness, previous execs, and pre-window parent inventory. References must
  match canonical/source identities and times, precede the dependent, and satisfy bound policy.
  Missing/malformed required witnesses are incorrect checks, not vacuous success. Timing
  rules are frozen as scalar mappings; the immutable timing-profile mapping must be copied
  with `dict()` before JSON encoding. Actual timing belongs to `target.source_timing`, not
  the unprojected canonical event. Witness cloning is detached and checkpoint-safe.
- Semantic source/consequence rules are current package-owned engine policy, not a verifier
  restored from a captured generation-data configuration. Linux SSH logoff conditionally
  includes syslog. Launch-item stages have separate required consequences; registration and
  dormant unload permit canonical `job_control`, while write/activate/exit/remove retain
  their file/process requirements. Typed job label/operation/path are independently checked.
- UDP budgets are normalized at canonical draft finalization and validated on immutable
  transactions, including IPv4/IPv6 overhead. Zeek no longer silently rewrites canonical UDP
  counters. Scan profiles return transport outcomes without an enforcement Boolean; actual
  policy on the traversed firewall path owns prevention/enforcer identity. Journal capture
  no longer invents an enforcer from source-side proximity. Drop/reject follows the selected
  on-path firewall, including when an off-path firewall with the opposite mode is listed first.
- Reports retain complete rule and unique-check counts with up to 100 deterministic
  representative examples across rule/format families. Predicates, native identities,
  candidate/selected/matched counts, cardinality, timing differences, bounded dependencies
  and concrete semantic values are visible. CLI/Studio show retained/displayed counts,
  truncation and historical verification limitations. There is no uncapped findings export.

Internal generation behavior revision **503** binds digest
`49bd418924b0b35df00cdfca28940b235156ffa655ddf366b80aa8d69d1a63db`.
The final replay includes the selected-firewall mode correction. Source checksums in
`/private/tmp/eforge-repairs-current-source-sha256.json` confirm that no package source or
resource changed during generation. Its 28 evidence files are byte-identical to the previous
repaired replay; see `/private/tmp/eforge-repairs-current-evidence-equality.json`.

#### Final unchanged-input comparison

Preserved original bundle:
`/private/tmp/eforge-macos-eval-review-hyj8pe9a/bundle`.
Fresh final bundle:
`/private/tmp/eforge-ground-truth-repairs-current`.
Both use the original captured resolved input; no original Studio bundle or job was modified.
The final manifest confirms seed **42**, target `default`, and the captured 12 source formats.
CLI integrity verification and evaluation completed successfully; the final report is
`/private/tmp/eforge-repairs-current-verified.json`.

| Evaluation | Parsed records | Agreement | Incorrect checks | Overall | Acceptance |
| --- | ---: | ---: | ---: | ---: | --- |
| Saved pre-repair result | 232,945 | 76.844637% | 311 | 90.259744 | FAIL |
| Preserved bundle, repaired evaluator | 232,945 | 99.293706% | 27 | 95.804639 | PASS |
| Fresh final generation | 231,613 | 100% | 0 | 96.122493 | PASS |

The preserved result retains eight actual original data/truth inconsistencies, 18 checks
lacking historical timing provenance, and one deferred DNS cache relationship finding.
The fresh run has **1,463 correct checks**, 71 neutral expected absences and two legitimate
zero-check launch-item actions. It produces no agreement findings. Its final source data is
**byte-identical across all 28 files** to the earlier probe with UDP/scan repairs present but
before timing-witness attachment, demonstrating that metadata capture does not change evidence.
Full counts, report checksums and explanatory comparison are saved in
`/private/tmp/eforge-repairs-comparison.json` and `eforge-repairs-comparison.md`.

Verification evidence:

- Consolidated source agreement, original defect, journal, outcome, parser, network and scan
  selection: **317 passed**, six slow cases deselected (141.20 seconds). The final agreement,
  reconciliation, journal and outcome rerun passed **94 tests** (138.66 seconds).
- Final native Mac/command/identity/timing fault controls: **34 passed** (11.59 seconds),
  including missing/malformed/false timing witnesses, true duplicate/missing/altered evidence,
  repeat-run and source-filter equivalence, stage-specific job consequences and wrong labels.
- Canonical/sensor/rendered UDP and same-LAN versus firewall drop/reject integration:
  **4 passed** (20.28 seconds), including an off-path first firewall with the opposite mode.
- Mac lifecycle/SSH relationship and evaluator acceptance selection: **132 passed**, one
  deselected (3.36 seconds). Timing/packed-owner/checkpoint selection: **106 passed**,
  145 deselected (2.03 seconds).
- Final Mac authored-history and SSH authored-close exact suspend/resume controls:
  **2 passed** (54.87 seconds), including deterministic bundle comparisons.
- Studio scorecard UI: **3 passed**; TypeScript compilation passed. Saved scorecard/backend
  and contract/manifest selections passed; historical reports without new fields still load.
- Ruff checks, formatting (1,544 Python files), whitespace and behavior-manifest validation
  passed. Generation-heavy tests ran without coverage.

#### Separate pre-repair recovery-fixture failures

Two existing slow fixtures fail required authored cleanup with `no_matching_session` before
reaching the intended suspend marker:
`test_combined_macos_workstation_exact_recovery` and
`test_macos_native_workspace_checkpoint_resume`.
Both failures were reproduced against the saved **revision-502 pre-repair feature engine** at
`/private/tmp/eforge-ground-truth-results-ln177v6s/engine`, not merely inferred from code.
The broad case fails intent `a80dc63d-945b-463a-8753-0e04c0ef1bee` at its unconditional warmup
GUI logoff. Fixture intent assumes a warmup session exists; generation did not establish one.
No correctness gate or typed logoff semantics was relaxed. These fixtures need explicit
lifecycle prerequisites/cleanup reconciliation separately from the completed repairs; the
passing history/SSH recovery cases verify current journal/timing restoration.

Baseline failure artifacts: `/private/tmp/eforge-recovery-before-repairs.stdout` and
`/private/tmp/eforge-native-recovery-before-repairs.txt`. Current failures:
`/private/tmp/eforge-repairs-mac-recovery.txt` and `/private/tmp/eforge-repairs-exact-recovery.txt`.
The interim metadata/provenance probes were diagnostic only; the final authoritative run is
`eforge-ground-truth-repairs-current`. Restart source-launched Studio to load the backend/UI
changes, including the increased representative-example limit.

#### User's Studio re-evaluation confirmed

Read-only inspection of evaluation `25a03b309ec6485db0840f1ded1e13ff` for the original
MacOS-test generation confirms its agreement result exactly matches the preserved-bundle
comparison: **99.293706%**, 1,340 correct and 27 incorrect checks, with 51 rule findings and
no truncation. Eighteen missing historical timing proofs produce 36 messages; six original
scan-prevention inconsistencies produce 12; two UDP inconsistencies produce two; the deferred
DNS cache finding produces one. The long list is overlapping diagnostics for these same
known checks, not a new regression or stale evaluator. Re-evaluation does not retrofit the
missing provenance or rewrite original evidence; complete verification requires a fresh run.

### Studio ground-truth diagnostic presentation

Implemented the user's combined presentation choices on the same feature branch:

- Ground truth now sits below the pillar scorecard with the other expandable sections.
  Scores show two decimal places. Its header distinguishes defective checks from diagnostic
  messages and uses the existing green/amber/red icon palette with text labels.
- Categories contain expandable checks, which contain their related diagnostic messages.
  Search and category/action/source/rule filters operate on displayed groups; an action shortcut
  focuses related checks. Reused the existing help icon for scoring and category explanations.
- Added stable `check_id` to newly evaluated messages, with shared IDs for the same source
  expectation and action-level semantic check. Scoring, thresholds, weights and the bounded
  example limit are unchanged. Older reports use available identities for grouping and disclose
  that limitation. Truncated examples explicitly distinguish displayed groups from complete totals.
- Removed the macOS process-coverage panel. After the user's follow-up, also removed the
  redundant census copy from new evaluation JSON and the Studio scorecard API/types. Historical
  report downloads remain unchanged and readable, including unused/incomplete census metadata.
  The generation-time all-process ES completeness guard and its `GROUND_TRUTH.json` receipt
  remain: they cover baseline/helpers/services as well as authored processes, beyond the scope
  of authored-action agreement. No native generation or completeness requirement was relaxed.

Verified the rendered layout and category filter in a temporary loopback preview using the
actual saved MacOS-test report: 18 metadata checks/36 messages, eight evidence checks/14 messages,
one relationship check/message. The unfiltered total remains 27 checks/51 messages; selecting
relationships shows one check/message. Temporary preview files and server were removed.

Verification:

- Scorecard/legacy-census/App UI selection: **124 passed** (11.63 seconds); the final focused
  scorecard/census rerun passed **10 tests** (1.46 seconds). Keyboard help, composable filters,
  exact/legacy grouping, truncation, saved thresholds, empty results and verdict icons are covered.
- Mac projection/timing faults and deterministic/source-filter controls: **nine passed**
  (12.32 seconds), including exact check-ID assertions for overlapping messages.
- Saved Studio scorecard/raw-report compatibility selection: **two passed** (1.78 seconds).
  Retained canonical census/exit coverage selection: **55 passed** (40.16 seconds).
- Re-evaluated the preserved bundle to a separate temporary report: score **99.293706%**,
  27 defective checks and 51 messages with exactly 27 distinct check IDs. Re-evaluated the
  fresh bundle after removing the redundant supplementary copy: agreement remains **100%**,
  1,463 correct checks, overall acceptance passes, and the generation census receipt remains.
  Reports: `/private/tmp/eforge-ground-truth-ui-exact-check-report.json` and
  `/private/tmp/eforge-ground-truth-ui-fresh-report.json`.
- TypeScript compilation, generated API type checks, Ruff/formatting and whitespace checks pass.
  No product version bump, release, schema change, commit, push or user-bundle modification.

#### Remaining macOS-specific evaluation statistics removed

The user's follow-up correctly identified that Windows/Linux have no equivalent all-process
census in evaluation. Inspection found a second leftover path in `host_log_profile`: Mac-only
eCAR/ES process counters and implementation coverage notes. Removed that computation and its
special fields. All platforms now use the same source-inventory fields, including ordinary
record volumes and expected/present/conditional sources. The generation completeness guard
and its ground-truth receipt remain internal to generation; no evaluation score depends on
these removed informational statistics.

Cross-source/report regressions: **96 passed** (1.26 seconds). Re-evaluation of the fresh
MacOS-test bundle verifies no census/host process-coverage/coverage-note blocks anywhere in
the resulting report; parsed records, every agreement result, overall score and acceptance
are unchanged (**100% agreement**, 1,463 correct checks, overall 96.122493, PASS).
Report: `/private/tmp/eforge-eval-platform-neutral-profile-report.json`.
Ruff, formatting and whitespace checks pass. Original bundles and historical reports were
not modified; no generation change or version bump was made.

#### Collapsed diagnostic categories and search

Following user testing, high-level ground-truth issue categories now start collapsed. Their
headers retain the icon, category label, description, check/message counts and help hover.
The drill-down order is category → defective check → individual messages. Categories expand
independently and can be closed again without changing the report or its counts.

Removed the category/action/source/rule dropdowns and the action-only shortcut in favor of
one search box. Search matches readable category/rule labels as well as original action,
occurrence, source, rule and evidence details. Matching category counts remain visible while
collapsed; clearing search restores the full list. Full versus sampled counts and truncation
remain explicit. This is presentation-only and works with saved reports without re-evaluation.

Focused scorecard/legacy-report UI tests: **10 passed** (1.91 seconds), including collapsed
defaults, independent category expansion, nested check/message drill-down and search across
all supported fields. TypeScript compilation and whitespace checks passed. No engine,
scoring, schema, generation, product version or user-bundle change was made.

#### Documentation consistency review — November 11

Reviewed the current user guides and canonical command references after the UI changes.
The detailed ground-truth section already described collapsed categories and search, but an
earlier Studio section and `docs/macos.md` still directed readers to the removed Mac coverage
panel. Updated both to locate the census in generation ground truth and describe platform-neutral
evaluation reporting. Studio now also explains defective checks versus diagnostic messages and
when saved-report viewing, re-evaluation or a fresh generation is needed.

Corrected the README capability summary to distinguish five equally weighted schema-5 pillars
from legacy four-pillar evaluation. Moved a misplaced ground-truth link out of the scenario
reference's YAML front matter. Canonical skill/command Mac references already describe the
retained ground-truth census correctly and needed no regeneration.

Checked **75 relative links** and available YAML front matter across six relevant documentation
files; no missing targets or metadata errors remain. Stale-panel/filter/four-pillar wording
search and whitespace checks passed. No release notes, product version or runtime code changed.

### PR integration and CI — November 11

User authorized opening a PR to `dev`, monitoring/fixing CI and merging after validation.
Feature commit `9d105bb5` is on PR **#470**. The full frontend suite passes **371 tests**
(13.18 seconds). Full routine and remote CI runs are in progress; no merge has occurred.

Integration repairs preserve the production checks:

- Recovery fixtures now explicitly establish the GUI session their cleanup logoffs close.
  The combined workload seeds these sessions in warmup and places cleanup far enough inside
  collection for its existing source/session timing. The native-workspace/terminal fixtures
  similarly provide an authored session instead of assuming baseline creates a storyline owner.
  Combined exact recovery and native-workspace recovery both pass (**two tests**, 80.01 seconds),
  including resumed/control and source-filter comparisons. This resolves the two previously
  recorded fixture failures without accepting missing required intents or weakening assertions.
- The shared test network factory now supplies protocol-correct UDP IP-byte defaults while
  preserving explicit values for validation. The authored-hour ordering spy calls the real
  execution owner rather than suppressing all canonical occurrences. The affected ASA,
  network-observation, ordering and documentation controls pass **159 tests** (7.26 seconds).
- The first remote lint failure was the worklog's first trademark reference; corrected the
  required marker. Lint/format and behavior/version declarations remain required.

No product version, release tag, publication or scoring threshold change is included.

The broader routine run exposed a config-validator integration defect: it interpreted the
semantic `ground_truth_contracts.yaml` document as format-keyed correlation rules. Registered
the file alongside the existing non-format evaluation documents, retaining format/field checks
for files that use those schemas. Corrected the firewall test's optional-coverage severity,
the IDS UDP fixture's transport overhead, and condensed the canonical bundle reference to its
existing focused-document budget. Regenerated the ignored local skills through the installer.
The affected config/identity/IDS/firewall/skill controls pass **105 tests**, 93 slow cases
deselected (16.67 seconds); checks and rule thresholds were not relaxed.

The same explicit-session setup repair now covers both terminal CLI variants, the packaged
native/filesystem smoke inputs and the thirty-minute acceptance fixture. The latter retains
its activity requirements and measurement rules; only the previously assumed cleanup owners
are now authored, with their startup in warmup and cleanup safely inside collection. Terminal
generation/filtering, exact checkpoint recovery and filesystem recovery pass **five tests**
(94.54 seconds). The native smoke and thirty-minute acceptance fixture generate successfully;
native-smoke agreement is **100%** with 25 correct checks. The user's captured MacOS-test input
and its comparison bundles remain unchanged.

The completed Ubuntu routine shard found one further golden-fixture count mismatch: the new
semantic contract adds one packaged config document. Updated its expected file count from
101 to 102, preserving the exact 14 expected validation errors, their order and deduplication.

The Windows and Ubuntu routine shards also exposed stale assertions that generic segment
coverage must warn and that a valid action cannot have informational alternative-source
coverage notes. Updated those assertions while retaining configuration-error checks. The raw
Zeek emitter regression now requires supplied UDP accounting to remain unchanged; canonical
accounting validation remains upstream. These repairs and the golden count pass **151 focused
tests** (8.31 seconds). A pre-existing launchd guard simulation compilation failure occurs only
on Linux; expose captured compiler stderr in its assertion so CI can identify the actual
portability defect without dropping strict compiler warnings. Ruff and whitespace checks pass.

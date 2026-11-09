# Representative Mac workload acceptance

**Current result (November 7, revision 482): PASS within the bounded scope.**
The unchanged workload passes complete native process coverage, independent joins,
browser ownership review and deterministic evaluation (95.70/100). Exact recovery
and native-only equivalence pass separately for the combined workstation and positive
Code filesystem workload. See the final results below; earlier failures remain history.
Standard-persona catalog launch qualification is now complete; the P2 cross-platform
catalog audit, Studio user acceptance and release gates remain open.

The user authorized item 1 of the release-preparation sequence: fresh generation
and bounded review of the actual MacOS-test scenario against integrated behavior
revision 474. Studio interactive acceptance, integration and release gates remain
separate. The eforge-generate/evaluate workflows apply; preserve authored input
and prior bundles, use a fresh output root and do not weaken coverage or tune the
scenario to conceal defects. No native collection or external workload execution
is part of this task.

## Source access

Read-only Studio metadata identifies the same managed draft
`45fc2adf-76a8-435c-8cd4-b74dbe1a4848` (MacOS-test, display name macOS Test).
The saved index source hash is
`b5ca9d9c98c380494d355fb39bfd40411826d9c68e21eedb901137e358ed1b00`.
The previously authorized November 4 temporary source and run directories are
no longer present. Direct reads of the exact current Documents draft return
macOS PermissionError/EPERM even with sandbox escalation. No service descriptor
exists for a running Studio helper. No cached library content or historical
resolved bundle has been substituted for the authored source.

The user copied that managed draft to
`/private/tmp/eforge-macos-test-input.XntSY1/draft`. Its source matches the saved
original hash exactly. The prior baseline working source hash
`18be80547b29d767406b76a2665f69c0ced5c6c6a36938caccdfb080cd95c263`
reflects the previously agreed macOS 26-to-27 compatibility-only changes. The
prior revision-384 run had 229 forks, 291 execs, 200 known exits, zero unknown
results and PASS evaluation across 224,701 records; these are comparison history,
not current-run results.

Acceptance root: `/private/tmp/eforge-macos-acceptance-20261106-_31mu3pa`.
Its `reports/CONTEXT.json` records the baseline and current commit. The prepared
read-only metrics script is `/private/tmp/eforge-macos-acceptance-review.py`
(syntax-checked; not exercised on a completed current bundle). It streams native/eCAR
records into bounded process/file/ownership/sequence metrics.

## Fresh validation and generation: failed acceptance

Preserved the full copied authored draft under `original-draft/` and made a separate
`working-draft/`. The only source changes are the previously authorized three literal
`macOS 26` to `macOS 27` compatibility substitutions. The working source hash matches
the November 4 baseline exactly. No seed, format, baseline, deployment, process-coverage
or event changes were made. Validation and generation used the repository working
directory without a project-root override. No production code was edited for this run.

Validation passes with zero errors, zero warnings and the same two informational
pivot notes. The workload retains six hosts, three users, an eight-hour window plus
one-hour warmup, seed 42, medium baseline, twelve output formats and all 85 authored
Mac process intents. Its Mac users are analyst and project_manager personas.

Fresh default-target generation exits **21** after **280.326 seconds**, at final
complete-native-process reconciliation. MAC-01 has **118/118 forks, 150/164 execs,
and 13 unresolved aggregate starts**. Diagnostic eCAR staging identifies the starts:

| Image | Aggregate starts |
| --- | ---: |
| Finder | 5 |
| Safari | 3 |
| Microsoft Edge | 3 |
| Microsoft Teams | 2 |

The four images are cataloged but absent from the qualified Finder-launch image
set in `macos_execution_metadata.yaml`. The remaining missing exec is exactly joined
by execution ID to `/opt/homebrew/bin/ssh -V` (PID 62693); its native decision is
`entitlements_unknown`. Ten MAC-01 exit decisions also lack image-security metadata.
These are canonical launch/metadata coverage gaps, not source-formatting errors.
Current baseline selection reaches these catalog entries; the exact change that
shifted selection from the historical sample has not been isolated. A supported fixed
seed passing historically does not prove complete coverage across other app selections.

MAC-02 prepared ingress contains 79 forks, 92 execs and 75 exits, with no aggregate
starts or nonexported in-window decisions. MAC-01 prepared ingress contains 118 forks,
150 execs and 104 exits, including one Chrome helper exec. These are diagnostic
prepared facts, **not published native output or an independently accepted bundle**.

Neither Mac launches Code in this workload, and neither has prepared native
create/modified-close/rename/unlink occurrences. The run therefore does not exercise
the bounded Code filesystem integration or Code helper family. Their existing focused
test evidence remains separate; absence here is not proof of an implementation defect.

There is no `GENERATION_MANIFEST.json` or completed authoritative bundle. No evaluation
was run and no current score, integrity pass, native-sequence pass or full narrative
acceptance is claimed. Preserve `bundle/.eforge-generation/` and all reports; no output
was overwritten, no partial-coverage rerun was substituted and no resume is claimed.
The failed short run has no committed recovery cursor. Peak child RSS was 644,874,240
bytes (about 615 MiB), above the forecast upper estimate of 228.7 MiB; this is a
secondary resource-forecast observation, not the cause of the generation failure.

Reports outside Git include `validation.json`, `generation-execution.json`, separate
generation stdout/stderr, `FAILED-STAGING-DIAGNOSTIC.json` and
`UNKNOWN-EXEC-EXACT-JOIN.json`. Raw authored/generated/private content stays outside Git.

## Result and next action

**FAIL: integrated MacOS-test acceptance remains open.** Repair canonical launch
admission/routing and the required Homebrew SSH executable metadata before repeating
this unchanged workload and its bounded review/evaluation. Do not infer qualification
from catalog presence, invent entitlements, weaken complete coverage or narrow the
scenario to recover the historical score. Any additional native qualification remains
bounded follow-up work, not implicitly authorized collection from this acceptance task.
The P0 blocker is recorded in `TODO.md`; historical November 4 results remain historical.
Studio GUI acceptance, integration and release gates remain separate.

## November 7: authorized root-cause follow-through

The user authorized the proposed canonical launch/admission, exact metadata,
preflight and regression fixes, including use of the reference Mac where needed.
Preserve the unchanged authored workload, complete coverage and failed staging.
Reference host access succeeds through the actual SSH client. Finder/Safari are
present on macOS 27.0.1 arm64; Edge/Teams/Homebrew SSH are absent. Bounded static
signing inspection reads only those executable facts, not personal logs/data.
Isolated public Edge/Teams/OpenSSH package inspection is in progress without
installation or execution. Local technical reports and a pre-edit source diff
are under `/private/tmp/eforge-macos-root-fixes-20261107`.

Confirmed structural issue: `generate_process` routes only explicitly qualified
GUI images into the native startup owner; other catalog GUI requests can reach
the generic aggregate path. Corrected browser/network ownership also broadens
previously case-folded Mac app eligibility and removes cross-family browser
substitution. Those ownership fixes must remain; passing one historical random
sample was not a catalog-coverage contract. The exact contribution of shared
random-stream changes remains to be established.

### Implemented launch ownership and metadata (revision 475)

The shared allocation-free `macos_launch_support` query uses exact compiled binary
identity and frozen runtime/launch policy. Schema validation checks reachable
installed baseline apps and authored installed targets; engine initialization uses
the same query, and the process-execution boundary rechecks before admission.
Canonical GUI routing consults that same mechanism result. Complete coverage does
not silently remove unsupported candidates; explicit partial diagnostics retain the
old unavailable-observation behavior. Output format filtering does not determine
which canonical launch contract applies.

Finder is a per-session singleton, with a lazy canonical startup on first activity
and reuse while live. Authored explicit launches stay explicit. The affected main
images plus the additional reachable Excel/nano gaps receive independently inspected
static templates, exact bundle identifiers and explicit modeled validation policy.
The reference Mac's Apple nano is not the catalog's Homebrew nano and is not used as
its template. Exact reference digests, provenance and model limitations are in
`catalog-native-metadata.md`. No app helper graphs were inferred or qualified.

Safari has 177 top-level entitlement entries and integer arrays. A bounded v2
property-object capability preserves the entire shape with a distinct checkpoint
tag; older source capabilities reject it. Existing depth/node/text limits remain.
Unknown, absent and empty values remain distinct. No runtime signing measurement
is claimed from static inspection.

Confirmed random-stream coupling: nominal file-workload selection consumed the
system-traffic RNG even without an eligible editor. It now uses an independent
stable generation-seed/host/hour stream. Ownership corrections for case-preserved
Mac executable lookup and exact-family browser reuse remain intact. Restoring a
historical sample was not the repair criterion. A five-seed regression verifies
that filesystem sampling cannot resample later app choice and that hosts differ.

Exhaustive preflight also exposes broader pre-existing development-catalog gaps
(e.g. Docker CLI, IntelliJ, Postman, Sublime, git and build tools). These are rejected
early rather than qualified, filtered or hidden. Focused lifecycle fixtures now
declare the applications their tests actually exercise; they do not imply that every
installed developer application is natively supported. The unchanged actual user
workload's reachable candidates pass without source/deployment overrides.

### First completed bundle and further owner corrections

Revision-475 fresh generation completes under
`/private/tmp/eforge-macos-root-fixes-20261107/bundle`, with 214/214 forks and
277/277 execs, zero aggregate starts and exact independent census identities.
All 192 canonical exits are observed; 188 have known published native outcomes.
The four unknown outcomes are exactly `/opt/homebrew/bin/ssh -V` invocations.
All 277 native execs independently join to eCAR by host/PID/generation/image and
matching exported credentials. All forks and known exits also join; fork-only and
pre-window lifetimes use separately reported unique PID/image matches. Native
sequence order is increasing without duplicates. There are no attributed FILE/FLOW
ownership contradictions or same-profile Chrome root overlaps in the bounded script.

The originally prepared review script's blanket 100ms timestamp join was invalid
for configured source latency. It is retained as a diagnostic, not reported as
missing evidence. The replacement report uses exact generation/credential identity
for every exec and separately reports less expressive fork/exit joins and observed
source-time deltas. No production timing or timestamps were changed to satisfy it.

The first attempted evaluator command used an invalid `--json` option and did not
run evaluation. The corrected single evaluation (`--format json`) verifies bundle
integrity and scores 95.01221935333223 across 242,556 records, but **FAILS** the hard
indicator-accuracy gate (84.7512 versus 85). Samples expose ASA 733100 appliance scan
alarms attributed to authored scans without checking the scanner. The evaluator
now requires a matching scanner source for those alarms. Focused positive, wrong-
source and unattributed-alarm regressions pass; the acceptance threshold is unchanged.
The original report remains the original failing report, not relabelled.

Revision 476 gives only the exact installed Homebrew `ssh -V` invocation its natural
status-zero completion through the existing command-completion owner. Upstream
OpenSSH `ssh.c` explicitly prints version and exits zero for `-V`; this is not a
successful-session inference. Other SSH commands remain unqualified by this selector.
The five real-engine declared-command regressions pass, including native exit and
independent census accounting for this invocation. A separate final generation is
running at `bundle-final`; neither completed earlier data nor failed staging is
replaced. Its final result/evaluation are pending.

### Verification completed while the final run executes

- 486 signing/publication tests pass, including exact extended-shape round trips,
  legacy-capability refusals, invalid-value bounds and per-phase publication faults.
- 40 regular-GUI native/filtered cases pass for the expanded main-image list. The
  focused launch suite verifies early preflight refusal, allocation-free execution
  refusal, Finder reuse and five-seed independent filesystem sampling. Four final
  shared Finder baseline/authored cases pass separately after isolating fixture
  application assignment from unrelated terminal/code choices.
- 92 filesystem/collection/source-profile routine cases pass (one slow deselected).
  Tests injecting exact save counts now call the workload's explicit RNG interface;
  the baseline owns its stream and its independence is tested separately.
- Filesystem exact checkpoint/resume/native-filter acceptance passes in 31.61s,
  with positive create/close/rename/unlink rows and **PASS deterministic evaluation**.
- Combined workstation exact recovery passes in 49.22s.
- Five real-engine declared-command completion cases pass, including Homebrew SSH.
- All 25 existing/updated ASA evaluator cases pass with the unchanged hard threshold.
- Whole-repository Ruff and format checks pass; behavior manifest is synchronized.

The early admission checks intentionally require test scenarios to declare the apps
whose lifecycles they exercise; unrelated unqualified catalog apps are not enabled to
make a narrow unit fixture resemble a full catalog acceptance run. The actual user's
source, seed, selected formats, deployment and baseline remain unchanged throughout.

The final owner regression selection passes **44 tests** (nine slow deselected):
launch support, Chrome, Code, root process ownership and native system jobs. The
installer-skill/document contracts pass **53 tests**. The broader native catalog
qualification gap has its own durable P1 backlog item; the Homebrew SSH metadata
part of the older P2 follow-up is now implemented, while native sqlcmd network
expansion remains separate.

### Revision 477: retained browser lifetime ownership

Revision 476 completes generation in 301.48s with complete starts and all 192
exits known and published. It is retained as an intermediate result, not final
acceptance: extending the read-only browser check beyond Chrome finds two same-
profile root overlaps, one Safari and one Edge. Both are ordinary baseline requests,
not authored independent profiles. Their existing processes had already been closed
in a later planning phase, so the running-only lookup missed lifetimes still active
at the earlier requested timestamp. Safari additionally crosses modeled logins for
the same host/user/profile. This is a historical process-query ownership defect.

The browser reuse owner now queries both live and bounded retained process entries,
resolves the exact execution at the requested time, and verifies its object identity
before comparing executable/profile/user. It does not revive an ended process or
reuse another PID incarnation. No second retained registry or checkpoint owner is
introduced. Existing callers still get running-only process lists by default.
The two real-engine Edge/Safari regressions verify historical reuse, same-profile
cross-login forwarding and a fresh PID after the old lifetime ends. All eight browser
instance tests and 45 process-precedence/PID-reuse/state regressions pass.

A separate unchanged-source revision-477 generation is running at `bundle-v477`.
Both exact recovery tests are repeated after this semantic change. Final native
reconciliation, generalized browser overlap checks and its single evaluation remain
pending. The earlier 100ms join diagnostic and two completed intermediate bundles
remain preserved with their actual limitations.

### Revision 478: connect the owning paths; correct indicator defaults

The revision-477 run completes in 315.44s with 214/214 forks, 277/277 execs and
192/192 known/published exits, zero unknown outcomes, and independent joins for
all phases. Its broader browser check still finds the same two overlaps. The
historical query repair is valid but was not sufficient: inferred network owners
have a second running-only/same-session lookup and explicitly disable browser reuse
when creating a process. That path now consults the shared browser lifetime/profile
owner first, with the actual connection/source-visible deadline. It does not use the
old generic image-only fallback for browser roots, so distinct profiles and explicit
independent-instance intent remain distinct. Helper processes retain their own
non-root ownership path. The extended real-engine regressions call this exact network
owner path for retained Edge/Safari roots and pass.

The revision-477 evaluation remains **FAIL 95.01221935333223** across 242,560 records.
The initial inference that generic ASA alarms caused the indicator-accuracy failure
was incomplete. The failing authored port scan omits its source override; the model
serializes that default as an empty string, the canonical scanner uses the storyline
host's IP, but evaluation treated the empty string as an asserted address. The
central resolved-intent builder now applies that documented default before matching
and scoring. Explicit source overrides remain authoritative, and wrong-source rows
still fail. The stricter 733100 alarm association is retained as an independent
matching correction, not presented as the cause of those 190 indicator failures.

All **35 browser/ASA/indicator regressions** pass, including the concrete connection
owner call, helper-versus-root classification, absent/empty source defaults, explicit
external sources and negative wrong-source checks. No source records, scenario inputs
or evaluation thresholds are rewritten. A fresh unchanged-source generation runs at
`bundle-v478`; exact recovery/filter/evaluation is repeated after the network-owner
change. Earlier completed candidates retain their actual results and limitations.

### Revision 480: observed ordering defect and event-time ownership

Revision 478 completes in 321.89s but still has the same two browser overlaps.
A passive call trace of the unchanged workload establishes the concrete ordering:
profile traffic first commits Edge at 17:47:31, then requests the same profile at
17:33:11. Retained-lifetime queries cannot reuse a process that has not started at
that earlier time. The diagnostic trace stops deliberately at the first overlap;
`browser-trace-bundle` is incomplete diagnostic output, never acceptance evidence.

The baseline now plans standard persona requests for all sessions in each bounded
host/hour before committing browser/network state, sorts by occurrence time and
uses per-intent deterministic emission randomness. There is no new persistent
queue or checkpoint owner. Flexible inferred activity can wait for an already
committed future browser main, with a bounded modeled readiness gap and renewed
session/pass admission; callers with fixed source deadlines refuse rather than
fabricate a duplicate root. Explicit fresh storyline launches and independent
profiles keep their existing semantics.

Network source resolution now uses a detached event-time process view, and the
identity lifecycle planner resolves source/target actors at the occurrence time.
The real-engine retained-browser FLOW regression initially exposed this second
lookup dropping PID after a later termination. It now preserves the exact active
execution, including image/credentials, without reviving state or attributing a
new PID incarnation. A state regression verifies historical exec fields, detached
mutation, end boundaries, restore and unchanged state digest.

The final focused selection passes **86 browser, identity, network and state
regressions**; **34 activity/traffic regressions** pass. The chronological profile
regression exercises the real profile-traffic path, checks call ordering and
complete native start census. Whole-repository Ruff and format checks pass and
the behavior manifest is revision 480. Fresh validation of the unchanged source
has zero warnings/errors (two narrative-pivot information messages).

A separate clean revision-480 generation runs at `bundle-v480`, alongside both
exact recovery tests. Final evaluation, native/eCAR joins and generalized browser
overlap results remain pending until that bundle completes. The old failing and
intermediate bundles/reports remain preserved with their original results.

Revision-480 recovery initially reports one failed assertion after successfully
verifying exact resumed/control files and native-only byte equivalence. Its fixed
unknown-outcome total of one was tied to the old sampled background commands. The
new scoped persona stream selects an additional literal `/bin/zsh -c 'ls -la
~/Library/LaunchAgents'` alongside the existing `id; groups` control; neither has a
qualified completion. Both hosts retain complete start/accounting reconciliation
and all known exits publish. The test now requires positive unknown outcomes,
keeps strict per-host accounting and independently checks the designated compound
control has its eCAR terminal and no invented native exit, instead of freezing a
sampled total. No command-completion policy or native coverage threshold changes.
The initial test report is preserved. Filesystem recovery passes on revision 480
with positive operations, exact resume/filter equality and passing evaluation;
combined workstation recovery is rerun after this test-only correction.

### Final unchanged-workload acceptance: revision 480

Fresh generation completes successfully in **332.875 seconds** at
`/private/tmp/eforge-macos-root-fixes-20261107/bundle-v480`, with an authoritative
manifest. The source still has SHA256
`18be80547b29d767406b76a2665f69c0ced5c6c6a36938caccdfb080cd95c263`;
its original copied input retains
`b5ca9d9c98c380494d355fb39bfd40411826d9c68e21eedb901137e358ed1b00`.
Seed 42, all twelve formats, medium baseline, six hosts, three users and the
collection window are unchanged. There are no format/seed overrides, packs or
OOB hosts. The product version remains 2.2.0a4; this is not a release.

| Host | Forks expected/published | Execs expected/published | Exits observed/known/published | Aggregate starts |
| --- | ---: | ---: | ---: | ---: |
| MAC-01 | 118/118 | 157/157 | 105/105/105 | 0 |
| MAC-02 | 82/82 | 99/99 | 71/71/71 | 0 |
| Total | 200/200 | 256/256 | 176/176/176 | 0 |

Both hosts have exact census identity matches, complete exit accounting and zero
unknown outcomes. All **85 authored Mac process intents** occur and have visible
native evidence. All 256 native execs independently join to eCAR by host/PID/public
generation/image and all seven exported audit credential fields. All forks/exits
also join; 12 forks and 21 exits use separately reported unique PID/image fallback
for fork-only or pre-window lifetimes whose eCAR rows lack an exec generation.
There are zero unmatched native phases or eCAR terminal rows without native exits.
Observed source timestamp differences reach 5.415 seconds; the exact identity joins
supersede the earlier diagnostic script's inappropriate 100ms process-join cutoff.

Native timestamps are ordered, global sequences strictly increase and have no
duplicates. The generalized host/user/executable/profile browser check finds **zero
overlaps** (Safari one root, Edge two nonoverlapping roots, Chrome one root).
All 403 attributed FLOW rows and both attributed FILE rows agree with their eCAR
actor PID/lifetime. There are 23,666 FLOW rows without PID; these are reported as
unattributed, not counted as successful process joins or proof of universal endpoint
attribution. This check does not turn network-sensor coverage into process visibility.

The one normal evaluation of this completed bundle is **PASS 95.69993178263871**
across **251,687 records**, with every applicable hard acceptance criterion passing.
Parseability and Causality score 100; Plausibility 86.982 and Timing 94.772. The
aspirational anomaly-rate flag remains (0.1% versus nominal 1–5%); it is not concealed
by tuning the scenario or acceptance thresholds. Fifteen of twenty aspirational
criteria pass. No new blind authenticity panel or general native fidelity claim is
made by this deterministic evaluation.

Final reports, outside Git with the private scenario/output, are
`generation-v480-execution.json`, `validation-v480.json`, `evaluation-v480.json`,
`exact-joins-v480.json`, `browser-overlaps-v480.json` and `bounded-review-v480.json`.
The bounded review's process matches remain diagnostic because of its old 100ms
cutoff; use `exact-joins-v480.json` for phase matching. All earlier failures and
intermediate candidates remain untouched.

Additional final verification:

- **159 launch/Finder/GUI/command/evaluator regressions pass** (one slow deselected).
- **86 browser/identity/network/state regressions pass**; **34 activity/traffic
  regressions pass**. Earlier extended entitlement/publication and filesystem
  regression results above remain applicable; their implementations did not change
  during the final generation.
- Combined workstation exact recovery passes in **48.66s** after the documented
  test-only sampled-total correction. It retains positive background native execs,
  unknown compound-command negative control, strict accounting, exact resumed/fresh
  deterministic files and native-only byte equivalence.
- The revision-480 filesystem exact recovery test passes with positive native
  create/modified-close/rename/unlink, exact resumed/fresh/native-only output and
  passing evaluation. The initial two-test run took 76.07s and reports its separate
  workstation sampled-total failure honestly; only workstation needed rerunning.
- This MacOS-test sample launches neither Code nor qualified browser helpers. The
  positive filesystem and helper/recovery fixtures remain separate evidence; this
  workload does not substitute for them.

This closes the November 6 integrated MacOS-test P0 blocker and the bounded repairs
authorized November 7. Remaining native catalog qualification stays a separate P1;
unsupported candidates still fail shared preflight under complete coverage. Finder
startup timing, larger helper graphs, unqualified launchd messages and exact vendor-
build parity remain within the documented limits. Studio interactive acceptance,
user satisfaction with the generated result, integration and release gates are not
closed here. No commit, push, PR, version bump, publication or release-gate campaign
was performed.

Final hygiene passes: all 35 manifest file hashes verify, repository-wide Ruff and
format checks pass (1,507 Python files), `git diff --check` is clean, and generation
behavior revision 480 matches its surface digest. Evaluation still logs its existing
unknown-field warnings for additional Cisco ASA fields; its bounded conformance and
all applicable hard criteria pass. These warnings are not a new external-parser
certification. Native source fidelity and external-parser acceptance retain their
separate documented contracts.

### Catalog follow-up acceptance: revision 482

The user-authorized standard-persona catalog completion has its own
[catalog worklog](2026-11-07-macos-catalog-qualification.md). Its final fresh
unchanged MacOS-test generation takes 312.502s and passes evaluation at
95.69993178263871 across 251,687 records. All 35 manifest hashes and the same
200/256/176 native fork/exec/known-exit identities reconcile, with all 85 authored
Mac starts visible, zero overlaps and zero attributed FILE/FLOW failures. All 28
data files are byte-identical to revision 480. New developer/desktop launches have
separate positive tests; this workload does not substitute for them. Both exact
recovery/filter checks pass again. The P2 full catalog audit, Studio acceptance
and release gates remain separate; no release action was performed.

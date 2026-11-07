# Alpha 5 preparation and automated readiness

The user explicitly requested the next alpha version bump and items 1–2 of the
remaining readiness plan: full automated release validation and a bounded longer
Mac/mixed-fleet resource measurement. Studio interactive acceptance remains for
the user. This authorizes preparation/testing, not tagging or publication.

Current source is `codex/macos-workstation-support`, HEAD `42d6440a`, with the
previously authorized implementation/documentation changes still uncommitted.
Remote tags confirm alpha 4 is the latest alpha; alpha 5 is unused. Target product
version is 2.2.0a5, with derived Studio version 2.2.0-alpha.5. The explicit request
authorizes preparing version files here; the normal release commit/integration on
dev remains separate from this working-tree preparation and the Studio hold.

CI needs a committed exact snapshot. Prepare an isolated validation branch with
read-only test/build workflows, retaining the original workspace and excluding
generated blind-review artifacts from the validation snapshot. Do not open a PR
into dev, move main/dev or create/push a release tag. Record exact source hashes,
workflow differences and validation commit/run IDs. Native platform CI/installer
success cannot be claimed from local Mac-only checks.

Planned checks: version/behavior/config/lint checks; known timing inventory and
older Mac extended regressions; routine pytest and enforced 70% Linux coverage;
all four slow shards without coverage; Python portability; Studio/frontend/Rust/
state recovery on supported native platforms; verified preview DMG and both Linux
AppImages. Do not weaken independent assertions or increase timing inventory caps
to hide failures. No soak campaign is part of this request.

Use one bounded longer Mac-inclusive workload with checkpointing on an otherwise
idle reference host. Record wall runtime, peak process-tree RSS, sampled working
disk, committed checkpoint size and completion/coverage. Measurement is not a
general scalability guarantee or Studio acceptance.

## Source and automated execution

Prepared 2.2.0a5 / 2.2.0-alpha.5 and the versioned changelog; no release tag,
publication or integration PR exists. Python/Studio sync, full Ruff checks and
behavior declaration checks pass. Behavior revision 483 migrates eleven remaining
continuous timing calls to semantic timing scopes. Two exact byte-size samplers
have separate non-temporal inventory caps; the existing temporal cap stays at
195 selectors / 358 calls. The timing guard passes (3 tests).

Focused filesystem/boot/executable checks pass (51 tests). Existing helper,
persistence and activity checks initially passed 552/578; boot fixture runtime
construction/signature and the stale termination fixture were corrected.
The latter now terminalizes through StateManager, rather than mutating only the
old cache and leaving canonical state live. Repaired extended Mac regressions
pass 4/4 in 170.90 seconds, retaining fresh-process/hash-seed determinism,
native filtering and exact SSH checkpoint recovery. Native assertions now require
each six-process SSH startup/close graph and per-event-type contiguous sequences.
Browser assertions join fork CREATE to helper exec MODIFY and exact parent/child
lifetime identity, including source-owned warm-up parents.

An isolated worktree/branch `codex/alpha5-readiness-20261107` contains validation
snapshot `c74b454cec54d36824a20e9df3ebc7ec70e10f98` (parent `42d6440a`).
Generated `scenarios/iteration-test/blind-test/` changes/artifacts were excluded;
the original worktree is preserved. Source-file hashes and the transfer archive
are under `/private/tmp/eforge-alpha5-readiness/`. The validation branch alone adds
two workflow_dispatch jobs to existing Installer Builds, calling reusable CI with
release coverage and Release Slow Tests on the exact same SHA. Other workflow
permissions and preview-only installer behavior remain unchanged. No changes were
made to main/dev or the Release publishing workflow.

[Validation run](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42405201687)
includes Linux routine coverage, Windows routine/durability, three native Studio/
state-recovery platforms, four slow shards without coverage, Python portability,
and three verified preview installers. CI lint and Python 3.12->3.13 checkpoint
portability have passed; remaining results are pending. The original worktree's
full default macOS pytest run is also in progress, without coverage.

## Bounded resource probe

Reference host: authorized `biancomac-d.local`, arm64 macOS 27, isolated source,
uv cache and managed Python 3.12 under
`/private/tmp/eforge-alpha5-resource.ys0OaM`. Engine/config files match the validation
snapshot. No native capture, privileged helper, real scenario commands or ambient
application collection is used. The measured input is committed as
`tests/fixtures/scenarios/macos-release-resource.yaml`: the existing invented
three-user/three-host Mac/Windows/Linux fleet, 26-hour collection plus one-hour
warm-up, medium baseline, seed 42, default target, native Mac ES/ULF added to its
existing endpoint/network formats, six-hour checkpoint cadence. Input SHA256:
`6fb5b75c8b904fbe5369a619940ccf0d7e7fe51a1a6ded966317212fa1267d1a`.
Validation has zero errors and one intentionally retained no-firewall warning;
this workload makes no ASA/NAT/firewall claim.

`scripts/measure_release_workload.py` samples aggregate simultaneous parent/child
RSS every 50 ms and uniquely allocated output/workspace disk every 200 ms. Peaks
are sampled lower bounds; they exclude dependency caches, preserved checkpoint
backup and the supervisor itself. Generation wall time sums initial generation
and resume; stopped checkpoint verification is timed separately. A fresh output
is required, a one-hour wall cap applies to generation, and valid checkpoints are
preserved before verification/resume. The final bundle is hash-verified.

The instrumentation pilot completed 26 hours with a verified exact resume, but
requested suspension immediately and therefore forced an hour-one checkpoint.
It is retained separately under `measurement/` and is not used for representative
checkpoint-size reporting. The supervisor was corrected to wait for the first
cadence checkpoint before requesting suspension; a fresh same-input run under
`measurement-cadence/` is in progress. This changes only the measurement script,
not engine behavior; its final hash/results will be recorded below.

### Cadence measurement result (revision 483)

The same-input cadence run completed: 67.859 seconds of generation/resume,
5.964 seconds of stopped checkpoint verification, peak process-tree RSS
335,298,560 bytes (319.8 MiB), sampled peak allocated working disk 57,524,224
bytes (54.9 MiB), and final logical output 16,962,792 bytes (16.2 MiB).
At the stopped hour-seven checkpoint (first normal cadence at six, then the
requested suspension), retained workspace size is 24,446,444 logical bytes
(23.3 MiB), 26,279,936 allocated bytes (25.1 MiB). The retained size includes both
indexed recovery points, shared immutable objects and staged output; it is not
one participant head or an estimate of a 24-hour cadence. Verification hydrated
all 25 participants with matched run identity, exact behavior and zero dangling
parents. Final bundle verification passed; manifest seed is 42 and target default.

Native start census reconciles 83/83 forks and 133/133 execs, no aggregate births;
57/57 known exits match. Nineteen additional exits have explicitly unknown outcomes
and no invented native exit row; start completeness is not exit completeness.
The forecast upper memory estimate is 328,989,435 bytes (313.7 MiB); actual RSS
is 1.019 times that estimate. Output/disk/checkpoint observations remain below
their upper estimates. Memory forecasting remains approximate and has a P2
calibration backlog item, including the earlier larger MacOS-test miss. This is
one bounded three-host duration check, not a larger-fleet capacity guarantee.

Reports/manifests are copied to
`/private/tmp/eforge-alpha5-readiness/resource-evidence.tar.gz`; full synthetic
bundles and the stopped checkpoint backup remain in the reference task directory.

## Readiness defects found during the first full pass

- Windows routine collection failed in 13 modules because four Mac reference tools
  imported POSIX-only `pwd` at module load. Native account access now lives behind
  a lazy `_current_account` boundary; mocked account reads remain portable. Focused
  catalog/reference tests pass 152/152. This does not enable Mac collection on Windows.
- The independent native service audit still classified the two now-qualified root
  residents as catalog-only. Audit and its exact two-entry test now distinguish
  pre-existing residents from the sixteen catalog-only entries, retaining no-startup
  and no-native-runtime-validation limitations.
- Baseline terminal-boundary tests mocked discrete RNG but not the new timing
  owner. Their selected zero jitter is now supplied at that explicit sampler seam;
  rendered-close assertions remain intact. A new reviewed post-planning persona
  bound call and the filesystem effect owner were added to the exact inventories.
- Older proxy tests expected a supplied wire header to be rewritten by process or
  host defaults, conflicting with the repaired canonical request ownership contract.
  Explicit headers now have exact preservation assertions, while an additional
  unspecified-header control still requires one stable per-process default. All
  116 proxy tests pass; independent header/budget tests remain intact.
- An existing empty-object contract caught a real native codec defect: Pydantic's
  second union coercion reinterpreted an empty frozen entitlement object as an array.
  The field now accepts the shared exact bounded freezer's authoritative result
  through a plain validator. All 64 native codec contract tests pass. Behavior
  revision 484 declares this localized source serialization change. Repeat the short
  resource probe on this final engine before final reporting.

### Corrected snapshot and subsequent fixture reconciliation

Corrected validation snapshot `7aa8cc19` (parent `c74b454c`) is running at
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42406220372 .
The next dispatch superseded the original reusable CI/slow groups through their
existing same-branch concurrency policy; original cancelled jobs are not passes.
Original x86_64 Linux preview installer verification passed. The original Linux
Studio Python gate found a single stale application-editor schema fixture
(539 passed, 1 skipped); the fixture now includes the live Mac argv/signing fields.
The complete local frontend suite passes 348 tests, and its production build passes.

An additional 154 process/file/recovery tests pass after retaining the engine's
single already-bound runtime artifact registry (including a matching fresh registry
for hydration), and constructing genuine historical StateManager schemas without
later filesystem directory/inode fields. Native v11 tests now distinguish admitted
integer entitlement arrays from mixed/bool arrays and round-trip all four newly
qualified file operation families. The previous blanket rejection predated the
agreed filesystem integration. Bounds, unknown-field checks and profile admission
remain separately enforced.

The full routine suite also found the filesystem retry dictionary absent from the
mutable retention policy inventory. Revision 485 adds its explicit bounded host/hour
batch owner: configured task counts bound it; successful drain removes it; failed
work blocks hour completion/checkpointing. This is an inventory declaration with
no evidence behavior change, not an exception to the inventory guard.

The final revision-484 resource rerun measured 67.721 seconds generation/resume,
6.071 seconds checkpoint verification, 336,101,376 bytes peak RSS (320.5 MiB),
57,278,464 bytes sampled allocated working disk (54.6 MiB), the same 24,446,444-byte
logical / 26,279,936-byte allocated hour-seven checkpoint workspace, and the same
16,962,792-byte final output. Host is Apple M1 Max, ten physical cores, 32 GiB RAM,
macOS 27.0.1, Python 3.12.15. All 767 engine files matched the local checksum
inventory, and all measured data-file hashes matched the prior revision-483 run.
Final reports and engine-file hashes are retained in
`/private/tmp/eforge-alpha5-readiness/resource-final-evidence.tar.gz`.
Revision 485 only adds inventory metadata; final source/run evidence will be
reconciled after the complete suite finishes.

A read-only triage of GitHub's default-branch dependency warning found the reported
filelock/virtualenv paths originate only in the optional dev extra through
pre-commit. `uv tree --frozen --invert --package filelock --package virtualenv`
confirms that scope; these are not Studio production requirements. No runtime
vulnerability or dependency remediation is claimed from that metadata check.

## Final local reconciliation before the last CI dispatch

The first full default macOS pass completed in 1976.10 seconds with 19,804 passed,
50 skipped, 62 failed and one setup error (2,435 slow/soak cases deselected).
This was a defect-finding pass while repairs were underway, not a passing final gate.
Every affected non-native module was rerun on reconciled source: 660 passed,
3 deselected in 77.54 seconds. Native helper/instance-lock/process-census checks
require normal macOS process inspection and loopback sockets; outside the session
sandbox all 35 tests passed in 18.55 seconds. No test was skipped or weakened to
work around these host permissions. Logs and the exact failure/module inventory
are retained under `/private/tmp/eforge-alpha5-readiness/`.

The extended run also exposed retained SSH/network attribution attempting a live
activity patch after State had already ended its source. Revision 486 separates
historical attribution from mutable live holds/frontiers, resolves SSH source and
session-fence facts at occurrence time, and uses the same event-time query for
State's active predicate. A PID-only request after alias retirement omits ambiguous
source attribution instead of adopting a later PID owner; already-bound durable
SSH continuations retain their original identity. The new positive/negative reuse
control and 717 activity/State/network/SSH checks pass (164 extended cases excluded).
Windows browser tests retain positive same-family reuse while proving Chrome and
Firefox own distinct mains and children, matching the repaired instance policy.

Other final fixture repairs adopt the shared engine registry for retained scripts,
keep infrastructure-auth tests about unspecified domain-selected headers, and keep
v11 integer arrays explicitly bounded at int64 limits. An overlong new behavior
summary was caught by the CLI manifest validator and shortened; the declared
revision/digest and version checks now pass. Studio input/codec tests pass 63/63,
retained-script/UA tests pass 37/37, runtime retention tests pass 12/12, and
v11/editor fixture tests pass 88/88. Full frontend tests pass 348/348 and the
production build passes. The initial suite's failures are all accounted for;
complete final Linux/Windows/slow/native/installer gates remain required below.

### Combined recovery positive controls

The original combined source's valid same-seed run became quiet under corrected
singleton reuse: all authored starts/roles and exact recovery/filtering passed,
but no new incidental background exec or compound command appeared. The test
had depended on incidental baseline selection for both positive/negative controls.
The managed recovery companion now admits already-qualified VS Code in the
Mac-Apple baseline profile and explicitly authors `compound-unknown` at +20m.
Seed 373, medium intensity, collection and original thirty-minute acceptance
source are unchanged. The compound oracle joins its authored PID/host, so extra
legitimate baseline compounds cannot falsely fail an exact-one assertion.
Code itself is now a required native image; the positive background assertion is
retained. Validation has the same four intentional warnings and no errors.
The strengthened full suspend/verify/exact-resume/native-filter test passes in
46.32 seconds: six background native execs, one Code exec, five ULF rows, complete
start census, 44 native known exits and three explicitly unknown outcomes.
Current results are retained at
`/private/tmp/eforge-alpha5-readiness/recovery-final-result.json`; historical
revision-374 `scenarios/macos-workstation-recovery/RESULTS.json` is preserved and
clearly labeled in its README. The reference toolkit's two remaining mocked
`os.getuid` seams now also work where that POSIX API is absent; 149 tests pass.

### Fully reconciled engine CI snapshot

Snapshot `b1c153c6702836b5ec68c0cb4bf9a585c95050d7` is running at
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42407787085 .
Engine revision is 486, digest
`73ae7aa778d77a7e8d1400428e7727a506c5e03f8df3bef893183cfa2d7efbbe`.
This run predates the explicit recovery fixture correction; retain it to discover
all remaining full-tier failures before the final fixture-only snapshot. All three
preview installers passed on prior snapshot 7aa8cc19; b1c153c6's Mac installer,
portability, lint, Windows durability and native state-recovery gates have passed.
A cancelled earlier gate is never counted as a pass. Other results remain pending.

### Working-disk measurement correction

Source inspection found Mac audit ledgers and Windows spools can use system temp,
outside the bundle. Prior reported disk peaks are therefore bundle-only lower
bounds. The supervisor now gives every child CLI phase a private TMPDIR/TMP/TEMP
under `working/temporary`, counts that and `working/bundle` together with inode
deduplication, and supervises checkpoint verification as well as generation/resume.
Backups, reports, dependencies and the supervisor remain outside the measured tree.
It additionally reports retained scratch after success. This changes measurement
instrumentation only; the engine and fixed workload remain unchanged.

The corrected owned-temp measurement completes in 67.937 seconds generation/resume
plus 6.103 seconds stopped verification, with 334,790,656 bytes peak process-tree RSS
(319.3 MiB) and **75,796,480 bytes (72.3 MiB) sampled total working disk**. The
hour-seven retained checkpoint remains 24,446,444 logical / 26,279,936 allocated
bytes; final output remains 16,962,792 bytes. The temp-isolated run's data hashes
match the prior revision-486 run exactly, and bundle verification passes. The memory
upper estimate remains slightly low; the P2 calibration item remains explicit.

The measurement additionally exposes 7,835,648 allocated bytes (7.5 MiB) of retained
Windows/Sysmon SQLite scratch after success: two initial suspension and two
verification spools outside the bundle. Normal final rendering removes its own
spools. The existing discard-only verification contract closes connections and
descriptors but does not delete these outside-root journals. Added a P2 owned-scratch
retirement item, distinct from the existing broader spool-relocation backlog. No
recovery source or external file is deleted to hide the observation; scoped scratch
and reports remain available on the reference Mac. The corrected supervisor's
`final_owned_temporary_allocated_bytes` makes that residual visible.


## Extended-suite reconciliation after revision 486

Validation snapshot `0902bf949c20d0eea75d9e40936e18ad40b18d47` on
`codex/alpha5-final-validation-20261107` runs at
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42409371753 .
Its product runtime source is byte-identical to b1c153c6; the changed recovery
companion and corrected owned-temp measurement supervisor are included. Neither
run is a full passing gate yet. b1c153c6 passed all three native Studio gates,
state recovery, Python portability, lint, Windows durability and preview installer
verification, while three completed slow shards exposed additional failures.
The remaining routine/coverage/fourth-shard results are still pending.

Revision 487 addresses two genuine root causes found by those slow gates:

- A Linux SSH call with no eCAR sink switched from exact to compatibility lifecycle
  construction once it might cross collection. That changed shared RNG consumption
  during warm-up and later Mac native timestamps. Missing eCAR is now an exact
  empty projection cohort; present sinks still require concrete immutable owners.
  Removed the obsolete warm-up-only admission/preview path. The original native
  full/filtered failing case passes and all 162 deferred SSH checks pass.
- Earlier background work can be visited after a later authored terminal launch
  has reserved the session's initial shell. The old readiness path attempted a
  second fresh app and failed. It now declines the unavailable future shell
  without modifying State or creating a window. Both terminal variants have
  positive same-owner reuse plus backdated no-mutation controls; all 15 terminal
  tests and the original Mac SSH exact suspend/resume regression pass.

Other repairs retain current source contracts: Mac 27 fixtures, one run seed for
native boot/activity, public chronological native delivery, fork CREATE joined to
exec MODIFY, absent Windows session IDs on Mac, exact dispatcher/state doubles,
new timing helper call sites, SMB2/3 share_type/path instead of SMB1-only service,
and withheld hashes when capture has missing file bytes. Native completeness
negative control now uses an actually unqualified invented app rather than the
now-qualified Chrome main. Generic SSH transport no longer asserts invalid-user
password authentication. Exact-close rejection tests distinguish permitted ordinary
preterminal rows from forbidden exact terminal admission. Independent counts,
identity/parent/lifetime, no-side-effect and exact recovery/filter assertions remain.
Additional Windows-only UID mock seams use raising=False for absent POSIX APIs.

Local test execution that overlapped source formatting produced manifest-digest
refusals; those are instrumentation timing failures and are rerun on the frozen
revision-487 digest, not counted as passes or independent product regressions.
19 mixed-platform receiver tests pass; 102 source-native/network checks passed
with the remaining ULF test rerun required after that formatting boundary.
Final owned-temp revision-486 reports/provenance are retained locally in
`/private/tmp/eforge-alpha5-readiness/resource-owned-temp-evidence.tar.gz`.
Repeat the same fixed resource workload on final runtime source before reporting
final metrics. No new workload, capture or application installation is authorized
or needed for this repeat.


### Completed slow diagnostics and final owner repairs

All four b1c153c6 slow shards finished: respectively 33/18/16/17 failures, with
537/505/498/574 passes (84 failed, 2,114 passed and five skips overall). These are
full defect-finding results, not a passing gate. Reconciled the remaining original
failures through focused runs: 19 receiver cases pass with native boot/activity
under the same seed and the public chronological-delivery mode; 102 of 103 source-
native/network cases passed before a formatting-boundary manifest refusal; the
ULF case subsequently passed on frozen source. A later 80-case slow reconciliation
had 76 pass and exposed four remaining fixtures/owners described below.

The terminal readiness fix now declines any unavailable existing initial shell,
including a source-visible readiness floor later than the backdated request. It
never treats an unavailable initial shell as permission to launch another window.
The persistence resume regression passes; both terminal variants retain positive
reuse and backdated birth/execution/source-readiness no-mutation controls.

A real process-exposure defect left later Mac exposures unrealized: the old env
carriers invoked an unmodeled second program and had no admitted finite lifetime,
so the initial carrier occupied its foreground shell indefinitely. Shared cached
spawn-rule data now supplies assignment-only env invocations and nominal bounded
lifetimes. Secret and adversarial renderers share that pool and preserve the exact
encoded wire substring through canonical argv quoting, including spaces and
apostrophes. No extra child/exec or known terminal result is invented. All five
exposures and their individual process terminations now appear; the corrected
integration gate passes. All 293 secret/payload/terminal/platform unit checks pass,
including positive literal argv/wire preservation and a negative extra-program
lifetime control.

Other final fixtures keep strong positive controls: the helper checkpoint fixture
explicitly owns a browser and renderer through a paired ten-hour logout instead
of depending on incidental high-baseline selection. Its positive retained-helper,
exact resume and final close checks pass. The natural-descendant closure case uses
an explicitly bounded id query rather than assuming an invented helper is short;
all three starts and matching terminations remain required. A root id query proves
its pre-existing elevated /bin/sh parent, no root USER_SESSION and finite closure;
that gate passes. Denied/failed exec census asserts zero aggregate starts and
exactly one canonical fork/exec, with native completeness correctly absent because
that fixture selects no native source.

The SOF-ELK® iteration gate found a real parser defect: RFC3164's unpadded day was
compared textually with Snare's padded day. Native payload year now owns the
calendar comparison, including February 29 when the fallback year is non-leap;
contradictory seconds still fail. All 177 Snare tests pass, including security and
Sysmon padding/conflict/leap-year cases. A fresh 141,847-record SOF-ELK bundle that
previously rejected all 31,004 Windows rows now passes evaluation, with both
Parseability measures at 100. No generated bundle was edited to obtain that pass.
The test now prints the failed parseability diagnostic if the strict check fails.

Windows job 128509132898 exhausted its 45-minute limit (confirmed by GitHub check
annotation); cancellation is not a pass and no usable completed log was retained.
The expanded routine budgets are 90 minutes for Windows and release Linux coverage,
and 45 minutes for ordinary Linux; strict tests and 70% coverage stay unchanged.
Routine commands now retain the twenty slowest durations. The existing Linux
coverage job remains pending; final repaired-source CI must still complete.
Full Ruff, formatting (1,509 files), version sync, behavior declaration, eleven
temporal migration/guard tests and config validation (101 files, zero findings)
pass. Final behavior revision 487 digest is
`e2dcdc1e242e8f03610d5d9129f4d2ca481a57e7a6c887302312583c8a7bbed8`.

### Final fixed-workload resource measurement

All 767 runtime/config files on the reference host match the final local inventory
`engine-v487-files.json`. The same workload SHA, host, seed, sources, 26-hour window,
one-hour warm-up, cadence and owned-temp supervisor are retained. Final measurement
`measurement-v487/` passes stopped checkpoint verification and exact resume:

- generation/resume 68.111 seconds; stopped verification 6.205 seconds;
- peak process-tree RSS 333,660,160 bytes (318.2 MiB);
- sampled total working disk 75,227,136 bytes (71.7 MiB);
- hour-seven checkpoint workspace 24,446,830 logical / 26,279,936 allocated bytes;
- final output 16,963,178 logical bytes; retained owned temporary scratch 7,835,648 bytes.

All eighteen generated data-file hashes equal the preceding owned-temp run.
The metadata/config size changed with declared behavior. Final reports, generation
manifest and source checksums are retained at
`/private/tmp/eforge-alpha5-readiness/resource-v487-evidence.tar.gz`.
The forecast calibration and 7.5 MiB scratch-retirement P2 items remain explicit.
This completes the bounded resource measurement, not general scalability or Studio
interactive acceptance. No tag, publication or dev integration PR is authorized.


Final repaired-source validation snapshot is
`63df4751c2b35b946e6713b1ce212338b51631e7` on
`codex/alpha5-final-validation-20261107`:
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42412964229 .
It includes the repaired runtime, evaluator, current fixtures, Windows POSIX-API
mock seams and revised CI budgets. All three preview builds and every release
CI/slow gate are requested on that exact commit. A full final local macOS routine
pass runs separately with normal native process inspection and loopback access.
No tag/publication/main/dev/PR change is part of this validation snapshot.


### Root cause of routine gate timeouts

The finalized Linux coverage log shows two rejection cases expanded 1 MiB/600 KiB
string payloads into node IDs (1,048,732- and 2,457,756-character status lines). Each
status transition stalled about 1,012 seconds; together they consumed roughly 34
minutes. The native binding module's full 39 cases pass in 1.36 seconds locally
with short explicit IDs. Inputs and assertions are unchanged. An AST audit found
three more unlabeled 64 KiB argument/environment pools; all four pools now use
semantic case names. Their full 94 cases pass. This addresses the logging root
cause rather than relying only on increased budgets.

The older Linux coverage job reached 44% with no failures before its 60-minute
limit; it is not a coverage pass. The initial final Mac routine worker was
interrupted deliberately before those large-ID cases and is restarted with the
bounded names. The runtime/measurement source is unchanged from 63df4751.
The superseded 0902 validation run was explicitly force-cancelled to release the
reusable CI concurrency slot; cancelled results are never treated as passes.


The current validation snapshot is
`49444e10e5f937f7a9e4f2137cd1866d9f348dc2`:
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42413530433 .
Only the four bounded test-name pools and worklog differ from 63df4751; the entire
product runtime, Studio and reference-measured engine are byte-identical. The
63df4751 run was deliberately superseded to remove the logging stall. The current
full Mac routine log is
`/private/tmp/eforge-alpha5-readiness/routine-macos-bounded-ids.txt`.
The three native state-recovery gates, lint, Python portability and Windows
durability pass. The Apple Silicon preview also passes isolated packaged runtime,
resources, checkpoint generation, native Mac generation/evaluation and DMG
integrity verification. Its downloaded checksum passes locally. Retained preview:
`/private/tmp/eforge-alpha5-readiness/installers/macos/preview-installer-macos-aarch64/`.

The local routine run found one documentation-policy failure: this worklog's
first external-parser product reference lacked its registered-trademark symbol.
That notice is corrected; both documentation checks pass. Snapshot 49444 still
contains the original notice, so its corresponding routine failure must not be
reported as a pass. Collect the rest of the full run before creating a corrected
snapshot. No product-runtime or measured-workload bytes changed for this repair.

### Remaining routine-gate findings

The complete Mac routine run on revision 487 finishes with 19,889 passed,
50 skipped and eight failed in 1,982.85 seconds. Besides the documentation notice,
five SSH retention cases expose missing collection-omission support in exact Linux
SSH publication; two compatibility timing cases expose exact admission of a
non-concrete dispatcher. Revision 488 admits only the concrete dispatcher and
permits authenticated in-window Linux SSH members to omit endpoint targets only
when eCAR is unselected. Present targets still require positive exact rows, and
the existing mixed warm-up rejection is preserved. Exact checkpoint capture now
authenticates the retained source identity against StateManager. Legacy and exact
retention/PID-reuse/lost-authority tests, network-only and no-source positive
closure, and the existing publication/rollback/loopback matrix pass (429 checks);
the timing/retention pair passes 29 checks after the dispatcher admission repair.

All three native Studio and state-recovery jobs and all three preview installers
pass on 49444. Slow shard three passes 514 cases. Other slow shards and coverage
are still running. The Windows routine job reaches 50% and then aborts inside
pytest reporting because a Path.stat test double leaks beyond its intended call.
Scope that double to the owned-image query. The retained log lists earlier
Windows portability failures but has no final tracebacks due to that abort.
A read-only Windows-only diagnostic dispatch on the isolated validation branch
will collect those failures before another complete gate run. It retains JUnit
results and changes no production release workflow or publication permissions.

The Windows-only diagnostic on b30333b2 (run 42416440454) completes in 66.7 seconds
and retains JUnit output. It identifies 109 UTF-8 fixture-read failures, principally
the shared Finder/catalog fixture, plus POSIX collector-operation tests (permissions,
UID ownership, no-follow opens, FIFO/select, native paths and poll.h C harnesses).
The catalog/Finder reads and non-ASCII history input now declare UTF-8 explicitly.
Only the specific native reference-operation test functions receive an explicit
POSIX requirement; portable simulation, model and codec tests remain eligible on
Windows. These are private Mac collector operating-system contracts, not a claim
that the collector can run on Windows. All existing assertions remain intact and
these operational cases remain required on Linux/macOS. A scoped Path.stat mock
also prevents a failed native-image query from corrupting pytest's own reporting.
The final local focused SSH/reference/history/docs group passes all 563 cases.

### Final revision-488 resource evidence

The final runtime's 767 files match inventory `engine-v488-files.json`; behavior
digest is `01b26ecea23f6edd0d1b9016f62a07e756c0eca918fc4caf88cbbe4c686a89f0`.
The same reference host/input/seed/cadence/owned-temp supervisor completes under
`measurement-v488/`, with exact stopped checkpoint verification and resume:

- generation/resume 68.150 seconds; checkpoint verification 5.884 seconds;
- peak process-tree RSS 336,822,272 bytes (321.2 MiB);
- sampled peak working disk 76,034,048 bytes (72.5 MiB);
- hour-seven checkpoint 24,446,830 logical / 26,279,936 allocated bytes;
- final output 16,963,178 logical bytes; retained temporary scratch 7,835,648 bytes.

All eighteen generated data hashes match revision 487. The final evidence archive
is `/private/tmp/eforge-alpha5-readiness/resource-v488-evidence.tar.gz`.
The same forecast-calibration and scratch-retirement P2 limits apply. No further
measurement is needed for test/documentation-only changes.

On 49444, slow shards one, three and four pass 571/514/590 tests respectively,
with four skips in those shards. Shard two and Linux coverage remain pending.
The corrected full Mac routine worker is running from the frozen revision-488
source at `/private/tmp/eforge-alpha5-readiness/routine-macos-r488.txt`.
Windows diagnostic two is run 42416861509 on test-only snapshot ac570be2.

The second Windows diagnostic passes: 914 passed, 279 explicit platform skips,
zero failures/errors in 519.1 seconds. JUnit is retained under
`/private/tmp/eforge-alpha5-readiness/windows-diagnostic-ac570/`.
The final slow shard on 49444 finishes with 522 passed, one skipped and one
filtered-SSH failure; all four shards total 2,197 passed, five skipped, one failed.
That last sudo/SSH lifecycle case passes on revision 488 in 1.87 seconds, including
TTY owner/route retirement and canonical session closure. No further source fix
was needed. Coverage on 49444 remains active and must finish undisturbed.

Request the complete final matrix from a separate isolated validation branch to
preserve that earlier coverage result. The runtime remains the measured revision
488; only test portability and worklog updates follow b30333b2. The original
Mac implementation branch/worktree remains uncommitted and preserved; no dev/main
movement, release tag, publication or integration PR is authorized.

Final full matrix: `e663a30f` on `codex/alpha5-release-gates-20261107`, run
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42417719269 .
It retains the measured revision-488 runtime, all corrected tests and original
strict gates. Lint, portability, Windows durability and all three native state
gates pass; the final Mac DMG, x86_64 AppImage and Linux ARM64 Studio gate pass.
Downloaded final-runtime DMG/checksum (local checksum verified):
`/private/tmp/eforge-alpha5-readiness/installers-e663/macos/`.
The matching x86_64 AppImage/checksum is under `installers-e663/linux-x86_64/`.
The full local Mac routine log is beyond 90% with no failures at this checkpoint.

An additional diagnostic-only branch `codex/alpha5-windows-complete-20261107`,
commit `798d0669`, expands the Windows diagnostic to the remaining reference-kit
modules beyond the old abort point. It changes only the diagnostic test list:
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/42418430886 .
The active isolated worktree is on this diagnostic branch. No final full run was
cancelled to start it. Status files: `ci-release-gates-status.json` for e663,
`ci-bounded-status.json` for the earlier 49444 coverage run, and
`windows-diagnostic3-status.json` for the expanded diagnostic, all beneath
`/private/tmp/eforge-alpha5-readiness/`. Read-only watchers retain state transitions;
the final full Mac routine log remains `routine-macos-r488.txt` there.

The full corrected macOS routine suite passes 19,904 tests with 50 skips in
1,947.02 seconds. Native reference-operation requirements do not skip any of
these POSIX cases on Mac. The expanded Windows diagnostic first exposed 174
additional POSIX reference-kit failures/errors. Specific operation tests now have
the same explicit platform requirement; portable codec/model assertions remain.
The complete focused retry passes 1,149 tests with 457 platform skips, zero
failures/errors in 23.8 seconds (2b5e8076, run 42419591594). Its JUnit is retained
under `windows-diagnostic-2b5e/`. The 121 expensive simulation tests excluded from
this *diagnostic-only retry* previously passed in the 914-case Windows diagnostic
and remain selected in every full routine/release gate.

The release-only Linux coverage job has exceeded 75 minutes despite bounded node
IDs. Give final instrumented coverage a 120-minute job budget for measured runtime
headroom; normal Linux remains 45 minutes and Windows 90 minutes. The 70% coverage
threshold, selected tests and source/native gates are unchanged. The earlier
coverage run remains active to collect its actual result before another final
complete snapshot is requested. No runtime bytes changed after the measured
revision 488.

The earlier Linux coverage job reaches 58% before its 90-minute cancellation.
There is no long test stall: the largest observed status interval is 72.5 seconds,
and maximum status-line length is 5,163 characters. It records the corrected
worklog notice and nine Linux-only reference-fixture failures. A focused Linux
diagnostic confirms exactly those nine failures (1,596 passed, one skipped):
eight mocked cleanup cases assume `/private/tmp`, and one setup fixture changes
the global account UID to 501 while its real private files belong to the Linux
runner UID. The cleanup fixture now redirects only mocked compiler scratch to
owned test storage while asserting the original requested native directory. The
account fixture uses the actual private-file owner and restores the real strict
reader instead of bypassing ownership. All 93 affected cases pass on Mac.

Full remaining checks will use the exact normal Windows routine and Linux 70%
coverage commands, with JUnit/coverage reports retained. Product runtime and
Studio bytes are unchanged from e663 and the measured revision 488; retain its
successful native/installer/slow evidence rather than repeat unrelated checks
for POSIX test declarations. Official publication still runs the complete release
workflow on the eventual authorized release commit. The user Studio hold remains.

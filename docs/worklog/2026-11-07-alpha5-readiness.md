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

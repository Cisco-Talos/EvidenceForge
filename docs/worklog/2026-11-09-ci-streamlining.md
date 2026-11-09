# CI streamlining

## Approved implementation

The user authorized removing repeated executions and balancing the existing
suites, without consolidating or reducing tests. Runner-minute savings are not a
priority. The organization API reports the Enterprise plan; GitHub's documented
standard concurrency allowance is 500 jobs, including 50 macOS jobs. Other
organization work still shares that capacity, so actual queueing must be observed.

Implementation branch: `codex/ci-streamlining-implementation-20261109`, based on
the a5 source snapshot `4302afd5`. The changes are:

- Eight independent routine shards on each of Ubuntu and Windows, with the
  existing 120-minute limits. Keep four slow Linux shards, now allocated by
  measured case cost instead of a node-ID hash. No in-process parallelism.
- Seed `.github/ci/timings.json` with retained routine/slow duration reports.
  Keep nine modules with module/class fixtures together. These are sparse initial
  estimates; unknown cases use a deterministic fallback. Required fresh runs now
  retain every case's setup/call/teardown duration and JUnit output.
- Verify complete, disjoint inventories and successful outcomes before the
  aggregate gate passes. Combine all eight Linux coverage files before applying
  the unchanged 70% threshold. Slow/soak selection remains separate.
- Record immutable successful-job evidence, with links in consumer job summaries.
  Match all tracked paths/modes/Git blob IDs except `CHANGELOG.md`, `TODO.md`,
  `docs/releases.md`, and `docs/worklog/**`. All other docs, tests, fixtures,
  configuration, versions, lockfiles, scripts and workflows invalidate reuse.
- Bind evidence to the actual Python/uv/toolchain (including portability's 3.13
  interpreter), runner label/architecture/image,
  Linux installed-package inventory, coverage mode and execution policy. Verify
  artifact-uploader source metadata and original successful job/steps through
  GitHub's API; reject forks, altered archives, incompatible inputs and results
  older than seven days. Reuploads retain the original producer and age.
  Compare the execution environment before and after a check; drift cannot be
  recorded as a successful result under a different profile.
- For PRs, verify the tested merge's parent/head relationship and require both its
  inputs and the API-authenticated PR head inputs to match. GitHub can clear
  `pull_requests` after merge. A PR merge containing additional base changes is a
  conservative reuse miss. Unavailable or unusable evidence executes fresh.
- Serialize equivalent logical checks across workflows with `queue: max`; the
  first successful producer supplies the following consumers. This retains queued
  consumers instead of cancelling older pending release checks. A failed producer
  leaves no reusable evidence, so a later consumer executes its own check.
- Give native recovery one reusable workflow on macOS and both Linux native
  targets. Remove the 84 repeated unit cases from each Studio unit selection and
  replace installer source-recovery repetitions with this same required gate.
  Keep the global slow recovery cases: `ubuntu-latest` differs from Ubuntu 24.04.
- Overlap read-only release installer builds with test gates after version/source
  validation. Publication waits for every selected test/coverage/slow/native gate
  and the actual verified installers. Retain only the publisher's write permission.
- Preserve manual recovery of snapshots predating these helpers using the three
  CI/build workflows pinned at `4302afd5`, against the original validated source.
  This keeps a5 immutable and avoids overlaying new scripts onto an older tag.

`workflow_dispatch` on CI, Release Slow Tests and Installer Builds exposes
`force-tests` to bypass reuse. CI also exposes `release-coverage` for readiness
checks before tagging. A plain successful Linux run cannot satisfy coverage;
Windows and matching native results can still be reused. Missing slow/coverage
evidence runs when required. No full-suite reruns are needed just to collect timing
data, and packaging artifacts are still built/verified for the actual candidate.

Refresh a timing seed after a complete successful required run by downloading its
matching `ci-evidence-*` shard artifacts, then running, for example:

```sh
gh run download RUN_ID --pattern 'ci-evidence-routine-windows-latest-plain-*' --dir /tmp/eforge-windows-timings
uv run python -m scripts.ci_shards --profile routine-windows --reports /tmp/eforge-windows-timings/*/evidence.json
```

Use `routine-linux` for one complete Linux group (plain or coverage, never a mix),
or `slow-linux` for all four slow shards. The updater requires a complete successful
inventory and every selected case's duration; review/commit the resulting seed.
Sharding policy changes themselves invalidate earlier evidence.

Validation includes real pytest hook executions, cross-directory coverage
combination, successful/failed/incomplete inventories, source/provenance/freshness
rejection, credentials stripped on artifact redirects, multiple recovery callers,
and actual publication-gate shell commands for modern/legacy success and failure.
`actionlint` 1.7.12 predates GitHub's `queue` option: validate everything else with
only its exact `unexpected key "queue" for "concurrency" section` diagnostic
excluded. Workflow tests require `queue: max` and prohibit cancellation. GitHub's
actual parser and the first required run remain the integration checks.

Local verification: focused infrastructure/release contracts pass; full repository
Ruff checks/formatting and workflow validation pass (with only the documented
validator compatibility exclusion). Collection-only verification assigns all
core routine cases (over 19,000) and all 2,203 slow cases exactly once across their
respective shard groups. These are local collected counts before runtime skips,
not claims that the full suites have passed on the new infrastructure.

## Separate a5 release blocker

The unchanged a5 release run `42699295865` failed slow checks: eight variants of
`test_legacy_ssh_checkpoint_resume_is_byte_identical` and
`test_cli_only_publication_round_trip_generation_and_evaluation`. These assertions
remain intact and required. The CI infrastructure changes do not repair these
source failures, rerun the active release, or move tag `v2.2.0a5`. Diagnose those
failures separately before publication; any changed release source needs a new
immutable snapshot/version.

## Original investigation

## Scope and evidence

The user requested exploration of faster CI and avoiding repeated tests across
PRs, merges and releases. Keep the active a5 release run `42699295865` and its
immutable tag unchanged. The following findings motivated the approved changes above.

Inspected `ci.yml`, `release-slow.yml`, `installers.yml`, `release.yml`, the pytest
tier/shard implementation, release publisher and retained GitHub job/step logs.
Only test collection was run locally; no expensive tests were rerun for timings.

| Completed evidence | Observed job time |
| --- | --- |
| PR #467 Linux routine, run 42684703438 | 36.18 min (35.97 in pytest) |
| Same PR Windows routine | 69.70 min (69.25 in pytest) |
| Same PR Studio on three native targets | 17.87–25.13 min |
| Same PR native state recovery | 2.53–3.45 min per target |
| Preview installers, run 42675168961 | 13.47–18.57 min per target |
| Historical slow shards, run 42417719269 | 29.4, 29.6, 38.5, 47.0 min |

The slow data is from the earlier readiness snapshot, not an a5 forecast. One
checkpoint/resume test alone took 1,058.90 seconds (17.65 minutes) in shard 2.
Coverage and slow tests run concurrently with other release tests, but installers
currently wait for all test gates. Approximate release critical path is the longest
test gate, plus the longest installer build/verification, plus publication/queueing.
Do not sum parallel slow shards or assume the routine Windows time bounds release
latency. All timings are examples with runner variance, not guarantees.

PR #467's tested source and tag v2.2.0a5 differ only in CHANGELOG.md, TODO.md,
docs/releases.md and the readiness worklog. Source, tests, scripts, lockfiles,
Studio and workflow inputs are identical. Current dev CI run `42699247913` and
Release run `42699295865` both use commit `4302afd5`: overlapping plain Windows,
Studio and recovery jobs are genuine duplication. Release Linux coverage and slow
checks are additional requirements not satisfied by plain PR pytest.

## Priority 1: reuse verified job results across events

Keep lightweight orchestrators on PR, dev push, tag and manual entry points. Each
required logical check resolves to a verified matching result, a matching active
producer to await, or a new run for the missing check. Keep an explicit aggregate
gate so reused checks remain required and visible rather than silently skipped.

Start with exact-commit reuse, which already removes simultaneous dev/tag copies.
Next allow different commit SHAs when the complete tested Git tree is identical
(PR test merge commits and final merge commits can have different SHAs). Then add
a narrow explicit documentation-only equivalence policy for cases like a5.
Always rerun documentation, version, release-note, tag, ancestry and provenance
checks appropriate to the target snapshot. Unknown changed paths invalidate reuse.

For each job, store a versioned evidence record identifying the producer run,
attempt/job IDs, checked-out source tree, tested-input digest, test selection and
collection inventory, platform/architecture/runner image, actual toolchain versions,
lockfile digests, workflow/policy revision, command, coverage mode and result.
Bind tracked paths, file modes and contents; include fixtures/config/catalogs,
scripts, tests, plugins and execution configuration. The generation-behavior digest
alone is insufficient. Initially use conservative broad inputs; narrower per-job
path scopes need an explicit dependency audit. Product-version changes invalidate
results until proven otherwise; they affect packaged metadata and behavior checks.

Validate source ancestry/content and producer success using GitHub's API and a
known workflow/policy, rather than trusting a PR-uploaded JSON claim. Treat reports
as data, never executable input. Preserve read-only test jobs and a separate
privileged publisher. Accept only reviewed, eligible same-repository evidence;
untrusted fork artifacts must not authorize publication. Reuse successful jobs,
not failed, cancelled or incomplete ones. Bound freshness, artifact retention and
active-job waits; missing, incompatible or expired evidence reruns the check.

Coverage is a distinct mode: a successful plain pytest run cannot provide coverage
retroactively. A plain-PR-to-release transition can reuse Windows/native results,
but must still run missing Linux coverage, slow and portability checks. Optional
release-readiness execution can fill only those gaps before tagging, after which
the tag verifies the collected evidence instead of repeating it. Preserve the
current policy of uninstrumented routine tests; making coverage the normal Linux
PR run is a separate speed/compute tradeoff to decide after measuring shards.

## Priority 2: parallelize and balance expensive suites

- Add JUnit and a complete collection/timing inventory to ordinary required runs,
  retaining setup/call/teardown costs. Seed from retained logs; collect better data
  during the next normal gate, not by rerunning individual slow tests for profiling.
- Shard Windows routine and Linux routine/coverage into isolated runner jobs.
  The initial proposal was four; the approved implementation uses eight per OS.
  Respect shared fixtures and known resource constraints. Real jobs add setup,
  fixture duplication, imbalance and queueing; ideal division of the old whole-job
  duration is not a runtime promise.
- Replace hash-only slow allocation with a deterministic duration-aware schedule.
  Retain a fallback for new tests and keep expensive fixture families together
  where practical. The historical four shards total about 144.5 runner-minutes;
  their ideal four-way balance is about 36 minutes versus the observed 47-minute
  longest shard. The longest individual test and shared fixtures limit scaling.
- Verify shard disjointness and complete union against the expected collection.
  Missing shards, empty accidental selections, changed markers or unexpected skips
  must not produce a green gate. Preserve slow/soak separation and all native gates.
- Combine every Linux routine coverage shard before applying the same combined
  statement/branch 70% gate. Do not average shard percentages or apply the global
  threshold to each partial shard. Keep slow/soak runs without coverage.

Track wall time, total runner-minutes and queueing separately: sharding reduces
elapsed time but can increase total work through repeated fixtures and setup.
Avoid enabling unrestricted in-process test parallelism before auditing global
state, fixed resources, subprocess and native helper assumptions.

## Priority 3: give duplicated checks one owner

Collection on the current source finds 22,193 non-soak cases, including 2,203 slow
cases. Counts describe collection, before runtime skips; they are not pass counts.
There are 84 routine cases shared by the Studio unit and native recovery selections
on each platform. The Linux installer job repeats 229 source-level routine cases
already selected by native recovery. In addition, 145 slow crash/migration cases
are selected by both native recovery and the global Linux slow tier.
The latter use different runner environments and remain required in both.

Create a checked-in ownership map: retain each required platform variant, select
source recovery cases in their owning native jobs, and have other jobs consume
that evidence. Keep the distinct real packaged CLI/app, AppImage/GStreamer and
DMG/checksum verification. A source-runtime test is not a substitute for an
installed-artifact check. Frontend behavior/API checks may eventually run once
while native builds and permission/lifecycle tests retain their platform matrix;
audit platform dependence before changing this selection.

## Priority 4: overlap packaging and batch dependency work

Start read-only installer builds after version/provenance validation in parallel
with the longer test gates. Publication still waits for every required test and
verified installer. This can remove roughly one installer duration from the
critical path, at the cost of occasionally building a candidate whose tests fail.
Measure runner availability and queueing before promising the observed 13–19
minute preview saving for a release build.

Initially keep final installers built for the actual release candidate. Later,
promote an already verified release-format artifact only when exact build inputs,
toolchain, identity, hashes and provenance match. Never rename preview/test builds
to imply release verification. Current publisher intentionally downloads this
run's artifacts; cross-run installer adoption needs an explicit reviewed contract.

Group compatible Dependabot updates within each ecosystem to reduce independent
full PR runs. Keep a combined final-snapshot check: isolated dependency successes
do not prove the combined lockfile. Cache improvements are secondary for current
routine jobs, whose dependency setup is measured in seconds. Cache Rust/package
build inputs where useful, with architecture/toolchain/lock-aware keys; caches
never stand in for a test result.

## Proposed delivery and acceptance

1. Capture complete timings/inventories and define exclusive test ownership.
2. Add per-job result evidence and exact-input reuse for PR/dev/release consumers,
   including waiting for matching in-flight jobs and explicit reused-result links.
3. Pilot balanced routine/coverage/slow shards and installer/test overlap, measuring
   both latency and compute. Extend safe documentation equivalence after exact
   tree matching is proven.

Exercise identical PR/merge trees; a docs-only release commit; changed source,
tests, fixtures, lockfiles, workflows, Python/Rust versions or runner images;
absent coverage; partial/missing/failed/cancelled/expired evidence; untrusted
artifacts; simultaneous consumers; and final installer hash/provenance mismatch.
The expected outcome is reuse only when justified, otherwise run the missing
check. Never weaken the 70% threshold, test assertions or platform/packaged gates.

## Clarification: tradeoffs and routine versus slow coverage

The first optimization pass preserves intended test cases, assertions, native
platforms, the coverage threshold and real packaged-artifact checks. It does give
up incidental repeated executions that can expose intermittent faults, and adds
maintenance and correctness obligations in evidence matching and scheduling.
Runner/toolchain freshness must be part of reuse eligibility. Parallel shards can
increase fixture work and total runner-minutes and change ordering/isolation;
early packaging can waste builds when another gate fails. Explicit periodic fresh
validation is an option for repeatability/environment drift rather than relying
on accidental PR/dev/tag repetition. Selecting a cadence remains a policy choice.

Only Ubuntu collects release coverage; Windows runs the routine suite without
coverage instrumentation. Default pytest selection excludes slow and soak tests.
The Linux-only slow workflow explicitly selects slow tests without coverage.
Collection of the actual core routine selection contains 19,289 cases; the global
slow selection contains 2,203, with zero identical node IDs in both sets. These
are collected counts before runtime skips, not pass counts.

They do exercise overlapping engine behavior. For example, the checkpoint smoke
function has two routine parameter variants and seven distinct slow variants.
The slow CLI family also tests fresh-process interruption and byte-identical
resumption for the representative iteration workload. The medium-dataset family
checks a shared 25-user/28-system organization release and correlated evidence.
These add scenarios, lifecycle states and integration depth beyond a code-coverage
percentage; high line/branch coverage alone does not establish those contracts.

Semantic duplication may still exist within or across families. Audit expensive
test assertions, fault cases and workload purpose before removing tests or
reducing workloads. The previously measured 145 exact slow-test duplicates refer
to native recovery versus global slow, not core routine versus global slow.
Test reduction is a separate decision from reusing results or balancing shards.

## Primary references

- [GitHub workflow events and PR merge commits](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
- [GitHub secure workflow use](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub dependency cache scope](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching)
- [Coverage data combination](https://coverage.readthedocs.io/en/latest/commands/cmd_combine.html)
- [pytest JUnit duration reporting](https://docs.pytest.org/en/latest/reference/reference.html#confval-junit_duration_report)
- [GitHub concurrency and queue behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [GitHub runner concurrency limits](https://docs.github.com/en/actions/reference/limits)

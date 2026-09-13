# FOR668 installed/fixed build comparison

## Kerberos timing fix — final acceptance complete

Implemented the approved fix from `237b72c1dd80f5486e284e31ddc21fe35bf00f41` on
`codex/2.0.0-code-cleanup`. The containing commit delivers the fix, 45 regression cases,
`scripts/check_kdc_timing.py`, behavior revision 80, and this worklog. No merge, release,
package/dependency update, schema change, fingerprint algorithm change, or compatibility-policy
change is included. All original scenarios, comparison reports, outputs and checkpoints remain
preserved. Final report: `/Users/bianco/TEMP/FOR668-data/comparison-kdc-r80-final.md`, with
adjacent JSON and `comparison-kdc-r80-final-details/` containing commands, logs and hash reports.

### Timing contract and scope

`SourceTimingPlanner` now budgets responder TCP/UDP Kerberos packet admission and subsequent
KDC processing together, before publishing WFP evidence. Bounds come from the existing
`windows.kerberos_after_wfp` profile and use integer microseconds. The possible AS/TGS pair
requires room for two strictly ordered sampled delays, with two available integer outcomes
per processing step. An admissible candidate is preserved; a late candidate is resampled
through the existing scoped sampler. The committed transport is never extended or rewritten.
The existing session-dependent ordering owner also keeps an admitted ticket pair inside that
same transport. No persistent state, cache, RNG, public API or parallel timing authority is added.

This constraint requires the exact admitted responder transport; absent/dropped or mismatched
WFP permits retain their prior policy. Generic/outbound WFP, submillisecond DNS, process
visibility floors, endpoint clocks, transaction ownership and publication/recovery remain with
their existing owners. Comments link the timing budget to the bounded regression tests.

Revision **80**, `kerberos-packet-admission-processing-budget`, declares `impact: localized`.
Final source surface:
`701c1ef2bd7fbc5fd7ea357734b43102d6c43b6901bb67739db86c53a5174f9e`.
Final installed-build digest:
`3222051bfcab8bec817b291b495110ac558858a89d2e893312a8095676a41dfb`.
Final acceptance root: `/private/tmp/eforge-kdc-final`; archived starting source:
`/private/tmp/eforge-kdc-baseline-237b72c1`. All acceptance runs below use the final frozen source.

### Final correctness gates

| Gate | Result |
|---|---|
| Focused timing/preparation/network tests | 239 passed, 12 deselected; 3.29 s |
| Standard suite | 8,618 passed, 27 skipped, 2,011 deselected; 340.51 s |
| Full slow suite | 1,780 passed, 8,876 deselected; 1,272.10 s |
| Targeted timing/network recovery | 109 passed, 4 soak cases deselected; 9.87 s |
| Both Ruff checks and behavior validation against `237b72c1` | Passed |
| Preserved raw-byte corpus | 250 cases complete; 244 identical, 6 attributable DC Security changes |
| New Kerberos matrix | 48 strict candidate cases pass; 2,184 audits, 348 AS/TGS pairs |
| Serial/threaded equivalence | All 24 new paired comparisons raw-byte identical |
| FOR668 CLI attempts | All 17 expected outcomes; 11 complete published bundles |

The corpus and Kerberos controls cover seeds 42/137, all three targets, full/narrowed formats,
serial/threaded emission and mixed platforms. Every listed artifact hash is verified. Evidence
and ground-truth comparisons use raw bytes and complete file sets; parsing is used only to
attribute already-detected differences. No golden file is replaced and no normalization is
used to pass acceptance. Full soak remains excluded as requested.

The standard skips are 22 tests requiring absent gitignored sample data, three unavailable
SOF-ELK® container-harness tests, one Splunk license-opt-in test, and one existing baseline test
that requires a fuller engine fixture. Their names remain in `logs/standard.log`; they are not
reported as passing. The bounded absent/mismatched-permit policy also passes four tests against
the original source, establishing preservation independently of the new implementation.

### FOR668 scenarios and checkpoints

All new directories are directly under `/Users/bianco/TEMP/FOR668-data`, using
`<scenario>-2.0.0-kdc-r80-final-<case>` names. Original failed workspaces remain untouched.

- Unchanged `2_2`, authored formats/default target: seed 42 completed twice (2,842.50 and
  2,849.55 seconds), and seed 137 completed (2,752.37 seconds). Both seed-42 bundles are
  raw-byte identical except manifest creation time. Seed 137 has 45 verified manifest hashes.
- Four compatible resumes completed: two copies of each retained installed/revision-79
  checkpoint. Each repeated pair is raw-byte identical, and the two origins produce identical
  evidence/ground truth. Their truthful provenance differs. Exact policy rejected all four
  older-build copies with exit 1 before resume and left their full trees unchanged.
- A final-build checkpoint captured after the first warmup hour resumed under exact policy
  (3,206.74 seconds). Its full evidence and ground truth match uninterrupted seed 42 byte for
  byte. Only validated resume provenance, manifest creation time, and explicit-vs-checkpoint
  seed override provenance differ; the effective seed is 42 in both.
- `1_1`, `1_1_bonus` and `1_2` completed and match their preserved outputs byte for byte, with
  only manifest creation time differing. `1_3` retains exit 2 and exactly the same validation
  text; no scenario repair or format override is made.

Both older checkpoints independently verify integrity and hydration, with compatible/localized
classification and no runtime differences. All 90 files per original checkpoint and all five
authored inputs retain their frozen hashes. Provenance checks authenticate origin/current build
identities, behavior history, cursor, policy and migration counts. The final-build checkpoint
capture also remains unchanged. Six independent generator processes ran concurrently on the
16-core/64-GiB host; these elapsed times are operational observations, not performance comparisons.

The original failing exchange now succeeds with the same UDP tuple
`192.168.2.107:51837 → 192.168.1.10:88` and LSASS PID 5996. WFP is at
`2026-04-11T16:21:28.0493656Z`, and 4769 is at `.0597579Z`, before the unchanged close
`.065618`. The old permit at `.065616` left only two microseconds.

### Intentional evidence differences and historical limits

Fresh corrected `2_2` versus an older-checkpoint resume differs in one file:
`data/dc01.halcyontrust.org/windows_event_security.xml`. All 161,330 record payloads and counts
match. There are 29,522 modeled timestamp changes: 7,569 WFP, 13,206 TGT, 8,730 TGS, 9 preauth
failures, and four machine-logon/logoff pairs. Each of those four pairs moves with its matching
service ticket; ticket-to-logon delay and session duration are unchanged. All modeled timestamp
changes precede the retained checkpoint cursor. Subsequent corrected timing agrees.

There are 142 record-ID differences; 18 non-KDC neighboring rows change only record ID and/or
the final 100-nanosecond rendering digit. Replaying the unchanged record-ID sequence and timestamp
formatter reproduces all **322,660** records across the two compared files exactly. The smaller
corpus has the same kind of source-order effects; its 27,832-record rendering replay also passes.
The detailed reports distinguish modeled microseconds from the final display digit. No other
family, payload, file set or ground truth changes.

The old failed `2_2` output was not a complete golden bundle. Across both origins, all 606,208
pre-cursor historical Security rows retain their payload and modeled timestamp on resume.
Completion adds 108 already-pending process termination rows per origin at their modeled earlier
times, so failed staged XML is not a byte-prefix of finalized output. Repeated complete resumes
and final exact-resume/fresh equality are the byte gates. The retained hour-72 cursor represents
64 collection hours plus eight warmup hours and precedes the failing exchange. These tests prove
load/resume compatibility for those retained checkpoints and the final first-hour checkpoint;
they do not claim exhaustive coverage of arbitrary persisted states or rewrite historical rows.
Copied `GENERATION_FAILED.txt` files remain historical diagnostics; the new successful manifests
are authoritative.

### Isolated performance observations

Same Python 3.12.9 environment, dependencies, machine and frozen inputs; no other task generation
or tests ran during measurements. One warmup round was discarded, followed by three alternating
baseline/candidate rounds. The timing workload uses 1,000 ample-headroom exchanges, with 50
additional internal warmups. Generation measures the fixed seed-42/default/full-format system
control including invariant/hash verification. Peak RSS comes from `/usr/bin/time -l`.

| Median measurement | Starting build | Fixed build |
|---|---:|---:|
| Timing loop | 0.4825 s | 0.4883 s |
| Timing exchanges/second | 2,072 | 2,048 |
| Timing peak RSS | 135.13 MiB | 135.19 MiB |
| Logical samples per 1,000 exchanges | 27,000 | 27,000 |
| End-to-end control | 14.656 s | 14.818 s |
| End-to-end output throughput | 156.72 KiB/s | 155.01 KiB/s |
| End-to-end peak RSS | 187.58 MiB | 188.16 MiB |

Measured ranges overlap (generation: baseline 14.631–14.857 s, fixed 14.580–14.825 s).
The small median differences do not establish a substantial runtime change; the fixed path adds
profile-bound and transport-budget checks while retaining existing state and sample owners.
No slowdown threshold was applied. Peak RSS and logical samples are observations, not exact
allocation counts or a proof for unbounded workloads; cancellation/commit census tests and
recovery coverage pass. All eight generation benchmark captures have zero timing violations.

### Retained failed attempts and final review

The initial candidate also constrained paired tickets without an exact observed WFP permit.
Four added regressions failed against it and passed against the original source. The final
exact-permit guard corrects that expansion. The initial source, reports, two completed resumes,
three interrupted unfinished runs and their checkpoints remain preserved separately; none is
counted as final acceptance. All candidate gates were repeated against the final frozen source.

Historical controls retain 24 expected forced-late failures and 12 natural baseline TGS-after-close
violations. Separate explicitly labeled historical captures support attribution without accepting
those violations. Candidate controls use strict assertions throughout. Initial raw-prefix and
narrow event-ID-only attribution assumptions failed: finalized rows include pending terminations,
and neighboring IDs plus four causally dependent session pairs also change. Full attribution
above resolves those differences without modifying evidence or broadening the approved exception.

The first benchmark workload succeeded but its wrapper exited 1 when the sandbox denied
`kern.clockrate`; the failed measurement is preserved and excluded. All 16 retried commands
succeeded with read-only resource queries enabled. An analysis assertion initially assumed this
seed's old benchmark would exhibit the other seed's historical violation; inspection showed all
captures are valid, and the report now checks that actual result. No production regression was
waived. Final report inventories preserve hashes, commands, test logs, failures and limitations.

## Superseded initial Kerberos candidate — retained test history

The subsequent approved fix starts at `237b72c1`. Original comparisons below remain historical
results; source, input and checkpoint references are preserved. The archived starting tree is
`/private/tmp/eforge-kdc-baseline-237b72c1`, and new controls/logs live in
`/private/tmp/eforge-kdc-fix`. All 250 preserved resolver-corrected byte controls were rehashed,
and both original FOR668 checkpoint trees have complete frozen file-hash inventories.

The exact `dc01` 2-microsecond-window failure was reproduced before edits: eight new cases fail
and the valid-candidate control passes. The source-only change reserves processing space before
responder WFP admission, using the existing Kerberos profile and integer timing bounds. It retains
the original generic WFP bounds and every existing state/clock/transaction owner.

Paired-ticket coverage exposed an additional interaction in the same timing path: generic
dependent ordering could move the second ticket outside the transport after its KDC timing check.
The joint budget now accommodates the possible AS/TGS pair, leaves successor space before TGT
publication, and resamples an otherwise escaping sibling-order delay inside the remaining window.
No committed evidence or network interval is rewritten. Candidate timestamps that remain
admissible are retained; no fixed timestamp clamp, new cache or RNG was introduced.

Revision 80 is `kerberos-packet-admission-processing-budget`, `impact: localized`.
Initial source surface: `c598d1977aafde0137174502d6a077252c902e56e861448bc7481188e083c50c`.
Initial installed-build digest: `3bb3d41ce547f842127bfc258906808fb835b5dd92d0ab4081ef09e49650ef4c`.
Focused source timing, preparation, baseline Kerberos and network publication coverage passes
235 tests, with 12 slow tests deselected. Earlier test-construction failure for a missing close
was corrected to omit duration too, satisfying the existing immutable transport constructor.

Fresh 2_2 runs, copied-checkpoint compatible/exact checks, unaffected FOR668 scenarios, the full
standard suite and the preserved byte corpus are running. Acceptance is not yet complete. New
FOR668 destinations use `-2.0.0-kdc-r80-<case>` under the original user-requested folder. No
original scenario, output or checkpoint is changed; no full-soak run, merge or release is planned.

### Completed bounded gates

- Standard suite: **8,614 passed, 27 skipped, 2,011 deselected**, 315.58 seconds. Existing
  skips remain unchanged. Focused source/Kerberos/network checks: **235 passed**, 12 deselected.
  Targeted timing preparation and network recovery, including slow cases: **109 passed**,
  4 soak cases deselected, 8.46 seconds.
- Preserved corpus: **250 completed; 244 raw-byte identical**. The two full-coverage cases and
  four default/Splunk system-family cases change only the DC Windows Security XML. Every
  manifest-listed artifact hash passes. Event counts and payloads match in all six changed
  files. Changes concern WFP/KDC timing, with five downstream record-ID changes in the two
  full-coverage files. An initially over-narrow attribution assertion found two neighboring
  DNS permits: their microsecond timestamps are unchanged; changed record IDs also change
  the renderer's deterministic final 100ns digit. Replaying the unchanged record-ID and
  timestamp renderers reproduces all 27,832 original/candidate full-coverage records exactly.
- Expanded controls: **48 corrected-build cases pass**, covering two seeds, three targets,
  full/Windows-only formats, serial/threaded emission, and natural/forced-late permits.
  They check **2,184 KDC observations and 348 AS/TGS pairs**. All 24 threading comparisons
  are raw-byte identical. Changed natural and forced-control evidence is confined to DC
  Security logs; unchanged payloads and record-ID-only effects on neighboring events are
  verified separately from the raw comparison. No ground-truth or other-family differences.
- Historical controls: all 24 forced-late baseline runs reproduce timing exhaustion. Twelve
  natural baseline cases expose a pre-existing TGS-after-close violation and initially trip
  the new strict assertion. Those failed attempts are retained. Separate historical captures
  explicitly record each violation without treating it as a pass; all corresponding candidate
  runs remain strict. The original matrix wrapper therefore exits 1 for historical defects;
  `reports/kdc-control-acceptance.json` records the fully classified 96 attempts plus the
  twelve additional historical captures. No failed candidate gate is waived.
- Both Ruff checks passed for the initial production/test revision; the final whole-tree
  repeats remain pending. Behavior validation against `237b72c1` passes at revision 80 with
  the surface hash above. No production changes have occurred during the long runs.

### Checkpoint comparison details discovered during acceptance

The first compatible resume from revision 79 completed successfully in 969.76 seconds.
Its 45 manifest-listed files have valid hashes. Provenance records revision 80's localized
change, the exact originating/current build identities, and the preserved hour-72 cursor
(64 collected hours plus eight warmup hours). The original checkpoint tree remains unchanged.
The second revision-79 copy and the installed-build copies are still pending/running.

Exact rejection returns CLI exit **1**, with the complete-original-fingerprint diagnostic,
and leaves the copied tree unchanged. The initial orchestration metadata mistakenly expected
21 (the previous generation-failure code); its actual assertion required rejection and an
unchanged tree. The saved driver is corrected to expect 1; original run records are preserved.

A raw prefix comparison against failed staged XML is not a valid final-output gate: completion
adds previously pending Event 4689 termination rows at their modeled earlier times. Across all
19 revision-79 Security files, every previously rendered pre-cursor event retains its payload
and microsecond timestamp; no historical event is missing. Re-finalization necessarily assigns
record IDs around those added rows. The failed prefix assertion and detailed attribution are
retained in `reports/historical-security-prefix.json` and
`reports/historical-security-row-attribution.json`. Repeated complete resumes, and final-build
exact resume versus uninterrupted generation, remain the raw-byte acceptance gates.

The complete slow tier passes: **1,780 passed, 8,872 deselected**, 1,216.76 seconds.
Final whole-tree Ruff checks pass (857 files formatted). Remaining FOR668 generation/resume
runs, performance measurements and final report/commit are pending. This section does not
claim final acceptance.

## Historical installed/fixed comparison

User-requested tests only: generate each scenario under `/Users/bianco/TEMP/FOR668-data`,
excluding `scenario-3_1.yaml`, once with the installed 2.0.0 CLI and once with the fixed build.
Do not repair scenarios or production code. Status: completed, all ten generation attempts.

## Final behavioral comparison

No unexpected old/new behavioral divergence was found in the observed outputs and failure
outcomes. Complete-output equivalence is established for three successful pairs; it remains
unestablished for the two scenarios that failed identically on both builds.

| Scenario | Installed / fixed outcome | Comparison |
|---|---|---|
| 1_1 | Both exit 0 | All evidence, ground truth, resolved inputs and sidecars byte-identical |
| 1_1_bonus | Both exit 0 | All evidence, ground truth, resolved inputs and sidecars byte-identical |
| 1_2 | Both exit 0 | All evidence, ground truth, resolved inputs and sidecars byte-identical |
| 1_3 | Both exit 2 | Same validation rejection, no evidence bundle |
| 2_2 | Both exit 21 | Same runtime error; all 19 partial XML files byte-identical |

The successful pairs differ only in `GENERATION_MANIFEST.json:/created_at`. Every listed
artifact hash was verified against its actual file. No evidence was normalized, and no new
output exception was needed. The partial 2_2 XML files total 406,968,789 bytes per build.
Both 2_2 builds reported exactly the same KDC source-window failure on `dc01`, at anchor
`2026-04-11T16:21:28.065616+00:00` and close `2026-04-11T16:21:28.065618+00:00`.
Both retained the hour-72 collection checkpoint. Its manifest hash agrees with its CURRENT
pointer. Neither build published final ground truth or a complete bundle for 2_2; no resume
or checkpoint hydration was attempted.

All ten output/failure directories are under `/Users/bianco/TEMP/FOR668-data`. The final
report is `comparison-2.0.0-installed-vs-fixed-237b72c1.md` in that directory, with adjacent
JSON and a details directory containing frozen inputs, controls, logs and per-file hashes.
Failed workspaces are preserved intact; historical logs retain their original temporary paths.

Delivery verification recomputed hashes after placement: report copies, all recorded control
files, five original inputs, complete output file sets and all partial XML hashes pass.
Published Markdown SHA-256:
`9f9fffe3b632e1a54ced6ad02ad3b559a18a0a9bdc0dd2594ac4f626762953a7`.
Published JSON SHA-256:
`4ac43ea69a25724713fe91476c4a046254d6586bc29dbcbf0f2c621a224f5c83`.

Final build digests equal the starting values below, and original input hashes still match.
No production code, dependencies, configuration or scenario files were changed. No generation
was repeated or repaired. No source-test suite was run for this generation-only comparison.
The only repository addition is this worklog; no commit, merge or release was made.

Limits: one seed (42), authored formats and default target, one attempt per scenario/build.
None of the inputs requests syslog, so this run does not directly exercise the corrected
resolver text. Both Python versions match, but the installed environments have seven shared
dependency-version differences. Matching bytes are observed results, not proof of equivalence
for every untested input or recovery path. Shared warnings, quality checks and resource
forecasts below are supporting diagnostics, not new-regression findings.

## Frozen inputs and builds

Run root: `/private/tmp/eforge-for668-comparison-20260913`. `plan.json` records input SHA-256
hashes, commands and options; `inputs/` contains unchanged source copies. Both builds use the
same working directory, `/Users/bianco/projects/EvidenceForge`, with no project config overlay
or selected packs. Authored formats, seed 42, target `default`, and 24-hour checkpoint cadence
are retained. Explicit new output roots keep existing authored destinations untouched.

- Installed: `/Users/bianco/.local/bin/eforge`, 2.0.0, behavior revision 42,
  build `a3cde0d7fdd75a37f27c1389afa1413b53bd891bec73d7ddec281c53b7a9e311`.
- Fixed: `uv run --no-sync eforge`, clean commit
  `237b72c1dd80f5486e284e31ddc21fe35bf00f41`, 2.0.0, behavior revision 79,
  build `e22031a0df979c05e03ca713cf888c3fd508ef5d17497e318b15e28c59f2729c`.
- Both use Python 3.12.9. Seven shared dependency versions differ: Pygments,
  annotated-doc, annotated-types, cffi, markdown-it-py, typing-inspection and typing_extensions.
  `builds.json` records all versions. Neither environment is modified.
- Semantic changes in this range: revision 49's Linux foreground ownership and revision 79's
  per-host resolver selection. All other intervening revisions declare behavior preservation.

## Validation

Validation ran on both builds with JSON output and storage forecasts before generation. Issue
lists and errors match for all five inputs. Resource snapshots can differ with observation time.
The largest final-output forecast is scenario 2_2: approximately 616 MB, with about 1.36 GB
expected peak working disk per run. Roughly 108 GiB was available before generation.

| Scenario | Hosts | Collection + warmup | Formats | Validation |
|---|---:|---|---|---|
| 1_1 | 2 | 24h + 8h | web_access | 7 warnings |
| 1_1_bonus | 2 | 48h + 8h | web_access, zeek_conn, zeek_dns | 7 warnings |
| 1_2 | 28 | 72h + 8h | proxy_access | 34 warnings |
| 1_3 | 27 | 48h + 8h | web_access, proxy_access | 1 error, 39 warnings |
| 2_2 | 19 | 72h + 8h | windows | 7 warnings, 2 informational issues |

Both builds reject 1_3 because configured persistent Windows SMB activity on `file02` has no
possible evidence projection in the requested proxy/web outputs. Generation is attempted once
per build to retain the actual CLI outcome; no scenario edits or format overrides are made.

Generation uses two concurrent processes, with each build/scenario assigned a fresh directory.
Elapsed times are operational observations, not isolated performance comparisons. Failures and
partial workspaces are retained. Evidence and ground truth will be compared as raw bytes and
file sets; provenance fields and runtime diagnostics will be assessed separately.

Operational notes: `eforge --version` is unsupported on both CLIs; version/build metadata was
read through each CLI's Python environment. The default uv cache is outside the sandbox, so the
fixed-build invocation uses `/private/tmp/eforge-for668-uv` with `--no-sync`.

## Execution notes (chronological)

The user requested all scenario/version directories directly under
`/Users/bianco/TEMP/FOR668-data` after the first generation pair had started. Completed bundles
are moved there only after their generation process exits, then evaluated at their final paths.
Names are `<scenario>-2.0.0-installed` and `<scenario>-2.0.0-fixed-237b72c1`. Active staging and
checkpoint workspaces remain at the original temporary root until completion. `placements.json`
records original and final paths; manifests/evidence are not rewritten during relocation.

Initial completed pair: scenario 1_1 succeeds on both builds, with identical raw evidence,
ground truth, resolved scenario and sidecars. Only `GENERATION_MANIFEST.json:/created_at` differs.
All manifest-listed file hashes were independently recomputed. Evaluation is being run once
per successful relocated bundle through the fixed evaluator for a common diagnostic comparison.

Completed through scenario 1_3: all three successful pairs (1_1, 1_1_bonus and 1_2) have
identical raw evidence/ground truth, with only manifest creation timestamps differing.
Both 1_3 CLI attempts exited 2 for the shared SMB visibility validation failure.
The fixed evaluator accepts the bonus outputs; 1_1 and 1_2 share unchanged hard-check failures
across builds. The final Windows pair, 2_2, remains running.

Shared resource-forecast limitation: at the scenario 1_2 72-hour checkpoint, `du -sk` measured
237,916 KiB installed and 238,192 KiB fixed (about 232 MiB each), versus the 24,431,635-byte
forecast upper working-disk bound. These are sampled lower bounds, not measured peak maxima.
`working-disk-observations.jsonl` preserves timestamped observations and checkpoint cursors.
Both runs completed with ample free disk. The forecast was not changed.

Scenario 2_2 checkpoint metadata confirms the live jobs use the expected distinct build hashes
and revisions (`checkpoint-build-verification.json`). Both reached the 48-hour checkpoint.
One-second read-only native CPU samples showed active computation/allocation, and are preserved
with the reports. A later live `ps` sample at about 24 minutes measured 1,312,832 KiB RSS installed
and 1,328,944 KiB RSS fixed, above the 886,672,483-byte memory forecast upper bound. These are
sampled lower bounds on peak usage; both processes remained active and 105 GiB disk was free.
The common forecast underestimation is recorded without changing code, configuration or limits.

User clarification: behavioral equivalence is the main acceptance question; shared generation
warnings, errors and quality scores are supporting information. No additional quality scoring
is scheduled for scenario 2_2. Its final file sets, raw hashes, manifest file hashes and
ground truth will receive the same full comparison as the preceding pairs.

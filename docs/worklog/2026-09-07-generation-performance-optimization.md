# Generation Performance Optimization Assessment

## Outcome

EvidenceForge now has permanent, opt-in generation profiling. The campaign met the overhead,
coverage, determinism, and stability gates, and produced the ranked top-ten target list below. No
hotspot was optimized and no implementation language was selected in this phase.

Working branch: `codex/generation-performance-optimization`

## Exact-first Python optimization campaign

The follow-on campaign is in progress. Every retained change starts with exact-output designs; no
alternate language or native dependency is in scope. The profiler foundation was committed as
`946a15698`, followed by checkpoint-inventory correction `bff4bf7cc` after the first real
checkpoint attempt found that the new process-local `profiler` field had not been classified as
deterministically rebuilt. The corrected foundation now suspends normally, and a resumed
invocation keeps only its own profiler.

### Dev integration epoch — 2026-09-09

Current `dev` at `f879c6a02` was merged after six generation, lifecycle, validation, and checkpoint
commits diverged from the optimization branch's base at `4587acfe7`. The merge preserves the
original optimization commits and their evidence. Two textual conflicts required manual
resolution:

- Generation behavior keeps the current `dev` history through revision 9, followed by the exact
  profiler, SMB, and timing entries at revisions 10 through 12. The provisional lifecycle entry
  was removed when its candidate failed the integrated correctness gate described below.
- Remaining red-herring work keeps its profiler span, while `dev`'s deferred storyline-process
  termination flush remains unconditional and receives its own named span.

The pre-integration measurements below remain valid historical evidence for their original code
epoch, but they are not acceptance evidence for the integrated runtime. Current `dev` intentionally
changes machine-auth transport allocation, collection-cutoff lifecycle settlement, authored
process retention, sensor identity, ancestry retention, reachability admission, and checkpoint
identity. A fresh post-integration baseline, exact-output comparison, checkpoint, profile, and
macro sequence are therefore required before reaffirming performance or retaining the lifecycle
candidate. Non-timing-sensitive merge and correctness validation may proceed while the machine is
busy; performance measurements remain deferred until a quiet-machine window.

Non-timing-sensitive integration validation completed on 2026-09-09:

- The focused profiler, CLI, engine, checkpoint, semantic-identity, reachability, SMB/state,
  timing, lifecycle, baseline, and deterministic integration selection passed with 1,016 tests and
  one skip.
- The first routine-suite run exposed three failure-neutrality regressions in the provisional lazy
  lifecycle snapshot cache. That candidate and its provisional behavior revision were fully
  reverted. The corrected routine suite then passed with 8,347 tests, five skips, and 2,008
  slow/soak tests deselected.
- The all-source workload was rebuilt from the tracked fixture and validated successfully against
  the merged compiler and current project overlay. It retained all 25 concrete formats and emitted
  only the four expected informational pivot-continuity hints.
- Ruff lint, Ruff formatting, generation-behavior revision 12 and digest validation, conflict-marker
  checks, and whitespace checks passed.
- No generation, profiler, benchmark, or elapsed-time acceptance run was performed during this
  busy-machine phase. Those measurements, the real checkpoint/output comparison, and the extended
  resource-intensive slow/soak gates remain deferred to a quiet-machine window.

Post-ASA cumulative correctness validation later completed with 8,350 routine tests passing, five
skipped, and 2,008 slow/soak tests deselected. The complete slow tier passed 1,777 tests and exposed
two instances of one profiler robustness defect in a partially constructed RDP failure harness;
commit `5a2a55ef7` made optional profiler access safe, and both affected slow cases plus all 11
profiling tests then passed. The other 1,777 slow cases require no rerun because they completed
successfully against the same cumulative candidate. Non-timing-sensitive soak gates passed for
31-day mixed Windows/Samba retention, 45-day connection state, and all three ordinary/HTTP/proxy
one-thousand-handoff capacity variants.
The 31-day external-sort bound and million-entry index compaction soak gates also passed once
machine contention subsided. The representative medium-generation gate passed in the slow tier.

### Target 1: SMB connection state validation and encoding — retained, exact

Three exact designs were evaluated together after isolated measurements:

1. Collapse duplicate full canonical validation inside one locked transition, while preserving a
   final public-plan validation before materialization leaves the lock.
2. Use exact-type, callback-safe validate-only text and integer paths for hostile map/index keys,
   avoiding temporary encoded-byte allocations. The ASCII path validates character and UTF-8 byte
   bounds without encoding, while non-ASCII and invalid-surrogate behavior remains exact.
3. Reuse the already-validated active authority record supplied by the commit claim after an exact
   identity/type check, rather than resolving and validating it again during the same transition.

The first duplicate-validation design improved the small lifecycle microbenchmark by 12.4%, below
the 15% focused gate. The combined candidate improved the representative large-index SMB auth path
from 233.76 to 297.97 operations/second (**21.55%**) and reduced full canonical validation calls per
materialization from seven to four (**42.9%**).

The interleaved `A-B-B-A-A-B` all-source macro runs completed in this order:

| Build | A1 | B1 | B2 | A2 | A3 | B3 | Median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Foundation A | 959.63 | — | — | 919.24 | 922.78 | — | 922.78 s |
| SMB candidate B | — | 878.38 | 858.28 | — | — | 870.77 | 870.77 s |

The candidate improved representative whole-run median wall time by **5.64%**. The equivalent
historical-fixture sequence produced medians of 230.51 seconds for A and 226.79 seconds for B, a
1.61% improvement rather than a regression. A residual all-source profile completed in 874.74
profiled seconds with 1,464,909,824 bytes peak RSS, a 0.36% increase from the 1,459,585,024-byte
foundation profile. Residual SMB-exclusive cost was approximately 10.2%, down about 36% from the
15.95% foundation share.

All six macro bundles had the same 278-file data inventory digest,
`9490a9fc69ff65f05043cc4727516ae538b98b9055efcbb75eeacaf7e3fbb2e1`. Direct output-equivalence
comparison found byte-identical `data/**` and deterministic sidecars. The candidate also resumed a
checkpoint created by the corrected pre-SMB foundation at simulated hour one, completed the two
collection hours, passed verification for all 287 manifest entries, and was byte-identical to an
uninterrupted candidate bundle. The CLI conservatively classified the changed-build resume as
compatible with output equivalence not guaranteed; empirical comparison established exact output
for this transition.

Decision: **retain as exact**. Generation behavior revision 5 records `impact: none`, domain
`smb-connection-lifecycle`, and no affected formats. All 25 concrete log formats remain
byte-identical. No semantic fallback was evaluated or justified.

### Target 2: timing distributions and RNG setup — retained, exact

A temporary bounded diagnostic around the historical workload observed 807,771 numeric timing
requests: 463,033 microsecond requests and 344,738 continuous-value requests. Clock-wander knots
accounted for 283,688 calls but only 3,170 unique immutable requests, or 280,518 exact repeats.
Route and close delay relationships contributed another 23,110 repeats. The diagnostic wrapper and
its generated bundle were temporary and are not part of the retained implementation.

Three exact designs were evaluated:

1. Reuse one standard-library `JSONEncoder` with the existing options, hash the same seed byte
   sequence incrementally, and extract the digest's low four bytes instead of converting the full
   hexadecimal digest and applying modulo `2**32`. The RNG stream is covered against the legacy
   algorithm for default and non-default seeds plus non-ASCII semantic keys. This alone improved
   isolated RNG construction by about 8%, below the focused gate.
2. Retain up to 16,384 pure deterministic source-clock wander knots in an explicit process-local
   cache shared by canonical and prepared timing paths. Hits still record every logical timing
   sample; misses recompute from the unchanged namespace, generation seed, clock key, wander spec,
   and ordinal. The cache is absent from checkpoint state, and eviction or a cold cache can only
   cause exact recomputation. Repeated clock projection improved from about 52,953 to 314,549
   operations/second (**83.2%**).
3. A generic `functools.lru_cache` implementation was rejected before generation by the trusted
   derived-cache security guard and replaced with the explicit bounded store. A subsequent
   two-lookup cache API intended to avoid a closure allocation reduced the focused rate to about
   267,779 operations/second, so that refinement was reverted.

The all-source `A-B-B-A-A-B` sequence compared accepted SMB commit `e0c74465a` with the timing
candidate:

| Build | A1 | B1 | B2 | A2 | A3 | B3 | Median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Accepted SMB A | 902.83 | — | — | 901.94 | 887.26 | — | 901.94 s |
| Timing candidate B | — | 841.89 | 860.70 | — | — | 837.85 | 841.89 s |

The candidate improved representative whole-run median wall time by **6.66%**. The historical
fixture sequence produced A times of 225.00, 227.69, and 224.88 seconds and B times of 222.74,
224.10, and 223.86 seconds. Its median improved from 225.00 to 223.86 seconds (**0.51%**) rather
than regressing.

The residual all-source profile improved from 874.74 to 858.52 profiled seconds. Peak RSS fell from
1,464,909,824 to 1,444,397,056 bytes (**1.40%**). Timing RNG inclusive share fell from 5.19% to
0.99%, clock projection inclusive share from 6.55% to 3.05%, and JSON encoder leaf share from
3.16% to 0.33%. The latter is timing-seed serialization removed here and is credited only to this
target.

All six all-source bundles had the same 278-file data inventory digest,
`6f3894f085b7148cc3a763f825dc3bcfefb6c195810c292dd7540ae8eedb259f`; each candidate also matched
the accepted build's deterministic sidecars. All six historical bundles were byte-identical by the
same output-equivalence comparison. A candidate invocation resumed an accepted-SMB checkpoint from
the warm-up boundary with an empty knot cache, completed safely, verified all 287 manifest entries,
and was byte-identical to an uninterrupted candidate run.

Decision: **retain as exact**. Generation behavior revision 6 records `impact: none`, domain
`canonical-timing`, and no affected formats. All 25 concrete log formats remain byte-identical. No
semantic fallback was needed, so no timestamps, generated identifiers, ordering, schemas, field
meanings, or resume policy changed. The cumulative accepted-stage median improvement from the
pre-optimization 922.78-second SMB macro baseline to 841.89 seconds is **8.77%**.

### Target 3: lifecycle authority and registry maintenance — exact designs rejected

Three exact designs have been investigated. No lifecycle optimization has been retained or
committed, and no semantic fallback has been attempted.

1. Disarming the weak-reference collection callback after a receipt was acknowledged eliminated
   the `lifecycle_authority.remove_collected` profile leaf (2.40% to zero), but aggregate focused
   acknowledgement throughput was neutral. Its all-source profile improved from 858.52 to 814.55
   seconds, while the complete macro median improved only 0.36% (803.31 to 800.41 seconds) and peak
   RSS rose 4.47%. The historical fixture was mathematically unable to finish within its 1%
   regression gate after two candidate runs; its best possible candidate median was 225.16 seconds
   against 222.11 seconds (1.37% slower). The design was rejected and fully reverted.
2. Eagerly publishing a bounded immutable terminal transport-ID snapshot at every closed physical
   transport improved repeated focused lookup from approximately 102,578 to 647,244 operations per
   second (**84.2%**). It reduced the residual profile from 858.52 to 829.63 seconds and peak RSS by
   5.77%, but the all-source macro median regressed 1.31% (802.33 to 812.83 seconds). The eager
   insertion cost applies to transports that never need this lookup, so this design was rejected.
3. A lazy variant retained the same bounded exact snapshot but created it after the first terminal
   transport-ID lookup. The focused repeated-lookup improvement remained about 84%. Its residual
   profile completed in 856.19 seconds (0.27% faster than the accepted timing build) with peak RSS
   of 1,323,548,672 bytes (8.37% lower). In that profile,
   `events/lifecycle.py:__post_init__` inclusive share fell to 0.72% and transport-row decoding to
   1.48%. After integrating current `dev`, the routine suite proved that the lookup mutated retained
   cache state before a later application-child fingerprint rejection. Three exact tamper cases
   therefore violated the required failure-neutral registry census. The candidate was rejected and
   fully reverted; the tests were not weakened.

The lazy candidate's all-source macro comparison was explicitly paused after the current B1 run:

| Build | A1 | B1 | B2 | A2 | A3 | B3 | Median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Accepted timing A (`ffc034d25`) | 896.69 | — | — | — | — | — | incomplete |
| Lazy lifecycle candidate B | — | 870.14 | — | — | — | — | incomplete |

B1 was 2.96% faster than the adjacent A1 run. Peak RSS was 1,469,890,560 bytes for A1 and
1,432,109,056 bytes for B1 (2.57% lower). This single adjacent pair is not sufficient evidence for
retention. Both bundles verified successfully, and direct comparison found all 278 `data/**` files
byte-identical.

Decision after `dev` integration (2026-09-09): **retain no lifecycle change**. All three exact
designs failed an acceptance gate, and no semantic fallback was justified. The incomplete A1/B1
pair remains historical diagnostic evidence only; do not resume that sequence. Re-profile the
post-integration accepted runtime before deciding whether another materially different exact
lifecycle design is warranted. No lifecycle changelog entry or affected format exists. Revision
13 records the separately approved localized ASA checkpoint-order repair, revision 14 records the
profiler-free recovery fix, and Target 5 uses exact revision 15.

### Target 4: JSON serialization — subsumed by exact timing work

The accepted timing profile reduced standard-library JSON encoder work from a ranked family to 375
exclusive samples out of 76,950 (**0.49%**). Encoder `iterencode` itself was 0.33% exclusive. The
remaining sampled callers were primarily exact Windows/Sysmon spool records, with a smaller amount
of timing-seed encoding and scattered source/checkpoint serialization. This is below the threshold
that justifies forcing a JSON representation change or a broad encoder refactor.

The first fresh post-`dev` accepted-build profile confirmed that JSON encoding and decoding remain
below 1% exclusive CPU in aggregate (790 of 87,336 samples, **0.90%**). No Target 4 code change is
justified. Close this target as subsumed by the exact timing work; no representation changed, no
format is affected, and no semantic JSON fallback is authorized by the evidence.

### Target 5: generic indexes and mappings — exact candidate 1 rejected

The accepted pre-integration timing profile identified two concrete avoidable costs in
`CompactIndexedStore`: generic `collections.abc` `get` dispatch consumed 591 exclusive samples and
1,175 inclusive samples (**1.53% inclusive**), while runtime-only `typing.cast` calls across index
paths consumed another 264 exclusive samples (**0.34%**). The dominant generic `get` caller was the
process lifecycle index; exact active/retired-map lookup and packed digest routes accounted for the
remaining index work.

The first exact candidate attempted:

- Add direct `get` and membership paths that resolve active and incrementally retired primary maps
  without generic ABC dispatch or exception-driven misses.
- Use the same direct resolution for `__getitem__` and `handle_for`, preserving active-map
  precedence and exact `KeyError` behavior.
- Remove runtime-only casts from live compact-slot reads; no container layout, lookup result,
  iteration order, compaction behavior, or checkpoint payload changes.

Focused rotation, active/retired lookup, deletion, missing-default, handle-reuse, collision,
lifecycle, application-channel, process-cache, state, and checkpoint coverage passed: 697 tests
with 14 slow/soak cases deselected. The complete routine suite passed with 8,348 tests, five skips,
and 2,008 slow/soak tests deselected. Provisional generation-behavior revision 13 allowed checkpoint
tests to exercise the candidate and was removed when the candidate failed its performance gate.

Those timing steps were deliberately not started on 2026-09-09 because unrelated Logitech helper,
browser, window-server, and security processes were consuming substantial CPU. Results collected
under that contention would not be comparable to the campaign baseline.

The first post-`dev` accepted-build profile and isolated-candidate screening profile completed on
2026-09-09:

| Run | Wall | Process CPU | Peak RSS | Samples |
|---|---:|---:|---:|---:|
| accepted profile A1 | 942.781 s | 937.602 s | 1,319,436,288 B | 87,336 |
| index candidate profile B1 | 862.266 s | 856.963 s | 1,318,780,928 B | 79,051 |
| accepted profile A2 | 837.254 s | 832.923 s | 1,346,191,360 B | 75,883 |

Both bundles verify with 287 manifest-tracked files. Their `data/**`, `artifacts/**`, and every
deterministic sidecar are byte-identical. Candidate peak RSS is 0.05% lower. Focused A-B-B-A-A-B
microbenchmarks over one million operations improved active-hit `get` by 22-26%, missing `get` by
79%, and membership by 22-25%, satisfying the focused-operation threshold.

The apparent A1-to-B1 process-CPU improvement was machine/run variance: the unchanged A2 accepted
build was another 2.9% faster than B1. Warm-up was effectively unchanged while collection hours
varied substantially. Runtime casts fell from 273 to 25 samples, but packed-map `_find_slot` rose
from 1,885 to 2,284 samples and generic-plus-direct mapping `get` samples did not fall. Compared with
A2, the targeted mapping/index sample total fell only about 1.5%, far short of the required 25%,
while macro process CPU regressed 2.9%. The candidate therefore failed the campaign gate and was
reverted in full. No production code, behavior revision, changelog entry, or format impact remains.

The integrated profile also exposed a separate residual Target 2 cost: generated dataclass hashing
is 5.20-5.27% exclusive and is dominated by nested source-clock and wander-cache keys. Those caches
are rebuilt rather than checkpointed, but any exact hash-key follow-up must be evaluated separately
from the Target 5 patch so performance attribution remains non-overlapping.

#### Exact candidate 2: singleton-first sparse temporal routes — rejected

The dominant packed-map samples came from `_SparseTemporalIndex.iter_after`: lifecycle identities
normally occur once, but each singleton query checked the empty promoted-history map before the
singleton map. Candidate 2 reverses those exact checks in add, predecessor, successor, and removal
paths. Promoted histories still resolve through the same segmented temporal index, and absent keys
still check both maps. It changes no retained layout, digest, collision check, iteration order, or
checkpoint representation.

A focused regression asserts that singleton predecessor/successor queries issue only one packed
route probe. The broader index, lifecycle, checkpoint, state-manager, application-channel,
process-cache, concurrency, and behavior suite passes with 792 tests and seven slow cases
deselected. Interleaved one-million-operation microbenchmarks improved singleton successor lookup
by 20-32% and predecessor lookup by 15-26%. Provisional behavior revision 13 declares `impact:
none` with no formats.

The first candidate profile completed with 943.303 s wall, 935.592 s process CPU, 1,230,700,544 B
peak RSS, 86,810 samples, and no degradation or dropped samples. Its two dominant singleton
`iter_after` probe stacks fell from 2,055 samples in accepted A2 to 1,072 (**47.8%**), while total
packed `_find_slot` samples fell from 2,504 to 1,810 (**27.7%**). The bundle verifies with 287
tracked files and is byte-identical to accepted A2 across `data/**`, `artifacts/**`, and every
deterministic sidecar. Whole-run timing remains inconclusive: candidate C1 clusters with slow
accepted A1 rather than fast accepted A2. Repeat the profile and complete interleaved unprofiled
macro runs before deciding whether the target-family reduction meets the macro-within-1% gate.

Candidate profile C2 completed with 890.782 s wall, 885.131 s process CPU, 1,312,129,024 B peak
RSS, 80,826 samples, and no degradation or dropped samples. It verifies and is byte-identical to
C1 across generated data and deterministic sidecars. Across the two accepted and two candidate
profiles, median singleton `iter_after` probe samples fell from 1,586.5 to 1,237 (**22.0%**) and
median total `_find_slot` samples fell from 2,194.5 to 1,944 (**11.4%**). Sampling variance is high:
accepted singleton stacks ranged from 1,109 to 2,064 despite byte-identical work. The profile pair
therefore does not independently clear the 25% target-exclusive gate. Candidate 2 advances only to
the alternative acceptance path: the unprofiled A-B-B-A-A-B sequence must demonstrate at least
1.5% median all-source wall improvement.

The unprofiled macro gate rejected candidate 2:

| Run | Build | Wall | User + system CPU |
|---|---|---:|---:|
| A1 | accepted | 799.05 s | 794.84 s |
| B1 | candidate | 885.52 s | 880.86 s |
| B2 | candidate | 849.47 s | 844.71 s |
| A2 | accepted | 904.16 s | 891.73 s |
| A3 | accepted | 833.90 s | 829.81 s |
| B3 | candidate | not run | not run |

The accepted wall median is 833.90 s. Even if B3 were arbitrarily fast, the candidate median could
not be lower than B2's 849.47 s, while the 1.5% acceptance threshold required 821.39 s or less.
Likewise, its best possible CPU median was already a 1.8% regression. B3 was started, then stopped
after 38.98 s at the user's direction because it could no longer influence the decision; it is not
part of the measurement table. Candidate 2 was reverted in full. No production code, behavior
revision, test, changelog entry, or format impact remains.

#### Exact candidate 3: specialized packed-digest reads — retained, exact

The final materially different Target 5 design keeps the packed arrays and mutation paths intact,
but specializes the dominant read-only `PackedUniqueDigestMap.get_digest` loop. It performs the
same unsigned-64-bit validation and sentinel normalization inline, probes the same open-addressed
cluster, and returns the same locator/default without an extra classmethod call or temporary
`(position, found)` tuple. A focused boundary test covers sentinel aliasing, defaults, and invalid
digests. The same 792-test broad focused suite passes with seven slow cases deselected.

Interleaved five-million-lookup microbenchmarks improved packed hits by about 35% and misses by
about 39%. The first all-source profile completed with 745.049 s wall, 741.769 s process CPU,
1,364,312,064 B peak RSS, 66,301 samples, and no degradation or dropped samples. Combined
`get_digest` plus `_find_slot` exclusive samples fell from the two-profile accepted median of 2,388
to 437 (**81.7%**). Peak RSS is 1.3-3.4% above the two accepted profiles, within the 5% gate. The
bundle verifies with 287 tracked files and is byte-identical to accepted A2 across `data/**`,
`artifacts/**`, and every deterministic sidecar. Candidate 3 clears the focused-operation and
target-exclusive CPU gates; retain it only if unprofiled macro runtime remains within 1% of the
accepted build and the remaining correctness/scale gates pass.

The decision-sensitive unprofiled sequence used the immediately preceding accepted A3 as A1, then
ran B1-B2-A2-A3. B3 was skipped because it could no longer change either median decision:

| Run | Build | Wall | User + system CPU |
|---|---|---:|---:|
| A1 | accepted | 833.90 s | 829.81 s |
| B1 | candidate | 776.64 s | 773.53 s |
| B2 | candidate | 780.73 s | 776.51 s |
| A2 | accepted | 927.99 s | 921.52 s |
| A3 | accepted | 799.29 s | 795.68 s |
| B3 | candidate | not run | not run |

The accepted median is 833.90 s wall and 829.81 s CPU. Regardless of B3, the candidate median can
be no worse than 780.73 s wall and 776.51 s CPU: at least **6.38% faster by wall** and **6.42%
faster by CPU**. B3 cannot influence retention and was omitted under the user's stop-when-fixed
guidance. All five completed macro bundles verify with 286 tracked files, and candidate runs are
byte-identical to the accepted run across generated data, artifacts, and deterministic sidecars.
Candidate 3 passes its performance and memory gates and advanced provisionally to compatibility
testing.

The checkpoint gate exposed a pre-existing ASA exact-resume defect rather than a packed-map
regression:

- An accepted revision-12 run suspended normally after the one-hour warm-up. The revision-13
  candidate classified it as load-compatible with the expected localized behavior-history and
  build differences. Full isolated hydration passed for all 28 participants. On macOS the first
  verifier attempt used the `/var` alias and Snort rejected that symlinked ancestry; repeating with
  the real `TMPDIR=/private/tmp` scratch root passed and did not alter the checkpoint.
- The candidate resumed the accepted checkpoint and completed both collection hours. All generated
  files, artifacts, and deterministic sidecars matched the uninterrupted accepted bundle except
  `data/profile-firewall/cisco_asa.log`. It retained exactly 87,559 rows, but one equal-second pair
  changed order and therefore exchanged the appliance-local finalized connection IDs. The resumed
  ASA SHA-256 was `cea4d688cd3058dc15d00b5420917b6d49798f347203f24281e72229e8dece79`;
  the uninterrupted SHA-256 was
  `ed5adc5664aaa9666788252b00342664441861d462c6156bf32d475e0e1161ba`.
- A second checkpoint was created and resumed entirely under the unchanged accepted revision-12
  build. It produced the same resumed ASA hash as the candidate while every other generated file,
  artifact, and deterministic sidecar matched. This proves the packed-digest read path neither
  caused nor worsened the mismatch. ASA's timestamp-only external merge leaves equal-second row
  order dependent on run boundaries, and final connection-ID allocation makes that latent ordering
  difference visible.
- One first repair attempt used a full lexical line tie-break after lifecycle priority. It preserved
  the ASA semantic multiset and changed no other format, but final connection-ID rewriting could
  disturb that order. It was refined rather than retained.

The user authorized the exact-first campaign's localized semantic fallback for this pre-existing
defect. Commit `f16bfd50d` applies a source-native total order: RFC3164 second, ASA lifecycle
priority, stable rendered content with generated TCP/UDP connection-ID digits removed, and the
numeric connection ID only as a final disambiguator. Restored immutable runs are normalized
atomically before canonical connection IDs are rebuilt. Generation behavior revision 13 declares
`impact: localized`, domain `cisco-asa-publication-order`, and concrete format `cisco_asa`.

The definitive uninterrupted all-source bundle changed only
`data/profile-firewall/cisco_asa.log` relative to the pre-repair build. The other 24 concrete
formats were byte-identical. ASA retained 87,559 rows and 43,746 connection-build rows; after
normalizing generated connection IDs, the old and new files were identical multisets. Final build
IDs are contiguous from 1,371,431 through 1,415,176, and the output satisfies the new total order.
Its ASA SHA-256 is `6b729959d06e3b813872ef4a27e04d3421f012dfda3f6785be4cfa6848c7caa0`.

A same-build checkpoint from the pre-profiler-fix candidate epoch suspended after warm-up, hydrated
all 28 participants, resumed
under `--resume-policy exact`, and matched the uninterrupted bundle byte-for-byte across generated
data, artifacts, and deterministic sidecars. A historical revision-12 checkpoint also hydrated all
28 participants and completed under the required `--resume-policy attempt`; empirically it matched
the current uninterrupted bundle byte-for-byte, although compatibility remains conservatively
documented as historically unguaranteed. The full-volume ASA repair therefore establishes a
corrected baseline against which candidate 3 can be revalidated without waiving its exact-output
gate.

The corrected all-source bundle verified and the authorized large evaluation parsed 588,060
records from 23 non-empty source families. It scored 94.67 overall with 100% specification
conformance, format constraints, value plausibility, IDS integrity, causal ordering, event
presence, pivot/linkability, temporal, storyline, and intent-reconciliation scores; field agreement
was 99.27 and indicator accuracy 98.99. The remaining Windows 4779 unknown-field warning and
web/Zeek status/OCSP diagnostics predate this optimization and did not fail a hard gate.

Candidate 3 was reapplied unchanged on top of the committed ASA and profiler-recovery fixes as
behavior revision 15, `impact: none`, and compared with immediate predecessor `5a2a55ef7`. The
corrected-baseline all-source sequence was `A-B-B-A-A`; B3 was omitted because it could no longer
change either median decision:

| Run | Build | Wall | User + system CPU |
|---|---|---:|---:|
| A1 | accepted | 806.77 s | 803.54 s |
| B1 | candidate | 784.73 s | 781.69 s |
| B2 | candidate | 786.91 s | 784.27 s |
| A2 | accepted | 816.20 s | 813.02 s |
| A3 | accepted | 818.92 s | 816.60 s |
| B3 | candidate | not run | not run |

The accepted medians are 816.20 seconds wall and 813.02 seconds CPU. Regardless of B3, the
candidate median is bounded at 784.73-786.91 seconds wall and 781.69-784.27 seconds CPU. It is
therefore guaranteed to improve whole-run wall time by at least **3.59%** and process CPU by at
least **3.54%**; the two-run candidate centers improve them by **3.72%** and **3.69%**. All five
bundles verify with 286 tracked files and are byte-identical across `data/**`, `artifacts/**`, and
every deterministic sidecar. The corrected ASA SHA-256 remains
`6b729959d06e3b813872ef4a27e04d3421f012dfda3f6785be4cfa6848c7caa0`.

The historical Zeek-focused sequence also stopped after `A-B-B-A-A` once B3 became unable to
change the regression decision:

| Run | Build | Wall | User + system CPU |
|---|---|---:|---:|
| A1 | accepted | 209.19 s | 208.31 s |
| B1 | candidate | 211.32 s | 210.27 s |
| B2 | candidate | 210.05 s | 209.26 s |
| A2 | accepted | 211.18 s | 210.51 s |
| A3 | accepted | 212.36 s | 211.52 s |
| B3 | candidate | not run | not run |

The accepted wall median is 211.18 seconds. The worst possible candidate median is 211.32 seconds,
only a **0.07%** regression, while its two-run center is 0.23% faster. All five historical bundles
verify with 26 tracked files, and candidate generated data and deterministic sidecars remain
byte-identical.

Two final candidate profiles completed at 808.72 and 809.31 profiled invocation seconds with
73,325 and 73,023 samples, zero drops, and no degradation. Combined `get_digest` and `_find_slot`
exclusive samples were 560 and 501, a **77.8%** reduction from the accepted two-profile median of
2,388 samples. Their top five leaf ranks moved by at most one position and relative share changed
by less than 7%, so no third profile was required. Peak RSS was 1,321,451,520 and 1,425,162,240
bytes; the 1,373,306,880-byte median is **3.04%** above the 1,332,813,824-byte accepted-profile
median and passes the 5% gate. Both profile sidecars validate, are manifest-hashed, and accompany
generated data byte-identical to the unprofiled candidate.

The final revision-15 same-build run suspended after warm-up, was classified as behavior and
output-equivalence exact, hydrated all 28 participants, and resumed under `--resume-policy exact`.
Its 286-file completed bundle verifies and matches uninterrupted candidate generation byte-for-byte
across data, artifacts, and deterministic sidecars. The first scratch verification attempt again
demonstrated the existing macOS `/var` alias rejection; canonical `TMPDIR=/private/tmp` hydration
passed without changing the checkpoint.

Decision: **retain candidate 3 as exact**. Focused hit/miss throughput improves by about 35%/39%,
target-exclusive samples fall 77.8%, all-source wall time improves by at least 3.59%, historical
runtime stays within 0.07% in the worst possible median, median RSS grows 3.04%, and all 25 concrete
formats remain byte-identical to the corrected ASA baseline. No semantic index fallback was used.
The direct retained-stage medians (8.77% after SMB plus timing, then the 3.72% candidate center)
imply about **12.16% cumulative improvement** over the original profiler foundation, while the
intervening `dev` merge means that cumulative figure is staged evidence rather than one single-epoch
A/B comparison.

#### Final residual leaf ranking

The two final profiles leave the following non-overlapping exclusive leaf paths. This is a
navigation aid for a future campaign rather than permission to optimize them in this one. Amdahl
maximum again means the impossible best case where the measured leaf becomes free.

| Rank | Residual leaf path | Mean exclusive share | Amdahl maximum | Principal scope |
|---:|---|---:|---:|---|
| 1 | SMB connection text validation | 7.87% | 1.085x | SMB lifecycle across endpoint, network, and Samba evidence |
| 2 | Generated dataclass hashing | 5.97% | 1.063x | Timing/cache keys shared by correlated outputs |
| 3 | Generated dataclass initialization | 3.93% | 1.041x | Canonical event/context construction |
| 4 | RFC3164 timestamp formatting | 3.83% | 1.040x | Syslog-family and Cisco ASA rendering |
| 5 | Deep-copy | 2.52% | 1.026x | Immutable canonical/network snapshots |
| 6 | Thread condition notification | 2.32% | 1.024x | Emitter queues and barriers |
| 7 | Lifecycle `__post_init__` | 2.31% | 1.024x | Canonical lifecycle objects |
| 8 | Generic index `__getitem__` | 1.99% | 1.020x | Shared state lookup |
| 9 | Lifecycle weak-reference cleanup | 1.91% | 1.019x | Authority retirement |
| 10 | Jinja template compilation | 1.79% | 1.018x | Text/XML source rendering |

The optimized packed `get_digest` plus `_find_slot` path now averages only 0.73% exclusive share,
so further work on that exact path has little remaining whole-run ceiling.

## Reusable profiling capability

- `eforge generate --profile` is a hidden developer option. The default path does not construct or
  enable a profiler and does not take worker thread-CPU snapshots.
- A profiled successful run atomically writes `GENERATION_PROFILE.json` into the bundle root after
  the resolved scenario and before `GENERATION_MANIFEST.json`.
- The profile is an optional registered sidecar. Bundle replacement installs or removes it as part
  of the matched sidecar set, rejects symlink destinations, and includes its SHA-256 in the final
  generation manifest.
- Profiling is excluded from scenario/run fingerprints and checkpoint state. A resumed invocation
  starts a new report and records the recovery cursor in `starting_cursor`.
- Supported Unix main threads use a bounded 100 Hz `ITIMER_PROF` sampler. Prior signal handler and
  timer state are restored after the invocation. Unsupported platforms and non-main threads retain
  coarse metrics and report `sampler: unavailable` with a degraded warning.
- Folded stacks retain line detail while function aggregation uses portable source-path plus
  function keys. Storage is bounded to 50,000 unique stacks with a depth limit of 96.
- Reports include inclusive/exclusive samples, phase and named-stage timing, per-hour wall/process
  CPU and peak RSS, final rendered rows for every concrete emitter, per-hour row deltas where rows
  are rendered before the barrier, barrier wall time, worker CPU, maximum observed pre-barrier queue
  depth, and constant-time state/index counters.
- Windows Security, Sysmon, and Snort defer final rendering. Their hourly rendered deltas can remain
  zero, so the final emitter summary is authoritative for their output-row totals.
- Profiler setup, signal, restoration, metric-provider, and write failures degrade the report path
  without invalidating otherwise successful generated output.
- `ProfileMetricProvider` is the permanent bounded-metric interface. Campaign-only frame grouping
  code was kept outside the repository and removed after the report was assembled.

## Representative workload

`scripts/build_all_source_profile_workload.py` derives a temporary scenario from the unchanged
`tests/fixtures/performance/network_warmup_profile.yaml` fixture. It verifies that the source still
contains 63 users and 78 systems, then applies only deterministic profiling overrides:

- Seed 42; Monday 2026-03-02 13:00:00Z collection start; one warm-up hour and two collection hours.
- High baseline intensity, medium variation, high suspicious noise, and a calibrated high web rate
  of 1,500-3,000 events/hour so a run remains near the 10-15 minute target.
- Existing Windows/Linux endpoints, domain controllers, file servers, mail, web, proxy, and network
  topology are preserved. The historical fixture currently contains four named segments, not three;
  all four are covered rather than deleting one to match the older planning assumption.
- The existing `edge-proxy` becomes an explicit forward proxy. IDS and firewall sensors cover every
  segment, and existing network sensors expose the complete Zeek family.
- Eight small authored anchors guarantee endpoint authentication/process, SSH/Linux process, SMB,
  DNS, HTTP/TLS/file, explicit proxy, web/IDS, firewall, and SMTP attachment paths.
- All 25 concrete formats reported by `eforge info formats` are selected.

The derived scenario validated successfully. Four informational pivot-continuity hints are expected
because the authored entries are independent coverage anchors, not one attack narrative.

### Final rendered output coverage

The post-correction confirmation report contains all 25 concrete emitters:

| Format | Rendered rows | Format | Rendered rows |
|---|---:|---|---:|
| bash_history | 113 | cisco_asa | 91,590 |
| ecar | 117,901 | proxy_access | 7,637 |
| snort_alert | 23 | syslog | 957 |
| web_access | 41,825 | windows_event_security | 69,950 |
| windows_event_sysmon | 16,245 | zeek_conn | 86,982 |
| zeek_dhcp | 116 | zeek_dns | 7,837 |
| zeek_files | 76,402 | zeek_http | 85,011 |
| zeek_ntp | 437 | zeek_ocsp | 126 |
| zeek_packet_filter | 0 | zeek_pe | 0 |
| zeek_reporter | 0 | zeek_smb_files | 1,417 |
| zeek_smb_mapping | 765 | zeek_smtp | 2 |
| zeek_ssl | 4,260 | zeek_weird | 0 |
| zeek_x509 | 1,378 |  |  |

Every major output family is non-empty. The four zero-row Zeek files are valid sparse exceptions:
the workload produced no packet-filter status change, PE extraction event, reporter diagnostic, or
weird-protocol condition. Their emitters, barriers, and worker CPU are still represented in the
profile.

## Campaign measurements

### Profiler overhead gate

The unchanged historical fixture was run three times without profiling and three times with
profiling. Wall times are seconds:

| Mode | Run 1 | Run 2 | Run 3 | Median |
|---|---:|---:|---:|---:|
| Unprofiled | 229.26 | 221.99 | 223.71 | 223.71 |
| Profiled | 232.19 | 224.14 | 220.54 | 224.14 |

Median overhead was **0.19%**, below the 5% acceptance ceiling.

### All-source runs

- Primary unprofiled run: 880.62 seconds wall time.
- Two ranking profiles: 885.67 and 887.85 seconds wall time.
- A third, corrective confirmation was required after finding that deferred Windows/Sysmon/Snort
  emitters needed a final row-total snapshot. It completed with 874.21 profiled invocation seconds.
  This was an instrumentation correction, not a stability-triggered extra sample.
- The confirmation captured 77,247 main-thread CPU samples, dropped zero samples, was not degraded,
  and reached 1,459,585,024 bytes peak RSS.
- Confirmation hour wall times were 133.56 seconds warm-up, then 349.83 and 303.79 seconds for the
  collection hours. Baseline generation consumed 787.20 seconds, including 745.79 seconds in system
  traffic and 35.11 seconds in user activity; finalization consumed 85.27 seconds.
- The unprofiled and post-correction profiled `data/**` trees produced the same aggregate SHA-256:
  `f126e72fbef6eeaee993234b02b221d1a7fdec566a8f73dd8d6b4ab236a6d13b`.
- The bundle verifier accepted the post-correction bundle and confirmed the profile's manifest hash.
  The deterministic parity integration test also compares all deterministic generated sidecars,
  excluding only the profile, generation log, and generation manifest's run-specific fields.

## Grouping and ranking method

Every sampled leaf frame was assigned to exactly one coherent optimization family. Inclusive share
counts a family once when it appears anywhere in a sampled stack. Ranking uses mean exclusive share
across the three all-source samples. “Maximum speedup” is the Amdahl-law ceiling if that family's
measured exclusive cost were reduced to zero; it is not an expected implementation result.

The repeated runs were stable. No family changed by 20% relative share, no family moved more than
one position, and the only top-five boundary movement was the one-position exchange between generic
indexes and thread/queue synchronization. A stability-triggered fourth profile was therefore not
required.

## Ranked optimization targets

| Rank | Non-overlapping family | Exclusive share | Inclusive share | Amdahl maximum | Owning stage and affected outputs |
|---:|---|---:|---:|---:|---|
| 1 | SMB connection state validation/encoding | 15.95% | 16.76% | 1.190x | System traffic; Windows Security, eCAR, Syslog/Samba, Zeek conn/SMB |
| 2 | Timing distributions and RNG setup | 12.84% | 25.95% | 1.147x | Canonical timing; all correlated endpoint, network, web, proxy, and IDS outputs |
| 3 | Lifecycle authority and registry maintenance | 9.27% | 24.41% | 1.102x | Canonical lifecycle; all sources with sessions, processes, transports, or files |
| 4 | JSON serialization | 8.23% | 8.23% | 1.090x | Generation and finalization journals/reports; eCAR and integrity sidecars directly |
| 5 | Generic index and mapping lookup | 7.30% | 7.87% | 1.079x | Canonical state lookup; shared across all output families |
| 6 | Thread and queue synchronization | 7.16% | 7.16% | 1.077x | Dispatch/barriers; all 25 emitter workers |
| 7 | Dataclass and lifecycle object construction | 6.71% | 10.27% | 1.072x | Canonical event/context construction; shared across all output families |
| 8 | Deep-copy and immutable network snapshots | 5.92% | 7.76% | 1.063x | Network bundle/runtime; Zeek, ASA, Snort, eCAR FLOW, web, and proxy |
| 9 | Jinja template compilation/rendering | 5.04% | 5.18% | 1.053x | Source-native rendering; broad text/XML emitter impact |
| 10 | Emitter rendering and source finalization | 3.88% | 16.94% | 1.040x | Finalization; especially Windows, Sysmon, Snort, and sorted/multiplexed outputs |

Exclusive-share ranges across the three all-source profiles were narrow: SMB 15.93-15.97%, timing
12.83-12.86%, lifecycle 8.99-9.62%, JSON 8.08-8.45%, indexes 7.16-7.41%, synchronization
7.08-7.27%, object construction 6.44-6.93%, immutable snapshots 5.71-6.04%, Jinja 4.80-5.19%,
and emitter finalization 3.86-3.92%.

### Historical-fixture comparison

The historical Zeek-focused profiles separate shared costs from broad-output costs:

- Lifecycle authority averaged 17.08% exclusive, timing/RNG 10.43%, JSON 10.75%, generic indexes
  11.09%, object construction 11.08%, and deep-copy/network snapshots 10.44%. These are shared
  canonical costs, not artifacts of enabling Windows, EDR, firewall, web, and proxy formats.
- SMB validation averaged only 1.74% on the historical workload but 15.95% all-source. It is the
  strongest workload-sensitive target.
- Jinja averaged less than 0.01% on the historical fixture but 5.04% all-source, making it clearly
  output-family-specific.
- Queue synchronization rose from 4.54% to 7.16% with all emitters active. Emitter-owned exclusive
  work rose from 0.19% to 3.88%, while its high inclusive share confirms substantial finalization
  beneath emitter call paths.

## Correctness constraints for future optimization

1. SMB work must preserve canonical connection identity, bounded index validation, lifecycle order,
   source-native filesystem/path views, and checkpoint hydration.
2. Timing/RNG work must preserve seed determinism, causal ordering, source timing contracts, and
   byte-stable replay.
3. Lifecycle work must retain exact ownership, bounded authorities, retry receipts, pruning, and no
   orphan or post-close evidence across checkpoint/resume.
4. Serialization changes must preserve exact source bytes, stable key/field semantics, manifest
   hashes, and durable journal recovery.
5. Index changes must preserve stale-entry and identity-reuse defenses for sessions, PIDs, threads,
   connections, and application channels.
6. Queue changes must preserve deterministic dispatch order, backpressure, worker-error propagation,
   and hour barriers.
7. Object-construction changes must keep immutable canonical truth shared across source renderers.
8. Snapshot changes must not permit tuple, process, DNS/TLS/proxy, or visibility facts to drift after
   canonical commit.
9. Template changes must preserve source-native escaping, headers/footers, formatting, and output
   bytes where byte compatibility is required.
10. Finalization changes must preserve atomic sorted publication, exact source cohorts, retries,
    symlink protections, and manifest-last bundle integrity.

These targets are evidence for choosing the next experiment. They do not yet justify Cython, Rust,
Go, multiprocessing, or any other implementation strategy; several of the highest costs are strong
candidates for algorithmic or data-structure improvements in Python first.

## Validation record

- Focused profiler, CLI, manifest, sidecar, checkpoint-adjacent, and determinism tests: passed.
- Post-correction integration parity test: passed with nonzero deferred Windows/Sysmon totals.
- Routine pytest suite: 8,303 passed, 5 skipped, and 2,006 slow/soak tests deselected.
- Ruff lint, Ruff format, behavior-surface manifest, and whitespace checks: passed.

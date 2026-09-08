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

### Target 3: lifecycle authority and registry maintenance — paused during exact evaluation

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
3. The current uncommitted candidate retains the same bounded exact snapshot but creates it lazily
   after the first terminal transport-ID lookup. The focused repeated-lookup improvement remains
   about 84%. Its residual profile completed in 856.19 seconds (0.27% faster than the accepted
   timing build) with peak RSS of 1,323,548,672 bytes (8.37% lower). In that profile,
   `events/lifecycle.py:__post_init__` inclusive share fell to 0.72% and transport-row decoding to
   1.48%.

The lazy candidate's all-source macro comparison was explicitly paused after the current B1 run:

| Build | A1 | B1 | B2 | A2 | A3 | B3 | Median |
|---|---:|---:|---:|---:|---:|---:|---:|
| Accepted timing A (`ffc034d25`) | 896.69 | — | — | — | — | — | incomplete |
| Lazy lifecycle candidate B | — | 870.14 | — | — | — | — | incomplete |

B1 was 2.96% faster than the adjacent A1 run. Peak RSS was 1,469,890,560 bytes for A1 and
1,432,109,056 bytes for B1 (2.57% lower). This single adjacent pair is not sufficient evidence for
retention. Both bundles verified successfully, and direct comparison found all 278 `data/**` files
byte-identical.

Pause state (2026-09-08): the candidate implementation, focused test, and provisional
generation-behavior revision 7 are checkpointed together for safe branch handoff. This checkpoint
is not a retention decision. No changelog entry has been added because the macro comparison is
incomplete. Resume the required `A-B-B-A-A-B` sequence with B2, then A2, A3, and B3. If the macro
gate passes, run the historical-fixture, deterministic-sidecar, checkpoint/resume, behavior-surface,
and focused lifecycle gates before deciding whether to retain the candidate. Do not treat revision
7 as accepted until those gates pass.

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

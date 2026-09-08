# Generation Performance Optimization Assessment

## Outcome

EvidenceForge now has permanent, opt-in generation profiling. The campaign met the overhead,
coverage, determinism, and stability gates, and produced the ranked top-ten target list below. No
hotspot was optimized and no implementation language was selected in this phase.

Working branch: `codex/generation-performance-optimization`

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

# Duration-stable PID allocation and safe reuse

## Objective

Replace run-history PID uniqueness with realistic Linux and Windows wrap/reuse while ensuring
allocator memory and CPU cost depend on current concurrency and a fixed scheduling window, never
total scenario duration.

## Implementation

- Linux now advances an unbounded logical PID position and renders through the exclusive
  `500..4,194,303` ring. The old all-history used-ID set is removed.
- Windows retains its multiples-of-four distribution and `4,000..65,532` ring, but checks every
  candidate against live reservations instead of checking only at reset.
- Fixed boot processes remain reserved for host lifetime. Syslog-only processes use explicit
  transient intervals; cached Postfix qmgr processes reserve through scenario completion and
  session/worker companions reserve through their final row.
- Candidate checks use current process/fixed/transient reservations, with probes bounded by the
  number of occupied reservations plus one.
- The engine advances a watermark after every generated hour while retaining the scheduler's
  fixed 24-hour out-of-order authoring horizon. Detailed allocations, timestamp ordinals, and
  transient intervals before the watermark are discarded; sealed history is one logical cursor
  per host.
- Source timing, termination timing, connection holds, foreground finalizers, and module
  deduplication are keyed by process instance `(host, PID, start)` and pruned at the watermark.
- The rendered-output probe accepts explicit high-to-low Linux wrap and narrow source-observation
  reorder while retaining errors for wider unexplained reversals.
- SSH process termination now treats transport close as a session deadline and retires residual
  receiver commands before close, preventing late dependent evidence uncovered by the 24-hour
  gate.

## Verification

- Focused allocator, lifecycle, source-timing, world-planner, evaluator, and integration tests
  pass.
- The 24-hour/seven-day/30-day duration probe at 64 allocations per hour reached identical
  retained allocator size for seven and 30 days (2,959,979 measured bytes), with exactly one
  candidate probe per collision-free allocation. The 30-day final-window cost was 0.9684× the
  24-hour window and retained-memory ratio was 1.0000.
- Four full-format 4×/24-hour assessment generations completed after the fixes. The two formal
  repeated measurements were byte-identical (`4176114b17b0564154a2043d634dc75132b5a96dec481d4a7751ee6696d9e98b`),
  took 81.6–86.8 seconds, used 315.6–337.3 MiB peak RSS, and emitted 148,610,713 bytes.
- Rendered eCAR lifecycle validation found 5,432 process creates, 4,842 visible terminations,
  zero overlapping PID lifetimes, zero stale termination/object mismatches, one valid Linux wrap,
  and zero unexplained Linux PID reversals.
- The completed resource calibration remained inside the existing memory and disk forecast
  intervals, so no forecast coefficient refit was made.

## Final verification

- Full non-slow suite: 5,393 passed, 27 skipped, and 15 deselected in 324.44 seconds.
- Repeated slow duration benchmark: passed in 8.86 seconds; all three repetitions satisfied the
  operation-count, late-window timing, and retained-memory gates.
- Repository Ruff lint and formatting checks passed after applying the formatter's one required
  line wrap. `git diff --check` also passed.

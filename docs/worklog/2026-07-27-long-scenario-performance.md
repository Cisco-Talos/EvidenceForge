# Long-scenario connection performance investigation

## Context

The FOR668 Lab 3.1 scenario is a 56-day, 63-user, 78-system, three-sensor,
seven-format Zeek workload. A partial SOF-ELK® run in a OneDrive-backed directory
produced about 3.1 million rows and 1.2 GB through roughly ten dense baseline
days, but required about four hours to reach the March 10 red-herring marker.

The investigation compared this behavior to the prior progressive slowdown fixed
by `b5b10fc6` (`fix: optimize connection tuple cache pruning`).

## Diagnostic instrumentation

Opt-in telemetry was added on `dev`, gated by `EFORGE_PERF_LOG`, to record:

- wall time and emitter-barrier time per simulated hour;
- recent connection tuple dictionary and expiry-heap sizes;
- tuple-prune calls and cumulative time;
- full-table Apache source-port lookup calls and cumulative time;
- open connection count and hourly sweep time; and
- cumulative emitter record count.

The original scenario and its partial output were not modified. A temporary copy
at `/tmp/eforge-perf-lab31.AsIhcE/scenario.yaml` changed only the top-level
duration from `56d` to `48h`. The run used the full authored format mix and
`--target sof-elk`, writing to local `/tmp` storage.

## 48-hour result

- Total CLI runtime: 10:59.
- Baseline hour loop: 627.3 seconds.
- Day 1: 131.9 seconds (Sunday/weekend activity).
- Day 2: 495.4 seconds (Monday/business activity).
- Emitted rows at hour 48: 502,303.
- Output size: 219 MB.
- Tuple cache maximum: 246,515.
- Tuple expiry heap maximum: 561,597.
- Open connection table maximum: 18,904.
- Total emitter barrier time: 24.7 seconds.
- Total hourly connection sweep time: 0.5 seconds.
- Total tuple-prune time: 1.3 seconds.
- Instrumented Apache full-table tuple lookup calls: zero.

The original `b5b10fc6` cache-pruning fix remains intact. Pruning itself consumed
about 0.2% of baseline-loop time and did not reproduce the old whole-dictionary
rebuild failure.

However, normalized generation cost rose with retained open connection count:

- Hour 2: 715 open connections, 0.635 seconds per 1,000 emitted rows.
- Hour 24: 7,257 open connections.
- Hour 37: 11,411 open connections, 1.152 seconds per 1,000 rows.
- Hour 48: 18,904 open connections, 1.980 seconds per 1,000 rows.

## Root cause

`ActivityGenerator._connection_tuple_recently_used()` first performs indexed
lookups in `_recent_connection_tuples`. When those miss, it linearly scans every
entry in `state_manager.state.open_connections` for each ephemeral-port candidate.
The benchmark recorded 23,000-60,000 tuple-prune/reuse checks per simulated hour.
At hour 48, approximately 47,600 checks could each inspect a table approaching
18,900 entries.

The open-connection table grows because `StateManager.sweep_closed_connections()`
removes only entries whose `state` is in `_TERMINAL_CONN_STATES`. Ordinary
connections can retain `state="established"` or `state="SF"` while already
carrying a past `close_time`; `SF` is not in the terminal set. Those completed
connections therefore remain in the table and amplify the fallback scan.

This is the same performance family as the June tuple-cache incident, but not a
revert of that fix. The remaining unindexed fallback scan and incomplete
lifecycle eviction create a new quadratic-like path as scenario history grows.

## Recommended fix boundary

Fix the connection lifecycle/index ownership rather than special-casing emitters:

1. Evict connections whose canonical `close_time` is at or before the sweep
   cutoff, while preserving future reservations created by non-monotonic
   storyline expansion.
2. Replace the fallback full-table scan with a tuple-keyed active/recent
   connection index owned by `StateManager`, or prove that the existing recent
   tuple cache is authoritative and remove the fallback.
3. Add a regression benchmark that crosses 100,000 recent tuples and verifies
   bounded open-connection state plus approximately stable normalized cost over
   a multi-day web/proxy-heavy workload.
4. Verify byte-identical or normalized-equivalent generated output before and
   after the optimization.

## Implementation on `dev`

The fix was implemented at the canonical state/activity boundary:

- `StateManager` now maintains an exact normalized 5-tuple → connection-ID
  index as connections are opened and removed.
- `ActivityGenerator._connection_tuple_recently_used()` delegates its live-state
  fallback to that index instead of scanning the global connection table.
- Hourly sweeps now remove connections whose canonical `close_time` is at or
  before the completed-hour cutoff, even when their legacy state string remains
  `established` or `SF`. Future-close reservations remain present.
- The prior 24-hour recent-tuple dictionary/heap from `b5b10fc6` remains intact.
- A second profiled linear lookup was removed by lazily indexing scenario
  systems by short hostname and FQDN.

## Verification

Fast regression coverage:

- 504 focused state/activity/Zeek tests passed.
- A structural test replaces `open_connections` with a mapping whose
  `.values()` raises, proving exact-tuple lookup does not fall back to a
  full-table scan.
- Lifecycle tests verify close and sweep operations remove tuple-index entries,
  and that a future-close connection survives an earlier cutoff.

Long-horizon coverage:

- It simulates 45 days × 1,000 connections and verifies that both retained
  connections and tuple-index entries return to zero after each daily cutoff.
- The test passed in 0.49 seconds locally. It is part of the default suite
  because that runtime is small enough not to warrant the `slow` marker.

Real-scenario comparison, using the same temporary 48-hour full-format SOF-ELK
slice:

- Before: 659 seconds end to end; 627 seconds in the baseline loop.
- After connection indexing/lifecycle eviction: 506.6 seconds end to end; about
  459 seconds in the baseline loop.
- Improvement: about 23% end to end and 27% in baseline generation.

A cProfile run covering an eight-hour warm-up plus one dense Monday hour showed:

- 73,712 tuple-reuse checks: 0.60 seconds total.
- 73,531 indexed live-state checks: 0.11 seconds total.
- Nine lifecycle sweeps: 0.06-0.09 seconds total.

This confirms that connection lookup/sweep cost is now bounded and negligible.
The hostname index reduced 96,192 hostname resolutions from 5.35 seconds to
0.22 seconds in the same profiled workload, reducing profiled runtime from
63.2 to 58.0 seconds. Remaining runtime is dominated by canonical network
transaction construction and rendering volume rather than scenario-age growth.

The release gate `uv run pytest --no-cov --include-slow` completed with 4,980
passes and 28 expected skips in 405.41 seconds. The 45-day connection-state test
ran as part of the default selection because its 0.49-second standalone runtime
does not justify a `slow` marker. Ruff checks, format checks, and
`git diff --check` also passed.

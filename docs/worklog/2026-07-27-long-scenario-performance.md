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

## Emitter barrier and storage benchmark

A temporary, uncommitted benchmark harness compared the same deterministic
48-hour scenario across local and OneDrive-backed output with one-hour and
six-hour baseline emitter barriers. It recorded queue depth, queue-put latency,
barrier time, dispatch time, writer flush count/time, final writer close/sort
time, output size, and SHA-256 hashes for every generated file.

| Storage | Barrier | Elapsed | Barrier time | Max queue | Flushes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Local `/tmp` | 1 hour | 374.1s | 25.0s | 1,827 | 880 |
| Local `/tmp` | 6 hours | 351.4s | 7.7s | 6,376 | 177 |
| OneDrive | 1 hour | 369.9s | 26.3s | 1,827 | 880 |
| OneDrive | 6 hours | 350.2s | 5.9s | 5,492 | 177 |

Six-hour barriers improved elapsed time by 6.1% locally and 5.3% on OneDrive.
All four runs produced the same 24 output paths, identical SHA-256 hashes, and
210,556,708 total bytes. Queue occupancy remained well below the 50,000-event
capacity. Across each run, only zero to five queue puts exceeded 10ms and no
queue-full/backpressure warning occurred.

OneDrive did not impose a measurable penalty in this controlled 201MB test.
Hourly writer flush time was 8.0s locally and 8.2s on OneDrive; final writer
close/global-sort time was 1.9-2.0s in both locations. The existing per-emitter
background threads therefore kept up comfortably, and the data does not support
adding a second write-thread stage.

Six-hour cadence caused substantially larger sorted flush batches: summed
emitter-thread flush time rose from about 8s to 84-95s, even though those threads
overlapped generation enough to reduce wall time. A more targeted follow-up is
preferable to simply changing cadence: remove the current sequential timeout
handshake from `barrier_flush()`. Each emitter worker waits for
`Queue.get(timeout=0.1)` to expire before observing `_flush_barrier`, and the
engine invokes seven emitter barriers sequentially. The measured roughly
0.5-second hourly barrier cost closely matches that design. A queue sentinel or
direct drain/flush acknowledgement could retain hourly ordering and small
buffers while avoiding most of the polling delay.

## FIFO emitter barrier implementation

The timeout handshake was replaced with a FIFO flush request placed on each
emitter's existing event queue. The worker processes every preceding event,
performs its existing emitter-specific barrier action, and acknowledges the
request before generation continues. This preserves the hourly boundary and
per-emitter ordering without waiting for an idle `Queue.get(timeout=0.1)` call.
Windows Security retains its barrier-specific SQLite spool behavior.

Verification results:

- 184 focused emitter tests passed, including a new regression proving that the
  queued barrier executes on the emitter worker and leaves no unfinished queue
  tasks.
- A two-hour, nine-system all-format SOF-ELK matrix produced 47 byte-identical
  files before and after the change.
- The one-hour slice of the supplied scenario produced the same 24 files and
  2,939,175 bytes. Aggregate barrier time fell from 0.899s to 0.029s.
- The 48-hour supplied-scenario comparison produced the same 24 files and
  210,556,708 bytes. Runtime fell from 374.1s to 347.9s (7.0%), while aggregate
  barrier time fell from 25.0s to 2.1s.
- The release gate `uv run pytest --no-cov --include-slow` passed with 4,981
  tests and 28 expected skips in 295.29 seconds. Repository-wide Ruff lint and
  format checks also passed.

The retained 2.1 seconds is useful work: draining queued events and flushing
writer buffers. The eliminated 22.9 seconds was polling/handshake latency.

## Unified duration-stable state indexes

A later stopped 56-day run showed that duration-growing work remained outside
the connection tuple path. Profiling and a repository-wide scan found the same
linear-history pattern in session history, process/thread lookup, connection
identity lookup, expiry caches, Linux logind allocation, and Linux PID
allocation. These paths now share four index primitives:

- `IndexedEntityStore` for insertion-ordered primary storage with equality
  secondary indexes;
- `GroupedTemporalIndex` for per-owner time-range lookups;
- `ExpiringIndex` for deadline-driven eviction; and
- `TemporalAllocationIndex` for chronological allocation bounds and elapsed
  delta checks.

StateManager now uses these primitives for active and ended sessions, running
processes and threads, open connections, connection close deadlines, Linux PID
history, and logind session history. ActivityGenerator uses the expiry index for
recent connection tuples, DNS observations, and foreground-process finalizers.
SSH, RDP, and Windows remote-authentication actions use direct Zeek UID and
transaction-ID lookups instead of scanning the connection table.

An equality-only ended-session index was insufficient: a 500,000-session
history still took about 4.3ms to filter one user's expired history. Adding the
grouped temporal bound reduced the same lookup to about 0.012ms, independent of
whether the total history contained 10,000, 100,000, or 500,000 sessions.

Linux PID allocation contained a separate quadratic retry chain. When the
time-derived candidate fell below the latest visible PID, it repeatedly hashed
and advanced through every intervening candidate. Before repair, 8,000
allocations took 18.18 seconds. The allocator now jumps deterministically above
the chronological lower bound, uses at most 64 bounded collision probes, and
queries a prefix-max temporal summary. Results after repair:

| Allocations | Elapsed | Cost per allocation |
| ---: | ---: | ---: |
| 1,000 | 0.0123s | 12.3µs |
| 2,000 | 0.0250s | 12.5µs |
| 4,000 | 0.0599s | 15.0µs |
| 8,000 | 0.1050s | 13.1µs |
| 16,000 | 0.2230s | 13.9µs |

The PID repair intentionally changes Linux PID values relative to earlier
versions, and those values can propagate into correlated record identities.
Determinism within the new version is preserved: two independent eight-hour
mixed Windows/Linux/SSH generations were byte-identical for every artifact
except the runtime-only `generation.log`.

Verification for commit `eafb0f05`:

- 112 focused index, PID, and StateManager tests passed.
- The default gate passed with 4,981 tests and 41 expected skips in 234.87s.
- `uv run pytest --no-cov --include-slow` passed with 4,994 tests and 28
  expected skips in 293.29s.
- Repository-wide Ruff lint and format checks passed.
- The explicit coverage gate was aborted at the maintainer's direction after
  25m23s (105 passed, 5 skipped) because instrumentation made generation-heavy
  integration tests prohibitively slow; it is not recorded as a passing gate.

## Lifecycle-boundary and syslog-memory hardening

The next full run reached 58% before failing to resolve a planned session. The
failure was a lifecycle-boundary bug rather than corrupt authored data:
`WorldPlanner` found no session at the activity time and requested a logon a few
seconds earlier, while `ActivityGenerator` reused an ended session that was
historically valid at the backdated logon time. The planner then correctly
rejected that returned ID because it was no longer active at the actual activity
time.

Commit `bb6d6033` separates these two contracts explicitly:

- historical session queries remain available for rendering out-of-order
  evidence before a visible logoff;
- active-only session queries are used when new state will be attached;
- backdated bootstrap requests carry the later time at which reuse must remain
  valid; and
- direct SSH and RDP source-session bootstrap paths use the same guard.

The repository-wide follow-up scan found three remaining global running-process
enumerations in session teardown and one global active-session enumeration in
Windows interactive-session selection. Running processes now have a LogonID
secondary index, teardown uses a session-scoped lookup, and interactive-session
selection uses the existing host index. No generation call sites remain that
enumerate every active session, running process, or open connection to locate
one owner.

Syslog was the remaining duration-growing memory consumer. It must preserve a
host-wide final sort and source-native logind, PAM, sudo, and kernel timestamp
normalization, so ordinary writer flushing could not safely write final output
early. Hourly barriers now spill each logical rendered record to a private,
record-preserving JSON-lines spool. Close processes one host at a time, performs
the same final normalization, writes the native year-partitioned output, and
removes the private spool. JSON framing is intentionally private: it preserves
embedded CRLF and other adversarial message content without changing final
syslog bytes.

A 200,000-row, 20-host synthetic measurement reduced pre-close maximum RSS from
about 109.7 MB to 93.0 MB (about 15%) at that scale. More importantly, retained
memory now scales with the largest host's finalization set rather than the
entire multi-host syslog corpus. Barrier-spooled and fully buffered syslog output
is byte-identical, including embedded CRLF records.

The Rich generation progress display now estimates speed over a 15-minute
window. This is display-only and prevents the ETA from disappearing when a
long-running scenario has irregular per-hour work.

Final verification:

- 617 combined focused lifecycle, state, activity, and logoff tests passed.
- 68 adversarial-payload integration tests passed.
- The deterministic-generation integration test passed with byte-identical
  artifacts across independent runs.
- The default non-slow selection produced 4,985 passes and 41 expected skips;
  its only initial failure was the sandbox denying a localhost port bind in the
  Splunk harness, and that test passed when rerun with the required permission.
- `uv run pytest --no-cov --include-slow` passed with 4,999 tests and 28
  expected skips in 288.82 seconds.
- After the final deterministic-identity compatibility review, 242 focused
  CLI, state, world-model, and emitter tests passed.
- Repository-wide Ruff lint, format, and diff checks passed.
- Coverage was not rerun, following the maintainer's direction that the
  coverage-instrumented generation suite was too slow. The default and slow
  gates were run without coverage as required by the project release policy.

## Final network-observation retention audit

The completed 56-day run peaked near 7.2 GB RSS even after connection-state and
syslog fixes. A repository-wide retained-container audit found that
`EventDispatcher` kept one `(canonical_uid, format)` entry for every planned
network observation for the entire run. The table had two real consumers:
storyline ground-truth UID projection and SMTP route reporting. Both consume
the result immediately after one connection finishes, so retaining every prior
connection was unnecessary.

Commit `b00bdd1f` changes dispatch to return the admitted sensor-local
identifiers for the current event. The network action bundle republishes only
the most recently completed connection after any nested OCSP or endpoint
effects finish. Existing callers retain the same blank/sensor-local/unplanned
semantics, while retained state is now one UID plus one small format mapping.
A 100,000-publication regression test verifies that only the latest two test
format values remain.

The same audit found that `GroupedTemporalIndex.remove()` and replacement
correctly made old records inactive but left their backing tuples allocated.
The shared index now compacts a group after at least 1,024 stale records make up
half its history. Live historical session records remain intact because they
are required for out-of-order lifecycle and durable identity correlation.

`COLLECTION_PROFILE.json` was also moved from `data/` to the run metadata root.
It is not log evidence, and its former location caused SOF-ELK ingestion scripts
that reasonably ingest every file under `data/` to treat the profile as a log.
CLI overwrite detection, staging, rollback, final listing, tests, and the
evidence-format reference now use the root location.

Verification:

- 514 combined focused engine, CLI, dispatcher, observation, activity, and
  index tests passed before the final CLI additions; the final focused set
  passed with 170 tests.
- A real one-hour CLI generation placed `COLLECTION_PROFILE.json` at the output
  root and left no profile inside `data/`.
- The supplied scenario was generated for 48 hours from exact parent commit
  `a6e79b8c` and from the network-retention implementation. All 24 artifacts
  and the complete directory trees were byte-identical.
- The prior full 56-day output was no longer present at
  `/Users/bianco/TEMP/lab-3.1`, so a separate prefix comparison against that
  completed run was not possible.
- The default gate passed with 4,988 tests and 41 expected skips in 240.51
  seconds.
- `uv run pytest --no-cov --include-slow` passed with 5,001 tests and 28
  expected skips in 300.94 seconds.
- Repository-wide Ruff lint, format, and diff checks passed.

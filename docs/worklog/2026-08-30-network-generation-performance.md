# Network Generation Performance

## Context

A long scenario spent roughly 55 minutes on an eight-hour warm-up. Live `py-spy` sampling showed
that generation saturated one core while emitter workers were idle. The dominant costs were
connection-cursor preflight, recursive validation of Python `Random` state, repeated request stable
identity encoding, commit-result deep copies, and HMAC authentication of engine-owned plan graphs.
Indexed session/cache lookup was negligible, so the earlier duration-growing cache-search problem
was not recurring.

## Decision

External scenarios, packs, configuration, and payloads remain untrusted. Exact objects created by
the deterministic generation engine are trusted. Connection planning retains manager ownership,
version/state-time/counter fences, owner RNG drift checks, one-shot lifecycle rules, atomic commit,
rollback, and recovery. It no longer treats arbitrary Python already executing in-process as an
attacker boundary.

## Implementation

- Connection RNG proxy calls use constant-time owner, lifecycle, and preview-stream checks.
- Full RNG states are compared at transaction validation rather than recursively walked on every
  draw, and connection cursor/identity tokens no longer encode those large states.
- Network request identity is captured once at planner entry and reused by timing and transaction
  helpers without changing the public seed-scoped `stable_id` property.
- Planner execution and the public `stable_id` property share the same canonical value encoder and
  digest framing without authenticating Python class, function, closure, or descriptor metadata.
- Frozen engine-owned commit results and transactions are reused through sealing rather than
  repeatedly deep-copied and revalidated.
- Connection composite plans carry an opaque manager-owner token plus their existing semantic
  fences; full graph HMAC recomputation was removed from the connection hot path.
- Tests whose sole contract was surviving `object.__setattr__`, callback traps, or copied internal
  capabilities were removed or rewritten around normal immutable and ownership contracts.

The remaining trusted-engine migration was split into four routine-suite-gated commits:

- `388b1d7d` removed hostile-runtime identity and binding defenses.
- `ee0f3072` replaced shared lifecycle, runtime, timing, registry, ledger, and preparation graph
  authentication with constant-time owner-issued authority state.
- `fd8d3590` simplified protocol, application-channel, observation, and continuation authorities.
- Stage 4 simplifies StateManager and emitter recovery authorities while retaining ownership,
  lifecycle/version fences, atomic publication, retry, rollback, and filesystem descriptor safety.

The dispatcher owner token used by a few compatibility carriers is a constant per-dispatcher
opaque marker, not a secret or security proof. Exact retained-carrier identity and explicit
lifecycle state remain authoritative.

## Measurements and Verification

The focused cursor benchmark performs 4,000 planning draws across 20 cancelled cursors. The
baseline was 0.783 seconds; the optimized implementation measured 0.004 seconds on the same host,
approximately 185 times faster for that hotspot.

For stable request identity, 200 repeated encodes of a normal request improved from 0.0498 seconds
to 0.0269 seconds (1.85 times faster). A nested DNS request with a Pydantic `System` improved from
0.0965 seconds to 0.0560 seconds (1.72 times faster). Representative simple, nested, and container
graphs produce exact matching IDs through the public and trusted paths across different generation
seeds.

A temporary copy of the reported scenario was reduced to a two-hour generation window plus its
minimum one-hour warm-up, with storyline and red-herring sections removed. The original source was
not changed. The archived pre-change implementation reached hour 1/2 after 15:18. The optimized
implementation reached hour 2/2 after 8:58, approximately 3.3 times the baseline generation
throughput at the observed progress points. Both runs were interrupted rather than spending more
time in finalization, so byte parity is covered by the deterministic unit/slow fixtures instead of
these incomplete bundles.

An authorized optimized `py-spy` repeat collected 2,005 samples during the shortened scenario's
warm-up. The former dominant stacks were absent: connection-cursor preflight, recursive RNG-state
validation, composite-plan authentication, and full graph-integrity token generation received no
samples. Stable request identity was a single bounded planner-entry operation (the largest observed
branch was 4.84%, down from 14.93%), while individual remaining deep-copy branches were below 1%
instead of the prior 9.94% aggregate hotspot.

The routine suite passed with 8,157 tests and 27 skips. The slow network-identity suite passed all
83 cases, including fresh-process determinism and trusted/public byte parity, and the focused
once-per-transaction identity test passed. Ruff check and format verification also passed.

After Stage 4, its focused exact-publication and service-logon recovery suite passed all 86 cases,
and the complete routine checkpoint passed 7,939 tests with 27 skips and 1,990 slow/soak cases
deselected. The reduced routine count reflects retirement of tests whose only contract was
resistance to hostile same-process mutation; ownership, stale-capability, duplicate-finalization,
rollback, interrupted-publication, and retry coverage remains.

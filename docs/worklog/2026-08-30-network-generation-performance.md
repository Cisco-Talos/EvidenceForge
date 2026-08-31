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
- `60ed3a05` simplified StateManager and emitter recovery authorities while retaining ownership,
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

The final shortened-scenario parity run completed on both revisions. Commit `2859218b` generated
the two-hour scenario plus one-hour warm-up in 5:10; Stage 4 completed it in 5:08. The output trees
were byte-identical except for `GENERATION_MANIFEST.json.created_at`. This matched run therefore did
not meet the planned two-times end-to-end throughput gate, despite the large isolated cursor gain.

The final 60-second Stage 4 `py-spy` capture contained approximately 5,995 samples. Recursive RNG
validation and HMAC graph authentication were no longer dominant. The next residual costs were
trusted request stable-ID encoding (667 samples), prepared source-timing work (612 samples), deep
copying (roughly 500 samples), and source-timing state digests (216 samples). Inspection localized
the largest redundant copies to exact frozen application-channel preparation carriers.

A final bounded follow-up removed those application-channel carrier copies, replaced source-timing
preparation digests with owner-issued constant-time tokens while retaining exact version and lane
fences, and added trusted reuse of Pydantic identity subgraph digests. Public request identity still
performs fresh boundary validation and retains seed-scoped behavior. This follow-up is intentionally
the pause point; another matched profile and scenario benchmark remain future work.

The shortened workload is now tracked as the anonymized performance fixture
`tests/fixtures/performance/network_warmup_profile.yaml`. It preserves the 78-system, 63-user,
four-segment, three-sensor topology and Zeek workload shape while replacing exercise,
organization, network-identity, host, and user names. Future baseline/current comparisons must run
the same tracked fixture on both revisions; its renamed stable-seed scopes mean its output is not
byte-comparable to the earlier non-anonymized shortened run.

The final slow gate passed 1,760 tests and had one environment-only failure because the referenced
`meridian-healthcare-solutions` pack was absent from both the worktree and main checkout. No soak
tests were run.

## 2026-08-31 profile-driven completion

Work resumed on `codex/fix-dns-watermark-order` from tracked HEAD `7ce9003d3` using Python 3.12.12,
uv 0.12.7, py-spy 0.4.2, seed 42, and the fixed anonymized fixture digest
`a222f484b6c038f4da23b1b4db0315a207c71b15b83aaa38b7a9cf52bb16b700`. Baseline commit
`2859218ba55c2b6dbc9c7bb97af10a5e1ace8864` was exported with `git archive`; no Git worktree was
created. Both revisions used locked dependencies, the same interpreter and machine, an empty
project root, and the fixture's packaged defaults. Validation passed on both revisions with the
expected 82 network-only warnings.

macOS prevented unattended py-spy attachment and child recording without root. A temporary
pure-Python `ITIMER_PROF` sampler therefore captured the main planner thread at 100 Hz for 60 CPU
seconds while each real generation completed. The initial profile collected 5,643 samples. Its
largest removable inclusive families were `random.Random.seed` (30.11%), cryptographic nonce
generation (19.16%), prepared source timing (17.93%), source-timing authority isolation (15.22%),
composite validation (16.69%), deep copying (6.27%), and trusted stable identity (6.57%). Inclusive
families overlap and are not additive.

The profile-driven changes were kept in independent rollback-safe commits:

- `9e0a702bf63f634e519b92df29271bc474e1332d` fixed termination after rejected GPO PID-0 admission.
- `af7e1ebd92a5a6512c2276fc8018997626b15413` cloned RNG state without redundant OS seeding. The
  focused benchmark improved to 727.586 connections/second with exact result identity.
- `635d9c464d210843e384d7ddee68ca3bae21b129` reused immutable trusted source-timing and network
  receipt proofs. Two focused checks measured 689.450 and 703.520 connections/second amid host
  variance, with exact result identity.
- `4e81a651497907fd1c382f67a9ebac9fb2121e24` transferred recursively frozen lifecycle requests at
  the private production adapter boundary. The focused result was 710.997 connections/second.
- `c90057ccdd3e0b24647e6a1e75264224352cd851` retained immutable trusted scalar identity digests and
  bypassed hostile-input resource accounting only in the private engine path. Public boundary
  validation and digest bytes are unchanged. The final focused result was 780.500
  connections/second, 29.23% above the pre-campaign 603.961 result.

The first matched post-batch profile collected 5,499 samples. Random seeding fell from 30.11% to
2.27%, cryptographic nonce generation from 19.16% to 0.15%, prepared source timing from 17.93% to
3.40%, timing-authority isolation from 15.22% to zero, and composite validation from 16.69% to
1.15%. It exposed lifecycle request copying at 8.00% inclusive. After that transfer, a 5,487-sample
profile measured lifecycle preparation at 2.15% and trusted stable identity at 10.04%. The final
5,599-sample profile measured trusted identity at 4.93%, lifecycle preparation at 2.27%, random
seeding at 2.13%, and nonce generation at 0.13%. Canonical event sealing remained 7.61% and total
deep copying 8.86%; this is required ownership isolation rather than removable trusted-carrier
work. No other removable family met the 5% threshold, so optimization stopped.

The production-path diagnostic benchmark used one excluded warm-up and seven measured repetitions
of 500 successful TCP connections with fresh state. Baseline measured 210.559 connections/second,
pre-campaign current measured 603.961, and final current measured 780.500. Every run produced exact
identity digest `bbaf0e1cfd2e0893ebd7215b135b9fdd0bee875fb0a6afeb3fa89885a3095f77`.

The retained completed-fixture timings were:

- baseline: 540.06, 537.24, and 550.68 seconds; median 540.06 seconds;
- current: 238.49, 264.27, and 247.61 seconds; median 247.61 seconds.

The second current run was below the 268.62-second two-times threshold but differed from the first
by 10.81%, so the planned third current and baseline measurements were run. Three-run medians give
`540.06 / 247.61 = 2.1811`, or 54.15% less runtime than baseline. The campaign's focused-path gain
did not produce a measurable whole-run improvement over the earlier 238.49-second current point on
this noisy host; the three-current median is 3.82% slower than that single point. The required
baseline-relative two-times gate nevertheless passes with median evidence.

`compare_generated_outputs` reported no missing, extra, byte, or normalized differences for the
final measured baseline/current pair. The complete `data/**` trees are byte-identical, as are the
included root JSON artifacts. The fixture digest remained unchanged.

Every optimization commit passed its focused tests, diagnostic benchmark, routine pytest, Ruff
check, and Ruff format check before commit. Routine checkpoints ended at 7,964 passed and 5 skipped;
the affected slow network-identity suite passed all 82 cases. The final combined slow gate passed
1,761 tests with 8,198 deselected in 406.85 seconds, including the formerly missing healthcare pack
test, so no environmental exception was needed. No soak tests were run.

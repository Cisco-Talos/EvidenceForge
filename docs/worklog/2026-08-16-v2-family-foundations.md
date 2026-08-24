# V2 Family-Level Realism Foundations

## Objective

Implement the recurring family-level priorities from V2 blind loops 11-30 on
`codex/v2-family-foundations`, branched from `dev` at `84da614e`.

The initiative owns seven related families:

1. canonical execution/effect planning;
2. append-only lifecycle state;
3. one timing and source-clock runtime;
4. compiled deployment and content identity;
5. explicit collection policy;
6. stateful application channels; and
7. duration-stable indexed storage shared by all of the above.

No feature work lands directly on `dev`. The branch uses milestone-scoped
conventional commits and targets one draft PR back to `dev`. Feature branches
do not change the package version.

## Cross-family contract

### Owning abstractions

- `generation/indexes.py` owns scalable primary, equality, temporal, lease, and
  expiry lookup primitives.
- action plans own required and optional operational consequences;
- the lifecycle registry owns canonical process, session, service, transport,
  hold, and closure state;
- the timing runtime owns deterministic distributions and source clocks;
- the world/deployment compiler owns installed software, services, tasks, and
  user application assignment;
- the content registry owns release, installation, profile, artifact, and file
  content identity;
- source deployment and projection envelopes own collection capabilities and
  observation admission; and
- protocol managers own application-channel semantics on top of a shared
  channel registry.

### Invariants

- Shared truth is computed once and rendered source-natively.
- A required effect is realized, linked to an authored sibling, or fails before
  partial state allocation.
- Published identity is immutable; token identity and lifecycle membership are
  separate.
- Canonical state is temporally queryable and append-only through closure.
- Canonical timestamps never absorb collection delay.
- Deployment and content identity do not depend on incidental host/user paths.
- Application children reserve immutable transport capacity and never rewrite
  an already dispatched parent.
- Collection policy can hide evidence but never invent or mutate canonical
  behavior.
- Exact lookup stays amortized `O(1)`, temporal lookup stays `O(log n + k)`, and
  retained state plateaus at an explicit horizon rather than scenario duration.

### Historical scale contract (retired)

New registries must use compact canonical records, exact composite indexes,
bounded temporal segments, explicit leases, and expiry queues. Hot paths may
not scan or sort complete registries, materialize unbounded result lists,
rebuild reverse indexes, or retain per-occurrence history after reconciliation.

The retired foundation harness covered 10 through 2,000,000 entries, skewed and uniform groups,
monotonic and out-of-order writes, expiry churn, 24-hour/7-day/30-day runs, and
worker-count determinism. Its former gates were:

- 1M exact lookup p95 no more than 2x the warmed 1K result;
- 1M temporal lookup p95 no more than 3x after result-count normalization;
- backing heap/segment state below 2x live entries after a watermark;
- 30-day late-hour cost no more than 1.25x the 24-hour result;
- 7-day and 30-day plateau memory within 10%; and
- byte-identical output and registry digests across worker counts and
  `PYTHONHASHSEED`.

These ranges and thresholds are preserved only to explain historical measurements. They are not
current or future acceptance gates, and the retired cross-product must not be rerun or recreated as
a substitute matrix.

## Compatibility contract

- Existing Scenario 2.0 files, CLI behavior, native formats, and `complete`
  observation profile remain valid.
- Legacy timing, proxy, observation, application, and installed-software
  shapes normalize at the configuration boundary and emit actionable
  deprecation warnings. Removal is documented only as occurring in a future
  release.
- New skill workflows and examples use the new models. Legacy syntax appears
  only in migration and warning-remediation references.
- Scenario authoring gains additive exact-host deployment overrides and exact
  source-instance observation overrides.

## Historical delivery sequence

The initiative originally followed this sequence. The scale-measurement and scale-gate steps record
completed historical work and create no current or future matrix requirement.

1. Captured clean baseline tests, generation/evaluation, blind probes, and state
   scale measurements.
2. Landed shared compact/indexed/temporal/lease primitives and historical scale gates.
3. Land execution/effect and lifecycle contracts in shadow mode, then migrate
   high-risk vertical slices.
4. Land the shared timing runtime and projection boundary.
5. Compile deployment/population and content identity.
6. Compile collection policy and source-instance envelopes.
7. Land the shared application-channel registry and migrate HTTP, proxy, SMB,
   SSH, and RDP.
8. Enforce contracts, remove adapters, update docs/skills, and complete final
   deterministic, performance, evaluation, and blind gates.

## Baseline

- Branch point: `84da614e` (`dev` == `origin/dev`).
- Worktree at branch creation: clean.
- `uv run eforge validate-config`: 93 files, 0 errors, 0 warnings, 0 info.
- `uv run pytest --no-cov`: 6,074 passed, 22 skipped in 592.82 seconds.
- `uv run ruff check .` and the clean-snapshot format check: passed.
- Existing Batch-7b duration-state probe: passed in 3.45 seconds. Retained IDs
  plateaued at 3,072 for both seven and 30 days; the 30-day/24-hour late-hour
  ratio was 1.0610, lookup ratio 1.0117, allocator-memory ratio 1.0, and all
  92,160 allocations/probes closed. Report SHA-256:
  `7f367dfc61b4e1798d74c6cbd67719e82ce4449382a9a41d9a766b5d082e82f5`.
- Clean-HEAD iteration scenario baseline: two successful generations in 29.00
  and 29.48 seconds. Both evaluations contained 86,097 records, passed
  acceptance, and scored 97.20159780813069 overall (parseability 99.9988,
  plausibility 96.9741, causality 95.5953, timing 95.2979).
- Deterministic baseline: both runs had identical data-tree SHA-256
  `14e8a8407f0320626686dbc79f5ff931fe549fb38c5470e28b83290b194ed8f4` and
  identical artifacts, ground truth, and resolved scenario. Only the generation
  manifest creation timestamp differed, as expected.
- Blind-assessment baseline: the immediately preceding Loop 30 deliberation
  scored Threat Hunter 70, Detection 68, Network 60, and Host/EDR 80
  synthetic-confidence (mean 69.5, likely synthetic). Its consensus families
  were scanner FLOW-before-CREATE ordering, post-logout RDP dependents,
  cross-build binary identity, RDP bootstrap/session identity, and proxy-DNS
  exact-millisecond timing. See
  `scenarios/iteration-test/blind-test/v2-loop-30/deliberation.md`.

## Milestone 1 handoff

The first implementation slice is the shared indexed-registry substrate. It
must be independently useful, fully tested, and behavior-preserving before any
new lifecycle or channel registry depends on it.

The retired Apple ARM64 foundation probes used a fresh child process per scale point and covered
sparse/uniform and single-owner-skewed groups, monotonic and 10%-out-of-order writes, plus
replacement/expiry/compaction churn. Their lookup gates measured each operation independently after
three symmetric untimed passes at both sizes. First-touch random results and their cross-size ratios
remain historical diagnostic-only cache-residency evidence; no fixed delay was added.

- Uniform 1K/1M refresh: 0.125/0.167 microseconds warmed exact p95 (1.336x) and
  0.625/0.792 microseconds warmed temporal p95 (1.2672x). The 1M child loaded in
  2.785 seconds at 427,180,032 bytes incremental RSS. First-touch cold ratios
  were 30.0x exact and 7.1344x temporal and are not release gates.
- Single-owner-skewed, 10%-out-of-order 1K/1M refresh: 0.125/0.167 microseconds
  warmed exact p95 (1.336x) and 1.25/1.75 microseconds warmed temporal p95
  (1.4x). The 1M child loaded in 4.141 seconds at 333,971,456 bytes incremental
  RSS. First-touch cold ratios were 30.664x exact and 4.2390x temporal.
- The prior uniform 2M structural point loaded in 4.918 seconds at 809,648,128
  bytes incremental peak RSS. The prior skewed churn point completed 500K
  replacements in 1.734 seconds, temporal compaction in 0.672 seconds, and
  100K current expirations in 0.090 seconds; post-watermark heap and temporal
  amplification were 1.0. These historical points are not current-revision
  evidence. The exhaustive foundation scale matrix that once would have rerun
  them is permanently retired; the official slow release suite and focused
  owner regressions are the current and future acceptance path.

At that historical checkpoint, the corrected independently warmed exact and candidate-normalized
temporal relative gates passed for both uniform and skewed layouts, along with the absolute
reference-host latency, 1M memory/load, and bounded-block gates. Raw
reports are `/tmp/registry-scale-warmed-uniform-v2.json` and
`/tmp/registry-scale-warmed-skewed-v2.json`; they remain historical diagnostics,
not final PR evidence. Final evidence comes from the official release gates and
the bounded real-generation/evaluation runs described below.

## Foundation implementation and independent review

The branch now contains behavior-preserving or shadow foundations for:

- immutable execution-effect graphs with a first nmap cardinality-reconciled
  vertical slice;
- compact lifecycle identity/transition/hold/closure state;
- one engine-owned timing runtime, typed microsecond distributions, source
  clocks, bounded deterministic audit metrics, and proxy-origin DNS timing;
- deployment/content identity, host deployments, user/application
  intersections, and bounded local-artifact retention;
- immutable source collection policy/deployment and indexed network-sensor
  visibility;
- protocol-neutral application channels plus an isolated HTTP manager; and
- additive exact-host deployment and exact-source observation overrides.

An independent adversarial review was run before the first commit. It found and
triggered fixes for transactional channel expiry, operation-ID reuse,
lifecycle containment/history scans/watermark fencing, artifact lease-admission
atomicity, host architecture/content-descriptor validation, quadratic
deployment compilation, cardinality reconciliation outside scanners,
cache/worker-dependent timing audit counts, stale structural collection bits,
and broad network-sensor scans. The first milestone will not be committed until
those fixes and their combined tests are coherent.

## Collection deployment production integration

Generation now compiles one immutable collection deployment after concrete
emitters and network visibility are known and injects it into the dispatcher
before publication. Dispatch uses explicit exact-target, deployment/capability/
window, topology, coherent-loss, source-timing, and render stages. Sensor fan-out
is exact per source ordinal before missingness, and eCAR source/destination FLOW
roles are independently admitted. Emitter calls carry a frozen projection
envelope and never query the deployment.

Focused gates cover stage ordering, one-sided real eCAR output, full-run
complete-profile byte parity across Windows, Zeek, eCAR, and ASA, divergent
two-sensor policy/timing, required versus optional capabilities, exact lookup
candidate bounds, no broad deployment-bucket scans, one/four-reader
determinism, hash-seed-stable compilation, and manifest digest binding. Exact
source timing plans are snapshotted before emitter handoff while retaining the
legacy deterministic planning order, and exact sensor delays shift only that
sensor's frozen observation interval.

Final focused results are 210/210 collection/network/dispatcher tests, 581/581
emitter tests, 101/101 engine/override/timing/lifecycle/deployment tests,
449/449 evaluation tests, and 8/8 deterministic-generation integration tests.
The standalone collection scale-probe test passes, and the 10/1,000-source
smoke run retained one-candidate exact lookup with warmed exact p95 below one
microsecond at both sizes. Repository Ruff check and collection-owned formatting
pass. Repository-wide format and whitespace checks passed at the collection
checkpoint; a subsequent concurrent deployment-registry edit introduced one
unused import, which was handed back to that file's owner before integration.

## Installed application content migration

The first catalog-application cohort now compiles through the immutable packed
deployment registry. Slack 4.38.125, Zoom 6.0.11.39959, and Postman 11.2.14 own
typed product/version/build/architecture/scope/variant/prevalence metadata in
the application catalog. The production compiler builds shared executable and
application-module content identities, user profiles, scoped installations,
application profiles, host deployments, and the exact installed-application ×
persona assignment intersection. Existing `compile_native_deployment_registry`
callers remain compatible through the full compiler wrapper.

Application content is shared across host/user/path placement and separated by
version, build, and architecture. Exact host, per-user, and module replacements
win over stable prevalence; platform/role/persona incompatibility creates no
installation, assignment, module handle, or path binding. Dispatcher path
attachment lets Sysmon render the migrated hashes and VERSIONINFO without the
legacy emitter catalog lookup.

Merged `eforge validate-config --json` checked 93 files with zero issues. The
focused application suite passed 8/8, the existing native deployment suite
passed 15/15, and the combined deployment/application/config/activity/Sysmon
regression selection passed 740/740. The rendered hard probe covers all three
applications and the deterministic probe covers host/user ordering plus two
`PYTHONHASHSEED` values.

## Local-artifact packed retention RSS

The bounded mutable local-artifact registry now retains no per-entry identity
object graph, composite index key, Python-dictionary history bucket, all-entry
route, or Python-big-integer deadline row. Canonical artifact/version digests,
platforms, payload locators, primary slots, equality memberships, deadlines,
and heap rows live in capacity-sized primitive columns allocated before publish
traffic begins. Exact history groups keep singleton handles inline and promote
only repeated values into insertion-ordered intrusive links. Application-profile
and content fingerprints are always verified against the exact compressed
payload, including forced-collision coverage. Common metadata uses fixed
per-shard inline arenas; rare large descriptors use bounded live overflow rows.
Exact lookup derives the owner shard and consults a sparse spill route only when
capacity balancing placed a version off-home.

This eliminates both logical growth and the allocator-arena pinning that kept
RSS high after the first primitive-column attempt. Fresh-process results are:

- 100,000 uniform: 26,722,304 bytes RSS (267.22 B/live), 25,574,605 estimated
  index bytes (255.75 B/live), 2.814 s load, 6.33 us warmed exact p95, and
  9.17 us warmed secondary p95.
- 100,000 skewed: 30,375,936 bytes RSS (303.76 B/live), 28,029,363 estimated
  index bytes (280.29 B/live), 3.535 s load, 6.96 us warmed exact p95, and
  9.42 us warmed secondary p95.
- 250,000 uniform: 61,980,672 bytes RSS (247.92 B/live), 61,215,707 estimated
  index bytes (244.86 B/live), 6.960 s load, 6.33 us warmed exact p95, and
  7.96 us warmed secondary p95.

The expanded deployment-registry suite passed 28/28, including capacity/lease
atomicity, watermark fences, mutation-version cursors, concurrent disjoint
owner lanes, exact forced digest collisions, large overflow payloads, and
handle reuse. At that checkpoint a mixed one-million-record rerun was still planned through the
shared foundation workload. That planned gate is now permanently retired and was not carried
forward.

Post-layout integration remained green: 266/266 deployment, application,
source-compiler, dispatcher, and eCAR tests; 694/694 activity, Sysmon, and
configuration tests; and merged configuration validation across 93 files with
zero issues. Repository Ruff lint passes; deployment-owned files are formatted,
while the root integration owner is coordinating four concurrently edited
timing/RDP/dispatcher/eCAR format-only differences before the combined gate.

## Direct HTTP/HTTPS application-channel migration

Direct HTTP and HTTPS persistence now use `HttpApplicationChannelManager`
instead of the generator-local tuple cache. The production planner constructs
an exact affinity from source/destination/port, normalized Host and User-Agent,
and an explicit cleartext/TLS dimension, then consumes the manager's frozen source port,
Zeek UID, connection identity, transaction depth, and canonical request time.
Reused transactions are application-only children, so they do not duplicate
conn, eCAR/WFP FLOW, IDS, or authentication evidence; canonical StateManager
byte totals still accumulate once per child. A reused HTTPS request also suppresses a
second handshake, certificate chain, and TLS payload extension, while retaining its
canonical HTTP/file child. The immutable TCP/TLS parent remains the sole StateManager
connection-interval owner. Encrypted children do not leak plaintext Zeek `http.log` rows without
an explicit decryption source. Explicit-proxy client and origin legs declare proxy ownership at the
canonical planner boundary, so they cannot also enter the direct-HTTP manager. The shared registry
therefore retains one proxy-owned channel while the direct-HTTP sidecar remains empty across HTTPS
subresource reuse.

The adapter now accepts an optional full child-span fence. A reuse ending
exactly at the immutable parent close is admitted; a one-microsecond overflow
atomically retires the exact sidecar without reserving operation or byte budget,
and the planner opens a fresh physical parent. The planner supplies a
conservative bound covering authored duration, source-native HTTP timing, and
request/response file-analysis duration floors. Accepted children preserve
their frozen start so later endpoint attribution cannot move them outside the
parent interval. Canonical engine watermarks advance both proxy and direct-HTTP
managers, and empty route partitions are reclaimed with bounded work.

Focused HTTP manager/production integration gates pass 40/40, including exact
affinity misses, one-parent/N-child reuse, observation loss, directional budget
and StateManager accounting, child-span boundary and overflow, application
window fencing, exact one-candidate lookup, 30-day plateau, output-filter
independence, one-versus-eight-worker identity, and two `PYTHONHASHSEED` values.
The direct browser contract also proves that a page and same-host HTTPS asset share one UID,
connection, source port, and increasing transaction depths while the child remains inside the
parent close. A real `GenerationEngine` test passes the same page through compiled collection and
source projection: Zeek sees one conn and one TLS occurrence, eCAR/WFP/Sysmon each receive one
physical transport, and the encrypted requests remain canonical children. The wider
HTTP/browser/network/Zeek/eCAR selection passed 774 cases; its two
concurrent timing-checkpoint failures were rerun after the timing owner restored
the eCAR FLOW anchor and now pass. Explicit-proxy isolation passed 148 cases
with one expected skip. The final focused checkpoint additionally passes the exact proxy-origin
ownership regression and 69/69 HTTP/proxy manager tests. All eight deterministic-generation tests
pass, and targeted Ruff/format/whitespace checks are clean.

## Production RDP reconnect selection

Repeated optional baseline RDP activity now queries the exact WorldPlanner/manager identity before
allocating a new target session. Activity inside the current immutable transport reuses the logical
session. Activity after that transport closes but before the reconnect and hard deadlines calls the
existing public `generate_rdp_reconnect` API with the next generation ordinal. The target LogonID,
session ID, logical object, principal, and source/target affinity remain frozen while the new
channel, transport ID, tuple, and Zeek UID are distinct. A live source-side `mstsc.exe` is reused;
if that process has ended, the existing source-process factory creates a non-overlapping
replacement. A genuinely different source affinity falls through to normal new-session planning.
Manager/StateManager identity drift fails closed, while an expired optional deadline uses the
typed `RdpSessionAdmissionError` already handled by baseline omission.

The closure proof initializes a real `GenerationEngine`, invokes the actual baseline system-traffic
producer in two later hours for one forced stable source/principal/target affinity, and spies on the
public reconnect, process, logon, and logoff APIs. It observes exactly one Type 10 target logon,
one non-duplicated `mstsc.exe`, one reconnect call, generation ordinal 0 to 1, distinct canonical
transport IDs and UIDs, stable logical identity, and exactly one final logoff after the shared
application watermark reaches the logical hard deadline. The focused real-engine baseline node and
the direct manager/browser reachability nodes pass; the combined HTTP/browser/RDP/world cohort
passed 92/92 before the two added audit-level real-engine proofs. At the final focused checkpoint,
the complete RDP production-integration file passes 6/6 against the coherent identity renderer.

Frozen production-reachability checkpoint SHA-256 values:

- `generation/http_channels.py`:
  `5c35d8b254988529e472c2d7f5e19737030a76bb9894e6a53319fe15e8323af4`;
- `generation/actions/network_connection.py`:
  `96c59cb2a20627e7803df00708f25018c0a2aff1e0684febd9b739a6889de2b1`;
- `generation/actions/network_transaction_planner.py`:
  `f10a703192ff2b1cc62c6d2c003b8a0a7d7476f1f00dab73c8dee6377aa8ae01`;
- `generation/actions/proxy_transaction.py`:
  `0469248e7d0ef3bf320be9dfec375c7cc74e9787803c4b8526f1483a7eeaf5aa`;
- shared `generation/activity/generator.py`:
  `d5ba5a8ee3bd0e54bf6ee58bb4d774cc4da0f6c34a02c6ad933a445c7c2ccc96`;
- `generation/world_model.py`:
  `68988daa8b43630d6d5a5131c2d9e6ba3e80d8dd1f2eea17b658de5f95e04018`;
- `test_http_channel_integration.py`:
  `9fc3e07c8b124ddb6ea2747cbefdf4593cc2bba6e9c082669267a2b1fd4a1487`;
- `test_browser_session_contract.py`:
  `377a5f04ee99ff73382647ecd5662bd414dbe184e4ab863cf70900a4a8a9e259`;
- `test_rdp_production_integration.py`:
  `a769d07b2a7c9b1b9eff760c8fce116e18d529bb23c6451dc0bd99d066ede4ac`;
- shared `test_explicit_proxy.py`:
  `9ec7c67adc90eff316c27055e93f25b9fc845bba288b18bf2f808cc5c8708aaa`.

## Canonical physical transport lifecycle root (in progress)

A final production-entry audit found that only SSH and RDP published canonical network transports
into `LifecycleRegistry`; generic connections, scanner probes, proxy legs, and Windows remote-admin
transports bypassed that authority. The network request now carries an internal typed publication
mode: `network` is the default physical-transport commit, while only SSH/RDP select
`deferred_session` so their higher bundle can add the exact session binding without duplicating the
base row. After the immutable `NetworkTransactionPlan` is finalized, the occurrence-local capture
freezes the effective disposition; an `application_layer_only` child always resolves to
`application_child` and cannot create another base transport. Identity capture alone never implies
deferral, so both explicit-proxy physical legs remain `network`.

Focused routing evidence passes: 37/37 network/HTTP contract tests prove physical-parent versus
application-child disposition; the exact explicit-proxy reuse node captures two physical `network`
legs and no deferred row; the RDP initial/reconnect production test captures two
`deferred_session` generations while retaining exactly two base transports and two closed session
bindings; and the exact SSH bundle lifecycle node captures one `deferred_session` transport. The
RDP production integration file passes 6/6. A stale activity-test interception of
`dispatcher.dispatch` was migrated to the required one-shot `publish_prepared` seam without
reapplying state.

Generic publication remains deliberately unwired until the lifecycle and dispatcher owners expose
the reservation-owning no-fail receipt. The agreed boundary is: finalize the immutable transaction;
run allocation-free `prepare_builder` and lifecycle transport prepare/receipt validation; then
authenticate one typed external-transport commit/apply boundary before ledger, audit, and source
projection. A fallible registry call after rendering is forbidden, as is committing transport state
before a fallible canonical-state apply. Final acceptance still requires nmap, ICMP, collection-drop,
HTTP-reuse, proxy, Windows remote-admin, SSH/RDP no-duplicate, and injected-failure proofs.

The application-channel half of that composite boundary is now frozen. The shared registry can
prepare a fresh channel plus its first completed operation, or one completed child on an existing
channel, without publishing channel state or consuming operation budget. Entering
`prepared_admission(token)` revalidates and claims the exact registry-bound token without retaining
route or owner locks; its one-shot `commit()` is the final no-fail channel step, while an uncommitted
exit or explicit cancellation releases every reserved ID. Claimed tokens fence watermarks past
their linearization time. Ordinary mutations use short exact-key and affinity claims, so a prepared
token cannot race its expected snapshot while disjoint owners remain concurrent. Six new contracts
cover exact cancel/abort census neutrality, one-shot commit, deferred budget accounting,
watermark fencing, and foreign/stale tokens. The common application, HTTP, and proxy cohort passes
92/92; the frozen application registry hash is
`ff8391af1c40c1d19293d5543f581dcaeeb5736c93cfdb5541175b87fd125c9e`.

While the composite StateManager/lifecycle receipt is pending, an eight-node coordinator-capture
acceptance slice passes without adding unsafe publication: single-target nmap and both Windows
remote-admin legs freeze ordinary physical plans; a silent ICMP attempt is still captured;
collection missingness drops rendered evidence only after the physical plan exists; HTTPS reuse
freezes one `network` parent and one `application_child`; explicit proxy freezes two `network`
legs and no direct-HTTP sidecar row; and SSH/RDP freeze only `deferred_session` generations. These
are routing proofs, not a claim that generic lifecycle publication is complete; injected composite
precommit rejection remains blocked on the pending authenticated StateManager/lifecycle API.

### Generator-local network transaction preparation freeze

The isolated generator-local half of the physical-transport composite is now adversarially frozen,
without wiring the planner or callers. `NetworkTransactionRuntime.begin(...)` returns one
`NetworkTransactionPreparation` for a single physical transport or application child. The
preparation owns an isolated State planning cursor and point-COW overlay behind the runtime,
exposes only the revocable RNG, one physical-identity reservation, exact point read/set/delete,
and a resolver-only `NetworkCryptographicMaterialPreparation`, then seals to one
`PreparedNetworkTransactionRoot`. The public root contains the exact finalized transaction,
State connection-composite plan, authenticated `NetworkTransactionPreparationToken`, and frozen
`NetworkConnectionCommitResult`. `claimed_preparation(token)` yields the only public outer commit;
`commit_no_fail()` returns a signed `NetworkTransactionPreparationReceipt`. Token and receipt
authenticators are total under malformed/deep caller tamper, and cancellation is exact and
RNG-neutral.

Runtime point storage uses exact typed families, point generations, reservations, deletion
tombstones, indexed preparation fences, indexed reservation deadlines, and an exact removable
expiry heap. Watermark pages never scan open preparations or reserved points; non-expiring updates
create no heap backing; finite replacement retains one deadline; future deletion retention anchors
to the trusted publication time; and final-window expiry plus its tombstone drains in bounded pages
at the reachable terminal cutoff. The O(1) current-state digest is commutative across disjoint
commit order and invariant to watermark page size. Caller-defined dataclasses, enums, equality-
aliasing bool/float keys, custom timezones, unstable copy/repr behavior, and result-model spoofing
are rejected before authority mutation.

`CryptographicMaterialRegistry.begin_tls_preparation()` now supplies the nested TLS point-COW
authority used by the runtime. Its public token/claim/cancel/receipt APIs authenticate exact public
key, authority, and certificate patches. Seal creates one registry-owned deep snapshot, rejects
duplicate points, validates every nested field's exact inert type, and proves each deterministic
value was derived for its exact semantic key. Cached and newly published authority/certificate
objects are copy-isolated. Duplicate/tampered claims cannot revoke the owning claim, and malformed
nested token fields release the registry-owned capability without running caller `repr` hooks.

The final adversarial review found no P0/P1 blocker. One private-reflection-only P2 remains
documented: test code with direct access to a caller object's private runtime owner could traverse
private `_claimed_composites` and invoke the nested TLS commit out of order. A static production
census proves `NetworkTransactionRuntime`, its preparation/claim types, `claimed_preparation`, and
the private capability maps have zero references outside `network_runtime.py`; supported public
and production paths cannot reach that traversal. Arbitrary Python private reflection is therefore
outside this freeze boundary and must not be confused with a supported token/claim capability.

Frozen SHA-256 values:

- `generation/network_runtime.py`:
  `b13d03cd364ad6d154da4ed441a81c3e8a8dc792d0d8318e863ee6121742dbce`;
- `generation/cryptographic_material.py`:
  `1770fc0583bf9428dd5dc8c06ca068ae44dd26833a0d41504f2c8c0df8956a6f`;
- `test_network_runtime.py`:
  `60c6082d52ec718a8170dd5f3abccf03b9bdb18a1f8040be926735f81dbf2f0a`;
- `test_cryptographic_material_contract.py`:
  `4e3f2eaea2875a58f4751dffb193fad4488f9bcd1db84da78f3826d1f9a36cd9`.

Final validation: 53/53 focused runtime/TLS contract tests; 33/33 TLS/cryptographic/OCSP
contracts; 29/29 frozen State connection-composite and lifecycle-authority contracts; and 104/104
network-realism, Zeek-file, and IDS attachment contracts. Scoped Ruff lint/format and whitespace
checks are clean. Planner, dispatcher, lifecycle, application/HTTP/proxy managers, and callers
remain deliberately untouched until the authority owner releases the authenticated outer
coordinator entrypoint.

## Registry-aware resource forecast

Resource-forecast model v5 retains historical foundation measurements through typed,
data-replaceable calibration rather than one opaque registry allowance. Workload estimation emits
five deterministic `RegistryWorkloadInput` rows in a stable order: lifecycle, application
channels, local artifacts, collection deployment, and deployment/content. Each row carries total
scenario time, base/effect counts, rendered-channel observations, effect/channel fanout, static
bindings, and exact scenario-override contribution. Deployment inputs mirror platform,
architecture, system-type, persona, stable fleet prevalence, scope, and exact host/user replacement
gates without materializing the registry.

`RegistryResourceProjection` reports created/live/retained/leased/stale/expired/backing/high-water
counts, structural/expected/upper memory, plateau horizon and reached time, lookup candidate bound,
heap/segment amplification, compaction budget, and projected load/mutation/lookup/expiry costs.
Mutable counts derive from scenario cadence and configured live/retention horizons, so 7-day and
30-day hot-state memory matches after plateau while lifetime expiry work continues to increase.
Static collection and deployment registries plateau at compile time.

Memory/load/lookup calibration uses the stable isolated 250K points: lifecycle 193,462,272 RSS and
54,440,724 structural bytes; channels 124,125,184 and 33,698,048; local artifacts 61,980,672 and
61,215,707; collection deployment 90,685,440 and 30,906,060. The mixed 1M point is 440,172,544 RSS,
180,260,539 structural bytes, and 22.9891 seconds load. Conservative mutable operation maxima came
from the prior deterministic smoke probes and are retained under the historical profile
`historical_smoke_calibration`: lifecycle mutation/expiry 42.52/14.70 us, channels 104.85/65.15 us,
and artifacts 15.81/6.71 us. Retiring the exhaustive foundation scale matrix means these historical
measurements are not implicitly promoted by the current completion work. Deployment/content
remains separately provisional under
`historical_deployment_path_packed_calibration`: 1M packed bindings loaded in 9.551 seconds at
358.58 RSS and 168.99 structural bytes/binding with 1.709 us warmed exact p95; it is not represented
as part of
the four-registry mixed result.

The registry-only total explicitly excludes interpreter/generator base, emitter queues/format
state, rendered and attachment payload buffers, external sort, and storage catalog state. Peak
memory is `max(legacy calibrated peak, registry + explicit exclusions)`, never their sum, which
keeps existing budgets compatible without double counting. Pre-v5 calibration objects may omit
the registry section and retain the exact prior behavior with `registry_report=None`; incomplete
v5 registry maps fail validation and unavailable measurements fail closed.

Verification at this checkpoint: 36/36 timing-runtime wiring, resource-forecast, workload, and
calibration-harness tests; 74/74 full unit CLI/JSON runtime-contract tests; deterministic
two-`PYTHONHASHSEED` report equality;
and focused Ruff/format checks. Coverage includes small/7-day/30-day plateau forecasts, exact
deployment overrides, render-channel lookup fanout without canonical-row duplication, the full
1,270-probe nmap effect expansion, measured-cost replacement, and explicit no-double-count logic.

## Linux shell execution/effect migration

`LinuxShellCommandActionBundle` now parses each bounded command once into immutable,
operator-aware cohorts and preflights an allocation-free `ExecutionEffectPlan` before child PID
allocation. Every emitted child owns a required PROCESS start and an actor-linked required close;
the execution adapter freezes exact start/close times, concurrency group, lifecycle identity, and
node identity before realization, then reconciles exact canonical occurrence counts into the
bounded intent audit. History-only and builtin-only commands use an explicit empty effect plan.
Nested `ProcessExecutionActionBundle` plans remain the sole owner of command-specific scanner
effects, and the shell adapter suppresses the former generic file-effect lottery so it does not
invent or duplicate FILE/NETWORK/TRANSFER consequences.

True pipes share one concurrent cohort. `&&`, `||`, `;`, and `&` create ordered cohorts; quoted
pipes remain argv. A background operator releases shell serialization for every peer in its pipe
job but never exempts lifecycle closure. Bounded children use a sampled close, while unbounded
detached children close at the exact session/transport/scenario fence when one exists. All newly
introduced gaps and lifetimes use the engine-owned `TimingSampler`; an equal legacy timing window
uses `ConstantDistribution` rather than constructing invalid triangular support. Hot planning uses
constant-time running-count access and retains only the bounded per-command plan.

Production direct, baseline, and storyline callers share the bundle; activity-key command catalogs
resolve through the same path, and nested shell scripts remain one exact wrapper child when that is
the existing canonical adapter's emitted process. Focused rendered-lifecycle probes match every
CREATE PID to exactly one TERMINATE PID, require the exact session shell parent, cover three-stage
and background pipelines, and fence all rows before owner close. Drift and near-close probes prove
no history row or child PID is published for a rejected plan. Busy-shell, mixed-operator, quoted
pipe, fixed-window, one/four/eight-worker, and cross-`PYTHONHASHSEED` determinism are covered.

The final coherent checkpoint passed 16/16 focused Linux-shell effect-plan tests and 796/796 broad
activity, process, lifecycle, baseline, command-effect, and shell tests, with one expected skip.
Scoped Ruff lint/format and repository whitespace checks passed. A later concurrent shared-channel
checkpoint temporarily made direct `ActivityGenerator` construction reject a missing injected
HTTP registry; that constructor repair is owned by the shared application-channel integration and
does not touch this slice.

## Public configuration compatibility boundary

Supported legacy authoring now normalizes once at its typed model or cached configuration-loader
boundary. `EvidenceForgeDeprecationWarning` is a visible `FutureWarning`; every warning names the
legacy path/use, gives exact replacement guidance, and states that the shape will be removed in a
future release. Generation and emitters consume only current normalized values.

The bounded compatibility set is explicit:

- timing `clock_skew_us`/`path_delay_us` rename unchanged to
  `clock_offset_us`/`route_delay_us`, with differing old+new values rejected;
- proxy `auth_policy.mode: legacy` remains typed and semantically exact, warns once per authored
  use, and never synthesizes non-human principal probabilities;
- unversioned named observation profiles normalize to `schema_version: 2` with identical source
  policy;
- unversioned applications, missing deployment descriptors, and pre-discriminator managed
  descriptors normalize to explicit `legacy_static`/`managed` descriptors; and
- installed-software display triples normalize to stable product IDs plus explicit release build,
  neutral architecture, and machine scope while preserving rendered name/publisher/version.

Partial current/legacy installed-software descriptors, duplicate product IDs, incompatible managed
application metadata, and conflicting timing aliases fail closed. Application package inventory,
runtime overlays, and pack-generated overlays all pass through the versioned catalog root; the
package-only pack registry no longer bypasses default deployment normalization.

Repository-owned data now uses observation/application schema version 2, explicit application
deployment intent, and full installed-software descriptors. Slack 4.38.125, Zoom 6.0.11.39959,
and Postman 11.2.14 remain the managed cohort; other packaged application platforms explicitly
inherit the `legacy_static` document default. The public migration guide is
`docs/reference/config-compatibility.md`, with matching scenario, output-format, config-skill, and
activity-data references.

Verification at this checkpoint:

- 303/303 compatibility, timing, observation, application/deployment, installed-software,
  validation, and proxy-attribution unit tests;
- 207/207 CLI, config-overlay, config-skill, and pack model/adapter/lifecycle tests;
- 100/100 explicit-proxy tests at the last coherent HTTP-channel checkpoint;
- both exact `complete` observation-profile byte-equivalence tests at the last coherent channel
  checkpoint;
- `eforge validate-config`: 93 files, zero errors/warnings/info;
- public `eforge validate tests/fixtures/scenarios/minimal.yaml`: schema and cross-references valid;
  and
- a fresh package-config process loaded 67 applications, eight installed products, current sensor
  timing, and the complete profile with zero compatibility warnings.

A later 612-case combined run crossed an active packed-HTTP edit: 597 passed, while 14 HTTP tests
and the complete-profile integration node hit missing `find_one`/decoded-cache census members.
Those transient channel failures are outside this compatibility slice and were handed to the
channel/root owner; no foreign HTTP code was changed.
After the HTTP owner published the coherent shared packed-row checkpoint, both exact
complete-profile byte-equivalence nodes and the legacy-proxy semantic regression reran green
(3/3).

## Engine-owned endpoint and network timing slices

`TimingRuntime` now owns the migrated Sysmon/eCAR process lifecycle and eCAR FLOW source clocks,
plus physical-sensor clocks and source-native timing for Zeek conn, SSL, HTTP, files, X.509, OCSP,
and PE projections. Canonical occurrence timestamps remain immutable; collection policy decides
visibility only, the dispatcher freezes exact per-source projection time before rendering, and the
migrated emitters only format the frozen result. TLS/HTTP/file-transfer duration paths use typed,
right-skew microsecond distributions with lifecycle containment rather than uniform/fixed floors.
The temporal constraint graph also replaces exact-bound clamping with deterministic sampled
interior slack and raises an audited contract error for an impossible window.

Compiled network dispatch now passes exact admitted sensor instances directly into the observation
planner. One production SMB regression exposed a second ownership bug: endpoint WFP companions
reused the canonical transport plan but overwrote the transport's frozen sensor-observation cache
with an empty projection. Only canonical sensor-transport occurrences now publish that cache, so
application children reuse the exact parent sensor UID, clock, interval, and admission. The full
semantic SMB read integration probe confirms conn/SMB UID and timing correlation.

Verification at this checkpoint: 236/236 dispatcher/source-timing/runtime/constraint/network tests,
154/154 Zeek/network protocol tests, 217/217 eCAR/Sysmon tests, 442/442 activity tests, all eight
deterministic-generation integration tests plus the production SMB correlation node, and whole-tree
Ruff lint/format/whitespace gates. Statistical cohorts cover right skew, non-flat bins, non-ms
texture, no bound/ceiling atoms, lifecycle containment, and timing-audit saturation below 0.5%; the
determinism matrix covers insertion order, worker count, clock-cache size, and two Python hash
seeds. Remaining migration inventory is explicit: Zeek DNS/DHCP/SMTP, unmigrated Windows/eCAR/
Sysmon source relationships, and canonical DNS/Kerberos/NTP/failed-connection/teardown timing still
retain compatibility planners or direct scoped RNG and are follow-up slices, not part of this
completion claim.

## Engine-owned auxiliary protocol timing follow-up

The same engine `TimingRuntime` now owns canonical DNS, Kerberos, NTP, failed-transport, foreground
process-teardown, and firewall-teardown timing, plus frozen physical-sensor projections for Zeek
DNS, DHCP, SMTP, and NTP. DNS RTTs use internal/public typed mixtures and a separately sampled
transport-close tail; Kerberos UDP/TCP exchanges use distinct typed response distributions; failed
states use state-specific partial-lifecycle distributions; and NTP request, server processing,
response, close, reference-age, and client/server source clocks are planned together. DHCP lease
duration and failed TLS handshake duration also use the injected runtime. Canonical occurrence and
transport times remain immutable, every admitted source row is frozen before rendering, and
multi-row admission uses the DNS response or DHCP close rather than only the first rendered row.

The Zeek DNS/DHCP/SMTP/NTP emitters no longer construct module-global `SourceTimingPlanner`
instances, plan timestamps, or repair duration floors. They render only frozen source time and
duration. Their direct low-level compatibility adapters remain stateless and day-local; production
paths cannot call them, as rendered probes replace those adapters with raising sentinels. The old
`_dns_rtt` helper remains only for two direct compatibility tests and has no production caller; a
static AST inventory enforces that baseline, storyline, and generator DNS/Kerberos/NTP connection
calls defer duration to the runtime. Packet-loss RNG remains intentionally local observation
texture and the policy test requires that draw to stay present.

Statistical cohorts cover DNS RTT and close slack, Kerberos UDP, NTP RTT, failed transports,
auxiliary sensor delays, and firewall teardown. They require open support, right skew, non-flat
bins, fewer than 0.5% exact-millisecond residues, no bound or timeout atom, and timing-audit
saturation below 0.5%. Lifecycle probes keep protocol rows inside the frozen source-visible
transport interval without changing canonical timestamps. Determinism covers insertion order,
one/eight workers, clock-cache size, source-instance clocks, and multiple Python hash seeds. A
public `SourceTimingPlanner.session_closure_tail()` / `max_session_closure_tail()` API exposes the
same typed closure bounds used internally so higher-level bundles can reserve admissible headroom
without copying the former 15-second constant.

Verification at this checkpoint: 616/616 focused DNS/Kerberos/NTP/DHCP/SMTP/firewall/network and
Zeek contract tests (with one known deployment-owned hostname test intentionally deselected), plus
356/356 parser, dispatcher, timing-foundation, constraint, eCAR, and Sysmon regression tests with
two expected external-parser skips, and 586/586 baseline, storyline, adversarial-payload, bulk,
and proxy regressions with one expected skip. Scoped Ruff lint/format is clean. The repository-wide
Ruff gate currently reports only import ordering in the concurrently owned RDP export and SMB action
files, which their owners were notified about. The deterministic-generation integration gate still
stops before timing on the concurrently owned lifecycle-shadow rejection of a parent close while
children remain active. Remaining module-global timing planners are confined to the explicitly
unmigrated Windows, Sysmon, and eCAR compatibility relationships; no Zeek emitter retains one.

## Engine-owned endpoint timing completion

The remaining Windows Security, Sysmon, and eCAR source-native timestamps now freeze through the
engine-owned `TimingRuntime`. This includes Security/Sysmon/eCAR process create, dependent, and
terminate rows; login, child, and logout containment; Security service, task, account, share,
file, and authentication rows; Sysmon network, DNS, registry, file, module, and process rows; and
eCAR session, service, file, registry, module, remote-thread, SMB, and process rows. Canonical
timestamps remain immutable. Source-observation delay records visibility metadata only, exact
source-instance clocks and typed queue delays are finalized before admission, and dispatcher
window checks use the final source-visible endpoint envelope.

No production emitter under `generation/emitters/` retains a module-global `SourceTimingPlanner`.
Windows, Sysmon, and eCAR also contain no direct timing-profile sampler calls. Canonical rows only
format frozen native/envelope fields; raw direct-dictionary compatibility uses explicit stateless
adapters in `source_timing.py`, with no retained clock/planner state. A static policy test rejects
new module-global planners and direct timing sampler/planner APIs in the three migrated emitters.
Security 5140/5145 share one lifecycle queue, eCAR SMB client file/delete companions use ordered
phases, remote authentication consumes only exact admitted transports, SSH eCAR login follows the
accepted/PAM readiness floor, and machine-account logon may follow a late admitted Kerberos ticket
after the ticket socket has legitimately closed.

Statistical cohorts cover process, FLOW, generic Security events, bounded transport slack, and
near-output-window session closure. They require right skew, non-flat bins, fewer than 0.5% exact
millisecond residues, no bound or ceiling atom, and audit saturation below 0.5%. Generic endpoint
rows for all three families are invariant to insertion order, one/four workers, and zero/one/eleven
clock-cache entries; the process cohort also covers multiple Python hash seeds. Rendered probes
replace compatibility adapters with raising sentinels to prove production emitters do not replan.

Verification at this checkpoint: 323/323 endpoint/source-timing/dispatcher/eCAR/Sysmon/native
deployment tests, 123/123 raw-emitter compatibility tests, 31/31 dedicated endpoint runtime tests,
and the minimal full-generation bit-perfect integration node. The RDP owner independently confirmed
the exact baseline RDP node and 3/3 production RDP tests after the machine-ticket correction. The
Linux SMB hash-seed integration probe currently stops in unrelated StateManager Linux PID-lane
capacity exhaustion. The lifecycle owner subsequently cleared the near-window RDP close blocker;
fresh SMB reuse and high-audit reruns now reach the SMB owner's actor-retention preflight, which
rejects the selected PID because the planned transport closes at the exclusive output fence. Both
nodes stop before their endpoint timestamp assertions, and the external blockers were handed to
their owners.

The next bounded direct-RNG slices have this selected timing-capable API census (constructors,
`_get_rng`, `randint`, `uniform`, `triangular`, and `randrange`; content-only `choice`/`random`
texture is intentionally not included):

- `actions/browser_session.py`: eight sample sites total, with three direct timing sites at the
  route request offset and primary/secondary connection duration paths (lines 368 and 566-567).
- `engine/baseline.py`: 347 selected API sites across 85 functions (43 scoped `Random`
  constructors, 16 `_get_rng` acquisitions, 170 `randint`, 115 `uniform`, and three
  `triangular`). Highest-value timing families are NTP/GPO/stale-failure schedules, auth/session/
  lock/sudo cadence, scheduled-task/anacron lifecycles, process lifetimes/termination, hourly
  placement, DHCP/Kerberos/system traffic, and application/network durations.
- `engine/storyline.py`: 174 selected API sites across 35 functions (11 scoped `Random`
  constructors, six `_get_rng` acquisitions, 107 `randint`, 44 `uniform`, four `randrange`, one
  `triangular`, and one `expovariate`). Highest-value timing families are global authored-event
  jitter, per-step cadence, availability/process-source clamps, logon/process/shell prerequisites,
  DNS-tunnel/beacon schedules, scan pacing, and transport/process durations.

These counts are an ownership census rather than a claim that every counted draw is temporal; byte,
count, PID, and payload draws sharing those APIs remain observation/content texture and should stay
outside the next timing migrations.

## SMB application-channel family and production migration

SMB now uses an injected `SmbApplicationChannelManager` over the one engine-owned
`ApplicationChannelRegistry`. Exact affinity includes the client/server identity and address,
client session, authenticated principal and account scope, dialect, signing/encryption policy,
server/share policy, and access mode. Same-share operations reuse one transport, authentication,
session, and tree; cross-share operations reuse that session but open one exact new tree. Versioned
handles retain only open state and derive source-native FUIDs without storing payload bytes or a
completed-operation history. The old StateManager session/tree/handle caches and hourly scans are
removed; StateManager retains only the canonical copy-on-write file mutation overlay.

Session rows, transport plans, close tokens, tree/handle metadata, affinity routes, and expiry are
packed behind compact integer handles in 64 lazy owner shards. Watermarks remove at most 4,096 due
handles per page, close common channels through ABA-safe primitive tokens, and return a lazy closure
view decoded outside locks. A sidecar exact lookup inspects exactly one successful cache or packed-
store candidate and zero candidates for misses. Shared registry and SMB expiry are measured
separately: 100,000 SMB sidecar records expired/compacted in 1.667 seconds, 100,000 common channel
records in 1.512 seconds, and the combined 200,000-record drain normalized to 1.59 seconds per
100,000 records. Rich closure decoding is reported separately at 0.626 seconds.

One historical one-million-session run retained one million SMB sessions, one million trees, one
million handles, one million common channels, one million active operations, and one million used
operation IDs: six million physical hot records. Load was 152.217 seconds, or 25.37 seconds per
million retained records. Warmed exact p95 at one million sessions was 1.000 microsecond versus
0.667 microsecond at one thousand (1.499x); first-touch p95 was 43.958 microseconds and exact
affinity p95 was 16.875 microseconds. Incremental RSS was 1,983,741,952 bytes, or 330.624 bytes per
physical hot record (315.31 MiB normalized per million). SMB sidecar structural index cost was
122.56 bytes per logical session, or 40.85 bytes per SMB session/tree/handle record. The public
census reports common channels, active operations, used IDs, SMB sessions, trees, and handles as
separate counts so the former mixed-memory gate was not evaluated against a misleading per-session
denominator.

The SMB slice is frozen against shared application-registry hash `85fe0852269a8e44e`, events
application-model hash `0d6b6f0256373de2`, and index hash `56770354475c08a2`; SMB manager and
probe hashes are `01e194de1843529b` and `bcd4bbc6804848e3`. A historical current-hash 10/1,000-entry
smoke loaded in 0.00214/0.14662 seconds, measured warmed exact p95 at 0.708/0.625 microseconds and
first-touch p95 at 34.041/17.708 microseconds, and inspected at most three exact candidates. The
shared-registry owner retained the cache-aware common-registry million-entry artifact as historical
diagnostic context only; it is not release authority and requires no rerun.

Production SMB preflights source-process attribution against the exact LifecycleRegistry process
interval and immutable close barrier, then acquires the required hold before reuse reservation or
transport generation. Optional baseline texture strips an unavailable actor; authored activity
fails before allocation. Local SMB prefers a local Type 2/7/11 desktop over a newer Type 10 RDP
session. A single read-only hard-session hold-limit helper is also consumed by the lifecycle hold
mutation, so a persistent transport is clamped to the same deterministic fence and source-native
session closure tail. Exact future-close-barrier, exact-end, near-end, and hold-limit drift tests
cover the boundary.

StorageWorld initial file versions compile once into `DeploymentContentRegistry` before activity
generation. HTTP and SMB resolve the same canonical content handle, ID, digest set, size, and MIME;
their native FUIDs remain distinct, and neither the deployment registry nor channel manager retains
payload bytes. The rendered same-file regression and the 10,000-entry exact-lookup/no-scan probe are
green.

Focused verification at this checkpoint: 143/143 SMB manager, actor lifecycle, profile, storage,
and boundary tests; 94/94 typed boundary/process-lifetime tests; 8/8 Windows and 30/30 Linux
rendered SMB integration tests; and 179/179 broad network-observation, network-contract, Zeek file,
and eCAR specification tests. The two former Linux blockers were generator-lifecycle
singleton/foreground lease-ID collisions and are resolved at the canonical authority boundary.
Windows byte-for-byte regeneration, Linux Python-hash-seed independence, and Linux
full-versus-filtered common output each pass their production integration gate. The manager
additionally covers 30-day plateau behavior, one-of-1,000 exact affinity, byte/operation overflow
atomicity, one/four/eight-worker identity determinism, lazy closure decoding, and candidate
accounting. A boundary regression also freezes storyline jitter before hour bucketing, so an
authored exact-hour SMB event cannot open behind the strict application watermark.

## SSH child-channel family and production migration

SSH now uses an engine-owned `SshApplicationChannelManager` over the one shared
`ApplicationChannelRegistry`. The action bundle remains the single authentication, PAM/logind,
endpoint-session, and close-evidence owner; the canonical network bundle remains the TCP/22,
tuple, Zeek UID, packet/byte budget, and transport-close owner. The manager adds only the reusable
SSH application session plus shell, exec, SFTP, and SCP child identities. A completed synchronous
child is reconciled atomically into the common aggregate/used-ID marker and leaves no active or
completed-operation history row. SCP payload and receiver-file truth remain outside the manager in
the deployment/content registry.

Every retained session freezes its exact client/server affinity, target lifecycle object and
LogonID, canonical transport, source-process hold when modeled, and target sshd/session hold.
Privileged target sshd ownership remains `root`; its immutable membership is validated separately,
while the frozen application hold principal comes from the authenticated target session. Immediate
bundle closes retire the sidecar without emitting duplicate close evidence. Deferred idle/hard/
transport deadlines produce bounded immutable `SshChannelClosure` intents, which the generator
drains through the exact lifecycle-authority identity-CAS adapter outside manager locks before the
one shared application-registry watermark.

The open-only sidecar uses packed byte rows, primitive close tokens and expiry indexes, stable owner
shards, and bounded operation-route partitions. Exact lookup has a bounded 16,384-entry immutable
hot cache keyed by exact channel ID and fenced by owner shard, compact handle, and ABA generation;
successful cold and hot reads both account exactly one public lookup candidate. Warm hits never
revisit the common primary route or reconstruct the packed object graph, and retired/reused handles
cannot return stale snapshots. Common admission accepts the already-resolved owner partition and
prepares owner/affinity/packed identity keys once before locking. SSH prepares its channel digest
and packed row once before the commit lane. Canonical route partitioning uses bits independent from
the packed map's low-bit slot selection, avoiding the skew/clustering discovered by the million-key
profile.

The historical actual one-million-session run retained one million SSH rows, one million common
channel rows, and one million packed used-operation markers (three million physical hot records).
It loaded in 58.405866 seconds against the former 60-second gate; warmed exact p95 was 0.875
microseconds against the former 10-microsecond gate (24.916 microseconds cold diagnostic); and
32,000 successful queries inspected exactly 32,000 candidates. No completed-operation rows were
retained. Common, sidecar,
and total structural indexes were respectively 81.405, 70.237, and 77.682 bytes per physical live
record; incremental RSS was 1,278,509,056 bytes, or 426.17 bytes per physical record. The historical
diagnostic report was `/tmp/foundation-ssh-1m-prepared.json`, SHA-256
`afe6b21bb9d979e61b3e13cb9e6d8bf4c696248285357914f05243776b470d04`.

Focused verification at this checkpoint: 20/20 manager concurrency, containment, fence,
determinism, plateau, cache, and candidate tests; 47/47 rendered SSH/action plus scale-smoke tests
with one expected slow skip; and 14/14 SSH/SCP storyline tests. The production action mapping hard
probe covers shell, exec, SFTP, and SCP and confirms one open common session, zero active child rows,
and one used initial-operation marker. Scoped Ruff lint/format and whitespace checks are clean.

## Historical actual-million SSH application-channel diagnostic (retired)

The shared application-channel admission path now prepares its packed identity, owner key, and
owner-affinity key once before acquiring route/owner locks. Exact affinity cardinality validation
still verifies the full semantic owner and affinity values on every digest candidate. The same
transient prepared value is then consumed by packed insertion, eliminating a duplicate affinity
digest and identity encoding without retaining authored objects. A focused structural regression
requires exactly one owner digest, one affinity digest, and one identity pack for combined channel
open plus completed first operation.

The historical 1,000,000-session SSH scale run passed on one coherent implementation:

- application-channel SHA-256 `fc779f1d8684ab583ea8fa45ed6e51de7a368cc00cb12d79c99c9b3cd81d7191`;
- SSH sidecar SHA-256 `50ee350ee20b921edb11b09cf9700fd245be9211c904376cc026b70bfd62ee0a`;
- probe SHA-256 `ad19ef259a9f7db660dfe47c5f71c8a0e344417e8d72cda0cf4b58e8fe7904b3`;
- load 58.405866 seconds (gate: at most 60 seconds);
- warmed exact p95 0.875 microseconds (gate: at most 10 microseconds), with a 24.916-microsecond
  first-touch diagnostic;
- 32,000 candidates inspected for 32,000 exact queries, exactly one per successful lookup;
- zero retained completed-operation rows;
- 81.405 common, 70.237 sidecar, and 77.682 combined structural bytes per physical live record;
  and
- 1,278,509,056 bytes incremental RSS across 3,000,000 physical hot records, or 426.17 bytes per
  physical record. The three rows per logical session are one SSH row, one common channel row, and
  one bounded completed-operation ID marker, so this result is not compared as a raw 1.28 GiB
  value against the separate one-million-mixed-record 512 MiB gate.

The historical JSON was `/tmp/foundation-ssh-1m-prepared.json` (SHA-256
`afe6b21bb9d979e61b3e13cb9e6d8bf4c696248285357914f05243776b470d04`). Focused common-registry and
SSH tests passed 48/48; the prepared-work regression raised that common-only selection to 29/29.
At that checkpoint this result would have closed only the SSH sidecar gate. The remaining protocol,
mixed-core, duration/determinism, and all-registry matrix requirements are now permanently retired
and were not carried forward.

## Generator-local lifecycle authority migration

Generator lifecycle truth now routes through one engine-owned `LifecycleRegistry`. Foreground
ownership is keyed by exact host, principal, session object, and owning shell process, so sibling
shells in one session progress independently while one shell remains serialized. Foreground lease
IDs include the exact shell object and acquisition instant; singleton IDs include the canonical
session object. Repeated singleton claims compare the full immutable claim, and a claim that is
already bound or renewed reports the resource as occupied instead of allocating a duplicate or
colliding on an evolved lease value.

Deferred process closure uses bounded commit-ordered pages. Process allocation drains due closure
work first, and lifecycle watermark advancement refuses to discard an undrained page. Hourly stale
cleanup retains exact active-session infrastructure (Linux user manager, terminal, shell, Windows
Explorer/winlogon, and transport ownership) by direct session fields rather than image heuristics or
history scans. This prevents a long-running session from repeatedly rematerializing its shell at an
old timestamp and exhausting the fixed PID reorder lane. The authoritative SSH responder remains a
per-connection target-session child: it closes after PAM/source closure while still obeying the
session hard deadline; the separate boot listener is not session-owned.

Verification on the coherent checkpoint: 79/79 generator-authority, process-lifetime, and system
stability tests; 30/30 Linux SMB rendered integration tests; exact Windows SMB and IDS integration
tests; the authoritative SSH lifecycle test; and Linux SMB `PYTHONHASHSEED` determinism. A real
full-coverage CLI generation reached the last baseline hour and then stopped on an independently
owned SSH application-channel end-window admission (transport close after the exclusive scenario
end); that remaining SSH window preflight is assigned to the SSH channel owner.

The generator's process-adjacent compatibility state now uses `BoundedRuntimeCache`, backed by one
`CompactIndexedStore` and a primitive `PackedHandleExpiryIndex`. Terminated-process markers,
source-create/terminate observations, session termination tails, loaded modules, SSH/SMB responder
bindings, SSH PID aliases, and SSH readiness are exact-key caches with explicit occurrence or
lifecycle deadlines. Process-owned bindings have exact reverse routes, so terminalization and
physical expiry repair only the affected records. The hourly watermark performs one fixed bounded
page per cache; it contains no map/set comprehension, `items()`, `values()`, global sort, or reverse
index rebuild. Logical watermarks make a due backlog immediately invisible while physical
reclamation remains paged. Constant-time census reports live/backing/stale/high-water counts,
estimated structural bytes, exact lookup candidates, expiry work, reverse subjects/bindings, and
the canonical watermark.

The actual one-million-entry process-runtime probe passed both uniform and single-owner-skewed
shapes. Uniform load was 2.605800 seconds, warmed exact p95 1.292 microseconds, one candidate per
query, 401,129,472 bytes incremental RSS, and 87,484,396 structural bytes (87.48 bytes per entry).
The skewed run loaded in 2.335882 seconds with 0.875-microsecond p95 and 205,537,280 bytes
incremental RSS. Expiring/compacting 100,000 due entries took 0.751541 seconds and left zero
backing rows. Seven- and 30-day profiles both retained 1,000 live/backing entries; the 30-day high
water was 1,040, proving duration plateau. The probe SHA-256 is
`052bc1cc3ec960508a62e8771c50d4b045d7203120a4fe8d17da8d466b7ddf6b`; the cache module SHA-256 is
`2726b6d6d7a0c2c2b7b24aced6ed54cf4d2ecb991bdec441628fba2210e94478`.

Deferred SSH session closure now consumes the LifecycleRegistry's bounded exact
`live_session_member_process_page` and child-page indexes. The generator repeatedly chooses an
exact leaf, terminates a still-live canonical StateManager process through the normal bundle path,
or commits an already-prepared close ticket for a retained registry-only process. Parent closes
therefore remain rejected until every child is closed, then reconcile post-order before the
session terminal event; no StateManager history scan, invented absent-process closure, or shadow
suppression is used. A focused regression freezes the rejected parent ticket, closes its child,
and proves the indexed drain commits the parent and empties the live-member index.

Verification after the compact-cache and deferred-close changes: 173/173 lifecycle, cache,
process-lifetime, shadow-wiring, stability, logoff, and baseline-foreground tests; 130/130 timing,
SSH channel, and rendered SSH/activity tests; 30/30 fresh Linux SMB integration tests; and 23 RDP
tests with one expected slow skip. The real full-coverage CLI completes all six hours and writes the
authoritative bundle at `/tmp/eforge-lifecycle-cli-20260816-final3`.

The final integrated replay exposed and fixed two additional canonical scheduling boundaries. A
foreground command whose RDP/session admission moved its CREATE now samples lifetime from the
published process start rather than the pre-admission request, preventing a terminate-before-start.
Nested process teardown now plans each child against the same exact sampled
dependent-to-parent gap later used at commit, recursively reserves that gap before mutation, and
fits the entire post-order tree below an immutable action-bundle/session fence. The full CLI's
former 49-millisecond descendant overflow is therefore gone. After the deployment owner coalesced
duplicate semantic installation contributions, the final Windows SMB/IDS integration selection
passes 9/9. Lifecycle/cache code is frozen. `git diff --check` is clean; final repository-wide Ruff
reported only concurrent foreign-owner deltas in deployment compilation, additive service/
transport lifecycle imports, and two baseline timing-format lines, all handed to their active
owners before this lifecycle/cache handoff.

## Timing runtime — bounded browser and baseline families

The next timing slice moves browser navigation/asset/page-settle timing and the bounded baseline
auth, lock/unlock, sudo, process-lifetime, scheduled-task, anacron, GPO, NTP, stale-credential,
and service-account schedule families onto the engine `TimingRuntime`. The migrated sites use
semantic stable IDs plus typed triangular, centered, mixture, or truncated-lognormal distributions;
counts, routing choices, status/body sizing, loss/skip decisions, and packet/data texture remain on
their scoped deterministic RNGs. Browser requests retain millisecond schema compatibility while a
separate microsecond remainder preserves non-quantized canonical ordering. Auth retry and management
sweep gaps, process terminations, schedule phases, GPO/NTP recurrences, and stale-account failures
are sampled once and remain inside their hour/session/process envelopes.

The policy gate in `test_baseline_timing_runtime.py` walks the migrated production functions' AST,
rejects continuous direct RNG and discrete RNG used beneath `timedelta` or temporal assignment
targets, and freezes the exact remaining texture-call inventory. It also proves one/four/eight-worker,
cache-capacity, iteration-order, and subprocess `PYTHONHASHSEED` independence. Distribution probes
cover right skew, absence of ceiling/flat-bin fingerprints, fewer than 0.5% exact-millisecond values,
and timing-audit saturation below 0.5%. The final integrated
browser/baseline/process/system-traffic/pack/RSAT gate is 340 passed/1 expected skip; minimal
bit-perfect generation and all eight rendered SMB integration tests also pass. Python compilation,
repository-wide Ruff lint/format, and the repository diff check are clean.

Optional SSH admission now distinguishes an unconstrained one-hour lifetime ceiling from a
multi-hour explicit required-activity horizon: required sessions receive at most one hour of bounded
sampled slack, while the complete packet-start, canonical-close, source-close, and exclusive-window
headroom remains reserved. Impossible optional and directly authored windows still reject before
port, transport, session, hold, or channel allocation. The full-coverage CLI replay clears the prior
14:30-to-18:59 SSH false rejection and reaches all six hours; it currently stops during independently
owned RDP/lifecycle finalization because a WS-MSANTOS-01 child closes 49 milliseconds after its
authoritative session end.

The follow-up inventory then classified the residual baseline continuous-RNG census and migrated
every temporal member. Generic role/inbound/persona traffic, IDS companions, legitimate
lateral movement, suspicious outbound and scan overlap, traffic affinities, background email,
pack-persona traffic, inbound web/tool traffic, RSAT, DHCP timer/registry effects, Kerberos/NTLM
gaps, journald schedules, polkit process timing, eCAR file churn, event distribution, stale-process
termination, and both canonical and compatibility SMB paths now use the engine runtime. Profile
traffic uses a typed weighted clustered-phase distribution, so burst-family selection and the
actual phase are one stateless runtime sample rather than separate direct RNG decisions. Near-window
children either sample admissible interior slack or are omitted/deferred; no emitter clamp was
introduced. Pack-authored weighted, periodic, and burst cadence now follows the same contract, and
baseline Kerberos prerequisites plus scheduled scan-probe durations no longer route through legacy
RNG timing helpers indirectly.

The exact remaining baseline continuous inventory is seven non-temporal calls: one lognormal
effective syslog-volume multiplier, one Gaussian hourly event count, three journald storage-size/
freed-space values, and two affinity byte-volume range values. The only browser continuous call is
the accepted partial-response body-size fraction. A repository AST gate freezes those exact eight
calls by file, function, method, and count, while the migrated-function policy rejects continuous
timing RNG and discrete RNG beneath temporal assignments or `timedelta`. Thus direct continuous
temporal RNG is now zero across the bounded baseline/browser slice rather than merely inventoried.
The clustered-phase distribution also has an explicit 4,096-sample no-bound, non-flat,
non-millisecond, sub-0.5%-saturation probe.

The next-slice storyline census remains explicit rather than hidden behind the baseline closure:
`engine/storyline.py` has 44 direct continuous calls. Forty-three are temporal: seven periodic/
DNS-tunnel/event-spacing/rate sites, sixteen web/port-scan duration and pacing sites, seven
logon/process/shell-prerequisite sites, and thirteen typed-event file/network/process/exfil/
background offsets or durations. The sole non-temporal call is the DGA label-length triangular
sample. This slice does not migrate those storyline-owned families.

## Remaining account and endpoint-effect production migrations

The read-only production-entry census found account/group/password writes in
`actions/windows_audit.py` plus their narrow generator adapters, isolated staged-archive SMB and
SCP receiver endpoint writes in `actions/file_transfer.py`, and the direct process-owned
file/registry lottery in `ActivityGenerator._execute_process_create_bundle`. Storyline/baseline
file and registry paths remained held by their timing/catalog owners. The account generator region
was explicitly released by the deployment owner; the transfer and process-file regions were later
released by root and the deployment/content owner. LifecycleRegistry, indexes, application/SSH/SMB
channel managers, deployment catalogs, timing runtime, module-load integration, and unrelated
generator regions were not edited for this slice.

All six Windows account/group/password requests now freeze one required Windows-audit effect before
session allocation. Generator adapters validate the exact plan and exclusive window before
mutation, dispatch exactly one canonical occurrence, reconcile exact cardinality, and update only
the bounded count audit. The generic endpoint foundation adds immutable exact-process bindings,
bounded file/registry/transfer graphs, explicit durable or ephemeral final-state disposition,
streamed stable occurrence identities, exact prepared-commit tokens, and reconcile-before-commit
semantics.

`StagedArchiveSmbReadActionBundle` now preflights the complete SMB/file/process-close graph without
allocating channel or endpoint state. SMB remains the canonical channel owner; the wrapper passes
the same compiled storage file object and therefore preserves its canonical file ID, byte size,
MIME, digest/FUID enrichment path, and no-fallback behavior. Local create/read identities bind to
exact process objects, bundle-created staging processes have one explicit closure, retained local
state has the exclusive exfil window as a bounded deadline, and channel omission publishes no
endpoint/audit state. `ScpReceiverFileActionBundle` now requires the already-created tuple-bound
SSH responder and exact ready time, never allocates a fallback responder, binds source/receiver
file evidence to exact process objects, and admits both endpoint artifacts together or neither.
Only externally existing process object IDs are `LINKED`; transfer and file effects are
`REALIZED`, so there are no phantom child-action links.

The process image/semantic/ambient file effects and ambient Windows registry lottery are now
collected before endpoint mutation and executed through one `ProcessOwnedEndpointEffectRequest`.
The adapter clamps source-native rows after the exact process CREATE observation, rejects a whole
near-window batch before commit, validates the current object/lifecycle binding twice, stages exact
cardinality outcomes, then publishes the existing source-native builders. File-content fields and
registry materialization/RNG order are unchanged; explicit file/registry identity plans add only
the exact process actor and canonical subject identity. Sessionless Linux process effects remain
valid because process object/lifecycle identity does not require an authentication session.

Focused verification: 10 generic endpoint-plan tests, 7 account tests, 12 transfer-plan tests, and
5 generator endpoint-integration tests pass. The combined account/endpoint/transfer/storyline gate
passes 111/111, including 1/4/8-worker and subprocess `PYTHONHASHSEED` determinism, exact
cardinality, retention/closure, channel omission, drift/no-commit, and near-window no-partial-state
cases. The full `test_activity.py` run passes 437/442; its five remaining failures are independently
owned lifecycle/application compatibility issues (one missing singleton session, one SMB browse
owner lifetime, and three custom dispatchers missing `lifecycle_shadow`) and were handed to root.
Scoped Ruff lint/format and Python compile checks are clean at handoff.

## Tracked authoring skills and V2 foundation reference

The eight tracked `/eforge` authoring command contracts now share one
`commands/eforge/references/v2-foundations.md` reference. It documents the implemented ownership
boundaries for execution effects, lifecycle state, deployment/content identity, collection
projection, application channels, source timing, and compatibility materialization. It also records
the exact low-to-high override precedence, omission-versus-explicit-empty behavior, and the rule that
large registries use exact or bounded indexed queries rather than duration-wide scans.

The config references now show the current typed application release/deployment, module release,
and installed-software inventory models. Scenario and organization-pack references cover exact-host
`deployment_overrides`, exact-source-instance `observation_overrides`, `os_build`, and
`architecture`. Pack examples intentionally remain within the public pack schema: pack process
descriptors are adapted at compile time, while `deployment` and `release_policy` remain project
config fields and are not advertised as pack YAML. The generation/evaluation references describe
compiled source deployments, aggregate collection diagnostics, and family-level interpretation.
`docs/ARCHITECTURE.md` now distinguishes canonical registry truth from `StateManager`'s
compatibility/materialized-live-state role and records the flat-lookup/bounded-retention contract.

Verification at this checkpoint:

- all 19 tracked command-reference slugs resolve;
- the config application, installed-software, pack process, scenario environment, exhaustive
  scenario override, and organization environment examples validate against their current Pydantic
  boundary models;
- the focused skill/override/deployment/source compiler gate passes 76/76;
- the broader pack/config contract gate passes 161/163. Its two failures are independently owned
  deployment/config regressions: the finance pack compiles a duplicate exact Chrome installation
  binding, and the third-party-module/Microsoft-identity validation test no longer receives its
  expected issue. Both exact nodes were handed to the deployment identity owner.

No project version, generated output, code, excluded compatibility/reference document, or public
pack schema was changed in this documentation slice.

## Frozen endpoint-effect production census and handoff

The final AST census of canonical `FileContext` and `RegistryContext` construction sites found 14
production entries. This slice owns the shared typed builder in `actions/file_transfer.py`, the
three process-local file candidates and one registry candidate in
`ActivityGenerator._execute_process_create_bundle`, and all six account/group/password adapters.
Those entries now pass through immutable preflight and exact reconciliation before their
source-native builders are published. The staged-SMB and SCP action bundles are the only callers of
the shared transfer file builder in this slice.

The remaining file/registry constructors were deliberately not broadened into this ownership:
HTTP multipart endpoint reads remain network-transaction-owned; canonical SMB file projection
remains SMB-channel-owned; remote-service payload creation was already typed; email cache and
attachment files remain email-family-owned; DHCP registry, eCAR churn, and system-traffic registry
entries remain baseline-owned; and HTTP upload/typed file entries remain storyline-owned. No
LifecycleRegistry, index, application-channel, deployment/catalog, timing-runtime, or module-load
surface was edited for this migration.

Final owned-path verification is 278/278 broad effect/account/transfer/process/storyline tests,
64/64 SMB/file-transfer validation and integration tests, and 442/442 `test_activity.py` tests. The
five activity and two storyline compatibility failures recorded above were repaired by their
integration owner and the exact seven-node rerun passes 7/7. Repository-wide Ruff lint and format,
Python compilation of the four production modules, and `git diff --check` are clean. The slice is
frozen without a commit.

## Adversarial follow-up: complete process-runtime cache census and strict lifecycle gate

The adversarial cross-family pass expanded the generator cache inventory beyond the original
process-observation cohort. `ProductionProcessRuntimeCaches` now owns 17 fixed production families:
terminated instances and latest routes; source create/terminate instances and latest routes;
session source-termination tails; loaded modules; SSH/SMB responders; SSH PID aliases/readiness;
APT frontends; CLI executable/command spacing; preferred-browser sessions; and browser-launch
sessions. The bundle also owns the real process reverse route rather than accepting a synthetic
census count. All records use exact compact keys, explicit deadlines, bounded watermark pages, and
mutation-time retained-byte accounting. The public census separately reports live/backing/stale/
high-water records, total retained bytes, structural index bytes, reverse subjects/bindings, lookup
candidates, and physical records. An AST policy inventories every mutable retained
`ActivityGenerator` field, so a new duration-wide dictionary or set cannot hide outside the
watermark wrapper.

The historical actual-million production-shape probe passed both layouts. Uniform traffic inserted
1,000,000 requested entries and retained 1,176,470 physical records including 176,470 reverse
bindings in 8.7975 seconds; warmed exact p95 was 1.500 microseconds with exactly one candidate per
query. Incremental RSS was 553,369,600 bytes, or about 448.7 MiB normalized per million physical
records; estimated retained/index bytes were 542,454,927/110,416,456. Single-owner skew retained
1,117,648 physical records in 8.5544 seconds with 1.125-microsecond p95 and 341,311,488 bytes RSS.
Expiring 100,000 due records took 0.6150 seconds and left zero backing records. The 24-hour,
seven-day, and 30-day profiles retained 1,128/1,264/1,263 physical records, respectively. All eight
former lookup, load, memory, candidate, expiry, backing, and duration-plateau gates passed. These
measurements are diagnostic history, not current or future acceptance criteria.

Production dispatch now calls lifecycle authority before `StateManager.apply`; generic process and
session create/close rejection therefore leaves both StateManager and emitters untouched. The
post-apply observer is metric-only and cannot invalidate an accepted canonical mutation. Every
engine-created dispatcher enables strict authority; direct unit fixtures retain an explicit
compatibility-only default. Forced parity drift, invalid parent/session intervals, live-child close,
and live-member session close regressions prove zero partial legacy or emitter mutation. The
registry remains the strict owner; no diagnostic-only production fallback or post-apply rollback
gap remains.

The final integration pass also moved intent occurrence recording after successful lifecycle
admission and `StateManager.apply`, but before source suppression, so a rejected dispatch mutates
neither canonical state, emitters, nor the bounded intent ledger. Linux login shells, terminal
servers, user systemd instances, and resident GVFS SMB owners are now classified as session
infrastructure rather than short foreground commands. Exact pending-close lookup prevents them
from becoming future parents after their half-open lifecycle ends; optional Windows browser/RSAT
paths no longer attach new activity to transport-closed sessions. Compatibility-only fixtures that
construct an `ActivityGenerator` without engine lifecycle wiring retain the legacy live-process
query, while every production constructor remains strict.

Final focused verification passes 114/114 dispatcher/lifecycle/cache tests, 197/197 process,
world-model, RSAT, and storyline lifecycle tests, and 445/445 activity tests. The full-coverage CLI
reaches its independently owned source-timing finalizer without a lifecycle/cache rejection; it
stops in hour two because a Zeek OCSP analyzer has only a two-microsecond interior before transport
close. Scoped Ruff lint is clean. Scoped format checking reports only concurrent generator
formatting deltas in timing/effect-owned regions; the owned cache, lifecycle, engine, baseline,
storyline, probe, and test files are formatted.

## Historical packed deployment/content actual-million diagnostic (retired)

The immutable deployment/content compiler now retains canonical values in contiguous variable-byte
rows with packed open-addressed exact routes rather than one Python object graph, tuple key, and
dictionary bucket per row. Binary, installed-release, user-profile, application-profile,
file-content, local-artifact, host-deployment, user-assignment, service, and task families rebuild
their frozen public values on demand. Semantic route digests are never trusted as identity: every
hit is checked against the exact canonical row, and a sparse exact-key collision lane preserves
multiple distinct keys with the same compact digest. The compatibility tier preserves object
identity for repository-authored sequence inputs of at most 10,000 rows; streamed/large populations
retain no compiler input objects. Compile-only decoded state is bounded and discarded when each
dependency family seals, so no duration-sized decoded cache was introduced.

The local-artifact path route is now packed and collision-checked, services/tasks use the same
packed immutable store, and installation storage exposes its already-packed product handle so
assignment compilation does not reconstruct release inventories. Binary rows retain their already
validated canonical IDs and digest resources in the packed row; runtime exact resolution therefore
does not re-hash content. Retained and index estimates are explicit constant-time sums of packed
row, interner, path, relationship, and route backing. The former whole-registry recursive graph
walk—which allocated a million-object `seen` set and materially inflated RSS—has been removed from
construction. Public exact/page/count/selection APIs and frozen value semantics remain unchanged.

During the retired checkpoint, `scripts/deployment_population_scale_probe.py` allocated an exact
requested physical denominator across all eleven canonical families, rejected populations below
eleven, supported uniform and single-profile skew, retained no payload bytes, and exposed only the
production registry/census API to the former unified foundation harness. The final historical skewed
1,000,000-row run retained 727,272 relationship bindings (1,727,272 total backing entries), loaded
in 53.111638 seconds, retained 429,490,176 bytes of incremental RSS, and peaked at 431,521,792
bytes. Explicit total/index estimates were 364,685,777/120,827,259 bytes, or 120.827 index bytes
per canonical physical row. Warm exact binary resolution p95 was 5.583 microseconds; warm weighted
profile/category selection p95 was 6.206 microseconds with exactly one candidate per query; the
90,909-entry skew bucket did not require materialization. All <=60-second load, <=512-MiB RSS,
<=256-byte index, <=10-microsecond lookup, and exact-candidate gates passed. The retired harness's
independent
100,000-row runner reproduced 4.2804-second load, 63,504,384-byte RSS, 127.31 index bytes per row,
5.916-microsecond exact lookup, and 5.5-microsecond category selection with stable start/end digest.

Focused registry/factory/collision/consumer verification passes 38/38 after the packed rewrite.
The initial broader deployment, compiler, catalog, config, pack, world-model, Sysmon, and activity
run passed 554/561. The owned exact-assignment sentinel was updated for the new process-bundle
boundary, and the resource-forecast owner repaired the sandboxed macOS swap probe; their combined
focused follow-up passes 28/28. A later deployment-heavy rerun passes 310/312, with only two
concurrent world-model process-lifetime/effect-plan nodes outside this slice still failing. Scoped
application/catalog/native-deployment/config verification passes 237/237 after final formatting.
Scoped Ruff lint/format and the packed factory/registry tests are clean; no commit was created.

## Engine-owned timing runtime and Sysmon dependent identity closure

The timing migration now has one engine-owned `TimingRuntime` and `SourceTimingPlanner` injected
through dispatcher, activity generation, source clocks, network observation, and source-native
endpoint planning. Canonical occurrence timestamps remain immutable; final source-native payload
and envelope times are frozen before admission and rendering. The exact global AST inventory has
no direct continuous temporal RNG in production generation code. Its residual allowlist contains
only explicitly named data, byte-volume, row-count, storage-size, and PID-identity-spacing texture.
`source_timing.py` has an additional exact policy gate and now contains no legacy
`sample_timing_delta`, packet helper, `_stable_seed`, `random.Random`, or direct continuous timing
draw. Profile delays, session dependents and closure, constraint gaps, packet/source microtexture,
lifecycle-child offsets, coherent eCAR process-create latency, and floor repairs all use typed,
semantically scoped runtime distributions. Explicit raw-emitter compatibility adapters construct
one stateless compatibility runtime and mark their plan as compatibility-only.

The production Sysmon ProcessGuid bypass is closed. `SourceTimingPlanner` freezes the Event 1
render seed for every relevant actor, subject, target, raw process, and DNS query process under the
normalized `(hostname, PID, process start)` identity. Events 3, 7, and 8 therefore retain the same
ProcessGuid seed even for boot-owned processes and when Event 1 is removed by collection policy.
The Sysmon emitter consumes that frozen exact/PID alias and raises when a production timing plan is
missing it; only an explicitly marked direct-emitter compatibility plan may use the stateless
adapter. No emitter owns a retained timing planner or repairs a production timestamp.

Focused source, endpoint, network, wiring, and AST-policy verification passes 136/136; source
census, typed-distribution, and constraint-graph verification passes another 40/40. Browser, DHCP,
network-transaction, OCSP, and Windows remote-auth action verification passes 111/111. Separate
Event
3/7/8 dropped-Event1 parity passes 4/4, and the endpoint plus Sysmon emitter cohort passes 71/71.
The inspected no-binary-identity compatibility XML remains 2,090 bytes with unchanged PE/hash
fallback semantics and passes its updated typed-timing snapshot. A parameterized GenerationEngine
test patches all three Sysmon compatibility timing helpers to raise for both `minimal.yaml` and
`full-coverage-apt.yaml`. The minimal case passes at the final checkpoint. An earlier full sentinel
completed with 107,347 Sysmon timing samples and 837,083 total timing samples, proving attribution
to the injected runtime; its final rerun currently stops before Sysmon projection on the
deployment-owned missing `/usr/sbin/sssd` identity for `MAIL-01`. The post-migration eight-node
deterministic generation matrix passes 8/8 in 57.61 seconds.
Scoped timing Ruff lint/format and the exact global policy are clean; no commit was created.

Compiled eCAR SMB projection now freezes every source-native row that its renderer can fan out:
the server-local FILE base and the client-local FILE companion receive independent endpoint-host
clocks and the exact source-instance queue for their owning host before `PreparedDispatch`
publication. A server-owned compiled projection can therefore render a copy/download companion
without entering the stateless compatibility planner or borrowing the server agent's timing scope.
The focused compiled projection regression and exact Windows SMB bit-perfect node pass 2/2; the
endpoint and source-timing suites pass 92/92. The final eight-node deterministic matrix passes 8/8
after the effect verifier and lifecycle checkpoints became coherent.

The final Sysmon renderer sweep also moved Event 11 `UtcTime` and `CreationUtcTime` onto the
already-frozen native source timestamp while retaining the provider-envelope `TimeCreated`.
Production rendering is guarded by compatibility sentinels and preserves visible Event 1 before
the file native time. Direct Event 3 and Event 22 compatibility tests now validate the configured
typed latency ranges and non-millisecond microtexture instead of reproducing the removed legacy
`sample_timing_delta` fingerprint. The resulting Sysmon renderer/endpoint aggregate passes
161/161.

## Atomic process-effect publication and bounded reconciliation closeout

Generic process execution now freezes the root process and every required endpoint consequence
before publishing any PID, thread, lifecycle start, artifact version, ledger occurrence, audit row,
projection, or rendered record. `StateManager.plan_process_materialization` supplies an opaque,
allocation-free root plan. `EventDispatcher.prepare_builder` seals one-shot prepared dispatches for
the root and dependents without mutation, and publication requires the exact authority-issued HMAC
materialization receipt. Receipt forgery, plan tampering, ABA drift, stale publication, and double
publication fail before mutation. Direct-dispatch fixtures retain byte parity through the
prepare-plus-publish compatibility wrapper.

The coordinator prepares the whole root/effect batch, claims runtime artifact tokens in canonical
effect order, commits StateManager and lifecycle authority once, commits artifact publications last
inside that no-fail authority boundary, and only then publishes the sealed root and dependents.
Unresolved process images receive one exact executable artifact publication using compiled host
architecture and profile identity. Every dependent row binds that same root binary identity plus
its own distinct file artifact when applicable. Required redirected output is a file-effect node in
the same pre-allocation graph; the former post-root raw `FileContext` publication path is gone.
Injected redirect preparation failure preserves the full StateManager materialization digest,
allocator state, lifecycle registry, retained process caches, artifact registry reservations,
intent ledger, effect audit, source status, and emitter counts.

Execution-effect reconciliation now has an independent publication denominator, so a published
effect-bearing occurrence without a matching plan cannot report a complete audit. The execution
ledger retains exact IDs only inside its explicit hot horizon/capacity and keeps compact counts,
commutative digests, and a bounded deterministic sample outside it. Per-source aggregates are
incremental and candidate-bounded. New ground-truth and generation-manifest documents always carry
the bounded reconciliation summary; generation fails before sidecar publication when required,
duplicate, cardinality, or publication-denominator totals are nonzero. Evaluation applies the
summary as a zero-weight 100-percent hard gate when present, while legacy documents may omit it.

Compatibility-wrapper dispatch now defers source target discovery until lifecycle and StateManager
accept the canonical occurrence; a rejected compatibility row therefore never calls even
`emitter.can_handle`. Explicit prepared root/dependent batches still freeze their entire projection
before external materialization. Runtime owner/profile or architecture admission failures are
translated at the process-effect boundary to typed `INVALID_ACTOR`; optional suspicious noise may
skip only that typed outcome, while authored/required work remains fail-closed.

Historical closeout verification passed 157/157 dispatcher/lifecycle/process/effect/artifact tests;
149/149 ledger, ground-truth, manifest, engine, and evaluation tests; the separately executed
actual million-entry skew diagnostic also passed. Another 143/143 file-transfer, account,
Linux-shell, command-effect, and endpoint-timing tests passed, as did 445/445 activity tests. The
historical million-entry one-intent probe confirmed bounded candidates and retained bytes; it is not
a current acceptance requirement. One/four/eight-worker, `PYTHONHASHSEED`, ordering,
digest, near-window all-or-none, drift, source-suppression, full-digest rejection, tamper, and exact
cardinality regressions are green. `git diff --check` is clean. The static engine-reachable direct
process/session-start census and its last compatibility migration are owned by the lifecycle
integration slice; its formerly failing nine activity nodes are now green. The final deterministic
eight-node matrix has cleared this slice and currently reaches 5/8; its first remaining failure is
deployment/content identity for an unregistered Linux `snapd` binary.

The optional suspicious-process caller now keeps its typed admission boundary around both the
allocation-free process preflight and any nested parent/session dependency admission reached while
executing that same frozen request. It executes through `ProcessExecutionActionBundle`, so a typed
`INVALID_ACTOR` raised by a missing exact Linux parent owner cancels every outer runtime-artifact
reservation before the optional action is skipped; other error codes remain fail-closed. A focused
rejection regression preserves the complete StateManager materialization digest, lifecycle census,
retained process-cache shape, artifact census, intent ledger, reconciliation audit, and emitter
count. The post-fix dispatcher/process/runtime aggregate passes 173/173, full activity passes
445/445, and the complete deterministic integration matrix passes 8/8.

Optional Linux sudo background noise now checks its exact compiled host/principal Linux profile
before entering TTY, session, shell, or process bootstrap. A missing profile becomes only typed
`INVALID_ACTOR` at that allocation-free caller boundary and skips the optional row; authored and
non-admission failures remain strict. The WEB-01/patricia.chen regression preserves the complete
StateManager materialization digest, and the focused sudo/caller suite passes 7/7. Avoiding the
previous partial sudo bootstrap advances the deterministic schedule to two independently owned
optional connection-owner failures (`gvfsd-smb-browse` for an inadmissible cross-host user) plus a
separate RDP baseline-selection assertion; those exact stacks were handed to the network/RDP owner.
The process/dispatcher effect regions remain frozen while those caller-owned gates advance.

## Deployment/content identity production closure checkpoint

The compiled deployment boundary now preserves typed compiler-owned service and task identities
through host-specific materialization, and exposes a separate collision-checked namespace for
runtime-created services. `CompiledSystemServiceMaterialization` and
`CompiledScheduledTaskMaterialization` retain the exact host/service-or-task ID alongside the
rendered image, command line, and parent key. The lifecycle production vertical consumed the
carrier with the compiled `print-spooler` descriptor and round-tripped it through registry
admission and process binding; its focused acceptance passes 5/5. Runtime-created identities are
derived from host, canonical service name, and root action rather than reusing an action ID as a
compiler deployment ID.

Native and role-owned binary placement is now explicit data. Linux native rows accept distro,
host-type, role, and service selectors. An `unspecified` legacy/custom binary compiles only when
one of those exact placement selectors proves installation; an unplaced path-only row remains
excluded. This preserves unknown package versions without fabricating VERSIONINFO or treating a
path as installation proof. The production Linux server-owner completeness regression executes
17 selector branches and requires exact registry resolution for sssd, Java, mysqladmin,
curl/wget/python, gunicorn, postfix, squid/apache, and role-scoped SMB workers; it also proves
role-incompatible and workstation-only negatives. The SQL Server boot service is likewise a
service-scoped `microsoft-sql-server-engine` deployment with an intentionally `unspecified`
release, present on the exact database/mssql host and absent from an ordinary file server.
Repository config validation remains 93 files with zero warnings or errors.

Runtime local-artifact retention now has explicit 24-hour, seven-day, and thirty-day focused
coverage. With a 48-hour retention horizon, live rows are 24/48/48 and high-water marks are
24/49/49. Backing slots remain hard-bounded at 24/100/126 of capacity 128, while estimated retained
bytes are 233,610/263,590/267,968; seven-to-thirty-day retained/index amplification is therefore
1.66 percent and the four retention/plateau assertions pass. Prepared, claimed, and reserved
publication residue remains zero after real generation. The combined native deployment,
deployment registry, and runtime-content focused suite passes 88/88; config/pack validation passes
163/163; the deterministic generation matrix passes 8/8.

The historical packed deployment shape had a provisional actual million-row green point: 53.11-second
load, 429.49-MiB incremental RSS, 120.83 index bytes per physical row, 5.58-microsecond warmed exact
lookup, and exactly one candidate. A final authoritative same-revision rerun was once held until the
aggregate timing/effect/lifecycle/network hash froze; that rerun is now permanently retired and is
not required. The full-coverage CLI has
advanced through the earlier sssd and optional-sudo admission failures. Its last retained run
stopped on the now-fixed SQL Server deployment before the network owner landed the separate
optional cross-host `gvfsd-smb-browse` typed-admission skip; no dispatcher or profile fallback was
introduced.

## Optional polkit admission and SSH atomic-batch handoff

Optional Linux polkit CLI noise now previews the exact action, executable, and subject through a
cloned generation stream before it commits agent, logind-session-pool, D-Bus, PID, process,
artifact, ledger, audit, or emitter state. A missing compiled host/principal profile raises only
typed `INVALID_ACTOR`; the system-traffic caller skips that optional row and propagates every other
plan error. Admitted rows replay the established RNG order exactly, while rejected rows advance the
planning stream without publishing retained state. The SAMBA-01/deploy `/usr/bin/pkcon` regression
preserves the full StateManager materialization digest and proves the polkit agent/session-pool/
D-Bus caches plus generator calls remain unchanged. Focused polkit tests pass 10/10 and the two
Linux SMB deterministic nodes pass 2/2 across `PYTHONHASHSEED` and format filtering.

The audited StateManager/lifecycle session-process batch API is frozen at StateManager hash
`5afb951d` and lifecycle-authority hash `51541a0e`. The intended SSH receiver batch member order is
one target session, the tuple-scoped privileged responder, and the optional session login shell,
with exact parent/session links sealed before publication. Each canonical start occurrence must be
prepared as `EXTERNAL_MATERIALIZED_START`; one keyed batch receipt must authenticate the session and
every process member, and each prepared row must publish exactly once in source-causal order.

Production SSH caller integration remains intentionally read-only because the canonical TCP/22
connection currently owns a separate `ConnectionMaterializationPlan` at the same StateManager
version as the receiver batch. Sequentially committing either plan advances the version and makes
the other stale, while publishing either side first would violate all-or-none transport/auth
semantics. The required next API is one composite connection-plus-optional-session/process plan and
authority receipt, committing the connection, session, responder, and shell at one State frontier.
Before that commit, preparation must validate the connection, every receiver member, lifecycle
authority, application-channel admission, artifact tokens, and all PreparedDispatch projections.
An injected rejection of the last shell/member must preserve the full StateManager digest,
lifecycle census, SSH application-channel census, artifact census and reservations, intent ledger,
effect audit, source/projection state, emitters, and receiver/session runtime caches. Success must
retain transport-before-auth rendering, one target session, exact responder/shell links, byte/event
parity where the canonical model is unchanged, and one-shot receipt/idempotence rejection. Generic
logon and RDP regions remain outside this ownership boundary.

## Historical SMB immediate-completion scale checkpoint (retired)

The retired SMB release probe exercised the production-shaped immediate-completion admission: one
immutable TCP/445 transaction, one SMB session/tree sidecar, one shared application channel, and
one bounded used-operation-ID marker per logical session. The common registry atomically records
the already-completed first operation without publishing an active operation row. The manager
retains the exact transport and session identity, and the public strict affinity constructor remains
unchanged. The scale fixture uses a private canonical ingress only for values it constructs in
normalized form; a focused differential regression proves its fields, owner, digest bytes, and
hex digest are byte-identical to the strict constructor.

The earlier fresh 100,000-session checkpoint loaded in 8.8068 seconds and therefore remained red
for the raw logical-session projection. The historical single-revision provisional points were:

- 20,000 sessions in 1.076861 seconds, projecting 53.843 seconds per million logical sessions;
- 100,000 sessions with the final 10,000-query warmed working set in 5.594801 seconds, projecting
  55.948 seconds per million logical sessions;
- 400,000 physical hot records at the 100,000-session point: 100,000 SMB sessions, 100,000 trees,
  100,000 common channels, and 100,000 common used-ID markers;
- 275,120,128 bytes incremental RSS, or 687.800 bytes per physical hot record;
- 155.946 sidecar index bytes per live SMB session and 0.625-microsecond warmed exact p95;
- identical start/end implementation digest
  `0504fd2f0b19ce60a83a269712e5bc1c4a0773f8a593c29d9627a3f86ad683de` for the latest
  100,000 run.

The improvement comes from preserving already-UTC timestamps, reusing immutable fixture values,
type-specific validated frozen application values, byte-identical compact affinity material,
avoiding a generated channel-key hex round trip, and allocation-light mutation/open-lock lanes.
Failure atomicity, disjoint-owner progress, close/expiry, cardinality, lookup, and hash-seed
semantics remain covered. At that checkpoint, the focused application-channel plus SMB cohort
passed 63/63 and the now-retired foundation harness passed 13/13. The route/view caches are bounded
to a 16,384-entry total warmed working set (256 views per fixed owner shard), which prevented the
former release probe's 10,000 exact queries
from measuring deterministic cache thrash while keeping cache memory independent of retained
duration.

One historical one-million-session diagnostic completed in 56.408143 seconds and retained 4,000,000
physical hot records. Its RSS delta was 1,634,828,288 bytes (408.707 bytes per physical record),
and sidecar index cost was 123.240 bytes per live session. That child exposed the former cache
limit as an 18.375-microsecond p95 and triggered the bounded-cache correction above. Concurrently
owned timing files changed during the child:
implementation digest moved from `96c3d12e9b811e4bcd17f3438a5cc30d8216f4148235b2ca483920ec4ae70eb7`
to `17748ed0a605287aefc9d03fc2c39f5060abf0203dd24a4dc65b7ff6590ca6d5`. The JSON is preserved at
`/tmp/foundation-smb-opt7-1m.json` as historical diagnostic context only. It is not current
calibration or acceptance evidence, and no rerun is required.

## Source-timing preparation atomicity checkpoint

The engine-owned `SourceTimingPlanner` now exposes an authenticated, copy-on-write
`SourceTimingPreparation` spanning related prepared dispatches. Exact cache reads see canonical
plus staged values without changing canonical lookup counters; all sixteen bounded timing indexes,
the shared source-clock registry, and timing-audit counters stage locally. Normal context exit
seals one stable binding token, cancellation leaves the planner census/digest, clock high-water,
and audit snapshot unchanged, and a claimed commit applies the overlay exactly once inside the
State/Lifecycle `finalize_external_no_fail` fence. The signed public receipt is created only by
`commit_no_fail`; a precommit or rejected claim cannot extract an authentic committed receipt.

The generic Windows logon path shares one preparation across the logon plus winlogon, userinit,
and explorer projections. A lifecycle rejection preserves the complete timing/runtime digest and
publishes no source evidence; success retains byte-equivalent sampling and commits once. Native
tests cover cancellation and success parity, tamper/wrong-owner/stale/double/ABA rejection,
precommit-receipt extraction, bounded overlay/clock census, watermark exclusion, and a static
production lock-order inventory requiring timing claim before authority materialization and timing
commit as its finalization callback. The focused source timing, timing foundation, dispatcher, and
generic-logon cohort passes 97/97. Frozen hashes are `63191eb1` (`source_timing.py`), `11320ce8`
(`timing/runtime.py`), `6563be79` (`timing/clocks.py`), `2c0278a4` (`timing/__init__.py`), and
`c2f5a2b9` (`test_source_timing_preparation.py`).

### Process/source-timing compound publication

Generic process execution now freezes the root process and every required endpoint dependent in
one `SourceTimingPreparation`. Due bounded-process closes drain as an independent committed
maintenance step before the State plan or timing overlay opens; no canonical planner/runtime work
runs between timing seal and claim. The compound commit order is timing claim, artifact claims,
State/Lifecycle materialization, artifact primitive commits, timing `commit_no_fail`, then root and
dependent `PreparedDispatch` publication. `generate_system_process` uses the same timing capability
and authority callback without changing its canonical output.

The required redirect rejection regression now fences the planner digest, bounded census, and
runtime audit in addition to State, lifecycle, artifacts, ledgers, effect audit, retained caches,
source status, and emitters. New tests cover system-process authority rejection, forged timing
capability rejection, one shared authenticated timing receipt for root plus every dependent,
artifact-before-timing-before-projection order, and a due-close timing sentinel whose later root
preparation rejects while preserving the exact post-maintenance snapshot. The owned endpoint file
plus system-process compatibility nodes pass 22/22; the timing owner's combined process/timing
cohort passes 117/117. Scoped Ruff check and format-check are clean. The integrated production and
process-regression hashes are `0f50fe08` (`activity/generator.py`) and `f6054bfa`
(`test_generator_endpoint_effect_integration.py`).

## Activity-generator duration-retention closure checkpoint

The whole-class AST inventory now discovers direct and lazy mutable ActivityGenerator fields, and
the whole-instance inventory rejects any materialized mutable owner without an explicit retention
policy. It includes custom mutable managers such as the email manifest spool, not only built-in
collections. Five statically dead/write-only fields were removed. Exact post-session-close routes
now release bash, local-session, workstation-lock, and sudo-TTY rows after successful generic or
SSH close publication; the SSH hook is guarded after both endpoint close companions and is absent
on either rejection path. Postfix terminal publication removes its exact queue row. Email manifest
payloads stream through a disposable SQLite spool with zero Python-retained payload rows, and an
exact byte-parity test preserves the former pretty, sorted JSON output.

Bash second reservations, fixed-logon high-cardinality browser targets, and privileged-auth 4672
replay claims now use exact indexed expiry on the engine's 24-hour retention watermark. Each path
has a hard 4,096-due-row gate rather than silently accumulating an expiry backlog. At four real
production-shaped occurrences per hour, the 24-hour/seven-day/thirty-day live and backing counts
are respectively 96/100/100 for all three paths; seven-day to thirty-day growth is zero, backing is
exactly 1x live, and maximum late-hour expiry work is four rows. Browser and privileged-auth replay
checks inspect exactly one candidate and preserve duplicate suppression inside the horizon.
Session-scoped rows and Postfix queues end at zero, with maximum concurrent semantic session rows
of ten and one queue row. The production process-cache control reports 114/125/126 physical rows
at 24 hours/seven days/thirty days. No million-entry or full-matrix run was used for this checkpoint.

The frozen focused cohort passes 71/71 across retention inventory/probes, generic logoff, SSH
channels, spool parity, close rejection, and privileged-auth duplicate semantics. Scoped Ruff,
format-check, and `py_compile` are clean. Frozen file SHA-256 values are
`cfa2cf652a891621b538bb15eaacf30b1cbc5f71ccb78abc8be65f505f76c97c`
(`activity/generator.py`),
`dd75b3200e6b44dda1fcd35b98d279b2c866d782765a8750f03441a5d26f596e`
(`actions/ssh_session.py`),
`ff04a12ed1fccf8339b1b44b4eba382a92e623c5b43d9a2ff40ab7c8e3f711ed`
(`process_runtime_cache.py`),
`f60e9194fa982b0bb5ffb4eaed68f252c5a103a8318aedc082889f8ad168c814`
(`scripts/process_runtime_cache_probe.py`),
`8259c78d81f952c786e58707bd423aaaf0c6a4f61492cfd700137f57eede42df`
(`test_process_runtime_cache.py`), and
`0f8d9aff5fa6c1aaef69949b07ae5e242e41bc8512bdc0f39eb5317ab2ce1237`
(`test_process_runtime_cache_probe.py`).

Duration debt is still explicitly open. The remaining definite-growing fields are
`_ad_srv_discovery_cache`, `_kerberos_audit_tuple_times`, and `_ssh_source_ports`, all assigned to
the network-runtime/foundation owner. Conditional DNS/TLS universes remain with that owner;
`_failed_logon_attempt_times` retains a 32-row per-key cap but its complete source-key universe is
still classified conditional. A representative email-engine test is externally red before any
retention code runs because the deployment identity registry has no exact runtime artifact for
`MAIL-ENG` `EdgeTransport.exe`; that deployment/content failure is recorded separately and was not
masked by this slice.

## Generator-owned timing-runtime migration checkpoint

The remaining owned logon, logoff, process creation/termination, source-visibility clamp, nmap
readiness, dependent-close, and recursive post-order-close gaps now sample through the engine's
shared `TimingRuntime` with typed `TimingScope` identities. Two local adapters preserve configured
relationship keys and inclusive microsecond support while routing both fixed and triangular gaps
through the runtime sampler. Across ten production methods, 23 exact sample sites replaced twelve
legacy timing-helper calls and eleven discrete `_stable_seed` temporal draws. The AST regression
freezes every sample key in source order and rejects any return of those legacy calls or hash-based
temporal sampling in the migrated functions.

`_zeek_conn_observation_time` remains the sole generator-local legacy timing-helper caller. Its
canonical caller is the separately owned network transaction planner and does not yet inject the
root engine runtime; changing helper and caller must land atomically in that slice. The complete
remaining production helper inventory is six exact calls: RDP `_target_logon_time`, SMB
`_execute_composite_transfer`, SSH `_plan_transport`, SSH
`_predicted_transport_open_time`, generator `_zeek_conn_observation_time`, and the legacy
`sample_packet_timing_delta` implementation's composition through `sample_timing_delta`. The
repository AST policy records one exact reason and count for each residual.

Generic logoff now invokes the duration owner's typed, idempotent session-retention release only
after the canonical logoff and every optional logind companion publish successfully. The release
uses the captured canonical session hostname and username when present. Focused tests prove one
successful release and zero release on publication rejection. Process-lifetime fixtures were also
updated to capture the current `publish_prepared` seam exactly once and to seed compatibility State
trees before the authority's one-time bootstrap. Exact descendant post-order closure, deliberate
State/authority drift with zero partial publication, SSH transport holds, foreground leases, and
watermark holds remain unchanged semantically; the complete process-lifetime module passes 61/61.

On the duration owner's released generator revision
`cfa2cf652a891621b538bb15eaacf30b1cbc5f71ccb78abc8be65f505f76c97c`, the final timing/policy/
logoff/process aggregate passes 106/106, the standalone lifetime rerun passes 61/61, and the
timing-owned SSH transport-close bound passes 1/1. Scoped Ruff, format-check, `py_compile`, and
diff-check are clean. The unrelated generic SSH-compatibility logon test still stops before timing
at `SshSessionActionBundle._ensure_session_identity` because it lacks the required immutable
preplanned Linux logind identity; that caller remains with the SSH identity owner and was not
weakened here.

## Production email service deployment identity closure

The finite production image census behind `ActivityGenerator._email_server_process_image` and
`_email_mta_outbound_process_image` now resolves entirely through compiled host deployment truth.
Windows mail servers receive role/service-selected, server-only Exchange Edge Transport and IMAP4
service descriptors; both retain the exact Microsoft Exchange product namespace while leaving
package version, build, and PE VERSIONINFO explicitly `unspecified`. Existing IIS resident-service
placement owns the OWA `w3wp.exe` worker. Linux mail hosts retain the existing Postfix resident
manager/worker deployment for `smtpd` and outbound `smtp`, gain an explicitly placed and
version-unspecified Dovecot daemon, and restrict the distro-owned Nginx row to mail/web roles or
the exact Nginx service capability. No path-only admission, dispatcher fallback, or inferred
Exchange/Dovecot package version was introduced; exact host OS build and architecture remain
separate deployment dimensions.

The production-owner regression derives all seven unique Windows/Linux paths from the two
generator helpers, requires exact registry resolution on `MAIL-ENG` and `MAIL-LINUX`, and requires
the same paths to be absent from role-incompatible Windows and Linux file servers. It additionally
checks the exact compiled Exchange service IDs, the IIS/Postfix resident-service IDs, authored
MAIL-ENG build/architecture, and absent PE metadata for the version-unspecified releases. The
representative email generation that previously stopped on strict Exchange IMAP identity now
completes. Final focused verification is 58/58 native-deployment, process-pool, merged-config, and
email-generation tests; `eforge validate-config --json` checks 93 files with zero errors, warnings,
or info findings. Scoped Ruff/format and repository diff checks are clean.

## SMB composite timing-runtime closure

Cross-server and share-to-client move deletion now requires the executor-owned engine
`TimingRuntime` before selecting a file or executing any composite child. The SMB planner no longer
constructs a compatibility runtime when an executor omits that dependency. The successful
read/create legs still complete in their existing order, then the delete gap is sampled once from
the configured 250–1200 ms relationship through source `smb`, the action lifecycle ID, and the
exact action/source/destination/completion stable preimage. Missing-runtime rejection is therefore
allocation-free, and no nested SMB child can silently use a second timing runtime.

Focused tests prove zero selection/child calls on missing-runtime rejection, identical
read/create/delete results and timestamps across fresh equivalent runtimes, configured gap bounds,
one runtime audit sample, and exact source ownership. The SMB timing/policy/validation/actor/channel
cohort passes 68/68. Production cross-server success ordering and failed-destination no-delete
integrations pass 2/2. Two wider integration invocations remain externally red in baseline process
effect preflight before their authored SMB assertion, where `PreparedProcessEndpointEffectPlan`
rejects an invalid root/window/retention interval; no generator/effect workaround was added.

The global helper policy now retains five exact production calls: RDP `_target_logon_time`, SSH
`_plan_transport`, SSH `_predicted_transport_open_time`, generator
`_zeek_conn_observation_time`, and legacy `sample_packet_timing_delta` composition through
`sample_timing_delta`. Scoped Ruff, format-check, `py_compile`, and diff-check are clean. Frozen
SHA-256 values are `515257cfcd18a66e7171d955ff0fc4e2f3de3764169e7044f1b6fdff6b166021`
(`actions/smb_activity.py`),
`acee64c61a31c5a19260c92f52b9ce0041b0927da1887cbc62992b5643e38ced`
(`test_smb_timing_runtime.py`),
`20def0f61a958000e1da4d29a7dd6a40063e36c1fad1ad44875aef3a3705be84`
(`test_smb_validation_boundaries.py`), and
`016da4fcefc5c0d513dcab7749242f676d82411c8c55586c881ba9ec4ceea79e`
(`test_global_temporal_rng_policy.py`).

## Retained-family forecast coverage and release provenance

The adaptive forecast boundary names the same exact twelve retained-state families as the former
foundation release harness: lifecycle, application channels, local artifacts, collection
deployment, deployment/content, process runtime, timing runtime, HTTP, proxy, SMB, RDP, and SSH.
Five registry-backed families retain their measured forecast rows. The other seven are represented
by explicit `legacy_calibrated_peak` provisional dispositions with a concrete rationale; they are
not silently omitted or mislabeled as final measurements. Model validation rejects omissions,
duplicates, changed registry mappings, and unrecognized dispositions. The previously proposed
exhaustive foundation scale matrix is permanently retired and is not a current or future acceptance
gate. Provisional rows remain explicitly labeled; completion evidence comes from the official
normal and slow release suites, focused regression/adversarial tests, and real-generation
evaluation without claiming exhaustive calibration.

Before retirement, the release harness implementation digest covered the integration owners that
could change a result without changing a leaf registry: dispatcher, StateManager, lifecycle
authority and production adapters, activity/baseline/storyline generation, network actions/runtime/
observation/
visibility, runtime content and source-deployment compilation, workload/forecast models, relevant
configuration, and the scale probes themselves. That historical change closed the earlier
possibility that `single_implementation_revision` remained true while a production integration
owner changed. Focused forecast and harness verification passed 36/36; the accompanying storyline
fixture repair passed 90/90, for 126/126 in that combined checkpoint. Scoped Ruff, format, and diff
checks are clean.

Public documentation now introduces compiled deployment/content and collection foundations in the
README, marks authenticated prepare/claim/commit as the current event-publication boundary in the
event-model PRD, and requires explicit host build/architecture plus deployment/observation override
coverage in the coverage prompt. `validation/schema.py` needs no duplicate rule: the existing
Pydantic scenario models, composition semantic validation, override-schema tests, and
`validate-config` already own those exact constraints.

## Early milestone commit checkpoint

Three dependency-isolated foundations were committed with exact-hunk staging while shared
integration files remained live: `c5d1e6d4` adds immutable execution-effect plans and the bounded
intent ledger, `fb6f9584` adds canonical deployment/content identities and registries, and
`4deb3097` adds the protocol-neutral application-channel registry. Each commit was verified from an
exact `git checkout-index` snapshot rather than relying only on the larger dirty worktree. Focused
gates pass 83 effect/ledger tests plus one deliberately targeted million-occurrence skew test in
7.66 seconds, 41 deployment-registry tests, and 52 application-channel tests. Whole-repository Ruff
lint/format and staged diff checks were green at each coordinated commit window. No version artifact
was changed.

## Independent timing, collection, and protocol-manager commits

Three additional dependency-isolated foundations were committed after validating the exact Git
index in temporary checkout-index snapshots. `af0bb0b9` adds the HTTP and explicit-proxy channel
managers and their focused tests; the exact staged snapshot passes 84/84. `6dbc1898` adds the
deterministic timing runtime foundation, clocks, distributions, constraint graph, and focused
contracts; the exact staged snapshot passes 38/38. `51f33162` adds immutable collection policy and
compiled collection deployment; only the matching collection imports and exports were selected
from the shared package initializers, and the exact staged snapshot passes 20/20.

Each commit used a coordinated writer pause so the pre-commit hook could stash and restore the
large shared worktree safely. Repository-wide Ruff lint and format checks, scoped formatting, and
staged whitespace checks were green at every boundary. Production network, lifecycle, generator,
SSH/RDP, and protocol-caller wiring remains deliberately outside these commits. No version
artifact changed, and no million-entry or complete release-matrix run was repeated for these
dependency-only milestones.

## Independent SMB, SSH, and RDP state commits

The protocol-state cores were then split from their still-live production integrations. `fe0ef69d`
adds bounded SMB channel state and its focused unit contracts; the exact staged snapshot passes
26/26. `809aa0da` adds bounded SSH child-channel state plus only its twelve package exports; the
exact staged snapshot passes 20/20. `a161db38` adds reconnectable RDP event/session state and only
the matching RDP imports and exports; the exact staged snapshot passes 19/19 with the embedded
million-query case deliberately deselected.

Repository-wide Ruff lint/format and staged whitespace checks were green at each coordinated
commit window. The SMB/SSH/RDP slow-scale scripts and production action-bundle wiring remain
outside these commits. Their recorded million-scale evidence does not match the current manager
hashes, so those gates are reserved for the final frozen implementation revision rather than being
repeated during dependency-only integration.

## Atomic process/service lifecycle integration checkpoint

Compiled baseline services and resident service families now use one authenticated
process-plus-service materialization boundary. The coordinator consumes the exact State process
plan and lifecycle service admission token, performs a final all-token sweep, commits the staged
process, service instance, and exact role binding as one primitive boundary, then completes the
shared source-timing preparation. Compiled deployment identity remains typed through the
publication; resident managers are created first, subsequent workers bind to the same live service
instance, and only the newly staged binding is reserved for each worker.

The symmetric close path uses an authenticated State process-termination plan and lifecycle
service-closure token. It atomically unbinds every exact service binding before closing the process,
keeps a resident service active while any worker or manager remains, and terminalizes it only under
the explicit last-binding policy. PreparedDispatch authenticates the outer close receipt and does
not reapply State or lifecycle mutations. Forced precommit rejection, nested token tamper, foreign
and stale plans, exact retry, one-shot publication, finite-service restart, and manager-plus-two-
worker closure are covered with complete accessible State/lifecycle/timing/cache/ledger/emitter
digests.

Baseline service lifetimes retain their exact canonical close timestamp but now carry a separate
frozen dispatch-eligibility frontier. Semantic blocks may therefore schedule a 04:26 close while a
later-generated block still materializes its legitimate 04:06 start; the close becomes eligible at
the next monotonic hour boundary and renders at 04:26. Watermark validation continues to use the
canonical deadline, so eligibility cannot hide or discard an overdue termination. The previously
failing organization-pack SMB generation and the complete SMB integration file now pass 8/8.

Current coherent gates are 182/182 for service/State/dispatcher integration, 88/88 for lifecycle
authority plus process lifetimes, 96/96 for phase-5 system traffic plus process stability, 449/449
for activity, and 29/29 for lifecycle-shadow plus deterministic generation. Repository Ruff lint,
format, and diff checks pass. The timing cohort reaches 106/107; its sole remaining failure is
outside this lifecycle slice: `full-coverage-apt.yaml` selects MAIL-01 user `james.walker` running
`/usr/bin/hostnamectl`, but runtime-content admission has no exact compiled host/principal profile.
That deployment/catalog correction is assigned separately; lifecycle strictness was not weakened.

Frozen implementation SHA-256 values at this checkpoint are
`0e2ad3ccb0010b43f56198cf25d1b16d7888dc68e9e6c2fd28e0a2592477b175`
(`lifecycle_authority.py`),
`f59ecb415df7911fc11232cc11bae37667f53e7c9c7677dd9cee705e4c97ed17`
(`state_manager.py`),
`7063feb8dbd697d25d729799fb5a0ca961aad9ec50d878f57d3f4984bee4918f`
(`dispatcher.py`),
`b8ccc7c740b177facfe09152c568ca24131d8dd9a79049609e4e00ce6dd3d0cd`
(`generator.py`), and
`70a4856f75c09e4b60c8164e31257b7f724f79285471aa6295877a2e8f295e90`
(`baseline.py`). No version artifact changed.

## Composite cohort authority hardening

The action-cohort integration remains gated on exact owner authority rather than on green happy-path
tests. Independent adversarial review proved one shared P1 pattern across State, lifecycle,
execution-effect audit, intent, source timing, local artifacts, and the outer dispatcher: after
certification, a caller could align-mutate every exposed carrier, record, authorization, and plan
copy, then publish different canonical state under the original authentic receipt. Several tails
also dynamically dispatched replaceable helpers after an earlier owner had committed, so a
call-original-then-raise fault could split canonical truth from the outer result.

The accepted correction is one non-exposed one-shot closure per claimed capability. Claim-time code
detaches a nested primitive preimage containing only exact targets, opcodes, primitive keys/values,
preallocated replacements, rollback operations, expected output, and terminal repair data. A
factory-local exact weak-capability locator retains that closure behind an opaque identity marker;
public carriers and owner records retain census and cleanup projections only. Commit, rollback, and
finalize inline the exact locator lookup and invoke captured primitives. They never re-read carrier
flags, module resolvers, current class methods, owner-record plans, or caller-reachable receipt
graphs. Provisional owners set private rollback-pending state before the first write and retain the
locator until exact cleanup or retry completes.

The trust boundary is explicit: the factory-local locator and closure cells are trusted owner state
and are not exposed through module globals, carrier fields, snapshots, census, receipts, results, or
representations. Pure Python cannot defend a reachable function's code object from arbitrary
mutation, so tests replace module/class bindings and all exposed graphs but do not introspect private
closure cells. Required gates cover aligned graph substitution, nested object mutation, copied and
stale capabilities, ID reuse, exact receipt repair, resolver/class/helper real-commit-then-raise,
hostile setters, first/middle/last provisional faults, finalize rejection while rollback is pending,
cleanup exhaustion and retry, capped/prunable authority retention, plateau behavior, and every outer
owner boundary. The previously proposed exhaustive foundation scale matrix is permanently out of
scope. These owner closures are certified through focused fault/regression coverage and the
official slow release suite.

Independent review subsequently tightened the construction boundary. Capturing a callback when a
claim starts is still too late: a replaceable owner method, ``deepcopy`` helper, lock context, or
nested collection method can be poisoned between prepare and claim, perform the real operation, and
then raise after canonical mutation. Likewise, a top-level immutable tuple is not detached when its
clock state, audit counter, route, receipt, or rollback entries remain caller-reachable objects.
Trusted primitive descriptors, constructors, copy/rebuild functions, and lock operations must be
captured once by the non-exposed module factory after definitions are complete; claim construction
must explicitly rebuild every nested preimage value. Post-certification writes must use those
captured original storage descriptors or prebuilt container replacements, because
``object.__setattr__`` still dispatches a class slot descriptor that can be replaced. Lock authority
also records exact acquisition depth before a fallible acquire and retains a public exact retry path
until interrupted acquire/release cleanup is terminal. These stricter rules invalidated the first
SourceTiming and Audit/Intent closure candidates despite their focused gates being green; their
reproductions are now mandatory regressions before the next immutable reviews.

## Completion-audit checkpoint

A requirement-by-requirement audit against the live branch confirms that the final objective is not
yet proved by the committed milestones. ``codex/v2-family-foundations`` is 53 commits ahead and zero
behind ``origin/dev`` at ``c2fcddac``, all three version declarations remain unchanged at
``2.0.0rc1``, and the Git index is empty. The remaining integration is still a large dirty tree, the
branch has no upstream, and no draft PR exists. Prior checkpoint prose and deleted ``/tmp`` JSON
files are not accepted as final evidence; applicable final results must be produced from the frozen
integration candidate.

The audit found two concrete implementation gaps in addition to the composite-cohort work.
``ActivityGenerator._ssh_source_ports`` remains the one field explicitly classified as definite
duration growth and retains an unbounded set; it must move to an indexed expiring owner with
24-hour/seven-day/30-day plateau proof. Five production paths still use legacy timing helpers:
RDP ``_target_logon_time``, SSH ``_plan_transport`` and
``_predicted_transport_open_time``, generator ``_zeek_conn_observation_time``, and the packet-helper
composition. They require migration to the engine-owned timing runtime or an explicit approved
compatibility-only exclusion; an inventory test alone is not completion. Conditional TLS key
universes must likewise be bounded or explicitly reviewed in the final retained-state census.

Final evidence must come from one clean final commit. Required gates include the complete normal
pytest suite, repository Ruff lint and format checks, config/scenario validation, the official slow
release suite (including the 31-day SMB retention integration), and the focused owner/adversarial
regressions. No exhaustive foundation scale matrix is part of this effort now or in the future. A
fresh two-run iteration-test generation must then prove byte-identical data
trees across the requested worker/hash-seed variants, pass quantitative evaluation without material
regression from the 97.2016 baseline, and feed an isolated four-person blind panel. The final blind
package must include canonical ``scores.json``, four reports, ``REPORT.md``, any triggered
deliberation, the effectiveness dashboard, and an A/B comparison to Loop 30 if standalone movement
is ambiguous. Only after those proofs, a clean dev-sync, no-version-diff check, push, and draft PR to
``dev`` satisfy delivery.

This completion contract was superseded on 2026-08-24 by the user-approved bounded closure plan.
That plan requires exactly two final deterministic generations, one quantitative evaluation, one
isolated four-person blind panel with protocol-triggered deliberation, durable reports, final hygiene
checks, and one local commit. It does not add an A/B panel or dashboard, and it does not authorize
dev sync, push, or a draft PR. The fresh blind panel records the outcome honestly; improvement
against Loop 30 is no longer asserted as a closure condition.

### Bounded SSH source-port retention landed

The first concrete completion-audit gap is closed in commit ``541ce9b4``
(``fix: bound SSH source-port retention``). The exact three-file commit replaces
``ActivityGenerator._ssh_source_ports`` with a paged ``BoundedRuntimeCache`` whose canonical
watermark retains exact source/destination/port reservations for an inclusive 24-hour horizon.
It preserves explicit reuse for the same physical connection within one second, synchronizes tuple
ownership with ``NetworkTransactionRuntime`` in both directions, and raises after 100 collisions
instead of reusing a live tuple. The retention census now classifies the owner as a bounded temporal
index and has no definite-growth field.

Independent exact-tree verification passed 18 focused cache/semantic/correlation tests plus the SCP
caller, repository-wide Ruff lint and format checks, and cached diff validation. Duration probes
plateaued at 100 live/backing entries for both seven and thirty days with maximum hourly expiry work
of four; repeated fill/drain cycles reclaimed all physical backing. The live aggregate snapshot's
stale unbounded-retention assertions were reconciled after landing. Its remaining SSH integration
failure is the separately reproduced deferred-session lifecycle-authority invariant, not a source-
port retention regression.

### Legacy timing-helper migration landed

Commit ``b3b93523`` (``refactor: route legacy timing through runtime``) closes the five
legacy-helper debts identified by the completion audit. RDP target authentication, SSH transport
open/responder prediction, and generic network observation now sample through the injected engine
``TimingRuntime``. SSH computes its transport anchor once and reuses it; the packet compatibility
helper makes one typed triangular draw rather than composing two separately seeded helpers. No
production caller of ``sample_packet_timing_delta`` remains.

The exact nine-file milestone passed its eight-node family, AST, worker, and
``PYTHONHASHSEED`` suite; 19 network-contract nodes; 32 SSH retention/admission/channel nodes; the
changed world/Zeek siblings; tracked RDP world, activity, admission, and reconnect suites; scoped
Ruff, format, compile, and diff checks. An independent live rerun passed the migration suite 8/8.
The branch reached 55 commits ahead and zero behind ``origin/dev`` with an empty index. One
pre-existing timing-profile assertion still derives its expected process-causal gap through the
retired helper even though production already uses the engine runtime; it remains assigned to that
owner rather than being hidden in this packet/RDP/SSH commit.

### Residual temporal and authority review

The complete temporal allowlist audit classified 70 keys: three are dead production semantics,
two are direct-emitter compatibility only, 29 are non-temporal size/identity/texture primitives,
and 36 are genuine one-runtime timing debts. Four of the 36 are closed by ``b3b93523``. The next
non-overlapping slice migrates SMB authentication and tree-connect gaps through its existing
executor-owned runtime; the remaining generator, SSH-auth, TLS-validity, suspicious-benign,
world-model, and helper sites still require migration or an explicit final compatibility decision.
The global policy test also has two stale owner names after production functions were moved and must
be reconciled against the AST rather than allowlisted by line number.

Adversarial review rejected otherwise-green TLS and State candidates before landing. The TLS hard
cap counted an owned reservation and its just-published live point twice, so an exact-capacity
two-point prepared certificate commit published the key and then failed on the certificate. State
captured internal slots correctly, but mutable public commit/finalize dispatch could call the real
tail then raise after publication, and a dynamically fetched manager lock could leak on
real-acquire-then-raise or commit without returning its result on hostile ``__exit__``. Both freezes
are withdrawn; their exact reproductions are mandatory in the replacement candidates.

### TLS certificate timing migration landed

Commit ``360b1397`` (``refactor: route TLS certificate timing through runtime``) moves all four
certificate-validity draws to the injected engine-owned timing runtime: validity duration,
not-before day, within-day placement, and issuer-bound offset. Persistent generation uses the exact
``ActivityGenerator`` runtime and prepared network planning uses its exact staged timing view.
Stable certificate and rotation-bucket scopes preserve certificate identity across connections,
while separate relationship and sample keys keep every draw independently audited. The replacement
distribution is an equal edge-triangular mixture whose rounded support preserves the former
inclusive integer ranges without restoring a mutable production RNG.

Independent exact-tree verification passed 97 focused certificate, cryptographic-material, DHCP,
and OCSP tests; an additional 100,000-scope distribution probe exercised every endpoint with a
1.047 maximum/minimum count ratio. The live replay passed 87 focused/adjacent nodes and 69 DHCP and
certificate nodes, plus scoped Ruff, format, compile, and full diff checks. The exact planner and
test hashes match the reviewed candidate, the milestone contains exactly three paths, the shared
index is empty, and no version artifact changed. The separate prepared TLS material capacity
atomicity defect remains explicitly open; this timing commit neither masks nor broadens it.

### RDP bootstrap timing migration landed

Commit ``e30b6dc3`` (``refactor: route RDP bootstrap timing through runtime``) removes the residual
``WorldPlanner._bootstrap_rdp_session`` integer RNG draw. Source-side ``mstsc.exe`` placement now
uses the exact ``ActivityGenerator`` timing runtime with relationship
``world.rdp.source_process_create_lead`` and a stable user/source/target/logon lifecycle scope. Its
open triangular support quantizes to the former inclusive 1.8--3.2 second lead window while adding
microsecond texture. Unmodeled external sources return before constructing a planner, so they
produce no phantom sample and do not consume the compatibility RNG.

The exact two-file milestone passed its five-node runtime/bounds/no-source/worker/hash-seed/AST
suite, 45 timing-adjacent tests, and 74 World/RDP tests with one known exact-base transport-overlap
node deselected. Independent replay ran 43 focused and adjacent nodes; the sole failure was then
reproduced unchanged on the unmodified ``360b1397`` tree. The live replay passed the five focused
nodes and 78 unaffected World/RDP nodes plus scoped Ruff, format, and compile checks. Its broader
eight lifecycle/connection-planner failures remain byte-for-byte baseline debts. The milestone
contains no policy, version, or engine changes; the stale global temporal-policy inventory entry is
reserved for the consolidated policy reconciliation.

### Lifecycle combined-authority review remains open

The first combined Lifecycle closure/rollback candidate on ``360b1397`` is withdrawn despite 73
focused and 109 adjacent owner tests passing. Independent adversarial review found six P1 clusters:
release-after-success cleanup over-released a caller's pre-existing recursive-lock depth; dynamic
post-certification rollback and cleanup helpers could mask the primary or strand a permanently
committing reservation; whole-object ``__dict__`` substitution could make commit return a receipt
while the public registry pointed at foreign state; forged scalar frontiers could produce authentic
state with negative retention/provenance counters; the factory-global owner lock could deadlock
against a route-lock holder reading capability state; and claim still resolved replaceable
``deepcopy``/constructor/helper bindings. The replacement must use exact per-scope acquisition
tokens, fully captured cleanup primitives with locator-last retry, exact owner-state/frontier
binding, command-local synchronization outside the owner-map lock, and import-time claim
construction primitives before it can be reviewed again.

### Suspicious-benign placement timing migration landed

Commit ``c4dd8b48`` (``refactor: route suspicious noise timing through runtime``) removes the nine
production placement ``randint`` draws from ``suspicious_benign.py``. Baseline generation now passes
the exact engine-owned ``TimingRuntime`` plus its stable event ordinal into every suspicious-noise
family. The runtime relationships retain each former inclusive support (eight 0--3599-second
placements and the 0--3500-second failed-logon placement) without a private or shared production
RNG fallback, and skipped families consume no phantom samples.

Independent review found no P0/P1 after the edge distribution was corrected to use exact half-step
open support. A 200,000-scope four-bin replay produced counts 49,888/49,994/50,126/49,992
(``chi-squared=0.5704``), showing the former endpoint PMF is preserved. Exact-tree focused and
adjacent gates passed 79/79 and timing-adjacent gates passed 87/87; the live integration passed
91 owned plus four adjacent nodes, Ruff, format, compile, and diff checks. The exact commit contains
only the two production files and the focused test, has tree ``c08561a4``, leaves version artifacts
unchanged, and advances the branch to 58 commits ahead of ``origin/dev`` with an empty index. The
live-only RSAT test double now carries an explicit timing runtime; that broader fixture remains with
its owning integration work rather than being folded into this exact three-path milestone. The
global temporal-policy inventory still needs consolidated reconciliation after the remaining timing
migrations land.

### SourceTiming clock hardening review remains open

The first exact ``e30b6dc3`` clock/nonfinite/retained-byte candidate is withdrawn despite 113
focused and 67 adjacent tests passing. Independent adversarial review showed that graph sizing
invoked caller-controlled ``__sizeof__`` and current key/spec/distribution descriptors before safe
rejection; a three-million-NUL identity passed the two-times pre-``repr`` estimate and then expanded
to roughly 12 MiB; a seen-set without an active recursion stack admitted cyclic mixture graphs; and
claim-time detachment authenticated infinite aggregate mixture weights, negative distribution
parameters, and a zero wander interval. The public clock facade also exposed ``_inner``, allowing a
caller to bypass the operation cap and census entirely, and cache-hit preflight charged a full value
before recognizing that only a bounded diagnostic operation would be retained.

The replacement must use captured exact field readers and type-first primitive accounting, explicit
active-stack cycle rejection, representation-safe byte accounting (or avoid retaining diagnostic
``repr`` data), constructor-equivalent distribution and wander validation at both staging and
claim, and an authority surface with no inner-facade bypass. A separate owner-layer P1 remains:
``BoundedRuntimeCache.set`` publishes its primary record before the fallible deadline-index update,
and SourceTiming replay cannot currently reconcile the resulting record/deadline/counter split.
That cache/index atomicity change remains approval-gated and is not hidden by the narrower clock
replacement now in progress.

The second exact ``c4dd8b48`` replacement is also withdrawn. Although its 134 focused and 67
adjacent nodes passed, the underlying clock registry still invoked a replaced
``SourceClockKey.__sizeof__`` after inserting the state, leaving one clock entry and two audit
operations outside the clock budget when the callback raised. A module-global unwrap helper also
returned the raw clock preparation and bypassed a zero operation capacity. The replacement charged
an aliased ``SourceClockState(0.0, 0.0)`` placeholder rather than the sampled state's two distinct
floats (1015 recorded bytes versus 1039 retained), expanded shared mixture DAGs during claim without
memoized depth/node/byte limits, and omitted the retained clock-state graph from the seal digest.
Its 512-node whole-registry claim limit also rejected an ordinary 64-entry prewarmed cache despite
the documented 2,048-entry/4,096-operation capacities. Finally, the claimed tree hash could not be
reconstructed from the exact two matching file hashes. The next replacement must harden the
underlying owner before insertion, remove every raw unwrap authority, account the actual retained
graph, bind it into the seal, preserve bounded DAG aliases while rejecting cycles, and publish a
reconstructible tree manifest.

### SSH authentication timing migration landed

The first complete SSH-authentication runtime candidate is withdrawn after independent review found
two narrow P1s. Four calls through ``_ssh_syslog_time`` still derived 0--88 microseconds of
connection/accepted/PAM/logind texture with ``_stable_seed % 89`` after the audited runtime plan.
Also, the integer-millisecond adapter widened open bounds by one full microsecond; a rounded outer
bin could therefore be rejected and cause the enclosing phase/cache mixture to be selected again,
slightly shifting configured weights (for example 0.18 to 0.179999893...). The replacement removes
the private lifecycle jitter and uses open half-microsecond bounds so every quantized value is
accepted without component reselection.

The rest of the five-path candidate reviewed clean: all former connection, accepted-auth component,
PAM, and logind RNG draws moved to the injected runtime; direct/prepared plans and full audit digests
matched; reuse caused no resampling; support metadata, worker ordering, ``PYTHONHASHSEED``, shared-RNG
neutrality, and compatibility-only helper isolation passed. Its 59 core, 125 timing-adjacent, and 73
SSH/SCP adjacent tests establish the retained baseline for the fresh ``c4dd8b48`` replacement.

Commit ``b62cc858`` (``refactor: route SSH authentication timing through runtime``) lands the
replacement on exact parent ``8336867f`` with tree ``e9edba8b``. The immutable auth plan now captures
the exact originating runtime and scope; connection, accepted-auth phase/cache/route/receiver/key,
PAM, logind, temporal-repair, and Linux process-visibility gaps all use that captured owner. Missing,
foreign, subclassed, or descriptor-backed runtime/scope objects reject before state or callback
access. The private ``_ssh_syslog_time``/``% 89`` lifecycle jitter is removed from both reachable and
dead generator/action paths, and every rounded millisecond leaf uses half-microsecond open support so
an enclosing configured mixture is never reselected at an endpoint.

Two independent read-only reviews found no P0--P2 findings and reconstructed the exact six-path
tree from the sealed bundle. Focused exact and live gates passed 26/26; exact ``-k ssh`` passed 219
nodes with four unchanged base failures, and live ``-k ssh`` passed 204 nodes with 34 unchanged
live-base failures and one skip. Ruff, scoped format, pycompile, bundle/fsck, and diff checks passed.
The reviewed live composition was then applied with exact hashes for the five non-generator paths;
the generator retained only the already-reviewed ICMP owner hunk beyond the SSH snapshot. The shared
index remained empty and version artifacts were unchanged.

### ICMP timing runtime migration landed

The first injected ICMP timing candidate and both SMB layers built on it are withdrawn. The helper
rejected only a missing runtime, so a raw ``TimingRuntimePreparation`` or descriptor-backed
duck-typed object exposing ``sampler`` could become the timing owner; non-string identities were
also accepted.

Commit ``8336867f`` (``refactor: route ICMP timing through runtime``) closes that admission gap and
moves reply and no-response RTT sampling to the exact injected ``TimingRuntime`` or
``SourceTimingPlanningRuntime``. Admission checks the exact runtime type and a built-in nonempty
connection identity before any descriptor or coercion can run; the semantic scope includes the
reserved connection ID. The transaction planner advances repeated same-tuple observations by the
prior RTT plus the existing jitter gap, keeping strict overlap rejection intact rather than
weakening the registry.

Independent rereview passed the 15 focused nodes, 148 adjacent timing/network nodes, nine ICMP
activity/emitter nodes, and repository-wide Ruff/format checks. A 100,000-sample replay matched the
85/15 no-request mixture and the 65/29.75/5.25 valid-request mixture; cancellation/retry was neutral,
and 1,000 repeated same-tuple operations produced zero overlaps, one bounded retained runtime point,
and full expiry. The exact three-path commit has tree ``769069ff`` and leaves version files
unchanged. SMB prerequisite and authentication/tree timing layers may now be rebuilt and reviewed on
this accepted parent.

The exact ICMP owner hunks were also replayed context-tightly into the broader live foundation
snapshot without staging unrelated work. The transaction planner file is byte-identical to the
reviewed milestone; the generator retains its other in-progress family changes while using the same
exact runtime/type/identity admission and mixture sampling tail. The focused ICMP/activity cohort
passed 17/17, and the formerly failing minimal timing-runtime wiring node now passes. The shared
index remained empty and the production-path diff check stayed clean.

### DNS scheduling timing migration landed

Commit ``4ad78107`` (``refactor: route DNS timing through runtime``) removes the six remaining
direct schedule ``randint`` sites from automatic DNS lookup and AD SRV discovery. Query lead,
discovery lead, companion, MX-to-address, NXDOMAIN lead, and later-SRV spacing now sample through the
exact engine-owned ``TimingRuntime``/``SourceTimingPlanningRuntime`` with stable request, host,
lifecycle, relationship, sample-key, and ordinal scopes. Each former inclusive integer range uses an
equal edge-triangular mixture over half-millisecond open support, preserving exact endpoint mass
without component reselection. Cache hits, supplied planned times, duplicate SRV points, and the
first SRV query consume no phantom samples.

Independent review found no P0/P1 in either the frozen live snapshot or its exact mechanical replay
on ``b62cc858``. The exact three-path tree ``413dec5c`` preserves every ICMP and SSH function AST,
passes 9/9 focused DNS timing nodes and a 32/32 AD/runtime/network-contract cohort, and retains the
same seven DNS-realism failures as its untouched parent while strengthening two row-selection
assertions. The live replay passed the focused 11/11 gate; its realism test and new focused test match
the reviewed bytes exactly, while the generator differs from the frozen DNS snapshot only by the
already-reviewed SSH and ICMP hunks. The combined live DNS/AD/network timing and transaction cohort
then passed 74/74. Ruff, format, pycompile, bundle, and diff checks passed; the shared index remained
empty and version artifacts were unchanged. Global temporal-policy inventory reconciliation remains
deliberately deferred until SMB and the other active timing owners settle.

### Temporal RNG policy reconciliation checkpoint

A read-only live-AST audit after the SSH and DNS milestones found the untracked global policy at
1/4: its bypass prohibition passes, while three inventories are stale. The live implementation has
22 continuous keys/37 calls (only the planner owner name differs), zero legacy-helper calls, and 30
discrete keys/53 calls. An in-memory correction matched those counts exactly. Of the remaining direct
RNG surface, 31 keys/48 calls are non-temporal identity/size/texture primitives, 18 keys/37 calls are
reachable production timing debt, and three keys/five calls are compatibility-only or dead in
canonical production.

TLS, SSH, suspicious-benign, ICMP, RDP bootstrap, and DNS now have no remaining direct draws in their
migrated regions. SMB still owns two pending gaps. The other production timing debt is confined to
disjoint generator functions for baseline RDP placement, causal expansion, foreground/bash
availability, email MTA placement, process correlation/effects, Kerberos/account exchange,
NTLM/failed-logon, and Linux session/PAM/logind timing. The policy will be edited once those owners
settle: rename the planner and failed-logon owners, delete all five stale legacy-helper rows and the
landed SSH/TLS/suspicious/RDP/packet rows, then remove DNS and SMB rows after their live integration.
This preserves an exact inventory gate instead of temporarily weakening it with broad allowlists.

The combined live timing-runtime wiring file now passes 9/10. The former minimal-scenario
``_ConnectionPlanningRandom`` failure is closed by the landed ICMP owner; the sole remaining node is
the unchanged full-coverage deferred-session lifecycle-authority rejection, which belongs to the
active Lifecycle replacement rather than a timing compatibility fallback.

### SMB persistent-channel prerequisite review remains open

The first exact ``8336867f`` SMB prerequisite and its unreviewed timing stack are withdrawn. The
focused manager and storyline-reuse tests passed, but full production review found four P1 owner
defects. Persistent SMB Type 3 sessions collided with ordinary baseline LogonIDs, leaving the full
SMB integration at 1/8 and the SMB determinism cohort unable to reach comparison. Reused operations
updated only ``StateManager`` after the immutable network transaction and rendered Zeek row were
frozen: the connection reported 1,844,463 responder bytes while its three SMB payloads already
totaled 3,948,544 before framing. A fault after operation/handle admission had no cancellation
boundary, masked the primary during finalization, and retained an open session, tree, handle,
channel, and active operation. Finally, an already-finalized lease could open a new handle while the
common registry reported zero active operations.

The replacement must move collision-safe session identity, deferred/final canonical transport-byte
truth, and authenticated operation/handle prepare-claim-commit-cancel semantics into the owning SMB
manager. Exact manager/channel generation, active operation, and tree identity must reject stale,
replayed, copied, tampered, and foreign leases before mutation. Required gates now include rendered
connection-byte equality, every post-reservation fault seam with primary preservation and zero
residue, the complete production SMB integration/determinism suites, and independent prerequisite
review before the timing layer is restacked.

### RDP outer-placement timing migration landed

Commit ``c61dfd028`` (``refactor: route remaining RDP timing through runtime``) removes the two
reachable baseline RDP placement ``randint`` draws. The session lead now preserves the former
inclusive 80--400 ms distribution, while the modeled source-process lead preserves the former
inclusive 1800--3200 ms distribution and remains conditional on an actual modeled source. Both
sample through the exact engine-owned ``TimingRuntime`` or active
``SourceTimingPlanningRuntime`` under stable resolved source/user/target/activity lifecycle scopes.
External and self-source fallbacks return without a phantom source-process sample.

Independent review found no P0/P1. The exact two-path tree ``afb40e62`` passed 10/10 focused nodes,
27/27 RDP prepared/activity/world-model nodes, 10/10 baseline timing nodes, initialized production
ordering, direct/prepared/cancel parity, hostile-runtime rejection, full-support PMF replays,
worker/order and ``PYTHONHASHSEED`` determinism, and repository-wide Ruff/format/compile/diff gates.
The exact-base duplicate machine-account LogonID failure reproduced unchanged outside the timing
branch. The reviewed bundle SHA-256 is ``30b1b86a...``.

The broader live snapshot preserves the reviewed helper and all three production statements
AST-for-AST. Its focused timing file passes 10/10; prepared/world-model nodes pass 12/12 and baseline
timing passes 10/10. Ten older RDP execution nodes still stop at the active Lifecycle replacement's
``Deferred-session network roots require their session authority`` check before reaching this
timing branch. The milestone leaves version artifacts unchanged, the shared index empty, and the
branch 62 commits ahead of ``origin/dev``.

### Email MTA process-placement timing migration landed

Commit ``95de31ccb`` (``refactor: route email MTA timing through runtime``) moves both outbound MTA
worker-placement draws from private seeded ``Random.randint(180, 850)`` calls to the exact
engine-owned ``TimingRuntime`` or active ``SourceTimingPlanningRuntime``. A stable
host/image/activity lifecycle scope owns the audited sample. Linux Postfix first checks for the
exact active manager/SMTP worker pair and reuses it without sampling; Windows continues to delegate
to its canonical mail-server process owner without a phantom outbound-worker draw. The half-step
edge-triangular mixture rounds to every integer from 180 through 850 with the former uniform mass.

Independent review found no P0/P1 and reconstructed the exact original two-path tree
``bf273f31``. Focused, preparation/timing, and storyline/legacy cohorts passed 8/8, 49/49, and
13/13; an independent 40,000-sample replay covered all 671 bins with chi-squared 638.813. Direct and
prepared values/audits match, cancellation and prepared worker failure leave no timing or process
residue, and worker order plus ``PYTHONHASHSEED`` are deterministic. The broad email file retained
the same machine-account LogonID failures as the untouched parent. Repository-wide Ruff, format,
compile, tree, and diff gates were clean.

The reviewed functions were replayed AST-for-AST onto ``c61dfd028`` while preserving the landed RDP
helpers. The resulting exact commit has tree ``d76d80d7`` and verified bundle SHA-256
``db5ed31e...``. The shared live composition passes 63/63 focused and adjacent timing nodes, leaves
the index empty and version artifacts unchanged, and advances the branch to 63 commits ahead of
``origin/dev``.

### Lifecycle duration scale boundary repaired

Commit ``aea2dde87`` (``fix: preserve lifecycle duration watermark boundary``) repairs the first
clean-HEAD scale-smoke failure without changing lifecycle authority semantics. The duration harness
previously advanced the inclusive lifecycle watermark to the exact next-hour boundary and then
published the following bucket's first session at that already-sealed timestamp. It now advances to
``next_hour - 1 microsecond``. The registry continues to reject every canonical mutation at or
behind its watermark.

Independent review found no P0/P1 and reconstructed exact tree ``1983008d``. The focused lifecycle
and scale-harness cohort passes 76/76, scoped Ruff and format checks pass, and the default 14-case
smoke profile completes with ``errors=[]`` and ``failed_gates=[]``. A two-hour 1/4/8-worker and
two-``PYTHONHASHSEED`` matrix is byte-deterministic. The live production integration census now
passes 71/72 across lifecycle authority, service lifecycle, endpoint effects, timing wiring,
deployment assignment, and collection deployment. Its sole failure is the existing RDP
deferred-session network root reaching lifecycle materialization without the exact session
authority; that handoff is the next lifecycle production blocker.

### Runtime-cache owner publication made atomic

Commit ``5845162ba`` (``fix: make runtime cache publication atomic``) closes the
SourceTiming-owned ``BoundedRuntimeCache`` record/deadline split without importing unrelated
dirty-live retention work. One owner ``RLock`` now serializes public mutation and observation.
Fresh insertion, replacement, and redeadline either publish the compact primary record, packed
deadline, payload-byte counter, and public high-water state together or restore their exact logical
preimage before propagating the primary failure. Failure repair performs bounded primary/deadline
compaction so repeated rejected installs do not retain duration-sized stale state.

The independently reconstructed clean candidate has parent ``aea2dde87``, tree
``d4ed9ca5``, and exactly two paths: the cache owner plus a dedicated atomicity test file.
Independent review found no public-boundary P0/P1. The dedicated and existing clean cache suites
pass 18/18, the available clean SourceTiming suites pass 67/67, and the live composition passes
141/141 across cache, preparation, action-cohort, and scale-census coverage. Tests cover
fail-before-primary, fail-after-primary, fail-after-deadline, fresh/replacement retry, redeadline,
eight-worker concurrency, exact counters, and seven-day versus 30-day failed-install retention.
Ruff, format, diff, and pre-commit gates are green. The pre-existing live TLS retention inventory
hunk remains unstaged and version artifacts remain unchanged. The post-commit current-live
14-case enforced smoke also completes with ``errors=[]``, ``failed_gates=[]``, one stable
implementation revision, and report SHA-256
``627721276ebc1de883199b0b94a87607e6b882633bf0f7f9c9329e747364f914``.

### Intent and execution-effect expected receipts landed

Commit ``2678ad09b`` (``feat: authenticate intent and effect cohort receipts``) adds the
public composite-commit boundary needed by the production action-cohort dispatcher. Intent
execution batches and execution-effect audit cohorts now precompute an exact expected receipt
while claimed, authenticate that prospective receipt separately from terminal publication, bind
certification to the exact preparation and claiming thread, and replay only the frozen commit plan
after certification. Public mutation fences prevent stale same-owner writes while a claim is
active, and the existing bounded preparation/claim capacities and cleanup paths remain intact.

The Intent terminal distinction is explicit: a prospective or aborted receipt cannot authenticate
as committed. A terminal HMAC proof is precomputed in the private plan and installed on the exact
receipt only after canonical aggregate, watermark, hot-cache, reservation, and stale-ticket replay
has completed. A copy made before commit remains permanently nonterminal; the exact returned
receipt and a copy made after commit authenticate. The execution-effect audit owner already
maintained this prospective-versus-terminal distinction and now exposes the matching expected-
receipt authentication and certification surface.

Independent public-threat review found no P0/P1. The exact four-path candidate has parent
``5845162ba`` and tree ``eb22074d``; its clean intent/audit/command cohort passes 140 tests with one
expected skip, plus Ruff, format, compile, and diff checks. The shared commit reconstructed that
tree exactly by applying the reviewed patch to the index only, leaving the broader live integration
files byte-for-byte unchanged. The richer live overlay then passed 202 tests with one expected skip
across all six intent, audit, and command-effect suites. Private closure-cell, descriptor,
class-monkeypatch, and frozen-object mutation hardening remains outside the approved threat model;
the remaining prerequisite work is the minimal public State transaction lane and bounded,
``O(delta)`` SourceTiming claim boundary.

A fresh clean clone of ``2678ad09b`` also completed the enforced 14-case foundation smoke with
``errors=[]``, ``failed_gates=[]``, a clean and stable repository revision, and all requested smoke
size/duration/isolation coverage. The revision-bound report is
``/private/tmp/foundation-smoke-2678ad09b.json`` with SHA-256
``107a4e1bd0962ddd7405dcbf946763f338b7bf256fac8dda390fe5e743af2c99``. This smoke run did not claim
exhaustive million-row, seven-/30-day, multiworker, or multi-hash-seed certification. Those
historical harness diagnostics are not current or future acceptance criteria.

### SourceTiming public composite boundary landed

Commit ``9b28fafd3`` (``fix: bound source timing composite publication``) replaces the rejected
whole-registry clone and private-reflection hardening attempts with the approved public transaction
boundary. A single planner/runtime admission lane excludes supported concurrent and same-thread
mutations while a preparation is claimed. The claimed plan retains only staged cache, audit, and
clock deltas, authenticates an exact thread-bound expected receipt, and performs a bounded
validation-free primitive tail after one-shot certification. Public audit and clock inputs are
validated before primitive publication, abort and seal failures release both lanes, terminal
capabilities discard staged payloads, and owner bookkeeping is bounded without scanning retained
registries.

Independent public-threat review found no P0/P1. The frozen five-path candidate has original parent
``5845162ba`` and tree ``9bdbbad9``; its staged blobs were reproduced exactly on the current branch
while all unrelated live worktree bytes remained unchanged. The committed revision passes 96/96
SourceTiming, preparation, action-cohort, and scale-census tests in a fresh clean clone, plus Ruff,
format, pre-commit, and diff checks. Version artifacts remain unchanged. The remaining critical
owner prerequisite is the State public transaction lane; production lifecycle composition must
then authenticate and certify this exact SourceTiming receipt before entering its wider no-fail
publication tail.

### DNS client-cache publication made transactional

Commit ``34de4ccd5`` (``fix: publish DNS cache after transport``) moves the client-visible DNS
address cache write after the canonical UDP/53 transaction has returned a nonempty UID. An ordinary
transport exception or rejected empty transaction now leaves the cache and rendered DNS evidence
neutral, so an exact retry is not suppressed by a phantom cache hit. Once the address transaction
has published, the cache is committed before optional companion questions; a later companion fault
therefore cannot duplicate the already-published address lookup on retry.

Independent review reproduced the old poisoned-cache behavior on the exact parent, found no
public-boundary P0/P1, and matched the candidate and committed patch IDs exactly. The clean committed
revision passes the focused rollback/retry node and 72 causal/proxy adjacency tests; the candidate's
broader 151-pass DNS/causal/proxy cohort retained the same two exact-parent failures. The full clean
DNS file likewise has an identical seven-node inherited failure set on parent and candidate.
Pre-commit, Ruff, format, and diff checks pass for the committed paths, unrelated live generator
and test bytes remain unchanged, and version artifacts are untouched.

The repaired execution/effect bridge is also independently commit-clear but remains queued behind
the State/lifecycle/dispatcher owner foundation. Its exact four-path chain closes File/Registry
multi-occurrence cardinality, equal-time identity, latest process/session frontiers, artifact-group
atomicity, and the prior scanner and State-only-session regressions. Scanner transport aggregation
itself remains a later execution-family milestone.

### Lifecycle SourceTiming publication certified

Commit ``9cada8072`` (``fix: certify source timing in lifecycle publication``) wires the public
SourceTiming expected-receipt contract into the production lifecycle coordinator. The coordinator
now captures the exact prospective receipt while the preparation is claimed, authenticates and
one-shot certifies it before entering the wider State, lifecycle, application, runtime, or timing
publication tail, then requires ``commit_no_fail`` to return that same object and authenticates its
terminal form before issuing the outer receipt. Failure before or during certification leaves every
owner neutral.

Independent review found no public-boundary P0/P1. The exact two-path candidate passed 126 focused
SourceTiming/caller tests and 277 adjacent lifecycle, State, and runtime tests. Its exact-parent
negative control reproduced the former split: rejecting the expected timing receipt after the other
owners had published left State/RNG and lifecycle transport residue. The committed ordering rejects
that failure before any canonical mutation. Ruff, format, diff, and cleanup gates pass; version
artifacts remain unchanged.

### State public composite transaction boundary landed

Commit ``3334dc705`` (``feat: add State composite transaction boundary``) supplies the remaining
public owner prerequisite for dispatcher action cohorts. Exact manager-owned capability records bind
the prepared object, manager, thread, plan, RNG, version, State time, and admission epoch. One unified
prepared-State lane excludes supported concurrent and same-thread mutations, copied or replayed
simple/composite tickets are revoked at terminalization, and touched preimages plus retention victims
are rolled back in ``O(delta)`` without restoring unrelated State.

Two independent-review blockers were repaired before landing. A post-certification apply or finalize
validation failure now consumes the exact ticket, so restoring a drifted preimage cannot revive it.
Every public capability-producing State builder, cursor, planner, and finalizer is also lane-fenced
and epoch-bound, preventing a capability minted from provisional State from surviving rollback plus
version/time/counter ABA realignment. Independent rereview found no P0/P1; the final exact two-path
tree passed 186 scoped State tests and a 318-node wider selection whose eight failures reproduced on
the exact parent. The committed-current State/action/lifecycle cohort passed 216/216, with repository
Ruff/format, compile, and diff checks green. Arbitrary direct mutation of compatibility read objects
remains outside the approved public-method threat model. Version artifacts remain unchanged.

The dispatcher action-cohort production coordinator and exact artifact-publication group subsequently
landed as commits ``dc595983b`` and ``a7a6cb01d``. The retained execution/effect bridge therefore
depends on those committed owners and must not replay or reconstruct another dispatcher foundation.

### Exact sink publication core and Bash/Snort adapters landed

Commit ``f6e9d3f96`` (``feat: add exact sink publication core``) supplies the bounded in-process
publication authority, immutable prepared rows, stable commit/release cursors, participant fences,
and retry-aware direct, host, Zeek, and external-sorted writer paths. Commit ``24520c45`` adds the
Snort adapter, and commit ``670b38432`` adds Bash history plus the combined adapter regression
matrix. The final four-path adapter tree is ``08fd42c8`` with reviewed patch SHA-256
``57682777...``; both production postimages remain byte-identical to their independently reviewed
source commits.

The adapter composition passes 116 Bash, 80 Snort, and 251 combined/IDS tests, plus focused
hash-seed, race, migration, lint, format, compile, and diff gates. Two wider IDS integration nodes
fail identically on the exact pre-composition tree and remain inherited. The integration branch
also reran the combined 251-node gate successfully. Version artifacts remain unchanged.

SQLite remains a temporary emitter-private implementation detail rather than a product database.
Snort already used a temporary candidate spool; exact Snort and Bash now use bounded, parameterized
SQLite journals in owner-only private spool directories for same-process lost-return recovery.
Ordinary Bash generation does not create a spool or open SQLite. These journals are removed after
terminal export/release, provide no external service, and do not claim interpreter-restart resume.

Windows Security and Sysmon cannot use per-event exact preparation because their immutable bytes do
not exist until the complete source cohort is sorted, record IDs are assigned, routing is fixed, and
Sysmon GUID/time synchronization finishes. The selected prerequisite is a caller-owned terminal
``SourceFinalizationEpoch`` above the unchanged exact core. ``GenerationEngine._finalize`` owns the
EOF completeness fence and one run authority; each source owns bounded candidate/final journals and
sealed immutable rows; exact child batches publish bounded chunks sequentially. The first landable
slice is Windows Security through the real engine boundary, using its existing spool foundation;
Sysmon follows only after that path is independently proven.

This choice guarantees exact terminal source publication and same-process retry. It deliberately
does not promise process-restart recovery or retroactive per-action atomicity between already-
committed canonical state and final Windows/Sysmon file bytes. If either stronger guarantee becomes
mandatory, stop before presenting the terminal epoch as sufficient and design the larger
authenticated watermark/deferred-row contract instead.

### Windows Security terminal source publication landed

Commit ``2facf92b9`` (``feat: finalize Windows source publication exactly``) implements the first
caller-owned terminal ``SourceFinalizationEpoch`` through the real ``GenerationEngine`` EOF
boundary. Windows candidate admission is bounded before in-memory or threaded retention, sealing
freezes global order, record IDs, routing, output target, header, footer, and final rendered bytes,
and one engine-owned publisher commits bounded exact-string chunks through the existing final
writers before durably checkpointing and releasing each child. Default rooted XML, Splunk, and
SOF/Snare bytes remain identical to the immutable parent across threaded/non-threaded buffer shapes
and multiple Python hash seeds.

The exact Windows path uses an owner-private temporary SQLite journal only during the
``eforge generate`` command. The journal is parameterized, bounded, descriptor-confined, mode
``0700``/``0600``, configured with in-memory SQLite temporary storage, and removed after terminal
footer and cleanup.
Direct/non-engine Windows use retains the legacy portable path. The contract remains same-process
retry only and adds no service, persistent product database, restart recovery, or LLM call.

Engine retry state now owns initialization, generation, EOF finalization, and emitter-close
progress explicitly. Concurrent or reentrant ``generate`` calls fail closed; partial initialization
and failed-generation cleanup can be retried without regenerating the body; progress callbacks
cannot skip cleanup; IDS totals apply once; and the exact emitter name-to-object cohort is pinned on
its first close attempt so stopped emitters are never closed twice and failed identities cannot be
replaced before retry. The final independently reviewed five-path patch has tree ``d607fb110`` and
binary diff SHA-256 ``21ea45d59da4ba393d6c70fdfc76dec17adb67245a027971c3d6abb106824466``.
Focused acceptance passes 47/47, the adjacent Windows/engine cohort passes 287/287, three hash-seed
runs produce the same default XML digest, and repository Ruff/format/diff checks are green.
After fast-forward integration, the exact core, sorted writer, ASA/eCAR, Bash, Snort/IDS, and Windows
source-finalization composition passes 417/417 on the integrated tree.

### Sysmon terminal source publication landed

Commit ``b68e53a7a`` (``feat: finalize Sysmon source publication exactly``) adds the second
engine-owned terminal source without changing the shared epoch, exact core, engine finalization,
Windows adapter, or host writer. Sysmon exact mode is enabled only by ``GenerationEngine``;
direct/non-engine construction remains on the legacy path. Candidate admission detaches typed JSON
and charges rows and UTF-8 bytes before FIFO or Python retention. The private owner-only temporary
SQLite journal is bounded, parameterized, descriptor-confined, and removed after terminal cleanup.

Terminal seal preserves the legacy cohort algorithm exactly: compatibility causal shifts update
the pre-sort keys; one stable ``(sort_key, insertion_sequence)`` order is frozen; per-host time and
EventRecordID state advances once without a second sort; UTC, follow-on, and ProcessGuid references
are synchronized over that same order; and only then are final routed strings sealed. Intermediate
and final payload growth share the source cap, retry-local clock/ID/GUID state is adopted only after
the seal commit is durable, and the existing final writers publish bounded chunks before the source
checkpoint advances and the exact receipt releases.

Independent review found no P0/P1/P2. The exact three-path commit has tree ``38000b04b`` and binary
diff SHA-256 ``f1182a9d31025f60efb523bb91a058f6e9253e96df742c55f62fea536523aebd``.
Focused Sysmon acceptance passes 39/39 under three hash seeds; adjacent Sysmon/engine/output-target
coverage passes 209/209; and the Windows/exact-publication composition passes 275/275 before
integration. The integrated exact core, sorted writer, ASA/eCAR, Bash, Snort/IDS, Windows, and
Sysmon publication cohort passes 456/456, followed by the integrated adjacent Sysmon matrix at
209/209. Default XML, Splunk, and SOF/Snare remain byte-identical to the immutable parent.

Windows Security and Sysmon now both satisfy the selected terminal EOF publication milestone with
same-process retry. The contract still does not claim interpreter-restart recovery or retroactive
per-action atomicity between committed canonical state and terminal source files; either stronger
requirement still needs the larger authenticated watermark/deferred-row design.

### Process execution/effect bridge landed

Commit ``f8fc76587`` (``feat: reconcile process execution effects exactly``) lands the queued
four-path process execution/effect bridge after the already-committed artifact-group and dispatcher
action-cohort owners. The generator now plans process-owned File and Registry effects before root
allocation, binds every realized occurrence to one stable ordinal/time identity, advances the exact
process and live-session activity frontiers to the latest admitted effect, and publishes the root,
all effect rows, and deduplicated local-artifact tokens through one dispatcher cohort. Required
artifact failure and cardinality overflow reject before State, lifecycle, timing, audit, artifact,
or emitter mutation.

The dispatcher relaxes multi-occurrence cardinality only for exact typed File and Registry intents.
It authenticates every per-ordinal provenance key, actor, lifecycle, member order, completion time,
and covering State frontier. Network effects remain single-occurrence on this boundary. Scanner
transport aggregation remains on its legacy publication path: unsupported scanner multi-occurrence
plans reject before mutation, while ordinary Linux nmap retains its post-parent-resolution foreground
close sampling and full probe publication.

Independent review found and closed two integration-specific P1s before the bridge was frozen. All
fallible constructor compatibility checks now precede dispatcher lifecycle, artifact, and effect-audit
binding, so a rejected owner combination leaves an exact retry neutral. The Linux scanner adapter also
retains the current-parent foreground finalizer rather than applying the strict pre-allocation close
requirement intended for File/Registry action cohorts. The final exact four-path patch has tree
``65032228`` and binary diff SHA-256
``8725844a40119373449b5ad913a3d7649f2bc30ea1f009913c4664a79f96f065``; the independent reviewer
returned CLEAR with no P0/P1/P2/P3.

Commit ``10c3301e6`` (``test: align activity execution-effect contracts``) is a separately reviewed
one-file compatibility migration. Five legacy tests now patch the bridge-owned deterministic
endpoint-effect RNG, create Linux parents through the lifecycle owner, assert allocation-free
``INVALID_ACTOR`` rejection after an authoritative session close, and inspect registry materialization
at its new allocation-free planning seam, including the exact occurrence timestamp argument. This
keeps the production bridge review at its approved four paths instead of silently expanding it.

Integrated gates pass 49/49 focused bridge tests, 524/524 State/lifecycle/content/action-cohort
adjacent tests, 5/5 migrated activity contracts, and 314/314 exact-publication plus Windows/Sysmon
terminal-source tests. The deterministic/RNG/census selection is 9/12; its Windows SMB missing
``open_smb_session`` failure and two Linux SMB LogonID-reuse failures reproduce unchanged on the
exact parent. The full activity file is 429 passed with the same 11 inherited failures. Repository
Ruff, 643-file format, compile, and diff checks are clean. This bridge introduces no SQLite or other
database path; temporary SQLite remains confined to the previously documented exact sink and
terminal source-finalization implementations.

### Type-5 service-logon exact projection landed

Commits ``4b71ab757`` (``feat: add exact Windows candidate admission``), ``5e052c297``
(``feat: recover exact action projections``), ``bde33c64a``
(``fix: drain exact projections before emitter close``), and ``ad2611061``
(``feat: publish service logons exactly``) close the bounded Type-5 service-logon projection
milestone. Every configured Windows Security and eCAR target is now prepared before canonical
mutation. The dispatcher retains one authenticated, bounded exact batch and its commit/release
cursor across same-process lost returns, while the engine drains unresolved dispatcher recovery
before any emitter close on both successful and failed generation.

Built-in SYSTEM, LOCAL SERVICE, and NETWORK SERVICE logons publish distinct successful
``authentication_occurrence`` identities with their well-known LUIDs and no fabricated State or
lifecycle session. Named service accounts publish exactly one State/lifecycle session, one stable
LUID, the Windows 4624/optional 4672 cohort, and the matching eCAR LOGIN row. Named cohorts also
record one deterministic zero-effect execution-audit plan. That audit entry intentionally changes
ground-truth audit metadata; equivalent source-native Windows and eCAR bytes remain identical to
the legacy renderer across retries, thread modes, and Python hash seeds.

Windows candidate admission reuses the existing bounded, owner-private temporary
source-finalization SQLite journal. It adds no product database, service, schema version, restart
recovery, or persistent state. Exact prepare reserves candidate capacity without inserting a row;
commit reconciles the reserved sequence/digest exactly once; release and terminal sealing retain
authenticated candidate ownership until the final source cohort is validated. The journal remains
an implementation detail of ``eforge generate`` and is removed at terminal cleanup.

Commit ``b6788b769`` (``fix: authenticate exact Windows abort publication``) closes the final
failed-generation boundary found by stacked review. A source-bound abort with released exact
candidates no longer clears their receipts and falls through legacy forced rendering. It
authenticates the raw marker rows, transactionally seals the partial cohort, and publishes each
immutable final row through the existing exact host-writer receipt before advancing the durable
cursor or retiring candidate ownership. Mid-render, writer, checkpoint, release, footer, and spool
cleanup fail-before or lost-return paths retain one same-process retry owner; public forced flush,
late admission, reconfiguration, barrier, and quiescence are fenced while that owner exists.
Ordinary no-receipt abort close keeps the legacy path unchanged.

Unknown service-account SIDs now use a bounded opaque reservation under a dedicated leaf lock,
never held across dispatcher or sink callbacks. Concurrent allocations skip reserved RIDs,
same-account tokens share one exact SID, foreign/stale/tampered tokens fail closed, and canonical
receipt proof installs the reserved mapping exactly once. Account-created 4720 generation owns the
same explicit-SID reservation before output; the prior direct storyline registry write is removed.
Pre-batch projection and SourceTiming failures cancel or prune every caller-owned preparation, so
the timing lane is immediately reusable.

Independent review returned CLEAR with no P0/P1/P2 on the final immutable slices. The integrated
tree passes 65/65 service-logon tests, 20/20 dispatcher recovery tests, 88/88 Windows exact-source
tests, 5/5 engine-drain tests, 15/15 SID/process tests, 6/6 adjacent account/storyline tests,
149/149 wider dispatcher/lifecycle tests, 168/168 engine/Windows/Sysmon tests, and 228/228 exact
publication tests. Two hash seeds times threaded/non-threaded generation pass 4/4; default, Splunk,
SOF/Snare, buffer, and threaded Windows parity pass 7/7. The full activity and storyline files
retain their exact-parent failure sets (429/440 and 75/79 respectively), with no new regression.
Repository Ruff, format, compile, and diff checks are clean.

The next dependency-ordered V2 milestone is the already-open SMB persistent-channel prerequisite
and production caller migration. Do not patch the removed legacy StateManager SMB methods back in;
route SMB authentication/tree/handle ownership through the prepared application-channel manager
and the now-proven auth/session projection boundary.

### Final verification scope and terminal-runtime review

On 2026-08-22 the exhaustive foundation scale matrix was explicitly and permanently removed from
the completion plan. It is not deferred, optional, or a future release gate, and it must not be
reintroduced through a comparable substitute matrix. Final verification instead uses the official
normal and slow release pytest suites, focused owner/regression and adversarial tests, config and
scenario validation, and two deterministic real generation/evaluation runs. These gates provide
integration confidence without claiming exhaustive cross-product scale certification.

The frozen terminal-runtime candidate completed its 68-case adversarial diagnostic with 68 passing
in 1,289.74 seconds. Its combined tracked/untracked digest remained
``7087003f893c7c1caf96f786722017dbaf065f3481fef8f4805dc311408cee0f`` and ``git diff --check``
remained clean. Independent review then found bounded owning-layer defects in TLS overlay duration
headroom, proxy runtime floors, machine-account logoff admission, sudo fail-before-mutation,
system-process source deadlines, failed-logon child deadlines, and terminal baseline family
selection. Those findings must receive focused regressions and a fresh exact-candidate review
before integration; the passing diagnostic is retained as pre-repair evidence, not final
certification.

### Terminal owner deadline closure integrated

Commit ``03d0b174f`` (``fix: enforce terminal owner deadlines``) integrates the repaired candidate
on ``codex/v2-family-integration``. Commit ``1c60b3f25`` separately records the permanent retirement
of the 161-case foundation scale matrix. No exhaustive or comparable substitute matrix is part of
the remaining release plan.

The integrated patch moves half-open generation-window admission to the owners of rendered truth.
Canonical network and baseline callers reserve source clock, observation, protocol, and
firewall/sensor teardown support; TLS and explicit-proxy bounds include automatic OCSP response,
DNS, and physical-leg children; SSH and RDP reserve cross-host clocks, observation delays, process
termination, dependent-to-logoff gaps, and transport close while preserving explicit-storyline end
identity and short-session behavior. Direct process generation and bounded wrapper owners reject
before allocating sessions, parent shells, PIDs, evidence, or cache state. Bounded polkit companion
processes reuse only an already-visible shell, treat PID zero as rejection, and schedule termination
only for a State-authenticated canonical process identity.

Independent exact-tree review returned CLEAR with no open P0/P1/P2 across the process, baseline,
SSH/RDP, and TLS/OCSP/proxy slices. The final reviews replayed 43 terminal process admission/runtime
cases; 21 decisive SSH/RDP deadline cases plus five adjacent cases; 73 baseline/caller-census,
transport, watermark, and Windows-runtime cases; 36 OCSP/proxy/schema cases; and 12 bounded polkit
cases. The OCSP direct-DNS/MX challenge ended its latest artifact 23.642 milliseconds inside the
exported family bound. Full owning-file follow-ups pass 50/50 RDP tests and 88/88 Phase 5
system-traffic tests; the original IDS integration reproduction also passes.

Repository-wide Ruff check and format check pass with 671 files already formatted. Project config
validation reports zero errors, warnings, or informational findings across 93 files. The
``scenarios/iteration-test/scenario.yaml`` schema and cross-references remain valid with the
scenario's existing advisory warnings. The official full normal pytest suite, the separately run
22-node slow suite, two deterministic generation/evaluation runs, and the final blind panel remain
to be executed from this clean integrated revision.

### Final release-gateway execution

The bounded release-gateway plan completed the official test evidence without reinstating the
permanently retired exhaustive foundation scale matrix or any comparable substitute. The normal
suite passed 10,087 tests with 49 skips and 10 warnings in 6,422.41 seconds. The consolidated
post-tail regression selection passed 3,112 tests with 22 skips and 10 warnings. The separate
22-node slow selection produced 20 functional passes and two explicit non-release skips. These
results supplement the focused owner/adversarial evidence above; no broad suite was rerun merely
to duplicate an already-green gate.

Two final real-generation failures exposed narrow terminal-window ownership gaps and were fixed at
their owning layers before the definitive bundles were produced:

- Same-hour authored storyline and red-herring entries now execute in nominal timestamp order, so
  a later storyline-owned RDP logoff cannot advance the lifecycle frontier ahead of an earlier
  red-herring RDP session. Authored RDP compatibility paths also receive an action-owned scenario
  deadline and reserve the complete source/transport close budget before mutation. The combined
  focused RDP regression selection passes 7/7, and independent review returned CLEAR with no
  P0/P1/P2 finding.
- Terminal organic Linux remote-administration SSH now reserves the WorldPlanner's full
  90-second post-activity support before bootstrap. An optional late candidate is skipped before
  State clock, session, or bundle mutation. The focused SSH selections pass 8/8 plus the dedicated
  production-caller regression, and independent review returned CLEAR with no blocker.

The definitive seed-42 bundle is
``/private/tmp/eforge-v2-final-a12.HrzaXo``. An independent repeat under
``PYTHONHASHSEED=99991`` is ``/private/tmp/eforge-v2-final-b1.Lxe3fn``. Each completed as an
authoritative 117-file bundle and occupies 46,464 KiB. A recursive comparison found every data,
artifact, ground-truth, resolved-scenario, collection, observation, storage, and artifact-manifest
byte identical. Only ``GENERATION_MANIFEST.json`` differs, and its sole diff is the expected
``created_at`` timestamp. Durable normalized manifest and data-tree digests are preserved in
``docs/design/realism-review/v2-family-foundations-final/generation-evidence.json`` so this proof
does not depend only on the temporary bundle paths.

The one planned automated evaluation ran against the authoritative A12 bundle and passed all hard
acceptance criteria: 88,187 records across 21 sources, overall score 96.89649234949579, and no
flags. Pillars were parseability 99.9876399015728, plausibility 96.90923695030301, causality
95.20215606567831, and timing 94.36176062514308. IDS integrity was 149/149, causal ordering
11,295/11,295, intent reconciliation 108/108, and event presence 44/46. Lower but non-blocking
diagnostic texture remains visible in pivot linkability, temporal coherence, and trace
completeness; it is recorded as follow-on realism evidence rather than converted into another
closure-time repair loop.

### Final blind assessment and plan closure

Four independent reviewers received only the common authenticity briefing, their own role, and the
A12 data directory. Their frozen verdicts and synthetic-confidence scores were Threat Hunter
Synthetic/66, Detection Engineer Synthetic/94, Network Forensics Inconclusive/47, and Host/EDR
Synthetic/96. Average verdict confidence was 90.25; average synthetic confidence was 75.75. That
is 6.25 points worse than this effort's immediate Loop 30 baseline at 69.5, while remaining 17.5
points better than the later post-P1-blockers checkpoint at 93.25. The result is mixed by comparator
and is not represented as a clean blind-improvement gate.

Verdict disagreement and the 49-point score spread triggered the protocol's one bounded
deliberation. After the endpoint evidence was cross-examined, all four final verdicts were Synthetic
with scores 85, 95, 78, and 97 (average 88.75). The facilitator preserved the network family's
strong result while concluding that widespread impossible Sysmon occurrence times, Windows
lifecycle/identity gaps, and post-termination eCAR module loads determine the whole-dataset verdict.
The independent initial average remains the trend measurement.

The complete reports, deliberation, canonical score artifact, prioritized improvements, and
automated-eval comparison are tracked under
``docs/design/realism-review/v2-family-foundations-final/``. The current V2 foundation plan closes
here: its official test, deterministic generation, automated acceptance, and fresh blind
measurement are complete under the bounded closure pivot. Concrete panel findings are preserved as
separate durable follow-on backlog; they do not open another closure-time assessment or repair loop.
External dev sync, push, and PR creation remain unperformed and require separate authorization.
Final repository Ruff lint and format checks, assessment-JSON validation, and ``git diff --check``
are green. The final read-only integration audit returned CLEAR after verifying the comparator
arithmetic, closure pivot, durable generation digests, intended commit scope, and late RDP/SSH seams.

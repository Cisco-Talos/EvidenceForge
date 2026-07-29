# Network Transaction and Observation Contract

## Status

Feature branch: `codex/network-transaction-observation-contract`

Base: `origin/dev` at `a0177422` after PR #356 merged. This work is divided into three
reviewable milestones. Each milestone receives focused verification plus an
`iteration-test-expanded` generation/evaluation and blind panel before the next milestone begins.

## Family Contract

### Owning abstractions

- The network-connection action bundle owns the canonical connection occurrence: tuple, outcome,
  phase anchors, connection state/history, duration, process ownership, and directional traffic
  accounting.
- Canonical `NetworkContext` and `StateManager` connection state own durable shared traffic truth.
- Network visibility and observation planning own the sensor-visible tuple, sensor identity,
  capture timing, packet loss, and source-local identifiers.
- The dispatcher owns final source-visible output-window admission using typed action lifecycle
  metadata.
- The explicit-proxy action bundle owns the client/proxy/DNS/origin phase graph and proxy byte
  semantics.
- Emitters own only source-native serialization of already-planned truth.

### Invariants

1. One finalized canonical ledger supplies payload bytes, packet counts, IP bytes, duration,
   state, and history to every consumer; action-generated fields are not independently mutated
   after finalization.
2. Lossless observations of one transaction retain identical accounting. NAT changes the visible
   tuple only. Counter divergence requires an explicit capture-loss decision with positive
   `missed_bytes`.
3. Sensor clocks and route delays are persistent scoped properties plus bounded capture jitter,
   not independently resampled broad offsets in emitters.
4. A fresh action group whose final source-visible start is outside the half-open output window is
   not rendered. Only typed closure evidence for a group that began before the end may trail past
   the window.
5. Proxy cache/deny/failure outcomes emit only phases that actually occurred. DNS and origin
   transport timing come from a conditional phase graph without a universal delay floor.
6. Proxy request/response body sizes and client/server transferred byte totals are distinct owned
   values.

### Entry paths

- Baseline and storyline calls to `ActivityGenerator.generate_connection()`.
- DNS, DHCP, SSH, RDP, browser, scanner, file-transfer, Kerberos, Windows remote-admin, and proxy
  action bundles that compose the canonical connection entrypoint.
- Causal prerequisite DNS and application-side-effect expansion.
- Persistent HTTP connections and explicit-proxy tunnel reuse.
- Direct canonical `SecurityEvent` construction used by focused tests and explicit low-level
  compatibility paths.

### Consumers

- Zeek conn/protocol/file emitters and their per-sensor multiplexer.
- Cisco ASA, Snort/Suricata, proxy, web, Sysmon, Windows Security, and eCAR FLOW renderers.
- `StateManager` open-connection/session/process lifetime checks.
- Source timing, observation policy, network visibility, NAT routing, eval parsers, hard probes,
  and blind network/host/detection/hunting review.

### Layer rationale

The repeated findings cross source and emitter boundaries, so no renderer can own the repair.
Connection truth must be complete at the action/context/state boundary; sensor-specific divergence
must be explicit at the routing/observation boundary; admission must happen only after final source
timing is known; and multi-connection proxy causality must stay in the higher proxy bundle.

### Sibling risks and exclusions

- Preserve source-native schema differences while removing invented semantic differences.
- Preserve valid endpoint attribution/lifetime clamps for SSH, RDP, Kerberos, and proxy paths.
- Keep direct test/raw events compatible when no canonical ledger or lifecycle metadata is
  supplied; they receive a validated compatibility projection rather than failing outright.
- Durable general-purpose thread, identity, role/activity, and session-bootstrap improvements are
  separate assessment families unless this contract directly owns the observed network evidence.

## Milestone Record

### Milestone 1 — Canonical transaction and ledger

Implementation and expanded-scenario acceptance complete:

- Moved the full connection orchestration body from `ActivityGenerator` into the action-owned
  `NetworkTransactionPlanner` without changing deterministic network behavior. The planner uses a
  mutable action-owned occurrence draft, freezes tuple, hostname, process ownership, phase anchors,
  outcome, state/history, interval, and accounting, and only then constructs `SecurityEvent`.
- Added immutable directional/bidirectional traffic ledgers and a finalized transaction plan.
- Finalized and validated action-generated `NetworkContext` truth immediately before dispatch;
  direct/raw compatibility contexts continue to project a read-only ledger on demand.
- Persisted the same ledger, interval, state/history, and duration in `OpenConnection`.
- Persistent HTTP application transactions reuse the parent's connection identity and accumulate
  its durable ledger. They reserve their prior logical request identity without opening shadow
  state, preserving the established deterministic RNG/ID stream.
- Added central invariant tests plus a non-sample IDS fan-out assertion.

Verification:

- Focused network/proxy/endpoint regression set: 332 passed, 1 skipped.
- Default suite: 4,918 passed and 19 skipped; the two initial failures were separately verified:
  the deterministic injection twin passed after preserving identity reservations, and the Splunk
  harness passed outside the restricted socket sandbox.
- Repository-wide Ruff lint and format checks passed.
- `iteration-test-expanded` generated 93,351 records and passed automated evaluation at
  95.83901668531391, exactly preserving the pre-milestone record count and score.
- The independent panel scored 82, 69, 87, and 76 synthetic confidence (78.5 average). Its two
  network-wide findings were the expected next contracts: emitter-owned per-flow sensor
  timing/accounting differences and the proxy's narrow multi-second DNS/origin delay. Strong
  transaction, protocol-parent, endpoint, TLS/certificate, and firewall joins were preserved.
- No contract-level regression required a repeated panel. The ignored assessment bundle is under
  `scenarios/iteration-test-expanded/blind-test/network-contract-milestone-1/`.

### Milestone 2 — Sensor observation and final-window admission

Implementation and expanded-scenario acceptance complete:

- Added immutable per-sensor observations after visibility routing. Each observation owns its
  sensor identity and path role, NAT-adjusted tuple, sensor-local UID/FUID values, clock-adjusted
  interval, visible formats, and loss-adjusted traffic ledger with explicit directional missed
  bytes.
- Extended data-driven observation profiles with stable sensor clock offset/drift, route delay,
  bounded per-event jitter, and capture-loss parameters, including an explicit `lossy_span`
  profile. Existing scenarios inherit the lossless default when no capture profile is specified.
- Made protocol siblings consume the same observation tuple, identity, interval, and accounting.
  Lossless and NAT-only mirrors now preserve canonical counters; only an explicit lossy profile
  may diverge, and it records positive missed bytes.
- Added typed lifecycle metadata and final dispatcher admission after source-native timing. Fresh
  groups starting outside `[start, end)` are suppressed, closure tails are retained only for
  groups that began in-window, nested children are admitted independently, and canonical state is
  still applied for suppressed warm-up/post-window actions.
- Moved ASA teardown timer/reason selection from its emitter into network observation planning.
  Embryonic connections now use the configured sensor timeout instead of a random per-row value,
  and short non-embryonic flows are no longer mislabeled `Conn-timeout`. Snort timestamps now
  retain the source-native six-digit fractional precision.

Verification:

- Pre-gate focused tests and the default suite passed; the latter reported 4,931 passed and 19
  skipped. After the panel-driven ownership correction, 124 focused tests passed and the complete
  default suite reported 4,933 passed and 19 skipped.
- Repository-wide Ruff lint and format checks passed.
- `iteration-test-expanded` generated 93,317 records and passed automated evaluation at
  95.63900732058868.
- The independent panel initially split 2–2 (48.0 average synthetic confidence). Required
  deliberation converged to 67.0 average with two Synthetic and two Inconclusive judgments. The
  reviewers independently confirmed identical lossless accounting, coherent NAT/path visibility,
  stable approximately 2 ppm sensor drift, and intact parent/fan-out joins.
- The only contract-owned defect was uniform ASA timeout synthesis in the renderer; it was fixed
  at the observation-planning layer and covered by focused regression tests. Scanner application
  fan-out and repetitive endpoint file/process noise were recorded as separate owning families,
  not patched in network rendering. No material contract rework required a repeated panel.
- The ignored assessment bundle is under
  `scenarios/iteration-test-expanded/blind-test/network-contract-milestone-2/`.

### Milestone 3 — Proxy phase and byte contract

Implementation and expanded-scenario acceptance complete:

- Added an immutable proxy transaction plan and data-driven resolver profiles. The proxy action
  bundle now owns a conditional phase graph covering client connect, request/CONNECT, policy/cache
  decision, optional DNS, origin transport, optional TLS, origin response, client flush, and close.
  Cache hits, denies, authentication requirements, misses/revalidation, and gateway failures emit
  only phases that occurred.
- Routed both client/proxy and proxy/origin legs through the canonical network contract and attached
  them as independently admitted children of the proxy action lifecycle. Planned prerequisite DNS
  uses the same parent action and preserves its explicit phase anchor.
- Split proxy request/response body sizes from transferred totals. Zeek HTTP renders body sizes;
  proxy access fields render transfer totals; the network ledger retains transport payload and IP
  accounting. CONNECT setup bytes are included exactly once in inspected-tunnel ledgers.
- Removed aggregate proxy egress delay and implemented the 65/32/3 resolver mixture. Visible,
  phase-bounded DNS/origin pairs have a fast majority plus a deterministic retry tail rather than a
  universal one-second floor.
- Corrected source-owned ordering defects exposed by blind review: Zeek HTTP and DNS now anchor to
  the finalized transaction interval; TCP IP-byte accounting cannot exceed modeled MTU capacity;
  machine-account logon/logoff endpoint evidence shares lifecycle identity; and proxy child FLOWs
  share one host-local source offset.
- Preserved higher-level phase anchors when endpoint process visibility is late. The network planner
  now drops unsafe process attribution on preserved bundle transports instead of moving transport
  truth behind a dependent proxy origin phase.

Acceptance history:

- The first milestone panel found 85 HTTP rows preceding their same-UID connection and three proxy
  setup byte overruns. Both were fixed at the Zeek source-timing and proxy-ledger owners.
- A repeated network review established DNS rows after short parent connections and 12 MTU
  accounting violations. DNS source anchoring and the canonical network ledger were corrected.
- Host review established orphan machine-account endpoint logout rows. Canonical machine-session
  lifecycle identity and eCAR projection were added; paired Windows lifecycles now have zero eCAR
  logout-only groups.
- A final pre-gate review found related proxy eCAR child FLOWs independently delayed. Group-coherent
  source timing removed 185/746 inversions; the last case exposed a canonical late-process shift and
  was eliminated by preserving the proxy bundle's transport anchor. The final corpus has 0/749
  origin-before-client proxy-host eCAR inversions.

Verification:

- Focused proxy/network/source-timing regression set: 270 passed.
- Complete default suite: 4,951 passed and 19 skipped.
- Repository-wide Ruff lint and format checks passed.
- Final `iteration-test-expanded` generation produced 83,122 records across 21 sources and passed
  automated evaluation at 95.91662287509753.
- Hard probes found zero HTTP and DNS protocol rows outside parent intervals, zero modeled-MTU
  accounting violations, zero proxy setup byte overruns, and no paired Windows/eCAR machine-session
  logout orphan.
- The bounded visible DNS-response-to-origin set contained 266 pairs: 255/266 (95.86%) below 250 ms
  and 11 above 500 ms.
- The final independent detection, network, host/EDR, and threat-hunting panel passed 4/4 after the
  required scope/semantics deliberation. Final synthetic-confidence scores were 24, 16, 6, and 24
  (17.5 average). No hard network transaction, observation, admission, or explicit-proxy
  contradiction remained.
- General process-lifecycle completeness and broader baseline/storyline texture were retained as
  separate improvement families rather than patched in this network/proxy milestone.
- The hash-verified acceptance bundle is under
  `scenarios/iteration-test-expanded/blind-test/network-contract-milestone-3/`.

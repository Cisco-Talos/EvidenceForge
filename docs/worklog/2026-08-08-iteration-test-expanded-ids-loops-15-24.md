# Iteration-Test-Expanded-IDS Assessment Loops 15-24

## Scope

Run ten iterative family-level realism assessment loops against
`iteration-test-expanded-ids`, continuing the existing benchmark after loop 14.
The scenario remains unchanged. New generated data and blind-review artifacts
are stored under `scenarios/iteration-test-expanded-ids/blind-test/loop-N/` in
this worktree; the pre-existing loops 1-14 in the primary checkout are treated
as read-only history.

## Loop 15 Baseline

Because the generator changed substantially after the previous assessment, loop
15 begins with fresh generation and a standalone blind panel. No prior-loop
finding is carried forward into target selection.

## Loop 15 Baseline Outcome

- Generated 86,744 records; automated evaluation passed at 96.27780948253039
  with exact IDS integrity at 213/213.
- Standalone blind scores were Threat 79, Detection 69, Network 65, and Host 94;
  average 76.75 (`likely synthetic`). All verdicts were Synthetic, so no
  deliberation ran.
- The highest validated next contract is Linux APT process ownership: 72 APT
  method helpers across seven hosts were rendered as direct PID-1/systemd
  children rather than children of an APT frontend.

## Loop 16 Family Contract

- **Selected family:** Debian APT frontend and transport-method process ownership.
- **Finding classification:** `new_family` hard contradiction.
- **Owning abstraction:** canonical Linux system connection-owner process planning.
- **Invariant:** every modeled `/usr/lib/apt/methods/http*` helper must have a
  live `/usr/bin/apt-get` frontend parent created first on the same host. The
  frontend remains systemd-owned; helpers never attach directly to PID 1.
- **Entry paths:** explicit-proxy package traffic, direct high-confidence package
  connections, background package refreshes, and HTTP/HTTPS method siblings.
- **Consumers:** canonical process state, eCAR PROCESS/FLOW, proxy/Zeek joins,
  lifecycle finalization, and endpoint blind review.
- **Layer rationale:** the impossible parent is created when canonical process
  ownership is materialized, before eCAR rendering. The renderer is exposing
  supplied truth correctly.
- **Sibling risks:** cover both `http` and `https` helpers, frontend reuse only
  while active, ordering before the helper, and unchanged DNF/YUM ownership.

## Loop 16 Outcome

- Commit `490e363b`; full suite 5,077 passed and 41 skipped; Ruff passed.
- Rendered probe: 62/62 helpers had a visible preceding `apt-get` parent; zero
  direct PID-1 helper ancestry remained.
- Automated evaluation passed at 96.47643566860552 over 87,468 records.
- Blind scores were 83/88/72/95, average 84.5. The direct parent defect was
  fixed, but the new frontend lacked a bounded serialized lifecycle and exposed
  APT-to-DNF state mixing. Loop 17 remains on the package-manager family to fix
  this latest-change regression before selecting an unrelated target.

## Loop 17 Family Contract

- **Selected family:** serialized package-manager frontend lifecycle and
  distro-native state effects.
- **Finding classification:** `exact_regression` plus `sibling_defect` from loop 16.
- **Owning abstraction:** canonical Linux package-manager process lifecycle;
  data-driven EDR package-state profiles.
- **Invariant:** a host has at most one visible APT frontend transaction at a
  time; helpers extend that transaction briefly, and the frontend terminates
  after its last helper. APT/dpkg write only Debian state, while DNF/YUM/RPM
  write only RPM state.
- **Entry paths:** proxy/direct APT HTTP and HTTPS helpers, repeated repository
  requests, foreground package commands, and generic file side effects.
- **Consumers:** process state, eCAR PROCESS/FLOW/FILE, lifecycle probes, config
  validation, and endpoint/detection review.
- **Layer rationale:** transaction concurrency and closure belong to canonical
  process lifecycle state; path enumerables belong to config. Renderers own
  neither fact.
- **Sibling risks:** helper fan-out must reuse a still-live frontend, requests
  after closure must create a new frontend, parent termination must follow all
  children, and RPM-family behavior must remain unchanged.

### Loop 17 rendered-data closure

The first post-commit hard probe caught a second entry path before blind review:
explicit-proxy repair materialized APT method helpers as system connection owners
without registering their one-shot finalizers. Those helpers were closed only by
later lifecycle cleanup, stretching both helper and parent intervals for hours.
The family fix now registers bounded helper closure at the canonical system-owner
boundary and extends the serialized APT frontend just beyond its last helper.
The next rendered probe exposed a higher-priority consumer of the same state:
hourly stale-process cleanup ignored registered foreground deadlines and replaced
them with its generic 30-minute-to-hours policy. Stale cleanup now consumes the
canonical bounded deadline when present, and out-of-order generation anchors a
deadline to the actual process start rather than an earlier intent timestamp.

## Loop 17 Outcome

- Commits `eba43cd9`, `ed2e4d80`, and `318dfe59`; final full suite 5,082 passed
  and 41 skipped; Ruff passed.
- Rendered package probe: 45/45 APT frontends paired, 109.884-second maximum,
  zero intervals over 180 seconds, zero overlaps, zero helper-parent errors, and
  zero APT-to-DNF state writes.
- Automated evaluation passed at 95.88584018050257 over 89,215 records with
  exact IDS integrity at 233/233.
- Initial blind synthetic-confidence scores were 28/72/79/92, average 67.75.
  Verdict disagreement triggered deliberation, which ended unanimously Synthetic
  at average synthetic confidence 83.5.
- Highest-impact new defect: HTTP transaction timestamps reverse `trans_depth`
  within nine UIDs and change request order across two matched sensor views.

## Loop 18 Family Contract

- **Selected family:** ordered HTTP transaction timing across source observations.
- **Finding classification:** `new_family` hard contradiction.
- **Owning abstraction:** canonical HTTP persistent-connection transaction order
  plus `SourceTimingPlanner` sensor clock/observation timing.
- **Invariant:** within a sensor, HTTP/1.x rows for one UID are monotonic by
  `trans_depth`; all sensors observing the same TCP stream preserve the same
  request order. Sensor offset, drift, and latency may alter absolute timestamps
  but never reorder packets or requests.
- **Entry paths:** browsing-session multiplexing, explicit proxy HTTP, storyline
  HTTP, repeated persistent connections, and per-source observation delay.
- **Consumers:** Zeek HTTP rows, paired core/DMZ views, connection intervals,
  HTTP/file fan-out, evaluator probes, and network-forensics review.
- **Layer rationale:** HTTP emitters correctly expose supplied timestamps; request
  sequence is canonical transaction truth and sensor clocks are source-timing
  truth. Independent record jitter at rendering time cannot safely own either.
- **Sibling risks:** preserve legitimate missing rows without changing later depth
  order, retain absolute sensor clock texture, keep rows inside connection bounds,
  and avoid forcing identical UIDs or timestamps across independent sensors.

## Loop 18 Outcome

- Commit `04eb354c`; full suite 5,084 passed and 41 skipped; Ruff passed.
- Automated evaluation passed at 96.13584007989348 over 89,215 records with
  exact IDS integrity at 233/233.
- Hard probe: zero cross-sensor request-order mismatches across 38 paired
  multi-transaction streams; all 38 retained sensor-specific timestamps. One
  same-stream depth inversion survived on a lossy flow because canonical
  connection-start jitter can still reorder requests before sensor projection.
- Initial blind scores were 28/73/68/93, average 65.5. Deliberation removed a
  factually incorrect Linux-syslog absence claim and ended unanimously Synthetic
  at average 73.75.
- Highest-impact next family: fleet maintenance and management-agent lifecycle
  modeling, independently identified by threat, detection, and host reviewers.

## Loop 19 Family Contract

- **Selected family:** stateful fleet maintenance and management-agent lifecycle.
- **Finding classification:** `new_family` distribution texture and contract gaps.
- **Owning abstractions:** baseline maintenance scheduling, canonical system
  process/action lifecycles, role-aware registry state, and data-driven job profiles.
- **Invariant:** successful package refreshes suppress immediate repeats; retries
  require a modeled failure or lock. Group Policy, registry updates, and health
  checks must be owned by a recognizable timer/task/service/agent and change
  state only when appropriate for the host role.
- **Entry paths:** Linux APT timers and unattended-upgrades, Windows Group Policy
  refresh, scheduled health checks, service workers, and baseline registry noise.
- **Consumers:** eCAR process/file/registry records, Windows Security and Sysmon,
  Linux syslog, network/proxy evidence, evaluator probes, and endpoint/detection
  blind review.
- **Layer rationale:** fleet cadence, product ownership, retry state, and role
  selection are generation/planning truth. Emitters should render those facts,
  not independently invent or suppress repeated activity.
- **Sibling risks:** retain legitimate failure-driven retries, serialize package
  managers, preserve source-local observation loss, avoid removing useful
  maintenance diversity, and keep existing process/session lifecycle invariants.

## Loop 19 Outcome

- Commit `294d2c80`; full suite 5,089 passed and 41 skipped; Ruff passed.
- Automated evaluation passed at 96.17321730394976 over 86,721 records with
  exact IDS integrity at 221/221.
- Fleet probe: four APT frontends across four hosts; six non-forced Group Policy
  refreshes; 134 paired Windows health checks with 55.498-second maximum; one
  repeated non-DHCP registry-state tuple.
- Initial blind scores were 22/84/71/91, average 67.0. Deliberation corrected a
  false Linux-syslog absence claim and ended unanimously Synthetic at average
  synthetic confidence 92.25.
- Highest-impact new defect: all 1,090 ASA dynamic translation builds follow the
  connection build that already consumes the translated tuple.

## Loop 20 Family Contract

- **Selected family:** ASA NAT and connection transaction ownership.
- **Finding classification:** `new_family` hard contradiction.
- **Owning abstraction:** Cisco ASA source-native firewall transaction rendering.
- **Invariant:** a dynamic translation allocation (`305011`) precedes the
  connection build (`302013`/`302015`) that consumes its mapped tuple; connection
  teardown (`302014`/`302016`) precedes translation release (`305012`).
- **Entry paths:** inside-to-outside and DMZ-to-outside dynamic PAT for TCP and
  UDP, canonical firewall observations, explicit-proxy egress, and storyline or
  baseline connections traversing the perimeter firewall.
- **Consumers:** Cisco ASA logs, ASA parser/evaluator, NAT integration tests,
  detection review, and SIEM stateful correlation.
- **Layer rationale:** canonical NAT context already owns the translated tuple;
  the defect is the source-native order in which one emitter renders the two
  records. No upstream identity, timing, or routing truth needs to change.
- **Sibling risks:** static NAT must remain configuration state without per-flow
  xlate churn; denies must not allocate translations; UDP ordering must match TCP;
  and connection/xlate teardown order must remain dependency-compatible.

## Loop 20 Outcome

- Commits `20f08d56` and `2ed74a5d`; full suite 5,092 passed and 41
  skipped; Ruff and config validation passed.
- Rendered probe: 1,107/1,107 translation allocations preceded their matching
  connection build and all releases followed the connection close. The probe
  caught and fixed nine SYN-timeout sibling releases before blind review.
- Automated evaluation passed at 96.17321730394976 over 86,721 records with
  exact IDS integrity at 221/221.
- Initial blind scores were 22/32/71/91, average 54.0. Deliberation ended
  unanimously Synthetic at 72.5, with final scores 63/67/77/83.
- Highest-impact next defect: independent per-flow core/DMZ sensor timestamp
  jitter produces nonphysical relative-clock scatter on nearby clean packets.

## Loop 21 Family Contract

- **Selected family:** sensor clock and packet-time coherence.
- **Finding classification:** `new_family` physical distribution defect.
- **Owning abstraction:** `NetworkObservationPlanner` source clock projection
  plus data-driven network observation timing profiles.
- **Invariant:** all records from one sensor use one clock function composed of
  stable offset, bounded drift, slowly varying clock wander, and stable path
  delay. Transaction identity must not independently perturb packet time.
- **Entry paths:** all canonical TCP/UDP/ICMP connections, protocol-child fan-out,
  dual-sensor paths, explicit proxy traffic, and IDS/firewall observations.
- **Consumers:** Zeek connection/protocol logs, Snort correlation, ASA timing,
  connection intervals, and cross-sensor forensic matching.
- **Layer rationale:** canonical packets already have ordered times; only the
  source-observation projection owns how each sensor clock transforms them.
- **Sibling risks:** preserve distinct sensor offsets, HTTP transaction order,
  DNS RTT containment, start/close duration, loss accounting, and deterministic
  path-specific timing without making sensor timestamps identical.

## Loop 21 Outcome

- Commit `dc4d519c`; full suite 5,093 passed and 41 skipped; Ruff and all
  87 config validations passed.
- Clock probe across 1,943 matched flows: 41-66 ms relative offsets, all one
  sign, 6.13 ms six-hour population deviation; specialist linear fit found
  about 1 ppm drift and about 1 ms residual deviation.
- Automated evaluation remained 96.17321730394976 over 86,721 records.
- Initial blind scores were 22/33/74/91, average 55.0. Deliberation ended
  unanimously Synthetic at 70.5, final scores 61/64/75/82.
- Highest-impact next defect: 187 clean matched one-datagram sensor pairs differ
  by symmetric one-byte payload changes with unchanged packet/content semantics.

## Loop 22 Family Contract

- **Selected family:** packet-derived dual-sensor traffic accounting.
- **Finding classification:** `new_family` near-hard physical contradiction.
- **Owning abstraction:** `NetworkObservationPlanner` capture-loss projection.
- **Invariant:** passive no-loss views of the same datagram retain identical
  directional payload/IP byte and packet totals unless an explicit packet-level
  loss or middlebox transformation is modeled with corresponding semantics.
- **Entry paths:** UDP DNS, ICMP, NTP/DHCP datagrams, TCP streams, and all
  multi-sensor canonical connections.
- **Consumers:** Zeek conn/protocol logs, IDS correlation, file byte envelopes,
  and cross-sensor forensic matching.
- **Layer rationale:** capture-loss projection owns sensor counter differences;
  emitters correctly render the frozen ledger. The current ledger lacks a
  packet sequence capable of representing whole-datagram loss safely.
- **Sibling risks:** retain TCP loss/missed-byte texture, never fabricate partial
  UDP/ICMP payload mutation, preserve packet/IP-byte arithmetic, and avoid
  suppressing protocol children without a modeled whole-packet observation.

## Loop 22 Outcome

- Commit `0e75af19`; full suite 5,094 passed and 41 skipped; Ruff passed.
- The hard probe matched 1,943 dual-sensor flows. All 809 clean datagram pairs
  retained identical counters, with zero symmetric one-byte mutations. A second
  ICMP-aware review confirmed all 1,702 clean equal-packet pairs agree.
- Automated evaluation passed at 96.22321730394975 over 86,721 records, with
  221/221 IDS integrity checks passing.
- Initial blind scores were 22/32/23/91, average 42.0. Deliberation ended Real
  by a 3-1 vote at 39.5, final scores 30/35/27/66.
- Highest-impact next defect: Windows server HTTP ownership creates 134 short,
  overlapping `service-healthcheck.exe` workers with target-specific command
  lines, including traffic better owned by native Windows update services.

## Loop 23 Family Contract

- **Selected family:** Windows service HTTP process ownership and lifecycle.
- **Finding classification:** `new_family` strong host-realism defect.
- **Owning abstraction:** activity-layer connection-owner selection and process
  lifecycle, plus explicit-proxy client process hints.
- **Invariant:** an installed monitoring agent is one durable, target-agnostic
  service process per host; Windows update and CryptoAPI traffic is owned by the
  relevant native service; generic server HTTP is not relabeled as monitoring.
- **Entry paths:** direct and explicit-proxy HTTP/HTTPS system traffic.
- **Consumers:** canonical process state, eCAR process/flow records, Sysmon
  process/network evidence, and proxy-correlated endpoint ownership.
- **Layer rationale:** emitters render the canonical process owner correctly;
  the activity layer currently chooses the wrong executable and lifetime.
- **Sibling risks:** preserve one-shot explicit health commands, Linux owners,
  Go/Meridian monitoring user agents, CryptoAPI/Windows Update identities,
  stable proxy ownership, and non-overlapping process lifetimes.

## Loop 23 Outcome

- Commit `2a205e0b`; full suite 5,095 passed and 41 skipped; Ruff passed.
- The prior Windows ServiceHealth pattern collapsed from 134 short workers to
  18 flows owned by one durable DC process, with zero target-bearing commands
  and zero overlapping workers in the collection.
- Automated evaluation passed at 96.47688957444862 over 83,522 records, with
  221/221 IDS integrity checks passing.
- Initial blind scores were 16/64/73/94, average 61.75. Deliberation ended
  unanimously Synthetic at 86.0, final scores 84/83/87/90.
- Decisive next defect: two no-loss HTTP streams render request depths `1,3,2`
  on the DMZ sensor and repeat the same inversion on the core sensor.

## Loop 24 Family Contract

- **Selected family:** HTTP/1.x persistent-connection transaction lifecycle.
- **Finding classification:** `regression` hard causal contradiction; Loop 18
  fixed emitter-local ordering but cross-action connection reuse can still
  assign a later depth to an earlier canonical request time.
- **Owning abstraction:** canonical HTTP persistent-connection state in the
  network transaction planner.
- **Invariant:** on one persistent TCP connection, canonical request time is
  strictly monotonic with assigned `trans_depth`; a request that cannot fit the
  remaining ordered interval starts a new connection at depth 1.
- **Entry paths:** direct browser sessions, repeated HTTP application actions,
  explicit callers supplying HTTP contexts, and proxy-origin HTTP transactions.
- **Consumers:** Zeek HTTP at every sensor, web/proxy access timing, file/PE
  analyzer timestamps, endpoint FLOW timing, and parent connection ledgers.
- **Layer rationale:** transaction depth and reuse are assigned before source
  observation; emitters cannot repair contradictory canonical request order.
- **Sibling risks:** preserve UID reuse, byte budgets, connection deadlines,
  source-port identity, request/file containment, proxy legs, sensor clocks,
  observation loss, and deterministic generation.

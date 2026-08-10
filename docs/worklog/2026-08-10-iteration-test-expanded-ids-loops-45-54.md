# Iteration Test Expanded IDS Assessment Loops 45-54

Scenario: `/Users/dabianco/projects/SURGe/EvidenceForge/scenarios/iteration-test-expanded-ids/scenario.yaml`

This set begins at committed `dev` state `d7162d57`. Loop 45 starts with
fresh generation and an isolated blind panel; no prior-loop finding is used to
select its first improvement. Every later loop regenerates the corpus and gives
reviewers only a new data-only copy plus the shared assessment guidance.

## Loop 45 Family Contract

- **Selected family:** source-native process ownership for explicit-proxy and
  high-confidence HTTP client connections.
- **Classification:** `sibling_defect`; multiple client and daemon families
  pass through the shared connection-owner planner.
- **Owning abstraction:** the canonical connection-owner resolver in
  `ActivityGenerator`, before eCAR, Zeek, proxy, and firewall projection.
- **Invariant:** when HTTP metadata identifies a source-native client family,
  the canonical initiating process is compatible with that family and any
  target-bearing command line names the same origin host as the request. Mail
  listeners and unrelated role daemons cannot own arbitrary HTTP client sockets.
- **Entry paths:** baseline direct connections, explicit-proxy client legs,
  service-host fallback ownership, inferred seeded PIDs, user-session clients,
  and package/service helper paths.
- **Consumers:** canonical `ProcessContext` and `NetworkTransactionPlan`,
  eCAR PROCESS/FLOW, Zeek conn/http, proxy access, ASA, lifecycle finalizers,
  and evaluator/process-ownership probes.
- **Layer rationale:** the mismatch exists before rendering and spans endpoint
  and network sources, so emitter fixes would preserve contradictory canonical
  truth. The shared resolver has the user agent, request hostname, host role,
  process state, and lifecycle information needed to prevent sibling defects.
- **Sibling risks:** browser wrappers, package-manager helpers, role-owned
  service health checks, tunnel reuse, user-versus-system ownership, parent
  selection, exact-command reuse, and one-shot process termination.

## Loop 45 Outcome

- **Generation/eval:** 83,707 fresh records; 96.02555389939702; FAIL only on
  pivot linkability (51.6129/100).
- **Blind panel:** Synthetic/Synthetic/Inconclusive/Real at 66/78/44/28,
  average 54.0; disagreement and a 50-point spread triggered deliberation.
- **Deliberation:** unanimous Synthetic at 74/80/67/69, average 72.5.
- **Selected family:** canonical source-native HTTP/proxy client process
  ownership. The shared resolver now preserves the request host in
  target-bearing commands, models Linux server CLI clients from strong
  User-Agent evidence, and prevents mail daemons from owning arbitrary web
  sockets.
- **Focused tests:** nine passed across explicit-proxy and high-confidence
  ownership paths.

## Loop 46 Family Contract

- **Selected family:** TLS SSL-to-X.509 lifecycle-group source observation.
- **Classification:** `sibling_defect`; SSL references and X.509 analyzer rows
  are sibling projections of the same captured certificate chain.
- **Owning abstraction:** frozen per-sensor `NetworkSensorObservation` and its
  `FileSensorObservation` analyzer-visibility decision.
- **Invariant:** every certificate FUID retained in a sensor's `ssl.log` has a
  corresponding `x509.log` row on that sensor; incomplete capture may retain a
  source-local files row but cannot retain analyzer-derived references.
- **Entry paths:** direct TLS, explicit-proxy origin TLS, STARTTLS, resumed and
  full handshakes, multi-certificate chains, and multi-zone projection.
- **Consumers:** Zeek SSL, files, and X.509 emitters; sensor-local FUID mapping;
  cross-source evaluator joins and hunter pivots.
- **Layer rationale:** packet capture completeness is sensor-local observation
  truth. Filtering only at an emitter-global format check cannot represent a
  chain visible on one sensor but incomplete on another.
- **Sibling risks:** partial chain visibility, mapped sensor FUIDs, complete
  capture, absent observation plans in low-level tests, and certificate files
  retained without analyzer output.

## Loop 46 Outcome

- **Generation/eval:** 80,525 fresh records; 96.09963396291859; FAIL only on
  pivot linkability (51.6129/100).
- **Loop 45 family probe:** 1,684 endpoint proxy flows; 1,678 exact HTTP joins;
  zero family, command-host, Postfix-owner, or lifecycle violations.
- **Blind panel:** Synthetic/Real/Synthetic/Synthetic at 66/24/66/70, average
  56.5; disagreement and a 46-point spread triggered deliberation.
- **Deliberation:** unanimous Synthetic at 72/61/71/75, average 69.75.
- **Selected family:** sensor-local TLS certificate lifecycle observation.
  SSL certificate FUIDs are now projected only when the same sensor's frozen
  file observation permits X.509 analysis.
- **Focused tests:** 82 passed across TLS, Zeek files, and network observation.

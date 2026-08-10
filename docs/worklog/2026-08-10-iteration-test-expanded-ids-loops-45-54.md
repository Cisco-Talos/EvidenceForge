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

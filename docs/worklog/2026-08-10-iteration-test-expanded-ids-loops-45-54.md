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

## Loop 47 Family Contract

- **Selected family:** durable SSH client credential identity and stable
  client/user/target authentication policy.
- **Classification:** `sibling_defect`; every session emitted through the
  baseline SSH bundle consumes shared credential and policy state.
- **Owning abstraction:** baseline remote-administration identity policy before
  the SSH action bundle constructs transport, endpoint, auth, PAM, and logind
  occurrences.
- **Invariant:** a client/user owns one durable public-key fingerprint across
  destinations unless explicit identity selection is modeled; repeated
  sessions on one client/user/target tuple use its stable authentication policy
  rather than independently redrawing password versus public key.
- **Entry paths:** ambient baseline SSH sessions for all modeled administrators,
  Windows and Linux clients, all Linux server targets, repeated and cross-zone
  observations.
- **Consumers:** SSH bundle requests, target syslog accepted-auth rows, PAM and
  logind lifecycle, eCAR client/server/session records, Zeek transport, and
  source command-line correlation.
- **Layer rationale:** credentials and authentication policy are durable actor
  state, not per-event source formatting. Fixing sshd messages would leave the
  bundle's canonical request contradictory.
- **Sibling risks:** per-user uniqueness on shared clients, fleet method
  diversity, explicit storyline keys, password-only targets, repeat sessions,
  source-port allocation, and SSH lifecycle timing.

## Loop 47 Outcome

- **Generation/eval:** 80,525 fresh records; 96.09963396291859; FAIL only on
  pivot linkability (51.6129/100).
- **Loop 46 family probe:** 530 SSL certificate references across two sensor
  zones; zero references absent from sensor-local X.509 logs.
- **Blind panel:** Synthetic/Real/Real/Synthetic at 67/18/27/64, average 44.0;
  disagreement and a 49-point spread triggered deliberation.
- **Deliberation:** 2-2 role split with narrow Synthetic consensus score 59,
  confidence 68; final role scores 72/40/39/74.
- **Selected family:** durable SSH client credential and authentication policy.
  Key identity now belongs to client/user across targets, while auth method is
  stable for each client/user/target tuple.
- **Focused tests:** 158 passed, one skipped across baseline and realism tests.

## Loop 48 Family Contract

- **Selected family:** Windows interactive session bootstrap process lifecycle
  and teardown timing.
- **Classification:** `sibling_defect`; every interactive/RDP session uses the
  same winlogon-userinit-Explorer bootstrap and session-close path.
- **Owning abstraction:** canonical session/process state and lifecycle before
  Windows Security, Sysmon, and eCAR observation/rendering.
- **Invariant:** session bootstrap processes visible at termination have a
  compatible visible create; userinit exits after shell handoff rather than at
  logout; child-before-parent teardown uses source-compatible variable timing,
  not a fleet-wide fixed cadence.
- **Entry paths:** Type 2, 10, and 11 logons, lazily repaired Explorer shells,
  baseline and storyline sessions, authoritative and ordinary logoff.
- **Consumers:** StateManager process/session ownership, Windows 4688/4689,
  Sysmon 1/5, eCAR PROCESS CREATE/TERMINATE and actor references, process
  lifecycle finalizers, and detector joins.
- **Layer rationale:** the contradiction exists in canonical process lifetime
  and session teardown state. Emitter-only timestamp changes would leave
  userinit alive and termination-only process identities in other sources.
- **Sibling risks:** logon caller visibility, SYSTEM versus user ownership,
  Explorer parent identity, early userinit termination, RDP shell timing,
  source-observation delay, child-before-parent order, and PID cleanup.

## Loop 48 Outcome

- **Generation/eval:** 81,305 fresh records; 96.41560731459667; FAIL only on
  pivot linkability (51.6129/100).
- **Loop 47 family probe:** 109 successful SSH auth rows across 20 tuples; zero
  mixed-method tuples and zero modeled admin identities with multiple keys.
- **Blind panel:** Inconclusive/Synthetic/Inconclusive/Real at 39/66/41/34,
  average 45.0; disagreement and a 32-point spread triggered deliberation.
- **Deliberation:** final 49/64/43/52; Inconclusive consensus score 52,
  confidence 84.
- **Selected family:** Windows session shell lifecycle. Bootstrap helpers now
  emit creates, userinit exits after Explorer handoff, and logout spacing is
  process-scoped rather than fixed at 50 ms.
- **Focused tests:** 488 passed across activity, process-lifetime, and state
  suites, including the new shell-lifecycle regression.

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

## Loop 49 Family Contract

- Fresh generation: 83,559 records from commit `81fc795c`.
- Automated eval: 96.2863 (Parseability 100.0, Plausibility 97.3484, Causality
  90.3902, Timing 96.7584).
- Initial blind synthetic-confidence: Hunter 66, Detection 66, Network 68, Host 56;
  average 64.0. Verdict disagreement triggered deliberation; final panel average 68.5.
- Selected only from Loop 49 evidence: duplicate RDP session bootstrap. Two hosts each showed
  one Type 10 login but two `userinit.exe → explorer.exe` chains under the same Logon ID.
- Contract: one active Windows interactive session owns at most one initial shell bootstrap
  chain; a repeated renderer/compatibility request must reuse the live session Explorer.

## Loop 49 Outcome

- Added idempotent shell-bootstrap ownership at the canonical logon lifecycle boundary.
- Added a regression that renders the same active Logon ID twice and asserts exactly one
  `winlogon.exe`, one `userinit.exe`, and one `explorer.exe` create chain.
- Focused activity/spawn/RDP/world-model verification: 439 passed.
- Loop 50 must generate fresh output from the committed fix and use a new blind panel before
  selecting another family.

## Loop 50 Family Contract

- Fresh generation/eval: 83,559 records, 96.2863.
- Initial blind scores: Hunter 91, Detection 39, Network 56, Host 76; average 65.5.
  Deliberation reconciled the 52-point spread to final 88/68/65/80, average 75.25.
- The fresh post-fix probe still found two one-login/two-shell-chain RDP groups. Full generation
  eagerly applies planned future termination, which clears live process references before a
  second semantic path reaches the same active session.
- Contract: initial Windows shell bootstrap is durable session-owned semantic state, not a
  property inferred from the current live-process map.

## Loop 50 Outcome

- Added `ActiveSession.windows_shell_bootstrapped` and made canonical logon bootstrap consult it.
- Strengthened the regression by removing Explorer from live state before replaying the same
  Logon ID; no second shell chain may be created.
- Focused activity/state/spawn/RDP/world verification: 541 passed.
- Highest fresh deferred target: fleet-global Event 5156 thread-ID universe.

## Loop 51 Family Contract

- Fresh generation/eval: 83,559 records, 96.2863.
- Blind scores: Hunter 76, Detection 68, Network 74, Host 78; average 74.0. All verdicts
  Synthetic, spread 10, so no deliberation.
- Detection independently reproduced the duplicate RDP shell chain. The post-fix probe also
  found both one-login/two-chain groups unchanged.
- Root cause: future-dated termination retains an identity with a future end time but removes it
  from the live map. Lazy Explorer repair only queried live state and recreated bootstrap.
- Contract: process activity at canonical time must use interval state (`start <= time < end`),
  including retained identities, rather than equating current live-map membership with history.

## Loop 51 Outcome

- Added `StateManager.is_process_active_at()` over live and retained identities.
- Retained each session's initial Explorer PID and made lazy repair suppress duplicate bootstrap
  when the original shell spans the requested canonical time; genuine later restart remains valid.
- Focused activity/state/spawn/RDP/world verification: 541 passed.
- Fresh deferred targets: registry-effect ownership, executable lifetime profiles, and source
  timing texture.

## Loop 52 Family Contract

- Fresh generation/eval: 82,371 records, 96.3674.
- Blind scores: Hunter 78, Detection 57, Network 64, Host 68; average 66.75. All verdicts
  Synthetic, spread 21, so no deliberation.
- The fresh post-fix probe found zero single-logon duplicate RDP shell groups.
- Fresh reviewers identified ordinary web clients in globally assigned but operationally
  implausible government networks, including 29/8.
- Contract: external-client generation must satisfy both protocol-level routability and the
  modeled population's operational identity; `is_global` alone is insufficient.

## Loop 52 Outcome

- Added data-driven `external_client_excluded_cidrs` policy in network parameters.
- The shared external-client allocator excludes configured DoD networks in addition to existing
  special-use and organization CIDR checks.
- Added a deterministic 29/8 regression; focused external-IP/network verification: 39 passed.

## Loop 53 Family Contract

- Fresh generation/eval: 83,084 records, 96.2327.
- Initial blind scores: Hunter 46, Detection 84, Network 30, Host 86; average 61.5. Mixed
  verdicts and a 56-point spread triggered deliberation.
- Deliberation converged unanimously on Synthetic at 82/89/88/93, average 88.0.
- Detection proved 138 completed SMB/445 sessions on six Linux roles were owned by `rsyncd`;
  Zeek success state and bidirectional bytes exclude a failed-probe explanation.
- Contract: canonical Linux SMB activity must be owned by an SMB/CIFS-capable client whose
  command and lifecycle identify the same target; `rsyncd` is not an SMB implementation.

## Loop 53 Outcome

- Replaced the shared Linux SMB service owner with target-bearing `/usr/bin/smbclient` and
  Kerberos-authenticated share semantics.
- Added SMB clients to exact-command and one-shot lifecycle classification.
- The Loop 52 external-network probe examined 36,378 source-IP values with zero excluded hits.
- Full activity-generator verification: 352 passed.

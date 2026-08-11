# iteration-test-expanded-ids assessment loops 90-99

## Scope

Ten fresh end-to-end assessment loops on `iteration-test-expanded-ids`, continuing from loop 89.
Each loop regenerates the corpus, runs deterministic evaluation, commissions four context-isolated
blind reviews, verifies the preceding family fix, and selects at most one family-level target. The
scenario remains unchanged.

## Loop 90

- Fresh generation produced 83,178 records. Automated score: 97.1941; all hard gates passed.
- SMB lexical probe passed: 167 normalized stems, 122 singleton stems, and 45 recurring stems,
  versus 50/6 in loop 89.
- Initial blind scores: 52/68/68/76 (mean 66.0), panel 3 Synthetic / 1 Inconclusive.
  Deliberation final mean: 69.0, retaining Synthetic with an informed minority.
- No hard contradiction was established. The selected target was source-specific clock and
  delivery texture after code inspection proved configured sensor drift and coherent jitter were
  not consumed by the planner.

### Family contract: source-specific clock and observation behavior

- **Owning abstraction:** `SourceTimingPlanner` and data-driven timing profiles.
- **Invariant:** persistent source offsets, drift, coherent wander, route delay, and residual noise
  survive rendering without canonical bounds erasing legitimate negative source-clock offsets.
- **Entry paths:** network sensors, Sysmon endpoint network observations, and startup modules.
- **Consumers:** Zeek, Sysmon, protocol pivots, timing probes, automated eval, and blind review.
- **Layer rationale:** source clock and delivery behavior is observation/timing truth.
- **Sibling risk:** eCAR FLOW interval handling and collector backlog remain separately measurable.

### Implementation

- Consumed configured per-sensor drift and coherent jitter in sensor timing.
- Added canonical-to-source-clock bound translation for Sysmon Event 3.
- Broadened sensor-clock and startup-module timing texture.
- Focused suite: 132 passed; config validation and Ruff checks pass.

## Loop 91

- Fresh generation produced 83,178 records. Automated score: 97.1940; all hard gates passed.
- Sensor timing probe passed: 1,927 matched flows covered a 254.941 ms offset range and 227
  distinct millisecond bins, versus 37.884 ms before the loop-90 fix.
- Initial blind scores: 64/26/36/74 (mean 50.0), split 2 Real / 2 Synthetic. Deliberation final
  scores: 70/44/38/77 (mean 57.25), mixed/inconclusive leaning synthetic.
- The selected target was interactive-command scheduling and lifecycle ownership after visible
  overlapping foreground children and session-clipped one-shot processes recurred across Windows
  and Linux.

### Family contract: interactive-command lifecycle ownership

- **Owning abstraction:** canonical process scheduling and lifecycle state.
- **Invariant:** a shell cannot own overlapping ordinary foreground children; bounded one-shot
  commands end according to executable/command semantics rather than session teardown.
- **Entry paths:** application activity, suspicious benign processes, connection owners, shell
  history, and session cleanup.
- **Consumers:** eCAR, Sysmon, Security, process-network attribution, and session closure.
- **Layer rationale:** concurrency and lifetime are shared canonical truths.
- **Sibling risk:** genuine long-running SSH and background/job behavior must remain representable.

### Implementation

- Bounded installer/update and `check --once` lifetimes.
- Prevented reuse of Windows shells already blocked by active foreground children.
- Backfilled executable-aware termination for orphaned bounded children at session close.
- Focused lifecycle suites: 427 passed; Ruff checks pass.

## Loop 92

- Fresh generation produced 80,064 evaluated records. Automated score: 97.6619; all hard gates
  passed.
- Lifecycle probe passed: bounded one-shot lifetimes maxed at 109.356 source-visible seconds and
  no overlapping Windows SSH clients shared a shell parent.
- Blind scores: 79/68/74/81 (mean 75.5), unanimously Synthetic; no deliberation trigger.
- The selected target was paired endpoint FLOW clock independence. Independent matching found
  2,034 exact-millisecond pairs among 6,184 matched endpoint observations (32.9%).

### Family contract: endpoint FLOW source-clock bounds

- **Owning abstraction:** `SourceTimingPlanner`.
- **Invariant:** preferred endpoint times and causal interval bounds share the endpoint's local
  clock frame, preserving host-local clock differences on short connections.
- **Entry paths:** all source and destination eCAR connection projections.
- **Consumers:** eCAR FLOW, process identity, remote-auth ordering, and pivot evaluation.
- **Layer rationale:** source clock translation belongs in shared timing planning.
- **Sibling risk:** short failures and SSH/RDP/proxy transport ordering remain bounded.

### Implementation

- Translated eCAR canonical connection bounds into each endpoint clock before constraints.
- Added an ultra-short paired endpoint FLOW serialization regression.
- Focused timing/eCAR suites: 230 passed; Ruff checks pass.

## Loop 93

- Fresh generation produced 80,064 evaluated records. Automated score: 97.6607; all hard gates
  passed.
- Endpoint-clock probe passed: 6,172 of 6,184 paired endpoint FLOW observations retained distinct
  milliseconds; only 12 (0.19%) coincided after serialization.
- Initial blind scores: 32/84/88/76 (mean 70.0), split 1 Real / 3 Synthetic. Deliberation final
  scores: 56/80/84/72 (mean 73.0), consensus Synthetic.
- The selected target was shared packet-provider observation timing: all 1,906 shared Zeek flows
  showed the same signed 0.515–0.771 second core/DMZ envelope, corroborated by IDS observations.

### Family contract: distributed packet-provider clock behavior

- **Owning abstraction:** source-observation timing profiles and shared timing planners.
- **Invariant:** packet providers retain persistent clock skew, slow drift, and small capture/path
  variation without embedding broad independently sampled latency in packet event time.
- **Entry paths:** every Zeek and IDS projection using distributed sensor observation.
- **Consumers:** Zeek, Snort, protocol pivots, and cross-sensor timing analysis.
- **Layer rationale:** provider clock and capture behavior belong in observation planning.
- **Sibling risk:** plausible persistent provider ordering must remain non-exact and slowly varying.

### Implementation

- Broadened persistent sensor offset while sharply reducing drift, path delay, and residual jitter.
- Added a six-hour stable-skew regression.
- Focused packet-observation suites: 169 passed; config validation and Ruff checks pass.

## Loop 94

- Fresh generation produced 80,064 evaluated records. Automated score: 97.6607; all gates passed.
- Provider-skew probe passed: 1,916 shared flows had 1,761 distinct rounded offsets across a
  27.987 ms range, versus 256 ms before the loop-93 fix.
- Initial blind scores: 82/31/86/93 (mean 73.0), split 3 Synthetic / 1 Real. Deliberation final
  scores: 72/63/83/86 (mean 76.0), consensus Synthetic.
- The selected target was source-native timing projection after 2,229/2,229 Sysmon native and
  event-envelope timestamps proved to be aliases inside one millisecond.

### Family contract: Sysmon native and provider-envelope timing

- **Owning abstraction:** `SourceTimingPlanner` and timing profiles.
- **Invariant:** semantic native time and provider envelope time are correlated but distinct, and
  final causal repairs preserve their latency relationship.
- **Entry paths:** every Sysmon event with a native `UtcTime`.
- **Consumers:** Sysmon XML, record ordering, process GUIDs, and cross-source pivots.
- **Layer rationale:** provider latency is source-observation truth.
- **Sibling risk:** final ordering repairs and process identity must stay coherent.

### Implementation

- Added data-driven right-skewed Sysmon provider-envelope latency with rare backlog tails.
- Preserved `UtcTime` separately from `TimeCreated` through final causal repairs.
- Focused Windows/source timing suites: 186 passed; config validation and Ruff checks pass.

## Loop 95

- Fresh generation produced 80,064 evaluated records. Automated score: 97.6607; all gates passed.
- Sysmon timing probe passed: 82.35% of 3,938 native/envelope pairs crossed a millisecond boundary,
  with 2,574 distinct deltas and a 54.437 ms tail.
- Initial blind scores: 18/82/22/74 (mean 49.0), split 2 Real / 2 Synthetic. Deliberation final
  scores: 72/88/24/86 (mean 67.5), consensus Synthetic.
- The selected target was canonical authentication/session occurrence identity after 353 LOGIN
  rows reused 23 objects, up to 55 starts per object.

### Family contract: authentication occurrence lifecycle

- **Owning abstraction:** canonical authentication action and session identity planning.
- **Invariant:** one normalized session object has at most one successful LOGIN start while native
  durable token LUIDs remain stable fields.
- **Entry paths:** repeated Type 5 built-in service-principal logons.
- **Consumers:** eCAR, Windows Security, session pivots, and duration/concurrency analytics.
- **Layer rationale:** lifecycle occurrence identity is canonical truth.
- **Sibling risk:** well-known Windows authentication IDs must remain native and stable.

### Implementation

- Made built-in Type 5 normalized object and lifecycle IDs occurrence-specific without changing
  `0x3e4/0x3e5/0x3e7` native LUIDs.
- Focused session/eCAR suites: 121 passed; Ruff checks pass.

## Loop 96

- Fresh generation produced 80,064 evaluated records. Automated score: 97.6607; all gates passed.
- Session probe passed: 1,071 successful LOGIN rows had 1,071 distinct objects; native service
  LUIDs remained stable across 352 built-in authentications.
- Initial blind scores: 70/86/42/81 (mean 69.75), split 3 Synthetic / 1 Real. Deliberation final
  scores: 66/70/45/76 (mean 64.25), consensus Synthetic.
- The selected target was SSH lifecycle ownership after 18/58 target sshd children preceded TCP
  open by more than two seconds, with a 28.684 second worst inversion.

### Family contract: SSH transport-first lifecycle ownership

- **Owning abstraction:** SSH action bundle plus delegated network contract.
- **Invariant:** source readiness precedes preserved TCP open; target sshd/auth/PAM/shell follow;
  late endpoint attribution is omitted rather than delaying transport.
- **Entry paths:** storyline, admin/baseline, compatibility, and SCP SSH.
- **Consumers:** Zeek, firewall, eCAR, syslog/PAM/logind, and receiver file evidence.
- **Layer rationale:** SSH bundle owns the cross-event lifecycle edges.
- **Sibling risk:** source process termination, authoritative close, failures, and tuple identity.

### Implementation

- Preserved the SSH bundle's transport anchor through network planning.
- Materialized Windows and Linux source clients before TCP planning and retained their lifecycle
  even when unsafe FLOW attribution is omitted.
- Fixed authoritative duration arithmetic against the preserved start.
- Focused SSH/network/session suites: 354 passed; Ruff checks pass.

## Loop 97

- Fresh generation produced 79,819 evaluated records. Automated score: 97.8099; all gates passed.
- SSH probe passed: 60 joined sessions had zero responder creates before transport, with the first
  responder process 0.122 seconds after TCP open.
- Blind scores: 66/65/84/64 (mean 69.75), unanimous Synthetic; no deliberation required.
- The selected target was IDS response semantics after STUN success responses appeared on an S0
  zero-response flow and used request-direction tuples.

### Family contract: response-class IDS evidence

- **Owning abstraction:** data-driven signature predicates and canonical transaction matching.
- **Invariant:** response signatures require responder payload and render responder packet direction.
- **Entry paths:** baseline and authored IDS attachments.
- **Consumers:** Snort/Suricata, Zeek pivots, evaluator summaries, and ground truth.
- **Layer rationale:** response admissibility is signature/transaction truth.
- **Sibling risk:** request-side signatures remain originator-directed and may fire on attempts.

### Implementation

- Added response phase, direction, payload threshold, and response requirement to STUN success SID.
- Focused IDS/config suites: 140 passed.

## Loop 98

- Fresh generation produced 79,817 evaluated records. Automated score: 97.8099; all gates passed.
- IDS probe passed: zero impossible STUN responses; nine request-side alerts remained.
- Initial blind scores: 84/79/94/88 (mean 86.25), split 2 Real / 2 Synthetic. Deliberation:
  Synthetic at moderate confidence, realism 86, professional PASS with reservations.
- The selected target was canonical session occurrence timing after projection collapsed known
  multi-second lifecycles onto an exact one-millisecond floor.

### Family contract: session interval projection

- **Owning abstraction:** canonical session lifecycle and source timing planner.
- **Invariant:** projected closure preserves at least the canonical session duration.
- **Entry paths:** local, network, SSH, RDP, baseline, storyline, and compatibility sessions.
- **Consumers:** eCAR, Windows Security, PAM/logind, processes, and FLOWs.
- **Layer rationale:** duration is canonical lifecycle truth.
- **Sibling risk:** transport/auth/dependent ordering and authoritative/window-boundary ends.

### Implementation

- Replaced the delayed-start one-millisecond closure floor with canonical-duration preservation.
- Focused source/session suites: 434 passed.

## Loop 99

- Fresh generation produced 79,817 evaluated records. Automated score: 97.8099; all gates passed.
- Session probe passed: 722 paired sessions, zero one-millisecond/nonpositive intervals, minimum
  1.696 seconds.
- Blind verdicts were unanimously Synthetic; initial realism 68/42/28/74. The 46-point spread
  triggered deliberation, which reached Synthetic, realism 64, verdict confidence 84.
- The selected target was SSH client visibility after 25/49 tuple-matched source processes
  rendered after target authentication.

### Family contract: SSH source-process causal visibility

- **Owning abstraction:** SSH action bundle, process-execution contract, source timing planner.
- **Invariant:** visible client process create precedes transport and target authentication.
- **Entry paths:** storyline, admin/baseline, Windows/Linux source, SCP, compatibility.
- **Consumers:** source process/FLOW, Zeek/firewall, sshd/PAM/logind, SCP artifacts.
- **Layer rationale:** source readiness is an action-level causal prerequisite.
- **Sibling risk:** parent/session readiness, close protection, tuple/UID, observation texture.

### Implementation

- Added a process `source_visible_by` causal deadline and applied transport open to SSH clients
  across eCAR, Sysmon, and Windows Security projections.
- Focused SSH/source/network suites: 578 passed.
- Corpus-level verification is deferred to the next fresh loop because this was the tenth and final
  requested assessment loop.

## Final validation

- Full suite: 5,374 passed, 41 skipped.
- Configuration validation: 88 files checked, 0 errors/warnings/info findings.
- Ruff lint: pass.
- Ruff format check: 465 files already formatted.
- Dashboard refreshed through loop 99 for the last 20 loops.

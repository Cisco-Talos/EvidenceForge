# Windows Remote-Authentication Observation Contract

## Objective

Make Windows remote authentication a canonical multi-event action whose transports, target
authentication, optional session, and source-visible ordering are correlated before rendering.

## Family Contract

- **Classification:** `family_level`, correcting a dataset-wide source-visible causality defect
  and the sibling failure-path defect that emits authentication before transport.
- **Owning abstractions:** the Windows remote-authentication action planner owns protocol phases
  and exact participating transports; the network transaction contract owns each tuple and
  interval; the dispatcher `SourceTimingPlanner` owns source-visible FLOW/WFP/auth ordering;
  observation policy owns missingness; emitters render finalized source truth.
- **Invariant:** for one remote-authentication action, every role-labelled transport has a unique
  transaction identity and exact tuple. When both target-side transport and authentication are
  visible in one source, the transport precedes authentication by the configured source-native
  gap. A failed attempt never creates a durable session, and missing observations are never
  fabricated to satisfy correlation.
- **Entry paths:** successful and failed Windows Type 3 logons, machine/service-account network
  authentication, RDP Type 10 compatibility, Kerberos/NTLM validation, and Windows remote-admin
  actions that create SMB/RPC/management transports.
- **Consumers:** StateManager session identity, network transaction planning, identity/lifecycle
  planning, observation and output-window admission, Windows Security, eCAR, Zeek/firewall
  rendering, evaluator probes, and storyline trace evaluation.
- **Layer rationale:** source ports, target service, outcome, and phase order are action truth
  shared by several sources. Emitter-local timestamp repair cannot identify the correct transport
  under concurrent attempts or tuple reuse and would leave failed-logon canonical order wrong.
- **Sibling risks:** RDP and SSH already have specialized transport/session contracts; RDP will
  adapt to the common Windows remote-auth plan without regressing SSH. Observation loss remains
  independent, and no scenario schema is added.

## Milestones

1. Add immutable remote-authentication types and a planner that owns Windows Type 3 success and
   failure transports, action grouping, and session parentage.
2. Finalize eCAR FLOW/session and Windows WFP/logon ordering in dispatcher source timing; reduce
   eCAR to consuming finalized timestamps.
3. Route sibling Windows authentication and remote-admin paths through the contract, add rendered
   family probes, and complete expanded-scenario and blind-panel acceptance.

## Acceptance Targets

- Zero exact-tuple eCAR remote-login-before-inbound-FLOW inversions, including SMB/445 and
  Kerberos/88 families.
- Zero matching Windows 4624/4625-before-5156 inversions when both rows are visible.
- No RDP or SSH ordering regression, no cross-host/port-reuse mis-correlation, and no synthesized
  companion evidence.
- Default tests, configuration validation, Ruff checks, `iteration-test-expanded` evaluation, one
  four-reviewer blind panel, and three reviewable milestone commits.

## Implementation Progress

- Milestone 1 (`d5fe4f68`) added immutable authentication/transport plans, routed successful and
  failed Type 3, RDP Type 10, and machine-account Kerberos paths through the action bundle, and
  parented network/session lifecycles to one stable remote-authentication group.
- Milestone 2 (`a66c363d`) moved exact action/transaction/host/tuple correlation and 8–140 ms
  source-local ordering into `SourceTimingPlanner`, applied admission after final source timing,
  and removed eCAR plus Windows-flush remote-authentication timestamp repair.
- Milestone 3 routes compatibility SMB, anonymous NTLM, machine-account, RDP, and remote-admin
  siblings through the common bundle and adds a rendered evaluator probe. Exact canonical
  transaction identity remains internal to planning and source timing; eCAR renders only
  source-native tuple and lifecycle fields. Missing FLOWs are exempt, while visible exact-tuple
  matches must be within the bounded authentication interval.

## Acceptance Corrections

- Time-aware session lookup and authoritative session-end checks prevent a stale or already-ended
  session from owning later network or authentication activity.
- `OpenConnection` retains canonical transaction identity so compatibility SMB paths can name the
  exact transport without timestamp-nearest fallback.
- Anonymous NTLM/SMB and machine-account authentication now enter the action bundle instead of
  bypassing lifecycle and source-timing ownership.
- SSH target-side FLOW/session timing uses the same source-planning principle as a regression
  reference, without changing SSH canonical chronology.
- The first blind panel identified a branch-introduced eCAR generator fingerprint: the internal
  `network_transaction_id` had leaked into rendered FLOW rows. The fix removed that field from the
  format and emitter, retained it only as canonical planner metadata, and changed the rendered
  evaluator to require host plus full tuple within a five-second correlation interval. A reused
  tuple outside that interval cannot hide a nearby inversion.

## Verification Log

- Milestone 1 focused authentication/RDP/machine-account tests: passed.
- Milestone 2 source-timing, eCAR, Windows emitter, dispatcher, and SSH regression tests:
  400 passed.
- Milestone 3 format, evaluator, exact-tuple rendering, and probe tests: passed.
- Configuration validation: 0 issues across 87 files.
- Repository Ruff and formatting gates: passed.
- Focused remote-authentication/network/source-timing/eCAR/RDP regression suite: 727 passed,
  1 skipped.
- Complete default suite after the source-native eCAR correction: 4,974 passed, 19 skipped.
- Expanded scenario: 82,102 records; automated score 95.6297; all hard acceptance criteria pass;
  causal ordering and storyline trace coverage are both 100%.
- Rendered eCAR probe: 706 visible exact-tuple remote-auth pairs, zero inversions, including
  249 Kerberos/88, 445 SMB/445, and 12 RDP/3389 pairs. Six logins have independently omitted FLOW
  companions. Gaps span 8–140 ms with 133 distinct values.
- Rendered Windows probe: 721 visible 5156/auth pairs, zero inversions; one independently omitted
  companion. Six visible failed authentications follow transport and create no session.
- SSH regression probe: 98/98 visible pairs, zero inversions.
- Final replacement four-reviewer panel synthetic-confidence scores: Threat Hunter 74, Detection
  Engineer 72, Network Forensics 88, Host/EDR 78; average 78.0 (`likely synthetic`). All verdicts
  were Synthetic, average verdict confidence was 91, and score spread was 16, so no deliberation
  trigger applied.
- Reviewers consistently rated the branch-owned network chronology, traffic accounting, independent
  sensor identity/timing, target-side remote-auth ordering, and endpoint identity as strong. No
  reviewer found the original remote-login-before-inbound-FLOW defect.
- Highest-leverage remaining groups belong to other contracts: standards-valid OCSP/DKIM payloads;
  explicit-credential/Event 4648 transport and field semantics; PsExec/file/process/SSH lifecycle
  ownership; source-native process timing and Sysmon content; and baseline/certificate texture.

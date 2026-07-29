# Explicit Session Closure Contract

## Objective

Make an explicit storyline `logoff` authoritative for the identity and canonical end of its
durable session. Session-owned processes and transports must respect that end; source-specific
observation delay must not rewrite it.

## Family Contract

- **Classification:** `family_level`, correcting an `exact_regression` in session lifecycle
  ownership with a sibling defect in process-owned network lifetimes.
- **Owning abstractions:** storyline intent planning binds a logoff to its durable session;
  authentication/session action bundles and canonical session state own the end plan; process and
  network action bundles consume the plan; `SourceTimingPlanner` owns bounded source-visible tails.
- **Invariant:** an explicit session end at `T` closes the intended storyline session at canonical
  time `T`. Non-detached session processes and their transports end no later than `T`; SSH close
  evidence stays tuple- and identity-coherent; RDP may disconnect before `T`; renderers never move
  canonical time or invent a replacement session.
- **Entry paths:** typed storyline `ssh_session`, `rdp_session`, successful `logon`, and `logoff`;
  WorldPlanner session bootstrap and spill-session recovery; direct SSH/RDP/logon/logoff adapters;
  process-owned canonical connections; baseline-generated session closure.
- **Consumers:** StateManager identity/lifecycle state, process and network transaction planners,
  dispatcher lifecycle admission, SourceTimingPlanner, Windows/Sysmon/eCAR/syslog/Zeek emitters,
  ground truth, and evaluation storyline matching.
- **Layer rationale:** the requested session and end time are explicit intent, while the dependent
  lifetime relationships are bundle/state truth shared by several sources. Emitter repair would
  hide contradictions rather than prevent them.
- **Sibling risks:** simultaneous author-controlled sessions for one actor/host remain implicitly
  paired because the scenario schema has no `session_ref`; deterministic storyline planning and an
  ordered runtime registry must handle existing scenarios without adding that schema in this PR.

## Milestones

1. Add canonical session-end state and exact storyline session binding.
2. Enforce the deadline across SSH/RDP transports, process-owned network transactions, and process
   teardown while preserving generated baseline behavior.
3. Keep bounded closure delay in source timing, validate `iteration-test-expanded`, and run one
   final four-reviewer blind panel.

## Acceptance Evidence

### Milestone 1 — Canonical session end and explicit pairing

- Added immutable `SessionEndPlan` state with canonical time, authority, and storyline event
  identity, exposed through `StateManager` planning and lookup APIs.
- Pre-planned each explicit logoff against the latest preceding successful storyline logon, SSH
  session, or RDP session for the same actor and host. The runtime registry retains ordered
  storyline sessions, and the pairing records the allocated LogonID rather than resolving the
  newest live session at logoff time.
- Preserved authoritative session validity across an early SSH/RDP transport disconnect so later
  commands cannot create a replacement session that steals the explicit close.

The expanded scenario exposed an important compatibility case after the initial implementation:
`evt-022` is an explicit successful Type 3 logon with a later `evt-034` logoff. Static pairing now
includes every explicit successful logon type, not only durable interactive types; generated
baseline sessions remain outside the storyline registry.

### Milestone 2 — Authoritative dependent-lifetime bounds

- Passed the end plan through World planning and the SSH, RDP, generic logon, process, and network
  action contracts.
- Durable SSH closes its transport 100–1500 ms before an explicit deadline. RDP may disconnect
  earlier, but an otherwise-open transport is capped before the session end.
- `NetworkTransactionPlanner` rejects process-owned connections beginning at or after an
  authoritative session end and re-finalizes capped transactions so every protocol and sensor
  projection consumes the corrected canonical duration.
- Process creation rejects post-deadline dependent activity. Explicit logoff teardown terminates
  session-owned processes children-first in the final 250–3000 ms and asserts that canonical
  process/connection holds do not survive the deadline.
- Generated baseline logoffs retain their prior stochastic after-last-activity behavior.

### Milestone 3 — Source-visible closure timing

- `SourceTimingPlanner` now tracks the latest dependent time per source and lifecycle group.
- eCAR and Windows logoff observations follow same-source dependent termination by 125–750 ms and
  remain within a 15-second tail of canonical end without rewriting canonical time.
- SSH PAM close follows transport close by 120–2500 ms; logind removal follows by 120–999 ms and
  remains within four seconds of canonical end.
- eCAR and Windows emitters no longer invoke explicit-logoff timestamp repair. They serialize the
  lifecycle and source timing already finalized by the dispatcher.

### Engineering validation

- Focused session, storyline, process-lifetime, network-contract, and source-timing sets: 214
  passed during implementation; the final storyline/logoff/network regression set passed 103.
- `uv run pytest --no-cov`: 4,954 passed, 19 skipped in 306.88 seconds after the final Type 3
  pairing correction.
- `uv run eforge validate-config`: 87 files valid with zero findings.
- `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml`: valid with the
  scenario's 26 pre-existing topology and pivot warnings.
- `uv run ruff check .`, `uv run ruff format --check .`, `git diff --check`, and JSON artifact
  parsing: clean.

### Expanded-scenario acceptance

`iteration-test-expanded` generated 83,906 records across 21 evaluated source families. Automated
evaluation passed at 95.5434 overall: Parseability 100.00, Plausibility 97.31, Causality 88.66,
and Timing 95.26. All 60/60 expected format traces were recovered, all 11,688 causal-order pairs
were correctly ordered, and all 12,404 rate-plausibility checks passed.

The rendered closure probe recovered the two previously missing logoff traces and the additional
explicit Type 3 close:

| Storyline event | Session | Source-visible delay | Identity/tuple result |
|---|---|---:|---|
| `evt-033` / trace 43 | Aisha Type 10/RDP | 2.575 s | Same session object, LogonID, and source tuple |
| `evt-034` | `svc_mhsync` Type 3 | 2.190 s | Same session object, LogonID, and source tuple |
| `evt-035` / trace 45 | APP-INT root SSH | 2.532 s | Same session object, LogonID, and `10.10.3.10:41880` tuple |

The APP-INT SSH observation closed 475 ms before the canonical logoff; both RDP and SSH transports
closed before their deadlines. No source-visible process belonging to any of the three sessions
appeared after its logout. Focused state/planner tests separately assert that canonical processes
and process-owned connections never extend beyond the authoritative end; source-visible process
termination may trail canonical time only inside its bounded source-delay window and still precedes
the source-visible logout.

Machine-readable acceptance artifacts are retained under
`scenarios/iteration-test-expanded/blind-test/session-closure-lifecycle-contract/`.

### Blind panel

The single independent four-reviewer data-only panel produced these initial scores (lower
synthetic confidence is better):

| Reviewer | Verdict | Verdict confidence | Synthetic confidence |
|---|---|---:|---:|
| Threat hunter | Synthetic | 87 | 79 |
| Detection engineer | Real | 78 | 34 |
| Network forensics | Real | 78 | 28 |
| Host/EDR forensics | Synthetic | 86 | 78 |

The initial synthetic-confidence average was 54.75 (`mixed/inconclusive`). The 51-point spread
triggered the assessment protocol's reconciliation pass, not another panel or A/B run. The final
facilitated positions were 83, 63, 44, and 84 respectively, averaging 68.5 (`likely synthetic`).

No reviewer found the intended explicit RDP or APP-INT SSH logoff delayed, rebound to a shadow
session, or retaining a child beyond its authored end. The higher scores instead exposed five
broader residual contracts:

1. 560/811 exact-tuple Windows eCAR remote logins precede their source-visible inbound FLOW,
   concentrated in SMB and Kerberos while SSH ordering remains correct.
2. Three non-authoritative SSH sessions gracefully close before the collection boundary but omit
   their PAM/eCAR/per-connection-process terminal group.
3. 34/279 duration-bearing Zeek file rows end 1–2 ms after their parent connection.
4. Three coherent post-window ASA teardowns conflict with the collection profile's perimeter-tail
   wording.
5. Two distinct Windows 4625 failures share one eCAR authentication object identity.

These findings do not invalidate the explicit-deadline contract in this branch. They belong to
Windows remote-auth source timing, generated/implicit SSH terminal completeness, file-transfer
parent duration, source-family admission policy, and authentication-attempt identity respectively.
The next improvement effort should start with the Windows FLOW-before-login ordering because it is
the broadest reproducible defect and has the largest expected score leverage.

The complete reports, corrected detection review, reconciliation, score artifact, automated eval,
and rendered contract probe are retained under
`scenarios/iteration-test-expanded/blind-test/session-closure-lifecycle-contract/`.

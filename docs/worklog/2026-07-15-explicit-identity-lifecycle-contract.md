# Explicit Identity and Lifecycle Contract

## Scope

This feature branch implements the identity/lifecycle realism family identified by the
`iteration-test-expanded` assessments. The work owns canonical process, thread, and session
identity; lifecycle groups and ordering; explicit eCAR source/target roles; and removal of
renderer-side identity repair. Durable file/task/inventory and broader baseline-texture findings
remain out of scope.

## Branch and integration

- Branch: `codex/explicit-identity-lifecycle-contract`
- Target: `dev`
- Shape: three milestone commits followed by one draft pull request
- Version: unchanged on the feature branch
- Dependency: PR #357 (`codex/network-transaction-observation-contract`)

The branch was initially created from PR #357's exact tip, `d36e0d04`, while GitHub still reported
the PR as open. After the merge completed, it was rebased before the first milestone commit onto
`origin/dev` at merge commit `23feeadd`.

## Family contract

| Truth | Correct owner |
|---|---|
| Process/session/thread object identity and role semantics | Canonical identity plan |
| Durable process, session, and thread existence | `StateManager` state |
| Lifecycle group membership and parentage | Process/auth action bundles |
| Lifecycle ordering and safe source attribution | Identity/lifecycle and source-timing planning |
| Source-local missingness and delay | Observation planning |
| eCAR field names and source-native serialization | eCAR schema/emitter |

Canonical process identity is host- and start-scoped. Canonical thread identity is scoped by
`(hostname, process_object_id, tid)`; PID and TID values themselves remain host-local and may
legitimately repeat on different hosts or after a completed lifecycle.

## Milestones

### Milestone 1 — Canonical identity and thread state

- Status: complete
- Acceptance: deterministic immutable identity snapshots, primary-thread state, explicit remote
  thread registration, cross-host collision resistance, and same-host PID-reuse isolation.

Implemented immutable `ThreadIdentity`, `ProcessIdentity`, `SessionIdentity`, and
`EventIdentityPlan` types. `StateManager` now allocates a durable primary thread with each process,
indexes every live thread by `(hostname, process_object_id, tid)`, validates explicit worker/remote
thread ownership, tears threads down with their owning process, and exposes immutable identity
snapshots. Linux leaders use `tid == pid`; Windows TIDs use a deterministic host-native allocator.
Process and session state now carry lifecycle group IDs, and `EdrContext` can validate its retained
compatibility fields against a canonical plan.

Focused acceptance:

- `uv run pytest --no-cov tests/unit/test_identity_contract.py tests/unit/test_state_manager.py tests/unit/test_state_manager_threading.py tests/unit/test_process_lifetimes.py -q`
  — 128 passed.
- `uv run pytest --no-cov` — 4,961 passed, 19 skipped in 308.52 seconds.

### Milestone 2 — Process and session lifecycle ownership

- Status: complete
- Acceptance: action-bundle ownership, durable lifecycle groups, upstream identity planning,
  causally safe actor attribution, and lifecycle-compatible observation/timing/admission.

Implemented `IdentityLifecyclePlanner` in the dispatcher before state application, observation,
and source timing. It freezes process/session/thread subject, actor, and target roles while live
state still exists; assigns process and session lifecycle groups; models Type 7 unlock as a child
reauthentication; and omits unavailable attribution instead of inventing it. Process access no
longer synthesizes a per-event source TID, and remote-thread creation now registers one durable
target-owned thread.

Process and logon action bundles pass their stable group IDs into state. SSH and RDP bundles now
allocate their own session identities and return them to `WorldPlanner`; ordinary World planning
also requests logon intent without pre-allocating state. Service logons use the same contract, and
session bootstrap process teardown now routes through the process-termination bundle. Fixed
kernel/bootstrap identities (Windows PID 4 and Linux PID 1) use a dedicated canonical
`register_process()` boundary instead of direct dictionary insertion.

Focused acceptance:

- Identity/lifecycle, dispatcher, observation, source timing, eCAR, LogonID, proxy, and systemd
  compatibility sets — 333 passed.
- Activity, World planning, SSH/RDP, process access, and remote-thread sets — 445 passed.
- Regression repairs (thread-local timing, engine mocks honoring bundle ownership, session-kind
  reuse, Sysmon cross-process semantics) — 70 passed.
- Representative deterministic/inbound integrations — 8 passed.
- Adversarial generation integration family — 68 passed.
- `uv run pytest --no-cov -q` — 4,968 passed, 19 skipped in 321.26 seconds.

The first full-suite attempt exposed boot-seeded PID 4/System and PID 1/systemd bypassing the
canonical registration boundary. The fix was made at `StateManager`/engine setup rather than in
the identity planner or emitter; the complete suite passed after that owning-layer repair.

### Milestone 3 — Explicit eCAR roles and renderer simplification

- Status: pending
- Acceptance: eCAR 1.1 optional source/target fields, unambiguous cross-process roles, canonical
  TIDs only, and serialization-only flush behavior.

## Final acceptance

- Focused tests and the normal non-slow suite at each milestone.
- Config validation, Ruff checks, and the complete default suite before final review.
- Generate and evaluate `iteration-test-expanded`, run the identity family probes, then conduct
  one independent four-reviewer blind panel.
- Record commands, results, scorecard, residual findings, and PR handoff here.

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

- Status: complete
- Acceptance: eCAR 1.1 optional source/target fields, unambiguous cross-process roles, canonical
  TIDs only, and serialization-only flush behavior.

Extended the eCAR format compatibly to version 1.1 with optional source and target process UUID,
PID, TID, image, and principal properties. `PROCESS/OPEN` now identifies the opened process as its
object and the opener as its actor; `THREAD/REMOTE_CREATE` identifies the new target-owned thread
as its object, the source process as its actor, and the owning target process explicitly. FLOW
attribution consumes the same frozen identity plan and is omitted as a complete group when safe
canonical ownership is unavailable.

The emitter no longer performs process-state lookups, TID synthesis, service-PID inference, shared
process identity invention, PID remapping, stale-reference filtering, lifecycle timestamp repair,
identity scrubbing, or semantic deduplication. Its flush path now delegates directly to the base
serializer/sorter/writer. Source-visible parent/create/dependent/terminate ordering moved to the
dispatcher-owned `SourceTimingPlanner`, keyed by durable process object identity. Removing the old
repair pipeline deleted roughly 1,400 lines of emitter normalization code and the legacy tests that
invoked those private repairs; upstream planner and serialization-boundary tests replace them.

The rendered acceptance run exposed one owning-layer classification gap: `system_process_create`
events allocated canonical processes and primary threads but were not classified as process starts
by `IdentityLifecyclePlanner`. Adding that event type to the canonical process-start contract made
all 1,881 rendered process creates and all 1,420 terminations carry their canonical primary TID.
The evaluation rule remains strict for CREATE and TERMINATE while dependent rows omit TID unless a
thread is explicitly modeled.

### Blind-gate owning-layer repairs

The first data-only acceptance gate found three material defects that the earlier aggregate probes
did not detect:

- Sysmon cached an emitter-invented `TerminalSessionId` before the canonical RDP session ID became
  available, causing five otherwise-identical eCAR/Sysmon process identities to disagree.
- eCAR projected both canonical endpoint identities into each host-local FLOW observation, leaking
  the remote host's process UUID, PID, image, and principal and exposing future SSH child identity.
- Syslog finalization rewrote canonical SSH child PIDs to force monotonic presentation, creating
  cross-source PID collisions with unrelated live Linux processes.

The repairs stayed at the correct owners. Sysmon now trusts canonical session state and renders
zero when it is unavailable; eCAR keeps both identities in the canonical plan but projects only the
local actor into each source-native FLOW row; and syslog finalization preserves the PID allocated by
the SSH/process bundle. Canonical event occurrence IDs also removed exact eCAR ID reuse, session
closure now waits for all session-owned process evidence, canonical actor activity protects process
lifetimes through dependent events and network close, and Sysmon ProcessAccess requires the
modeled source primary thread.

The material rework justified the plan's one permitted repeat panel. Findings about Windows record
counter texture, DHCP/TLS/DNS timing texture, scan distribution, actor-coverage cliffs, privilege
populations, and broader inventory remain outside this identity/lifecycle contract.

## Final acceptance

`iteration-test-expanded` generated 86,294 records across 20 evaluated sources. Automated
evaluation passed at 95.3421 overall: Parseability 100.00, Plausibility 97.27, Causality 88.02, and
Timing 95.10. Contract gates passed at 86,294/86,294 spec and format checks, 26,618/26,618
co-occurrence checks, 15,613/15,613 cross-source field pairs, 11,854/11,854 causal-order pairs, and
12,833/12,833 rate-plausibility checks.

Rendered identity/lifecycle probes on the corrected output found:

- Zero duplicate eCAR IDs, TID-without-PID rows, missing or mismatched create/terminate primary
  TIDs, post-termination actor references, or session-object mismatches.
- Zero cross-host FLOW actors or remote process identity groups in host-local FLOW observations.
- Zero syslog SSH PID collisions with non-SSH processes or one PID assigned to multiple tuples.
- Zero eCAR/Sysmon terminal-session mismatches across 186 process pairs with canonical sessions.
- Zero nonpositive source TIDs across all 658 Sysmon ProcessAccess records.
- All three visible local Linux bootstrap chains included ordered login, PAM, logind, terminal, and
  shell evidence.

Final engineering gates:

- Focused identity, eCAR, Sysmon, syslog, SSH/RDP, World, and source-timing set — 302 passed.
- `uv run pytest --no-cov -q` — 4,948 passed, 19 skipped in 305.56 seconds.
- `uv run eforge validate-config` — 87 configuration files valid with zero findings.
- `uv run eforge validate scenarios/iteration-test-expanded/scenario.yaml` — valid with the
  scenario's 26 pre-existing topology/storyline warnings.
- Ruff checks, format checks, and `git diff --check` — clean.

Acceptance artifacts are retained under
`scenarios/iteration-test-expanded/blind-test/identity-lifecycle-contract/`.

## Corrected blind panel

The four reviewers inspected only a frozen copy of generated data. They received no scenario,
ground truth, evaluation results, source, tests, repository history, prior panel findings, or other
reviewer reports. The initial independent score spread exceeded 30 points, so the assessment
protocol's single anonymized cross-review round was applied. After reconciliation, all four
reviewers independently accepted the identity/lifecycle contract:

| Reviewer role | Verdict | Verdict confidence | Synthetic confidence | Realism | Identity/lifecycle |
|---|---|---:|---:|---:|---:|
| Threat hunter | Inconclusive | 80 | 48 | 89 | 96 |
| Detection engineer | Inconclusive | 86 | 47 | 88 | 95 |
| Network forensics | Inconclusive | 86 | 47 | 88 | 95 |
| Host/EDR forensics | Inconclusive | 84 | 47 | 89 | 95 |

The panel found zero hard identity, lifecycle, actor/target-role, SSH PID, terminal-session, or
network ownership contradictions. Residual synthetic signals were explicitly outside the phase's
contract: narrow population timing, scan and service-coverage distributions, stable sensor-clock
relationships without calibration data, curated collection-manifest language, and Windows record
counter/export texture. Those findings remain inputs to the next baseline/source-texture effort.

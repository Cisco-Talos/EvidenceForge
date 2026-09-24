# Iteration-Test Assessment Loops 97–101

Five family-first realism assessment loops requested on 2026-09-24. The durable benchmark is
`scenarios/iteration-test/scenario.yaml`; loop artifacts live under
`scenarios/iteration-test/blind-test/v2-loop-N/`.

## Loop 97 Family Contract

### Finalized process-dependent source timing

- **Classification:** `sibling_defect`, `hard_contradiction`, and `family_level`; Loop 96 rendered
  six eCAR module loads for the exact `runas.exe` process identity 45 seconds after its visible
  termination.
- **Owning abstraction:** `SourceTimingPlanner` owns finalized endpoint observation times and the
  per-process dependent frontier used to place source-visible termination. Typed action and
  transport constraints own causal phase ordering; a session-wide admission frontier does not.
- **Invariant:** source-visible process creation precedes every retained MODULE, FILE, REGISTRY,
  FLOW, PROCESS_OPEN, THREAD, and child-process dependent for that identity, and source-visible
  termination follows them. Unrelated activity in the same interactive session cannot move a
  retroactively materialized credential helper's startup evidence outside its own lifecycle.
- **Entry paths:** baseline and storyline process execution, Type 9/NewCredentials bootstrap,
  service/task/remote-admin execution, startup and runtime module loads, file/registry effects,
  network ownership, process access, remote thread creation, and child process creation.
- **Consumers:** eCAR, Sysmon, Windows Security, process/session source timing, logoff ordering,
  lifecycle probes, and evaluator temporal/linkability checks.
- **Layer rationale:** canonical process state correctly rejects activity outside the modeled
  lifetime and emitters render the finalized plan. The defect arose between preliminary source
  timing and later session constraints, so the timing planner is the first shared owner capable of
  preventing the contradiction in every endpoint source.
- **Sibling risks:** preserve login-before-dependent and logoff-after-dependent relationships,
  typed KDC/SMB/proxy/SSH/RDP ordering, parent-before-child and child-before-parent-close rules,
  source-native Sysmon envelopes, observation loss, collection cutoff behavior, bounded cache
  retention, and checkpoint determinism.

## Loop 97 Result

- Commit `0cca756a` moved process-dependent frontier publication after final source-time constraint
  resolution and prevented unrelated same-session activity from shifting process-owned dependents.
- Routine verification passed: 11,710 tests, 48 skipped, 2,030 deselected; Ruff check/format;
  92 packaged configuration files; behavior revision 148 and digest
  `89ef920882eb8b1b2b23d5b894f9ef99f39492c98f97708b2efec129b0751d6a`.
- Generation produced 122,048 records. Deterministic evaluation passed at 96.9729. The hard probe
  checked 1,804 terminated eCAR processes and found zero dependents outside their lifetime,
  including both prior `runas.exe` offenders.
- Initial blind synthetic-confidence scores were 58, 30, 27, and 52 (mean 41.75). Deliberation
  classified the result mixed/inconclusive at 47.5 and upheld two exact SMB process/share ownership
  mismatches as the highest-priority defect.
- Next family: canonical SMB action/process ownership and explicit shell execution semantics for
  adjacent collection commands.

## Loop 98 Family Contract

### Exact Type 9 SMB operation ownership

- **Classification:** `hard_contradiction`, `contract_gap`, and `family_level`; Loop 97 rendered two
  exact, valid SMB tuples under adjacent PowerShell processes whose command targets named a
  different share or no remote operation at all.
- **Owning abstraction:** the typed storyline SMB handler owns the exact source-visible client
  operation process before the canonical SMB action bundle freezes process, transport, tree, and
  file identity. The shared storyline shell frontier owns bounded sibling readiness.
- **Invariant:** every credentialed Type 9 SMB browse, read, create, update, delete, copy, or move is
  attributed to a live helper whose command names the operation's exact share/path. Sequential
  helpers under the same controller do not overlap, terminate only after their own SMB dependents,
  and do not collapse into a group-end termination cluster.
- **Entry paths:** typed storyline SMB operations using a Windows NewCredentials session, including
  share targets, share-to-client and client-to-share transfers, batched selection, Windows-native
  access to Samba, success and denied outcomes.
- **Consumers:** canonical SMB sessions/trees/operations, network connection ownership, eCAR FLOW
  and PROCESS records, Windows Security/Sysmon process evidence, Zeek conn/smb_mapping/smb_files,
  local file effects, and ground truth.
- **Layer rationale:** downstream bundles preserved the exact PID they received; emitters rendered
  it faithfully. The defect was the pre-bundle fallback to the newest live Type 9 process, so the
  typed storyline operation-process owner is the first shared layer capable of preventing semantic
  cross-assignment.
- **Sibling risks:** preserve the local token versus outbound SMB principal split, exact LUID and
  controller identity, authored downstream timing, process-before-transport and
  dependents-before-termination ordering, batch completion, non-Type9/baseline Explorer ownership,
  explicit concurrency, checkpoint state, cutoff behavior, and retry-stable persistent SMB roots.

## Loop 98 Result

- Commits `c64ae348`, `5beb3b6f`, and `c1b965ee` replaced newest-live attribution with exact Type 9
  SMB operation helpers, serialized the collection children, and narrowed generic Windows closure
  to the independently owned SMB boundary.
- Final verification passed: 11,711 tests, 48 skipped, 2,030 deselected; Ruff check/format; 92
  packaged configuration files; behavior revision 150 and digest
  `26eacbea6a1a7b53e2e242648b9997a767fee3b7078d2db847be60f55f0bcba6`.
- Generation produced 122,017 records. Deterministic evaluation passed at 96.3163. The hard probe
  found zero overlap across seven collection children and exact command/share ownership on all five
  SMB flows.
- Initial blind synthetic-confidence scores were 66, 68, 36, and 48 (mean 54.5). Deliberation
  reached a Synthetic consensus at 61.75 and ranked one-use PKINIT certificate identity as the
  highest-leverage recurring family.
- Next family: stable canonical Kerberos credential identity keyed by directory SID and credential
  epoch.

## Loop 99 Family Contract

### Stable canonical Kerberos credential epochs

- **Classification:** `distribution_texture`, `environment_or_collection_plausibility`, and
  `family_level`; multiple panels observed that every PKINIT 4768 request uses a fresh certificate
  identity, including repeated principals and closely spaced cross-DC requests.
- **Owning abstraction:** canonical Kerberos credential identity resolution owns the long-lived
  authentication credential for a directory principal. Ticket requests own request-local fields,
  while emitters only render the resolved credential identity.
- **Invariant:** repeated PKINIT TGT requests for one canonical SID reuse the same certificate
  issuer, serial, thumbprint, and public-key identity within a deterministic credential epoch,
  across domain controllers and independent ticket requests. User and machine eligibility and CA
  profile selection remain scope-aware.
- **Entry paths:** baseline and storyline TGT requests, DC prerequisite bundles, domain logons,
  machine-account authentication, explicit credentials, remote administration, SMB, RDP, and
  any future PKINIT-capable Kerberos request path.
- **Consumers:** Windows Security 4768, Kerberos request contexts, DC-side audit evidence, principal
  state, evaluator distribution checks, and blind authentication hunting.
- **Layer rationale:** per-request certificate sampling in the Kerberos realism helper creates the
  churn before Windows rendering. A SID-keyed credential resolver is the first shared layer that
  can preserve identity across all DCs and request paths without emitter-local reconstruction.
- **Sibling risks:** preserve ticket-local encryption/pre-auth variation, password-based Kerberos,
  smart-card versus enterprise issuance semantics, user/machine scoping, certificate-format
  validity, cross-process and cross-DC determinism, checkpoint/retry neutrality, bounded cache
  retention, and data-driven CA/profile pools.

## Loop 99 Result

- Commit `01167d78` introduced pure SID/scope/profile/epoch credential identity derivation and
  scope-aware PKINIT profiles without mutable caches.
- Verification passed: 11,715 tests, 48 skipped, 2,030 deselected; Ruff check/format; 92 packaged
  configuration files; behavior revision 151 and digest
  `59274ba66fad539871a172c7ed69b903918d2554df8fa03f7142e9ba4b2fa4c6`.
- Generation produced 129,694 records. The deterministic score was 96.0836 but failed pivot
  linkability (78.67/80) and temporal integrity (83.67/85). The family hard probe passed: 30 PKINIT
  requests reduced to eight stable credentials, with all six repeated principals and all four
  cross-DC principals preserving one exact certificate identity.
- Initial blind synthetic-confidence scores were 68, 66, 47, and 58 (mean 59.75). Deliberation
  reached a Synthetic consensus at 65.75 and independently confirmed two matched Type 3 sessions
  that lose their named principal only at logout.
- Next family: canonical SMB/Type 3 session-principal preservation through paired lifecycle
  consumers.

## Loop 100 Family Contract

### Canonical SMB session-principal preservation

- **Classification:** `hard_contradiction`, `contract_gap`, and `family_level`; two DC-01 Type 3
  sessions render a named Security/eCAR login but a blank principal on the matched Security 4634
  and eCAR logout for the same LogonID.
- **Owning abstraction:** canonical authentication session allocation owns the effective principal
  for the entire lifecycle. For SMB sessions, the explicit SMB principal may refine local account
  identity, but an omitted refinement must resolve to the authenticated user rather than an empty
  sentinel.
- **Invariant:** every successful SMB/Type 3 session stores a non-empty canonical principal and
  preserves username, SID, domain, LogonID, source tuple, authentication protocol, and lifecycle
  identity across login, dependents, and paired logout. No emitter reconstructs or substitutes the
  identity.
- **Entry paths:** baseline SMB sessions, explicit-credential/runas remote access, storyline SMB
  bundles, Windows remote administration, machine/service authentication, and compatibility calls
  to generic logon generation with `session_kind="smb"`.
- **Consumers:** StateManager session state, AuthContext, Security 4624/4634, eCAR LOGIN/LOGOUT,
  SMB operation attribution, lifecycle validation, evaluator pivots, and blind hunt timelines.
- **Layer rationale:** the explicit-credential bundle supplies a real user but omits the optional
  SMB-principal override; generic session allocation persists that empty value, and generic logoff
  later prefers it over the user. Resolving the fallback once at the canonical logon boundary fixes
  every consumer without renderer-specific repair.
- **Sibling risks:** preserve Type 9 local-token versus outbound-principal separation, machine
  accounts, qualified-domain and UPN inputs, Linux SMB clients, non-SMB sessions, failed logons,
  preallocated sessions, checkpoint state, logon-guid/session-object identity, and source-native
  field omission rules.

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

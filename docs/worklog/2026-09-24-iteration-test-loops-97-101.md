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


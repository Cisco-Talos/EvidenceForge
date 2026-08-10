# Loop 48 Assessment Report

Loop 48 regenerated 81,305 records after the Loop 47 SSH policy repair.
Automated evaluation scored 96.4156 and failed only pivot linkability. The SSH
family probe covered 109 successful authentications across 20
user/source/target tuples: zero tuples mixed methods, and all three modeled
administrator client/user identities used one durable key across targets.

The initial blind panel was Inconclusive/Synthetic/Inconclusive/Real at
39/66/41/34, average 45.0. Verdict disagreement and a 32-point spread triggered
deliberation. Final role scores were 49/64/43/52, with an Inconclusive consensus
at synthetic score 52 and verdict confidence 84.

## Fresh Findings

- Detection found repeated Windows session teardown triplets that terminated
  `explorer.exe`, `userinit.exe`, and `winlogon.exe` in exact 50 ms steps across
  unrelated hosts and sessions.
- Those session bootstrap helpers had termination-only endpoint evidence;
  `userinit.exe` also remained alive until logout instead of exiting after
  handing off to Explorer.
- Detection found several short Linux utility terminations without visible
  creates despite bash-history evidence placing execution inside the window.
- Network found no schema or contract contradiction and rated Zeek, ASA, IDS,
  proxy timing, tuple, UID, and accounting behavior strongly.
- Host and Network independently found low-diversity public scanner/UFW noise;
  Host also found overused Windows maintenance processes and scripts.

## Selected Improvement

**Family:** Windows interactive session bootstrap process lifecycle and teardown
timing. **Classification:** `family_level` canonical lifecycle repair.

Session-specific winlogon, userinit, and Explorer processes now receive visible
create events. Userinit exits shortly and variably after Explorer starts.
Remaining session processes close child-before-parent with deterministic,
process-scoped variable gaps instead of a fixed 50 ms template.

## Verification

The Loop 47 SSH family probe is clean. The focused Windows activity, process
lifetime, and state-manager suites pass 488 tests, including a new regression
for visible shell-process creates, early userinit exit, and non-50-ms logout
spacing. Loop 49 will validate the rendered Windows lifecycle independently.

## Prioritized Remaining Findings

- **P1:** Apply coherent create/terminate observation grouping to short-lived
  Linux utility processes.
- **P1:** Expand public scanner and UFW source/fingerprint diversity.
- **P2:** Make Windows and Linux fleet maintenance role-specific rather than
  reusing compact executable/script pools.
- **P2:** Reduce broad administrative-access topology and command repetition.

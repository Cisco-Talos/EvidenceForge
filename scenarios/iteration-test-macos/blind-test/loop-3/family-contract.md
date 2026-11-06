# Loop 3 family contract

- **Family / classification:** authoritative macOS session close cadence; recurring `sibling_defect` from loop 1 and loop 2.
- **Owner:** `ActivityGenerator._plan_generic_logoff_process_closes`, which owns canonical process termination instants inside an authoritative session-end plan.
- **Invariant:** unrelated processes closed by one exact macOS session end have deterministic, process-scoped timing variation within the existing bounded closure window; every dependent process closes after its children and every close remains before the exact session deadline.
- **Entry paths:** generic local macOS logoff from typed storyline events and baseline/session lifecycle finalizers; also exact process/session teardown sequences that use the same planner. Non-authoritative Windows/Linux timing remains on its existing policy.
- **Consumers:** canonical StateManager/lifecycle process endings, native macOS Endpoint Security exit observations, eCAR and session-close source projections, ground-truth lifecycle accounting, and evaluation chronology.
- **Rationale:** the exact 100 ms pattern is created before source rendering when the generic session planner assigns canonical close times. Changing emitters would leave State and sibling source truth on the same staircase.
- **Sibling risk:** preserve session deadline clamps, parent-after-child ordering, live-process/connection holds, process identity, and retry-stable timestamps. Verify multiple process families and more than one Mac session; do not relax source coverage.
- **Fix type:** `family_level`.

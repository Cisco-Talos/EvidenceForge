# Loop 72 family contract — profile-scoped browser roots

- **Owner:** canonical process state and the shared browser-instance identity/reuse policy in
  `generation/activity/browser_instances.py` and `generation/actions/process_support/reuse.py`.
- **Invariant:** for one host, user, executable, and resolved user-data directory, ordinary
  browsing requests reuse one eligible live canonical root; explicit independent profiles remain
  distinct, and native process/fork/exec/exit evidence follows the canonical process lifetime.
- **Entry paths:** baseline persona browsing via `WorldPlanner.ensure_connection_process`,
  direct/storyline `ActivityGenerator.generate_process`, and explicit-proxy/network owner
  attribution via `_ensure_user_connection_owner_process`; source-bounded callers must not create
  duplicate roots when reuse is not yet visible.
- **Consumers:** StateManager process identity/lifecycle, eCAR process and flow ownership,
  Windows Security/Sysmon, and macOS Endpoint Security fork/exec/exit rendering.
- **Why this layer owns the truth:** profile identity and whether an existing process can serve a
  request are shared application-instance semantics; emitter-side suppression would hide a real
  canonical root and break sibling evidence.
- **Sibling risks:** Windows and macOS baseline paths may differ in command line and visibility
  timing; explicit user-data directories, independent-instance flags, Firefox named profiles,
  historical lifetimes, and bounded source deadlines must remain distinct and correctly handled.
- **Classification before changes:** loop65/68 reports retained this family; current code already
  contains a shared profile-key/reuse implementation. This loop first probes the unchanged
  loop71 output and a fresh fixed-seed generation. If all invariants hold, record this as
  `false_positive_or_unproven` for current output and make no code change; only a reproduced
  sibling gap authorizes edits in this family.

# Batch 7: compatibility removal and documentation reconciliation

## Scope and baseline

- Branch: `codex/batch7-compatibility-docs`
- Parent: Batch 6 commit `03401ad0`
- Contract: remove legacy mutable or duplicate truth only after every affected producer and
  consumer uses the canonical owner; reconcile public architecture, scenario, source, evaluation,
  and review status with enforced behavior.
- Constraint: no silent public API/schema migration and no version bump. A compatibility surface
  with live consumers remains explicitly gated instead of being removed by assertion.

## Removal-readiness audit

### Removal-ready internal paths

1. `module_load` is an unreachable emitter alias. Production emits the registered `image_load`
   event; no production `SecurityEvent` constructor produces `module_load`.
2. `special_privileges` is an unreachable canonical-event alias. Windows Event 4672 is a
   source-native projection of an elevated `logon`; no production constructor emits a separate
   `special_privileges` occurrence.
3. `_nat_swaps_by_sensor` duplicates the final tuple/locality already owned by immutable
   `NetworkSensorObservation`. NAT policy remains in `NatContext` and topology/visibility; the
   observation planner can derive the final sensor view directly before freezing it.
4. Dispatcher-side process activity updates from delayed source copies violate the canonical-time
   boundary. `StateManager.apply()` already consumes the canonical event time and finalized
   network close, so observation delay must not extend runtime state.

### Not removal-ready without a separately approved migration

- `SecurityEvent.event_type: str`, mutable context slots, and the compatibility carrier: 67
  constructor sites and all dispatcher/emitter consumers still use this shape. Dispatch admission
  can be enforced independently, but replacing the carrier is not behavior-preserving.
- `NetworkContext` flat tuple/accounting/timing fields: the immutable transaction is authoritative
  after finalization, but roughly 300 direct field references still construct or project the
  compatibility view.
- `EdrContext` object/actor/thread fields: many event families still acquire the canonical
  `EventIdentityPlan` during dispatcher planning, so construction-time removal would break direct
  generator/emitter paths.
- TLS/X.509/OCSP/proxy mutable contexts and their immutable plans: migrated transaction paths use
  the plans, while retained transparent, direct-helper, and source-projection paths still consume
  the context views.
- singular `ids` plus `ids_alerts`: automatic and authored alert paths intentionally enter through
  different compatibility shapes before `all_ids_alerts()` provides the common projection.
- `RawLogEntry`/`RawContext`: explicitly approved escape hatches outside cross-source consistency
  guarantees, not legacy debt to remove.

These retained surfaces are architectural migration debt, not proof that their duplicate values
are equally authoritative. Batch 7a tightens documentation and executable drift checks around
that distinction; Batch 7b remains an approval-gated migration.

## Verification plan

1. Add negative tests proving the two dead event aliases have no emitter/registry admission.
2. Move NAT tuple/locality derivation into `NetworkObservationPlanner`, delete the event-side map,
   and preserve multi-sensor/static/dynamic NAT rendered evidence.
3. Remove source-observation feedback into process/session state and prove state is format/profile
   independent while rendered delay remains intact.
4. Regenerate static inventories and representative network/profile outputs; compare canonical
   ledgers and common source evidence in proportion to intentional changes.
5. Reconcile README, architecture, scenario/evaluation references, finding statuses, roadmap, and
   a machine-readable Batch 7 disposition ledger.
6. Run Ruff, focused suites, full non-slow tests, targeted parallel equivalence, and review probes.

## Implementation

### Closed dispatch admission and identity repairs

- `EventDispatcher` now rejects any contract seal with violations before assigning an event ID,
  applying state, making observation decisions, or calling an emitter.
- Existing incomplete dispatcher test placeholders were replaced with minimal valid canonical
  occurrences. Representative minimal and branch-office generation had zero contract violations
  before enforcement.
- The full suite exposed two real niche producer gaps. Late process termination now resolves its
  durable ended-process identity by object ID, and the SSH bundle rejects an unowned or
  contradictory caller-supplied LogonID/object pair instead of publishing parallel identity
  truth. Valid SSH paths use one `StateManager`-owned session identity.

### Removed duplicate ownership

- Removed the unreachable eCAR `module_load` and Windows `special_privileges` admissions. Their
  supported semantics remain canonical `image_load` and source-native Event 4672 logon fan-out.
- Removed `SecurityEvent._nat_swaps_by_sensor` and the Zeek compatibility fallback. The observation
  planner now derives static-inbound and dynamic-outbound tuple/locality views from the frozen
  transaction, `NatContext`, and sensor topology, then freezes `NetworkSensorObservation`.
- Removed dispatcher feedback from delayed source copies into process activity state. Canonical
  state is updated once from the canonical event; source delay remains projection-only.

### Static and rendered evidence

- Regenerated the tracked census: 31 authored specs, 64 discovered event types, 67 constructors,
  38 mutable contexts, 27 plans/identities, 51 bundles, and 23 formats. There are no unresolved
  dynamic constructors, emitter contract types without a producer, or path-classification gaps.
- The Batch 6 parent and Batch 7 branch produce byte-identical complete-profile branch-office
  `data/` trees across 40 files (`fbb7ba1a…b7f68d479e`).
- Under `enterprise_standard`, endpoint output changes where the parent incorrectly allowed source
  delay to extend canonical process state. Both the parent and current rendered invariant probes
  report zero findings.

### Documentation and disposition

- Reconciled README, architecture, event-model design, scenario seed/include/workload reference,
  evaluation limits/categories, security disposition, review census/report, and all remediated
  finding statuses.
- Split the roadmap into completed behavior-preserving Batch 7a and approval-gated Batch 7b. The
  retained mutable carrier/context surfaces have live consumers and must not be removed as cleanup.

## Verification status

- Focused contract/dispatcher/network/NAT/Zeek suite: 146 passed.
- Producer-gap regression slice: 4 passed.
- Initial full non-slow suite: 5,224 passed, 41 skipped; four producer gaps were then repaired. The
  remaining Splunk loopback-bind failure is a sandbox restriction and requires the scoped
  unrestricted rerun.
- Final unrestricted non-slow suite: 5,230 passed, 41 skipped in 243.43 seconds. Ruff check and
  format, review JSON parsing, and `git diff --check` pass. Optional Docker/licensed external
  parser tests remain skipped by their existing dependency gates; the local Splunk harness unit
  suite passed with loopback access. Exact evidence is in `batch7-results.json`.

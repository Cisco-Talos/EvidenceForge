# Event, Context, Bundle, and Output Path Census

## Status

Static census and manual path classification are complete for baseline commit
`0a035e97d94cd2a35ebd1498cc4e133336fe14a4`. Dynamic contract probes and the
source-native reference audit are complete with the limitations recorded in the empirical and
reference ledgers; neither activity changed generator behavior.

The machine-readable source of truth is
[`event-context-paths.json`](event-context-paths.json). Grouped human review decisions live in
[`path-classifications.json`](path-classifications.json), and
[`coverage-summary.json`](coverage-summary.json) proves that no inventoried row remains
unclassified.

## Inventory boundary

The deterministic AST extractor covers every Python source and test file under `src/evidenceforge`
and `tests`. It records typed scenario specifications, literal and finite dynamic event names,
`SecurityEvent` constructors, context constructors and consumers, action bundles, generator call
sites, state-manager call sites, concrete format registrations, emitter contracts, evaluator
references, and test references.

| Contract family | Reviewed rows |
|---|---:|
| Authored event specifications | 31 |
| All discovered event names | 66 |
| `SecurityEvent` constructors | 68 |
| Dynamic constructor sites | 7 |
| Context dataclasses | 38 |
| Plans and identities | 27 |
| Concrete action bundles | 51 |
| Concrete output formats | 23 |
| Generator methods with call sites | 57 |
| State-manager methods with call sites | 53 |

The original extractor undercounted internal events because it only followed literal constructor
arguments and comparisons. The corrected inventory takes the union of producers and emitter
contracts, then resolves the finite dynamic domains for file actions, scheduled-task actions, and
group-membership actions. That surfaced twelve additional dynamically produced names and two
emitter-only names. This correction is evidence that the present string-based event contract is not
self-enumerating.

## Entry-path conclusions

Every parallel path was classified as an intentional adapter, a behaviorally equivalent alternate
entry, an incompatible bypass, a duplicate owner, or an unsupported escape hatch. Rows with no
parallel path are explicitly marked `single_canonical_path`.

### Authored intent

All 31 typed specifications enter through `StorylineMixin._execute_typed_event`. Authored macro
events such as `beacon`, `credential_spray`, `dga_queries`, `dns_tunnel`, `process`, `spillage`, and
`adversarial_payload` intentionally expand into lower-level canonical occurrences. The authored
name is not expected to survive as a `SecurityEvent.event_type`.

The `process` branch has the broadest authored fan-out. Depending on OS, command, and declared
effects it may request logon or service-logon setup, a Bash or process occurrence, network
connections, SSH, explicit credential use, file side effects, and process termination. The branch
uses canonical public methods for most families but still directly constructs the storyline
output-file occurrence. This is an alternate file entry, not a second process owner.

### Canonical high-fan-out families

- `generate_connection` has 64 static call sites. All real transports converge on
  `NetworkConnectionActionBundle` and `NetworkTransactionPlanner`. The sole direct `connection`
  constructor outside that planner is an application-layer-only proxy request on an already-open
  CONNECT tunnel. EDR and Sysmon explicitly reject that event as transport evidence.
- Logon compatibility calls converge through `LogonActionBundle`; Windows Type 10 with a real
  remote source delegates to `RdpSessionActionBundle`, and Linux remote-interactive compatibility
  delegates to the SSH path. Generic, machine, anonymous, service, RDP, and SSH sessions retain
  distinct bundle owners.
- `SshSessionActionBundle` owns TCP/22, auth/PAM/logind phases, endpoint session occurrence, and
  close intent. `RdpSessionActionBundle` owns the RDP client/transport/Type 10 relationship and
  delegates transport through `NetworkConnectionActionBundle`.
- Dynamic scheduled-task and group-membership names are finite and produced by one bundle family
  each. File-action names are finite but are produced by multiple real-world action owners.

### Parallel paths that need remediation design

1. **Process creation crosses the projection boundary.** Parent-chain repair can directly build a
   `process_create` occurrence outside `ProcessExecutionActionBundle`, and the Sysmon emitter builds
   a synthetic `SecurityEvent(event_type="process_create")` to recompute a source timestamp for a
   `ProcessGuid`. The latter is an incompatible bypass because source timing is shared truth.
2. **Process termination has two owners.** User processes use `ProcessTerminationActionBundle`,
   while system-process termination has a separate direct implementation that independently
   coordinates state removal, source timing, identity, and rendering.
3. **File and image occurrences have equivalent alternate entries.** File events are directly built
   by process side effects, storyline output handling, transfer bundles, remote-service
   installation, and baseline EDR noise. Image loads have an automatic process side-effect path and
   a public direct path. They currently use compatible contexts, but no shared builder enforces it.
4. **Thin bundles expose an ownership-shaped API without owning execution.** Thirty-three anchored
   bundles delegate immediately to legacy `_execute_*` methods. This is a useful convergence layer,
   but the implementation owner remains `ActivityGenerator` or the baseline/storyline monolith.
5. **Email lifecycle identity is weaker than peer families.** `EmailDeliveryActionBundle` and
   `EmailAccessActionBundle` are thin delegates with no `ActionAnchor` and no direct bundle tests.
   `EmailContext` is attached to connection planning but consumed by no emitter or evaluator;
   SMTP rendering uses `SmtpContext` and artifact generation uses bundle-local results.
6. **Two emitter names have no producer.** `module_load` and `special_privileges` remain in emitter
   support tables without a production `SecurityEvent` producer. Module evidence uses `image_load`.
   Windows event 4672 is renderer-side fan-out from a `logon`.
7. **`zeek_weird` is registered but not generated.** `WeirdContext` has no production constructor,
   automatic weird generation is disabled, and only direct emitter tests exercise the format.

### Intentional exclusions and adapters

- `raw` is an explicit escape hatch. `RawContext` is consumed by `EventDispatcher.dispatch_raw`,
  and raw records are outside cross-source consistency guarantees. The remaining review covers raw
  target validation, payload safety, path behavior, and documentation.
- Nested IDS filter/policy dataclasses and `ProcessTargetSecurityContext` are value objects inside
  their parent contexts, not missing top-level event contexts.
- `sensor_startup`, generic `syslog`, Bash history, and similar source-local occurrences may be
  built directly because they do not own shared transport/session facts. Their fidelity remains
  subject to source-specific review.

## Object and plan ownership observations

The frozen identity, authentication, network, cryptographic, lifecycle, proxy, and world-model
plans have coherent intended owners. Two timing structures are exceptions:

- `SourceTimingPlan` is mutable and can be populated/finalized by generators, dispatcher logic, and
  emitters. Source timing is distributed rather than exclusively owned by `SourceTimingPlanner` at
  the observation boundary.
- `TemporalNode` is mutable by design, but it is solver workspace rather than a published canonical
  plan. Its mutability is acceptable only while it remains private to constraint-graph resolution.

All 38 occurrence contexts are mutable. For shared facts, ownership is conventional rather than
enforced even where the census found only one current producer. The proposed contract package will
distinguish immutable published snapshots from private mutable builders.

## Output projection conclusions

Twenty-one formats appear projection-only in the static trace. Two need explicit contract changes:

- `windows_event_sysmon` recomputes destination hostname from a global reverse-DNS registry and
  creates a synthetic canonical event to obtain process-create timing.
- `windows_event_security` projects most occurrences but also owns 4672 record fan-out from a logon
  while advertising an otherwise unreachable `special_privileges` input type.

This does not complete source-native fidelity assessment. Field morphology, nullability, native
time semantics, ordering, parser behavior, and target-specific transformations are evaluated in the
reference and empirical ledgers.

## Reproduction

```bash
uv run --extra dev python scripts/realism_review_inventory.py
uv run --extra dev ruff check scripts/realism_review_inventory.py
uv run --extra dev ruff format --check scripts/realism_review_inventory.py
jq '.review_state, .path_classification_gaps' \
  docs/design/realism-review/coverage-summary.json
```

The final command must report `manual_path_classification: complete` and empty `missing` and
`unknown` arrays for events, contexts, plans/identities, bundles, and formats.

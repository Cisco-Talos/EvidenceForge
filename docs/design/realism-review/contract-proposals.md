# Approved Canonical Contracts

Status: **approved 2026-08-05 with the amendments recorded below**

Baseline: `0a035e97d94cd2a35ebd1498cc4e133336fe14a4`

These contracts are the smallest coherent set that addresses the review's root causes. Approval
authorizes incremental implementation on feature branches; it does not authorize an unreviewed
public schema migration or one campaign-long change set.

Batch 7b implementation amendment, approved 2026-08-08:

- EvidenceForge has no supported public Python API. Internal constructors, carriers, and context
  views migrate directly to the approved end state without deprecation periods or compatibility
  layers.
- The supported boundary for this migration is the CLI, authored scenario schema, and source-native
  output contracts. The ground-truth artifact may advance to a new schema version and remove the
  redundant sequence-derived dispatch identifier.
- Runtime identity and lifecycle indexes optimize hot lookup latency first when lookup speed and
  memory conflict. They must nevertheless remain duration-stable: lookup cost may not grow with
  elapsed scenario duration, and retained history must have an explicit bounded or referenced
  lifetime.

## Approved decisions

The user approved the package with six binding amendments:

- ground truth retains an independent authored-intent ledger and reconciles intent, plans,
  occurrences, and observations rather than projecting only generated facts;
- occurrence identity prefers stable semantic instance keys over positional ordinals;
- missing infrastructure fails validation by default and is synthesized only under an explicit
  scenario policy;
- one action owner means one authority for each shared fact and lifecycle, not one monolithic
  implementation class;
- observation coherence and evaluation gates represent legitimate partial visibility explicitly;
- path and resource safety move into the early foundation work rather than waiting for the last
  migration batch.

Within those amendments, the following decisions are approved:

1. **Internal event kinds become closed and typed.** Authored YAML event names remain the existing
   discriminated union; internal occurrence kinds move from free strings to a registry-backed enum.
2. **One action authority owns every shared fact and lifecycle.** Baseline, storyline, red-herring,
   startup, and causal callers submit the same typed action request. They may use separate intent
   adapters and composable planners, but they do not independently allocate shared evidence.
3. **Published occurrences are immutable.** Mutable builders are private. A single seal operation
   validates legal context combinations and creates immutable occurrence snapshots.
4. **Action identity is explicit.** Every action has one stable `ActionId`; every emitted occurrence
   has a declared `OccurrenceRole` and a stable semantic instance key. Positional ordinals are
   reserved for intrinsically anonymous repetitions and never depend on global dispatch sequence.
5. **Canonical and observed time are different types.** State accepts canonical time only. Source
   timing and collection delay cannot mutate canonical state.
6. **Observation is group-coherent.** Drop/delay decisions apply to declared source-local lifecycle
   groups, not independently to rows that must remain joinable.
7. **Emitters are projection-only.** An emitter may derive source-local formatting fields, but may
   not allocate shared identity, resolve shared hostnames, retime canonical occurrences, or create
   sibling canonical events.
8. **Ground truth reconciles independent intent and execution ledgers.** It consumes authored
   intent, sealed action/occurrence, and observation ledgers rather than separately maintained
   storyline dictionaries, and it exposes omissions between each transition.
9. **Input resource budgets are first-class contracts.** Validation estimates work before
   generation/evaluation and requires an explicit override above documented defaults.

## 1. Event-kind contract

The proposed registry is authoritative and machine-readable. Each internal kind declares:

```python
@dataclass(frozen=True, slots=True)
class EventKindContract:
    kind: EventKind
    required_contexts: frozenset[ContextKind]
    optional_contexts: frozenset[ContextKind]
    forbidden_contexts: frozenset[ContextKind]
    source_host_role: HostSemantic
    destination_host_role: HostSemantic
    identity_requirement: IdentityRequirement
    lifecycle_role: LifecycleRole
    state_effect: StateEffect
    permitted_producers: frozenset[ActionKind]
    emitter_consumers: frozenset[FormatKind]
    evaluator_consumers: frozenset[EvaluatorContract]
```

Proposed enforcement:

- `SecurityEvent` is replaced internally by a builder and a frozen `CanonicalOccurrence`.
- `seal()` rejects an unknown kind, missing/forbidden context, illegal host-direction combination,
  absent required identity/lifecycle, or a producer that does not own the kind.
- `EventDispatcher.dispatch()` accepts only sealed occurrences.
- `raw` remains a separate `RawProjectionRequest` and is never registered as a canonical kind.
- Renderer fan-out such as Windows 4624 -> 4672 is declared as multiple projections of one
  occurrence. `special_privileges` is not advertised as a separately producible event unless a
  real canonical occurrence is added later.

Migration seed: generate the initial registry from the reviewed 66-row path matrix, then require
an explicit manual decision for every row. The generated inventory becomes a CI closure check.

## 2. Action contract and occurrence identity

Every correlated activity uses a typed request/result pair:

```python
@dataclass(frozen=True, slots=True)
class ActionRequest:
    action_id: ActionId
    kind: ActionKind
    intent_time: CanonicalTime
    actor: ActorRef | None
    source_host: HostRef | None
    destination_host: HostRef | None
    parent_action_id: ActionId | None

@dataclass(frozen=True, slots=True)
class PlannedAction:
    action_id: ActionId
    timeline: ActionTimeline
    occurrences: tuple[CanonicalOccurrence, ...]
    state_commands: tuple[StateCommand, ...]
    truth: ActionTruth
```

`OccurrenceId` is derived from `ActionId`, a finite `OccurrenceRole`, and a stable semantic instance
key. An ordinal is permitted only for an intrinsically anonymous repetition and must be assigned
from a deterministic ordering independent of global dispatch sequence. This preserves replay while
preventing unrelated preceding or sibling events from renumbering later evidence.

An action may request a lower-level action, such as SSH requesting a network connection, but it
must do so through a typed child request. Rendered source rows never trigger actions.

The existing substantial network, SSH, RDP, proxy, browser, and cryptographic planners are the
starting implementations. Thin bundles are migration adapters until their `_execute_*` behavior
is moved behind the typed contract.

## 3. Identity and lifecycle contract

The identity directory publishes immutable references:

```python
@dataclass(frozen=True, slots=True)
class SessionIdentity:
    host: HostId
    logon_id: LogonId
    logon_guid: LogonGuid | NotApplicable
    principal: PrincipalId
    kind: SessionKind
    lifecycle_group: LifecycleGroupId

@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    host: HostId
    process_id: ProcessObjectId
    pid: int
    session: SessionIdentity
    image: CanonicalPath
    role: ProcessRole
```

Rules:

- A process cannot be reattached to another session.
- Reuse queries require identity equality, including `SessionIdentity`, not just username/image.
- A one-shot process may own one action unless a declared multiplexing capability exists.
- Dependents and termination must fall within the owning lifecycle interval.
- Session fields such as LogonGuid are finalized before the first dependent occurrence and never
  upgraded later.
- Failed authentication attempts use an attempt identity, not a successful-session identity, and
  include an explicit ordinal.
- Process roles declare legal parent roles. Parent-chain repair cannot cross incompatible roles.

This contract resolves the current SSH process reuse, post-logoff evidence, mutable LogonGuid,
failed-attempt collision, Explorer ancestry, and Linux login-tree defects as one ownership family.

## 4. Time contract

Three types make the boundary explicit:

```python
CanonicalTime  # world/action occurrence and all StateManager commands
ObservedTime   # coverage delay/drop result for one source-local observation group
RenderedTime   # source clock/timezone/precision projection
```

An `ActionTimeline` is frozen before state application:

```python
@dataclass(frozen=True, slots=True)
class ActionTimeline:
    canonical_nodes: Mapping[TimelineRole, CanonicalTime]
    intervals: Mapping[IntervalRole, CanonicalInterval]
    constraints: tuple[TemporalConstraint, ...]
```

The source planner consumes the timeline and emits an immutable `SourceTimingProjection`. It may
shift or drop observations within declared bounds, but it cannot write to StateManager. Child
source records consume the parent's final source-visible interval; they do not independently call
clock/jitter planners.

Required examples:

- RDP/SSH endpoint FLOW precedes successful authentication for the matching tuple.
- Zeek file/analyzer rows remain inside the final sensor-visible connection interval.
- Process dependents and termination remain inside the canonical process/session lifecycle.
- Source close evidence may differ naturally across sources while remaining lifecycle-compatible.

## 5. Observation-group contract

Each occurrence declares zero or more source-local observation groups:

```python
@dataclass(frozen=True, slots=True)
class ObservationGroup:
    group_id: ObservationGroupId
    source: FormatKind
    policy: ObservationPolicyRef
    members: tuple[OccurrenceProjectionRef, ...]
    coherence: ObservationCoherence
```

`ObservationCoherence` initially supports:

- `atomic`: drop/delay all members together;
- `ordered_subset`: optional members may drop, retained members preserve declared order;
- `independent`: only for truly source-local, non-lifecycle evidence.

Process create/dependent/terminate, session login/logout, and network/protocol companions declare
either `atomic` or `ordered_subset` based on the real source's collection behavior. `ordered_subset`
is the ordinary lifecycle default so observation does not become unrealistically tidy. Evaluation
distinguishes retained contradictions from legitimate declared partial visibility.

## 6. Network, protocol, and IDS contract

The current immutable `NetworkTransactionPlan` becomes the canonical template. One plan owns:

- canonical tuple and source/destination semantics;
- transport outcome/state and interval;
- directional packet/byte ledgers;
- source port, Zeek UID, NAT/routing, and sensor-visible tuple;
- source-process reference when valid;
- protocol children and file-transfer identities;
- IDS attachment eligibility.

IDS signatures gain structured preconditions:

```python
@dataclass(frozen=True, slots=True)
class SignaturePredicate:
    direction: PayloadDirection
    phase: TransportPhase
    requires_response: bool
    minimum_payload_bytes: int
    application_protocol: ApplicationProtocol | None
    inspection: InspectionCapability
    semantic_claim: SemanticClaim
```

The predicate is evaluated after transport and protocol outcome planning. A 403/server-response
signature cannot attach to S0/zero-response traffic, and an HTTP-body signature cannot attach to
opaque TLS without a modeled inspection capability.

## 7. Projection contract

Each emitter implements a narrow interface:

```python
class SourceProjector(Protocol):
    format_kind: FormatKind

    def project(
        self,
        occurrence: CanonicalOccurrence,
        observation: SourceObservation,
        timing: SourceTimingProjection,
    ) -> tuple[RenderedRecord, ...]: ...
```

Allowed source-local derivation includes record IDs, provider constants, timestamp formatting,
null markers, escaping, field ordering, and documented renderer fan-out. Forbidden derivation
includes shared hostnames, hashes, PIDs, LogonIDs/Guids, tuples, accounting, network UIDs,
certificate identities, action outcome, and canonical/source timing selection.

Projection purity is tested by running the same canonical ledger through full, filtered, and
parallel emitter sets and requiring byte-identical output for each common format.

## 8. World/capability contract

`WorldModel` becomes authoritative for typed capabilities rather than fallback IPs and naming
heuristics:

```python
@dataclass(frozen=True, slots=True)
class HostCapabilities:
    host: HostId
    os: OsFamily
    roles: frozenset[HostRole]
    services: frozenset[ServiceCapability]
    identities: HostIdentitySet
    network_attachments: tuple[NetworkAttachment, ...]
```

Action preflight requests capabilities such as `DhcpServer`, `DnsResolver`, `DomainController`,
`RdpClient`, or `SshReceiver`. If no valid distinct owner exists, validation rejects the scenario
by default. It may create synthetic infrastructure only when the scenario explicitly selects that
policy and records the synthesized owner in the world and truth ledgers. It never silently assigns
the only endpoint to mutually incompatible roles.

## 9. Ground-truth and evaluation contract

Ground truth reconciles an immutable `AuthoredIntentLedger` with `PlannedAction`,
`CanonicalOccurrence`, and the observation ledger. Authored intent remains independent of what the
generator successfully planned so missing actions cannot disappear from the evaluation oracle.
It does not maintain a parallel imperative event dictionary. Every planned truth assertion
references `ActionId` and occurrence roles; every expected source is derived from observation
decisions, while unplanned or unobserved intent remains an explicit reconciliation result.

Evaluation acceptance is separated into:

- parseability and source-schema conformance;
- canonical cross-source invariants;
- declared scenario completeness;
- distribution/realism diagnostics;
- optional expert-review comparison.

Required invariant or coverage denominators cannot receive a vacuous 100. Missing declared
indicators, high-impact temporal inversions, duplicate stable identities, or impossible semantic
attachments become explicit hard gates.

## 10. Input and workload budget contract

Validation computes a `WorkloadEstimate` before allocation:

```python
@dataclass(frozen=True, slots=True)
class WorkloadEstimate:
    canonical_occurrences: int
    rendered_records_by_format: Mapping[FormatKind, int]
    artifact_bytes: int
    input_bytes: int
    include_files: int
    include_depth: int
```

Defaults bound scenario duration, periodic expansion, CIDR enumeration, attachment bytes, include
graphs, archive extraction, parser record bytes, and evaluation corpus size. Legitimate scale work
uses a named explicit override recorded in the manifest; it does not bypass path/symlink safety.

## Incremental migration order

1. Land the registry, semantic occurrence-key scaffolding, authored-intent ledger scaffolding, and
   seal validation; generate closure checks from the current matrix and fail CI for inventory
   drift or invalid dispatch admission.
2. Establish shared safe-path and workload-budget boundaries early, with compatibility defaults
   and explicit manifests, before expanding the input surface further.
3. Introduce typed time domains and stop observation-to-state feedback.
4. Introduce ActionId/OccurrenceRole identity and the action/occurrence ledger alongside existing
   event IDs and ground truth.
5. Fix identity/lifecycle ownership as one vertical slice: sessions, processes, SSH, RDP, failed
   auth, Windows/Linux bootstrap.
6. Promote the network plan to the complete transport/protocol/IDS contract; bind file/analyzer
   timing to final sensor intervals.
7. Move baseline/storyline/red-herring callers behind the same bundle request per family, then
   retire direct stateful constructors and thin legacy delegates.
8. Enforce projection purity and format-filter/parallel equivalence; remove emitter shared-truth
   recomputation.
9. Reconcile authored intent, action, occurrence, observation, and ground-truth ledgers; harden
   evaluator acceptance without treating declared partial visibility as a failure.
10. Complete remaining workload budgets and external-parser staging constraints.
11. Replace internal compatibility fields and legacy event names directly once their consumers are
    migrated. Do not retain internal aliases. Treat CLI, authored scenario-schema, or source-output
    contract changes as separately approved migrations; version ground-truth schema changes.

## Implementation boundary

Implementation proceeds as bounded commits on the cumulative feature branch. The foundation batch
established contracts without changing public scenario schemas. Batch 7b may now enforce the final
internal contracts directly, replace sequence-derived internal event IDs, and advance the
ground-truth schema. It must not change CLI syntax, authored scenario schemas, or source-native
format contracts without separate approval.

Batch 7b implemented this approved boundary on 2026-08-08. Reproducible hashes, duration-scaling
measurements, generation comparisons, and verification results are recorded in
`batch7b-results.json`.

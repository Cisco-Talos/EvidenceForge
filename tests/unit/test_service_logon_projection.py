# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Generator-side exact projection contracts for Windows Type-5 logons."""

from __future__ import annotations

import copy
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier, Event, Thread
from unittest.mock import Mock

import pytest

import evidenceforge.events.dispatcher as dispatcher_types
import evidenceforge.generation.activity.generator as generator_module
from evidenceforge.events.dispatcher import (
    ActionCohortProjectionOutcome,
    ActionCohortPublicationResult,
    EventDispatcher,
)
from evidenceforge.events.identity import EntityIdentity
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions import ServiceLogonRequest
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models import System, User
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.utils.rng import _stable_seed, stable_uuid

_TIME = datetime(2026, 1, 15, 10, 0, tzinfo=UTC)


class _FakeStateNeutralProjectionPublicationResult:
    """Base-tip stand-in for the not-yet-composed exact dispatcher result."""

    __slots__ = ("intent", "projection", "receipt", "timing")

    def __init__(
        self,
        *,
        receipt: object,
        timing: object,
        intent: object,
        projection: ActionCohortProjectionOutcome,
    ) -> None:
        self.receipt = receipt
        self.timing = timing
        self.intent = intent
        self.projection = projection


class _FakePublicationReceipt:
    """Mutable base-tip receipt shape for focused dispatcher protocol fakes."""

    __slots__ = ("occurrence_ids", "root_action_id", "state_semantic_id")

    def __init__(self) -> None:
        self.occurrence_ids: tuple[str, ...] = ()
        self.root_action_id = ""
        self.state_semantic_id = ""


@pytest.fixture(autouse=True)
def _install_state_neutral_result_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """Install the frozen dispatcher result shape while tests run on the clean base."""

    if hasattr(dispatcher_types, "StateNeutralProjectionPublicationResult"):
        return
    monkeypatch.setattr(
        dispatcher_types,
        "StateNeutralProjectionPublicationResult",
        _FakeStateNeutralProjectionPublicationResult,
        raising=False,
    )


def _projection_outcome(
    occurrence_id: str,
    *,
    status: str = "succeeded",
    error: BaseException | None = None,
) -> ActionCohortProjectionOutcome:
    """Build one exact outcome in a requested fake terminal state."""

    outcome = ActionCohortProjectionOutcome(occurrence_id)
    object.__setattr__(outcome, "_status", status)
    object.__setattr__(outcome, "_error", error)
    return outcome


def _state_neutral_result(
    receipt: object,
    occurrence_id: str,
    *,
    status: str = "succeeded",
    error: BaseException | None = None,
    receipt_occurrence_id: str | None = None,
) -> object:
    """Build one fake exact state-neutral publication result."""

    if type(receipt) is _FakePublicationReceipt:
        receipt.occurrence_ids = (receipt_occurrence_id or occurrence_id,)
    result_type = dispatcher_types.StateNeutralProjectionPublicationResult
    return result_type(
        receipt=receipt,
        timing=object(),
        intent=object(),
        projection=_projection_outcome(occurrence_id, status=status, error=error),
    )


def _action_cohort_result(
    receipt: object,
    occurrence_id: str,
    *,
    status: str = "succeeded",
    error: BaseException | None = None,
) -> ActionCohortPublicationResult:
    """Build one exact named-cohort result for the base-tip fake protocol."""

    if type(receipt) is _FakePublicationReceipt:
        receipt.occurrence_ids = (occurrence_id,)
    return ActionCohortPublicationResult(
        receipt=receipt,
        state=object(),
        lifecycle=object(),
        audit=object(),
        artifacts=None,
        intent=None,
        timing=object(),
        projections=(
            _projection_outcome(
                occurrence_id,
                status=status,
                error=error,
            ),
        ),
    )


def _bind_fake_action_receipt(
    receipt: object,
    root_action_id: object,
    state_plan: object,
) -> None:
    """Bind one focused fake receipt to the exact named cohort being prepared."""

    if type(receipt) is _FakePublicationReceipt:
        state_semantic_id = getattr(state_plan, "semantic_id", None)
        if type(root_action_id) is not str or type(state_semantic_id) is not str:
            raise AssertionError("Fake action receipt requires exact semantic identities")
        receipt.root_action_id = root_action_id
        receipt.state_semantic_id = state_semantic_id


def _strict_service_runtime() -> tuple[
    ActivityGenerator,
    StateManager,
    LifecycleRegistry,
    EventDispatcher,
    SourceTimingPlanner,
    Mock,
]:
    """Return one production-shaped State/lifecycle/timing owner graph."""

    state = StateManager()
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow)
    runtime = TimingRuntime(reference_time=_TIME)
    timing = SourceTimingPlanner(
        clock_profile_name="complete",
        timing_runtime=runtime,
    )
    emitter = Mock()
    emitter.can_handle.return_value = True
    emitters = {"windows_event_security": emitter}
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters=emitters,
        timing_runtime=runtime,
        source_timing_planner=timing,
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        timing_runtime=runtime,
        source_timing_planner=timing,
        lifecycle_shadow=shadow,
        lifecycle_authority=authority,
    )
    state.set_current_time(_TIME)
    return generator, state, registry, dispatcher, timing, emitter


def _real_exact_service_runtime(
    output_root: Path,
    *,
    threaded: bool = False,
) -> tuple[
    ActivityGenerator,
    StateManager,
    LifecycleRegistry,
    EventDispatcher,
    WindowsEventEmitter,
    EcarEmitter,
]:
    """Return a real generator/dispatcher/Windows/eCAR exact owner graph."""

    state = StateManager()
    registry = LifecycleRegistry()
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow)
    runtime = TimingRuntime(reference_time=_TIME)
    timing = SourceTimingPlanner(
        clock_profile_name="complete",
        timing_runtime=runtime,
    )
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        output_root / "windows",
        threaded=threaded,
        source_finalization=True,
    )
    ecar = EcarEmitter(load_format("ecar"), output_root / "ecar", threaded=threaded)
    emitters = {
        "windows_event_security": windows,
        "ecar": ecar,
    }
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters=emitters,
        timing_runtime=runtime,
        source_timing_planner=timing,
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        timing_runtime=runtime,
        source_timing_planner=timing,
        lifecycle_shadow=shadow,
        lifecycle_authority=authority,
    )
    state.set_current_time(_TIME)
    return generator, state, registry, dispatcher, windows, ecar


def _expected_service_audit_snapshot(request: ServiceLogonRequest) -> object:
    """Return the deterministic one-plan/no-effect audit snapshot for a request."""

    counter = ExecutionEffectAuditCounter()
    plan = ExecutionEffectPlan(
        ActionAnchor(
            family="service_logon",
            stable_id=request.stable_id,
            source=request.source,
        ),
        (),
    )
    counter.record(plan.reconcile(()))
    return counter.snapshot()


def _exact_source_bytes(output_root: Path) -> dict[str, bytes]:
    """Return only final source-native Windows/eCAR records."""

    return {
        str(path.relative_to(output_root)): path.read_bytes()
        for path in sorted(output_root.rglob("*"))
        if path.is_file() and path.name in {"windows_event_security.xml", "ecar.json"}
    }


def _system() -> System:
    return System(
        hostname="APP-01",
        ip="10.0.0.20",
        os="Windows Server 2022",
        type="server",
    )


def _sid_only_generator() -> ActivityGenerator:
    """Return a generator with one realistic domain SID allocator seed."""

    return ActivityGenerator(
        StateManager(),
        {},
        sid_registry={"seed-account": "S-1-5-21-100-200-300-1100"},
    )


def _precommit_census(
    generator: ActivityGenerator,
    state: StateManager,
    registry: LifecycleRegistry,
    dispatcher: EventDispatcher,
    timing: SourceTimingPlanner,
) -> tuple[object, ...]:
    """Return every live preparation/canonical count relevant to Type-5 admission."""

    timing_preparations = timing.preparation_authority_census()
    return (
        state.materialization_digest(),
        state.materialization_version,
        state.preview_logon_id("APP-01", _TIME),
        registry.census(),
        registry.action_cohort_preparation_census(),
        dispatcher.action_cohort_publication_census(),
        timing.state_digest(),
        timing_preparations.retained_preparations,
        timing_preparations.active_claims,
        timing_preparations.terminal_preparations,
        timing_preparations.retained_receipts,
        timing_preparations.capacity,
        tuple(sorted(generator.sid_registry.items())),
        (hasattr(generator, "_domain_sid_prefix"), getattr(generator, "_domain_sid_prefix", None)),
        (hasattr(generator, "_max_rid"), getattr(generator, "_max_rid", None)),
        (
            generator._sid_reservation_census()[0],
            generator._sid_reservation_census()[1],
            generator._sid_reservation_census()[3],
        ),
    )


def _assert_timing_lane_reusable(timing: SourceTimingPlanner) -> None:
    """Prove one failed operation released the planner's exclusive owner lane."""

    marker = RuntimeError("timing lane reuse probe")
    with pytest.raises(RuntimeError) as raised:
        with timing.prepared_planning():
            raise marker
    assert raised.value is marker


def test_sid_allocator_without_reservations_preserves_the_legacy_serial_formula() -> None:
    """The leaf lock does not perturb ordinary deterministic SID allocation."""

    generator = _sid_only_generator()
    username = "ordinary-principal"
    expected_rid = 1100 + 1 + (_stable_seed(f"unknown_sid_{username}") % 50)

    assert generator._get_sid(username) == f"S-1-5-21-100-200-300-{expected_rid}"
    assert generator._max_rid == expected_rid
    assert generator._sid_reservation_census() == (0, 0, 0, 1024)


def test_generated_sid_reservation_fences_concurrent_allocators_until_commit() -> None:
    """Another allocator skips an active RID while the owner commits outside callbacks."""

    generator = _sid_only_generator()
    canonical_before = dict(generator.sid_registry)
    reservation, reserved_sid = generator._reserve_sid("svc-reserved")
    assert generator.sid_registry == canonical_before
    assert not hasattr(generator, "_domain_sid_prefix")
    assert not hasattr(generator, "_max_rid")

    start = Barrier(2)
    allocated = Event()
    failures: list[BaseException] = []
    other_sids: list[str] = []

    def allocate_other() -> None:
        try:
            start.wait(timeout=3)
            other_sids.append(generator._get_sid("concurrent-principal"))
        except BaseException as error:
            failures.append(error)
        finally:
            allocated.set()

    worker = Thread(target=allocate_other)
    worker.start()
    start.wait(timeout=3)
    assert allocated.wait(timeout=3)
    assert generator._commit_sid_reservation(reservation) == reserved_sid
    worker.join(timeout=3)

    assert not worker.is_alive()
    assert failures == []
    assert len(other_sids) == 1
    assert other_sids[0] != reserved_sid
    assert int(other_sids[0].rsplit("-", 1)[1]) > int(reserved_sid.rsplit("-", 1)[1])
    assert generator.sid_registry["svc-reserved"] == reserved_sid
    assert generator._sid_reservation_census() == (0, 0, 1, 1024)


def test_same_account_sid_reservations_are_ref_safe_and_install_exactly_once() -> None:
    """Shared account tokens retain one SID across cancellation and multiple commits."""

    generator = _sid_only_generator()
    first, expected_sid = generator._reserve_sid("svc-shared")
    second, second_sid = generator._reserve_sid("svc-shared")
    assert second_sid == expected_sid
    assert generator._cancel_sid_reservation(first)
    assert generator._sid_reservation_census()[:2] == (1, 1)
    assert generator._get_sid("svc-shared") == expected_sid
    assert generator._commit_sid_reservation(second) == expected_sid
    assert generator.sid_registry["svc-shared"] == expected_sid
    assert generator._sid_reservation_census()[:2] == (0, 0)

    third, third_sid = generator._reserve_sid("svc-shared")
    fourth, fourth_sid = generator._reserve_sid("svc-shared")
    assert third_sid == fourth_sid == expected_sid
    assert generator._commit_sid_reservation(third) == expected_sid
    assert generator._commit_sid_reservation(fourth) == expected_sid
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_sid_reservation_cap_and_terminal_reclaim_are_constant_time() -> None:
    """The 1024-token authority rejects before mutation and reclaims every token."""

    generator = _sid_only_generator()
    capacity = generator._sid_reservation_census()[3]
    reservations = [generator._reserve_sid("svc-capacity")[0] for _ in range(capacity)]
    assert generator._sid_reservation_census() == (1, capacity, capacity, capacity)

    with pytest.raises(StateError, match="capacity is exhausted"):
        generator._reserve_sid("svc-over-capacity")

    assert generator._sid_reservation_census() == (1, capacity, capacity, capacity)
    for reservation in reservations:
        assert generator._cancel_sid_reservation(reservation)
    assert generator._sid_reservation_census() == (0, 0, capacity, capacity)


@pytest.mark.parametrize("reservation_kind", ["generated", "explicit"])
def test_sid_token_allocation_failure_rolls_back_every_reservation_index(
    monkeypatch: pytest.MonkeyPatch,
    reservation_kind: str,
) -> None:
    """Token allocation failure occurs before any group/index/canonical mutation."""

    generator = _sid_only_generator()
    canonical_before = dict(generator.sid_registry)

    def fail_token_allocation(*_args: object, **_kwargs: object) -> object:
        raise MemoryError("injected SID token allocation failure")

    monkeypatch.setattr(generator_module, "_SidReservation", fail_token_allocation)
    with pytest.raises(MemoryError, match="token allocation failure"):
        if reservation_kind == "generated":
            generator._reserve_sid("svc-allocation-failure")
        else:
            generator._reserve_explicit_sid(
                "created-allocation-failure",
                "S-1-5-21-100-200-300-1200",
            )

    assert generator.sid_registry == canonical_before
    assert generator._sid_reservation_census() == (0, 0, 0, 1024)
    assert not hasattr(generator, "_domain_sid_prefix")
    assert not hasattr(generator, "_max_rid")


def test_sid_reservation_rejects_copied_foreign_stale_and_tampered_tokens() -> None:
    """Only the exact untampered owner-retained capability can commit or cancel."""

    generator = _sid_only_generator()
    foreign_generator = _sid_only_generator()
    reservation, expected_sid = generator._reserve_sid("svc-token")
    copied = copy.copy(reservation)

    with pytest.raises(StateError, match="stale or already terminal"):
        generator._commit_sid_reservation(copied)
    assert not generator._cancel_sid_reservation(copied)
    with pytest.raises(StateError, match="foreign or malformed"):
        foreign_generator._commit_sid_reservation(reservation)

    object.__setattr__(reservation, "_sid", f"{expected_sid}-tampered")
    with pytest.raises(StateError, match="stale or already terminal"):
        generator._commit_sid_reservation(reservation)
    assert not generator._cancel_sid_reservation(reservation)
    object.__setattr__(reservation, "_sid", expected_sid)
    assert generator._cancel_sid_reservation(reservation)
    with pytest.raises(StateError, match="stale or already terminal"):
        generator._commit_sid_reservation(reservation)
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_sid_reservation_kind_tamper_cannot_callback_under_leaf_lock() -> None:
    """Malformed token scalars reject before hostile hash/equality can reenter the leaf lock."""

    generator = _sid_only_generator()
    reservation, _sid = generator._reserve_sid("svc-hostile-kind")
    callback_entered = Event()
    failures: list[BaseException] = []

    class _HostileKind:
        def __hash__(self) -> int:
            callback_entered.set()
            generator._sid_reservation_census()
            return 0

    object.__setattr__(reservation, "_kind", _HostileKind())

    def reject_tampered_token() -> None:
        try:
            generator._commit_sid_reservation(reservation)
        except BaseException as error:
            failures.append(error)

    worker = Thread(target=reject_tampered_token, daemon=True)
    worker.start()
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert not callback_entered.is_set()
    assert len(failures) == 1
    assert type(failures[0]) is StateError

    object.__setattr__(reservation, "_kind", "generated")
    assert generator._cancel_sid_reservation(reservation)
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_explicit_sid_reservation_rejects_conflicts_before_install() -> None:
    """A storyline SID claim rejects same-account and exact active-RID conflicts."""

    generator = _sid_only_generator()
    explicit_sid = "S-1-5-21-100-200-300-1200"
    reservation = generator._reserve_explicit_sid("created-user", explicit_sid)
    with pytest.raises(StateError, match="active account"):
        generator._reserve_explicit_sid("created-user", f"{explicit_sid}1")
    with pytest.raises(StateError, match="reserved RID"):
        generator._reserve_explicit_sid("other-user", explicit_sid)
    assert "created-user" not in generator.sid_registry

    assert generator._commit_sid_reservation(reservation) == explicit_sid
    assert generator.sid_registry["created-user"] == explicit_sid
    assert generator._max_rid == 1200
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_shared_explicit_sid_remains_collision_reserved_by_a_generated_token() -> None:
    """Dropping one explicit token cannot expose its SID while a shared token remains."""

    generator = _sid_only_generator()
    collision_username = "collision-principal"
    collision_rid = 1100 + 1 + (_stable_seed(f"unknown_sid_{collision_username}") % 50)
    explicit_sid = f"S-1-5-21-100-200-300-{collision_rid}"
    explicit = generator._reserve_explicit_sid("created-user", explicit_sid)
    generated, shared_sid = generator._reserve_sid("created-user")
    assert shared_sid == explicit_sid
    assert generator._cancel_sid_reservation(explicit)

    allocated_sid = generator._get_sid(collision_username)

    assert allocated_sid != explicit_sid
    assert int(allocated_sid.rsplit("-", 1)[1]) == collision_rid + 1
    assert generator._cancel_sid_reservation(generated)
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_account_created_sid_reservation_cancels_on_dispatch_failure_then_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed 4720 leaves no target binding; a later success installs the exact SID."""

    generator, state, _registry, dispatcher, _timing, emitter = _strict_service_runtime()
    actor = User(username="operator", full_name="Operator", email="operator@example.test")
    target_sid = "S-1-5-21-100-200-300-1200"
    generator.sid_registry[actor.username] = "S-1-5-21-100-200-300-1101"
    original_dispatch = dispatcher.dispatch_builder
    failure = RuntimeError("injected account-created dispatch failure")

    def fail_account_created(event: object) -> object:
        if event.event_type == "account_created":
            raise failure
        return original_dispatch(event)

    monkeypatch.setattr(dispatcher, "dispatch_builder", fail_account_created)
    with pytest.raises(RuntimeError) as raised:
        generator.generate_account_created(
            actor=actor,
            system=_system(),
            time=_TIME,
            target_username="created-user",
            target_sid=target_sid,
        )

    assert raised.value is failure
    assert "created-user" not in generator.sid_registry
    assert generator._sid_reservation_census()[:2] == (0, 0)

    monkeypatch.setattr(dispatcher, "dispatch_builder", original_dispatch)
    generator.generate_account_created(
        actor=actor,
        system=_system(),
        time=_TIME,
        target_username="created-user",
        target_sid=target_sid,
    )

    assert generator.sid_registry["created-user"] == target_sid
    assert generator._sid_reservation_census()[:2] == (0, 0)
    account_events = [
        call.args[0]
        for call in emitter.emit.call_args_list
        if call.args[0].event_type == "account_created"
    ]
    assert len(account_events) == 1
    assert account_events[0].account_management.target_sid == target_sid
    assert state.get_sessions_for_user(actor.username)


def test_account_created_conflict_rejects_before_any_4720_dispatch() -> None:
    """An active same-account SID owner rejects a conflicting storyline SID pre-output."""

    generator, _state, _registry, _dispatcher, _timing, emitter = _strict_service_runtime()
    actor = User(username="operator", full_name="Operator", email="operator@example.test")
    generator.sid_registry[actor.username] = "S-1-5-21-100-200-300-1101"
    reservation, reserved_sid = generator._reserve_sid("created-user")
    conflicting_sid = f"{reserved_sid}1"

    with pytest.raises(StateError, match="active account"):
        generator.generate_account_created(
            actor=actor,
            system=_system(),
            time=_TIME,
            target_username="created-user",
            target_sid=conflicting_sid,
        )

    assert emitter.emit.call_count == 0
    assert "created-user" not in generator.sid_registry
    assert generator._cancel_sid_reservation(reservation)
    assert generator._sid_reservation_census()[:2] == (0, 0)


def test_named_type5_stable_id_failure_precedes_sid_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fallible request identity is frozen before any SID capability is issued."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected stable-id failure")

    def fail_stable_id(_request: ServiceLogonRequest) -> str:
        raise failure

    monkeypatch.setattr(ServiceLogonRequest, "stable_id", property(fail_stable_id))
    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, "svc-stable-id")

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert emitter.emit.call_count == 0


@pytest.mark.parametrize(
    ("account", "expected_luid"),
    [
        ("SYSTEM", "0x3e7"),
        ("LOCAL SERVICE", "0x3e5"),
        ("NETWORK SERVICE", "0x3e4"),
    ],
)
def test_builtin_type5_is_state_neutral_authentication_occurrence(
    monkeypatch: pytest.MonkeyPatch,
    account: str,
    expected_luid: str,
) -> None:
    """A built-in token projects one auth occurrence without a session owner."""

    generator, state, registry, dispatcher, timing, _emitter = _strict_service_runtime()
    system = _system()
    captured = []
    receipt = _FakePublicationReceipt()

    def publish_state_neutral(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        captured.append(occurrence)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        return _state_neutral_result(receipt, occurrence.occurrence_id)

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        publish_state_neutral,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        lambda candidate: candidate is receipt,
        raising=False,
    )
    state_digest = state.materialization_digest()
    lifecycle_census = registry.census()
    timing_digest = timing.state_digest()

    logon_id = generator.generate_service_logon(system, _TIME, account)

    assert logon_id == expected_luid
    assert len(captured) == 1
    occurrence = captured[0]
    expected_request = ServiceLogonRequest(system=system, time=_TIME, service_account=account)
    assert isinstance(occurrence.identity_plan.subject, EntityIdentity)
    assert occurrence.identity_plan.subject.kind == "authentication_occurrence"
    assert occurrence.identity_plan.subject.semantic_key == expected_request.stable_id
    assert occurrence.identity_plan.subject.hostname == system.hostname
    assert occurrence.identity_plan.actor is None
    assert occurrence.identity_plan.target is None
    assert occurrence.identity_plan.session is None
    assert occurrence.event_type == "logon"
    assert occurrence.dst_host.hostname == system.hostname
    assert occurrence.auth.username == account
    assert (
        occurrence.auth.user_sid
        == {
            "SYSTEM": "S-1-5-18",
            "LOCAL SERVICE": "S-1-5-19",
            "NETWORK SERVICE": "S-1-5-20",
        }[account]
    )
    assert occurrence.auth.source_ip == "-"
    assert occurrence.auth.source_port == 0
    assert occurrence.auth.subject_sid == "S-1-5-18"
    assert occurrence.auth.subject_username == "SYSTEM"
    assert occurrence.auth.subject_domain == "NT AUTHORITY"
    assert occurrence.auth.subject_logon_id == "0x3e7"
    assert occurrence.auth.logon_process == "Advapi"
    assert occurrence.auth.auth_package == "Negotiate"
    assert occurrence.auth.lm_package == "-"
    assert occurrence.lifecycle.group_id == stable_uuid(
        "windows-built-in-service-authentication-occurrence",
        system.hostname,
        expected_luid,
        expected_request.stable_id,
    )
    assert occurrence.lifecycle.canonical_start == _TIME
    assert occurrence.lifecycle.phase == "start"
    assert occurrence.lifecycle.parent_group_id is None
    assert state.get_session(expected_luid) is None
    assert state.materialization_digest() == state_digest
    assert registry.census() == lifecycle_census
    assert timing.state_digest() == timing_digest


@pytest.mark.parametrize("threaded", [False, True])
def test_named_type5_composes_real_windows_and_ecar_exact_publication(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """A named service token commits one State session and both exact sinks."""

    generator, state, registry, dispatcher, windows, ecar = _real_exact_service_runtime(
        tmp_path,
        threaded=threaded,
    )
    request = ServiceLogonRequest(
        system=_system(),
        time=_TIME,
        service_account="svc-backup",
    )
    prior_state_version = state.materialization_version
    try:
        logon_id = generator.generate_service_logon(
            request.system,
            request.time,
            request.service_account,
        )

        session = state.get_session(logon_id)
        assert session is not None
        assert session.username == "svc-backup"
        assert session.logon_type == 5
        assert state.materialization_version == prior_state_version + 1
        assert registry.census().live_sessions == 1
        assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
        dispatcher.assert_exact_projection_recoveries_drained()
        assert generator.execution_effect_audit_snapshot() == _expected_service_audit_snapshot(
            request
        )
        windows_census = windows.exact_candidate_census()
        assert (
            windows_census.current_rows,
            windows_census.released_rows,
            windows_census.current_participants,
            windows_census.completed_participants,
        ) == (2, 2, 1, 1)
        assert len(ecar._writers) == 1
        ecar_writer = next(iter(ecar._writers.values()))
        assert ecar_writer._sorted_writer is not None
        ecar_census = ecar_writer._sorted_writer.exact_journal_census()
        assert (
            ecar_writer._sorted_writer.event_count,
            ecar_census.admitted_rows,
            ecar_census.pending_export_rows,
            ecar_census.reserved_rows,
            ecar_census.live_receipts,
        ) == (1, 1, 1, 0, 0)
    finally:
        windows.close()
        ecar.close()

    exact_census = windows.exact_candidate_census()
    assert exact_census.current_rows == 0
    assert exact_census.current_bytes == 0
    assert exact_census.current_participants == 0
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0
    source_bytes = _exact_source_bytes(tmp_path)
    assert {Path(path).name for path in source_bytes} == {
        "windows_event_security.xml",
        "ecar.json",
    }
    assert all(source_bytes.values())
    assert (
        hashlib.sha256(
            next(content for path, content in source_bytes.items() if path.endswith(".xml"))
        ).hexdigest()
        == "9ae7ab331ed889f073997ed34325d7ed0a63f60c3182d193c8638ca53f71786f"
    )
    assert (
        hashlib.sha256(
            next(content for path, content in source_bytes.items() if path.endswith(".json"))
        ).hexdigest()
        == "1493767f8b7271e3a65ea441091cbbad8087f3f7caab7e46d03f1098a69516ce"
    )


@pytest.mark.parametrize(
    "fault_mode",
    ["windows_4672", "ecar_before", "ecar_after"],
)
def test_named_type5_real_multisink_retry_is_exact_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_mode: str,
) -> None:
    """One retained batch resumes after a later Windows/eCAR admission failure."""

    request = ServiceLogonRequest(
        system=_system(),
        time=_TIME,
        service_account="svc-backup",
    )
    reference_root = tmp_path / "reference"
    reference = _real_exact_service_runtime(reference_root)
    reference_generator, _, _, reference_dispatcher, reference_windows, reference_ecar = reference
    try:
        reference_generator.generate_service_logon(
            request.system,
            request.time,
            request.service_account,
        )
        reference_dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        reference_windows.close()
        reference_ecar.close()

    fault_root = tmp_path / "fault"
    generator, state, registry, dispatcher, windows, ecar = _real_exact_service_runtime(fault_root)
    original_windows_commit = windows._commit_exact_candidate_row
    original_ecar_commit = ExternalSortedLineWriter._commit_exact_row
    original_resume = dispatcher.resume_action_cohort_projection
    faulted = False
    resume_receipts: list[object] = []

    def commit_windows(key: tuple[str, int, int], digest: str, frozen: object) -> None:
        nonlocal faulted
        if fault_mode == "windows_4672" and key[2] == 1 and not faulted:
            faulted = True
            raise RuntimeError("injected Windows 4672 admission failure")
        original_windows_commit(key, digest, frozen)

    def commit_ecar(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal faulted
        if fault_mode.startswith("ecar") and not faulted:
            faulted = True
            if fault_mode == "ecar_after":
                original_ecar_commit(writer, key, digest, frozen)
            raise RuntimeError("injected eCAR admission failure")
        original_ecar_commit(writer, key, digest, frozen)

    def resume_same_batch(receipt: object) -> ActionCohortPublicationResult:
        resume_receipts.append(receipt)
        assert dispatcher.authenticates_action_cohort_publication_receipt(receipt)
        assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
        return original_resume(receipt)

    monkeypatch.setattr(windows, "_commit_exact_candidate_row", commit_windows)
    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", commit_ecar)
    monkeypatch.setattr(dispatcher, "resume_action_cohort_projection", resume_same_batch)
    prior_state_version = state.materialization_version
    try:
        logon_id = generator.generate_service_logon(
            request.system,
            request.time,
            request.service_account,
        )
        assert len(resume_receipts) == 1
        assert faulted
        assert state.materialization_version == prior_state_version + 1
        assert state.get_session(logon_id) is not None
        assert registry.census().live_sessions == 1
        assert generator.execution_effect_audit_snapshot() == _expected_service_audit_snapshot(
            request
        )
        dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        windows.close()
        ecar.close()

    reference_bytes = _exact_source_bytes(reference_root)
    assert {Path(path).name for path in reference_bytes} == {
        "windows_event_security.xml",
        "ecar.json",
    }
    assert all(reference_bytes.values())
    assert (
        hashlib.sha256(
            next(content for path, content in reference_bytes.items() if path.endswith(".xml"))
        ).hexdigest()
        == "9ae7ab331ed889f073997ed34325d7ed0a63f60c3182d193c8638ca53f71786f"
    )
    assert (
        hashlib.sha256(
            next(content for path, content in reference_bytes.items() if path.endswith(".json"))
        ).hexdigest()
        == "1493767f8b7271e3a65ea441091cbbad8087f3f7caab7e46d03f1098a69516ce"
    )
    assert _exact_source_bytes(fault_root) == reference_bytes
    exact_census = windows.exact_candidate_census()
    assert (
        exact_census.current_rows,
        exact_census.current_bytes,
        exact_census.current_participants,
    ) == (0, 0, 0)
    recovery_census = dispatcher.exact_projection_recovery_census()
    assert recovery_census.unresolved_recoveries == 0
    assert recovery_census.authority.active_batches == 0


def test_named_type5_engine_abort_drains_real_pending_multisink_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Engine abort drains a twice-failed real batch before closing its exact sinks."""

    output_root = tmp_path / "pending"
    generator, state, registry, dispatcher, windows, ecar = _real_exact_service_runtime(output_root)
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_commit = ExternalSortedLineWriter._commit_exact_row
    commit_attempts = 0

    def fail_twice_then_commit(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal commit_attempts
        commit_attempts += 1
        if commit_attempts <= 2:
            raise RuntimeError("injected retained eCAR recovery")
        original_commit(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_twice_then_commit)
    prior_state_version = state.materialization_version
    with pytest.raises(RuntimeError, match="retained eCAR recovery"):
        generator.generate_service_logon(_system(), _TIME, "svc-backup")

    assert commit_attempts == 2
    assert state.materialization_version == prior_state_version + 1
    assert registry.census().live_sessions == 1
    pending = dispatcher.exact_projection_recovery_census()
    assert pending.unresolved_recoveries == 1
    assert pending.authority.active_batches == 1
    pending_sid = generator.sid_registry["svc-backup"]
    assert pending_sid.startswith("S-1-5-21-")
    assert generator._sid_reservation_census()[:2] == (0, 0)
    pending_windows = windows.exact_candidate_census()
    assert (
        pending_windows.current_rows,
        pending_windows.current_participants,
        pending_windows.completed_participants,
    ) == (2, 1, 0)

    engine = object.__new__(GenerationEngine)
    engine.dispatcher = dispatcher
    engine.emitters = {
        "windows_event_security": windows,
        "ecar": ecar,
    }
    engine._finalization_complete = False
    engine._finalization_aborted = False
    engine._exact_projection_recovery_dispatcher = None
    engine._expected_close_emitters = None
    engine._closed_emitter_names = set()
    finalization_errors: list[BaseException] = []

    def finalize_aborted_generation() -> None:
        try:
            engine._finalize(generation_succeeded=False)
        except BaseException as error:
            finalization_errors.append(error)

    worker = Thread(target=finalize_aborted_generation)
    worker.start()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert not finalization_errors
    assert commit_attempts == 3
    assert engine._finalization_aborted
    assert engine._finalization_complete
    dispatcher.assert_exact_projection_recoveries_drained()
    terminal = dispatcher.exact_projection_recovery_census()
    assert terminal.unresolved_recoveries == 0
    assert terminal.authority.active_batches == 0
    terminal_windows = windows.exact_candidate_census()
    assert (
        terminal_windows.current_rows,
        terminal_windows.current_bytes,
        terminal_windows.current_participants,
    ) == (0, 0, 0)
    source_bytes = _exact_source_bytes(output_root)
    assert {Path(path).name for path in source_bytes} == {
        "windows_event_security.xml",
        "ecar.json",
    }
    windows_bytes = next(content for path, content in source_bytes.items() if path.endswith(".xml"))
    ecar_bytes = next(content for path, content in source_bytes.items() if path.endswith(".json"))
    assert windows_bytes.count(b"<EventID>4624</EventID>") == 1
    assert windows_bytes.count(b"<EventID>4672</EventID>") == 1
    assert len(ecar_bytes.splitlines()) == 1
    assert generator.sid_registry["svc-backup"] == pending_sid


def test_named_type5_exact_sink_callback_cannot_steal_the_reserved_sid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sink callback allocation skips the service SID reserved before exact admission."""

    generator, state, _registry, dispatcher, windows, ecar = _real_exact_service_runtime(tmp_path)
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_commit = windows._commit_exact_candidate_row
    callback_sids: list[str] = []

    def allocate_during_commit(
        key: tuple[str, int, int],
        digest: str,
        frozen: object,
    ) -> None:
        if not callback_sids:
            callback_sids.append(generator._get_sid("callback-principal"))
        original_commit(key, digest, frozen)

    monkeypatch.setattr(windows, "_commit_exact_candidate_row", allocate_during_commit)
    try:
        logon_id = generator.generate_service_logon(_system(), _TIME, "svc-backup")
        service_sid = generator.sid_registry["svc-backup"]
        assert state.get_session(logon_id) is not None
        assert len(callback_sids) == 1
        assert callback_sids[0] != service_sid
        assert int(callback_sids[0].rsplit("-", 1)[1]) > int(service_sid.rsplit("-", 1)[1])
        assert generator._sid_reservation_census()[:2] == (0, 0)
        dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        windows.close()
        ecar.close()

    windows_bytes = next(
        content for path, content in _exact_source_bytes(tmp_path).items() if path.endswith(".xml")
    )
    assert service_sid.encode("utf-8") in windows_bytes
    assert windows_bytes.count(b"<EventID>4624</EventID>") == 1
    assert windows_bytes.count(b"<EventID>4672</EventID>") == 1


def test_builtin_type5_immediately_resumes_attached_projection_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A built-in sink lost return resumes its carrier instead of rebuilding it."""

    generator, state, registry, dispatcher, _timing, _emitter = _strict_service_runtime()
    receipt = _FakePublicationReceipt()
    prepared_occurrences = []
    resumed = []
    recovery: dict[str, object] = {}

    def fail_after_publication(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        prepared_occurrences.append(occurrence)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        error = RuntimeError("built-in projection returned late")
        result = _state_neutral_result(
            receipt,
            occurrence.occurrence_id,
            status="failed",
            error=error,
        )
        recovery["result"] = result
        error.state_neutral_projection_receipt = receipt
        error.state_neutral_projection_result = result
        raise error

    def resume(attached: object) -> object:
        resumed.append(attached)
        result = recovery["result"]
        object.__setattr__(result.projection, "_status", "succeeded")
        object.__setattr__(result.projection, "_error", None)
        return result

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        fail_after_publication,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_state_neutral_exact_projection",
        resume,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        lambda candidate: candidate is receipt,
        raising=False,
    )

    assert generator.generate_service_logon(_system(), _TIME, "SYSTEM") == "0x3e7"
    assert len(prepared_occurrences) == 1
    assert resumed == [receipt]
    assert state.get_session("0x3e7") is None
    assert registry.census().session_entries == 0


@pytest.mark.parametrize("authenticator_raises", [False, True])
def test_builtin_type5_rejects_forged_projection_receipt_attribute(
    monkeypatch: pytest.MonkeyPatch,
    authenticator_raises: bool,
) -> None:
    """A receipt-named arbitrary attribute cannot enter state-neutral recovery."""

    generator, state, _registry, dispatcher, _timing, _emitter = _strict_service_runtime()
    forged_receipt = object()
    failure = RuntimeError("untrusted built-in sink failure")
    failure.state_neutral_projection_receipt = forged_receipt
    resume = Mock()
    authenticator_calls = 0

    def fail_untrusted(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        failure.state_neutral_projection_result = _state_neutral_result(
            forged_receipt,
            occurrence.occurrence_id,
            status="failed",
            error=failure,
        )
        raise failure

    def authenticate_untrusted(_candidate: object) -> bool:
        nonlocal authenticator_calls
        authenticator_calls += 1
        if authenticator_raises:
            raise KeyboardInterrupt
        return False

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        fail_untrusted,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        authenticate_untrusted,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_state_neutral_exact_projection",
        resume,
        raising=False,
    )

    with pytest.raises(RuntimeError) as raised:
        generator.generate_service_logon(_system(), _TIME, "SYSTEM")

    assert raised.value is failure
    assert authenticator_calls == 1
    resume.assert_not_called()
    assert state.get_session("0x3e7") is None


def test_builtin_type5_rejects_stale_authentic_attached_receipt_before_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prior authentic receipt cannot enter recovery for the current built-in occurrence."""

    generator, state, registry, dispatcher, timing, _emitter = _strict_service_runtime()
    receipt = _FakePublicationReceipt()
    failure = RuntimeError("stale built-in projection receipt")
    resume = Mock()
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def fail_with_stale_receipt(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        result = _state_neutral_result(
            receipt,
            occurrence.occurrence_id,
            status="failed",
            error=failure,
            receipt_occurrence_id="prior-authentication-occurrence",
        )
        failure.state_neutral_projection_receipt = receipt
        failure.state_neutral_projection_result = result
        raise failure

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        fail_with_stale_receipt,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        lambda candidate: candidate is receipt,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_state_neutral_exact_projection",
        resume,
        raising=False,
    )

    with pytest.raises(RuntimeError) as raised:
        generator.generate_service_logon(_system(), _TIME, "SYSTEM")

    assert raised.value is failure
    resume.assert_not_called()
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census


@pytest.mark.parametrize(
    "result_mode",
    [
        "wrong_type",
        "wrong_occurrence",
        "failed",
        "tampered_projection",
        "foreign_receipt",
        "stale_receipt",
    ],
)
def test_builtin_type5_rejects_invalid_direct_publication_results(
    monkeypatch: pytest.MonkeyPatch,
    result_mode: str,
) -> None:
    """Direct state-neutral success must return an authenticated terminal proof."""

    generator, state, registry, dispatcher, timing, _emitter = _strict_service_runtime()
    receipt = _FakePublicationReceipt()
    foreign_receipt = object()
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def publish_invalid(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        if result_mode == "wrong_type":
            return object()
        result = _state_neutral_result(
            foreign_receipt if result_mode == "foreign_receipt" else receipt,
            "wrong-occurrence" if result_mode == "wrong_occurrence" else occurrence.occurrence_id,
            status="failed" if result_mode == "failed" else "succeeded",
            error=RuntimeError("injected terminal error") if result_mode == "failed" else None,
            receipt_occurrence_id=(
                "prior-authentication-occurrence" if result_mode == "stale_receipt" else None
            ),
        )
        if result_mode == "tampered_projection":
            object.__setattr__(result, "projection", object())
        return result

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        publish_invalid,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        lambda candidate: candidate is receipt,
        raising=False,
    )

    with pytest.raises(StateError):
        generator.generate_service_logon(_system(), _TIME, "SYSTEM")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.get_session("0x3e7") is None


def test_builtin_type5_rejects_copied_resumed_publication_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume must return the exact exception-attached canonical result object."""

    generator, state, registry, dispatcher, timing, _emitter = _strict_service_runtime()
    receipt = _FakePublicationReceipt()
    recovery: dict[str, object] = {}
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def fail_with_result(carrier: object) -> object:
        occurrence = dispatcher.action_cohort_projection_occurrence(carrier)
        assert dispatcher.cancel_prepared_action_cohort_projection(carrier)
        failure = RuntimeError("built-in projection returned late")
        result = _state_neutral_result(
            receipt,
            occurrence.occurrence_id,
            status="failed",
            error=failure,
        )
        recovery["result"] = result
        failure.state_neutral_projection_receipt = receipt
        failure.state_neutral_projection_result = result
        raise failure

    def resume_with_copy(_receipt: object) -> object:
        result = recovery["result"]
        object.__setattr__(result.projection, "_status", "succeeded")
        object.__setattr__(result.projection, "_error", None)
        return copy.copy(result)

    monkeypatch.setattr(
        dispatcher,
        "publish_state_neutral_exact_projection",
        fail_with_result,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_state_neutral_exact_projection",
        resume_with_copy,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_state_neutral_projection_publication_receipt",
        lambda candidate: candidate is receipt,
        raising=False,
    )

    with pytest.raises(StateError, match="different publication result"):
        generator.generate_service_logon(_system(), _TIME, "SYSTEM")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census


def test_named_type5_projection_prepare_failure_releases_all_preparations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Projection construction failure leaves no State, timing, or carrier authority."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def fail_projection(_occurrence: object) -> object:
        raise EventContractError("injected Type-5 projection preparation failure")

    monkeypatch.setattr(dispatcher, "_prepare_projection", fail_projection)

    with pytest.raises(EventContractError, match="projection preparation failure"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0
    _assert_timing_lane_reusable(timing)


@pytest.mark.parametrize("account", ["SYSTEM", "svc_backup"])
def test_type5_projection_prepare_lost_return_prunes_the_orphaned_carrier(
    monkeypatch: pytest.MonkeyPatch,
    account: str,
) -> None:
    """A prepare call-original-then-raise cannot retain a weak-ownerless carrier."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected projection prepare lost return")
    original_prepare = dispatcher.prepare_action_cohort_projection

    def prepare_then_fail(*args: object, **kwargs: object) -> object:
        original_prepare(*args, **kwargs)
        raise failure

    monkeypatch.setattr(dispatcher, "prepare_action_cohort_projection", prepare_then_fail)

    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, account)

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0
    _assert_timing_lane_reusable(timing)


@pytest.mark.parametrize("account", ["SYSTEM", "svc_backup"])
def test_type5_occurrence_view_failure_cancels_the_unbound_projection_carrier(
    monkeypatch: pytest.MonkeyPatch,
    account: str,
) -> None:
    """A post-prepare view failure releases built-in and named carrier authority."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected Type-5 occurrence view failure")

    def fail_occurrence_view(_carrier: object) -> object:
        raise failure

    monkeypatch.setattr(
        dispatcher,
        "action_cohort_projection_occurrence",
        fail_occurrence_view,
    )

    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, account)

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


@pytest.mark.parametrize("account", ["SYSTEM", "svc_backup"])
@pytest.mark.parametrize("cleanup_mode", ["fail_before", "lost_return"])
def test_type5_projection_cleanup_reconciles_one_failed_cancel_return(
    monkeypatch: pytest.MonkeyPatch,
    account: str,
    cleanup_mode: str,
) -> None:
    """Carrier cleanup retries one fail-before or lost-return cancellation."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    primary = KeyboardInterrupt("injected Type-5 occurrence view failure")
    cleanup_failure = RuntimeError("injected Type-5 carrier cleanup failure")
    original_cancel = dispatcher.cancel_prepared_action_cohort_projection
    cleanup_attempts = 0

    def fail_occurrence_view(_carrier: object) -> object:
        raise primary

    def flaky_cancel(carrier: object) -> bool:
        nonlocal cleanup_attempts
        cleanup_attempts += 1
        if cleanup_attempts == 1:
            if cleanup_mode == "lost_return":
                original_cancel(carrier)
            raise cleanup_failure
        return original_cancel(carrier)

    monkeypatch.setattr(
        dispatcher,
        "action_cohort_projection_occurrence",
        fail_occurrence_view,
    )
    monkeypatch.setattr(
        dispatcher,
        "cancel_prepared_action_cohort_projection",
        flaky_cancel,
    )

    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, account)

    assert raised.value is primary
    assert cleanup_attempts == 2
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


@pytest.mark.parametrize("account", ["SYSTEM", "svc_backup"])
def test_type5_timing_seal_lost_return_cancels_the_unbound_projection_carrier(
    monkeypatch: pytest.MonkeyPatch,
    account: str,
) -> None:
    """A context-exit failure after timing seal cannot strand its projection carrier."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected Type-5 timing seal lost return")
    original_seal = SourceTimingPreparation.seal

    def seal_then_fail(preparation: SourceTimingPreparation) -> None:
        original_seal(preparation)
        raise failure

    monkeypatch.setattr(SourceTimingPreparation, "seal", seal_then_fail)

    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, account)

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


def test_named_type5_audit_construction_failure_precedes_all_preparations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero-effect audit failure occurs before timing/carrier ownership exists."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def fail_audit_reconciliation(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("injected Type-5 audit construction failure")

    monkeypatch.setattr(ExecutionEffectPlan, "reconcile", fail_audit_reconciliation)

    with pytest.raises(RuntimeError, match="audit construction failure"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


def test_named_type5_bind_failure_cancels_the_authentic_projection_carrier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure before binding transfers ownership cancels the exact carrier."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def fail_bind(_carrier: object, **_kwargs: object) -> object:
        raise EventContractError("injected Type-5 projection bind failure")

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", fail_bind)

    with pytest.raises(EventContractError, match="projection bind failure"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0
    _assert_timing_lane_reusable(timing)


def test_named_type5_bind_lost_return_releases_the_consumed_timing_lane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bind call-original-then-raise cannot strand its consumed carrier's timing lane."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected projection bind lost return")
    original_bind = dispatcher.bind_action_cohort_projection

    def bind_then_fail(*args: object, **kwargs: object) -> object:
        original_bind(*args, **kwargs)
        raise failure

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_then_fail)

    with pytest.raises(KeyboardInterrupt) as raised:
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0
    _assert_timing_lane_reusable(timing)


def test_named_type5_exact_preflight_rejection_is_canonically_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every exact target rejects before the named State/lifecycle session commits."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    exact_flags: list[bool] = []

    def reject_exact_preflight(*args: object, **kwargs: object) -> object:
        exact_flags.append(kwargs.pop("exact_projection") is True)
        assert len(args[3]) == 1
        raise EventContractError("injected exact Type-5 target rejection")

    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", reject_exact_preflight)
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    with pytest.raises(EventContractError, match="injected exact Type-5 target rejection"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert exact_flags == [True]
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0
    _assert_timing_lane_reusable(timing)


def test_named_type5_exact_batch_prepare_lost_return_prunes_and_releases_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact batch call-original-then-raise leaves no batch, sink, SID, or timing claim."""

    generator, state, registry, dispatcher, windows, ecar = _real_exact_service_runtime(tmp_path)
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    timing = dispatcher.source_timing_planner
    census = _precommit_census(generator, state, registry, dispatcher, timing)
    failure = KeyboardInterrupt("injected exact batch prepare lost return")
    original_prepare = dispatcher.prepare_action_cohort_batch

    def prepare_then_fail(*args: object, **kwargs: object) -> object:
        original_prepare(*args, **kwargs)
        raise failure

    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_then_fail)
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            generator.generate_service_logon(_system(), _TIME, "svc_backup")

        assert raised.value is failure
        assert _precommit_census(generator, state, registry, dispatcher, timing) == census
        assert state.list_active_sessions() == []
        exact_census = windows.exact_candidate_census()
        assert exact_census.current_rows == 0
        assert exact_census.current_participants == 0
        _assert_timing_lane_reusable(timing)
    finally:
        windows.close()
        ecar.close()


def test_named_type5_claim_failure_keeps_sid_and_canonical_state_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-admission claim failure cannot publish the previewed SID cache state."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    prepared_dispatches = []
    failure = EventContractError("injected Type-5 exact claim failure")
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        prepared_dispatches.append(args[2][0])
        return object()

    def fail_claim(_batch: object) -> object:
        prepared_dispatches[0]._source_timing_preparation.cancel()
        raise failure

    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", fail_claim)

    with pytest.raises(EventContractError) as raised:
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert raised.value is failure
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


@pytest.mark.parametrize(
    "result_mode",
    [
        "wrong_type",
        "wrong_occurrence",
        "failed",
        "tampered_projection",
        "foreign_receipt",
        "stale_receipt",
        "wrong_root",
        "wrong_state",
    ],
)
def test_named_type5_rejects_invalid_direct_publication_results_without_sid_mutation(
    monkeypatch: pytest.MonkeyPatch,
    result_mode: str,
) -> None:
    """Named direct success validates its exact terminal proof before SID publication."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_bind = dispatcher.bind_action_cohort_projection
    prepared_dispatches = []
    occurrences = []
    receipt = _FakePublicationReceipt()
    foreign_receipt = object()
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def bind_projection(carrier: object, **kwargs: object) -> object:
        occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        _bind_fake_action_receipt(receipt, args[0], args[1])
        prepared_dispatches.append(args[2][0])
        return object()

    def publish_invalid(_batch: object) -> object:
        prepared_dispatches[0]._source_timing_preparation.cancel()
        occurrence = occurrences[0]
        if result_mode == "wrong_type":
            return object()
        result = _action_cohort_result(
            foreign_receipt if result_mode == "foreign_receipt" else receipt,
            "wrong-occurrence" if result_mode == "wrong_occurrence" else occurrence.occurrence_id,
            status="failed" if result_mode == "failed" else "succeeded",
            error=RuntimeError("injected terminal error") if result_mode == "failed" else None,
        )
        if result_mode == "tampered_projection":
            object.__setattr__(result, "projections", (object(),))
        elif result_mode == "stale_receipt":
            receipt.occurrence_ids = ("prior-authentication-occurrence",)
        elif result_mode == "wrong_root":
            receipt.root_action_id = "foreign-action-root"
        elif result_mode == "wrong_state":
            receipt.state_semantic_id = "foreign-state-plan"
        return result

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", publish_invalid)
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )

    with pytest.raises(StateError):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


def test_named_type5_rejects_copied_resumed_result_without_sid_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Named recovery accepts only the attached canonical result identity."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_bind = dispatcher.bind_action_cohort_projection
    prepared_dispatches = []
    occurrences = []
    receipt = _FakePublicationReceipt()
    recovery: dict[str, object] = {}
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def bind_projection(carrier: object, **kwargs: object) -> object:
        occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        _bind_fake_action_receipt(receipt, args[0], args[1])
        prepared_dispatches.append(args[2][0])
        return object()

    def fail_with_result(_batch: object) -> object:
        prepared_dispatches[0]._source_timing_preparation.cancel()
        failure = RuntimeError("named projection returned late")
        result = _action_cohort_result(
            receipt,
            occurrences[0].occurrence_id,
            status="failed",
            error=failure,
        )
        recovery["result"] = result
        failure.action_cohort_receipt = receipt
        failure.action_cohort_result = result
        raise failure

    def resume_with_copy(_receipt: object) -> object:
        result = recovery["result"]
        object.__setattr__(result.projections[0], "_status", "succeeded")
        object.__setattr__(result.projections[0], "_error", None)
        return copy.copy(result)

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", fail_with_result)
    monkeypatch.setattr(
        dispatcher,
        "resume_action_cohort_projection",
        resume_with_copy,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )

    with pytest.raises(StateError, match="different publication result"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


def test_named_type5_accepts_valid_direct_result_then_reconciles_sid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Named direct success validates proof and only then publishes its SID cache row."""

    generator, state, _registry, dispatcher, _timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_bind = dispatcher.bind_action_cohort_projection
    prepared_dispatches = []
    occurrences = []
    receipt = _FakePublicationReceipt()

    def bind_projection(carrier: object, **kwargs: object) -> object:
        occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        _bind_fake_action_receipt(receipt, args[0], args[1])
        prepared_dispatches.append(args[2][0])
        return object()

    def publish_valid(_batch: object) -> object:
        occurrence = occurrences[0]
        identity = occurrence.identity_plan.session
        assert identity is not None
        assert (
            state.create_session(
                username=occurrence.auth.username,
                system=identity.hostname,
                logon_type=occurrence.auth.logon_type,
                source_ip=occurrence.auth.source_ip,
                session_kind=identity.session_kind,
                start_time=occurrence.timestamp,
                logon_guid_required=False,
                session_id=identity.session_id,
                lifecycle_group_id=identity.lifecycle_group_id,
            )
            == identity.logon_id
        )
        prepared_dispatches[0]._source_timing_preparation.cancel()
        emitter.emit(occurrence)
        return _action_cohort_result(receipt, occurrence.occurrence_id)

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", publish_valid)
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )

    logon_id = generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert state.get_session_identity(logon_id) == occurrences[0].identity_plan.session
    assert generator.sid_registry["svc_backup"] == occurrences[0].auth.user_sid
    emitter.emit.assert_called_once_with(occurrences[0])


def test_named_type5_rejects_wrong_state_identity_before_sid_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A terminal outcome with wrong State identity cannot mutate SID/RID ownership."""

    generator, state, _registry, dispatcher, _timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_bind = dispatcher.bind_action_cohort_projection
    original_get_session_identity = state.get_session_identity
    prepared_dispatches = []
    occurrences = []
    receipt = _FakePublicationReceipt()
    wrong_state_identity = False
    prior_sid_registry = dict(generator.sid_registry)
    prior_sid_owner = (
        hasattr(generator, "_domain_sid_prefix"),
        getattr(generator, "_domain_sid_prefix", None),
        hasattr(generator, "_max_rid"),
        getattr(generator, "_max_rid", None),
    )

    def bind_projection(carrier: object, **kwargs: object) -> object:
        occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        _bind_fake_action_receipt(receipt, args[0], args[1])
        prepared_dispatches.append(args[2][0])
        return object()

    def publish_valid(_batch: object) -> object:
        nonlocal wrong_state_identity
        occurrence = occurrences[0]
        identity = occurrence.identity_plan.session
        assert identity is not None
        assert (
            state.create_session(
                username=occurrence.auth.username,
                system=identity.hostname,
                logon_type=occurrence.auth.logon_type,
                source_ip=occurrence.auth.source_ip,
                session_kind=identity.session_kind,
                start_time=occurrence.timestamp,
                logon_guid_required=False,
                session_id=identity.session_id,
                lifecycle_group_id=identity.lifecycle_group_id,
            )
            == identity.logon_id
        )
        prepared_dispatches[0]._source_timing_preparation.cancel()
        emitter.emit(occurrence)
        wrong_state_identity = True
        return _action_cohort_result(receipt, occurrence.occurrence_id)

    def get_session_identity(logon_id: str) -> object:
        if wrong_state_identity:
            return object()
        return original_get_session_identity(logon_id)

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", publish_valid)
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )
    monkeypatch.setattr(state, "get_session_identity", get_session_identity)

    with pytest.raises(StateError, match="invalid session identity"):
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert generator.sid_registry == prior_sid_registry
    assert (
        hasattr(generator, "_domain_sid_prefix"),
        getattr(generator, "_domain_sid_prefix", None),
        hasattr(generator, "_max_rid"),
        getattr(generator, "_max_rid", None),
    ) == prior_sid_owner
    emitter.emit.assert_called_once_with(occurrences[0])


def test_named_type5_rejects_foreign_action_cohort_receipt_attribute(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign receipt-named object cannot resume a named Type-5 cohort."""

    generator, state, _registry, dispatcher, _timing, _emitter = _strict_service_runtime()
    foreign_receipt = object()
    failure = RuntimeError("untrusted named sink failure")
    failure.action_cohort_receipt = foreign_receipt
    prepared_dispatches = []
    resume = Mock()

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        prepared_dispatches.append(args[2][0])
        return object()

    def fail_untrusted(_batch: object) -> object:
        prepared_dispatches[0]._source_timing_preparation.cancel()
        raise failure

    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", fail_untrusted)
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is not foreign_receipt,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_action_cohort_projection",
        resume,
        raising=False,
    )

    with pytest.raises(RuntimeError) as raised:
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert raised.value is failure
    resume.assert_not_called()
    assert state.list_active_sessions() == []


def test_named_type5_rejects_stale_authentic_attached_receipt_before_resume_or_sid_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prior receipt cannot resume or install the current named account's reserved SID."""

    generator, state, registry, dispatcher, timing, emitter = _strict_service_runtime()
    generator.sid_registry["seed-account"] = "S-1-5-21-100-200-300-1100"
    original_bind = dispatcher.bind_action_cohort_projection
    receipt = _FakePublicationReceipt()
    prepared_dispatches = []
    occurrences = []
    failure = RuntimeError("stale named projection receipt")
    resume = Mock()
    census = _precommit_census(generator, state, registry, dispatcher, timing)

    def bind_projection(carrier: object, **kwargs: object) -> object:
        occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        assert kwargs.pop("exact_projection") is True
        assert kwargs.pop("owned_effect_plans") == ()
        _bind_fake_action_receipt(receipt, args[0], args[1])
        prepared_dispatches.append(args[2][0])
        return object()

    def fail_with_stale_receipt(_batch: object) -> object:
        prepared_dispatches[0]._source_timing_preparation.cancel()
        result = _action_cohort_result(
            receipt,
            occurrences[0].occurrence_id,
            status="failed",
            error=failure,
        )
        receipt.occurrence_ids = ("prior-authentication-occurrence",)
        failure.action_cohort_receipt = receipt
        failure.action_cohort_result = result
        raise failure

    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(
        dispatcher,
        "publish_prepared_action_cohort_batch",
        fail_with_stale_receipt,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )
    monkeypatch.setattr(
        dispatcher,
        "resume_action_cohort_projection",
        resume,
        raising=False,
    )

    with pytest.raises(RuntimeError) as raised:
        generator.generate_service_logon(_system(), _TIME, "svc_backup")

    assert raised.value is failure
    resume.assert_not_called()
    assert _precommit_census(generator, state, registry, dispatcher, timing) == census
    assert state.list_active_sessions() == []
    assert emitter.emit.call_count == 0


def test_named_type5_sink_lost_return_resumes_one_session_and_luid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed named session resumes projection without a second State plan."""

    generator, state, registry, dispatcher, _timing, emitter = _strict_service_runtime()
    original_begin = state.begin_action_cohort_materialization
    original_bind = dispatcher.bind_action_cohort_projection
    begin_count = 0
    exact_flags: list[bool] = []
    emitted = []
    prepared_occurrences = []
    receipt = _FakePublicationReceipt()
    recovery: dict[str, object] = {}

    def begin_action_cohort() -> object:
        nonlocal begin_count
        begin_count += 1
        return original_begin()

    def bind_projection(carrier: object, **kwargs: object) -> object:
        prepared_occurrences.append(dispatcher.action_cohort_projection_occurrence(carrier))
        return original_bind(carrier, **kwargs)

    def prepare_exact(*args: object, **kwargs: object) -> object:
        exact_flags.append(kwargs.pop("exact_projection") is True)
        assert kwargs.pop("owned_effect_plans") == ()
        assert (
            args[0]
            == ServiceLogonRequest(
                system=_system(),
                time=_TIME,
                service_account="svc_backup",
            ).stable_id
        )
        state_plan = args[1]
        _bind_fake_action_receipt(receipt, args[0], state_plan)
        assert len(state_plan.sessions) == 1
        assert state_plan.sessions[0].identity == prepared_occurrences[0].identity_plan.session
        return object()

    def append_then_raise(occurrence: object) -> None:
        emitted.append(occurrence)
        if len(emitted) == 1:
            raise RuntimeError("named projection returned late")

    def publish(_batch: object) -> object:
        occurrence = prepared_occurrences[0]
        identity = occurrence.identity_plan.session
        assert identity is not None
        created_logon_id = state.create_session(
            username=occurrence.auth.username,
            system=identity.hostname,
            logon_type=occurrence.auth.logon_type,
            source_ip=occurrence.auth.source_ip,
            session_kind=identity.session_kind,
            start_time=occurrence.timestamp,
            logon_guid_required=False,
            session_id=identity.session_id,
            lifecycle_group_id=identity.lifecycle_group_id,
        )
        assert created_logon_id == identity.logon_id
        result = _action_cohort_result(
            receipt,
            occurrence.occurrence_id,
            status="started",
        )
        recovery["result"] = result
        try:
            emitter.emit(occurrence)
        except BaseException as error:
            object.__setattr__(result.projections[0], "_status", "failed")
            object.__setattr__(result.projections[0], "_error", error)
            error.action_cohort_receipt = receipt
            error.action_cohort_result = result
            raise
        raise AssertionError("The injected first exact sink call did not fail")

    def resume(attached: object) -> object:
        assert attached is receipt
        emitter.emit(prepared_occurrences[0])
        result = recovery["result"]
        object.__setattr__(result.projections[0], "_status", "succeeded")
        object.__setattr__(result.projections[0], "_error", None)
        return result

    monkeypatch.setattr(state, "begin_action_cohort_materialization", begin_action_cohort)
    monkeypatch.setattr(dispatcher, "bind_action_cohort_projection", bind_projection)
    monkeypatch.setattr(dispatcher, "prepare_action_cohort_batch", prepare_exact)
    monkeypatch.setattr(dispatcher, "publish_prepared_action_cohort_batch", publish)
    monkeypatch.setattr(
        dispatcher,
        "resume_action_cohort_projection",
        resume,
        raising=False,
    )
    monkeypatch.setattr(
        dispatcher,
        "authenticates_action_cohort_publication_receipt",
        lambda candidate: candidate is receipt,
    )
    emitter.emit.side_effect = append_then_raise
    initial_version = state.materialization_version
    previewed_logon_id = state.preview_logon_id("APP-01", _TIME)

    logon_id = generator.generate_service_logon(_system(), _TIME, "svc_backup")

    sessions = state.get_sessions_for_user("svc_backup")
    assert exact_flags == [True]
    assert begin_count == 1
    assert logon_id == previewed_logon_id
    assert len(sessions) == 1
    assert sessions[0].logon_id == logon_id
    assert state.materialization_version == initial_version + 1
    assert len(emitted) == 2
    assert emitted[0].occurrence_id == emitted[1].occurrence_id

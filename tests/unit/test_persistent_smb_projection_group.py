# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for inert bounded persistent-SMB detached projection groups."""

from __future__ import annotations

import copy
import gc
import hashlib
from dataclasses import replace
from threading import Event, Thread
from weakref import ReferenceType, ref

import pytest

from evidenceforge.events import dispatcher as dispatcher_module
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation import persistent_smb_projection as projection_module
from evidenceforge.generation.persistent_smb_projection import (
    PersistentSmbProjectionGroupAuthority,
    PersistentSmbProjectionMemberToken,
    PersistentSmbProjectionPhase,
    encode_persistent_smb_projection_capsule,
)
from evidenceforge.generation.source_timing import (
    SourceTimingDetachedPreparationBinding,
    SourceTimingPlanner,
    SourceTimingPreparation,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class _CallbackTrap:
    def __init__(self) -> None:
        self.calls = 0

    def _called(self) -> None:
        self.calls += 1
        raise AssertionError("untrusted callback ran")

    def __eq__(self, _other: object) -> bool:
        self._called()

    def __hash__(self) -> int:
        self._called()

    def __repr__(self) -> str:
        self._called()

    def __str__(self) -> str:
        self._called()


class _HostileString(str):
    calls = 0
    __hash__ = str.__hash__

    @classmethod
    def _called(cls) -> None:
        cls.calls += 1
        raise AssertionError("hostile string callback ran")

    def __eq__(self, _other: object) -> bool:
        self._called()

    def __lt__(self, _other: object) -> bool:
        self._called()

    def encode(self, *_args: object, **_kwargs: object) -> bytes:
        self._called()


class _TargetDestructorProbe:
    def __init__(self, dispatcher: EventDispatcher, results: list[bool]) -> None:
        self.dispatcher = dispatcher
        self.results = results

    def __del__(self) -> None:
        acquired = self.dispatcher._persistent_smb_topology_lock.acquire(blocking=False)
        self.results.append(acquired)
        if acquired:
            self.dispatcher._persistent_smb_topology_lock.release()


class _AuthoritySlotDestructorProbe:
    def __init__(
        self,
        authority: PersistentSmbProjectionGroupAuthority,
        results: list[bool],
    ) -> None:
        self.authority = authority
        self.results = results

    def __del__(self) -> None:
        acquired = self.authority._lock.acquire(blocking=False)
        self.results.append(acquired)
        if acquired:
            self.authority._lock.release()


class _MemberSlotDestructorProbe(str):
    def __new__(
        cls,
        value: str,
        authority: PersistentSmbProjectionGroupAuthority,
        results: list[bool],
    ) -> _MemberSlotDestructorProbe:
        instance = str.__new__(cls, value)
        instance.authority = authority
        instance.results = results
        return instance

    def __init__(
        self,
        value: str,
        authority: PersistentSmbProjectionGroupAuthority,
        results: list[bool],
    ) -> None:
        del value, authority, results

    def __del__(self) -> None:
        acquired = self.authority._lock.acquire(blocking=False)
        self.results.append(acquired)
        if acquired:
            self.authority._lock.release()


class _WeakTarget:
    pass


class _EstimateBytesTrap:
    def __init__(self) -> None:
        self.calls = 0

    def __bool__(self) -> bool:
        self.calls += 1
        raise AssertionError("estimate_bytes callback ran")


def _group_lock_probe_target(
    dispatcher: EventDispatcher,
    metadata_results: list[bool],
    destructor_results: list[bool],
) -> object:
    class _ProbeTargetMeta(type):
        @property
        def __module__(cls) -> str:
            acquired = dispatcher._persistent_smb_group_lock.acquire(blocking=False)
            metadata_results.append(acquired)
            if acquired:
                dispatcher._persistent_smb_group_lock.release()
            dispatcher.emitters.clear()
            return "tests.unit"

    class _ProbeTarget(metaclass=_ProbeTargetMeta):
        def __del__(self) -> None:
            acquired = dispatcher._persistent_smb_group_lock.acquire(blocking=False)
            destructor_results.append(acquired)
            if acquired:
                dispatcher._persistent_smb_group_lock.release()

    return _ProbeTarget()


def _install_member_snapshot_destructor_race(
    monkeypatch: pytest.MonkeyPatch,
    *,
    authority: PersistentSmbProjectionGroupAuthority,
    token: PersistentSmbProjectionMemberToken,
    snapshot_number: int,
) -> tuple[Thread, list[bool], list[BaseException]]:
    original_operation = token.operation_id
    original_snapshot = authority._snapshot_member_token
    exact_type = type
    snapshot_loaded = Event()
    snapshot_may_finish = Event()
    destructor_results: list[bool] = []
    thread_failures: list[BaseException] = []
    snapshot_calls = 0

    def gated_type(value: object) -> type[object]:
        value_type = exact_type(value)
        if value_type is _MemberSlotDestructorProbe:
            snapshot_loaded.set()
            if not snapshot_may_finish.wait(timeout=2):
                raise AssertionError("member snapshot race did not restore its public slot")
        return value_type

    def snapshot(value: object) -> object:
        nonlocal snapshot_calls
        snapshot_calls += 1
        if snapshot_calls == snapshot_number:
            object.__setattr__(
                token,
                "operation_id",
                _MemberSlotDestructorProbe(
                    original_operation,
                    authority,
                    destructor_results,
                ),
            )
        return original_snapshot(value)

    def restore_public_slot() -> None:
        try:
            if not snapshot_loaded.wait(timeout=2):
                raise AssertionError("member snapshot race was never reached")
            object.__setattr__(token, "operation_id", original_operation)
        except BaseException as error:
            thread_failures.append(error)
        finally:
            snapshot_may_finish.set()

    monkeypatch.setattr(projection_module, "type", gated_type, raising=False)
    monkeypatch.setattr(authority, "_snapshot_member_token", snapshot)
    thread = Thread(target=restore_public_slot)
    thread.start()
    return thread, destructor_results, thread_failures


def _sealed_timing(planner: SourceTimingPlanner) -> SourceTimingPreparation:
    with planner.prepared_planning() as timing:
        pass
    return timing


def _prepared_member(
    *,
    authority: PersistentSmbProjectionGroupAuthority | None = None,
    planner: SourceTimingPlanner | None = None,
    operation_id: str = "smb-operation-1",
    member_budget: int = 4,
    byte_budget: int = 32_768,
) -> tuple[
    PersistentSmbProjectionGroupAuthority,
    SourceTimingPlanner,
    SourceTimingPreparation,
    object,
    PersistentSmbProjectionMemberToken,
]:
    retained_authority = authority or PersistentSmbProjectionGroupAuthority()
    retained_planner = planner or SourceTimingPlanner()
    group = retained_authority.reserve_group(
        projection_configuration_digest=_digest("dispatcher-route-generation-1"),
        member_budget=member_budget,
        byte_budget=byte_budget,
    )
    timing = _sealed_timing(retained_planner)
    token = retained_authority.prepare_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id=operation_id,
        operation_binding_digest=_digest(f"owner:{operation_id}"),
        projection_capsule=encode_persistent_smb_projection_capsule(
            (b"canonical-smb-operation-v1", operation_id.encode("ascii"))
        ),
        timing_planner=retained_planner,
        timing_preparation=timing,
    )
    return retained_authority, retained_planner, timing, group, token


def test_public_api_has_no_self_activation_committed_recovery_or_ack_path() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    public_names = {
        name
        for name in dir(dispatcher)
        if "persistent_smb_projection" in name and not name.startswith("_")
    }

    assert public_names == {
        "cancel_empty_persistent_smb_projection_group",
        "cancel_persistent_smb_projection_member",
        "persistent_smb_projection_group_census",
        "prepare_persistent_smb_projection_member",
        "recover_inactive_persistent_smb_projection_member",
        "reserve_persistent_smb_projection_group",
    }
    forbidden_fragments = ("activat", "certif", "receipt", "acknowledge", "release")
    assert not any(
        fragment in name.casefold()
        for name in dir(PersistentSmbProjectionGroupAuthority)
        for fragment in forbidden_fragments
    )
    assert not any(
        fragment in name.casefold()
        for name in dir(projection_module)
        if not name.startswith("_")
        for fragment in ("activation", "certification", "receipt")
    )


def test_capsule_encoder_accepts_only_bounded_exact_bytes_without_callbacks() -> None:
    capsule = encode_persistent_smb_projection_capsule((b"one", b"two"))

    assert capsule.startswith(len(b"persistent-smb-projection-capsule-v1").to_bytes(8, "big"))
    with pytest.raises(EventContractError, match="exact tuple"):
        encode_persistent_smb_projection_capsule([b"one"])  # type: ignore[arg-type]
    with pytest.raises(EventContractError, match="exact bytes"):
        encode_persistent_smb_projection_capsule((bytearray(b"one"),))  # type: ignore[arg-type]
    trap = _CallbackTrap()
    with pytest.raises(EventContractError, match="exact bytes"):
        encode_persistent_smb_projection_capsule((trap,))  # type: ignore[arg-type]
    assert trap.calls == 0


def test_group_capacity_scalars_are_bounded_before_framing() -> None:
    huge = 1 << 100_000

    with pytest.raises(EventContractError, match="signed 63-bit"):
        PersistentSmbProjectionGroupAuthority(group_capacity=huge)
    authority = PersistentSmbProjectionGroupAuthority()
    with pytest.raises(EventContractError, match="signed 63-bit"):
        authority.reserve_group(
            projection_configuration_digest=_digest("huge-member-budget"),
            member_budget=huge,
            byte_budget=4_096,
        )
    with pytest.raises(ValueError, match="signed 63-bit"):
        EventDispatcher(StateManager(), {}, persistent_smb_byte_capacity=huge)


def test_group_reserves_declared_member_future_receipt_and_byte_budgets() -> None:
    authority = PersistentSmbProjectionGroupAuthority(
        group_capacity=3,
        member_capacity=3,
        receipt_capacity=3,
        byte_capacity=64_000,
    )
    first = authority.reserve_group(
        projection_configuration_digest=_digest("route-a"),
        member_budget=2,
        byte_budget=4_000,
    )
    before = authority.census()
    assert before.reserved_member_capacity == 2
    assert before.reserved_receipt_capacity == 2
    assert before.reserved_byte_capacity == 4_000
    with pytest.raises(EventContractError, match="member capacity"):
        authority.reserve_group(
            projection_configuration_digest=_digest("route-b"),
            member_budget=2,
            byte_budget=4_000,
        )
    assert authority.census() == before

    receipt_authority = PersistentSmbProjectionGroupAuthority(
        member_capacity=4,
        receipt_capacity=3,
    )
    with pytest.raises(EventContractError, match="receipt budget"):
        receipt_authority.reserve_group(
            projection_configuration_digest=_digest("route-receipts"),
            member_budget=4,
            byte_budget=4_000,
        )

    byte_authority = PersistentSmbProjectionGroupAuthority(
        group_capacity=2,
        member_capacity=2,
        receipt_capacity=2,
        byte_capacity=9_000,
    )
    byte_authority.reserve_group(
        projection_configuration_digest=_digest("route-byte-a"),
        member_budget=1,
        byte_budget=4_000,
    )
    byte_before = byte_authority.census()
    with pytest.raises(EventContractError, match="byte capacity"):
        byte_authority.reserve_group(
            projection_configuration_digest=_digest("route-byte-b"),
            member_budget=1,
            byte_budget=4_000,
        )
    assert byte_authority.census() == byte_before

    authority.cancel_empty_group(first)
    reclaimed = authority.census()
    assert reclaimed.retained_groups == 0
    assert reclaimed.reserved_member_capacity == 0
    assert reclaimed.reserved_receipt_capacity == 0
    assert reclaimed.reserved_byte_capacity == 0


def test_group_capacity_rejection_occurs_before_random_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbProjectionGroupAuthority(group_capacity=1)
    authority.reserve_group(
        projection_configuration_digest=_digest("route-a"),
        member_budget=1,
        byte_budget=4_096,
    )

    def fail_rng(_length: int) -> str:
        raise AssertionError("RNG ran after deterministic capacity exhaustion")

    monkeypatch.setattr(projection_module.secrets, "token_hex", fail_rng)
    with pytest.raises(EventContractError, match="group capacity"):
        authority.reserve_group(
            projection_configuration_digest=_digest("route-b"),
            member_budget=1,
            byte_budget=4_096,
        )


def test_malformed_group_generation_is_neutral_and_callback_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    before = authority.census(estimate_bytes=True)
    trap = _CallbackTrap()

    monkeypatch.setattr(projection_module.secrets, "token_hex", lambda _length: trap)
    with pytest.raises(EventContractError, match="malformed scalar"):
        authority.reserve_group(
            projection_configuration_digest=_digest("malformed-generation"),
            member_budget=1,
            byte_budget=4_096,
        )

    assert trap.calls == 0
    assert authority.census(estimate_bytes=True) == before


def test_forced_public_generation_collision_cannot_cross_authority_timing_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        projection_module.secrets,
        "token_hex",
        lambda octets: "a" * (octets * 2),
    )
    first = PersistentSmbProjectionGroupAuthority()
    second = PersistentSmbProjectionGroupAuthority()
    planner = SourceTimingPlanner()
    timing = _sealed_timing(planner)
    configuration = _digest("forced-collision-configuration")
    first_group = first.reserve_group(
        projection_configuration_digest=configuration,
        member_budget=1,
        byte_budget=4_096,
    )
    second_group = second.reserve_group(
        projection_configuration_digest=configuration,
        member_budget=1,
        byte_budget=4_096,
    )

    first_token = first.prepare_member(
        first_group,
        phase=PersistentSmbProjectionPhase.TRANSPORT,
        operation_id="forced-collision-operation",
        operation_binding_digest=_digest("forced-collision-owner"),
        projection_capsule=b"capsule",
        timing_planner=planner,
        timing_preparation=timing,
    )
    second_token = second.prepare_member(
        second_group,
        phase=PersistentSmbProjectionPhase.TRANSPORT,
        operation_id="forced-collision-operation",
        operation_binding_digest=_digest("forced-collision-owner"),
        projection_capsule=b"capsule",
        timing_planner=planner,
        timing_preparation=timing,
    )

    assert first.dispatcher_id == second.dispatcher_id
    assert first_group.generation_id == second_group.generation_id
    assert first_token.timing_context_digest != second_token.timing_context_digest
    assert first_token.timing_binding is not second_token.timing_binding
    assert planner.detached_binding_census().retained_bindings == 2
    first.cancel_member(first_token, timing_planner=planner)
    assert second.authenticates_member_token(second_token, timing_planner=planner)
    second.cancel_member(second_token, timing_planner=planner)
    first.cancel_empty_group(first_group)
    second.cancel_empty_group(second_group)
    timing.cancel()


def test_group_and_member_capacity_are_charged_before_timing_detach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbProjectionGroupAuthority(
        group_capacity=1,
        member_capacity=1,
        receipt_capacity=1,
        byte_capacity=6_000,
    )
    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("route"),
        member_budget=1,
        byte_budget=4_000,
    )
    timing = _sealed_timing(planner)
    original = SourceTimingPlanner.detach_preparation_binding
    called = False

    def observe_detach(
        owner: SourceTimingPlanner,
        preparation: SourceTimingPreparation,
        *,
        context_digest: str,
    ) -> SourceTimingDetachedPreparationBinding:
        nonlocal called
        called = True
        census = authority.census()
        assert census.inactive_members == 1
        assert census.retained_bytes > 0
        assert census.reserved_member_capacity == 1
        assert census.reserved_receipt_capacity == 1
        assert census.reserved_byte_capacity == 4_000
        return original(owner, preparation, context_digest=context_digest)

    monkeypatch.setattr(SourceTimingPlanner, "detach_preparation_binding", observe_detach)
    token = authority.prepare_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="op-1",
        operation_binding_digest=_digest("op-1"),
        projection_capsule=b"capsule",
        timing_planner=planner,
        timing_preparation=timing,
    )

    assert called
    assert authority.authenticates_member_token(token, timing_planner=planner)
    with pytest.raises(EventContractError, match="group member budget"):
        authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
            operation_id="op-2",
            operation_binding_digest=_digest("op-2"),
            projection_capsule=b"capsule",
            timing_planner=planner,
            timing_preparation=timing,
        )


def test_operation_character_cap_precedes_utf8_encoding_and_member_mutation() -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("operation-character-cap"),
        member_budget=1,
        byte_budget=8_192,
    )
    timing = _sealed_timing(planner)
    before = authority.census(estimate_bytes=True)

    with pytest.raises(EventContractError, match="exceeds 512 retained UTF-8 bytes"):
        authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
            operation_id="\ud800" * 513,
            operation_binding_digest=_digest("operation-character-cap-owner"),
            projection_capsule=b"capsule",
            timing_planner=planner,
            timing_preparation=timing,
        )

    assert authority.census(estimate_bytes=True) == before
    assert planner.detached_binding_census().retained_bindings == 0
    authority.cancel_empty_group(group)


def test_failed_timing_detach_reclaims_inactive_slot_and_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("route"),
        member_budget=2,
        byte_budget=8_192,
    )
    timing = _sealed_timing(planner)
    before = authority.census(estimate_bytes=True)

    def fail_detach(*_args: object, **_kwargs: object) -> SourceTimingDetachedPreparationBinding:
        raise StateError("injected detached timing failure")

    monkeypatch.setattr(SourceTimingPlanner, "detach_preparation_binding", fail_detach)
    with pytest.raises(StateError, match="injected"):
        authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
            operation_id="op-1",
            operation_binding_digest=_digest("op-1"),
            projection_capsule=b"capsule",
            timing_planner=planner,
            timing_preparation=timing,
        )

    after = authority.census(estimate_bytes=True)
    assert after.inactive_members == before.inactive_members == 0
    assert after.retained_bytes == before.retained_bytes
    assert after.entry_semantic_bytes == before.entry_semantic_bytes
    assert after.table_backing_bytes == before.table_backing_bytes


def test_failed_member_shell_reclaims_detached_binding_and_live_charge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("route-shell-failure"),
        member_budget=2,
        byte_budget=8_192,
    )
    timing = _sealed_timing(planner)
    before = authority.census(estimate_bytes=True)

    def fail_shell(*_args: object, **_kwargs: object) -> object:
        raise StateError("injected member-shell failure")

    monkeypatch.setattr(projection_module, "PersistentSmbProjectionMemberToken", fail_shell)
    with pytest.raises(StateError, match="member-shell failure"):
        authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
            operation_id="op-shell-failure",
            operation_binding_digest=_digest("op-shell-failure"),
            projection_capsule=b"capsule",
            timing_planner=planner,
            timing_preparation=timing,
        )

    after = authority.census(estimate_bytes=True)
    assert after.inactive_members == before.inactive_members == 0
    assert after.retained_bytes == before.retained_bytes
    assert after.entry_semantic_bytes == before.entry_semantic_bytes
    assert after.table_backing_bytes == before.table_backing_bytes
    assert planner.detached_binding_census().retained_bindings == 0


def test_retained_member_graph_is_deeply_detached_and_has_no_forbidden_capabilities() -> None:
    authority, planner, timing, _group, token = _prepared_member()
    group_record = authority._groups[token.group_id]
    member = group_record.members[token.member_id]

    assert type(member.capsule) is bytes
    assert type(token.timing_binding) is SourceTimingDetachedPreparationBinding
    assert group_record.owner_ref() is authority
    assert group_record.owner_ref.__callback__ is None
    forbidden_names = {
        "PreparedDispatch",
        "SourceTimingPreparation",
        "PreparedProjection",
        "LogEmitter",
    }
    retained = (
        member.token,
        member.capsule,
        member.operation_id,
        member.operation_binding_digest,
        member.capsule_digest,
        member.timing_binding,
    )
    assert all(type(value).__name__ not in forbidden_names for value in retained)
    assert all(not callable(value) for value in retained)
    assert timing not in retained
    assert member.timing_owner_ref is not None
    assert member.timing_owner_ref() is planner
    assert member.timing_owner_ref.__callback__ is None
    assert not hasattr(member, "receipt")
    assert not hasattr(member, "certification")


def test_inactive_same_operation_lost_return_recovers_exact_token_in_o1() -> None:
    authority, planner, timing, group, token = _prepared_member()
    repeated = authority.prepare_member(
        group,
        phase=token.phase,
        operation_id=token.operation_id,
        operation_binding_digest=token.operation_binding_digest,
        projection_capsule=encode_persistent_smb_projection_capsule(
            (b"canonical-smb-operation-v1", token.operation_id.encode("ascii"))
        ),
        timing_planner=planner,
        timing_preparation=timing,
    )
    recovery = authority.recover_inactive_member(
        group,
        operation_id=token.operation_id,
        operation_binding_digest=token.operation_binding_digest,
        timing_planner=planner,
    )

    assert repeated is token
    assert recovery.state == "inactive"
    assert recovery.member_token is token
    assert authority.census().inactive_members == 1

    with pytest.raises(EventContractError, match="different detached projection facts"):
        authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.LOGOFF,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            projection_capsule=b"different",
            timing_planner=planner,
            timing_preparation=timing,
        )
    with pytest.raises(EventContractError, match="foreign operation binding"):
        authority.recover_inactive_member(
            group,
            operation_id=token.operation_id,
            operation_binding_digest=_digest("another-owner"),
            timing_planner=planner,
        )


def test_lost_return_recovery_uses_private_group_identity_without_locked_slot_repair() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    copied_group = replace(group)
    original_configuration = group.projection_configuration_digest
    destructor_results: list[bool] = []
    object.__setattr__(
        group,
        "projection_configuration_digest",
        _AuthoritySlotDestructorProbe(authority, destructor_results),
    )
    assert not authority.authenticates_group(group)

    authority._group_token_locators[id(copied_group)] = group.group_id
    with pytest.raises(EventContractError, match="foreign, copied, or stale"):
        authority.recover_inactive_member(
            copied_group,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            timing_planner=planner,
        )
    authority._group_token_locators.pop(id(copied_group))

    recovery = authority.recover_inactive_member(
        group,
        operation_id=token.operation_id,
        operation_binding_digest=token.operation_binding_digest,
        timing_planner=planner,
    )

    assert recovery.member_token is token
    assert destructor_results == []
    assert not authority.authenticates_group(group)
    tampered_slot = object.__getattribute__(group, "projection_configuration_digest")
    object.__setattr__(group, "projection_configuration_digest", original_configuration)
    del tampered_slot
    gc.collect()
    assert destructor_results == [True]
    assert authority.authenticates_group(group)
    authority.cancel_member(recovery.member_token, timing_planner=planner)
    authority.cancel_empty_group(group)
    census = authority.census()
    assert census.retained_groups == 0
    assert census.inactive_members == 0
    assert census.reserved_member_capacity == 0
    assert census.reserved_receipt_capacity == 0
    assert census.reserved_byte_capacity == 0


def test_member_copy_tamper_foreign_and_stale_timing_fail_closed() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    copied_group = replace(group)
    copied_token = replace(token)
    foreign = PersistentSmbProjectionGroupAuthority()

    assert not authority.authenticates_group(copied_group)
    assert not authority.authenticates_member_token(copied_token, timing_planner=planner)
    assert not foreign.authenticates_member_token(token, timing_planner=planner)
    with pytest.raises(EventContractError, match="foreign, copied, or stale"):
        authority.recover_inactive_member(
            copied_group,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            timing_planner=planner,
        )

    original_operation = token.operation_id
    trap = _CallbackTrap()
    object.__setattr__(token, "operation_id", trap)
    assert not authority.authenticates_member_token(token, timing_planner=planner)
    with pytest.raises(EventContractError, match="tampered or stale"):
        authority.recover_inactive_member(
            group,
            operation_id=original_operation,
            operation_binding_digest=_digest(f"owner:{original_operation}"),
            timing_planner=planner,
        )
    assert trap.calls == 0

    authority.cancel_member(token, timing_planner=planner)
    assert planner.detached_binding_census().retained_bindings == 0
    authority.cancel_empty_group(group)


def test_foreign_timing_owner_and_cancelled_member_are_stale_without_leaks() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    foreign_planner = SourceTimingPlanner()

    assert not authority.authenticates_member_token(
        token,
        timing_planner=foreign_planner,
    )
    with pytest.raises(EventContractError, match="stale timing binding"):
        authority.recover_inactive_member(
            group,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            timing_planner=foreign_planner,
        )
    with pytest.raises(EventContractError, match="foreign, collected, or stale"):
        authority.cancel_member(token, timing_planner=foreign_planner)
    assert authority.census().inactive_members == 1
    assert planner.detached_binding_census().retained_bindings == 1

    authority.cancel_member(token, timing_planner=planner)
    assert not authority.authenticates_member_token(token, timing_planner=planner)
    with pytest.raises(EventContractError, match="tampered or stale"):
        authority.recover_inactive_member(
            group,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            timing_planner=planner,
        )
    with pytest.raises(EventContractError, match="foreign, copied, or stale"):
        authority.cancel_member(token, timing_planner=planner)
    assert planner.detached_binding_census().retained_bindings == 0
    authority.cancel_empty_group(group)


def test_cancel_reclaims_member_after_exact_owner_already_discarded_timing_binding() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    planner.discard_detached_preparation_binding(token.timing_binding)
    assert planner.detached_binding_census().retained_bindings == 0

    authority.cancel_member(token, timing_planner=planner)

    census = authority.census()
    assert census.inactive_members == 0
    authority.cancel_empty_group(group)
    assert authority.census().retained_groups == 0


def test_dispatcher_cancel_reclaims_member_after_exact_timing_owner_is_collected() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("owner-gc-route"),
        member_budget=1,
        byte_budget=8_192,
    )
    owner = dispatcher.source_timing_planner
    timing = _sealed_timing(owner)
    token = dispatcher.prepare_persistent_smb_projection_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="owner-gc-operation",
        operation_binding_digest=_digest("owner-gc-operation"),
        projection_capsule=b"owner-gc-capsule",
        timing_preparation=timing,
    )
    owner_ref = ref(owner)
    dispatcher.source_timing_planner = object()  # type: ignore[assignment]
    del timing
    del owner
    gc.collect()

    assert owner_ref() is None
    dispatcher.cancel_persistent_smb_projection_member(token)
    dispatcher.cancel_empty_persistent_smb_projection_group(group)
    census = dispatcher.persistent_smb_projection_group_census()
    assert census.retained_groups == 0
    assert census.inactive_members == 0
    assert census.reserved_member_capacity == 0
    assert census.reserved_receipt_capacity == 0
    assert census.reserved_byte_capacity == 0


def test_lost_return_recovery_reclaims_member_after_timing_owner_collection() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("lost-return-owner-gc-route"),
        member_budget=1,
        byte_budget=8_192,
    )
    owner = dispatcher.source_timing_planner
    timing = _sealed_timing(owner)
    operation_id = "lost-return-owner-gc-operation"
    owner_digest = _digest(operation_id)
    dispatcher.prepare_persistent_smb_projection_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id=operation_id,
        operation_binding_digest=owner_digest,
        projection_capsule=b"lost-return-owner-gc-capsule",
        timing_preparation=timing,
    )
    owner_ref = ref(owner)
    dispatcher.source_timing_planner = SourceTimingPlanner(
        timing_runtime=dispatcher.timing_runtime,
    )
    del timing
    del owner
    gc.collect()

    assert owner_ref() is None
    with pytest.raises(EventContractError, match="reclaimed a collected timing owner"):
        dispatcher.recover_inactive_persistent_smb_projection_member(
            group,
            operation_id=operation_id,
            operation_binding_digest=owner_digest,
        )
    assert dispatcher.persistent_smb_projection_group_census().inactive_members == 0
    dispatcher.cancel_empty_persistent_smb_projection_group(group)


def test_dispatcher_rebind_rejects_live_foreign_timing_owner_before_cancel() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("live-owner-rebind-route"),
        member_budget=1,
        byte_budget=8_192,
    )
    owner = dispatcher.source_timing_planner
    timing = _sealed_timing(owner)
    token = dispatcher.prepare_persistent_smb_projection_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="live-owner-rebind-operation",
        operation_binding_digest=_digest("live-owner-rebind-operation"),
        projection_capsule=b"live-owner-rebind-capsule",
        timing_preparation=timing,
    )
    replacement = SourceTimingPlanner(timing_runtime=dispatcher.timing_runtime)
    dispatcher.source_timing_planner = replacement

    with pytest.raises(EventContractError, match="foreign, collected, or stale"):
        dispatcher.cancel_persistent_smb_projection_member(token)
    assert dispatcher.persistent_smb_projection_group_census().inactive_members == 1

    dispatcher.source_timing_planner = owner
    dispatcher.cancel_persistent_smb_projection_member(token)
    dispatcher.cancel_empty_persistent_smb_projection_group(group)


def test_exact_identity_locators_reject_copies_and_clean_tampered_originals() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    copied_group = replace(group)
    copied_token = replace(token)

    # Simulate stale/reused integer locator keys. Strong retained references and
    # the final exact-object check must still reject the copied carriers.
    authority._group_token_locators[id(copied_group)] = group.group_id
    authority._member_token_locators[id(copied_token)] = (token.group_id, token.member_id)
    assert not authority.authenticates_group(copied_group)
    assert not authority.authenticates_member_token(copied_token, timing_planner=planner)
    with pytest.raises(EventContractError, match="foreign, copied, or stale"):
        authority.cancel_member(copied_token, timing_planner=planner)
    authority._group_token_locators.pop(id(copied_group))
    authority._member_token_locators.pop(id(copied_token))

    trap = _CallbackTrap()
    object.__setattr__(token, "operation_id", trap)
    authority.cancel_member(token, timing_planner=planner)
    assert trap.calls == 0
    assert id(token) not in authority._member_token_locators

    object.__setattr__(group, "member_budget", trap)
    authority.cancel_empty_group(group)
    assert trap.calls == 0
    assert id(group) not in authority._group_token_locators
    census = authority.census()
    assert census.retained_groups == 0
    assert census.reserved_member_capacity == 0
    assert census.reserved_receipt_capacity == 0
    assert census.reserved_byte_capacity == 0


def test_authority_copy_and_shared_private_map_forgery_cannot_claim_original_records() -> None:
    authority, planner, _timing, group, token = _prepared_member()

    with pytest.raises(EventContractError, match="noncopyable"):
        copy.copy(authority)
    with pytest.raises(EventContractError, match="noncopyable"):
        copy.deepcopy(authority)

    forged = object.__new__(PersistentSmbProjectionGroupAuthority)
    forged.__dict__.update(authority.__dict__)
    assert not forged.authenticates_group(group)
    assert not forged.authenticates_member_token(token, timing_planner=planner)
    with pytest.raises(EventContractError, match="foreign, copied, or stale"):
        forged.cancel_member(token, timing_planner=planner)

    authority.cancel_member(token, timing_planner=planner)
    authority.cancel_empty_group(group)


def test_group_public_tamper_cannot_drift_budget_or_call_back_concurrently() -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("route-concurrent"),
        member_budget=1,
        byte_budget=8_192,
    )
    timing = _sealed_timing(planner)
    original_budget = group.member_budget
    trap = _CallbackTrap()
    started = Event()

    def mutate_public_slot() -> None:
        started.set()
        for _ in range(5_000):
            object.__setattr__(group, "member_budget", trap)
            object.__setattr__(group, "member_budget", original_budget)

    thread = Thread(target=mutate_public_slot)
    thread.start()
    assert started.wait(timeout=1)
    while thread.is_alive():
        try:
            authority.prepare_member(
                group,
                phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
                operation_id="concurrent-operation",
                operation_binding_digest=_digest("concurrent-owner"),
                projection_capsule=b"capsule",
                timing_planner=planner,
                timing_preparation=timing,
            )
        except EventContractError:
            pass
    thread.join(timeout=1)
    object.__setattr__(group, "member_budget", original_budget)
    token = authority.prepare_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="concurrent-operation",
        operation_binding_digest=_digest("concurrent-owner"),
        projection_capsule=b"capsule",
        timing_planner=planner,
        timing_preparation=timing,
    )

    assert trap.calls == 0
    assert authority.authenticates_member_token(token, timing_planner=planner)
    assert authority.census().inactive_members == 1


def test_member_public_tamper_cannot_change_private_recovery_authority() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    original_operation = token.operation_id
    trap = _CallbackTrap()
    started = Event()

    def mutate_public_slot() -> None:
        started.set()
        for _ in range(5_000):
            object.__setattr__(token, "operation_id", trap)
            object.__setattr__(token, "operation_id", original_operation)

    thread = Thread(target=mutate_public_slot)
    thread.start()
    assert started.wait(timeout=1)
    while thread.is_alive():
        authority.authenticates_member_token(token, timing_planner=planner)
    thread.join(timeout=1)
    object.__setattr__(token, "operation_id", original_operation)

    recovery = authority.recover_inactive_member(
        group,
        operation_id=original_operation,
        operation_binding_digest=_digest(f"owner:{original_operation}"),
        timing_planner=planner,
    )
    assert recovery.member_token is token
    assert trap.calls == 0
    authority.cancel_member(token, timing_planner=planner)


def test_member_authentication_final_snapshot_releases_public_slot_outside_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, planner, _timing, group, token = _prepared_member()
    thread, destructor_results, thread_failures = _install_member_snapshot_destructor_race(
        monkeypatch,
        authority=authority,
        token=token,
        snapshot_number=2,
    )

    assert not authority.authenticates_member_token(token, timing_planner=planner)
    thread.join(timeout=2)
    gc.collect()

    assert not thread.is_alive()
    assert not thread_failures
    assert destructor_results == [True]
    authority.cancel_member(token, timing_planner=planner)
    authority.cancel_empty_group(group)


@pytest.mark.parametrize("snapshot_number", (1, 2))
def test_member_recovery_snapshots_release_public_slot_outside_lock(
    monkeypatch: pytest.MonkeyPatch,
    snapshot_number: int,
) -> None:
    authority, planner, _timing, group, token = _prepared_member()
    thread, destructor_results, thread_failures = _install_member_snapshot_destructor_race(
        monkeypatch,
        authority=authority,
        token=token,
        snapshot_number=snapshot_number,
    )

    with pytest.raises(EventContractError, match="tampered or stale|changed or became stale"):
        authority.recover_inactive_member(
            group,
            operation_id=token.operation_id,
            operation_binding_digest=token.operation_binding_digest,
            timing_planner=planner,
        )
    thread.join(timeout=2)
    gc.collect()

    assert not thread.is_alive()
    assert not thread_failures
    assert destructor_results == [True]
    authority.cancel_member(token, timing_planner=planner)
    authority.cancel_empty_group(group)


def test_cancellation_reclaims_member_group_and_source_timing_authority() -> None:
    authority, planner, _timing, group, token = _prepared_member()
    group_only_bytes = authority._groups[group.group_id].retained_bytes - token.retained_bytes

    authority.cancel_member(token, timing_planner=planner)
    member_cancelled = authority.census()
    assert member_cancelled.inactive_members == 0
    assert member_cancelled.retained_bytes == group_only_bytes
    assert planner.detached_binding_census().retained_bindings == 0

    authority.cancel_empty_group(group)
    reclaimed = authority.census(estimate_bytes=True)
    assert reclaimed.retained_groups == 0
    assert reclaimed.retained_bytes == 0
    assert reclaimed.entry_semantic_bytes == 0
    assert reclaimed.reserved_member_capacity == 0
    assert reclaimed.reserved_receipt_capacity == 0
    assert reclaimed.reserved_byte_capacity == 0


def test_census_reports_constant_time_semantic_and_table_backing_bytes() -> None:
    authority = PersistentSmbProjectionGroupAuthority(
        group_capacity=2,
        member_capacity=4,
        receipt_capacity=4,
        byte_capacity=32_768,
    )
    default_empty = authority.census()
    measured_empty = authority.census(estimate_bytes=True)
    assert default_empty.entry_semantic_bytes == 0
    assert default_empty.table_backing_bytes == 0
    assert default_empty.estimated_bytes == 0
    assert measured_empty.entry_semantic_bytes == 0
    assert measured_empty.table_backing_bytes > 0
    assert measured_empty.estimated_bytes == measured_empty.table_backing_bytes

    planner = SourceTimingPlanner()
    group = authority.reserve_group(
        projection_configuration_digest=_digest("census-route"),
        member_budget=2,
        byte_budget=8_192,
    )
    after_group = authority.census(estimate_bytes=True)
    timing = _sealed_timing(planner)
    token = authority.prepare_member(
        group,
        phase=PersistentSmbProjectionPhase.TRANSPORT,
        operation_id="census-operation",
        operation_binding_digest=_digest("census-owner"),
        projection_capsule=b"census-capsule",
        timing_planner=planner,
        timing_preparation=timing,
    )
    after_member = authority.census(estimate_bytes=True)
    assert after_group.entry_semantic_bytes == after_group.retained_bytes > 0
    assert after_member.entry_semantic_bytes == after_member.retained_bytes
    assert (
        after_member.entry_semantic_bytes == after_group.entry_semantic_bytes + token.retained_bytes
    )
    assert after_member.estimated_bytes == (
        after_member.entry_semantic_bytes + after_member.table_backing_bytes
    )

    authority.cancel_member(token, timing_planner=planner)
    authority.cancel_empty_group(group)
    gc.collect()
    final = authority.census(estimate_bytes=True)
    assert final.entry_semantic_bytes == 0
    assert final.table_backing_bytes == measured_empty.table_backing_bytes
    assert final.estimated_bytes == measured_empty.estimated_bytes


def test_census_requires_exact_bool_before_authority_or_topology_locks() -> None:
    authority = PersistentSmbProjectionGroupAuthority()
    dispatcher = EventDispatcher(StateManager(), {})
    authority_trap = _EstimateBytesTrap()
    dispatcher_trap = _EstimateBytesTrap()

    with pytest.raises(EventContractError, match="estimate_bytes requires an exact bool"):
        authority.census(estimate_bytes=authority_trap)  # type: ignore[arg-type]
    with pytest.raises(EventContractError, match="estimate_bytes requires an exact bool"):
        dispatcher.persistent_smb_projection_group_census(
            estimate_bytes=dispatcher_trap,  # type: ignore[arg-type]
        )

    assert authority_trap.calls == 0
    assert dispatcher_trap.calls == 0


def test_repeated_create_cancel_churn_returns_table_backing_to_empty_plateau() -> None:
    authority = PersistentSmbProjectionGroupAuthority(
        group_capacity=1,
        member_capacity=1,
        receipt_capacity=1,
        byte_capacity=8_192,
    )
    planner = SourceTimingPlanner()
    baseline = authority.census(estimate_bytes=True).table_backing_bytes

    for ordinal in range(64):
        group = authority.reserve_group(
            projection_configuration_digest=_digest(f"route-{ordinal}"),
            member_budget=1,
            byte_budget=4_096,
        )
        timing = _sealed_timing(planner)
        token = authority.prepare_member(
            group,
            phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
            operation_id=f"operation-{ordinal}",
            operation_binding_digest=_digest(f"owner-{ordinal}"),
            projection_capsule=b"capsule",
            timing_planner=planner,
            timing_preparation=timing,
        )
        authority.cancel_member(token, timing_planner=planner)
        timing.cancel()
        authority.cancel_empty_group(group)

    census = authority.census(estimate_bytes=True)
    assert census.table_backing_bytes == baseline
    assert census.estimated_bytes == baseline
    assert planner.detached_binding_census().retained_bindings == 0


def test_dispatcher_bridge_privately_binds_route_and_target_generation() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    first = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("route-1"),
        member_budget=1,
        byte_budget=8_192,
    )
    same = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("route-1"),
        member_budget=1,
        byte_budget=8_192,
    )
    second_route = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("route-2"),
        member_budget=1,
        byte_budget=8_192,
    )
    dispatcher.emitters["future_exact_source"] = _WeakTarget()
    replaced_topology = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("route-1"),
        member_budget=1,
        byte_budget=8_192,
    )

    assert first.projection_configuration_digest == same.projection_configuration_digest
    assert (
        len(
            {
                first.projection_configuration_digest,
                second_route.projection_configuration_digest,
                replaced_topology.projection_configuration_digest,
            }
        )
        == 3
    )
    for group in (first, same, second_route, replaced_topology):
        dispatcher.cancel_empty_persistent_smb_projection_group(group)


def test_forced_target_nonce_collision_still_detects_same_type_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = EventDispatcher(StateManager(), {"future_exact_source": _WeakTarget()})
    monkeypatch.setattr(
        "evidenceforge.events.dispatcher.secrets.token_hex",
        lambda octets: "b" * (octets * 2),
    )
    route_digest = _digest("forced-target-nonce-collision")
    first = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=4_096,
    )
    dispatcher.emitters["future_exact_source"] = _WeakTarget()
    replacement = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=4_096,
    )

    assert first.projection_configuration_digest != replacement.projection_configuration_digest
    dispatcher.cancel_empty_persistent_smb_projection_group(first)
    dispatcher.cancel_empty_persistent_smb_projection_group(replacement)


def test_dispatcher_target_generation_census_and_stale_cleanup_are_bounded() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    route_digest = _digest("target-generation-census")
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert baseline.retained_target_generations == 0
    assert baseline.target_generation_capacity == 16_385
    assert baseline.target_generation_semantic_bytes == 0
    assert baseline.target_generation_table_backing_bytes > 0

    dispatcher.emitters["future_exact_source"] = _WeakTarget()
    retained_group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=4_096,
    )
    retained = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert retained.retained_target_generations == 1
    assert retained.target_generation_semantic_bytes > 0
    assert retained.high_water_target_generations == 1
    dispatcher.cancel_empty_persistent_smb_projection_group(retained_group)

    dispatcher.emitters.clear()
    cleanup_group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=4_096,
    )
    cleaned = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert cleaned.retained_target_generations == 0
    assert cleaned.target_generation_semantic_bytes == 0
    assert (
        cleaned.target_generation_table_backing_bytes
        == baseline.target_generation_table_backing_bytes
    )
    dispatcher.cancel_empty_persistent_smb_projection_group(cleanup_group)


def test_dispatcher_target_registry_is_weak_and_retires_when_last_group_cancels() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    target = _WeakTarget()
    target_ref = ref(target)
    dispatcher.emitters["future_exact_source"] = target
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("weak-target-retirement"),
        member_budget=1,
        byte_budget=4_096,
    )
    retained = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    located = next(iter(dispatcher._persistent_smb_target_generations.values()))

    assert type(located[0]) is type(ref(target))
    assert located[0]() is target
    assert retained.retained_target_generations == 1
    assert retained.target_generation_semantic_bytes > 0

    dispatcher.emitters.clear()
    del target
    gc.collect()
    assert target_ref() is None

    dispatcher.cancel_empty_persistent_smb_projection_group(group)
    retired = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert retired.retained_target_generations == 0
    assert retired.target_generation_semantic_bytes == 0
    assert (
        retired.target_generation_table_backing_bytes
        == baseline.target_generation_table_backing_bytes
    )


def test_stale_target_destructor_never_runs_under_topology_lock() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    results: list[bool] = []
    probe = _TargetDestructorProbe(dispatcher, results)
    dispatcher.emitters["future_exact_source"] = probe
    retained_group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("destructor-lock-gate"),
        member_budget=1,
        byte_budget=4_096,
    )
    dispatcher.cancel_empty_persistent_smb_projection_group(retained_group)

    dispatcher.emitters.clear()
    del probe
    cleanup_group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("destructor-lock-gate"),
        member_budget=1,
        byte_budget=4_096,
    )

    assert results == [True]
    dispatcher.cancel_empty_persistent_smb_projection_group(cleanup_group)


def test_emitter_metadata_and_staging_destructor_run_outside_group_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    metadata_results: list[bool] = []
    staging_results: list[bool] = []
    destructor_results: list[bool] = []
    target = _group_lock_probe_target(dispatcher, metadata_results, destructor_results)
    target_identity = id(target)
    dispatcher.emitters["future_exact_source"] = target

    def clearing_ref(value: object) -> ReferenceType[object]:
        acquired = dispatcher._persistent_smb_group_lock.acquire(blocking=False)
        staging_results.append(acquired)
        if acquired:
            dispatcher._persistent_smb_group_lock.release()
        if id(value) == target_identity:
            dispatcher.emitters.clear()
        return ref(value)

    monkeypatch.setattr(dispatcher_module, "ref", clearing_ref)
    del target

    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("group-lock-callback-gate"),
        member_budget=1,
        byte_budget=4_096,
    )

    assert not metadata_results
    assert staging_results == [True]
    assert destructor_results == [True]
    dispatcher.cancel_empty_persistent_smb_projection_group(group)


def test_exact_emitter_dict_count_cap_precedes_snapshot_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _WeakTarget()
    dispatcher = EventDispatcher(
        StateManager(),
        {f"future-exact-source-{ordinal}": target for ordinal in range(16_385)},
    )
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    tuple_calls = 0

    def forbidden_tuple(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        nonlocal tuple_calls
        tuple_calls += 1
        raise AssertionError("emitter items were allocated before their count cap")

    monkeypatch.setattr(dispatcher_module, "tuple", forbidden_tuple, raising=False)
    with pytest.raises(EventContractError, match="too many emitter targets"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=_digest("emitter-count-preflight"),
            member_budget=1,
            byte_budget=4_096,
        )

    assert tuple_calls == 0
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == baseline


def test_dispatcher_topology_preflight_is_bounded_neutral_and_callback_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    route_digest = _digest("topology-preflight")
    before = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)

    _HostileString.calls = 0
    dispatcher.emitters[_HostileString("hostile")] = object()
    with pytest.raises(EventContractError, match="exact strings"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=route_digest,
            member_budget=1,
            byte_budget=4_096,
        )
    assert _HostileString.calls == 0
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == before

    dispatcher.emitters.clear()
    dispatcher.emitters["x" * 4_097] = object()
    with pytest.raises(EventContractError, match="4096 UTF-8 bytes"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=route_digest,
            member_budget=1,
            byte_budget=4_096,
        )
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == before

    dispatcher.emitters.clear()
    dispatcher.emitters["future_exact_source"] = _WeakTarget()
    trap = _CallbackTrap()
    monkeypatch.setattr(
        "evidenceforge.events.dispatcher.secrets.token_hex",
        lambda _length: trap,
    )
    with pytest.raises(EventContractError, match="malformed scalar"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=route_digest,
            member_budget=1,
            byte_budget=4_096,
        )
    assert trap.calls == 0
    assert dispatcher._persistent_smb_target_generations == {}
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == before


def test_dispatcher_topology_character_and_utf8_caps_precede_generation() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    route_digest = _digest("topology-text-preflight")
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    baseline_counter = dispatcher._persistent_smb_next_target_generation

    for emitter_name in ("\ud800" * 4_097, "é" * 4_096):
        dispatcher.emitters.clear()
        dispatcher.emitters[emitter_name] = _WeakTarget()
        with pytest.raises(EventContractError, match="4096 UTF-8 bytes"):
            dispatcher.reserve_persistent_smb_projection_group(
                route_generation_digest=route_digest,
                member_budget=1,
                byte_budget=4_096,
            )
        assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == baseline
        assert dispatcher._persistent_smb_next_target_generation == baseline_counter


def test_group_identity_rng_failure_after_target_staging_is_topology_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dispatcher = EventDispatcher(StateManager(), {"future_exact_source": _WeakTarget()})
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    baseline_counter = dispatcher._persistent_smb_next_target_generation
    trap = _CallbackTrap()
    calls = 0

    def staged_then_failed_rng(octets: int) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            assert octets == 16
            return "a" * 32
        assert octets == 32
        return trap

    monkeypatch.setattr(
        "evidenceforge.events.dispatcher.secrets.token_hex",
        staged_then_failed_rng,
    )
    monkeypatch.setattr(projection_module.secrets, "token_hex", staged_then_failed_rng)

    with pytest.raises(EventContractError, match="generation returned a malformed scalar"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=_digest("staged-group-rng-failure"),
            member_budget=1,
            byte_budget=4_096,
        )

    assert calls == 2
    assert trap.calls == 0
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == baseline
    assert dispatcher._persistent_smb_next_target_generation == baseline_counter


def test_dispatcher_rejected_group_admission_never_mutates_topology_generation() -> None:
    dispatcher = EventDispatcher(
        StateManager(),
        {},
        persistent_smb_group_capacity=1,
        persistent_smb_member_capacity=1,
        persistent_smb_receipt_capacity=1,
    )
    route_digest = _digest("failed-admission-neutrality")
    target = _WeakTarget()
    dispatcher.emitters["future_exact_source"] = target
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    baseline_counter = dispatcher._persistent_smb_next_target_generation

    for member_budget, byte_budget in ((0, 4_096), (1, 0)):
        with pytest.raises(EventContractError):
            dispatcher.reserve_persistent_smb_projection_group(
                route_generation_digest=route_digest,
                member_budget=member_budget,
                byte_budget=byte_budget,
            )
        assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == baseline
        assert dispatcher._persistent_smb_next_target_generation == baseline_counter

    dispatcher.emitters.clear()
    retained = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=4_096,
    )
    dispatcher.emitters["future_exact_source"] = target
    exhausted = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    exhausted_counter = dispatcher._persistent_smb_next_target_generation
    with pytest.raises(EventContractError, match="group capacity"):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=route_digest,
            member_budget=1,
            byte_budget=4_096,
        )
    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == exhausted
    assert dispatcher._persistent_smb_next_target_generation == exhausted_counter
    dispatcher.cancel_empty_persistent_smb_projection_group(retained)


@pytest.mark.parametrize(
    ("dispatcher_kwargs", "first_byte_budget", "error_match"),
    (
        ({"persistent_smb_member_capacity": 1}, 4_096, "member capacity"),
        (
            {
                "persistent_smb_member_capacity": 2,
                "persistent_smb_receipt_capacity": 2,
                "persistent_smb_byte_capacity": 10_000,
            },
            5_000,
            "byte capacity",
        ),
    ),
)
def test_dispatcher_member_and_byte_exhaustion_precede_topology_generation(
    dispatcher_kwargs: dict[str, int],
    first_byte_budget: int,
    error_match: str,
) -> None:
    dispatcher = EventDispatcher(StateManager(), {}, **dispatcher_kwargs)
    route_digest = _digest(f"{error_match}-neutrality")
    first = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=route_digest,
        member_budget=1,
        byte_budget=first_byte_budget,
    )
    dispatcher.emitters["future_exact_source"] = _WeakTarget()
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    baseline_counter = dispatcher._persistent_smb_next_target_generation

    with pytest.raises(EventContractError, match=error_match):
        dispatcher.reserve_persistent_smb_projection_group(
            route_generation_digest=route_digest,
            member_budget=1,
            byte_budget=first_byte_budget,
        )

    assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == baseline
    assert dispatcher._persistent_smb_next_target_generation == baseline_counter
    dispatcher.cancel_empty_persistent_smb_projection_group(first)


def test_concurrent_dispatcher_reserve_cancel_returns_to_zero_target_plateau() -> None:
    dispatcher = EventDispatcher(
        StateManager(),
        {"future_exact_source": _WeakTarget()},
        persistent_smb_group_capacity=8,
        persistent_smb_member_capacity=8,
        persistent_smb_receipt_capacity=8,
        persistent_smb_byte_capacity=128_000,
    )
    baseline = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    start = Event()
    failures: list[BaseException] = []

    def reserve_and_cancel(worker: int) -> None:
        start.wait(timeout=1)
        try:
            for ordinal in range(32):
                group = dispatcher.reserve_persistent_smb_projection_group(
                    route_generation_digest=_digest(f"concurrent-route-{worker}-{ordinal}"),
                    member_budget=1,
                    byte_budget=4_096,
                )
                dispatcher.cancel_empty_persistent_smb_projection_group(group)
        except BaseException as error:
            failures.append(error)

    threads = [Thread(target=reserve_and_cancel, args=(worker,)) for worker in range(4)]
    for thread in threads:
        thread.start()
    start.set()
    for thread in threads:
        thread.join(timeout=5)

    assert not failures
    assert all(not thread.is_alive() for thread in threads)
    final = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert final.retained_groups == 0
    assert final.retained_target_generations == 0
    assert final.reserved_member_capacity == 0
    assert final.reserved_receipt_capacity == 0
    assert final.reserved_byte_capacity == 0
    assert final.target_generation_semantic_bytes == 0
    assert (
        final.target_generation_table_backing_bytes
        == baseline.target_generation_table_backing_bytes
    )


def test_dispatcher_bridge_recovers_only_inactive_member_and_reclaims_all_state() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("compiled-route-generation"),
        member_budget=2,
        byte_budget=16_384,
    )
    timing = _sealed_timing(dispatcher.source_timing_planner)
    owner_digest = _digest("outer-owner-proof-placeholder")
    token = dispatcher.prepare_persistent_smb_projection_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="operation-1",
        operation_binding_digest=owner_digest,
        projection_capsule=encode_persistent_smb_projection_capsule((b"member",)),
        timing_preparation=timing,
    )

    recovery = dispatcher.recover_inactive_persistent_smb_projection_member(
        group,
        operation_id="operation-1",
        operation_binding_digest=owner_digest,
    )
    assert recovery.state == "inactive"
    assert recovery.member_token is token
    dispatcher.cancel_persistent_smb_projection_member(token)
    dispatcher.cancel_empty_persistent_smb_projection_group(group)
    census = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
    assert census.retained_groups == 0
    assert census.inactive_members == 0
    assert census.retained_bytes == 0

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public activation contract for persistent-SMB projection members."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from threading import Barrier, Thread

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_files import ZeekFilesEmitter
from evidenceforge.generation.emitters.zeek_smb import (
    ZeekSmbFilesEmitter,
    ZeekSmbMappingEmitter,
)
from evidenceforge.generation.persistent_smb_projection import (
    PersistentSmbProjectionCommittedMemberRecovery,
    PersistentSmbProjectionMemberCertification,
    PersistentSmbProjectionMemberCommitReceipt,
    PersistentSmbProjectionPhase,
    encode_persistent_smb_projection_capsule,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _uninitialized_exact(target_type: type[object]) -> object:
    """Construct an inert exact target; topology admission never calls it."""

    return object.__new__(target_type)


def _allowed_emitters() -> dict[str, object]:
    return {
        "zeek_conn": _uninitialized_exact(ZeekEmitter),
        "zeek_smb_mapping": _uninitialized_exact(ZeekSmbMappingEmitter),
        "zeek_smb_files": _uninitialized_exact(ZeekSmbFilesEmitter),
        "zeek_files": _uninitialized_exact(ZeekFilesEmitter),
        "ecar": _uninitialized_exact(EcarEmitter),
        "windows_event_security": _uninitialized_exact(WindowsEventEmitter),
    }


def _prepared_member(
    emitters: dict[str, object] | None = None,
) -> tuple[EventDispatcher, SourceTimingPlanner, object, object, object]:
    planner = SourceTimingPlanner()
    dispatcher = EventDispatcher(
        StateManager(),
        emitters or _allowed_emitters(),  # type: ignore[arg-type]
        source_timing_planner=planner,
        timing_runtime=planner.timing_runtime,
    )
    group = dispatcher.reserve_persistent_smb_projection_group(
        route_generation_digest=_digest("route-generation"),
        member_budget=4,
        byte_budget=32_768,
    )
    with planner.prepared_planning() as timing:
        pass
    member = dispatcher.prepare_persistent_smb_projection_member(
        group,
        phase=PersistentSmbProjectionPhase.TREE_OR_FILE,
        operation_id="smb-operation-1",
        operation_binding_digest=_digest("operation-owner"),
        projection_capsule=encode_persistent_smb_projection_capsule(
            (b"persistent-smb-member-v1", b"opaque projection facts")
        ),
        timing_preparation=timing,
    )
    return dispatcher, planner, group, member, timing


def _certify(
    dispatcher: EventDispatcher,
    member: object,
    timing_receipt: object,
    *,
    target_formats: tuple[str, ...] = ("windows_event_security", "zeek_conn", "ecar"),
) -> PersistentSmbProjectionMemberCertification:
    return dispatcher.certify_persistent_smb_projection_member(
        member,  # type: ignore[arg-type]
        target_formats=target_formats,
        lifecycle_binding_digest=_digest("lifecycle-binding"),
        lifecycle_binding_generation=11,
        network_binding_digest=_digest("network-binding"),
        network_binding_generation=12,
        traffic_binding_digest=_digest("traffic-binding"),
        traffic_binding_generation=13,
        expected_timing_receipt=timing_receipt,  # type: ignore[arg-type]
    )


def test_public_surface_exposes_explicit_member_activation_lifecycle() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    public_names = {
        name
        for name in dir(dispatcher)
        if "persistent_smb_projection" in name and not name.startswith("_")
    }

    assert public_names == {
        "acknowledge_persistent_smb_projection_member",
        "cancel_empty_persistent_smb_projection_group",
        "cancel_persistent_smb_projection_member",
        "certify_persistent_smb_projection_member",
        "commit_persistent_smb_projection_member",
        "persistent_smb_projection_group_census",
        "prepare_persistent_smb_projection_member",
        "recover_committed_persistent_smb_projection_member",
        "recover_inactive_persistent_smb_projection_member",
        "reserve_persistent_smb_projection_group",
    }
    assert not any("activate" in name.casefold() for name in public_names)


def test_certify_commit_recover_ack_is_exact_and_reclaims_every_live_member() -> None:
    dispatcher, planner, group, member, preparation = _prepared_member()
    timing = member.timing_binding

    with preparation.claimed_commit() as claimed:
        certification = _certify(dispatcher, member, claimed.expected_receipt)
        assert isinstance(certification, PersistentSmbProjectionMemberCertification)
        assert certification.target_formats == (
            "zeek_conn",
            "ecar",
            "windows_event_security",
        )
        assert (
            dispatcher.certify_persistent_smb_projection_member(
                member,
                target_formats=("ecar", "windows_event_security", "zeek_conn"),
                lifecycle_binding_digest=_digest("lifecycle-binding"),
                lifecycle_binding_generation=11,
                network_binding_digest=_digest("network-binding"),
                network_binding_generation=12,
                traffic_binding_digest=_digest("traffic-binding"),
                traffic_binding_generation=13,
                expected_timing_receipt=claimed.expected_receipt,
            )
            is certification
        )
        with pytest.raises(EventContractError, match="source timing.*not committed"):
            dispatcher.commit_persistent_smb_projection_member(certification)
        claimed.commit_no_fail()

    receipt = dispatcher.commit_persistent_smb_projection_member(certification)
    assert isinstance(receipt, PersistentSmbProjectionMemberCommitReceipt)
    assert receipt.state == "committed_unacknowledged"
    assert receipt.generation_id == group.generation_id
    assert receipt.target_formats == certification.target_formats
    assert planner.authenticates_committed_detached_preparation_binding(
        timing,
        certification.expected_timing_receipt,
        context_digest=member.timing_context_digest,
    )

    recovered = dispatcher.recover_committed_persistent_smb_projection_member(
        group,
        operation_id="smb-operation-1",
        operation_binding_digest=_digest("operation-owner"),
    )
    assert isinstance(recovered, PersistentSmbProjectionCommittedMemberRecovery)
    assert recovered.commit_receipt is receipt
    assert recovered.state == "committed_unacknowledged"
    assert dispatcher.commit_persistent_smb_projection_member(certification) is receipt

    before_ack = dispatcher.persistent_smb_projection_group_census()
    assert before_ack.inactive_members == 0
    assert before_ack.certified_members == 0
    assert before_ack.committed_unacknowledged_members == 1
    assert before_ack.retained_commit_receipts == 1
    assert not dispatcher.acknowledge_persistent_smb_projection_member(
        receipt,
        expected_generation_id=_digest("wrong-generation"),
    )
    assert dispatcher.persistent_smb_projection_group_census() == before_ack

    assert dispatcher.acknowledge_persistent_smb_projection_member(
        receipt,
        expected_generation_id=group.generation_id,
    )
    assert not dispatcher.acknowledge_persistent_smb_projection_member(
        receipt,
        expected_generation_id=group.generation_id,
    )
    after_ack = dispatcher.persistent_smb_projection_group_census()
    assert after_ack.inactive_members == 0
    assert after_ack.certified_members == 0
    assert after_ack.committed_unacknowledged_members == 0
    assert after_ack.retained_commit_receipts == 0
    assert planner.detached_binding_census().retained_bindings == 0
    dispatcher.cancel_empty_persistent_smb_projection_group(group)
    assert dispatcher.persistent_smb_projection_group_census().retained_groups == 0


@pytest.mark.parametrize(
    ("format_name", "target_type"),
    (
        ("zeek_conn", ZeekEmitter),
        ("zeek_smb_mapping", ZeekSmbMappingEmitter),
        ("zeek_smb_files", ZeekSmbFilesEmitter),
        ("zeek_files", ZeekFilesEmitter),
        ("ecar", EcarEmitter),
        ("windows_event_security", WindowsEventEmitter),
    ),
)
def test_certification_accepts_each_exact_supported_target(
    format_name: str,
    target_type: type[object],
) -> None:
    dispatcher, _planner, _group, member, preparation = _prepared_member(
        {format_name: _uninitialized_exact(target_type)}
    )
    with preparation.claimed_commit() as claimed:
        certification = _certify(
            dispatcher,
            member,
            claimed.expected_receipt,
            target_formats=(format_name,),
        )
        claimed.commit_no_fail()
    assert certification.target_formats == (format_name,)
    dispatcher.cancel_persistent_smb_projection_member(member)


@pytest.mark.parametrize(
    "format_name",
    (
        "syslog",
        "sysmon",
        "cisco_asa",
        "snort_alert",
        "suricata_alert",
        "zeek_notice",
    ),
)
def test_certification_rejects_every_unsupported_source_before_state_change(
    format_name: str,
) -> None:
    dispatcher, _planner, _group, member, preparation = _prepared_member()
    before = dispatcher.persistent_smb_projection_group_census()
    with pytest.raises(EventContractError, match="unsupported target"):
        with preparation.claimed_commit() as claimed:
            _certify(
                dispatcher,
                member,
                claimed.expected_receipt,
                target_formats=(format_name,),
            )
    assert dispatcher.persistent_smb_projection_group_census() == before
    assert (
        dispatcher.recover_inactive_persistent_smb_projection_member(
            _group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).member_token
        is member
    )


def test_certification_rejects_allowed_name_bound_to_subclass_without_callbacks() -> None:
    class EcarSubclass(EcarEmitter):
        pass

    dispatcher, _planner, group, member, preparation = _prepared_member(
        {"ecar": _uninitialized_exact(EcarSubclass)}
    )
    before = dispatcher.persistent_smb_projection_group_census()
    with pytest.raises(EventContractError, match="exact target type"):
        with preparation.claimed_commit() as claimed:
            _certify(
                dispatcher,
                member,
                claimed.expected_receipt,
                target_formats=("ecar",),
            )
    assert dispatcher.persistent_smb_projection_group_census() == before
    assert (
        dispatcher.recover_inactive_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).member_token
        is member
    )


def test_certification_cross_binds_external_generations_and_rejects_copies() -> None:
    dispatcher, _planner, group, member, preparation = _prepared_member()
    with preparation.claimed_commit() as claimed:
        certification = _certify(dispatcher, member, claimed.expected_receipt)
        with pytest.raises(EventContractError, match="different certified facts"):
            dispatcher.certify_persistent_smb_projection_member(
                member,
                target_formats=certification.target_formats,
                lifecycle_binding_digest=_digest("lifecycle-binding"),
                lifecycle_binding_generation=99,
                network_binding_digest=_digest("network-binding"),
                network_binding_generation=12,
                traffic_binding_digest=_digest("traffic-binding"),
                traffic_binding_generation=13,
                expected_timing_receipt=claimed.expected_receipt,
            )
        claimed.commit_no_fail()

    copied = replace(certification)
    with pytest.raises(EventContractError, match="copied, foreign, tampered, or stale"):
        dispatcher.commit_persistent_smb_projection_member(copied)
    receipt = dispatcher.commit_persistent_smb_projection_member(certification)
    copied_receipt = replace(receipt)
    assert not dispatcher.acknowledge_persistent_smb_projection_member(
        copied_receipt,
        expected_generation_id=group.generation_id,
    )
    assert (
        dispatcher.recover_committed_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).commit_receipt
        is receipt
    )


def test_target_replacement_after_reservation_fails_before_certification() -> None:
    emitters = {"ecar": _uninitialized_exact(EcarEmitter)}
    dispatcher, _planner, group, member, preparation = _prepared_member(emitters)
    emitters["ecar"] = _uninitialized_exact(EcarEmitter)
    before = dispatcher.persistent_smb_projection_group_census()
    with pytest.raises(EventContractError, match="topology generation"):
        with preparation.claimed_commit() as claimed:
            _certify(
                dispatcher,
                member,
                claimed.expected_receipt,
                target_formats=("ecar",),
            )
    assert dispatcher.persistent_smb_projection_group_census() == before
    assert (
        dispatcher.recover_inactive_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).member_token
        is member
    )


def test_empty_duplicate_and_nonexact_target_collections_are_rejected_neutrally() -> None:
    for targets in ((), ("ecar", "ecar")):
        dispatcher, _planner, group, member, preparation = _prepared_member()
        before = dispatcher.persistent_smb_projection_group_census()
        with pytest.raises(EventContractError, match="target"):
            with preparation.claimed_commit() as claimed:
                _certify(
                    dispatcher,
                    member,
                    claimed.expected_receipt,
                    target_formats=targets,
                )
        assert dispatcher.persistent_smb_projection_group_census() == before
        assert (
            dispatcher.recover_inactive_persistent_smb_projection_member(
                group,
                operation_id="smb-operation-1",
                operation_binding_digest=_digest("operation-owner"),
            ).member_token
            is member
        )

    dispatcher, _planner, group, member, preparation = _prepared_member()
    before = dispatcher.persistent_smb_projection_group_census()
    with pytest.raises(EventContractError, match="exact tuple"):
        with preparation.claimed_commit() as claimed:
            _certify(
                dispatcher,
                member,
                claimed.expected_receipt,
                target_formats=["ecar"],  # type: ignore[arg-type]
            )
    assert dispatcher.persistent_smb_projection_group_census() == before
    assert (
        dispatcher.recover_inactive_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).member_token
        is member
    )


def test_certification_capacity_and_binding_validation_are_allocation_neutral() -> None:
    invalid_cases = (
        {"lifecycle_binding_digest": "not-a-digest"},
        {"network_binding_generation": 0},
        {"traffic_binding_generation": True},
    )
    for override in invalid_cases:
        dispatcher, _planner, group, member, preparation = _prepared_member()
        before = dispatcher.persistent_smb_projection_group_census(estimate_bytes=True)
        with pytest.raises(EventContractError):
            with preparation.claimed_commit() as claimed:
                kwargs: dict[str, object] = {
                    "target_formats": ("ecar",),
                    "lifecycle_binding_digest": _digest("lifecycle-binding"),
                    "lifecycle_binding_generation": 11,
                    "network_binding_digest": _digest("network-binding"),
                    "network_binding_generation": 12,
                    "traffic_binding_digest": _digest("traffic-binding"),
                    "traffic_binding_generation": 13,
                    "expected_timing_receipt": claimed.expected_receipt,
                }
                kwargs.update(override)
                dispatcher.certify_persistent_smb_projection_member(
                    member,
                    **kwargs,  # type: ignore[arg-type]
                )
        assert dispatcher.persistent_smb_projection_group_census(estimate_bytes=True) == before
        assert (
            dispatcher.recover_inactive_persistent_smb_projection_member(
                group,
                operation_id="smb-operation-1",
                operation_binding_digest=_digest("operation-owner"),
            ).member_token
            is member
        )


def test_inactive_cancel_remains_available_and_certified_member_is_not_inactive() -> None:
    dispatcher, _planner, group, member, preparation = _prepared_member()
    with preparation.claimed_commit() as claimed:
        _certify(dispatcher, member, claimed.expected_receipt, target_formats=("ecar",))
        with pytest.raises(EventContractError, match="inactive"):
            dispatcher.recover_inactive_persistent_smb_projection_member(
                group,
                operation_id="smb-operation-1",
                operation_binding_digest=_digest("operation-owner"),
            )
        claimed.commit_no_fail()
    dispatcher.cancel_persistent_smb_projection_member(member)
    census = dispatcher.persistent_smb_projection_group_census()
    assert census.inactive_members == 0
    assert census.certified_members == 0
    dispatcher.cancel_empty_persistent_smb_projection_group(group)


def test_sysmon_exact_class_is_rejected_even_when_named_like_windows_security() -> None:
    dispatcher, _planner, group, member, preparation = _prepared_member(
        {"windows_event_security": _uninitialized_exact(SysmonEventEmitter)}
    )
    with pytest.raises(EventContractError, match="exact target type"):
        with preparation.claimed_commit() as claimed:
            _certify(
                dispatcher,
                member,
                claimed.expected_receipt,
                target_formats=("windows_event_security",),
            )
    assert (
        dispatcher.recover_inactive_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).member_token
        is member
    )


def test_parallel_commit_lost_returns_converge_and_only_one_ack_reclaims() -> None:
    dispatcher, _planner, group, member, preparation = _prepared_member()
    with preparation.claimed_commit() as claimed:
        certification = _certify(
            dispatcher,
            member,
            claimed.expected_receipt,
            target_formats=("ecar",),
        )
        claimed.commit_no_fail()

    commit_start = Barrier(3)
    receipts: list[PersistentSmbProjectionMemberCommitReceipt] = []
    failures: list[BaseException] = []

    def commit() -> None:
        try:
            commit_start.wait(timeout=2)
            receipts.append(dispatcher.commit_persistent_smb_projection_member(certification))
        except BaseException as error:
            failures.append(error)

    commit_threads = [Thread(target=commit) for _ordinal in range(2)]
    for thread in commit_threads:
        thread.start()
    commit_start.wait(timeout=2)
    for thread in commit_threads:
        thread.join(timeout=2)

    assert not failures
    assert all(not thread.is_alive() for thread in commit_threads)
    assert len(receipts) == 2
    assert receipts[0] is receipts[1]
    receipt = receipts[0]
    assert (
        dispatcher.recover_committed_persistent_smb_projection_member(
            group,
            operation_id="smb-operation-1",
            operation_binding_digest=_digest("operation-owner"),
        ).commit_receipt
        is receipt
    )

    ack_start = Barrier(3)
    acknowledgements: list[bool] = []

    def acknowledge() -> None:
        try:
            ack_start.wait(timeout=2)
            acknowledgements.append(
                dispatcher.acknowledge_persistent_smb_projection_member(
                    receipt,
                    expected_generation_id=group.generation_id,
                )
            )
        except BaseException as error:
            failures.append(error)

    ack_threads = [Thread(target=acknowledge) for _ordinal in range(2)]
    for thread in ack_threads:
        thread.start()
    ack_start.wait(timeout=2)
    for thread in ack_threads:
        thread.join(timeout=2)

    assert not failures
    assert all(not thread.is_alive() for thread in ack_threads)
    assert sorted(acknowledgements) == [False, True]
    census = dispatcher.persistent_smb_projection_group_census()
    assert census.committed_unacknowledged_members == 0
    assert census.retained_commit_receipts == 0
    dispatcher.cancel_empty_persistent_smb_projection_group(group)

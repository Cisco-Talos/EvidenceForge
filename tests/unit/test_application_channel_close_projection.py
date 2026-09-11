# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Exact precommit projection contracts for application-channel closure."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation import application_channels as application_channels_module
from evidenceforge.generation.application_channels import (
    ApplicationChannelCloseAdmissionResult,
    ApplicationChannelCloseCommitRecovery,
    ApplicationChannelPreparedCloseToken,
    ApplicationChannelRegistry,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 19, 12, tzinfo=UTC)
_END = _START + timedelta(days=1)


def _registry() -> ApplicationChannelRegistry:
    return ApplicationChannelRegistry(window_start=_START, window_end=_END)


def _identity() -> ApplicationChannelIdentity:
    return ApplicationChannelIdentity(
        channel_id="channel-close-projection",
        protocol="smb",
        owner_id="smb-owner",
        affinity_digest="a" * 64,
        binding=ApplicationTransportBinding(
            transport_id="transport-close-projection",
            opened_at=_START,
            closes_at=_START + timedelta(hours=1),
        ),
        opened_at=_START,
        idle_timeout=timedelta(minutes=30),
        hard_deadline=_START + timedelta(hours=1),
        budget=ApplicationChannelBudget(
            initiator_bytes=10_000,
            responder_bytes=20_000,
            operations=8,
        ),
    )


def _operation() -> ApplicationOperationReservation:
    return ApplicationOperationReservation(
        operation_id="operation-close-projection",
        channel_id="channel-close-projection",
        ordinal=0,
        started_at=_START + timedelta(minutes=1),
        ended_at=_START + timedelta(minutes=2),
        initiator_bytes=321,
        responder_bytes=654,
    )


def _prepare_close(
    registry: ApplicationChannelRegistry,
) -> ApplicationChannelPreparedCloseToken:
    registry.open_channel_with_completed_operation(_identity(), _operation())
    return registry.prepare_close_channel(
        "channel-close-projection",
        closed_at=_START + timedelta(minutes=3),
        reason="persistent channel finalized",
    )


def _snapshot_digest(registry: ApplicationChannelRegistry) -> tuple[object, ...]:
    snapshot = registry.get("channel-close-projection")
    assert snapshot is not None
    return (
        snapshot.identity.channel_id,
        snapshot.identity.protocol,
        snapshot.identity.owner_id,
        snapshot.identity.affinity_digest,
        snapshot.identity.binding.transport_id,
        snapshot.identity.binding.opened_at,
        snapshot.identity.binding.closes_at,
        snapshot.identity.opened_at,
        snapshot.identity.idle_timeout,
        snapshot.identity.hard_deadline,
        snapshot.identity.budget.initiator_bytes,
        snapshot.identity.budget.responder_bytes,
        snapshot.identity.budget.operations,
        snapshot.last_activity_at,
        snapshot.idle_deadline,
        snapshot.reserved_initiator_bytes,
        snapshot.reserved_responder_bytes,
        snapshot.reserved_operations,
        snapshot.completed_operations,
        snapshot.active_operations,
        snapshot.closed_at,
        snapshot.close_reason,
    )


class _HostileScalar:
    """Record any callback a proof validator accidentally invokes."""

    def __init__(self, callbacks: list[str]) -> None:
        self._callbacks = callbacks

    def _called(self, name: str) -> object:
        self._callbacks.append(name)
        raise AssertionError(f"hostile {name} callback executed")

    def __repr__(self) -> str:
        return self._called("repr")  # type: ignore[return-value]

    def __str__(self) -> str:
        return self._called("str")  # type: ignore[return-value]

    def __eq__(self, _other: object) -> bool:
        return self._called("eq")  # type: ignore[return-value]

    def __hash__(self) -> int:
        return self._called("hash")  # type: ignore[return-value]

    def __bool__(self) -> bool:
        return self._called("bool")  # type: ignore[return-value]


def test_prepared_close_exposes_exact_authenticated_precommit_projection() -> None:
    """A close preparation exposes its exact detached prestate and terminal poststate."""

    registry = _registry()
    token = _prepare_close(registry)

    projection = registry.prepared_close_projection(token)

    assert registry.authenticates_prepared_close_projection(token, projection)
    assert projection.channel_id == "channel-close-projection"
    assert projection.owner_id == "smb-owner"
    assert projection.transport_id == "transport-close-projection"
    assert projection.expected_current.closed_at is None
    assert projection.projected_terminal.closed_at == _START + timedelta(minutes=3)
    assert projection.cumulative_initiator_bytes == 321
    assert projection.cumulative_responder_bytes == 654
    assert projection.cumulative_operations == 1
    assert projection.completed_operations == 1
    assert projection.active_operations == 0
    assert projection.owner_partition_id == registry.owner_partition_id("smb-owner")
    assert projection.channel_handle == token._channel_handle
    assert projection.channel_generation == token._channel_generation
    assert projection.publication_token == token.publication_token
    assert projection.proof_token
    assert projection.expected_current is not token._expected_snapshot
    assert projection.projected_terminal is not token._prepared_snapshot
    assert projection.expected_current is not projection.projected_terminal
    assert projection.expected_current.identity is not projection.projected_terminal.identity
    assert (
        projection.expected_current.identity.binding
        is not projection.projected_terminal.identity.binding
    )
    assert (
        projection.expected_current.identity.budget
        is not projection.projected_terminal.identity.budget
    )


def test_projection_exact_cross_binding_never_rereads_mutable_channel_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A manager/State coordinator can bind exact facts without a loose live read."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)
    expected_binding = (
        "smb-owner",
        "a" * 64,
        "transport-close-projection",
        321,
        654,
        1,
        0,
        _START + timedelta(minutes=3),
    )

    monkeypatch.setattr(
        registry,
        "get",
        lambda _channel_id: pytest.fail("projection authentication reread live state"),
    )
    actual_binding = (
        projection.owner_id,
        projection.affinity_digest,
        projection.transport_id,
        projection.cumulative_initiator_bytes,
        projection.cumulative_responder_bytes,
        projection.cumulative_operations,
        projection.active_operations,
        projection.closed_at,
    )

    assert actual_binding == expected_binding
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert actual_binding[:-1] + (_START + timedelta(minutes=4),) != expected_binding


def test_close_before_last_activity_is_projection_and_census_neutral() -> None:
    """A rejected early close cannot reserve proof or recovery authority."""

    registry = _registry()
    registry.open_channel_with_completed_operation(_identity(), _operation())
    before_digest = _snapshot_digest(registry)
    before_census = registry.census()

    with pytest.raises(StateError, match="before its last activity"):
        registry.prepare_close_channel(
            "channel-close-projection",
            closed_at=_START + timedelta(minutes=1),
            reason="too early",
        )

    assert _snapshot_digest(registry) == before_digest
    after_census = registry.census()
    assert after_census.lookup_candidates_inspected == before_census.lookup_candidates_inspected + 1
    assert (
        replace(
            after_census,
            lookup_candidates_inspected=before_census.lookup_candidates_inspected,
        )
        == before_census
    )


def test_projection_copy_foreign_cancel_and_ack_are_fail_closed() -> None:
    """Only the exact retained proof remains authoritative over its bounded lifetime."""

    registry = _registry()
    foreign = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)

    assert not registry.authenticates_prepared_close_projection(replace(token), projection)
    assert not registry.authenticates_prepared_close_projection(deepcopy(token), projection)
    assert not registry.authenticates_prepared_close_projection(token, replace(projection))
    assert not registry.authenticates_prepared_close_projection(token, deepcopy(projection))
    assert not foreign.authenticates_prepared_close_projection(token, projection)
    assert registry.cancel_prepared_close(token)
    assert not registry.authenticates_prepared_close_projection(token, projection)
    with pytest.raises(StateError, match="copied|stale"):
        registry.prepared_close_projection(token)

    token = registry.prepare_close_channel(
        "channel-close-projection",
        closed_at=_START + timedelta(minutes=3),
        reason="persistent channel finalized",
    )
    projection = registry.prepared_close_projection(token)
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.acknowledge_committed_close(token, result)
    assert not registry.authenticates_prepared_close_projection(token, projection)


@pytest.mark.parametrize(
    "fault_stage",
    (
        "close-ack-record",
        "close-secondary-indexes",
        "close-accounting-marker",
        "close-primary-token",
        "close-capability",
        "close-ack-slot",
        "close-ack-result",
        "close-ack-receipt",
        "close-ack-release-marker",
    ),
)
def test_projection_remains_authoritative_through_commit_reconcile_and_ack_retry(
    monkeypatch: pytest.MonkeyPatch,
    fault_stage: str,
) -> None:
    """Committed recovery and an interrupted ack retain the exact projection authority."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)

    with registry.prepared_close(token) as prepared:
        assert registry.authenticates_prepared_close_projection(token, projection)
        result = prepared.commit_no_fail()
        assert registry.authenticates_prepared_close_projection(token, projection)
    recovery = registry.reconcile_committed_close(token)
    assert recovery.status == "committed"
    assert recovery.result is result
    assert registry.recover_committed_close(token) is result

    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == fault_stage and not faulted:
            faulted = True
            raise RuntimeError("injected close projection ack tail")

    if fault_stage == "close-ack-record":
        monkeypatch.setattr(registry, "_prepared_retention_fault", fail_once)
    else:
        monkeypatch.setattr(registry, "_prepared_release_fault", fail_once)
    with pytest.raises(RuntimeError, match="projection ack tail"):
        registry.acknowledge_committed_close(token, result)
    assert faulted
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.prepared_close_projection(token) is projection
    assert registry.recover_committed_close(token) is result

    monkeypatch.setattr(registry, "_prepared_retention_fault", lambda _stage: None)
    monkeypatch.setattr(registry, "_prepared_release_fault", lambda _stage: None)
    assert registry.acknowledge_committed_close(token, result)
    assert not registry.authenticates_prepared_close_projection(token, projection)


def test_projection_acknowledgement_lost_return_has_terminal_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception after a successful ack cannot strand or replay proof authority."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()
    original_acknowledge = registry.acknowledge_committed_close

    def acknowledge_then_raise(
        prepared_token: ApplicationChannelPreparedCloseToken,
        committed_result: ApplicationChannelCloseAdmissionResult,
    ) -> object:
        acknowledged = original_acknowledge(prepared_token, committed_result)
        assert acknowledged
        raise RuntimeError("lost acknowledgement return")

    monkeypatch.setattr(registry, "acknowledge_committed_close", acknowledge_then_raise)
    with pytest.raises(RuntimeError, match="lost acknowledgement return"):
        registry.acknowledge_committed_close(token, result)

    monkeypatch.setattr(registry, "acknowledge_committed_close", original_acknowledge)
    assert registry.recover_committed_close(token) is None
    assert not registry.authenticates_prepared_close_projection(token, projection)
    assert registry.census().prepared_close_projections == 0
    assert not registry.acknowledge_committed_close(token, result)


def test_projection_survives_call_original_then_raise_commit_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost common-close return adopts exact terminal truth and keeps its proof."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)
    original = registry._commit_prepared_close_locked
    faulted = False

    def commit_then_raise(prepared: ApplicationChannelPreparedCloseToken) -> object:
        nonlocal faulted
        result = original(prepared)
        if not faulted:
            faulted = True
            raise RuntimeError("lost close result")
        return result

    monkeypatch.setattr(registry, "_commit_prepared_close_locked", commit_then_raise)
    with registry.prepared_close(token) as prepared:
        result = prepared.commit_no_fail()

    assert faulted
    assert prepared.committed
    assert prepared.recovery_status == "committed"
    assert registry.recover_committed_close(token) is result
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.acknowledge_committed_close(token, result)


def test_projection_indeterminate_fail_before_converges_to_noncommit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-mutation failure keeps proof authority until certified cancel."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)
    original_reconcile = registry._reconcile_claimed_close

    def fail_before(_trusted: ApplicationChannelPreparedCloseToken) -> object:
        raise RuntimeError("failed before close mutation")

    monkeypatch.setattr(registry, "_commit_prepared_close_locked", fail_before)
    monkeypatch.setattr(
        registry,
        "_reconcile_claimed_close",
        lambda _token: ApplicationChannelCloseCommitRecovery("indeterminate"),
    )
    with pytest.raises(RuntimeError, match="before close mutation"):
        with registry.prepared_close(token) as prepared:
            prepared.commit_no_fail()
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.census().claimed_admissions == 1

    monkeypatch.setattr(registry, "_reconcile_claimed_close", original_reconcile)
    recovery = registry.reconcile_committed_close(token)
    assert recovery.status == "not_committed"
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.cancel_prepared_close(token)
    assert not registry.authenticates_prepared_close_projection(token, projection)


def test_projection_indeterminate_primitive_fault_converges_to_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A journaled ambiguous close converges to committed truth with the same proof."""

    registry = _registry()
    token = _prepare_close(registry)
    projection = registry.prepared_close_projection(token)
    original_reconcile = registry._reconcile_claimed_close
    faulted = False

    def fail_once(stage: str) -> None:
        nonlocal faulted
        if stage == "close-row" and not faulted:
            faulted = True
            raise RuntimeError("ambiguous close row")

    monkeypatch.setattr(registry, "_prepared_commit_fault", fail_once)
    monkeypatch.setattr(
        registry,
        "_reconcile_claimed_close",
        lambda _token: ApplicationChannelCloseCommitRecovery("indeterminate"),
    )
    with pytest.raises(RuntimeError, match="ambiguous close row"):
        with registry.prepared_close(token) as prepared:
            prepared.commit_no_fail()
    assert faulted
    assert registry.authenticates_prepared_close_projection(token, projection)

    monkeypatch.setattr(registry, "_reconcile_claimed_close", original_reconcile)
    monkeypatch.setattr(registry, "_prepared_commit_fault", lambda _stage: None)
    recovery = registry.reconcile_committed_close(token)
    assert recovery.status == "committed"
    assert recovery.result is not None
    assert registry.authenticates_prepared_close_projection(token, projection)
    assert registry.acknowledge_committed_close(token, recovery.result)


def test_projection_capacity_is_reserved_and_explicitly_reclaimed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proof authority consumes the existing bounded recovery slot without eviction."""

    monkeypatch.setattr(application_channels_module, "_MAX_RECOVERABLE_ADMISSION_RESULTS", 1)
    registry = _registry()
    registry.open_channel_with_completed_operation(_identity(), _operation())
    registry.open_channel_with_completed_operation(
        replace(
            _identity(),
            channel_id="channel-close-projection-2",
            owner_id="smb-owner-2",
            affinity_digest="b" * 64,
            binding=replace(
                _identity().binding,
                transport_id="transport-close-projection-2",
            ),
        ),
        replace(
            _operation(),
            operation_id="operation-close-projection-2",
            channel_id="channel-close-projection-2",
        ),
    )
    first = registry.prepare_close_channel(
        "channel-close-projection",
        closed_at=_START + timedelta(minutes=3),
        reason="first close",
    )
    first_projection = registry.prepared_close_projection(first)
    assert registry.census().prepared_close_projections == 1

    with pytest.raises(StateError, match="recovery capacity"):
        registry.prepare_close_channel(
            "channel-close-projection-2",
            closed_at=_START + timedelta(minutes=3),
            reason="second close",
        )
    assert registry.authenticates_prepared_close_projection(first, first_projection)
    assert registry.census().prepared_close_projections == 1

    assert registry.cancel_prepared_close(first)
    assert registry.census().prepared_close_projections == 0
    replacement = registry.prepare_close_channel(
        "channel-close-projection-2",
        closed_at=_START + timedelta(minutes=3),
        reason="second close",
    )
    assert registry.census().prepared_close_projections == 1
    assert registry.cancel_prepared_close(replacement)
    assert registry.census().prepared_close_projections == 0

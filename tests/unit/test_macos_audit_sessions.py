# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Synthetic audit identities have independent atomic and durable ownership."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.identity import MacosAuditSession, PosixProcessCredentials
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import (
    StateManagerParticipant,
    _capture_head,
    _restore_head,
)
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_identity import _START, _start


def _plan(
    manager: StateManager, host: str = "MAC-A", uid: int = 501
) -> tuple[MaterializationBatchBuilder, SessionMaterializationPlan]:
    builder = manager.begin_materialization_batch()
    session = builder.plan_session(
        username="casey",
        system=host,
        logon_type=10,
        source_ip="192.0.2.10",
        session_kind="ssh",
        auth_protocol="ssh",
        start_time=_START,
        source_ready_time=_START + timedelta(seconds=2),
        network_close_time=_START + timedelta(minutes=5),
    )
    return builder, builder.enrich_macos_audit_session(
        session, audit_uid=uid, authenticated_at=_START + timedelta(seconds=1)
    )


def _commit(manager: StateManager, builder: MaterializationBatchBuilder) -> None:
    with manager.prepared_materialization_batch(builder.seal()) as prepared:
        prepared.apply_provisional()
        prepared.finalize_no_fail()


def test_audit_origin_is_allocation_free_separate_from_session_and_process_ids() -> None:
    manager = StateManager()
    process = _start(manager)
    before = manager.materialization_digest()
    builder, session = _plan(manager)
    origin = session.audit_origin
    assert origin is not None
    assert origin.audit_uid == 501
    assert origin.audit_session_id == 100_000
    assert origin.audit_session_id != process.pid
    assert session.identity.session_id == 0
    assert not manager._macos_audit_session_counters
    assert manager.materialization_digest() == before
    _commit(manager, builder)
    assert manager.get_session(session.identity.logon_id).audit_origin == origin
    assert manager._macos_audit_session_counters == {"MAC-A": 100_000}
    assert not manager._linux_logind_session_counters
    assert manager.get_current_time() == origin.created_at


def test_audit_origin_abort_restores_allocator_and_exact_batch_can_retry() -> None:
    manager = StateManager()
    _start(manager)
    builder, session = _plan(manager)
    origin = session.audit_origin
    assert origin is not None
    actor = builder.plan_process(
        system="MAC-A",
        parent_pid=0,
        image="/bin/zsh",
        command_line="-zsh",
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        logon_id=session.identity.logon_id,
        session_plan=session,
        require_session=True,
        start_time=_START + timedelta(seconds=2),
        credentials=PosixProcessCredentials(
            501, 501, 20, 20, origin.audit_uid, origin.audit_session_id
        ),
    )
    plan = builder.seal()
    digest = manager.materialization_digest()
    with manager.prepared_materialization_batch(plan) as prepared:
        prepared.apply_provisional()
        assert manager._macos_audit_session_counters == {"MAC-A": 100_000}
        assert manager.get_process_identity("MAC-A", actor.identity.pid) == actor.identity
    assert manager.materialization_digest() == digest
    # A generic batch abort invalidates its admission fence; replan the retry.
    retry, retried_session = _plan(manager)
    assert retried_session.audit_origin == origin
    _commit(manager, retry)
    assert manager.get_session(retried_session.identity.logon_id).audit_origin == origin
    second, second_session = _plan(manager)
    assert second_session.audit_origin.audit_session_id == 100_001
    _commit(manager, second)


def test_audit_origin_checkpoint_and_host_namespaces_remain_independent() -> None:
    manager = StateManager()
    participant = StateManagerParticipant(manager)
    _start(manager)
    _start(manager, "MAC-B")
    first, first_session = _plan(manager)
    _commit(manager, first)
    other, other_session = _plan(manager, "MAC-B", 502)
    _commit(manager, other)
    assert (
        other_session.audit_origin.audit_session_id == first_session.audit_origin.audit_session_id
    )
    restored = StateManager()
    seal = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    StateManagerParticipant(restored).restore_checkpoint(
        seal.head.payload, tuple(segment.payload for segment in seal.segments)
    )
    assert (
        restored.get_session(first_session.identity.logon_id).audit_origin
        == first_session.audit_origin
    )
    left, left_session = _plan(manager)
    right, right_session = _plan(restored)
    assert left_session.audit_origin == right_session.audit_origin
    _commit(manager, left)
    _commit(restored, right)
    assert restored._macos_audit_session_counters == manager._macos_audit_session_counters
    assert restored._used_logon_ids == manager._used_logon_ids


@pytest.mark.parametrize("uid", [True, -1, 2**32 - 1, "501"])
def test_invalid_account_origin_never_consumes_audit_namespace(uid: object) -> None:
    manager = StateManager()
    _start(manager)
    before = manager.materialization_digest()
    with pytest.raises(ValueError, match="known unsigned account"):
        _plan(manager, uid=uid)
    assert manager.materialization_digest() == before


def test_audit_namespace_exhaustion_and_non_mac_enrichment_fail_explicitly() -> None:
    manager = StateManager()
    _start(manager, platform="linux")
    with pytest.raises(StateError, match="Mac SSH"):
        _plan(manager)
    manager = StateManager()
    _start(manager)
    manager._macos_audit_session_counters["MAC-A"] = 2**32 - 2
    before = manager.materialization_digest()
    with pytest.raises(StateError, match="exhausted"):
        _plan(manager)
    assert manager.materialization_digest() == before


def test_audit_origin_and_counter_tampering_are_bound_to_publication_token() -> None:
    manager = StateManager()
    _start(manager)
    _builder, session = _plan(manager)
    changed = replace(session.audit_origin, audit_uid=502)
    forged = replace(session, _payload=replace(session._payload, audit_origin=changed))
    with pytest.raises(StateError, match="integrity"):
        manager.materialize_session(forged)
    forged = replace(
        session,
        _allocator_patch=replace(
            session._allocator_patch, macos_audit_session_counter=("MAC-B", 100_000)
        ),
    )
    with pytest.raises(StateError, match="inconsistent"):
        manager.materialize_session(forged)
    assert not manager._macos_audit_session_counters


@pytest.mark.parametrize("field", ["state_time", "effective_uid", "source_ready_time"])
def test_audited_session_publication_binds_credential_and_timing_facts(field: str) -> None:
    manager = StateManager()
    _start(manager)
    _builder, session = _plan(manager)
    changed = 502 if field == "effective_uid" else _START + timedelta(seconds=4)
    forged = replace(session, _payload=replace(session._payload, **{field: changed}))
    with pytest.raises(StateError, match="integrity"):
        manager.materialize_session(forged)
    assert not manager._macos_audit_session_counters


@pytest.mark.parametrize("seconds", [-1, 3, 300])
def test_audit_authentication_cannot_precede_open_or_follow_readiness(seconds: int) -> None:
    manager = StateManager()
    _start(manager)
    builder = manager.begin_materialization_batch()
    session = builder.plan_session(
        username="casey",
        system="MAC-A",
        logon_type=10,
        source_ip="192.0.2.10",
        session_kind="ssh",
        auth_protocol="ssh",
        start_time=_START,
        source_ready_time=_START + timedelta(seconds=2),
        network_close_time=_START + timedelta(minutes=5),
    )
    before = manager.materialization_digest()
    with pytest.raises(StateError, match="open interval"):
        builder.enrich_macos_audit_session(
            session, audit_uid=501, authenticated_at=_START + timedelta(seconds=seconds)
        )
    assert manager.materialization_digest() == before


def test_retained_session_origin_survives_logoff_and_checkpoint() -> None:
    manager = StateManager()
    _start(manager)
    builder, session = _plan(manager)
    _commit(manager, builder)
    manager.end_session(session.identity.logon_id, _START + timedelta(minutes=5))
    restored = StateManager()
    _restore_head(restored, _capture_head(manager))
    ended = restored._ended_sessions[session.identity.logon_id][0]
    assert ended.audit_origin == session.audit_origin
    assert restored._macos_audit_session_counters == {"MAC-A": 100_000}


def test_checkpoint_rejects_missing_counter_authority_and_older_head_contract() -> None:
    manager = StateManager()
    _start(manager)
    builder, _session = _plan(manager)
    _commit(manager, builder)
    head = loads(_capture_head(manager))
    head["simple"]["_macos_audit_session_counters"] = encode_state_value({})
    with pytest.raises(CheckpointCorruptionError, match="audit origin"):
        _restore_head(StateManager(), dumps(head))
    head["schema_version"] = "2"
    with pytest.raises(CheckpointCorruptionError, match="schema"):
        _restore_head(StateManager(), dumps(head))


def test_legacy_session_records_preserve_absent_audit_origin() -> None:
    manager = StateManager()
    session = manager.materialize_session(
        manager.plan_session_materialization(
            username="casey",
            system="LINUX",
            logon_type=10,
            source_ip="192.0.2.10",
            start_time=_START,
        )
    )
    encoded = encode_state_value(session)
    assert encoded[1] == "active-session-v2"
    encoded[1] = "active-session"
    encoded[2].pop()
    assert decode_state_value(encoded) == session
    encoded[2].pop()
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encoded)


def test_native_audit_snapshot_rejects_default_sentinels_and_unaware_time() -> None:
    for value in [0, 99_999, 2**32 - 1, True]:
        with pytest.raises(ValueError, match="kernel-assigned"):
            MacosAuditSession(501, value, _START)
    with pytest.raises(ValueError, match="aware timestamp"):
        MacosAuditSession(501, 100_000, _START.replace(tzinfo=None))

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented GUI audit origins are login-owned, durable and independent of POSIX SIDs."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import (
    StateManagerParticipant,
    _capture_head,
    _restore_head,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _START, _commit, _plan, _start
from tests.unit.test_macos_installed_provisioning import _scenario


def _gui(
    state: StateManager, *, seconds: int = 0, **changes: object
) -> tuple[MaterializationBatchBuilder, SessionMaterializationPlan]:
    batch = state.begin_materialization_batch()
    values = {
        "username": "casey",
        "system": "MAC-A",
        "logon_type": 2,
        "source_ip": "-",
        "session_kind": "interactive",
        "auth_protocol": "local",
        "effective_uid": 501,
        "effective_gid": 20,
        "session_id": 0,
        "start_time": _START + timedelta(seconds=seconds),
    }
    values.update(changes)
    session = batch.plan_session(**values)
    return batch, batch.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=session.identity.started_at
    )


def test_gui_origin_reserves_one_independent_identity_and_rolls_back() -> None:
    state = StateManager()
    _start(state)
    before = state.materialization_digest()
    batch, session = _gui(state)
    assert session.audit_origin.audit_uid == 501
    assert session.audit_origin.audit_session_id == 100_000
    assert session.identity.session_id == 0
    assert state.materialization_digest() == before
    with state.prepared_materialization_batch(batch.seal()) as prepared:
        prepared.apply_provisional()
        assert state.get_session(session.identity.logon_id).audit_origin == session.audit_origin
    assert state.materialization_digest() == before
    retry, planned = _gui(state)
    assert planned.audit_origin == session.audit_origin
    _commit(state, retry)
    assert not state._windows_session_id_counters
    assert not state._linux_logind_session_counters


def test_gui_relogin_and_ssh_share_durable_host_audit_allocator() -> None:
    state = StateManager()
    _start(state)
    batch, first = _gui(state)
    _commit(state, batch)
    state.end_session(first.identity.logon_id, _START + timedelta(seconds=5))
    batch, remote = _plan(state)
    _commit(state, batch)
    restored = StateManager()
    participant = StateManagerParticipant(state)
    checkpoint = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    StateManagerParticipant(restored).restore_checkpoint(
        checkpoint.head.payload, tuple(segment.payload for segment in checkpoint.segments)
    )
    left, next_left = _gui(state, seconds=10)
    right, next_right = _gui(restored, seconds=10)
    assert next_left.identity == next_right.identity
    assert next_left.audit_origin == next_right.audit_origin
    assert next_left._allocator_patch == next_right._allocator_patch
    assert first.audit_origin.audit_uid == next_left.audit_origin.audit_uid
    assert first.audit_origin.audit_session_id < remote.audit_origin.audit_session_id
    assert next_left.audit_origin.audit_session_id == remote.audit_origin.audit_session_id + 1
    _commit(state, left)
    _commit(restored, right)
    assert restored._macos_audit_session_counters == state._macos_audit_session_counters
    assert restored._used_logon_ids == state._used_logon_ids
    assert restored.get_session(next_right.identity.logon_id) == state.get_session(
        next_left.identity.logon_id
    )
    assert (
        restored.get_session_at(first.identity.logon_id, _START).audit_origin == first.audit_origin
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"logon_type": 3},
        {"session_kind": "service"},
        {"auth_protocol": "kerberos"},
        {"source_ip": "192.0.2.55"},
        {"source_port": 12345},
        {"transport_pid": 99},
        {"network_close_time": _START + timedelta(minutes=5)},
        {"effective_uid": 502},
        {"effective_uid": None},
        {"session_id": 1},
    ],
)
def test_nonlocal_or_mismatched_gui_facts_cannot_allocate_audit_origin(
    changes: dict[str, object],
) -> None:
    state = StateManager()
    _start(state)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="Mac SSH or local GUI"):
        _gui(state, **changes)
    assert state.materialization_digest() == before


@pytest.mark.parametrize(
    "changes",
    [
        {"username": "other"},
        {"auth_protocol": ""},
        {"session_kind": "ssh"},
        {"source_ip": "192.0.2.55"},
        {"source_port": 1},
        {"source_port": False},
        {"session_id": 7},
        {"session_id": False},
        {"effective_uid": 502},
        {"transport_pid": 10},
        {"network_close_time": _START + timedelta(minutes=5)},
    ],
)
def test_published_gui_origin_cannot_be_reassigned_by_generic_session_metadata(
    changes: dict[str, object],
) -> None:
    state = StateManager()
    _start(state)
    batch, session = _gui(state)
    _commit(state, batch)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="GUI audit owner"):
        state.update_session_metadata(session.identity.logon_id, **changes)
    assert state.materialization_digest() == before


def test_checkpoint_rejects_duplicate_gui_origin_and_wrong_authentication_owner() -> None:
    state = StateManager()
    _start(state)
    batch, first = _gui(state)
    _commit(state, batch)
    batch, second = _gui(state, seconds=10)
    _commit(state, batch)
    live = state.get_session(second.identity.logon_id)
    original = live.audit_origin
    live.audit_origin = replace(first.audit_origin, created_at=second.identity.started_at)
    with pytest.raises(CheckpointCorruptionError, match="duplicated"):
        _restore_head(StateManager(), _capture_head(state))
    live.audit_origin = original
    live.auth_protocol = "ssh"
    with pytest.raises(CheckpointCorruptionError, match="audit origin"):
        _restore_head(StateManager(), _capture_head(state))


def test_gui_readiness_cannot_be_backdated_before_authentication() -> None:
    state = StateManager()
    _start(state)
    batch, session = _gui(state)
    _commit(state, batch)
    before = state.materialization_digest()
    with pytest.raises(StateError, match="GUI readiness"):
        state.update_session_metadata(
            session.identity.logon_id, source_ready_time=_START - timedelta(seconds=1)
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize("legacy_profile", [False, True])
def test_engine_gui_origin_binds_explicit_launches_and_child_inheritance(
    tmp_path: Path, legacy_profile: bool
) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "run", generation_seed=334)
    try:
        engine._initialize()
        generator = engine.activity_generator
        provider = engine.macos_execution_metadata
        if legacy_profile:
            provider.profile = provider.profile.model_copy(update={"gui_audit_origin": None})
        system = next(s for s in engine.scenario.environment.systems if s.hostname == "MAC-01")
        user = next(u for u in engine.scenario.environment.users if u.username == "alex")
        at = engine.start_time + timedelta(minutes=10)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        session = engine.state_manager.get_session(logon)
        origin = session.audit_origin
        assert (origin is None) == legacy_profile
        assert session.session_id == 0
        pid = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(seconds=30))
        shell = engine.state_manager.get_process_identity(system.hostname, pid)
        assert shell is not None
        credentials = shell.credentials
        assert credentials.real_uid == credentials.effective_uid == 501
        if legacy_profile:
            assert credentials.audit_uid is credentials.audit_session_id is None
        else:
            assert (credentials.audit_uid, credentials.audit_session_id) == (
                origin.audit_uid,
                origin.audit_session_id,
            )
            assert origin.audit_session_id != shell.job_control.session.sid
            # A second terminal POSIX session consumes the existing GUI origin.
            terminal = engine.state_manager.plan_process_materialization(
                system=system.hostname,
                parent_pid=pid,
                image="/bin/zsh",
                command_line="-zsh",
                username=user.username,
                integrity_level="Medium",
                os_category="macos",
                start_time=at + timedelta(seconds=35),
                logon_id=logon,
                credentials=provider.gui_launch_credentials(
                    engine.state_manager,
                    system.hostname,
                    user.username,
                    logon_id=logon,
                    at=at + timedelta(seconds=35),
                    credentials=PosixProcessCredentials(501, 501, 20, 20),
                ),
                new_posix_session=True,
            )
            engine.state_manager.materialize_process(terminal)
            assert terminal.identity.credentials == credentials
            assert terminal.identity.job_control.session != shell.job_control.session
            with pytest.raises(StateError, match="foreign audit"):
                provider.gui_launch_credentials(
                    engine.state_manager,
                    system.hostname,
                    user.username,
                    logon_id=logon,
                    at=at + timedelta(seconds=35),
                    credentials=replace(credentials, audit_session_id=origin.audit_session_id + 1),
                )
        # Ordinary command identity follows its known parent rather than a session-ID guess.
        child_credentials = generator._process_credentials(
            system, user.username, pid, at + timedelta(seconds=40)
        )
        assert child_credentials == credentials
        cohort = engine.state_manager.begin_action_cohort_materialization()
        child = cohort.fork_process(shell, forked_at=at + timedelta(seconds=40))
        executed = cohort.execute_process(
            child,
            image="/usr/bin/id",
            command_line="/usr/bin/id",
            executed_at=at + timedelta(seconds=41),
        )
        engine.state_manager.materialize_action_cohort(cohort.seal())
        assert child.identity.credentials == executed.credentials == credentials
        restored = StateManager()
        _restore_head(restored, _capture_head(engine.state_manager))
        assert restored.get_session(logon).audit_origin == origin
        assert restored.get_process_identity(system.hostname, executed.pid) == executed
    finally:
        engine._close_emitters()


def test_explicit_gui_logon_id_reuses_its_origin_without_readmitting_login(tmp_path: Path) -> None:
    engine = GenerationEngine(_scenario(), tmp_path / "run", generation_seed=334)
    try:
        engine._initialize()
        generator = engine.activity_generator
        system = next(s for s in engine.scenario.environment.systems if s.hostname == "MAC-01")
        user = next(u for u in engine.scenario.environment.users if u.username == "alex")
        at = engine.start_time + timedelta(minutes=10)
        logon = generator.generate_logon(user, system, at, logon_id="0xaabbcc")
        origin = engine.state_manager.get_session(logon).audit_origin
        assert origin is not None
        assert (
            generator.generate_logon(user, system, at + timedelta(seconds=2), logon_id=logon)
            == logon
        )
        assert engine.state_manager.get_session(logon).audit_origin == origin
        assert (
            engine.state_manager._macos_audit_session_counters[system.hostname]
            == origin.audit_session_id
        )
        restored = StateManager()
        _restore_head(restored, _capture_head(engine.state_manager))
        assert restored.get_session(logon).audit_origin == origin
        generator.generate_logoff(user, system, at + timedelta(minutes=2), logon)
        next_login = generator.generate_logon(
            user, system, at + timedelta(minutes=3), allow_local_session_reuse=False
        )
        next_origin = engine.state_manager.get_session(next_login).audit_origin
        assert next_origin.audit_uid == origin.audit_uid
        assert next_origin.audit_session_id != origin.audit_session_id
        # An overridden effective UID cannot become an inferred audit user.
        unqualified = generator.generate_logon(
            user,
            system,
            at + timedelta(minutes=4),
            effective_uid=502,
            allow_local_session_reuse=False,
        )
        assert engine.state_manager.get_session(unqualified).audit_origin is None
    finally:
        engine._close_emitters()

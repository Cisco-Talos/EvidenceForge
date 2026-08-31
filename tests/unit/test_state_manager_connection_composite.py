# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Atomic StateManager connection-planning and composite-publication contracts."""

import random
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionProtocol,
)
from evidenceforge.generation.network_runtime import NetworkTransactionRuntime
from evidenceforge.generation.state_manager import (
    ConnectionExistingSessionPatch,
    ConnectionExistingSessionProcessRolesPatch,
    ConnectionMaterializationMode,
    ConnectionPlanningCursor,
    DeferredSessionStateAuthority,
    MaterializationBatchPlan,
    PhysicalTransportFingerprint,
    ProcessActivityPatch,
    ProcessMaterializationPlan,
    SessionActivityPatch,
    StateManager,
    _random_from_state,
)
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.ids import generate_zeek_uid_from_rng

_START = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)


def test_random_state_clone_does_not_seed_replaced_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact RNG cloning must not seed an instance before restoring its trusted state."""

    source = random.Random(42)
    state = source.getstate()
    expected = source.random()

    def fail_seed(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("RNG clone seeded a state that should be restored directly")

    monkeypatch.setattr(random.Random, "seed", fail_seed)

    clone = _random_from_state(state)

    assert clone.random() == expected


def _traffic(*, orig: int = 120, resp: int = 480) -> NetworkTrafficLedger:
    return NetworkTrafficLedger(
        orig=DirectionalTrafficLedger(payload_bytes=orig, packets=2, ip_bytes=orig + 80),
        resp=DirectionalTrafficLedger(payload_bytes=resp, packets=3, ip_bytes=resp + 120),
    )


def _transaction(
    *,
    conn_id: str,
    zeek_uid: str,
    stable_id: str = "network-composite",
    started_at: datetime = _START,
    duration: float = 1.25,
    traffic: NetworkTrafficLedger | None = None,
    application_layer_only: bool = False,
    src_port: int = 50_001,
    dst_port: int = 443,
    service: str = "https",
    initiating_pid: int = -1,
    responding_pid: int = -1,
    hostname: str = "example.test",
) -> NetworkTransactionPlan:
    closed_at = started_at + timedelta(seconds=duration)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname=hostname,
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=src_port,
        dst_ip="10.0.0.20",
        dst_port=dst_port,
        protocol="tcp",
        service=service,
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=duration,
        conn_state="SF",
        history="ShADadFf",
        traffic=traffic or _traffic(),
        initiating_pid=initiating_pid,
        responding_pid=responding_pid,
        application_layer_only=application_layer_only,
    )


def _physical_plan(
    manager: StateManager,
    owner: random.Random,
    *,
    early_draws: int = 0,
):
    cursor = manager.begin_connection_planning(owner)
    for _ in range(early_draws):
        cursor.rng.random()
    identity = cursor.reserve_identity()
    cursor.rng.random()
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(conn_id=identity.conn_id, zeek_uid=identity.zeek_uid),
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="example.test",
        initiating_pid=4242,
    )
    return cursor, identity, plan


@dataclass(frozen=True, slots=True)
class _ExistingSshRoleInputs:
    manager: StateManager
    owner: random.Random
    cursor: ConnectionPlanningCursor
    transaction: NetworkTransactionPlan
    session_patch: ConnectionExistingSessionPatch
    batch: MaterializationBatchPlan
    receiver: ProcessMaterializationPlan
    shell: ProcessMaterializationPlan
    source_process: ProcessMaterializationPlan | None = None
    foreign_session_process: ProcessMaterializationPlan | None = None


def _existing_ssh_role_inputs(
    *,
    extras: bool = False,
    live_shell: bool = False,
) -> _ExistingSshRoleInputs:
    manager = StateManager()
    manager.set_current_time(_START)
    target_logon_id = manager.create_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="ssh",
    )
    target_identity = manager.get_session_identity(target_logon_id)
    assert target_identity is not None
    if live_shell:
        old_shell_pid = manager.create_process(
            "TARGET-01",
            4,
            "/bin/bash",
            "-bash",
            "analyst",
            "Medium",
            logon_id=target_logon_id,
        )
        target_session = manager.get_session(target_logon_id)
        assert target_session is not None
        target_session.session_shell_pid = old_shell_pid

    source_logon_id = ""
    source_identity = None
    foreign_logon_id = ""
    foreign_identity = None
    if extras:
        source_logon_id = manager.create_session(
            username="analyst",
            system="SOURCE-01",
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        source_identity = manager.get_session_identity(source_logon_id)
        foreign_logon_id = manager.create_session(
            username="other",
            system="TARGET-01",
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        foreign_identity = manager.get_session_identity(foreign_logon_id)
        assert source_identity is not None and foreign_identity is not None

    owner = random.Random(73)
    cursor = manager.begin_connection_planning(owner)
    connection_identity = cursor.reserve_identity()
    builder = manager.begin_materialization_batch()
    source_process = None
    if source_identity is not None:
        source_process = builder.plan_process(
            system="SOURCE-01",
            parent_pid=4,
            image="/usr/bin/ssh",
            command_line="ssh analyst@TARGET-01",
            username="analyst",
            integrity_level="Medium",
            os_category="linux",
            logon_id=source_logon_id,
            start_time=_START + timedelta(milliseconds=10),
            require_session=True,
            auth_session_id=source_identity.session_id,
            auth_logon_type=2,
        )
    foreign_session_process = None
    if foreign_identity is not None:
        foreign_session_process = builder.plan_process(
            system="TARGET-01",
            parent_pid=4,
            image="/bin/sh",
            command_line="sh",
            username="other",
            integrity_level="Medium",
            os_category="linux",
            logon_id=foreign_logon_id,
            start_time=_START + timedelta(milliseconds=115),
            require_session=True,
            auth_session_id=foreign_identity.session_id,
            auth_logon_type=2,
        )
    receiver = builder.plan_process(
        system="TARGET-01",
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="sshd: analyst [priv]",
        username="root",
        integrity_level="System",
        os_category="linux",
        logon_id=target_logon_id,
        start_time=_START + timedelta(milliseconds=110),
        require_session=True,
        auth_session_id=target_identity.session_id,
        auth_logon_type=10,
    )
    shell = builder.plan_process(
        system="TARGET-01",
        parent_pid=receiver.identity.pid,
        parent_plan=receiver,
        image="/bin/bash",
        command_line="-bash",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        logon_id=target_logon_id,
        start_time=_START + timedelta(milliseconds=120),
        require_session=True,
        auth_session_id=target_identity.session_id,
        auth_logon_type=10,
    )
    batch = builder.seal()
    transaction = _transaction(
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        started_at=_START,
        duration=3,
        dst_port=22,
        service="ssh",
        responding_pid=receiver.identity.pid,
    )
    session_patch = manager.prepare_connection_existing_session_start_patch(
        target_identity,
        username="analyst",
        target_system="TARGET-01",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=100),
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        transport_pid=receiver.identity.pid,
        lifecycle_group_id="deferred-session-lifecycle",
        network_close_time=transaction.closed_at,
        session_kind="ssh",
    )
    return _ExistingSshRoleInputs(
        manager=manager,
        owner=owner,
        cursor=cursor,
        transaction=transaction,
        session_patch=session_patch,
        batch=batch,
        receiver=receiver,
        shell=shell,
        source_process=source_process,
        foreign_session_process=foreign_session_process,
    )


def _preallocated_ssh_state_authority(
    *,
    extras: bool = False,
) -> tuple[
    _ExistingSshRoleInputs,
    ConnectionExistingSessionProcessRolesPatch,
    DeferredSessionStateAuthority,
]:
    """Return one exact strict PREALLOCATED SSH State payload."""

    inputs = _existing_ssh_role_inputs(extras=extras)
    roles = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    payload = inputs.manager.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=(DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START),
        bound_at=inputs.session_patch.after.source_ready_time
        or inputs.session_patch.after.identity.started_at,
        batch=inputs.batch,
        existing_session_patch=inputs.session_patch,
        existing_session_process_roles_patch=roles,
    )
    return inputs, roles, payload


def _active_rdp_state_inputs(
    *,
    include_target_process: bool = False,
    foreign_source_session: bool = False,
) -> tuple[
    StateManager,
    MaterializationBatchPlan,
    ConnectionExistingSessionPatch,
    ProcessMaterializationPlan | None,
]:
    """Return one ACTIVE RDP process-only batch and exact live-session patch."""

    manager = StateManager()
    manager.set_current_time(_START)
    target_logon_id = manager.create_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="rdp",
    )
    source_logon_id = manager.create_session(
        username="analyst",
        system="SOURCE-01",
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )
    target_identity = manager.get_session_identity(target_logon_id)
    source_identity = manager.get_session_identity(source_logon_id)
    assert target_identity is not None and source_identity is not None
    builder = manager.begin_materialization_batch()
    source_process_logon_id = target_logon_id if foreign_source_session else source_logon_id
    source_process_session_id = (
        target_identity.session_id if foreign_source_session else source_identity.session_id
    )
    source_process_logon_type = 10 if foreign_source_session else 2
    builder.plan_process(
        system="SOURCE-01",
        parent_pid=4,
        image=r"C:\Windows\System32\mstsc.exe",
        command_line="mstsc.exe /v:TARGET-01",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=source_process_logon_id,
        start_time=_START + timedelta(milliseconds=10),
        require_session=True,
        auth_session_id=source_process_session_id,
        auth_logon_type=source_process_logon_type,
    )
    target_plan = None
    if include_target_process:
        target_plan = builder.plan_process(
            system="TARGET-01",
            parent_pid=4,
            image=r"C:\Windows\System32\userinit.exe",
            command_line="userinit.exe",
            username="analyst",
            integrity_level="Medium",
            os_category="windows",
            logon_id=target_logon_id,
            start_time=_START + timedelta(milliseconds=110),
            require_session=True,
            auth_session_id=target_identity.session_id,
            auth_logon_type=10,
        )
    batch = builder.seal()
    patch = manager.prepare_connection_live_session_patch(
        target_identity,
        source_ip="10.0.0.10",
        source_port=50_001,
        transport_pid=batch.processes[0].identity.pid,
        source_ready_time=_START + timedelta(milliseconds=100),
        network_close_time=_START + timedelta(seconds=3),
    )
    return manager, batch, patch, target_plan


def test_connection_cursor_preserves_uid_draw_point_and_owner_rng_parity() -> None:
    manager = StateManager()
    owner = random.Random(42)
    reference = random.Random(42)
    owner_entry = owner.getstate()
    digest = manager.materialization_digest()

    cursor = manager.begin_connection_planning(owner)
    assert cursor.rng.random() == reference.random()
    assert cursor.rng.randint(1, 100) == reference.randint(1, 100)
    identity = cursor.reserve_identity()
    assert identity.zeek_uid == generate_zeek_uid_from_rng(reference, "C")
    assert cursor.rng.uniform(0.0, 1.0) == reference.uniform(0.0, 1.0)
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(conn_id=identity.conn_id, zeek_uid=identity.zeek_uid),
    )

    assert owner.getstate() == owner_entry
    assert manager.materialization_digest() == digest
    result = manager.materialize_connection_composite(plan, owner)
    assert result.connection is not None
    assert plan.mode is ConnectionMaterializationMode.PHYSICAL
    assert plan.physical_transport_id == plan.transaction.stable_id
    assert plan.physical_transport_fingerprint == PhysicalTransportFingerprint(
        transport_id=plan.transaction.stable_id,
        conn_id=plan.transaction.conn_id,
        zeek_uid=plan.transaction.zeek_uid,
        tuple_key=(
            plan.transaction.src_ip,
            plan.transaction.src_port,
            plan.transaction.dst_ip,
            plan.transaction.dst_port,
            plan.transaction.protocol,
        ),
        started_at=plan.transaction.started_at,
        closed_at=plan.transaction.closed_at,
    )
    assert owner.getstate() == reference.getstate()
    assert owner.random() == reference.random()

    fresh_owner = random.Random(7)
    fresh_reference = random.Random(7)
    fresh_cursor = StateManager().begin_connection_planning(fresh_owner)
    fresh_identity = fresh_cursor.reserve_identity()
    assert fresh_identity.zeek_uid == generate_zeek_uid_from_rng(fresh_reference, "C")


def test_connection_cursor_cancel_retry_one_shot_and_owner_binding() -> None:
    manager = StateManager()
    owner = random.Random(9)
    owner_entry = owner.getstate()
    digest = manager.materialization_digest()
    cursor, identity, plan = _physical_plan(manager, owner, early_draws=1)

    with manager.prepared_connection_composite_materialization(plan, owner):
        pass
    assert manager.materialization_digest() == digest
    assert owner.getstate() == owner_entry

    same_state_other_owner = random.Random()
    same_state_other_owner.setstate(owner_entry)
    with pytest.raises(StateError, match="another RNG owner"):
        manager.validate_connection_composite_materialization(plan, same_state_other_owner)
    assert manager.materialization_digest() == digest

    with pytest.raises(StateError, match="already sealed"):
        cursor.rng.random()
    with pytest.raises(StateError, match="already sealed"):
        cursor.reserve_identity()

    duplicate_cursor = manager.begin_connection_planning(owner)
    duplicate_cursor.reserve_identity()
    with pytest.raises(StateError, match="already reserved"):
        duplicate_cursor.reserve_identity()
    duplicate_cursor.cancel()

    retry_cursor, retry_identity, retry_plan = _physical_plan(manager, owner, early_draws=1)
    assert retry_identity == identity
    assert retry_plan.publication_token == plan.publication_token
    with manager.prepared_connection_composite_materialization(retry_plan, owner) as prepared:
        prepared.commit()
        committed_digest = manager.materialization_digest()
        with pytest.raises(StateError, match="already committed"):
            prepared.commit()
        assert manager.materialization_digest() == committed_digest

    cancelled_owner = random.Random(17)
    cancelled = StateManager().begin_connection_planning(cancelled_owner)
    proxy = cancelled.rng
    cancelled.cancel()
    for operation in (lambda: proxy.random(), cancelled.reserve_identity, cancelled.cancel):
        with pytest.raises(StateError, match="cancelled"):
            operation()


def test_connection_cursor_draws_do_not_walk_full_random_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trusted cursor draws and cancellation avoid recursive RNG-state validation."""

    manager = StateManager()
    owner = random.Random(7_301)

    def reject_recursive_validation(_value: object) -> None:
        raise AssertionError("connection cursor recursively validated its RNG state")

    monkeypatch.setattr(manager, "_validate_smb_random_state_safe", reject_recursive_validation)
    cursor = manager.begin_connection_planning(owner)
    for _ in range(100):
        cursor.rng.random()
    cursor.cancel()


def test_connection_cursor_and_composite_reject_foreign_manager_tamper_and_staleness() -> None:
    manager = StateManager()
    foreign = StateManager()
    owner = random.Random(11)
    cursor = manager.begin_connection_planning(owner)
    owner_entry = owner.getstate()
    manager_digest = manager.materialization_digest()
    foreign_digest = foreign.materialization_digest()

    with pytest.raises(StateError, match="another StateManager"):
        foreign.finalize_connection_composite_materialization(
            cursor,
            _transaction(conn_id="conn-0", zeek_uid="Cforeign"),
        )
    identity = cursor.reserve_identity()
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(conn_id=identity.conn_id, zeek_uid=identity.zeek_uid),
    )
    with pytest.raises(StateError, match="another StateManager"):
        foreign.materialize_connection_composite(plan, owner)
    assert manager.materialization_digest() == manager_digest
    assert foreign.materialization_digest() == foreign_digest
    assert owner.getstate() == owner_entry


def test_connection_composite_owner_drift_rejects_then_retries_exactly() -> None:
    manager = StateManager()
    owner = random.Random(23)
    owner_entry = owner.getstate()
    _cursor, identity, plan = _physical_plan(manager, owner, early_draws=2)
    digest = manager.materialization_digest()

    tampered = replace(plan, _final_state_time=plan.final_state_time + timedelta(seconds=1))
    with pytest.raises(StateError, match="final State frontier changed"):
        manager.materialize_connection_composite(tampered, owner)
    assert manager.materialization_digest() == digest

    owner.random()
    with pytest.raises(StateError, match="RNG owner changed"):
        manager.materialize_connection_composite(plan, owner)
    assert manager.materialization_digest() == digest

    owner.setstate(owner_entry)
    result = manager.materialize_connection_composite(plan, owner)
    assert result.connection is not None
    assert result.connection.conn_id == identity.conn_id
    assert result.connection.zeek_uid == identity.zeek_uid
    committed_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale before commit"):
        manager.materialize_connection_composite(plan, owner)
    assert manager.materialization_digest() == committed_digest


def test_connection_composite_commits_connection_and_batch_in_one_version() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    owner = random.Random(31)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    builder = manager.begin_materialization_batch()
    session_plan = builder.plan_session(
        username="analyst",
        system="LNX-01",
        logon_type=10,
        source_ip="10.0.0.10",
        start_time=_START + timedelta(milliseconds=100),
        session_kind="ssh",
    )
    responder = builder.plan_process(
        system="LNX-01",
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="sshd: analyst [priv]",
        username="root",
        integrity_level="System",
        os_category="linux",
        start_time=_START + timedelta(milliseconds=110),
    )
    shell = builder.plan_process(
        system="LNX-01",
        parent_pid=responder.identity.pid,
        parent_plan=responder,
        image="/bin/bash",
        command_line="-bash",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        logon_id=session_plan.identity.logon_id,
        start_time=_START + timedelta(milliseconds=120),
        require_session=True,
        session_plan=session_plan,
        auth_session_id=session_plan.identity.session_id,
        auth_logon_type=10,
    )
    builder.bind_session_processes(
        session_plan,
        transport_plan=responder,
        shell_plan=shell,
        process_tree_root_plan=responder,
    )
    batch = builder.seal()
    prior_version = manager.materialization_version
    activity_time = _START + timedelta(seconds=2)
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(conn_id=identity.conn_id, zeek_uid=identity.zeek_uid),
        batch=batch,
        process_activity=(ProcessActivityPatch(shell.identity, activity_time),),
        session_activity=(SessionActivityPatch(session_plan.identity, activity_time),),
    )

    result = manager.materialize_connection_composite(plan, owner)
    assert manager.materialization_version == prior_version + 1
    assert result.connection is not None
    assert result.session is not None
    assert result.session.transport_pid == responder.identity.pid
    assert result.session.session_shell_pid == shell.identity.pid
    assert result.session.process_tree_root == responder.identity.pid
    assert tuple(process.ecar_object_id for process in result.processes) == (
        responder.identity.object_id,
        shell.identity.object_id,
    )
    assert manager.get_process("LNX-01", shell.identity.pid).last_activity_time == activity_time
    assert manager.get_session(session_plan.identity.logon_id).last_activity_time == activity_time
    assert manager.state.current_time == plan.final_state_time


def test_connection_composite_commits_preallocated_ssh_roles_once() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    logon_id = manager.create_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="ssh",
    )
    session_identity = manager.get_session_identity(logon_id)
    assert session_identity is not None
    owner = random.Random(37)
    cursor = manager.begin_connection_planning(owner)
    connection_identity = cursor.reserve_identity()
    builder = manager.begin_materialization_batch()
    receiver = builder.plan_process(
        system="TARGET-01",
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="sshd: analyst [priv]",
        username="root",
        integrity_level="System",
        os_category="linux",
        logon_id=logon_id,
        start_time=_START + timedelta(milliseconds=110),
        require_session=True,
        auth_session_id=session_identity.session_id,
        auth_logon_type=10,
        parent_lifecycle_group_id="deferred-session-lifecycle",
    )
    shell = builder.plan_process(
        system="TARGET-01",
        parent_pid=receiver.identity.pid,
        parent_plan=receiver,
        image="/bin/bash",
        command_line="-bash",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        logon_id=logon_id,
        start_time=_START + timedelta(milliseconds=120),
        require_session=True,
        auth_session_id=session_identity.session_id,
        auth_logon_type=10,
        parent_lifecycle_group_id="deferred-session-lifecycle",
    )
    batch = builder.seal()
    transaction = _transaction(
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        started_at=_START,
        duration=3,
        dst_port=22,
        service="ssh",
        responding_pid=receiver.identity.pid,
    )
    patch = manager.prepare_connection_existing_session_start_patch(
        session_identity,
        username="analyst",
        target_system="TARGET-01",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=100),
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        transport_pid=receiver.identity.pid,
        lifecycle_group_id="deferred-session-lifecycle",
        network_close_time=transaction.closed_at,
        session_kind="ssh",
    )
    roles_patch = manager.prepare_connection_existing_session_process_roles_patch(
        patch,
        batch,
        transport_plan=receiver,
        shell_plan=shell,
        process_tree_root_plan=receiver,
    )
    activity_time = transaction.closed_at
    assert activity_time is not None
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        initiating_pid=transaction.initiating_pid,
        batch=batch,
        rdp_existing_session_patch=patch,
        existing_session_process_roles_patch=roles_patch,
        process_activity=(
            ProcessActivityPatch(receiver.identity, activity_time),
            ProcessActivityPatch(shell.identity, activity_time),
        ),
        session_activity=(SessionActivityPatch(patch.after.identity, activity_time),),
    )
    prior_version = manager.materialization_version

    result = manager.materialize_connection_composite(plan, owner)

    assert manager.materialization_version == prior_version + 1
    assert result.session is manager.get_session(logon_id)
    assert result.session is not None
    assert result.session.lifecycle_group_id == "deferred-session-lifecycle"
    assert result.session.transport_pid == receiver.identity.pid
    assert result.session.session_shell_pid == shell.identity.pid
    assert result.session.process_tree_root == receiver.identity.pid
    assert tuple(item.ecar_object_id for item in result.processes) == (
        receiver.identity.object_id,
        shell.identity.object_id,
    )
    assert manager.get_process("TARGET-01", receiver.identity.pid) is result.processes[0]
    assert manager.get_process("TARGET-01", shell.identity.pid) is result.processes[1]
    assert all(process.last_activity_time == activity_time for process in result.processes)
    assert result.session.last_activity_time == activity_time


def test_connection_composite_keeps_rdp_source_outside_target_role_patch() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    source_logon_id = manager.create_session(
        username="analyst",
        system="SOURCE-01",
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )
    source_session_identity = manager.get_session_identity(source_logon_id)
    assert source_session_identity is not None
    target_logon_id = manager.create_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="rdp",
    )
    target_session_identity = manager.get_session_identity(target_logon_id)
    assert target_session_identity is not None
    owner = random.Random(38)
    cursor = manager.begin_connection_planning(owner)
    connection_identity = cursor.reserve_identity()
    builder = manager.begin_materialization_batch()
    source_client = builder.plan_process(
        system="SOURCE-01",
        parent_pid=4,
        image=r"C:\Windows\System32\mstsc.exe",
        command_line="mstsc.exe /v:TARGET-01",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=source_logon_id,
        start_time=_START + timedelta(milliseconds=10),
        require_session=True,
        auth_session_id=source_session_identity.session_id,
        auth_logon_type=2,
    )
    winlogon = builder.plan_process(
        system="TARGET-01",
        parent_pid=4,
        image=r"C:\Windows\System32\winlogon.exe",
        command_line="winlogon.exe",
        username="SYSTEM",
        integrity_level="System",
        os_category="windows",
        logon_id="0x3e7",
        start_time=_START + timedelta(milliseconds=105),
    )
    userinit = builder.plan_process(
        system="TARGET-01",
        parent_pid=winlogon.identity.pid,
        parent_plan=winlogon,
        image=r"C:\Windows\System32\userinit.exe",
        command_line="userinit.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=target_logon_id,
        start_time=_START + timedelta(milliseconds=110),
        require_session=True,
        auth_session_id=target_session_identity.session_id,
        auth_logon_type=10,
    )
    explorer = builder.plan_process(
        system="TARGET-01",
        parent_pid=userinit.identity.pid,
        parent_plan=userinit,
        image=r"C:\Windows\explorer.exe",
        command_line="explorer.exe",
        username="analyst",
        integrity_level="Medium",
        os_category="windows",
        logon_id=target_logon_id,
        start_time=_START + timedelta(milliseconds=120),
        require_session=True,
        auth_session_id=target_session_identity.session_id,
        auth_logon_type=10,
    )
    batch = builder.seal()
    transaction = _transaction(
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        started_at=_START,
        duration=3,
        dst_port=3389,
        service="rdp",
        initiating_pid=source_client.identity.pid,
    )
    session_patch = manager.prepare_connection_existing_session_start_patch(
        target_session_identity,
        username="analyst",
        target_system="TARGET-01",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=100),
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        transport_pid=source_client.identity.pid,
        lifecycle_group_id="deferred-rdp-lifecycle",
        network_close_time=transaction.closed_at,
        session_kind="rdp",
    )
    roles_patch = manager.prepare_connection_existing_session_process_roles_patch(
        session_patch,
        batch,
        user_manager_plan=userinit,
        winlogon_plan=winlogon,
        explorer_plan=explorer,
        process_tree_root_plan=winlogon,
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="SOURCE-01",
        initiating_pid=source_client.identity.pid,
        batch=batch,
        rdp_existing_session_patch=session_patch,
        existing_session_process_roles_patch=roles_patch,
    )

    result = manager.materialize_connection_composite(plan, owner)

    assert result.session is manager.get_session(target_logon_id)
    assert result.session is not None
    assert result.session.transport_pid == source_client.identity.pid
    assert result.session.session_winlogon_pid == winlogon.identity.pid
    assert result.session.session_user_manager_pid == userinit.identity.pid
    assert result.session.explorer_pid == explorer.identity.pid
    assert result.session.initial_explorer_pid == explorer.identity.pid
    assert result.session.process_tree_root == winlogon.identity.pid
    assert result.session.windows_shell_bootstrapped
    assert manager.get_process("SOURCE-01", source_client.identity.pid) is result.processes[0]
    assert tuple(process.system for process in result.processes) == (
        "SOURCE-01",
        "TARGET-01",
        "TARGET-01",
        "TARGET-01",
    )


def test_existing_session_role_patch_rejects_foreign_unstaged_and_live_overwrite() -> None:
    inputs = _existing_ssh_role_inputs(extras=True)
    assert inputs.source_process is not None
    assert inputs.foreign_session_process is not None

    with pytest.raises(StateError, match="another host"):
        inputs.manager.prepare_connection_existing_session_process_roles_patch(
            inputs.session_patch,
            inputs.batch,
            transport_plan=inputs.source_process,
        )
    with pytest.raises(StateError, match="another session"):
        inputs.manager.prepare_connection_existing_session_process_roles_patch(
            inputs.session_patch,
            inputs.batch,
            shell_plan=inputs.foreign_session_process,
        )
    with pytest.raises(StateError, match="exact batch member"):
        inputs.manager.prepare_connection_existing_session_process_roles_patch(
            inputs.session_patch,
            inputs.batch,
            shell_plan=replace(inputs.shell),
        )

    live = _existing_ssh_role_inputs(live_shell=True)
    with pytest.raises(StateError, match="cannot overwrite a live process"):
        live.manager.prepare_connection_existing_session_process_roles_patch(
            live.session_patch,
            live.batch,
            transport_plan=live.receiver,
            shell_plan=live.shell,
            process_tree_root_plan=live.receiver,
        )


def test_existing_session_role_composite_cancel_and_replay_are_exact() -> None:
    inputs = _existing_ssh_role_inputs()
    roles_patch = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    plan = inputs.manager.finalize_connection_composite_materialization(
        inputs.cursor,
        inputs.transaction,
        batch=inputs.batch,
        rdp_existing_session_patch=inputs.session_patch,
        existing_session_process_roles_patch=roles_patch,
    )
    digest = inputs.manager.materialization_digest()
    owner_state = inputs.owner.getstate()

    with inputs.manager.prepared_connection_composite_materialization(plan, inputs.owner):
        pass

    assert inputs.manager.materialization_digest() == digest
    assert inputs.owner.getstate() == owner_state
    assert inputs.manager.list_open_connections() == []
    assert inputs.manager.get_process("TARGET-01", inputs.receiver.identity.pid) is None
    with pytest.raises(StateError, match="admission fence"):
        inputs.manager.materialize_connection_composite(plan, inputs.owner)

    retry = _existing_ssh_role_inputs()
    retry_roles = retry.manager.prepare_connection_existing_session_process_roles_patch(
        retry.session_patch,
        retry.batch,
        transport_plan=retry.receiver,
        shell_plan=retry.shell,
        process_tree_root_plan=retry.receiver,
    )
    retry_plan = retry.manager.finalize_connection_composite_materialization(
        retry.cursor,
        retry.transaction,
        batch=retry.batch,
        rdp_existing_session_patch=retry.session_patch,
        existing_session_process_roles_patch=retry_roles,
    )
    retry.manager.materialize_connection_composite(retry_plan, retry.owner)
    committed_digest = retry.manager.materialization_digest()
    with pytest.raises(StateError, match="stale before commit"):
        retry.manager.materialize_connection_composite(retry_plan, retry.owner)
    assert retry.manager.materialization_digest() == committed_digest


def test_boot_batch_claim_rejects_concurrent_validation_and_remains_neutral() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_materialization_batch()
    builder.plan_boot_time("BOOT-01", _START - timedelta(hours=2))
    plan = builder.seal()
    copied_plan = replace(plan)
    digest = manager.materialization_digest()
    version = manager.materialization_version

    assert manager.authenticates_materialization_plan(copied_plan)
    with manager.prepared_materialization_batch(plan):
        manager.validate_materialization_batch(plan)
        with pytest.raises(StateError, match="admission fence"):
            manager.validate_materialization_batch(copied_plan)

    assert manager.materialization_digest() == digest
    assert manager.materialization_version == version
    assert manager.get_boot_time("BOOT-01") is None
    with pytest.raises(StateError, match="admission fence"):
        manager.validate_materialization_batch(plan)


def test_connection_composite_claim_matches_only_its_exact_nested_batch() -> None:
    inputs = _existing_ssh_role_inputs()
    roles_patch = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    plan = inputs.manager.finalize_connection_composite_materialization(
        inputs.cursor,
        inputs.transaction,
        batch=inputs.batch,
        rdp_existing_session_patch=inputs.session_patch,
        existing_session_process_roles_patch=roles_patch,
    )
    copied_batch = replace(inputs.batch)
    digest = inputs.manager.materialization_digest()
    version = inputs.manager.materialization_version

    assert inputs.manager.authenticates_materialization_plan(copied_batch)
    with inputs.manager.prepared_connection_composite_materialization(plan, inputs.owner):
        inputs.manager.validate_materialization_batch(inputs.batch)
        with pytest.raises(StateError, match="admission fence"):
            inputs.manager.validate_materialization_batch(copied_batch)

    assert inputs.manager.materialization_digest() == digest
    assert inputs.manager.materialization_version == version
    with pytest.raises(StateError, match="admission fence"):
        inputs.manager.validate_materialization_batch(inputs.batch)


def test_existing_session_process_batch_rejects_second_session_and_epoch_aba() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    logon_id = manager.create_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="ssh",
    )
    session_identity = manager.get_session_identity(logon_id)
    assert session_identity is not None
    owner = random.Random(39)
    cursor = manager.begin_connection_planning(owner)
    connection_identity = cursor.reserve_identity()
    builder = manager.begin_materialization_batch()
    builder.plan_session(
        username="second",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.11",
        start_time=_START + timedelta(milliseconds=100),
        session_kind="ssh",
    )
    second_session_batch = builder.seal()
    transaction = _transaction(
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        dst_port=22,
        service="ssh",
    )
    patch = manager.prepare_connection_existing_session_start_patch(
        session_identity,
        username="analyst",
        target_system="TARGET-01",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=100),
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        transport_pid=None,
        lifecycle_group_id="deferred-session-lifecycle",
        network_close_time=transaction.closed_at,
        session_kind="ssh",
    )

    with pytest.raises(StateError, match="new State session"):
        manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            batch=second_session_batch,
            rdp_existing_session_patch=patch,
        )

    process_builder = manager.begin_materialization_batch()
    process_builder.plan_process(
        system="TARGET-01",
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="sshd: analyst [priv]",
        username="root",
        integrity_level="System",
        os_category="linux",
        logon_id=logon_id,
        start_time=_START + timedelta(milliseconds=110),
        require_session=True,
        auth_session_id=session_identity.session_id,
        auth_logon_type=10,
    )
    stale_batch = process_builder.seal()
    other_owner = random.Random(41)
    _cursor, _identity, other = _physical_plan(manager, other_owner)
    with manager.prepared_connection_composite_materialization(other, other_owner):
        pass
    assert stale_batch.expected_version == manager.materialization_version

    retry_cursor = manager.begin_connection_planning(owner)
    retry_identity = retry_cursor.reserve_identity()
    retry_transaction = _transaction(
        conn_id=retry_identity.conn_id,
        zeek_uid=retry_identity.zeek_uid,
        dst_port=22,
        service="ssh",
    )
    retry_patch = manager.prepare_connection_existing_session_start_patch(
        session_identity,
        username="analyst",
        target_system="TARGET-01",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=100),
        source_ip=retry_transaction.src_ip,
        source_port=retry_transaction.src_port,
        transport_pid=None,
        lifecycle_group_id="deferred-session-lifecycle",
        network_close_time=retry_transaction.closed_at,
        session_kind="ssh",
    )
    with pytest.raises(StateError, match="admission fence"):
        manager.finalize_connection_composite_materialization(
            retry_cursor,
            retry_transaction,
            batch=stale_batch,
            rdp_existing_session_patch=retry_patch,
        )


def test_strict_preallocated_state_authority_is_exact_and_allocation_neutral() -> None:
    inputs = _existing_ssh_role_inputs()
    roles = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    digest = inputs.manager.materialization_digest()
    payload = inputs.manager.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=(DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START),
        bound_at=inputs.session_patch.after.source_ready_time
        or inputs.session_patch.after.identity.started_at,
        batch=inputs.batch,
        existing_session_patch=inputs.session_patch,
        existing_session_process_roles_patch=roles,
    )

    assert inputs.manager.materialization_digest() == digest
    assert inputs.manager.authenticates_deferred_session_state_authority(payload)
    assert not inputs.manager.authenticates_deferred_session_state_authority(replace(payload))
    assert not StateManager().authenticates_deferred_session_state_authority(payload)
    assert not payload.outer_bound


def test_network_runtime_seals_exact_strict_batch_patch_and_roles() -> None:
    inputs, roles, payload = _preallocated_ssh_state_authority()
    runtime = NetworkTransactionRuntime(
        state_manager=inputs.manager,
        cryptographic_material=CryptographicMaterialRegistry(),
        window_start=_START,
        window_end=_START + timedelta(days=1),
    )
    owner = random.Random(101)
    preparation = runtime.begin(
        owner_rng=owner,
        stable_id="strict-ssh-transport",
        linearization_time=_START,
    )
    identity = preparation.reserve_physical_identity()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        stable_id="strict-ssh-transport",
        dst_port=22,
        service="ssh",
        responding_pid=inputs.receiver.identity.pid,
        duration=3,
    )
    digest = inputs.manager.materialization_digest()

    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode="deferred_session",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        batch=payload.batch,
        rdp_existing_session_patch=payload.existing_session_patch,
        existing_session_process_roles_patch=(payload.existing_session_process_roles_patch),
    )

    assert root.state_plan.batch is payload.batch
    assert root.state_plan.existing_session_patch is payload.existing_session_patch
    assert root.state_plan.existing_session_process_roles_patch is roles
    assert inputs.manager.materialization_digest() == digest


def test_strict_new_ssh_state_authority_requires_session_process_role_order() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    builder = manager.begin_materialization_batch()
    session = builder.plan_session(
        username="analyst",
        system="TARGET-01",
        logon_type=10,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="ssh",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=_START + timedelta(milliseconds=120),
        network_close_time=_START + timedelta(seconds=3),
    )
    receiver = builder.plan_process(
        system="TARGET-01",
        parent_pid=0,
        image="/usr/sbin/sshd",
        command_line="sshd: analyst [priv]",
        username="root",
        integrity_level="System",
        os_category="linux",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(milliseconds=110),
        require_session=True,
        session_plan=session,
        auth_session_id=session.identity.session_id,
        auth_logon_type=10,
    )
    builder.bind_session_processes(
        session,
        transport_plan=receiver,
        process_tree_root_plan=receiver,
    )
    batch = builder.seal()
    digest = manager.materialization_digest()

    payload = manager.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        bound_at=_START + timedelta(milliseconds=120),
        batch=batch,
    )

    assert manager.materialization_digest() == digest
    assert payload.batch.session is session
    assert payload.batch.processes == (receiver,)
    assert manager.authenticates_deferred_session_state_authority(payload)


@pytest.mark.parametrize(
    ("disposition", "roles", "message"),
    (
        (
            DeferredSessionBindingDisposition.NEW_SESSION,
            True,
            "NEW deferred session authority",
        ),
        (
            DeferredSessionBindingDisposition.ACTIVE_SESSION,
            True,
            "binding disposition disagrees",
        ),
        (
            DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START,
            False,
            "require an exact session role patch",
        ),
    ),
)
def test_strict_existing_state_authority_rejects_wrong_shape_neutrally(
    disposition: DeferredSessionBindingDisposition,
    roles: bool,
    message: str,
) -> None:
    inputs = _existing_ssh_role_inputs()
    role_patch = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    digest = inputs.manager.materialization_digest()

    with pytest.raises(StateError, match=message):
        inputs.manager.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.SSH,
            binding_disposition=disposition,
            bound_at=inputs.session_patch.after.source_ready_time
            or inputs.session_patch.after.identity.started_at,
            batch=inputs.batch,
            existing_session_patch=inputs.session_patch,
            existing_session_process_roles_patch=role_patch if roles else None,
        )

    assert inputs.manager.materialization_digest() == digest


def test_strict_state_authority_rejects_disguised_same_host_member_neutrally() -> None:
    inputs = _existing_ssh_role_inputs(extras=True)
    roles = inputs.manager.prepare_connection_existing_session_process_roles_patch(
        inputs.session_patch,
        inputs.batch,
        transport_plan=inputs.receiver,
        shell_plan=inputs.shell,
        process_tree_root_plan=inputs.receiver,
    )
    digest = inputs.manager.materialization_digest()

    with pytest.raises(StateError, match="disagree exactly"):
        inputs.manager.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.SSH,
            binding_disposition=(DeferredSessionBindingDisposition.PREALLOCATED_SESSION_START),
            bound_at=inputs.session_patch.after.source_ready_time
            or inputs.session_patch.after.identity.started_at,
            batch=inputs.batch,
            existing_session_patch=inputs.session_patch,
            existing_session_process_roles_patch=roles,
        )

    assert inputs.manager.materialization_digest() == digest


def test_strict_state_authority_rejects_admission_epoch_aba() -> None:
    inputs, _roles, payload = _preallocated_ssh_state_authority()
    other_owner = random.Random(97)
    _cursor, _identity, other_plan = _physical_plan(inputs.manager, other_owner)
    digest = inputs.manager.materialization_digest()

    with inputs.manager.prepared_connection_composite_materialization(
        other_plan,
        other_owner,
    ):
        pass

    assert inputs.manager.materialization_digest() == digest
    assert payload.batch.expected_version == inputs.manager.materialization_version
    assert not inputs.manager.authenticates_deferred_session_state_authority(payload)


def test_strict_active_rdp_source_only_authority_excludes_target_roles() -> None:
    manager, batch, patch, target_plan = _active_rdp_state_inputs()
    assert target_plan is None
    digest = manager.materialization_digest()

    payload = manager.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.RDP,
        binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
        bound_at=patch.after.source_ready_time or patch.after.identity.started_at,
        batch=batch,
        existing_session_patch=patch,
    )

    assert manager.materialization_digest() == digest
    assert payload.existing_session_process_roles_patch is None
    assert manager.authenticates_deferred_session_state_authority(payload)


def test_strict_active_rdp_rejects_mixed_source_and_target_members_neutrally() -> None:
    manager, batch, patch, target_plan = _active_rdp_state_inputs(include_target_process=True)
    assert target_plan is not None
    roles = manager.prepare_connection_existing_session_process_roles_patch(
        patch,
        batch,
        user_manager_plan=target_plan,
    )
    digest = manager.materialization_digest()

    with pytest.raises(StateError, match="cannot start target-session processes"):
        manager.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.RDP,
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            bound_at=patch.after.source_ready_time or patch.after.identity.started_at,
            batch=batch,
            existing_session_patch=patch,
            existing_session_process_roles_patch=roles,
        )

    assert manager.materialization_digest() == digest


def test_strict_active_rdp_rejects_foreign_source_session_neutrally() -> None:
    manager, batch, patch, _target_plan = _active_rdp_state_inputs(foreign_source_session=True)
    digest = manager.materialization_digest()

    with pytest.raises(StateError, match="target LogonID across hosts"):
        manager.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.RDP,
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            bound_at=patch.after.source_ready_time or patch.after.identity.started_at,
            batch=batch,
            existing_session_patch=patch,
        )

    assert manager.materialization_digest() == digest


def test_application_child_accounts_parent_once_without_identity_or_counter_advance() -> None:
    manager = StateManager()
    physical_owner = random.Random(41)
    _cursor, identity, physical_plan = _physical_plan(manager, physical_owner)
    physical = manager.materialize_connection_composite(physical_plan, physical_owner).connection
    assert physical is not None
    physical_snapshot = replace(physical)
    counter_before = manager._connection_id_counter
    child_owner = random.Random(43)
    child_reference = random.Random(43)
    child_cursor = manager.begin_connection_planning(child_owner)
    assert child_cursor.rng.random() == child_reference.random()
    child_traffic = _traffic(orig=30, resp=70)
    child = _transaction(
        conn_id=physical.conn_id,
        zeek_uid=physical.zeek_uid,
        stable_id="http-child",
        started_at=_START + timedelta(milliseconds=100),
        duration=0.5,
        traffic=child_traffic,
        application_layer_only=True,
    )
    plan = manager.finalize_connection_composite_materialization(
        child_cursor,
        child,
        mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    digest = manager.materialization_digest()
    rng_entry = child_owner.getstate()
    with manager.prepared_connection_composite_materialization(plan, child_owner):
        pass
    assert manager.materialization_digest() == digest
    assert child_owner.getstate() == rng_entry

    physical.bytes_sent += 1
    with pytest.raises(StateError, match="parent changed after planning"):
        manager.materialize_connection_composite(plan, child_owner)
    physical.bytes_sent -= 1
    assert manager.materialization_digest() == digest
    assert child_owner.getstate() == rng_entry

    result = manager.materialize_connection_composite(plan, child_owner)
    assert result.connection is physical
    assert plan.mode is ConnectionMaterializationMode.APPLICATION_CHILD
    assert plan.physical_transport_id == physical.transaction_id
    assert plan.physical_transport_id != plan.transaction.stable_id
    fingerprint = plan.physical_transport_fingerprint
    assert fingerprint.conn_id == physical.conn_id
    assert fingerprint.zeek_uid == physical.zeek_uid
    assert fingerprint.tuple_key == (
        physical.src_ip,
        physical.src_port,
        physical.dst_ip,
        physical.dst_port,
        physical.protocol,
    )
    assert fingerprint.started_at == physical.start_time
    assert fingerprint.closed_at == physical.close_time
    assert len(manager.state.open_connections) == 1
    assert manager._connection_id_counter == counter_before
    assert physical.zeek_uid == physical_snapshot.zeek_uid
    assert physical.transaction_id == physical_snapshot.transaction_id
    assert physical.start_time == physical_snapshot.start_time
    assert physical.close_time == physical_snapshot.close_time
    assert physical.duration == physical_snapshot.duration
    assert physical.traffic_ledger == physical_snapshot.traffic_ledger.accumulate(child_traffic)
    assert child_owner.getstate() == child_reference.getstate()
    committed_digest = manager.materialization_digest()
    with pytest.raises(StateError, match="stale before commit"):
        manager.materialize_connection_composite(plan, child_owner)
    assert manager.materialization_digest() == committed_digest


def test_application_child_rejects_reserved_identity_and_out_of_parent_interval() -> None:
    manager = StateManager()
    owner = random.Random(47)
    _cursor, _identity, physical_plan = _physical_plan(manager, owner)
    physical = manager.materialize_connection_composite(physical_plan, owner).connection
    assert physical is not None
    digest = manager.materialization_digest()

    child_owner = random.Random(49)
    reserved = manager.begin_connection_planning(child_owner)
    reserved.reserve_identity()
    valid_child = _transaction(
        conn_id=physical.conn_id,
        zeek_uid=physical.zeek_uid,
        started_at=_START + timedelta(milliseconds=100),
        duration=0.5,
        application_layer_only=True,
    )
    with pytest.raises(StateError, match="cannot reserve a new identity"):
        manager.finalize_connection_composite_materialization(
            reserved,
            valid_child,
            mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )
    reserved.cancel()

    outside = manager.begin_connection_planning(child_owner)
    out_of_range = _transaction(
        conn_id=physical.conn_id,
        zeek_uid=physical.zeek_uid,
        started_at=_START - timedelta(milliseconds=1),
        duration=0.5,
        application_layer_only=True,
    )
    with pytest.raises(StateError, match="outside its parent interval"):
        manager.finalize_connection_composite_materialization(
            outside,
            out_of_range,
            mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )
    outside.cancel()

    ambiguous = manager.begin_connection_planning(child_owner)
    with pytest.raises(StateError, match="explicit typed mode"):
        manager.finalize_connection_composite_materialization(
            ambiguous,
            valid_child,
            mode=False,  # type: ignore[arg-type]
        )
    ambiguous.cancel()
    assert manager.materialization_digest() == digest


def test_connection_composite_normalizes_activity_patches_and_frontier() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    logon_id = manager.create_session(
        username="analyst",
        system="WS-01",
        logon_type=2,
        source_ip="-",
    )
    process = manager.create_process(
        "WS-01",
        4,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        "analyst",
        "Medium",
        logon_id=logon_id,
    )
    process_identity = manager.get_process_identity("WS-01", process)
    session_identity = manager.get_session_identity(logon_id)
    assert process_identity is not None
    assert session_identity is not None
    owner = random.Random(51)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    later = _START + timedelta(seconds=8)
    process_patches = (
        ProcessActivityPatch(process_identity, _START + timedelta(seconds=2)),
        ProcessActivityPatch(process_identity, later),
    )
    session_patches = (
        SessionActivityPatch(session_identity, _START + timedelta(seconds=3)),
        SessionActivityPatch(session_identity, _START + timedelta(seconds=7)),
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(conn_id=identity.conn_id, zeek_uid=identity.zeek_uid),
        process_activity=process_patches,
        session_activity=session_patches,
    )

    second_cursor = manager.begin_connection_planning(owner)
    second_identity = second_cursor.reserve_identity()
    reverse_plan = manager.finalize_connection_composite_materialization(
        second_cursor,
        _transaction(conn_id=second_identity.conn_id, zeek_uid=second_identity.zeek_uid),
        process_activity=tuple(reversed(process_patches)),
        session_activity=tuple(reversed(session_patches)),
    )

    assert len(plan.process_activity) == 1
    assert len(plan.session_activity) == 1
    assert reverse_plan.process_activity == plan.process_activity
    assert reverse_plan.session_activity == plan.session_activity
    assert reverse_plan.publication_token == plan.publication_token
    assert plan.final_state_time == later
    manager.materialize_connection_composite(plan, owner)
    assert manager.get_process("WS-01", process).last_activity_time == later
    assert manager.get_session(logon_id).last_activity_time == _START + timedelta(seconds=7)
    assert manager.state.current_time == later


def test_physical_connection_composite_atomically_starts_type3_and_terminalizes_smb_file() -> None:
    """Initial root, collision-safe Type-3 identity, and first file op commit together."""

    manager = StateManager()
    manager.set_current_time(_START)
    compiled = CompiledStorageFile(
        file_id="file-initial-smb-root",
        share="FS-01.finance",
        path="Scratch\\initial-smb-root.txt",
        size_bytes=10,
        mime_type="text/plain",
    )
    manager.touch_smb_file(compiled)
    journal = manager.begin_smb_file_mutation_journal("operation-initial-smb-root")
    manager.update_smb_file(compiled.file_id, size_bytes=20, journal=journal)

    batch_builder = manager.begin_materialization_batch()
    session_plan = batch_builder.plan_session(
        username="EXAMPLE\\analyst",
        system="FS-01",
        logon_type=3,
        source_ip="10.0.0.10",
        source_port=50_001,
        session_kind="network",
        start_time=_START,
        logon_id=None,
        smb_principal="EXAMPLE\\analyst",
        auth_protocol="NTLMv2",
        auth_session_ref="smb-auth-root",
        account_scope="EXAMPLE",
    )
    batch = batch_builder.seal()
    owner = random.Random(833)
    cursor = manager.begin_connection_planning(owner)
    cursor.terminalize_smb_file_mutation(journal)
    identity = cursor.reserve_identity()
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(
            conn_id=identity.conn_id,
            zeek_uid=identity.zeek_uid,
            dst_port=445,
            service="smb",
        ),
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="fs-01.example.test",
        batch=batch,
    )

    assert manager.smb_file_size(compiled) == 10
    assert manager.get_session(session_plan.identity.logon_id) is None
    result = manager.materialize_connection_composite(plan, owner)

    assert result.session is not None
    assert result.session.logon_id == session_plan.identity.logon_id
    assert result.smb_file_mutation is not None
    assert manager.recover_smb_file_mutation_commit(journal) is result.smb_file_mutation
    assert manager.smb_file_size(compiled) == 20
    assert manager.state.open_connections[identity.conn_id] is result.connection
    assert manager.acknowledge_smb_file_mutation_commit(result.smb_file_mutation)
    summary = manager.get_state_summary()
    assert summary["smb_file_mutation_journals"] == 0
    assert summary["smb_file_mutation_retained_bytes"] == 0


def test_physical_connection_smb_file_mutation_requires_physical_root() -> None:
    """An initial SMB file mutation cannot be attached to an application child."""

    manager = StateManager()
    manager.set_current_time(_START)
    compiled = CompiledStorageFile(
        file_id="file-initial-smb-binding",
        share="FS-01.finance",
        path="Scratch\\initial-smb-binding.txt",
        size_bytes=10,
        mime_type="text/plain",
    )
    manager.touch_smb_file(compiled)
    journal = manager.begin_smb_file_mutation_journal("operation-initial-smb-binding")
    manager.update_smb_file(compiled.file_id, size_bytes=20, journal=journal)
    owner = random.Random(834)
    cursor = manager.begin_connection_planning(owner)
    cursor.terminalize_smb_file_mutation(journal)
    identity = cursor.reserve_identity()
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        _transaction(
            conn_id=identity.conn_id,
            zeek_uid=identity.zeek_uid,
            dst_port=445,
            service="smb",
        ),
    )
    assert plan._smb_file_mutation_terminalization is not None

    child_owner = random.Random(835)
    child = manager.begin_connection_planning(child_owner)
    child.terminalize_smb_file_mutation(journal)
    with pytest.raises(StateError, match="requires a physical root"):
        manager.finalize_connection_composite_materialization(
            child,
            _transaction(
                conn_id="missing-parent",
                zeek_uid="Cmissingparent",
                application_layer_only=True,
                dst_port=445,
                service="smb",
            ),
            mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )
    child.cancel()
    manager.cancel_smb_file_mutation_journal(journal)
    assert manager.get_state_summary()["smb_file_mutation_retained_bytes"] == 0


def _pinned_smb_root(
    *,
    acknowledge_install: bool = True,
) -> tuple[
    StateManager,
    random.Random,
    object,
    object,
    NetworkTransactionPlan,
]:
    """Materialize one exact TCP/445 root with a generated Type-3 session pin."""

    manager = StateManager()
    manager.set_current_time(_START)
    transaction_owner = random.Random(9_445)
    cursor = manager.begin_connection_planning(transaction_owner)
    identity = cursor.reserve_identity()
    pin = cursor.reserve_smb_connection_pin()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        dst_port=445,
        service="smb",
        hostname="FS-01",
    )
    batch_builder = manager.begin_materialization_batch()
    session_plan = batch_builder.plan_session(
        username="EXAMPLE\\analyst",
        system="FS-01",
        logon_type=3,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        session_kind="network",
        start_time=transaction.started_at + timedelta(milliseconds=50),
        logon_id=None,
        network_close_time=transaction.closed_at,
        closure_owned_by_bundle=True,
        end_plan=SessionEndPlan(
            canonical_end=transaction.closed_at,
            authority="action_bundle",
        ),
        smb_principal="EXAMPLE\\analyst",
        auth_protocol="NTLMv2",
        auth_session_ref="smb-auth-root",
        account_scope="EXAMPLE",
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="WS-01",
        source_hostname="WS-01",
        hostname="FS-01",
        batch=batch_builder.seal(),
    )
    result = manager.materialize_connection_composite(plan, transaction_owner)
    receipt = result.smb_connection_pin_install
    assert receipt is not None
    assert receipt.pin is pin
    assert receipt.session_identity == session_plan.identity
    assert manager.recover_smb_connection_pin_install(pin) is receipt
    assert manager.authenticates_smb_connection_pin(pin)
    if acknowledge_install:
        assert manager.acknowledge_smb_connection_pin_install(receipt)
        assert manager.recover_smb_connection_pin_install(pin) is None
    return manager, transaction_owner, pin, session_plan.identity, transaction


def _planned_smb_root(
    *,
    started_at: datetime = _START,
    duration: float = 1.25,
    src_port: int = 50_001,
) -> tuple[
    StateManager,
    random.Random,
    ConnectionPlanningCursor,
    object,
    NetworkTransactionPlan,
    MaterializationBatchPlan,
]:
    """Return one valid unsealed SMB root for adversarial preflight tests."""

    manager = StateManager()
    manager.set_current_time(started_at)
    owner = random.Random(9_448)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    pin = cursor.reserve_smb_connection_pin()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        started_at=started_at,
        duration=duration,
        src_port=src_port,
        dst_port=445,
        service="smb",
        hostname="FS-01",
    )
    batch_builder = manager.begin_materialization_batch()
    batch_builder.plan_session(
        username="EXAMPLE\\analyst",
        system="FS-01",
        logon_type=3,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        session_kind="network",
        start_time=transaction.started_at + timedelta(milliseconds=50),
        logon_id=None,
        network_close_time=transaction.closed_at,
        closure_owned_by_bundle=True,
        end_plan=SessionEndPlan(
            canonical_end=transaction.closed_at,
            authority="action_bundle",
        ),
        smb_principal="EXAMPLE\\analyst",
        auth_protocol="NTLMv2",
        auth_session_ref="smb-auth-preflight",
        account_scope="EXAMPLE",
    )
    return manager, owner, cursor, pin, transaction, batch_builder.seal()


@pytest.mark.parametrize("src_port", [0, 65_536])
def test_smb_root_rejects_invalid_source_port_before_state_or_rng_mutation(
    src_port: int,
) -> None:
    """A physical SMB root admits only a positive 16-bit client port."""

    manager, owner, cursor, _pin, transaction, batch = _planned_smb_root(
        src_port=src_port,
    )
    before_digest = manager.materialization_digest()
    before_summary = manager.get_state_summary()
    before_owner_state = owner.getstate()

    with pytest.raises(StateError, match="source port"):
        manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            source_system="WS-01",
            source_hostname="WS-01",
            hostname="FS-01",
            batch=batch,
        )

    assert manager.materialization_digest() == before_digest
    assert manager.get_state_summary() == before_summary
    assert owner.getstate() == before_owner_state
    cursor.cancel()


@pytest.mark.parametrize("src_port", [1, 65_535])
def test_smb_root_accepts_source_port_boundaries(src_port: int) -> None:
    """The positive 16-bit SMB client-port boundaries seal and publish exactly."""

    manager, owner, cursor, pin, transaction, batch = _planned_smb_root(
        src_port=src_port,
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="WS-01",
        source_hostname="WS-01",
        hostname="FS-01",
        batch=batch,
    )

    assert manager.authenticates_materialization_plan(plan)
    result = manager.materialize_connection_composite(plan, owner)
    receipt = result.smb_connection_pin_install
    assert receipt is not None
    assert receipt.pin is pin
    assert result.connection.src_port == src_port
    assert manager.acknowledge_smb_connection_pin_install(receipt)


def test_smb_root_requires_full_terminal_retention_time_headroom() -> None:
    """Root admission reserves the exact close plus ended-session retention interval."""

    latest_close = datetime.max.replace(tzinfo=UTC) - timedelta(hours=48)
    valid_start = latest_close - timedelta(seconds=1)
    manager, _owner, cursor, _pin, transaction, batch = _planned_smb_root(
        started_at=valid_start,
        duration=1.0,
    )
    plan = manager.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="WS-01",
        source_hostname="WS-01",
        hostname="FS-01",
        batch=batch,
    )
    assert manager.authenticates_materialization_plan(plan)

    invalid_start = valid_start + timedelta(microseconds=1)
    manager, owner, cursor, _pin, transaction, batch = _planned_smb_root(
        started_at=invalid_start,
        duration=1.0,
    )
    digest = manager.materialization_digest()
    owner_state = owner.getstate()
    with pytest.raises(StateError, match="retention headroom"):
        manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            source_system="WS-01",
            source_hostname="WS-01",
            hostname="FS-01",
            batch=batch,
        )
    assert manager.materialization_digest() == digest
    assert owner.getstate() == owner_state
    cursor.cancel()


def test_connection_pin_installs_with_type3_and_fences_every_connection_writer() -> None:
    """One exact pin hides terminal indexes and blocks every ordinary root writer."""

    manager, owner, pin, _session_identity, transaction = _pinned_smb_root()
    connection = manager.state.open_connections[transaction.conn_id]
    digest = manager.materialization_digest()

    assert transaction.conn_id not in manager._connection_expirations
    assert transaction.conn_id not in manager._terminal_connection_ids
    assert manager.sweep_closed_connections(transaction.closed_at) == 0
    assert manager.state.open_connections[transaction.conn_id] is connection
    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.update_connection_interval(
            transaction.conn_id,
            transaction.started_at,
            transaction.closed_at,
        )
    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.update_connection_bytes(transaction.conn_id, 1, 1)
    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.update_connection_transaction(transaction.conn_id, transaction)
    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.close_connection(transaction.conn_id)

    child_owner = random.Random(9_446)
    child_cursor = manager.begin_connection_planning(child_owner)
    child = replace(
        transaction,
        stable_id="pinned-application-child",
        application_layer_only=True,
    )
    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.finalize_connection_composite_materialization(
            child_cursor,
            child,
            mode=ConnectionMaterializationMode.APPLICATION_CHILD,
        )
    child_cursor.cancel()

    assert manager.materialization_digest() == digest
    assert owner is not None and pin is not None


def test_connection_composite_rejects_pinned_session_activity_precanonical() -> None:
    """An unrelated physical root cannot patch a pinned Type-3 activity frontier."""

    manager, _owner, pin, session_identity, pinned = _pinned_smb_root()
    session = manager.get_session(session_identity.logon_id)
    assert session is not None
    owner = random.Random(9_450)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        stable_id="unrelated-pinned-session-activity",
        started_at=pinned.started_at,
    )
    before = manager.materialization_digest()
    before_fields = dict(session.__dict__)
    owner_state = owner.getstate()

    with pytest.raises(StateError, match="pinned SMB session"):
        manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            source_system="WS-01",
            source_hostname="WS-01",
            hostname="example.test",
            session_activity=(SessionActivityPatch(session_identity, pinned.closed_at),),
        )

    assert manager.materialization_digest() == before
    assert session.__dict__ == before_fields
    assert owner.getstate() == owner_state
    assert manager.authenticates_smb_connection_pin(pin)
    cursor.cancel()


def test_apply_rejects_pinned_connection_before_process_or_row_mutation() -> None:
    """The compatibility apply path checks the pin before any related activity write."""

    manager, _owner, pin, _session_identity, transaction = _pinned_smb_root()
    pid = manager.create_process(
        "WS-01",
        0,
        r"C:\Windows\System32\client.exe",
        "client.exe",
        "EXAMPLE\\analyst",
        "Medium",
    )
    process = manager.get_process("WS-01", pid)
    connection = manager.state.open_connections[transaction.conn_id]
    assert process is not None
    before = manager.materialization_digest()
    process_before = dict(process.__dict__)
    connection_before = dict(connection.__dict__)

    with pytest.raises(StateError, match="pinned SMB connection"):
        manager.apply(
            OccurrenceBuilder(
                timestamp=transaction.closed_at,
                event_type="connection",
                src_host=HostContext(
                    hostname="WS-01",
                    ip=transaction.src_ip,
                    os="Windows 11",
                    os_category="windows",
                    system_type="workstation",
                ),
                process=ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image=r"C:\Windows\System32\client.exe",
                    command_line="client.exe",
                    username="EXAMPLE\\analyst",
                ),
                network=transaction,
            )
        )

    assert manager.materialization_digest() == before
    assert process.__dict__ == process_before
    assert connection.__dict__ == connection_before
    assert manager.authenticates_smb_connection_pin(pin)


@pytest.mark.parametrize("supplied_logon_id", ["0x3e4", "0x3e5", "0x3e7"])
def test_connection_pin_rejects_supplied_reserved_type3_logon_ids(
    supplied_logon_id: str,
) -> None:
    """SMB roots accept only collision-probed generated Type-3 identities."""

    manager = StateManager()
    manager.set_current_time(_START)
    owner = random.Random(9_447)
    cursor = manager.begin_connection_planning(owner)
    identity = cursor.reserve_identity()
    cursor.reserve_smb_connection_pin()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        dst_port=445,
        service="smb",
        hostname="FS-01",
    )
    batch_builder = manager.begin_materialization_batch()
    batch_builder.plan_session(
        username="EXAMPLE\\analyst",
        system="FS-01",
        logon_type=3,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        session_kind="network",
        start_time=transaction.started_at,
        logon_id=supplied_logon_id,
        network_close_time=transaction.closed_at,
        closure_owned_by_bundle=True,
        end_plan=SessionEndPlan(
            canonical_end=transaction.closed_at,
            authority="action_bundle",
        ),
        smb_principal="EXAMPLE\\analyst",
        auth_protocol="NTLMv2",
        auth_session_ref="reserved-logon-negative",
        account_scope="EXAMPLE",
    )
    batch = batch_builder.seal()
    digest = manager.materialization_digest()

    with pytest.raises(StateError, match="generated LogonID"):
        manager.finalize_connection_composite_materialization(
            cursor,
            transaction,
            source_system="WS-01",
            source_hostname="WS-01",
            hostname="FS-01",
            batch=batch,
        )

    assert manager.materialization_digest() == digest
    cursor.cancel()

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
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.state_manager import (
    ConnectionMaterializationMode,
    PhysicalTransportFingerprint,
    ProcessActivityPatch,
    SessionActivityPatch,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.ids import generate_zeek_uid_from_rng

_START = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)


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
) -> NetworkTransactionPlan:
    closed_at = started_at + timedelta(seconds=duration)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="example.test",
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=50_001,
        dst_ip="10.0.0.20",
        dst_port=443,
        protocol="tcp",
        service="https",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=duration,
        conn_state="SF",
        history="ShADadFf",
        traffic=traffic or _traffic(),
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
    with pytest.raises(StateError, match="integrity validation failed"):
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
    with pytest.raises(StateError, match="integrity validation failed"):
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

    digest = manager.materialization_digest()
    owner_entry = owner.getstate()
    original_processes = batch._processes
    object.__setattr__(batch, "_processes", tuple(reversed(original_processes)))
    with pytest.raises(StateError, match="plan integrity validation failed"):
        manager.materialize_connection_composite(plan, owner)
    assert manager.materialization_digest() == digest
    assert owner.getstate() == owner_entry
    object.__setattr__(batch, "_processes", original_processes)

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

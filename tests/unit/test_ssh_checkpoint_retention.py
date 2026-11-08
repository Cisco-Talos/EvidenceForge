"""SSH references survive event-time lookahead and host-local PID reuse."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle, SshSessionRequest
from evidenceforge.generation.checkpoints.activity_head import _capture_ssh_lifecycles
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.state_values import decode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_ssh_deferred_production import (
    _START,
    _fixture,
    _modeled_scp_owned_close,
    _RealSshFixture,
)


def _retained_request(fixture: _RealSshFixture, *, exact: bool) -> tuple[SshSessionRequest, int]:
    request, pid = _modeled_scp_owned_close(fixture)
    if not exact:
        # An explicitly existing receiver session exercises the supported legacy
        # continuation; removing a source alone must retain exact ownership.
        logon_id = fixture.state.create_session(
            fixture.user.username,
            fixture.target.hostname,
            10,
            fixture.source.ip,
            start_time=request.time,
            session_kind="ssh",
        )
        request = replace(request, logon_id=logon_id)
    return request, pid


def _captured_source_identity(fixture: _RealSshFixture, *, exact: bool) -> object:
    row = _capture_ssh_lifecycles(fixture.generator)[0]
    return decode_state_value(row[26] if exact else row[3][11])


def test_identity_retirement_uses_completed_work_not_event_cursor() -> None:
    manager = StateManager()
    manager.set_current_time(_START)
    session = manager.create_session("analyst", "WS-01", 2, "10.0.0.1")
    pid = manager.create_process(
        "WS-01", 0, r"C:\Windows\System32\cmd.exe", "cmd.exe", "analyst", "Medium", session
    )
    process = manager.get_process_identity("WS-01", pid)
    assert process is not None and process.primary_thread is not None
    manager.end_process("WS-01", pid, _START + timedelta(minutes=1))
    manager.end_session(session, _START + timedelta(minutes=2))
    manager.set_current_time(_START + timedelta(days=56))
    assert manager.get_process_identity_by_object_id(process.object_id) == process
    assert manager.get_session_identity(session) is not None
    assert len(manager._ended_threads) == 1

    manager.advance_pid_allocation_watermark(_START + timedelta(hours=48))
    assert manager.get_process_identity_by_object_id(process.object_id) == process
    manager.advance_pid_allocation_watermark(_START + timedelta(hours=49))
    assert manager.get_process_identity_by_object_id(process.object_id) is None
    assert manager.get_session_identity(session) is None
    assert len(manager._ended_threads) == 0
    # Repeated retirement is harmless and never advances the event cursor.
    manager.advance_pid_allocation_watermark(_START + timedelta(hours=49))
    assert manager.get_current_time() == _START + timedelta(days=56)


def test_ssh_does_not_invent_source_identity_from_an_image(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    try:
        bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
        assert bundle._resolve_source_process(4321, r"C:\Windows\System32\ssh.exe") is None
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("seed", [42, 137])
@pytest.mark.parametrize("exact", [False, True])
def test_pending_ssh_identity_survives_periodic_lookahead(
    tmp_path: Path, seed: int, exact: bool
) -> None:
    reset_thread_rng(seed)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    request, pid = _retained_request(fixture, exact=exact)
    try:
        SshSessionActionBundle(request, fixture.generator).execute()
        before = _capture_ssh_lifecycles(fixture.generator)
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        # A periodic handler visits the future without sealing intervening hours.
        fixture.state.set_current_time(request.time + timedelta(days=56))
        fixture.state.advance_time(timedelta(hours=1))
        fixture.state.set_current_time(request.time + timedelta(seconds=10))
        assert fixture.state.get_process_identity_by_object_id(identity.object_id) == identity
        assert _capture_ssh_lifecycles(fixture.generator) == before
        census = fixture.generator.ssh_close_journal_census()
        assert census.exact_pending == int(exact)
        assert census.legacy_pending == int(not exact)
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("same_image", [False, True])
@pytest.mark.parametrize("exact", [False, True])
def test_ssh_checkpoint_keeps_original_process_after_pid_reuse(
    tmp_path: Path, same_image: bool, exact: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    fixture.state._initialize_pid_allocator(fixture.source.hostname, "windows")
    fixture.state._pid_counters[fixture.source.hostname] = 5000
    request, pid = _retained_request(fixture, exact=exact)
    try:
        SshSessionActionBundle(request, fixture.generator).execute()
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        entry = fixture.generator._pending_ssh_session_closures[0]
        close_time = entry.plan.close_time if exact else entry[0]
        fixture.state.set_current_time(close_time + timedelta(seconds=60))
        # Place the allocator at this PID's next valid Windows ring occurrence.
        fixture.state._pid_counters[fixture.source.hostname] = pid + 61536
        replacement_pid = fixture.state.create_process(
            fixture.source.hostname,
            0,
            identity.image if same_image else r"C:\Windows\System32\cmd.exe",
            "different command",
            fixture.user.username,
            "Medium",
            identity.logon_id,
        )
        assert replacement_pid == pid
        captured = _captured_source_identity(fixture, exact=exact)
        assert captured == identity
        fixture.generator.finalize_ssh_session_lifecycles(close_time + timedelta(minutes=2))
        assert fixture.state.get_process(fixture.source.hostname, replacement_pid) is not None
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("reuse_pid", [False, True])
def test_ssh_binds_retained_process_that_spans_transport_open(
    tmp_path: Path, reuse_pid: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    fixture.state._initialize_pid_allocator(fixture.source.hostname, "windows")
    fixture.state._pid_counters[fixture.source.hostname] = 5000
    request, pid = _modeled_scp_owned_close(fixture)
    try:
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        fixture.state.end_process(
            fixture.source.hostname, pid, end_time=request.time + timedelta(minutes=3)
        )
        replacement = None
        if reuse_pid:
            later = request.time + timedelta(minutes=4)
            fixture.state.set_current_time(later)
            fixture.state._pid_counters[fixture.source.hostname] = pid + 61536
            replacement_pid = fixture.state.create_process(
                fixture.source.hostname,
                0,
                identity.image,
                "later unrelated process",
                fixture.user.username,
                "Medium",
                identity.logon_id,
            )
            assert replacement_pid == pid
            replacement = fixture.state.get_process_identity(fixture.source.hostname, pid)
            assert replacement.object_id != identity.object_id
        SshSessionActionBundle(request, fixture.generator).execute()
        captured = decode_state_value(_capture_ssh_lifecycles(fixture.generator)[0][3][11])
        if replacement is not None:
            # PID reuse retires the old numeric alias. This request has no durable
            # object reference, so omit ambiguous attribution instead of binding
            # the later process. Already-bound SSH continuations are tested above.
            assert captured is None
            assert fixture.state.get_process_identity(fixture.source.hostname, pid) == replacement
        else:
            assert captured == identity
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("exact", [False, True])
def test_ssh_checkpoint_still_rejects_lost_canonical_identity(tmp_path: Path, exact: bool) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    request, pid = _retained_request(fixture, exact=exact)
    try:
        SshSessionActionBundle(request, fixture.generator).execute()
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        fixture.state._ended_processes_by_object_id.pop(identity.object_id)
        with pytest.raises(CheckpointError, match="source process lost State authority"):
            _capture_ssh_lifecycles(fixture.generator)
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("collect_network", [False, True])
def test_exact_ssh_retains_and_closes_identity_without_endpoint_collection(
    tmp_path: Path, collect_network: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    if not collect_network:
        fixture.generator.dispatcher.emitters.pop("zeek_conn")
    request, pid = _retained_request(fixture, exact=True)
    try:
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        SshSessionActionBundle(request, fixture.generator).execute()
        assert fixture.generator.ssh_close_journal_census().exact_pending == 1
        assert _captured_source_identity(fixture, exact=True) == identity
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=1))
        assert fixture.generator.ssh_close_journal_census().total_pending == 0
        assert fixture.state.get_process(fixture.source.hostname, pid) is None
    finally:
        endpoint_rows, network_rows = fixture.close_and_read()
    assert endpoint_rows == []
    assert len(network_rows) == int(collect_network)
    if collect_network:
        assert network_rows[0]["id.orig_h"] == fixture.source.ip
        assert network_rows[0]["id.resp_h"] == fixture.target.ip
        assert network_rows[0]["id.resp_p"] == 22

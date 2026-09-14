"""SSH references survive event-time lookahead and host-local PID reuse."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.generation.checkpoints.activity_head import _capture_ssh_lifecycles
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.checkpoints.state_values import decode_state_value
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import reset_thread_rng
from tests.unit.test_ssh_deferred_production import _START, _fixture, _modeled_scp_owned_close


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
def test_pending_ssh_identity_survives_periodic_lookahead(tmp_path: Path, seed: int) -> None:
    reset_thread_rng(seed)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    request, pid = _modeled_scp_owned_close(fixture)
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
        assert fixture.generator.ssh_close_journal_census().legacy_pending == 1
    finally:
        fixture.close_and_read()


@pytest.mark.parametrize("same_image", [False, True])
def test_ssh_checkpoint_keeps_original_process_after_pid_reuse(
    tmp_path: Path, same_image: bool
) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    fixture.state._initialize_pid_allocator(fixture.source.hostname, "windows")
    fixture.state._pid_counters[fixture.source.hostname] = 5000
    request, pid = _modeled_scp_owned_close(fixture)
    try:
        SshSessionActionBundle(request, fixture.generator).execute()
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        entry = fixture.generator._pending_ssh_session_closures[0]
        fixture.state.set_current_time(entry[0] + timedelta(seconds=60))
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
        captured = decode_state_value(_capture_ssh_lifecycles(fixture.generator)[0][3][11])
        assert captured == identity
        fixture.generator.finalize_ssh_session_lifecycles(entry[0] + timedelta(minutes=2))
        assert fixture.state.get_process(fixture.source.hostname, replacement_pid) is not None
    finally:
        fixture.close_and_read()


def test_ssh_binds_retained_process_that_spans_transport_open(tmp_path: Path) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    request, pid = _modeled_scp_owned_close(fixture)
    try:
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        fixture.state.end_process(
            fixture.source.hostname, pid, end_time=request.time + timedelta(minutes=3)
        )
        SshSessionActionBundle(request, fixture.generator).execute()
        captured = decode_state_value(_capture_ssh_lifecycles(fixture.generator)[0][3][11])
        assert captured == identity
    finally:
        fixture.close_and_read()


def test_ssh_checkpoint_still_rejects_lost_canonical_identity(tmp_path: Path) -> None:
    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.generator.dispatcher.emitters.pop("ecar")
    request, pid = _modeled_scp_owned_close(fixture)
    try:
        SshSessionActionBundle(request, fixture.generator).execute()
        identity = fixture.state.get_process_identity(fixture.source.hostname, pid)
        assert identity is not None
        fixture.state._ended_processes_by_object_id.pop(identity.object_id)
        with pytest.raises(CheckpointError, match="source process lost State authority"):
            _capture_ssh_lifecycles(fixture.generator)
    finally:
        fixture.close_and_read()

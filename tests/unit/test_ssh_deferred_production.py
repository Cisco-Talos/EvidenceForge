# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Real-caller coverage for exact SSH deferred-session publication."""

from __future__ import annotations

import json
import random
from collections.abc import Iterator
from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortCapability
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle, SshSessionRequest
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.emitters.base import ExactPublicationBatch
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.web import WebEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    PreparedLifecycleClosedTransportPublication,
)
from evidenceforge.generation.network_runtime import NetworkTransactionPreparedCommit
from evidenceforge.generation.source_timing import SourceTimingPreparation
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelPreparedCommit,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.world_model import SessionPlan, WorldPlanner
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import reset_thread_rng

_START = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)
_SSH_AUTH_TIMING_RELATIONSHIPS = (
    "ssh.authentication.connection_after_transport",
    "ssh.authentication.phase",
    "ssh.authentication.cache_delay",
    "ssh.authentication.route_delay",
    "ssh.authentication.receiver_delay",
    "ssh.authentication.pam_after_accepted",
    "ssh.authentication.logind_after_pam",
)


@dataclass(slots=True)
class _RealSshFixture:
    """One real ActivityGenerator plus exact built-in SSH source sinks."""

    generator: ActivityGenerator
    state: StateManager
    ecar: EcarEmitter
    zeek: ZeekEmitter
    ecar_root: Path
    zeek_path: Path
    source: System
    target: System
    user: User

    def request(self) -> SshSessionRequest:
        """Return one deterministic new-session request."""

        return SshSessionRequest(
            user=self.user,
            target_system=self.target,
            time=_START,
            source_ip=self.source.ip,
            source_system=self.source,
            source_port=50_001,
            duration=30.0,
            orig_bytes=12_345,
            resp_bytes=54_321,
            source="ssh_deferred_production_test",
        )

    def close_and_read(self) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        """Close both real sinks and parse their final immutable rows."""

        self.ecar.close()
        self.zeek.close()
        ecar_rows = [
            json.loads(line)
            for output in sorted(self.ecar_root.rglob("ecar.json"))
            for line in output.read_text(encoding="utf-8").splitlines()
        ]
        zeek_rows = (
            [json.loads(line) for line in self.zeek_path.read_text(encoding="utf-8").splitlines()]
            if self.zeek_path.exists()
            else []
        )
        return ecar_rows, zeek_rows

    def frozen_bytes(self) -> tuple[tuple[tuple[str, bytes], ...], bytes]:
        """Close and return path-qualified eCAR bytes plus Zeek bytes."""

        self.ecar.close()
        self.zeek.close()
        ecar = tuple(
            (str(path.relative_to(self.ecar_root)), path.read_bytes())
            for path in sorted(self.ecar_root.rglob("ecar.json"))
        )
        return ecar, self.zeek_path.read_bytes()


def _fixture(
    tmp_path: Path,
    *,
    threaded: bool = False,
    extra_emitters: dict[str, object] | None = None,
    member_capacity: int = 65_536,
    output_start_time: datetime | None = None,
) -> _RealSshFixture:
    """Build the real production caller with concrete eCAR and Zeek adapters."""

    state = StateManager()
    state.set_current_time(_START)
    ecar_root = tmp_path / "ecar"
    zeek_path = tmp_path / "zeek_conn.json"
    ecar = EcarEmitter(load_format("ecar"), ecar_root, threaded=threaded)
    zeek = ZeekEmitter(load_format("zeek_conn"), zeek_path, threaded=threaded)
    emitters: dict[str, object] = {"ecar": ecar, "zeek_conn": zeek}
    emitters.update(extra_emitters or {})
    dispatcher = EventDispatcher(
        state,
        emitters,  # type: ignore[arg-type]
        output_start_time=output_start_time,
        action_cohort_member_capacity=member_capacity,
    )
    generator = ActivityGenerator(
        state,
        emitters,  # type: ignore[arg-type]
        dispatcher=dispatcher,
        generation_window_start=_START - timedelta(days=1),
        generation_window_end=_START + timedelta(days=1),
    )
    source = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="DB-01",
        ip="10.0.0.20",
        os="Ubuntu 24.04",
        type="server",
        services=["ssh"],
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    return _RealSshFixture(
        generator=generator,
        state=state,
        ecar=ecar,
        zeek=zeek,
        ecar_root=ecar_root,
        zeek_path=zeek_path,
        source=source,
        target=target,
        user=User(
            username="analyst",
            full_name="Security Analyst",
            email="analyst@example.test",
        ),
    )


def _assert_no_dispatcher_residue(dispatcher: EventDispatcher) -> None:
    """Require every exact deferred-source reservation to be terminal."""

    deferred = dispatcher.deferred_session_publication_census()
    recovery = dispatcher.exact_projection_recovery_census()
    action = dispatcher.action_cohort_publication_census()
    assert deferred.prepared_batches == 0
    assert deferred.retained_members == 0
    assert deferred.retained_bytes == 0
    assert deferred.pending_receipts == 0
    assert deferred.receipt_reservations == 0
    assert deferred.recovery_reservations == 0
    assert recovery.unresolved_recoveries == 0
    assert recovery.reserved_recoveries == 0
    assert recovery.authority.active_batches == 0
    assert action.prepared_batches == 0
    assert action.claimed_batches == 0
    assert action.retained_members == 0
    assert action.retained_bytes == 0
    assert action.capability_locators == 0
    assert action.prepared_projections == 0
    assert action.projection_groups == 0
    assert action.projection_retained_bytes == 0


def _execute_real_caller(
    fixture: _RealSshFixture,
    *,
    emit_session_close: bool = False,
    defer_session_close: bool = False,
) -> tuple[str, str]:
    """Use the ActivityGenerator entrypoint exercised by production callers."""

    request = fixture.request()
    return fixture.generator._execute_ssh_session_bundle(
        user=request.user,
        target_system=request.target_system,
        time=request.time,
        source_ip=request.source_ip,
        source_system=request.source_system,
        source_port=request.source_port,
        duration=request.duration,
        orig_bytes=request.orig_bytes,
        resp_bytes=request.resp_bytes,
        auth_method=request.auth_method,
        emit_session_close=emit_session_close,
        defer_session_close=defer_session_close,
        source=request.source,
    )


def _modeled_scp_owned_close(
    fixture: _RealSshFixture,
) -> tuple[SshSessionRequest, int]:
    """Build one live explicit SCP actor whose exact SSH bundle owns deferred close."""

    source_logon = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    source_image = r"C:\Windows\System32\OpenSSH\scp.exe"
    source_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        source_logon,
        source_image,
        f"{source_image} report.csv {fixture.target.ip}:/tmp/report.csv",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    return (
        replace(
            fixture.request(),
            time=_START + timedelta(seconds=2),
            source_pid=source_pid,
            source_process_image=source_image,
            source="storyline_scp",
            emit_session_close=True,
            defer_session_close=True,
        ),
        source_pid,
    )


def _assert_owned_close_recovers(
    fixture: _RealSshFixture,
    *,
    source_pid: int,
) -> None:
    """Drain an exact postcommit error and prove every SSH/source owner terminates once."""

    target_sessions = [
        session
        for session in fixture.state.get_sessions_for_user(fixture.user.username)
        if session.system == fixture.target.hostname
    ]
    assert len(target_sessions) == 1
    session = target_sessions[0]
    assert session.transport_pid is not None
    receiver_pid = session.transport_pid
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 1
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    recovery = fixture.generator.dispatcher.exact_projection_recovery_census()
    if recovery.unresolved_recoveries:
        results = fixture.generator.dispatcher.drain_exact_projection_recoveries()
        assert all(
            outcome.status == "succeeded" for result in results for outcome in result.projections
        )

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fixture.state.get_session(session.logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_rows] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("threaded", (False, True), ids=("direct", "threaded"))
def test_real_ssh_caller_reaches_exact_bridge_and_publishes_transport_first(
    threaded: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real bundle publishes one exact owner graph and source-causal rows."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path, threaded=threaded)
    original = GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication
    bridge_calls = 0

    def capture_bridge(
        authority: GeneratorLifecycleAuthority,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal bridge_calls
        bridge_calls += 1
        return original(authority, *args, **kwargs)

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "materialize_prepared_deferred_session_publication",
        capture_bridge,
    )
    uid, logon_id = _execute_real_caller(fixture)

    assert bridge_calls == 1
    assert uid
    session = fixture.state.get_session(logon_id)
    assert session is not None
    assert session.session_kind == "ssh"
    assert session.transport_pid is not None
    receiver = fixture.state.get_process(fixture.target.hostname, session.transport_pid)
    assert receiver is not None
    assert receiver.image == "/usr/sbin/sshd"
    assert receiver.parent_pid == 0
    assert receiver.logon_id == logon_id
    assert receiver.integrity_level == "System"
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 1
    timing_audit = fixture.generator.timing_runtime.audit.snapshot()
    assert all(
        timing_audit.sample_counts[relationship] == 1
        for relationship in _SSH_AUTH_TIMING_RELATIONSHIPS
    )
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)

    ecar_rows, zeek_rows = fixture.close_and_read()
    target_rows = [row for row in ecar_rows if row.get("hostname") == fixture.target.hostname]
    flow_times = [row["timestamp_ms"] for row in target_rows if row.get("object") == "FLOW"]
    process_times = [row["timestamp_ms"] for row in target_rows if row.get("object") == "PROCESS"]
    login_times = [
        row["timestamp_ms"]
        for row in target_rows
        if row.get("object") == "USER_SESSION" and row.get("action") == "LOGIN"
    ]
    assert flow_times and process_times and login_times
    assert max(flow_times) < min(process_times) < min(login_times)
    assert len(zeek_rows) == 1
    assert zeek_rows[0]["uid"] == uid
    assert zeek_rows[0]["orig_bytes"] == 12_345
    assert zeek_rows[0]["resp_bytes"] == 54_321


def test_real_ssh_caller_materializes_fully_suppressed_warmup_session(
    tmp_path: Path,
) -> None:
    """A wholly pre-output SSH owner graph commits canonically without source rows."""

    reset_thread_rng(42)
    fixture = _fixture(
        tmp_path,
        output_start_time=_START + timedelta(hours=1),
    )

    uid, logon_id = _execute_real_caller(
        fixture,
        emit_session_close=True,
        defer_session_close=True,
    )

    assert uid
    session = fixture.state.get_session(logon_id)
    assert session is not None
    assert session.session_kind == "ssh"
    assert session.transport_pid is not None
    receiver_pid = session.transport_pid
    assert session.network_close_time is not None
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.state.get_session(logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    assert (
        fixture.generator._source_timing_planner.preparation_authority_census().active_claims == 0
    )
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_mixed_warmup_and_visible_members_still_require_positive_targets(
    tmp_path: Path,
) -> None:
    """A suppressed transport cannot admit later visible session members without proof."""

    reset_thread_rng(42)
    fixture = _fixture(
        tmp_path,
        output_start_time=_START + timedelta(seconds=1),
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
    )

    with pytest.raises(EventContractError, match="positive exact target"):
        _execute_real_caller(fixture)

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
    )
    assert after == before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_zero_row_warmup_open_release_recovers_exactly_once(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Zero-row release retries or adopts one canonical warm-up owner graph."""

    reset_thread_rng(42)
    fixture = _fixture(
        tmp_path,
        output_start_time=_START + timedelta(hours=1),
    )
    original = ExactPublicationBatch.release_no_fail
    attempts = 0

    def inject(batch: ExactPublicationBatch) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(batch)
            raise OSError(f"zero-row release {failure_mode}")
        original(batch)

    monkeypatch.setattr(ExactPublicationBatch, "release_no_fail", inject)
    if failure_mode == "fail-before":
        with pytest.raises(OSError, match=f"zero-row release {failure_mode}"):
            _execute_real_caller(fixture)
        before_retry = fixture.state.materialization_digest()
        recovery = fixture.generator.dispatcher.exact_projection_recovery_census()
        assert recovery.unresolved_recoveries == 1
        results = fixture.generator.dispatcher.drain_exact_projection_recoveries()
        assert len(results) == 1
        assert all(outcome.status == "succeeded" for outcome in results[0].projections)
        assert fixture.state.materialization_digest() == before_retry
    else:
        uid, _logon_id = _execute_real_caller(fixture)
        assert uid

    assert attempts == (2 if failure_mode == "fail-before" else 1)
    assert (
        fixture.generator._source_timing_planner.preparation_authority_census().active_claims == 0
    )
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_exact_bytes_match_threaded_and_direct_modes(tmp_path: Path) -> None:
    """Threading changes no exact eCAR/Zeek byte or identity."""

    outputs = []
    for threaded in (False, True):
        reset_thread_rng(42)
        fixture = _fixture(tmp_path / ("threaded" if threaded else "direct"), threaded=threaded)
        request = replace(fixture.request(), emit_session_close=True)
        SshSessionActionBundle(request, fixture.generator).execute()
        assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
        outputs.append(fixture.frozen_bytes())
    assert outputs[0] == outputs[1]


def test_deferred_close_uses_immutable_models_after_shared_owner_mutation(tmp_path: Path) -> None:
    """Deferred terminal evidence is independent of mutable request model aliases."""

    outputs = []
    for mutate_shared_models in (False, True):
        reset_thread_rng(42)
        fixture = _fixture(tmp_path / ("mutated" if mutate_shared_models else "canonical"))
        request = replace(
            fixture.request(),
            emit_session_close=True,
            defer_session_close=True,
        )
        SshSessionActionBundle(request, fixture.generator).execute()
        if mutate_shared_models:
            fixture.user.username = "intruder"
            fixture.source.hostname = "foreign-source"
            fixture.target.hostname = "foreign-target"
            fixture.target.ip = "203.0.113.199"
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
        assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
        assert fixture.generator._pending_ssh_session_closures == []
        outputs.append(fixture.frozen_bytes())

    assert outputs[0] == outputs[1]


def test_deferred_close_is_fully_prepared_before_committed_owner_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed bridge return cannot reopen mutable request facts before journaling."""

    outputs = []
    original = GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication
    for mutate_during_commit in (False, True):
        reset_thread_rng(42)
        fixture = _fixture(tmp_path / ("mutated" if mutate_during_commit else "canonical"))
        request = replace(
            fixture.request(),
            emit_session_close=True,
            defer_session_close=True,
        )

        def materialize_then_mutate(
            authority: GeneratorLifecycleAuthority,
            *args: object,
            _mutate_during_commit: bool = mutate_during_commit,
            _fixture: _RealSshFixture = fixture,
            **kwargs: object,
        ) -> object:
            receipt = original(authority, *args, **kwargs)
            if _mutate_during_commit:
                _fixture.user.username = "intruder"
                _fixture.source.hostname = "foreign-source"
                _fixture.target.hostname = "foreign-target"
                _fixture.target.ip = "203.0.113.199"
            return receipt

        monkeypatch.setattr(
            GeneratorLifecycleAuthority,
            "materialize_prepared_deferred_session_publication",
            materialize_then_mutate,
        )
        SshSessionActionBundle(request, fixture.generator).execute()
        assert len(fixture.generator._pending_ssh_session_closures) == 1
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
        assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
        assert fixture.generator._pending_ssh_session_closures == []
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        outputs.append(fixture.frozen_bytes())

    assert outputs[0] == outputs[1]


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_close_capacity_reservation_failure_is_precommit_and_released(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reservation faults retain no journal capacity or canonical SSH owner."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()
    original = ActivityGenerator._reserve_exact_ssh_close_continuation
    expected_message = f"close reservation {failure_mode}"

    def inject(*args: object, **kwargs: object) -> None:
        if failure_mode == "lost-return":
            original(*args, **kwargs)
        raise OSError(expected_message)

    monkeypatch.setattr(
        ActivityGenerator,
        "_reserve_exact_ssh_close_continuation",
        inject,
    )

    with pytest.raises(OSError, match=expected_message) as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert str(raised.value) == expected_message
    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is not None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    census = fixture.generator.ssh_close_journal_census()
    assert census.prepared_reservations == 0
    assert census.total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    _ecar_rows, zeek_rows = fixture.close_and_read()
    assert zeek_rows == []


def test_exact_close_capacity_exhaustion_rejects_before_state(tmp_path: Path) -> None:
    """A required close cannot open when its bounded terminal journal is full."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    fixture.generator._ssh_close_journal_capacity = 0
    before = fixture.state.materialization_digest()

    with pytest.raises(StateError, match="close journal capacity is exhausted"):
        SshSessionActionBundle(request, fixture.generator).execute()

    assert fixture.state.materialization_digest() == before
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is not None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    census = fixture.generator.ssh_close_journal_census()
    assert census.capacity == 0
    assert census.prepared_reservations == 0
    assert census.total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    _ecar_rows, zeek_rows = fixture.close_and_read()
    assert zeek_rows == []


def test_exact_close_rejects_transport_at_generation_end_before_state(tmp_path: Path) -> None:
    """A transport at the half-open end cannot commit an unfinalizable SSH tail."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        duration=timedelta(days=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.ssh_close_journal_census(),
        fixture.generator.timing_runtime.state_digest(),
    )

    with pytest.raises(StateError, match="terminal tail.*generation window"):
        SshSessionActionBundle(request, fixture.generator).execute_with_identity()

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.ssh_close_journal_census(),
        fixture.generator.timing_runtime.state_digest(),
    )
    assert after == before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize(
    ("boundary_delta", "admitted"),
    (
        (-timedelta(microseconds=1), True),
        (timedelta(0), True),
        (timedelta(microseconds=1), False),
        (timedelta(milliseconds=1), False),
    ),
)
def test_exact_close_reserves_maximum_terminal_tail_inside_half_open_window(
    boundary_delta: timedelta,
    admitted: bool,
    tmp_path: Path,
) -> None:
    """The 3.5-second terminal family has one exact half-open admission boundary."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    maximum_terminal_tail = timedelta(milliseconds=3_500)
    duration = timedelta(days=1) - maximum_terminal_tail + boundary_delta
    request = replace(
        fixture.request(),
        duration=duration.total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
    )
    before = fixture.state.materialization_digest()

    if not admitted:
        with pytest.raises(StateError, match="terminal tail.*generation window"):
            SshSessionActionBundle(request, fixture.generator).execute_with_identity()
        assert fixture.state.materialization_digest() == before
        assert fixture.generator.ssh_close_journal_census().total_pending == 0
        assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        ecar_rows, zeek_rows = fixture.close_and_read()
        assert ecar_rows == []
        assert zeek_rows == []
        return

    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    assert fixture.state.get_session(logon_id) is not None
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(days=1))
    assert fixture.state.get_session(logon_id) is None
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_rows] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


def test_exact_close_reauthenticates_frozen_terminal_tail_before_transport_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A prepared terminal timestamp cannot move outside the window before open."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        duration=(timedelta(days=1) - timedelta(milliseconds=3_500)).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
    )
    original = SshSessionActionBundle._open_deferred_transport

    def tamper_tail(
        bundle: SshSessionActionBundle,
        state: object,
        prepared: object,
    ) -> object:
        close_owner = object.__getattribute__(prepared, "close_continuation")
        assert close_owner is not None
        plan = object.__getattribute__(close_owner, "plan")
        object.__setattr__(plan, "logind_remove_time", _START + timedelta(days=1))
        return original(bundle, state, prepared)

    monkeypatch.setattr(SshSessionActionBundle, "_open_deferred_transport", tamper_tail)
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.timing_runtime.state_digest(),
    )

    with pytest.raises(StateError, match="terminal tail changed after precommit preparation"):
        SshSessionActionBundle(request, fixture.generator).execute_with_identity()

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.timing_runtime.state_digest(),
    )
    assert after == before
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_exact_close_binding_rejects_copies_foreign_owners_and_stale_replay(
    tmp_path: Path,
) -> None:
    """Only the reserved payload and captured transaction can install or replay a close."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path / "canonical")
    foreign = _fixture(tmp_path / "foreign")
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    bundle = SshSessionActionBundle(request, fixture.generator)
    state = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(state)
    transaction = bundle._open_deferred_transport(state, prepared)
    assert prepared.close_continuation is not None

    with pytest.raises(StateError, match="captured transaction"):
        prepared.close_continuation.bind(copy(transaction))

    continuation = bundle._bind_deferred_close_continuation(prepared, transaction)
    assert continuation is not None
    with pytest.raises(StateError, match="copied or foreign carrier"):
        fixture.generator._recover_exact_ssh_close_continuation_no_fail(copy(continuation))
    with pytest.raises(StateError, match="no reserved journal owner"):
        foreign.generator._recover_exact_ssh_close_continuation_no_fail(continuation)

    fixture.generator._recover_exact_ssh_close_continuation_no_fail(continuation)
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    fixture.generator.assert_ssh_session_lifecycles_drained()
    with pytest.raises(StateError, match="no reserved journal owner"):
        fixture.generator._recover_exact_ssh_close_continuation_no_fail(continuation)

    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    _ecar_rows, zeek_rows = fixture.close_and_read()
    assert len(zeek_rows) == 1
    foreign.ecar.close()
    foreign.zeek.close()


@pytest.mark.parametrize(
    "owner_kind",
    ("foreign-manager", "copied-manager", "foreign-registry", "stale-registry"),
)
def test_exact_close_rejects_replaced_ssh_application_owner_before_retirement(
    owner_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-window SSH manager or registry alias cannot acknowledge the close journal."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path / "canonical")
    foreign = _fixture(tmp_path / "foreign")
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, fixture.generator).execute()
    original_manager = fixture.generator._ssh_channel_manager
    original_registry = original_manager.application_registry
    continuation = fixture.generator._pending_ssh_session_closures[0]
    original_session = original_manager.find_by_transport(continuation.transaction.stable_id)
    assert original_session is not None
    original_snapshot = original_registry.get(original_session.channel_id)
    assert original_snapshot is not None
    assert original_snapshot.is_open
    assert original_manager.census().open_sessions == 1
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1

    if owner_kind == "foreign-manager":
        fixture.generator._ssh_channel_manager = foreign.generator._ssh_channel_manager
    elif owner_kind == "copied-manager":
        fixture.generator._ssh_channel_manager = copy(original_manager)
    elif owner_kind == "foreign-registry":
        monkeypatch.setattr(
            original_manager,
            "_registry",
            foreign.generator._ssh_channel_manager.application_registry,
        )
    else:
        monkeypatch.setattr(original_manager, "_registry", copy(original_registry))

    with pytest.raises(StateError, match="original SSH application owner"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert original_manager.census().open_sessions == 1
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    retained_snapshot = original_registry.get(original_session.channel_id)
    assert retained_snapshot is not None
    assert retained_snapshot.identity == original_snapshot.identity
    assert retained_snapshot.is_open

    fixture.generator._ssh_channel_manager = original_manager
    monkeypatch.setattr(original_manager, "_registry", original_registry)
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert original_manager.census().open_sessions == 0
    assert original_manager.session_view(original_session.channel_id) is None
    retired_snapshot = original_registry.get(original_session.channel_id)
    assert retired_snapshot is not None
    assert retired_snapshot.identity == original_snapshot.identity
    assert retired_snapshot.closed_at == original_session.transport.closes_at
    assert retired_snapshot.close_reason == "bundle_close"
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()
    foreign.ecar.close()
    foreign.zeek.close()


def test_exact_close_original_ssh_application_owner_retires_before_ack(tmp_path: Path) -> None:
    """The exact original SSH manager and registry close before journal acknowledgement."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, fixture.generator).execute()
    manager = fixture.generator._ssh_channel_manager
    pending = fixture.generator._pending_ssh_session_closures
    assert len(pending) == 1
    continuation = pending[0]
    session = manager.find_by_transport(continuation.transaction.stable_id)
    assert session is not None
    channel_id = session.channel_id

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert manager.session_view(channel_id) is None
    snapshot = manager.application_registry.get(channel_id)
    assert snapshot is not None
    assert snapshot.closed_at == session.transport.closes_at
    assert snapshot.close_reason == "bundle_close"
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_close_ssh_application_retirement_is_retryable_before_ack(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SSH manager close failures retain the journal until exact retirement is proven."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, fixture.generator).execute()
    manager = fixture.generator._ssh_channel_manager
    registry = manager.application_registry
    continuation = fixture.generator._pending_ssh_session_closures[0]
    session = manager.find_by_transport(continuation.transaction.stable_id)
    assert session is not None
    open_snapshot = registry.get(session.channel_id)
    assert open_snapshot is not None
    target_session = fixture.state.get_session(session.binding.logon_id)
    assert target_session is not None
    assert target_session.transport_pid is not None
    receiver_pid = target_session.transport_pid
    original = SshApplicationChannelManager.close_session
    attempts = 0

    def inject(
        owner: SshApplicationChannelManager,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(owner, channel_id, closed_at=closed_at, reason=reason)
            raise OSError(f"application retirement {failure_mode}")
        return original(owner, channel_id, closed_at=closed_at, reason=reason)

    monkeypatch.setattr(SshApplicationChannelManager, "close_session", inject)

    with pytest.raises(OSError, match=f"application retirement {failure_mode}"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert manager.census().open_sessions == (1 if failure_mode == "fail-before" else 0)
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    assert fixture.state.get_session(target_session.logon_id) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    retained_snapshot = registry.get(session.channel_id)
    assert retained_snapshot is not None
    assert retained_snapshot.identity == open_snapshot.identity
    if failure_mode == "fail-before":
        assert retained_snapshot.is_open
        assert manager.session_view(session.channel_id) == session
    else:
        assert retained_snapshot.closed_at == session.transport.closes_at
        assert retained_snapshot.close_reason == "bundle_close"
        assert manager.session_view(session.channel_id) is None
        original_get = ApplicationChannelRegistry.get

        def hide_retirement_proof(
            owner: ApplicationChannelRegistry,
            channel_id: str,
        ) -> object | None:
            snapshot = original_get(owner, channel_id)
            if owner is registry and channel_id == session.channel_id:
                return None
            return snapshot

        with monkeypatch.context() as proof_patch:
            proof_patch.setattr(ApplicationChannelRegistry, "get", hide_retirement_proof)
            with pytest.raises(StateError, match="shared application retirement is not proven"):
                fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
        assert fixture.generator.ssh_close_journal_census().exact_pending == 1
        assert fixture.state.get_session(target_session.logon_id) is not None
        assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert attempts == (2 if failure_mode == "fail-before" else 1)
    assert manager.census().open_sessions == 0
    assert manager.session_view(session.channel_id) is None
    closed_snapshot = registry.get(session.channel_id)
    assert closed_snapshot is not None
    assert closed_snapshot.identity == open_snapshot.identity
    assert closed_snapshot.closed_at == session.transport.closes_at
    assert closed_snapshot.close_reason == "bundle_close"
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


@pytest.mark.parametrize(
    ("watermark_delta", "expected_reason"),
    (
        (timedelta(microseconds=-1), "bundle_close"),
        (timedelta(0), "deadline"),
        (timedelta(microseconds=1), "deadline"),
    ),
    ids=("before-close", "at-close", "after-close"),
)
@pytest.mark.parametrize("retry", (False, True), ids=("direct", "retry"))
def test_exact_close_converges_after_public_ssh_application_watermark(
    watermark_delta: timedelta,
    expected_reason: str,
    retry: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public SSH watermark cannot orphan the exact deferred close journal."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, fixture.generator).execute()
    manager = fixture.generator._ssh_channel_manager
    registry = manager.application_registry
    continuation = fixture.generator._pending_ssh_session_closures[0]
    session = manager.find_by_transport(continuation.transaction.stable_id)
    assert session is not None
    open_snapshot = registry.get(session.channel_id)
    assert open_snapshot is not None
    target_session = fixture.state.get_session(session.binding.logon_id)
    assert target_session is not None
    assert target_session.transport_pid is not None
    receiver_pid = target_session.transport_pid

    fixture.generator.advance_application_channel_watermark(
        continuation.transaction.closed_at + watermark_delta
    )
    watermarked_snapshot = registry.get(session.channel_id)
    assert watermarked_snapshot is not None
    assert watermarked_snapshot.identity == open_snapshot.identity
    if expected_reason == "deadline":
        assert manager.session_view(session.channel_id) is None
        assert watermarked_snapshot.closed_at == session.transport.closes_at
        assert watermarked_snapshot.close_reason == "deadline"
    else:
        assert manager.session_view(session.channel_id) == session
        assert watermarked_snapshot.is_open

    attempts = 0
    original = SshSessionActionBundle._terminate_receiver_session_children

    def fail_after_application_retirement(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if retry and attempts == 1:
            raise OSError("post-watermark close retry")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        SshSessionActionBundle,
        "_terminate_receiver_session_children",
        fail_after_application_retirement,
    )

    if retry:
        with pytest.raises(OSError, match="post-watermark close retry"):
            fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
        assert fixture.generator.ssh_close_journal_census().exact_pending == 1
        assert fixture.state.get_session(target_session.logon_id) is not None
        assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert attempts == (2 if retry else 1)
    assert manager.session_view(session.channel_id) is None
    retired_snapshot = registry.get(session.channel_id)
    assert retired_snapshot is not None
    assert retired_snapshot.identity == open_snapshot.identity
    assert retired_snapshot.closed_at == session.transport.closes_at
    assert retired_snapshot.close_reason == expected_reason
    assert fixture.state.get_session(target_session.logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    fixture.generator.assert_ssh_session_lifecycles_drained()
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


@pytest.mark.parametrize("threaded", (False, True), ids=("direct", "threaded"))
def test_world_planner_real_ssh_bootstrap_uses_exact_bridge_and_defers_close(
    threaded: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The baseline/storyline WorldPlanner caller enters the exact open bridge."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path, threaded=threaded)
    world = SimpleNamespace(hosts={fixture.source.hostname: SimpleNamespace(os_category="windows")})
    planner = WorldPlanner(world, fixture.state, fixture.generator)  # type: ignore[arg-type]
    plan = SessionPlan(
        target_system=fixture.target,
        source_system=fixture.source,
        source_ip=fixture.source.ip,
        logon_type=10,
        session_kind="ssh",
        requires_transport=True,
    )
    original = GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication
    bridge_calls = 0

    def capture_bridge(
        authority: GeneratorLifecycleAuthority,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal bridge_calls
        bridge_calls += 1
        return original(authority, *args, **kwargs)

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "materialize_prepared_deferred_session_publication",
        capture_bridge,
    )
    result = planner._bootstrap_ssh_session(
        fixture.user,
        plan,
        _START,
        _START + timedelta(minutes=5),
        random.Random(9),
        required_until=_START + timedelta(minutes=10),
    )

    assert bridge_calls == 1
    assert result.network_uid
    assert result.session.session_kind == "ssh"
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 1
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    assert result.session.network_close_time is not None
    fixture.generator.finalize_ssh_session_lifecycles(
        result.session.network_close_time + timedelta(seconds=10)
    )
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_sessions] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


def test_exact_ssh_open_preserves_unresolved_source_process_compatibility(tmp_path: Path) -> None:
    """An unresolved authored source process stays on the compatibility path."""

    fixture = _fixture(tmp_path)
    request = replace(
        fixture.request(),
        source_pid=4_321,
        source_process_image=r"C:\Windows\System32\OpenSSH\ssh.exe",
    )

    assert not SshSessionActionBundle(
        request,
        fixture.generator,
    )._uses_exact_deferred_publication()
    fixture.ecar.close()
    fixture.zeek.close()


def test_storyline_scp_shape_uses_existing_source_process_in_exact_bridge(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The modeled-process SCP caller binds, rather than reinvents, its source actor."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    source_logon = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    source_image = r"C:\Windows\System32\OpenSSH\scp.exe"
    source_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        source_logon,
        source_image,
        f"{source_image} report.csv {fixture.target.ip}:/tmp/report.csv",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    request = replace(
        fixture.request(),
        time=_START + timedelta(seconds=2),
        source_pid=source_pid,
        source_process_image=source_image,
        source="storyline_scp",
        emit_session_close=True,
        defer_session_close=True,
    )
    original = GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication
    bridge_calls = 0

    def capture_bridge(
        authority: GeneratorLifecycleAuthority,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal bridge_calls
        bridge_calls += 1
        return original(authority, *args, **kwargs)

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "materialize_prepared_deferred_session_publication",
        capture_bridge,
    )
    uid = SshSessionActionBundle(request, fixture.generator).execute()

    assert uid
    assert bridge_calls == 1
    application = fixture.generator._ssh_channel_manager.find_by_transport(
        fixture.generator._last_connection_effective_transaction_id
    )
    assert application is not None
    assert application.transport.source_process is not None
    assert application.transport.source_process.pid == source_pid
    assert application.transport.source_process.process_object_id
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.generator.finalize_ssh_session_lifecycles(
        application.transport.closes_at + timedelta(seconds=10)
    )
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator._pending_ssh_session_closures == []
    ecar_rows, zeek_rows = fixture.close_and_read()
    source_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.source.hostname and row.get("object") == "FLOW"
    ]
    assert source_flows
    assert source_flows[0]["pid"] == source_pid
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("ended_owner", ("process", "session"))
def test_ended_explicit_scp_owner_stays_on_compatibility_path(
    ended_owner: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained-but-ended actor cannot enter the exact source-owner graph."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    source_logon = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    source_image = r"C:\Windows\System32\OpenSSH\scp.exe"
    source_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        source_logon,
        source_image,
        f"{source_image} report.csv {fixture.target.ip}:/tmp/report.csv",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    if ended_owner == "process":
        fixture.generator.generate_process_termination(
            fixture.user,
            fixture.source,
            _START + timedelta(seconds=2),
            source_pid,
            source_image,
            source_logon,
        )
        assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
        assert fixture.state.get_session(source_logon) is not None
    else:
        fixture.generator.generate_logoff(
            fixture.user,
            fixture.source,
            _START + timedelta(seconds=2),
            source_logon,
            logon_type=3,
        )
        assert fixture.state.get_session(source_logon) is None
    assert fixture.state.get_process_identity(fixture.source.hostname, source_pid) is not None

    request = replace(
        fixture.request(),
        time=_START + timedelta(seconds=3),
        source_pid=source_pid,
        source_process_image=source_image,
        source="storyline_scp",
    )
    bundle = SshSessionActionBundle(request, fixture.generator)
    bridge_calls = 0
    original = GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication

    def capture_bridge(
        authority: GeneratorLifecycleAuthority,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal bridge_calls
        bridge_calls += 1
        return original(authority, *args, **kwargs)

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "materialize_prepared_deferred_session_publication",
        capture_bridge,
    )

    assert not bundle._uses_exact_deferred_publication()
    assert bundle.execute()
    assert bridge_calls == 0
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows
    assert zeek_rows
    assert any(row["id.resp_p"] == 22 for row in zeek_rows)


def test_exact_ssh_receiver_preserves_live_global_sshd_parent_and_system_token(
    tmp_path: Path,
) -> None:
    """The exact per-session worker retains its canonical daemon parent and token."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    systemd_pid = fixture.generator.generate_system_process(
        fixture.target,
        _START - timedelta(seconds=10),
        "/usr/lib/systemd/systemd",
        "/usr/lib/systemd/systemd --system",
        parent_pid=0,
        username="root",
        emit_linux_syslog=False,
    )
    global_sshd_pid = fixture.generator.generate_system_process(
        fixture.target,
        _START - timedelta(seconds=9),
        "/usr/sbin/sshd",
        "/usr/sbin/sshd -D",
        parent_pid=systemd_pid,
        username="root",
        emit_linux_syslog=False,
    )
    fixture.generator._system_pids = {
        fixture.target.hostname: {"systemd": systemd_pid, "sshd": global_sshd_pid}
    }
    global_identity = fixture.state.get_process_identity(
        fixture.target.hostname,
        global_sshd_pid,
    )
    assert global_identity is not None
    assert (
        fixture.generator._lifecycle_authority.registry.get_process(global_identity.object_id)
        is not None
    )

    _, logon_id = SshSessionActionBundle(
        fixture.request(),
        fixture.generator,
    ).execute_with_identity()

    session = fixture.state.get_session(logon_id)
    assert session is not None and session.transport_pid is not None
    receiver = fixture.state.get_process(fixture.target.hostname, session.transport_pid)
    assert receiver is not None
    assert receiver.parent_pid == global_sshd_pid
    assert receiver.username == "root"
    assert receiver.integrity_level == "System"
    ecar_rows, zeek_rows = fixture.close_and_read()
    receiver_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname
        and row.get("object") == "PROCESS"
        and row.get("pid") == receiver.pid
        and row.get("action") == "CREATE"
    ]
    assert len(receiver_rows) == 1
    assert receiver_rows[0]["ppid"] == global_sshd_pid
    assert receiver_rows[0]["principal"] == "root"
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("runtime_kind", ("copied", "foreign", "stale"))
def test_exact_ssh_rejects_noncanonical_timing_runtime_before_state(
    runtime_kind: str,
    tmp_path: Path,
) -> None:
    """Preview and replay must share the exact engine-owned timing runtime."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    canonical = fixture.generator._source_timing_planner.timing_runtime
    assert fixture.generator.dispatcher.timing_runtime is canonical
    if runtime_kind == "copied":
        candidate = copy(canonical)
    else:
        candidate = TimingRuntime(reference_time=_START)
        if runtime_kind == "stale":
            candidate.audit.record_sample("ssh.test.stale", "constant")
    assert candidate is not canonical
    fixture.generator.timing_runtime = candidate
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._source_timing_planner.state_digest(),
        canonical.state_digest(),
        candidate.state_digest(),
    )

    with pytest.raises(StateError, match="share one exact TimingRuntime"):
        _execute_real_caller(fixture)

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._source_timing_planner.state_digest(),
        canonical.state_digest(),
        candidate.state_digest(),
    )
    assert after == before
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize("owner_slot", ("dispatcher", "planner"))
def test_exact_ssh_rejects_split_timing_owner_before_state(
    owner_slot: str,
    tmp_path: Path,
) -> None:
    """The dispatcher and SourceTiming planner cannot split from the engine runtime."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    canonical = fixture.generator.timing_runtime
    foreign = TimingRuntime(reference_time=_START)
    if owner_slot == "dispatcher":
        fixture.generator.dispatcher.timing_runtime = foreign
    else:
        fixture.generator._source_timing_planner.timing_runtime = foreign
    before = (
        fixture.state.materialization_digest(),
        canonical.state_digest(),
        foreign.state_digest(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
    )

    with pytest.raises(StateError, match="share one exact TimingRuntime"):
        _execute_real_caller(fixture)

    after = (
        fixture.state.materialization_digest(),
        canonical.state_digest(),
        foreign.state_digest(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
    )
    assert after == before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_exact_ssh_timing_authority_rejects_foreign_runtime_at_use(
    tmp_path: Path,
) -> None:
    """A prepared authority cannot replace its runtime owner before replay."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    foreign = TimingRuntime(reference_time=_START)
    object.__setattr__(prepared.authority, "ssh_timing_runtime", foreign)
    before = (
        fixture.state.materialization_digest(),
        fixture.generator.timing_runtime.state_digest(),
        foreign.state_digest(),
    )

    with pytest.raises(StateError, match="changed its runtime owner"):
        bundle._open_deferred_transport(transport, prepared)

    after = (
        fixture.state.materialization_digest(),
        fixture.generator.timing_runtime.state_digest(),
        foreign.state_digest(),
    )
    assert after == before
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_unsupported_required_target_rejects_before_state(
    tmp_path: Path,
) -> None:
    """A non-exact required source cannot activate after canonical mutation."""

    reset_thread_rng(42)
    unsupported = Mock()
    unsupported.can_handle.return_value = True
    fixture = _fixture(tmp_path, extra_emitters={"syslog": unsupported})
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
    )
    timing_before = fixture.generator._source_timing_planner.census()
    timing_runtime_before = fixture.generator.timing_runtime.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        _execute_real_caller(fixture)

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
    )
    assert after == before
    timing_after = fixture.generator._source_timing_planner.census()
    assert timing_after.live_entries == timing_before.live_entries == 0
    assert timing_after.backing_entries == timing_before.backing_entries == 0
    assert timing_after.stale_entries == timing_before.stale_entries == 0
    assert timing_after.watermark == timing_before.watermark
    assert fixture.generator.timing_runtime.state_digest() == timing_runtime_before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    assert unsupported.emit.call_count == 0
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_exact_member_capacity_rejects_neutrally(tmp_path: Path) -> None:
    """The root plus two dependents reserve capacity before State publication."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path, member_capacity=2)
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()

    with pytest.raises(StateError, match="member capacity is exhausted"):
        _execute_real_caller(fixture)

    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_dependent_tamper_rejects_before_state(tmp_path: Path) -> None:
    """A copied inert dependent with changed timing cannot enter the network boundary."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    session_spec = prepared.authority.dependent_occurrences[1]
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()
    object.__setattr__(
        session_spec,
        "canonical_time",
        prepared.session_plan.identity.started_at - timedelta(microseconds=1),
    )

    with pytest.raises(StateError, match="authority changed before timing replay"):
        bundle._open_deferred_transport(transport, prepared)

    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_dependent_role_ordinal_swap_rejects_before_state(tmp_path: Path) -> None:
    """Contiguous ordinals cannot be reassigned across the process/login roles."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    process_spec, session_spec = prepared.authority.dependent_occurrences
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()
    object.__setattr__(
        prepared.authority,
        "dependent_occurrences",
        (
            replace(session_spec, publication_ordinal=1),
            replace(process_spec, publication_ordinal=2),
        ),
    )

    with pytest.raises(StateError, match="authority changed before timing replay"):
        bundle._open_deferred_transport(transport, prepared)

    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_real_ssh_timing_preview_tamper_rejects_without_audit_residue(
    tmp_path: Path,
) -> None:
    """Previewed auth timing must replay exactly inside the shared timing owner."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    timing_intent = prepared.authority.ssh_timing_intent
    assert timing_intent is not None
    object.__setattr__(
        timing_intent,
        "expected_plan",
        replace(
            timing_intent.expected_plan,
            pam_gap_ms=timing_intent.expected_plan.pam_gap_ms + 1.0,
            logind_gap_ms=timing_intent.expected_plan.logind_gap_ms - 1.0,
        ),
    )
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()

    with pytest.raises(StateError, match="replay disagrees with its previewed plan"):
        bundle._open_deferred_transport(transport, prepared)

    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize("malformation", ("copied", "foreign", "stale"))
def test_real_ssh_authority_malformation_rejects_without_residue(
    malformation: str,
    tmp_path: Path,
) -> None:
    """Copied, foreign-owner, and stale production handoffs fail before publication."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path / "primary")
    bundle = SshSessionActionBundle(fixture.request(), fixture.generator)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    foreign_fixture: _RealSshFixture | None = None
    if malformation == "copied":
        prepared.authority.bind_strict_state_authority(fixture.state)
        prepared = replace(prepared, authority=copy(prepared.authority))
    elif malformation == "foreign":
        foreign_fixture = _fixture(tmp_path / "foreign")
        assert prepared.authority.application_intent is not None
        prepared = replace(
            prepared,
            authority=replace(
                prepared.authority,
                application_intent=replace(
                    prepared.authority.application_intent,
                    manager=foreign_fixture.generator._ssh_channel_manager,
                ),
            ),
        )
    else:
        fixture.state.set_current_time(_START + timedelta(seconds=1))
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()

    with pytest.raises(StateError):
        bundle._open_deferred_transport(transport, prepared)

    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    if foreign_fixture is not None:
        foreign_census = foreign_fixture.generator._ssh_channel_manager.census()
        assert foreign_census.open_sessions == 0
        assert foreign_census.application.prepared_admissions == 0
        assert foreign_census.application.claimed_admissions == 0
        foreign_fixture.ecar.close()
        foreign_fixture.zeek.close()
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize(
    ("owner_name", "owner_type", "method_name"),
    (
        (
            "lifecycle",
            PreparedLifecycleClosedTransportPublication,
            "commit_no_fail",
        ),
        (
            "state",
            StateManager,
            "_commit_claimed_connection_composite_materialization",
        ),
        ("application", SshChannelPreparedCommit, "commit_no_fail"),
        ("runtime", NetworkTransactionPreparedCommit, "commit_no_fail"),
        ("timing", SourceTimingPreparation, "commit_no_fail"),
    ),
)
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_real_ssh_each_canonical_owner_recovers_before_source_publication(
    owner_name: str,
    owner_type: type[object],
    method_name: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real caller retries or adopts every canonical owner exactly once."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    original = getattr(owner_type, method_name)
    attempts = 0

    def inject(*args: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(*args)
            raise OSError(f"injected {owner_name} {failure_mode}")
        return original(*args)

    monkeypatch.setattr(owner_type, method_name, inject)
    uid, _ = _execute_real_caller(fixture)

    assert uid
    assert attempts == (2 if failure_mode == "fail-before" else 1)
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert sum(row.get("object") == "USER_SESSION" for row in ecar_rows) == 1
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("sink_name", ("ecar", "zeek"))
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_real_ssh_sink_failure_retains_one_exact_recovery(
    sink_name: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sink failure after canonical commit resumes without duplicate bytes."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def inject(
        writer: ExternalSortedLineWriter,
        key: object,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        is_target = (
            writer.output_path.name == "ecar.json"
            if sink_name == "ecar"
            else writer.output_path.name == "zeek_conn.json"
        )
        if is_target and attempts == 0:
            attempts += 1
            if failure_mode == "lost-return":
                original(writer, key, digest, frozen)
            raise OSError(f"injected {sink_name} {failure_mode}")
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", inject)
    with pytest.raises(OSError, match=f"{sink_name} {failure_mode}"):
        _execute_real_caller(fixture)

    assert (
        fixture.generator.ssh_responder_pid_for_tuple(
            fixture.source.ip,
            50_001,
            fixture.target.ip,
        )
        is not None
    )
    assert (
        fixture.generator.ssh_session_ready_time_for_tuple(
            fixture.source.ip,
            50_001,
            fixture.target.ip,
        )
        is not None
    )
    assert (
        fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    )
    results = fixture.generator.dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert sum(row.get("object") == "USER_SESSION" for row in ecar_rows) == 1
    assert len(zeek_rows) == 1


@pytest.mark.parametrize(
    "terminal_kind",
    ("source-terminate", "receiver-terminate", "target-logout"),
)
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_close_retries_terminal_sink_from_retained_receipt_not_missing_state(
    terminal_kind: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terminal sink retry authenticates retained facts before any consumed State owner."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    window_end = _START + timedelta(days=1)
    request = replace(
        request,
        duration=(window_end - request.time - timedelta(milliseconds=3_500)).total_seconds(),
    )
    original_sink = ExternalSortedLineWriter._commit_exact_row
    attempts = 0
    receiver_pid = -1

    def fail_terminal_row(
        writer: ExternalSortedLineWriter,
        key: object,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        row = json.loads(frozen) if writer.output_path.name == "ecar.json" else {}
        is_target = (
            (
                terminal_kind == "source-terminate"
                and row.get("hostname") == fixture.source.hostname
                and row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("pid") == source_pid
            )
            or (
                terminal_kind == "receiver-terminate"
                and row.get("hostname") == fixture.target.hostname
                and row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("pid") == receiver_pid
            )
            or (
                terminal_kind == "target-logout"
                and row.get("hostname") == fixture.target.hostname
                and row.get("object") == "USER_SESSION"
                and row.get("action") == "LOGOUT"
            )
        )
        if is_target and attempts == 0:
            attempts += 1
            if failure_mode == "lost-return":
                original_sink(writer, key, digest, frozen)
            raise OSError(f"{terminal_kind} {failure_mode}")
        original_sink(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_terminal_row)
    bundle = SshSessionActionBundle(request, fixture.generator)
    if terminal_kind == "source-terminate":
        with pytest.raises(OSError, match=f"{terminal_kind} {failure_mode}") as raised:
            bundle.execute_with_identity()
        target_sessions = [
            session
            for session in fixture.state.get_sessions_for_user(fixture.user.username)
            if session.system == fixture.target.hostname
        ]
        assert len(target_sessions) == 1
        logon_id = target_sessions[0].logon_id
        assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
    else:
        _uid, logon_id = bundle.execute_with_identity()
        live_target = fixture.state.get_session(logon_id)
        assert live_target is not None
        receiver_pid = live_target.transport_pid or -1
        with pytest.raises(OSError, match=f"{terminal_kind} {failure_mode}") as raised:
            fixture.generator.finalize_ssh_session_lifecycles(window_end)
        if terminal_kind == "receiver-terminate":
            assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
            assert fixture.state.get_session(logon_id) is not None
        else:
            assert fixture.state.get_session(logon_id) is None

    assert str(raised.value) == f"{terminal_kind} {failure_mode}"
    receipt = getattr(raised.value, "action_cohort_receipt", None)
    result = getattr(raised.value, "action_cohort_result", None)
    assert receipt is not None
    assert result is not None
    assert result.receipt is receipt
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    recovery = fixture.generator.dispatcher.exact_projection_recovery_census()
    assert recovery.unresolved_recoveries == 1
    resumed = fixture.generator.dispatcher.drain_exact_projection_recoveries()
    assert len(resumed) == 1
    assert resumed[0] is result

    if terminal_kind == "source-terminate":
        original_get_process = StateManager.get_process

        def reject_consumed_source_read(
            manager: StateManager,
            hostname: str,
            pid: int,
        ) -> object:
            if hostname == fixture.source.hostname and pid == source_pid:
                raise AssertionError("retry consulted consumed source process State")
            return original_get_process(manager, hostname, pid)

        monkeypatch.setattr(StateManager, "get_process", reject_consumed_source_read)
    elif terminal_kind == "receiver-terminate":
        original_get_process = StateManager.get_process

        def reject_consumed_receiver_read(
            manager: StateManager,
            hostname: str,
            pid: int,
        ) -> object:
            if hostname == fixture.target.hostname and pid == receiver_pid:
                raise AssertionError("retry consulted consumed receiver process State")
            return original_get_process(manager, hostname, pid)

        monkeypatch.setattr(StateManager, "get_process", reject_consumed_receiver_read)
    else:
        original_get_session = StateManager.get_session

        def reject_consumed_session_read(manager: StateManager, candidate: str) -> object:
            if candidate == logon_id:
                raise AssertionError("retry consulted consumed target session State")
            return original_get_session(manager, candidate)

        monkeypatch.setattr(StateManager, "get_session", reject_consumed_session_read)

    fixture.generator.finalize_ssh_session_lifecycles(window_end)

    assert fixture.generator._pending_ssh_session_closures == []
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    source_terminates = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.source.hostname
        and row.get("object") == "PROCESS"
        and row.get("action") == "TERMINATE"
        and row.get("pid") == source_pid
    ]
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert len(source_terminates) == 1
    assert [row["action"] for row in target_sessions] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("terminal_kind", ("source-terminate", "target-logout"))
def test_exact_close_retries_action_claim_context_lost_return(
    terminal_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed cohort remains receipt-backed when its owner context loses return."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    original = EventDispatcher.claimed_action_cohort
    target_phase = "source-terminate" if terminal_kind == "source-terminate" else "logout"
    expected_message = f"{terminal_kind} claim lost-return"
    injected = False

    @contextmanager
    def lose_claim_return(
        dispatcher: EventDispatcher,
        batch: object,
    ) -> Iterator[object]:
        nonlocal injected
        with original(dispatcher, batch) as capability:
            yield capability
        root_action_id = object.__getattribute__(batch, "_root_action_id")
        if not injected and root_action_id.endswith(f":{target_phase}"):
            injected = True
            raise OSError(expected_message)

    monkeypatch.setattr(EventDispatcher, "claimed_action_cohort", lose_claim_return)
    bundle = SshSessionActionBundle(request, fixture.generator)
    if terminal_kind == "source-terminate":
        with pytest.raises(OSError, match=expected_message) as raised:
            bundle.execute_with_identity()
    else:
        _uid, logon_id = bundle.execute_with_identity()
        with pytest.raises(OSError, match=expected_message) as raised:
            fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
        assert fixture.state.get_session(logon_id) is None

    assert str(raised.value) == expected_message
    receipt = getattr(raised.value, "action_cohort_receipt", None)
    result = getattr(raised.value, "action_cohort_result", None)
    assert receipt is not None
    assert result is not None
    assert result.receipt is receipt
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    # Every sink succeeded before the owner context lost its return, so the
    # dispatcher has no failed projection to drain.  The journal still retains
    # and authenticates that exact successful result before consulting State.
    assert (
        fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    )

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
    assert fixture.generator._pending_ssh_session_closures == []
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_rows] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


def test_exact_close_rejects_forged_terminal_commit_return_and_reuses_canonical_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged postcommit return cannot replace the source phase's exact result."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    original = PreparedActionCohortCapability.commit_no_fail

    def forge_source_return(capability: PreparedActionCohortCapability) -> object:
        result = original(capability)
        if result.receipt.root_action_id.endswith(":source-terminate"):
            return object()
        return result

    monkeypatch.setattr(
        PreparedActionCohortCapability,
        "commit_no_fail",
        forge_source_return,
    )

    with pytest.raises(StateError, match="forged cohort result") as raised:
        SshSessionActionBundle(request, fixture.generator).execute_with_identity()

    result = getattr(raised.value, "action_cohort_result", None)
    assert result is not None
    assert result.receipt.root_action_id.endswith(":source-terminate")
    assert (
        fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    )
    _assert_owned_close_recovers(fixture, source_pid=source_pid)


def test_exact_close_rejects_projection_owner_change_before_terminal_state(
    tmp_path: Path,
) -> None:
    """A post-open target swap cannot mutate any due close owner before rejection."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, _source_pid = _modeled_scp_owned_close(fixture)
    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    live_session = fixture.state.get_session(logon_id)
    assert live_session is not None
    receiver_pid = live_session.transport_pid or -1
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.dispatcher.action_cohort_publication_census(),
    )
    fixture.generator.dispatcher.emitters["ecar"] = Mock()

    with pytest.raises(StateError, match="original eCAR/Zeek projection owners"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.dispatcher.action_cohort_publication_census(),
    )
    assert after == before
    assert fixture.state.get_session(logon_id) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    fixture.generator.dispatcher.emitters["ecar"] = fixture.ecar
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.generator._pending_ssh_session_closures == []
    fixture.close_and_read()


def test_exact_close_accepts_stable_full_emitter_topology(tmp_path: Path) -> None:
    """A production-like non-target emitter does not replace the SSH projection owners."""

    reset_thread_rng(42)
    web = WebEmitter(
        load_format("web_access"),
        tmp_path / "web",
        threaded=False,
    )
    fixture = _fixture(
        tmp_path / "ssh",
        extra_emitters={"web_access": web},
    )
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    try:
        _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
        assert fixture.state.get_session(logon_id) is not None

        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

        assert fixture.state.get_session(logon_id) is None
        assert fixture.generator.ssh_close_journal_census().total_pending == 0
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        ecar_rows, zeek_rows = fixture.close_and_read()
        target_rows = [
            row
            for row in ecar_rows
            if row.get("hostname") == fixture.target.hostname
            and row.get("object") == "USER_SESSION"
        ]
        assert [row["action"] for row in target_rows] == ["LOGIN", "LOGOUT"]
        assert len(zeek_rows) == 1
    finally:
        fixture.ecar.close()
        fixture.zeek.close()
        web.close()


def test_exact_close_terminal_capacity_preserves_canonical_owners_and_retry_converges(
    tmp_path: Path,
) -> None:
    """Terminal cohort capacity leaves State/lifecycle retryable under the close journal."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, _source_pid = _modeled_scp_owned_close(fixture)
    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    live_session = fixture.state.get_session(logon_id)
    assert live_session is not None
    receiver_pid = live_session.transport_pid or -1
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator.dispatcher.action_cohort_publication_census(),
    )
    original_capacity = fixture.generator.dispatcher._action_cohort_preparation_capacity
    fixture.generator.dispatcher._action_cohort_preparation_capacity = 0

    with pytest.raises(EventContractError, match="preparation capacity is exhausted"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    fixture.generator.dispatcher._action_cohort_preparation_capacity = original_capacity
    after = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator.dispatcher.action_cohort_publication_census(),
    )
    assert after == before
    assert fixture.state.get_session(logon_id) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


@pytest.mark.parametrize(
    "failure_seam",
    (
        "ecar-fail-before",
        "ecar-lost-return",
        "zeek-fail-before",
        "zeek-lost-return",
        "bridge-lost-return",
    ),
)
def test_committed_exact_ssh_failure_retains_and_recovers_owned_close(
    failure_seam: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A postcommit open failure cannot strand the SSH owner graph or source actor."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    source_logon = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    source_image = r"C:\Windows\System32\OpenSSH\scp.exe"
    source_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        source_logon,
        source_image,
        f"{source_image} report.csv {fixture.target.ip}:/tmp/report.csv",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    request = replace(
        fixture.request(),
        time=_START + timedelta(seconds=2),
        source_pid=source_pid,
        source_process_image=source_image,
        source="storyline_scp",
        emit_session_close=True,
        defer_session_close=True,
    )
    if failure_seam != "bridge-lost-return":
        original_sink = ExternalSortedLineWriter._commit_exact_row
        attempts = 0
        sink_file = "ecar.json" if failure_seam.startswith("ecar-") else "zeek_conn.json"

        def fail_sink(
            writer: ExternalSortedLineWriter,
            key: object,
            digest: str,
            frozen: object,
        ) -> None:
            nonlocal attempts
            if writer.output_path.name == sink_file and attempts == 0:
                attempts += 1
                if failure_seam.endswith("lost-return"):
                    original_sink(writer, key, digest, frozen)
                raise OSError(failure_seam)
            original_sink(writer, key, digest, frozen)

        monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_sink)
    else:
        original_bridge = (
            GeneratorLifecycleAuthority.materialize_prepared_deferred_session_publication
        )

        def lose_bridge_return(
            authority: GeneratorLifecycleAuthority,
            *args: object,
            **kwargs: object,
        ) -> object:
            original_bridge(authority, *args, **kwargs)
            raise OSError(failure_seam)

        monkeypatch.setattr(
            GeneratorLifecycleAuthority,
            "materialize_prepared_deferred_session_publication",
            lose_bridge_return,
        )

    with pytest.raises(OSError, match=failure_seam):
        SshSessionActionBundle(request, fixture.generator).execute()

    target_sessions = [
        session
        for session in fixture.state.get_sessions_for_user(fixture.user.username)
        if session.system == fixture.target.hostname
    ]
    assert len(target_sessions) == 1
    session = target_sessions[0]
    assert session.transport_pid is not None
    receiver_pid = session.transport_pid
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is not None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 1
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    unresolved = (
        fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries
    )
    assert unresolved == (0 if failure_seam == "bridge-lost-return" else 1)
    if unresolved:
        results = fixture.generator.dispatcher.drain_exact_projection_recoveries()
        assert len(results) == 1
        assert all(outcome.status == "succeeded" for outcome in results[0].projections)

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fixture.state.get_session(session.logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_sessions] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("failure_mode", ("false", "fail-before", "lost-return"))
def test_committed_second_receipt_authentication_preserves_capture_and_close(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The planner's postcommit receipt check cannot release transport/close recovery."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    original = GeneratorLifecycleAuthority.authenticates_prepared_network_receipt
    calls = 0

    def inject(*args: object, **kwargs: object) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            if failure_mode == "false":
                return False
            if failure_mode == "fail-before":
                raise OSError("second receipt auth fail-before")
            original(*args, **kwargs)
            raise OSError("second receipt auth lost-return")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        GeneratorLifecycleAuthority,
        "authenticates_prepared_network_receipt",
        inject,
    )
    expected_type = AssertionError if failure_mode == "false" else OSError
    expected_message = (
        "Prepared network authority returned an invalid receipt"
        if failure_mode == "false"
        else f"second receipt auth {failure_mode}"
    )

    with pytest.raises(expected_type, match=expected_message) as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert str(raised.value) == expected_message
    assert calls == 2
    _assert_owned_close_recovers(fixture, source_pid=source_pid)


@pytest.mark.parametrize("failure_mode", ("no-op", "forged-return"))
def test_committed_capture_publication_postcondition_retains_close_recovery(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A false private publish cannot release the claim for a committed SSH owner."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)

    def inject(*_args: object, **_kwargs: object) -> object | None:
        return object() if failure_mode == "forged-return" else None

    monkeypatch.setattr(
        NetworkConnectionIdentityCapture,
        "_publish_committed_claimed",
        inject,
    )
    expected_message = (
        "forged publication result"
        if failure_mode == "forged-return"
        else "did not publish its exact committed owner"
    )

    with pytest.raises(StateError, match=expected_message) as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert expected_message in str(raised.value)
    _assert_owned_close_recovers(fixture, source_pid=source_pid)


@pytest.mark.parametrize(
    ("owner_type", "method_name", "seam_name"),
    (
        (ActivityGenerator, "_remember_ssh_responder_pid", "responder-cache"),
        (ActivityGenerator, "_remember_ssh_session_ready_time", "readiness-cache"),
        (ActivityGenerator, "_defer_ssh_session_close", "close-journal"),
        (SshSessionActionBundle, "_terminate_source_ssh_client_process", "source-teardown"),
    ),
)
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_committed_postopen_seam_installs_close_before_fallible_followups(
    owner_type: type[object],
    method_name: str,
    seam_name: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Caches, journal installation, and source teardown cannot strand exact SSH owners."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    original = getattr(owner_type, method_name)
    attempts = 0
    expected_message = f"{seam_name} {failure_mode}"

    def inject(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(*args, **kwargs)
            raise OSError(expected_message)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner_type, method_name, inject)

    with pytest.raises(OSError, match=expected_message) as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert str(raised.value) == expected_message
    _assert_owned_close_recovers(fixture, source_pid=source_pid)


def test_committed_capture_recovery_does_not_consult_fallible_state_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recovery-only State read cannot mask the primary postcommit exception."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    original_get_session = StateManager.get_session
    state_failure_enabled = False

    def fail_journal(*_args: object, **_kwargs: object) -> None:
        nonlocal state_failure_enabled
        state_failure_enabled = True
        raise OSError("journal-primary")

    def fail_recovery_read(manager: StateManager, logon_id: str) -> object:
        if state_failure_enabled:
            raise RuntimeError("commit-probe-masked")
        return original_get_session(manager, logon_id)

    monkeypatch.setattr(ActivityGenerator, "_defer_ssh_session_close", fail_journal)
    monkeypatch.setattr(StateManager, "get_session", fail_recovery_read)

    with pytest.raises(OSError, match="journal-primary") as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert str(raised.value) == "journal-primary"
    state_failure_enabled = False
    _assert_owned_close_recovers(fixture, source_pid=source_pid)


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_close_event_is_prebuilt_before_any_canonical_mutation(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Close-event construction failure remains a completely precommit rejection."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    request, source_pid = _modeled_scp_owned_close(fixture)
    before = fixture.state.materialization_digest()
    timing_before = fixture.generator.timing_runtime.state_digest()
    original = SshSessionActionBundle._build_session_event
    calls = 0
    expected_message = f"close-event {failure_mode}"

    def inject(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        if calls == 1:
            if failure_mode == "lost-return":
                original(*args, **kwargs)
            raise OSError(expected_message)
        return original(*args, **kwargs)

    monkeypatch.setattr(SshSessionActionBundle, "_build_session_event", inject)

    with pytest.raises(OSError, match=expected_message) as raised:
        SshSessionActionBundle(request, fixture.generator).execute()

    assert str(raised.value) == expected_message
    assert fixture.state.materialization_digest() == before
    assert fixture.generator.timing_runtime.state_digest() == timing_before
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is not None
    assert not [
        session
        for session in fixture.state.get_sessions_for_user(fixture.user.username)
        if session.system == fixture.target.hostname
    ]
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    _ecar_rows, zeek_rows = fixture.close_and_read()
    assert zeek_rows == []

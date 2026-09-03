# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Real-caller coverage for exact SSH deferred-session publication."""

from __future__ import annotations

import json
import random
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from copy import copy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortCapability
from evidenceforge.events.lifecycle import ProcessLifecycleSnapshot, SessionEndPlan
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
from evidenceforge.generation.actions.ssh_session import (
    SshSessionActionBundle,
    SshSessionRequest,
    _PreparedSshCloseContinuation,
    _ssh_action_deadline_source_tail,
    ssh_action_deadline_transport_headroom_seconds,
)
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import TimingWindow, get_timing_window
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.checkpoints.activity_head import ActivityGeneratorStateParticipant
from evidenceforge.generation.checkpoints.application_channel_head import (
    ApplicationChannelRegistryParticipant,
)
from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
from evidenceforge.generation.checkpoints.lifecycle_head import LifecycleRegistryParticipant
from evidenceforge.generation.checkpoints.network_runtime_head import (
    NetworkTransactionRuntimeParticipant,
)
from evidenceforge.generation.checkpoints.packed import loads
from evidenceforge.generation.checkpoints.rng import GenerationRngParticipant
from evidenceforge.generation.checkpoints.source_timing_head import SourceTimingPlannerParticipant
from evidenceforge.generation.checkpoints.ssh_channel_head import (
    SshApplicationChannelParticipant,
)
from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
from evidenceforge.generation.checkpoints.timing_runtime_head import TimingRuntimeParticipant
from evidenceforge.generation.emitters.base import ExactPublicationAuthority, ExactPublicationBatch
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.web import WebEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import (
    PreparedLifecycleClosedTransportPublication,
)
from evidenceforge.generation.network_observation import NetworkObservationPlanner
from evidenceforge.generation.network_runtime import NetworkTransactionPreparedCommit
from evidenceforge.generation.process_runtime_cache import (
    ActivityGeneratorSessionRetentionRelease,
)
from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelClosure,
    SshChannelPreparedCommit,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.generation.world_model import SessionPlan, WorldPlanner
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import reset_thread_rng

pytestmark = pytest.mark.slow

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
_TERMINAL_PROCESS_RELATIONSHIPS = frozenset(
    {
        "source.ecar_process_create",
        "source.ecar_process_terminate",
        "source.windows_security_process_create",
        "source.windows_security_process_terminate",
        "source.sysmon_process_create",
        "source.sysmon_process_terminate",
    }
)


def _install_terminal_process_latency_overlay(
    monkeypatch: pytest.MonkeyPatch,
    *,
    latency_ms: float = 60_000,
    dependent_gap_ms: float = 10_000,
) -> None:
    """Install one schema-valid process-termination relationship overlay."""

    original = get_timing_window

    def overlay_window(key: str, **kwargs: object) -> TimingWindow:
        if key in _TERMINAL_PROCESS_RELATIONSHIPS:
            return TimingWindow(
                min_ms=latency_ms,
                max_ms=latency_ms,
                position="after",
            )
        if key == "windows.logoff_after_rendered_dependents":
            return TimingWindow(
                min_ms=dependent_gap_ms,
                max_ms=dependent_gap_ms,
                position="after",
            )
        return original(key, **kwargs)

    monkeypatch.setattr(
        "evidenceforge.generation.source_timing.get_timing_window",
        overlay_window,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session.get_timing_window",
        overlay_window,
    )


def _install_asymmetric_terminal_process_latency_overlay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Make only Sysmon termination slower than every endpoint session source."""

    original = get_timing_window

    def overlay_window(key: str, **kwargs: object) -> TimingWindow:
        if key == "source.sysmon_process_terminate":
            return TimingWindow(min_ms=60_000, max_ms=60_000, position="after")
        if key == "windows.logoff_after_rendered_dependents":
            return TimingWindow(min_ms=10_000, max_ms=10_000, position="after")
        return original(key, **kwargs)

    monkeypatch.setattr(
        "evidenceforge.generation.source_timing.get_timing_window",
        overlay_window,
    )
    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session.get_timing_window",
        overlay_window,
    )


def _fixed_observation_policy(**source_delay_ms: int) -> ObservationPolicy:
    """Return an isolated complete policy with fixed source-family delays."""

    policy = ObservationPolicy("complete")
    policy.default = dict(policy.default)
    policy.sources = dict(policy.sources)
    for source, delay_ms in source_delay_ms.items():
        policy.sources[source] = {
            "delay_ms": {
                "min_ms": delay_ms,
                "max_ms": delay_ms,
            }
        }
    return policy


def _syslog_render_times(root: Path) -> tuple[datetime, ...]:
    """Parse RFC 5424 timestamps from one concrete Syslog output tree."""

    return tuple(
        datetime.fromisoformat(line.split(" ", 2)[1].replace("Z", "+00:00"))
        for output in root.rglob("syslog.log")
        for line in output.read_text(encoding="utf-8").splitlines()
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
    clock_profile_name: str = "complete",
    production_timing_runtime: bool = False,
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
    source_timing_planner = (
        SourceTimingPlanner(
            clock_profile_name=clock_profile_name,
            timing_runtime=TimingRuntime(
                reference_time=_START - timedelta(days=1),
                namespace="ssh-deferred-production",
            ),
        )
        if production_timing_runtime or clock_profile_name != "complete"
        else None
    )
    dispatcher = EventDispatcher(
        state,
        emitters,  # type: ignore[arg-type]
        output_start_time=output_start_time,
        action_cohort_member_capacity=member_capacity,
        source_timing_planner=source_timing_planner,
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


def test_ssh_checkpoint_rebinds_future_close_to_fresh_authorities(tmp_path: Path) -> None:
    """Hydration reconstructs untouched SSH close work against fresh runtime owners."""

    original = _fixture(tmp_path / "original")
    request = replace(
        original.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, original.generator).execute()
    SourceTimingPlannerParticipant(original.generator._source_timing_planner).prepare_checkpoint(0)
    LifecycleRegistryParticipant(
        original.generator._lifecycle_authority.registry
    ).prepare_checkpoint(0)
    original.generator._scenario_environment = SimpleNamespace(
        systems=[original.source, original.target],
        users=[original.user],
    )
    state_seal = StateManagerParticipant(original.state).prepare_checkpoint(0)
    application_seal = ApplicationChannelRegistryParticipant(
        original.generator._application_channel_registry
    ).prepare_checkpoint(0)
    ssh_seal = SshApplicationChannelParticipant(
        original.generator._ssh_channel_manager
    ).prepare_checkpoint(0)
    activity_seal = ActivityGeneratorStateParticipant(original.generator).prepare_checkpoint(0)

    fresh = _fixture(tmp_path / "fresh")
    fresh.generator._scenario_environment = SimpleNamespace(
        systems=[fresh.source, fresh.target],
        users=[fresh.user],
    )
    StateManagerParticipant(fresh.state).restore_checkpoint(
        state_seal.head.payload,
        tuple(segment.payload for segment in state_seal.segments),
    )
    ApplicationChannelRegistryParticipant(
        fresh.generator._application_channel_registry
    ).restore_checkpoint(application_seal.head.payload, ())
    SshApplicationChannelParticipant(fresh.generator._ssh_channel_manager).restore_checkpoint(
        ssh_seal.head.payload,
        (),
    )
    restored_activity = ActivityGeneratorStateParticipant(fresh.generator)
    restored_activity.restore_checkpoint(activity_seal.head.payload, ())

    original_document = loads(activity_seal.head.payload)
    restored_document = loads(restored_activity.prepare_checkpoint(1).head.payload)
    assert isinstance(original_document, dict)
    assert isinstance(restored_document, dict)
    assert restored_document["ssh_lifecycles"] == original_document["ssh_lifecycles"]
    assert fresh.generator.ssh_close_journal_census().exact_pending == 1
    restored = fresh.generator._pending_ssh_session_closures[0]
    assert restored.prepared.ssh_manager_owner is fresh.generator._ssh_channel_manager
    assert restored.prepared.dispatcher_owner is fresh.generator.dispatcher

    original.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    original.close_and_read()
    fresh.close_and_read()


def test_legacy_ssh_checkpoint_resume_is_byte_identical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compatibility close hydrates from semantic facts without retaining its open event."""

    monkeypatch.setattr(
        SshSessionActionBundle,
        "_uses_exact_deferred_publication",
        lambda _bundle: False,
    )
    reset_thread_rng(42)
    original = _fixture(tmp_path / "original")
    original.generator._scenario_environment = SimpleNamespace(
        systems=[original.source, original.target],
        users=[original.user],
    )
    for emitter in original.generator.dispatcher.emitters.values():
        emitter.enable_incremental_checkpointing()
    request = replace(
        original.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    SshSessionActionBundle(request, original.generator).execute()
    assert original.generator.ssh_close_journal_census().legacy_pending == 1
    for emitter in original.generator.dispatcher.emitters.values():
        emitter.flush()

    state_seal = StateManagerParticipant(original.state).prepare_checkpoint(0)
    timing_seal = TimingRuntimeParticipant(original.generator.timing_runtime).prepare_checkpoint(0)
    source_timing_seal = SourceTimingPlannerParticipant(
        original.generator._source_timing_planner
    ).prepare_checkpoint(0)
    lifecycle_seal = LifecycleRegistryParticipant(
        original.generator._lifecycle_authority.registry
    ).prepare_checkpoint(0)
    application_seal = ApplicationChannelRegistryParticipant(
        original.generator._application_channel_registry
    ).prepare_checkpoint(0)
    network_seal = NetworkTransactionRuntimeParticipant(
        original.generator._network_transaction_runtime
    ).prepare_checkpoint(0)
    ssh_seal = SshApplicationChannelParticipant(
        original.generator._ssh_channel_manager
    ).prepare_checkpoint(0)
    activity_seal = ActivityGeneratorStateParticipant(original.generator).prepare_checkpoint(0)
    emitter_seal = EmitterSpoolParticipant(
        emitters=original.generator.dispatcher.emitters,
        output_root=original.ecar_root.parent,
    ).prepare_checkpoint(0)
    rng_seal = GenerationRngParticipant().prepare_checkpoint(0)

    original.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    original_bytes = original.frozen_bytes()

    reset_thread_rng(999)
    fresh = _fixture(tmp_path / "fresh")
    fresh.generator._scenario_environment = SimpleNamespace(
        systems=[fresh.source, fresh.target],
        users=[fresh.user],
    )
    for emitter in fresh.generator.dispatcher.emitters.values():
        emitter.enable_incremental_checkpointing()
    StateManagerParticipant(fresh.state).restore_checkpoint(state_seal.head.payload, ())
    TimingRuntimeParticipant(fresh.generator.timing_runtime).restore_checkpoint(
        timing_seal.head.payload,
        (),
    )
    SourceTimingPlannerParticipant(fresh.generator._source_timing_planner).restore_checkpoint(
        source_timing_seal.head.payload,
        (),
    )
    LifecycleRegistryParticipant(fresh.generator._lifecycle_authority.registry).restore_checkpoint(
        lifecycle_seal.head.payload,
        tuple(segment.payload for segment in lifecycle_seal.segments),
    )
    ApplicationChannelRegistryParticipant(
        fresh.generator._application_channel_registry
    ).restore_checkpoint(application_seal.head.payload, ())
    NetworkTransactionRuntimeParticipant(
        fresh.generator._network_transaction_runtime
    ).restore_checkpoint(network_seal.head.payload, ())
    SshApplicationChannelParticipant(fresh.generator._ssh_channel_manager).restore_checkpoint(
        ssh_seal.head.payload,
        (),
    )
    ActivityGeneratorStateParticipant(fresh.generator).restore_checkpoint(
        activity_seal.head.payload,
        (),
    )
    EmitterSpoolParticipant(
        emitters=fresh.generator.dispatcher.emitters,
        output_root=fresh.ecar_root.parent,
    ).restore_checkpoint(
        emitter_seal.head.payload,
        tuple(segment.payload for segment in emitter_seal.segments),
    )
    GenerationRngParticipant().restore_checkpoint(rng_seal.head.payload, ())

    restored_seal = ActivityGeneratorStateParticipant(fresh.generator).prepare_checkpoint(1)
    assert (
        loads(restored_seal.head.payload)["ssh_lifecycles"]
        == loads(activity_seal.head.payload)["ssh_lifecycles"]
    )
    assert fresh.generator.ssh_close_journal_census().legacy_pending == 1
    fresh.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fresh.frozen_bytes() == original_bytes


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


def test_real_ssh_caller_publishes_exact_cisco_transport_lifecycle(
    tmp_path: Path,
) -> None:
    """The production SSH caller admits a concrete Cisco sink exactly once."""

    reset_thread_rng(42)
    asa_root = tmp_path / "asa"
    asa = CiscoAsaEmitter(
        load_format("cisco_asa"),
        asa_root,
        threaded=False,
        sensor_hostnames=["fw01"],
    )
    asa._segment_config = [
        {"name": "workstations", "cidr": "10.0.0.0/28"},
        {"name": "servers", "cidr": "10.0.0.16/28"},
    ]
    asa._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "dmz",
            "_default": "outside",
        }
    }
    fixture = _fixture(tmp_path, extra_emitters={"cisco_asa": asa})

    uid, logon_id = _execute_real_caller(fixture)

    assert uid
    assert fixture.state.get_session(logon_id) is not None
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    asa.close()
    rendered = b"\n".join(output.read_bytes() for output in sorted(asa_root.rglob("cisco_asa.log")))
    built_ids = re.findall(rb"Built .* connection (\d+) for", rendered)
    teardown_ids = re.findall(rb"Teardown .* connection (\d+) for", rendered)
    assert len(built_ids) == len(teardown_ids) == 1
    assert built_ids == teardown_ids
    assert any(row.get("object") == "USER_SESSION" for row in ecar_rows)
    assert len(zeek_rows) == 1


def test_real_ssh_caller_materializes_fully_suppressed_warmup_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wholly pre-output SSH owner graph commits canonically without source rows."""

    reset_thread_rng(42)
    syslog_root = tmp_path / "syslog"
    syslog = SyslogEmitter(load_format("syslog"), syslog_root, threaded=False)
    marker_reads = 0

    def reject_marker_read(_emitter: SyslogEmitter) -> bool:
        nonlocal marker_reads
        marker_reads += 1
        raise AssertionError("suppressed SSH Syslog exact marker executed")

    monkeypatch.setattr(
        SyslogEmitter,
        "supports_exact_projection_publication",
        property(reject_marker_read),
    )
    fixture = _fixture(
        tmp_path,
        extra_emitters={"syslog": syslog},
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
    shell_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=5),
        logon_id,
        "/bin/bash",
        "-bash",
        parent_pid=receiver_pid,
        suppress_command_file_effect=True,
    )
    child_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=6),
        logon_id,
        "/usr/bin/tail",
        "tail -f /var/log/syslog",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    assert session.network_close_time is not None
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.state.get_session(logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.state.get_process(fixture.target.hostname, shell_pid) is None
    assert fixture.state.get_process(fixture.target.hostname, child_pid) is None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    assert (
        fixture.generator._source_timing_planner.preparation_authority_census().active_claims == 0
    )
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    syslog.close()
    assert ecar_rows == []
    assert zeek_rows == []
    assert marker_reads == 0
    assert not tuple(syslog_root.rglob("syslog.log"))
    exact = syslog.exact_candidate_census()
    assert exact.high_water_rows == exact.high_water_bytes == 0
    assert exact.admitted_rows == exact.admitted_bytes == 0
    assert exact.reserved_rows == exact.reserved_bytes == 0


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


def test_action_bundle_deadline_caps_full_hour_transport_and_terminal_tail(
    tmp_path: Path,
) -> None:
    """An action-owned final-hour SSH session chooses a complete earlier terminal time."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    deadline = _START + timedelta(hours=1)
    end_plan = SessionEndPlan(deadline, "action_bundle")
    request = replace(
        fixture.request(),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=end_plan,
    )

    bundle = SshSessionActionBundle(request, fixture.generator)
    expected_close = bundle._hard_deadline_transport_close_limit()
    _uid, logon_id = bundle.execute_with_identity()

    session = fixture.state.get_session(logon_id)
    assert session is not None
    assert session.end_plan == end_plan
    assert expected_close is not None
    assert session.network_close_time == expected_close
    assert ssh_action_deadline_transport_headroom_seconds() == pytest.approx(49.350998)
    fixture.generator.finalize_ssh_session_lifecycles(deadline)
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
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    logout_rows = [row for row in target_rows if row["action"] == "LOGOUT"]
    assert len(logout_rows) == 1
    assert datetime.fromtimestamp(logout_rows[0]["timestamp_ms"] / 1_000, tz=UTC) < deadline
    assert len(zeek_rows) == 1
    assert (
        datetime.fromtimestamp(
            zeek_rows[0]["ts"] + zeek_rows[0]["duration"],
            tz=UTC,
        )
        < deadline
    )


def test_process_overlay_finishes_real_ssh_output_before_action_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow endpoint dependents and their logoff gap finalize inside the raw fence."""

    _install_terminal_process_latency_overlay(monkeypatch)
    fixture = _fixture(tmp_path)
    deadline = _START + timedelta(hours=1)
    request = replace(
        fixture.request(),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )

    assert SourceTimingPlanner.session_closure_tail("ecar") == timedelta(
        seconds=70,
        milliseconds=4,
    )
    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    fixture.generator.finalize_ssh_session_lifecycles(deadline)
    assert fixture.state.get_session(logon_id) is None
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    ssh_zeek_rows = [row for row in zeek_rows if row.get("id.resp_p") == 22]
    assert len(ssh_zeek_rows) == 1
    assert (
        datetime.fromtimestamp(
            ssh_zeek_rows[0]["ts"] + ssh_zeek_rows[0]["duration"],
            tz=UTC,
        )
        < deadline
    )


def test_action_deadline_reserves_syslog_observation_delay_in_real_output(
    tmp_path: Path,
) -> None:
    """A delayed exact Syslog logout remains inside the raw action fence."""

    syslog_root = tmp_path / "syslog"
    syslog = SyslogEmitter(load_format("syslog"), syslog_root, threaded=False)
    fixture = _fixture(tmp_path / "ssh", extra_emitters={"syslog": syslog})
    fixture.generator.dispatcher.observation_policy = _fixed_observation_policy(syslog=120_000)
    deadline = _START + timedelta(hours=1)
    request = replace(
        fixture.request(),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    try:
        _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
        fixture.generator.finalize_ssh_session_lifecycles(deadline)
        assert fixture.state.get_session(logon_id) is None
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        ecar_rows, _zeek_rows = fixture.close_and_read()
        syslog.close()
        syslog_times = _syslog_render_times(syslog_root)
        assert syslog_times
        assert max(syslog_times) < deadline
        assert all(
            datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline
            for row in ecar_rows
        )
        rendered = "\n".join(
            output.read_text(encoding="utf-8") for output in syslog_root.rglob("syslog.log")
        )
        assert "Removed session" in rendered
    finally:
        fixture.ecar.close()
        fixture.zeek.close()
        syslog.close()


@pytest.mark.parametrize(
    ("delayed_source", "exact_path"),
    (("syslog", True), ("ecar", False)),
    ids=("syslog-terminal-exact", "ecar-auth-compatibility"),
)
def test_action_deadline_observation_support_rejects_one_microsecond_short(
    delayed_source: str,
    exact_path: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Endpoint delay bounds reject before RNG on exact and compatibility paths."""

    fixture = _fixture(tmp_path)
    policy = _fixed_observation_policy(**{delayed_source: 120_000})
    fixture.generator.dispatcher.observation_policy = policy
    if not exact_path:
        monkeypatch.setattr(
            SshSessionActionBundle,
            "_uses_exact_deferred_publication",
            lambda _bundle: False,
        )
    deadline = _START + timedelta(hours=1)
    base_request = fixture.request()
    required_headroom = ssh_action_deadline_transport_headroom_seconds(
        min_duration_seconds=base_request.min_duration or 0.0,
        auth_method=base_request.auth_method,
        public_key_type=base_request.public_key_type,
        route_class="private",
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=fixture.generator.dispatcher.network_observation_planner,
        observation_policy=policy,
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    exact_request = replace(
        base_request,
        time=deadline - timedelta(seconds=required_headroom),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    assert (
        SshSessionActionBundle(
            exact_request,
            fixture.generator,
        )._hard_deadline_transport_close_limit()
        is not None
    )
    short_request = replace(
        exact_request,
        time=exact_request.time + timedelta(microseconds=1),
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("SSH observation admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        SshSessionActionBundle(short_request, fixture.generator).execute_with_identity()

    assert (
        fixture.state.materialization_digest(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    ) == before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_action_deadline_extreme_cross_host_clocks_reject_before_rng(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid endpoint-clock extrema are part of the modeled-source admission bound."""

    fixture = _fixture(tmp_path)
    monkeypatch.setattr(
        SourceTimingPlanner,
        "endpoint_clock_positive_headroom",
        lambda _planner, _canonical_time, os_category: (
            timedelta(seconds=300) if os_category == "windows" else timedelta(0)
        ),
    )
    monkeypatch.setattr(
        SourceTimingPlanner,
        "endpoint_clock_negative_headroom",
        lambda _planner, _canonical_time, os_category: (
            timedelta(seconds=300) if os_category == "linux" else timedelta(0)
        ),
    )
    deadline = _START + timedelta(hours=1)
    policy = fixture.generator.dispatcher.observation_policy
    base_request = fixture.request()
    required_headroom = ssh_action_deadline_transport_headroom_seconds(
        min_duration_seconds=base_request.min_duration or 0.0,
        auth_method=base_request.auth_method,
        public_key_type=base_request.public_key_type,
        route_class="private",
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=fixture.generator.dispatcher.network_observation_planner,
        observation_policy=policy,
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    assert required_headroom > 600
    exact_request = replace(
        base_request,
        time=deadline - timedelta(seconds=required_headroom),
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    assert (
        SshSessionActionBundle(
            exact_request,
            fixture.generator,
        )._hard_deadline_transport_close_limit()
        is not None
    )
    short_request = replace(
        exact_request,
        time=exact_request.time + timedelta(microseconds=1),
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("SSH cross-clock admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        SshSessionActionBundle(short_request, fixture.generator).execute_with_identity()
    assert (
        fixture.state.materialization_digest(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    ) == before
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize("exact_path", (True, False), ids=("exact", "compatibility"))
def test_modeled_ssh_source_positive_clock_orders_flow_and_retains_hold(
    exact_path: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forced late client FLOW precedes LOGIN on both publication paths."""

    def forced_endpoint_clock(
        _planner: SourceTimingPlanner,
        canonical_time: datetime,
        *,
        hostname: str,
        os_category: str,
    ) -> datetime:
        del os_category
        return canonical_time + (
            timedelta(seconds=300)
            if hostname == "WS-01"
            else -timedelta(seconds=300)
            if hostname == "DB-01"
            else timedelta(0)
        )

    def forced_positive_headroom(
        _planner: SourceTimingPlanner,
        _canonical_time: datetime,
        os_category: str,
    ) -> timedelta:
        return timedelta(seconds=300) if os_category == "windows" else timedelta(0)

    monkeypatch.setattr(
        SourceTimingPlanner,
        "_runtime_endpoint_clock_time",
        forced_endpoint_clock,
    )
    monkeypatch.setattr(
        SourceTimingPlanner,
        "endpoint_clock_positive_headroom",
        forced_positive_headroom,
    )
    monkeypatch.setattr(
        SourceTimingPlanner,
        "endpoint_clock_negative_headroom",
        lambda _planner, _canonical_time, os_category: (
            timedelta(seconds=300) if os_category == "linux" else timedelta(0)
        ),
    )
    if not exact_path:
        monkeypatch.setattr(
            SshSessionActionBundle,
            "_uses_exact_deferred_publication",
            lambda _bundle: False,
        )

    fixture = _fixture(
        tmp_path,
        clock_profile_name="messy_collection",
        production_timing_runtime=True,
    )
    deadline = _START + timedelta(hours=1)
    request, source_pid = _modeled_scp_owned_close(fixture)
    request = replace(
        request,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )

    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    application = fixture.generator._ssh_channel_manager.find_by_transport(
        fixture.generator._last_connection_effective_transaction_id
    )
    if exact_path:
        assert application is not None
        assert application.transport.source_process is not None
        assert application.transport.source_process.pid == source_pid
    fixture.generator.finalize_ssh_session_lifecycles(deadline)
    assert fixture.state.get_session(logon_id) is None
    assert fixture.state.get_process(fixture.source.hostname, source_pid) is None
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    source_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.source.hostname
        and row.get("object") == "FLOW"
        and row.get("properties", {}).get("dst_port") == "22"
    ]
    assert len(source_flows) == 1
    assert "pid" not in source_flows[0]
    assert "principal" not in source_flows[0]
    target_logins = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname
        and row.get("object") == "USER_SESSION"
        and row.get("action") == "LOGIN"
    ]
    assert len(target_logins) == 1
    assert source_flows[0]["timestamp_ms"] < target_logins[0]["timestamp_ms"]
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    ssh_zeek_rows = [row for row in zeek_rows if row.get("id.resp_p") == 22]
    assert len(ssh_zeek_rows) == 1
    assert (
        datetime.fromtimestamp(
            ssh_zeek_rows[0]["ts"] + ssh_zeek_rows[0]["duration"],
            tz=UTC,
        )
        < deadline
    )


def test_process_overlay_deadline_rejects_one_microsecond_short_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The overlay-aware composite rejects one microsecond below its exact support."""

    _install_asymmetric_terminal_process_latency_overlay(monkeypatch)
    assert _ssh_action_deadline_source_tail(
        source_clock_headroom=timedelta(0),
        network_sensor_headroom=timedelta(0),
        ecar_observation_headroom=timedelta(0),
        syslog_observation_headroom=timedelta(0),
    ) == timedelta(seconds=70, microseconds=89_001)
    fixture = _fixture(tmp_path)
    deadline = _START + timedelta(hours=1)
    required_headroom = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=fixture.generator.dispatcher.network_observation_planner,
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    exact_request = replace(
        fixture.request(),
        time=deadline - timedelta(seconds=required_headroom),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    assert (
        SshSessionActionBundle(
            exact_request,
            fixture.generator,
        )._hard_deadline_transport_close_limit()
        is not None
    )
    request = replace(exact_request, time=exact_request.time + timedelta(microseconds=1))
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.ssh_close_journal_census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("SSH overlay deadline admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        SshSessionActionBundle(request, fixture.generator).execute_with_identity()

    assert (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.ssh_close_journal_census(),
        fixture.generator.timing_runtime.state_digest(),
        fixture.generator._source_timing_planner.state_digest(),
    ) == before
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_action_bundle_deadline_rejects_too_late_ssh_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Less than the owner minimum plus terminal tail rejects without partial publication."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    deadline = _START + timedelta(hours=1)
    required_headroom = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=(fixture.generator.dispatcher.network_observation_planner),
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    request = replace(
        fixture.request(),
        time=deadline - timedelta(seconds=required_headroom) + timedelta(microseconds=1),
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator._lifecycle_authority.registry.census(),
        fixture.generator._ssh_channel_manager.census(),
        fixture.generator._network_transaction_runtime.census(),
        fixture.generator.ssh_close_journal_census(),
        fixture.generator.timing_runtime.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("SSH deadline admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        unexpected_rng,
    )

    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
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


def test_action_deadline_preflight_includes_extreme_authentication_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Overlay auth support rejects one-microsecond-short admission before RNG."""

    fixture = _fixture(tmp_path)
    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session.ssh_authentication_timing_support",
        lambda *_args, **_kwargs: SimpleNamespace(
            lifecycle_gap_ms=SimpleNamespace(bounds=(0.0, 141_100.0))
        ),
    )
    deadline = _START + timedelta(hours=1)
    required_headroom = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=(fixture.generator.dispatcher.network_observation_planner),
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    assert required_headroom > 143.1
    request = replace(
        fixture.request(),
        time=deadline - timedelta(seconds=required_headroom) + timedelta(microseconds=1),
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    before = (
        fixture.state.materialization_digest(),
        fixture.generator.timing_runtime.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("SSH auth-support admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        SshSessionActionBundle(request, fixture.generator).execute_with_identity()

    assert (
        fixture.state.materialization_digest(),
        fixture.generator.timing_runtime.state_digest(),
    ) == before
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_action_deadline_headroom_includes_overlay_transport_open_jitter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compatibility admission includes the overlayable maximum transport-open sample."""

    maximum_jitter_ms = 2_500
    maximum_jitter = timedelta(
        milliseconds=maximum_jitter_ms,
        microseconds=997,
    )
    original_get_timing_window = get_timing_window

    def overlay_window(
        key: str,
        **kwargs: object,
    ) -> TimingWindow:
        if key == "network.connection_start_jitter":
            return TimingWindow(min_ms=0, max_ms=maximum_jitter_ms, position="after")
        return original_get_timing_window(key, **kwargs)

    def maximum_packet_sample(
        _planner: BaselineTimingPlanner,
        **_kwargs: object,
    ) -> timedelta:
        return maximum_jitter

    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session.get_timing_window",
        overlay_window,
    )
    monkeypatch.setattr(
        BaselineTimingPlanner,
        "packet_observation_delta",
        maximum_packet_sample,
    )
    fixture = _fixture(tmp_path)
    deadline = _START + timedelta(hours=1)
    headroom_seconds = ssh_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=fixture.generator.dispatcher.source_timing_planner,
        network_observation_planner=(fixture.generator.dispatcher.network_observation_planner),
        source_ip=fixture.source.ip,
        target_ip=fixture.target.ip,
    )
    admission_start = deadline - timedelta(seconds=headroom_seconds)
    request = replace(
        fixture.request(),
        time=admission_start,
        duration=timedelta(hours=1).total_seconds(),
        emit_session_close=True,
        defer_session_close=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )

    bundle = SshSessionActionBundle(request, fixture.generator)
    expected_close = bundle._hard_deadline_transport_close_limit()
    state = bundle._plan_transport()

    assert request.time + timedelta(seconds=headroom_seconds) == deadline
    assert state.open_time == admission_start + maximum_jitter
    assert state.duration == 30.0
    assert state.close_time == expected_close
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


def test_network_sensor_close_headroom_covers_firewall_terminal_branches() -> None:
    """The shared bound is conservative for complete and partial transport facts."""

    planner = NetworkObservationPlanner(
        None,
        timing_runtime=TimingRuntime(
            reference_time=_START,
            namespace="network-close-headroom-test",
        ),
    )
    successful = planner.network_sensor_close_positive_headroom(
        _START,
        protocol="tcp",
        conn_state="SF",
        payload_bytes=1,
    )
    datagram = planner.network_sensor_close_positive_headroom(
        _START,
        protocol="udp",
        payload_bytes=0,
    )
    embryonic = planner.network_sensor_close_positive_headroom(
        _START,
        protocol="tcp",
        conn_state="S0",
        payload_bytes=0,
    )

    assert successful - datagram == timedelta(microseconds=4_000)
    assert embryonic - successful == timedelta(seconds=30, microseconds=6_000)
    assert (
        planner.network_sensor_close_positive_headroom(
            _START,
            protocol="tcp",
            conn_state="S0",
        )
        == embryonic
    )
    assert (
        planner.network_sensor_close_positive_headroom(
            _START,
            protocol="tcp",
        )
        == embryonic
    )
    assert planner.network_sensor_close_positive_headroom(_START) == embryonic
    with pytest.raises(ValueError, match="protocol must be"):
        planner.network_sensor_close_positive_headroom(_START, protocol="TCP")
    with pytest.raises(ValueError, match="conn_state must be"):
        planner.network_sensor_close_positive_headroom(
            _START,
            protocol="tcp",
            conn_state="s0",
            payload_bytes=0,
        )


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
    original = SshSessionActionBundle._terminate_exact_receiver_descendants

    def fail_after_application_retirement(*args: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if retry and attempts == 1:
            raise OSError("post-watermark close retry")
        return original(*args, **kwargs)

    monkeypatch.setattr(
        SshSessionActionBundle,
        "_terminate_exact_receiver_descendants",
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


@pytest.mark.parametrize("retry", (False, True), ids=("direct", "retry"))
def test_multi_hour_watermark_transfers_ssh_proof_without_rendering_lifecycle(
    retry: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A long watermark retains retryable proof while the action remains the renderer."""

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
    target_session = fixture.state.get_session(session.binding.logon_id)
    assert target_session is not None and target_session.transport_pid is not None
    receiver_pid = target_session.transport_pid
    frontier = continuation.transaction.closed_at + timedelta(hours=3)
    adoption_attempts = 0
    lifecycle_attempts = 0
    original_adopt = _PreparedSshCloseContinuation.adopt_application_retirement

    def adopt_with_retry(
        prepared: _PreparedSshCloseContinuation,
        closure: SshChannelClosure,
    ) -> None:
        nonlocal adoption_attempts
        adoption_attempts += 1
        if retry and adoption_attempts == 1:
            raise OSError("injected SSH closure adoption failure")
        original_adopt(prepared, closure)

    def forbid_lifecycle_rendering(*_args: object, **_kwargs: object) -> None:
        nonlocal lifecycle_attempts
        lifecycle_attempts += 1
        raise AssertionError("watermark rendered an SSH terminal lifecycle")

    with monkeypatch.context() as watermark_patch:
        watermark_patch.setattr(
            _PreparedSshCloseContinuation,
            "adopt_application_retirement",
            adopt_with_retry,
        )
        watermark_patch.setattr(
            ActivityGenerator,
            "_execute_exact_ssh_close_continuation",
            forbid_lifecycle_rendering,
        )
        if retry:
            with pytest.raises(OSError, match="SSH closure adoption failure"):
                fixture.generator.advance_application_channel_watermark(frontier)
            failed_census = fixture.generator.ssh_close_journal_census()
            assert failed_census.manager_pending == 1
            assert failed_census.exact_pending == 1
            assert registry.get(session.channel_id) is not None

        fixture.generator.advance_application_channel_watermark(frontier)
        fixture.generator.advance_application_channel_watermark(frontier)

    assert lifecycle_attempts == 0
    assert adoption_attempts == (2 if retry else 1)
    assert manager.session_view(session.channel_id) is None
    assert registry.get(session.channel_id) is None
    retained_census = fixture.generator.ssh_close_journal_census()
    assert retained_census.manager_pending == 0
    assert retained_census.exact_pending == 1
    assert retained_census.total_pending == 1
    assert fixture.state.get_session(target_session.logon_id) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None

    fixture.generator.finalize_ssh_session_lifecycles(frontier)

    assert fixture.state.get_session(target_session.logon_id) is None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is None
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    fixture.generator.assert_ssh_session_lifecycles_drained()
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


def test_world_planner_storyline_ssh_stays_inside_scenario_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unpaired late storyline SSH session gets one action-owned window fence."""

    fixture = _fixture(tmp_path, production_timing_runtime=True)
    scenario_end = fixture.generator._ssh_channel_manager.application_registry.window_end
    activity_time = scenario_end - timedelta(minutes=45)
    fixture.generator._scenario_start_time = scenario_end - timedelta(days=1)
    fixture.generator._scenario_end_time = scenario_end
    fixture.generator._users_by_username = {fixture.user.username: fixture.user}
    fixture.state.create_session(
        username=fixture.user.username,
        system=fixture.source.hostname,
        logon_type=2,
        source_ip=fixture.source.ip,
        session_kind="interactive",
        start_time=activity_time - timedelta(hours=2),
    )
    plan = SessionPlan(
        target_system=fixture.target,
        source_system=fixture.source,
        source_ip=fixture.source.ip,
        logon_type=10,
        session_kind="ssh",
        requires_transport=True,
    )
    world = SimpleNamespace(
        hosts={fixture.source.hostname: SimpleNamespace(os_category="windows")},
        plan_session=lambda **_kwargs: plan,
    )
    planner = WorldPlanner(world, fixture.state, fixture.generator)  # type: ignore[arg-type]
    original_exact_path = SshSessionActionBundle._uses_exact_deferred_publication
    exact_path_decisions: list[bool] = []

    def capture_exact_path(bundle: SshSessionActionBundle) -> bool:
        decision = original_exact_path(bundle)
        exact_path_decisions.append(decision)
        return decision

    monkeypatch.setattr(
        SshSessionActionBundle,
        "_uses_exact_deferred_publication",
        capture_exact_path,
    )
    reset_thread_rng(2)

    result = planner.bootstrap_user_session(
        user=fixture.user,
        target_system=fixture.target,
        time=activity_time,
        rng=random.Random(9),
        session_kind="ssh",
        source_system=fixture.source,
        allow_existing=False,
        source_ip_override=fixture.source.ip,
        storyline_protected=True,
    )

    assert exact_path_decisions == [False]
    session = fixture.state.get_session(result.session.logon_id)
    assert session is not None
    assert session.end_plan == SessionEndPlan(scenario_end, "action_bundle")
    assert session.network_close_time is not None
    assert activity_time < session.network_close_time < scenario_end
    connection = fixture.state.get_connection_by_zeek_uid(result.network_uid)
    assert connection is not None
    assert connection.close_time is not None
    assert connection.close_time <= fixture.generator._network_transaction_runtime.window_end
    fixture.generator.finalize_ssh_session_lifecycles(scenario_end)
    assert fixture.state.get_session(session.logon_id) is None
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < scenario_end
        for row in ecar_rows
    )
    assert all(
        datetime.fromtimestamp(row["ts"] + row["duration"], tz=UTC) < scenario_end
        for row in zeek_rows
    )


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


def test_no_ecar_uses_exact_bridge_only_for_wholly_suppressed_warmup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing eCAR sink preserves exact warm-up ownership but not visible cohorts."""

    reset_thread_rng(42)
    output_start = _START + timedelta(hours=2)
    fixture = _fixture(tmp_path, output_start_time=output_start)
    assert fixture.generator.dispatcher.emitters.pop("ecar") is fixture.ecar
    visible = replace(fixture.request(), time=output_start)
    assert not SshSessionActionBundle(
        visible,
        fixture.generator,
    )._uses_exact_deferred_publication()
    crossing_authoritative_close = replace(
        fixture.request(),
        session_end_plan=SessionEndPlan(
            output_start + timedelta(hours=1),
            "explicit_storyline",
            "ssh-warmup-crossing-close",
        ),
    )
    assert not SshSessionActionBundle(
        crossing_authoritative_close,
        fixture.generator,
    )._uses_exact_deferred_publication()

    owner_rng = random.Random(42)
    monkeypatch.setattr(
        "evidenceforge.generation.actions.ssh_session._get_rng",
        lambda: owner_rng,
    )
    request = replace(
        fixture.request(),
        time=output_start - timedelta(minutes=59),
        source_port=None,
        duration=None,
        emit_session_close=True,
        defer_session_close=True,
    )
    bundle = SshSessionActionBundle(request, fixture.generator)
    rng_state = owner_rng.getstate()
    assert bundle._uses_exact_deferred_publication()
    assert owner_rng.getstate() == rng_state
    uid, logon_id = bundle.execute_with_identity()

    assert uid
    assert fixture.state.get_session(logon_id) is not None
    assert len(fixture.generator._pending_ssh_session_closures) == 1
    assert fixture.generator._pending_ssh_session_closures[0].plan.logind_remove_time < output_start
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=3))
    assert fixture.state.get_session(logon_id) is None
    assert fixture.generator._pending_ssh_session_closures == []
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize("source_os", ("Windows 11", "Ubuntu 24.04"))
def test_implicit_ssh_client_eligibility_is_allocation_free(
    source_os: str,
    tmp_path: Path,
) -> None:
    """An eligible implicit source actor keeps exact preparation mutation-free."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    fixture.source = System(
        hostname=fixture.source.hostname,
        ip=fixture.source.ip,
        os=source_os,
        type="workstation",
    )
    fixture.generator._ip_to_system[fixture.source.ip] = fixture.source
    fixture.generator._users_by_username = {fixture.user.username: fixture.user}
    fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=2,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    request = replace(fixture.request(), time=_START + timedelta(minutes=5))
    before = fixture.state.materialization_digest()

    assert fixture.generator.has_implicit_ssh_client_owner(
        user=request.user,
        source_system=fixture.source,
        time=request.time,
    )
    assert not SshSessionActionBundle(
        request,
        fixture.generator,
    )._uses_exact_deferred_publication()
    assert fixture.state.materialization_digest() == before
    fixture.close_and_read()


def test_ecar_availability_does_not_change_implicit_ssh_source_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Renderer selection cannot change canonical SSH source-process attribution."""

    attributions: dict[str, tuple[str, int]] = {}
    for mode in ("ecar", "no_ecar"):
        reset_thread_rng(42)
        fixture = _fixture(tmp_path / mode)
        fixture.generator._users_by_username = {fixture.user.username: fixture.user}
        if mode == "no_ecar":
            assert fixture.generator.dispatcher.emitters.pop("ecar") is fixture.ecar
        source_logon = fixture.generator.generate_logon(
            fixture.user,
            fixture.source,
            _START,
            logon_type=2,
            source_ip=fixture.source.ip,
            emit_network_evidence=False,
        )
        source_image = r"C:\Windows\System32\OpenSSH\ssh.exe"
        source_pid = fixture.generator.generate_process(
            fixture.user,
            fixture.source,
            _START + timedelta(seconds=1),
            source_logon,
            source_image,
            f"{source_image} {fixture.user.username}@{fixture.target.ip}",
            parent_pid=0,
            suppress_command_file_effect=True,
        )

        ensure_client = Mock(return_value=(source_pid, source_image))
        observed_pids: list[int] = []
        generate_connection = fixture.generator.generate_connection

        def capture_connection(
            *args: object,
            _observed_pids: list[int] = observed_pids,
            _generate_connection: Callable[..., str] = generate_connection,
            **kwargs: object,
        ) -> str:
            if kwargs.get("service") == "ssh" and kwargs.get("dst_port") == 22:
                pid = kwargs.get("pid")
                assert isinstance(pid, int)
                _observed_pids.append(pid)
            return _generate_connection(*args, **kwargs)

        request = replace(fixture.request(), time=_START + timedelta(minutes=5))
        bundle = SshSessionActionBundle(request, fixture.generator)
        assert not bundle._uses_exact_deferred_publication()
        with monkeypatch.context() as patch:
            patch.setattr(fixture.generator, "ensure_ssh_client_process", ensure_client)
            patch.setattr(fixture.generator, "generate_connection", capture_connection)
            uid = bundle.execute()

        assert uid
        ensure_client.assert_called_once()
        assert len(observed_pids) == 1
        assert observed_pids[0] == source_pid
        attributions[mode] = (uid, observed_pids[0])
        fixture.close_and_read()

    assert attributions["ecar"] == attributions["no_ecar"]


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


def test_modeled_ssh_client_publishes_one_source_finalized_sysmon_event3(
    tmp_path: Path,
) -> None:
    """The real exact SSH caller publishes one actor-bound Sysmon transport row."""

    reset_thread_rng(42)
    sysmon_root = tmp_path / "sysmon"
    fixture = _fixture(tmp_path)
    source_logon = fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=3,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    source_image = r"C:\Windows\System32\OpenSSH\ssh.exe"
    source_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=1),
        source_logon,
        source_image,
        f"{source_image} {fixture.target.hostname}",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=False,
        source_finalization=True,
    )
    fixture.generator.dispatcher.emitters["windows_event_sysmon"] = sysmon
    request = replace(
        fixture.request(),
        time=_START + timedelta(seconds=2),
        source_pid=source_pid,
        source_process_image=source_image,
        source="storyline_ssh",
    )

    uid = SshSessionActionBundle(request, fixture.generator).execute()
    application = fixture.generator._ssh_channel_manager.find_by_transport(
        fixture.generator._last_connection_effective_transaction_id
    )
    assert uid and application is not None
    assert application.transport.source_process is not None
    assert application.transport.source_process.pid == source_pid
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)

    coordinator = SourceFinalizationCoordinator(
        (sysmon,),
        ExactPublicationAuthority(
            capacity=1,
            row_capacity=256,
            byte_capacity=8 * 1024 * 1024,
        ),
    )
    coordinator.finalize()
    sysmon.close()
    coordinator.mark_closed()
    _ecar_rows, zeek_rows = fixture.close_and_read()
    rendered = "\n".join(
        output.read_text(encoding="utf-8")
        for output in sysmon_root.rglob("windows_event_sysmon.xml")
    )
    assert rendered.count("<EventID>3</EventID>") == 1
    assert f'<Data Name="ProcessId">{source_pid}</Data>' in rendered
    assert f'<Data Name="Image">{source_image}</Data>' in rendered
    assert '<Data Name="SourceIp">10.0.0.10</Data>' in rendered
    assert '<Data Name="DestinationIp">10.0.0.20</Data>' in rendered
    assert '<Data Name="DestinationPort">22</Data>' in rendered
    assert len(zeek_rows) == 1
    exact = sysmon.exact_candidate_census()
    assert exact.current_rows == exact.current_bytes == exact.current_participants == 0
    assert exact.released_rows == exact.released_bytes == exact.completed_participants == 0


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


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_ssh_close_retries_sudo_tty_release_after_canonical_close(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact SSH continuation retries sudo-TTY release without consulting closed State."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    _uid, logon_id = _execute_real_caller(
        fixture,
        emit_session_close=True,
        defer_session_close=True,
    )
    session = fixture.state.get_session(logon_id)
    assert session is not None
    fixture.generator.generate_linux_sudo_session(
        system=fixture.target,
        time=_START + timedelta(seconds=10),
        command_message=(
            "analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id"
        ),
        sudo_user=fixture.user.username,
        uid=1000,
        runtime=timedelta(seconds=2),
    )
    tty_key = (fixture.target.hostname, fixture.user.username, "pts/1")
    assert fixture.generator._linux_sudo_tty_sessions == {tty_key: logon_id}
    assert fixture.generator._linux_sudo_tty_keys_by_logon_id == {logon_id: {tty_key}}
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1

    original_release = fixture.generator._release_session_retention_state
    attempts = 0

    def fail_release(
        *,
        hostname: str,
        username: str,
        logon_id: str,
    ) -> ActivityGeneratorSessionRetentionRelease:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original_release(
                    hostname=hostname,
                    username=username,
                    logon_id=logon_id,
                )
            raise OSError(f"sudo TTY release {failure_mode}")
        return original_release(
            hostname=hostname,
            username=username,
            logon_id=logon_id,
        )

    monkeypatch.setattr(fixture.generator, "_release_session_retention_state", fail_release)
    close_horizon = _START + timedelta(hours=1)
    with pytest.raises(OSError, match=f"sudo TTY release {failure_mode}"):
        fixture.generator.finalize_ssh_session_lifecycles(close_horizon)

    lifecycle = fixture.generator._lifecycle_authority.registry.get_session(session.ecar_object_id)
    assert fixture.state.get_session(logon_id) is None
    assert lifecycle is not None and lifecycle.closed_at is not None
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    if failure_mode == "fail-before":
        assert fixture.generator._linux_sudo_tty_sessions == {tty_key: logon_id}
        assert fixture.generator._linux_sudo_tty_keys_by_logon_id == {logon_id: {tty_key}}
    else:
        assert not fixture.generator._linux_sudo_tty_sessions
        assert not fixture.generator._linux_sudo_tty_keys_by_logon_id

    fixture.generator.finalize_ssh_session_lifecycles(close_horizon)

    assert attempts == 2
    assert fixture.generator.ssh_close_journal_census().exact_pending == 0
    assert not fixture.generator._linux_sudo_tty_assignments
    assert not fixture.generator._linux_sudo_tty_owners
    assert not fixture.generator._linux_sudo_tty_sessions
    assert not fixture.generator._linux_sudo_tty_available
    assert not fixture.generator._linux_sudo_tty_keys_by_logon_id
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_sessions] == ["LOGIN", "LOGOUT"]
    assert len(zeek_rows) == 1


def test_exact_ssh_postcondition_rejection_retains_sudo_tty_route_before_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact postconditions precede cleanup so a rejected tail preserves retry state."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    _uid, logon_id = _execute_real_caller(
        fixture,
        emit_session_close=True,
        defer_session_close=True,
    )
    session = fixture.state.get_session(logon_id)
    assert session is not None
    fixture.generator.generate_linux_sudo_session(
        system=fixture.target,
        time=_START + timedelta(seconds=10),
        command_message=(
            "analyst : TTY=pts/1 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/id"
        ),
        sudo_user=fixture.user.username,
        uid=1000,
        runtime=timedelta(seconds=2),
    )
    tty_key = (fixture.target.hostname, fixture.user.username, "pts/1")
    assert fixture.generator._linux_sudo_tty_sessions == {tty_key: logon_id}
    assert fixture.generator._linux_sudo_tty_keys_by_logon_id == {logon_id: {tty_key}}

    original_postcondition = _PreparedSshCloseContinuation.require_application_session_retired
    postcondition_attempts = 0

    def reject_postcondition_once(prepared: _PreparedSshCloseContinuation) -> None:
        nonlocal postcondition_attempts
        postcondition_attempts += 1
        if postcondition_attempts == 1:
            raise OSError("injected exact SSH postcondition rejection")
        original_postcondition(prepared)

    release = Mock(wraps=fixture.generator._release_session_retention_state)
    monkeypatch.setattr(
        _PreparedSshCloseContinuation,
        "require_application_session_retired",
        reject_postcondition_once,
    )
    monkeypatch.setattr(fixture.generator, "_release_session_retention_state", release)
    close_horizon = _START + timedelta(hours=1)
    with pytest.raises(OSError, match="exact SSH postcondition rejection"):
        fixture.generator.finalize_ssh_session_lifecycles(close_horizon)

    lifecycle = fixture.generator._lifecycle_authority.registry.get_session(session.ecar_object_id)
    assert fixture.state.get_session(logon_id) is None
    assert lifecycle is not None and lifecycle.closed_at is not None
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    assert release.call_count == 0
    assert fixture.generator._linux_sudo_tty_sessions == {tty_key: logon_id}
    assert fixture.generator._linux_sudo_tty_keys_by_logon_id == {logon_id: {tty_key}}

    fixture.generator.finalize_ssh_session_lifecycles(close_horizon)

    assert postcondition_attempts == 2
    assert release.call_count == 1
    assert fixture.generator.ssh_close_journal_census().exact_pending == 0
    assert not fixture.generator._linux_sudo_tty_assignments
    assert not fixture.generator._linux_sudo_tty_owners
    assert not fixture.generator._linux_sudo_tty_sessions
    assert not fixture.generator._linux_sudo_tty_available
    assert not fixture.generator._linux_sudo_tty_keys_by_logon_id
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname and row.get("object") == "USER_SESSION"
    ]
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


@pytest.mark.parametrize(
    "failure_mode",
    (
        "success",
        "commit-fail-before",
        "commit-lost-return",
        "release-fail-before",
        "release-lost-return",
    ),
)
def test_exact_close_accepts_concrete_syslog_and_publishes_one_logout(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real SSH close publishes one recoverable target logout to eCAR and Syslog."""

    reset_thread_rng(42)
    syslog_root = tmp_path / "syslog"
    syslog = SyslogEmitter(
        load_format("syslog"),
        syslog_root,
        threaded=False,
    )
    fixture = _fixture(
        tmp_path / "ssh",
        extra_emitters={"syslog": syslog},
    )
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    try:
        _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
        original_reserve = ExactPublicationBatch.reserve_participants
        reserved_participants: list[tuple[object, ...]] = []

        def capture_participants(
            batch: ExactPublicationBatch,
            participants: tuple[object, ...],
        ) -> None:
            reserved_participants.append(participants)
            original_reserve(batch, participants)

        monkeypatch.setattr(ExactPublicationBatch, "reserve_participants", capture_participants)
        original_commit = syslog._commit_exact_candidate
        original_release = syslog._release_exact_candidate
        commit_attempts = 0
        release_attempts = 0

        def fault_exact_logout(key: object, digest: str, frozen: object) -> None:
            nonlocal commit_attempts
            _route, _logical_route, rendered = SyslogEmitter._decode_exact_candidate(frozen)
            is_logout = "session closed for user analyst" in rendered
            if failure_mode.startswith("commit-") and is_logout and commit_attempts == 0:
                commit_attempts += 1
                if failure_mode.endswith("lost-return"):
                    original_commit(key, digest, frozen)
                raise OSError(f"injected exact Syslog {failure_mode}")
            original_commit(key, digest, frozen)

        def fault_exact_release(key: object) -> None:
            nonlocal release_attempts
            if failure_mode.startswith("release-") and release_attempts == 0:
                release_attempts += 1
                if failure_mode.endswith("lost-return"):
                    original_release(key)
                raise OSError(f"injected exact Syslog {failure_mode}")
            original_release(key)

        monkeypatch.setattr(syslog, "_commit_exact_candidate", fault_exact_logout)
        monkeypatch.setattr(syslog, "_release_exact_candidate", fault_exact_release)
        if failure_mode != "success":
            with pytest.raises(OSError, match=f"exact Syslog {failure_mode}"):
                fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
            assert fixture.state.get_session(logon_id) is None
            recovery = fixture.generator.dispatcher.exact_projection_recovery_census()
            assert recovery.unresolved_recoveries == 1
            resumed = fixture.generator.dispatcher.drain_exact_projection_recoveries()
            assert len(resumed) == 1
            assert all(
                outcome.status == "succeeded"
                for result in resumed
                for outcome in result.projections
            )
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

        assert fixture.state.get_session(logon_id) is None
        assert fixture.generator.ssh_close_journal_census().total_pending == 0
        assert commit_attempts == int(failure_mode.startswith("commit-"))
        assert release_attempts == int(failure_mode.startswith("release-"))
        assert any(
            len(participants) == 2 and participants[0] is fixture.ecar and participants[1] is syslog
            for participants in reserved_participants
        )
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        ecar_rows, zeek_rows = fixture.close_and_read()
        syslog.close()
        target_rows = [
            row
            for row in ecar_rows
            if row.get("hostname") == fixture.target.hostname
            and row.get("object") == "USER_SESSION"
        ]
        rendered_syslog = "\n".join(
            output.read_text(encoding="utf-8") for output in syslog_root.rglob("syslog.log")
        )
        assert [row["action"] for row in target_rows] == ["LOGIN", "LOGOUT"]
        assert rendered_syslog.count("session closed for user analyst") == 1
        assert len(zeek_rows) == 1
        exact = syslog.exact_candidate_census()
        assert exact.admitted_rows == exact.admitted_bytes == 0
        assert exact.reserved_rows == exact.reserved_bytes == 0
    finally:
        fixture.ecar.close()
        fixture.zeek.close()
        syslog.close()


class _SyslogSubclass(SyslogEmitter):
    """Concrete-type impostor that inherits the exact publication marker."""


class _DuckExactSyslog:
    """Duck marker whose descriptor must not authorize an exact SSH sink."""

    marker_reads = 0
    emit_calls = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if concrete-type admission executes a foreign descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("duck Syslog exact marker executed")

    def can_handle(self, event: object) -> bool:
        """Participate in every SyslogContext projection."""

        return getattr(event, "syslog", None) is not None

    def emit(self, _event: object) -> None:
        """Accept ordinary preterminal rows without side effects."""

        type(self).emit_calls += 1


@pytest.mark.parametrize("target_kind", ("subclass", "duck", "alias"))
def test_exact_close_syslog_admission_rejects_nonconcrete_targets_before_state(
    target_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inherited, duck, and wrongly aliased markers cannot authorize a Syslog target."""

    reset_thread_rng(42)
    _DuckExactSyslog.marker_reads = 0
    _DuckExactSyslog.emit_calls = 0
    alias_marker_reads = 0
    target: object
    if target_kind == "subclass":
        target = _SyslogSubclass(load_format("syslog"), tmp_path / "subclass")
    elif target_kind == "duck":
        target = _DuckExactSyslog()
    else:

        def reject_alias_marker(_emitter: SyslogEmitter) -> bool:
            nonlocal alias_marker_reads
            alias_marker_reads += 1
            raise AssertionError("wrong-alias Syslog exact marker executed")

        monkeypatch.setattr(
            SyslogEmitter,
            "supports_exact_projection_publication",
            property(reject_alias_marker),
        )
        target = SyslogEmitter(load_format("syslog"), tmp_path / "alias")
    target_name = "syslog_alias" if target_kind == "alias" else "syslog"
    fixture = _fixture(
        tmp_path / "ssh",
        extra_emitters={target_name: target},
    )
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    try:
        _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
        session_before = fixture.state.get_session_identity(logon_id)
        assert session_before is not None

        with pytest.raises(EventContractError, match="syslog.*unsupported before State"):
            fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

        assert fixture.state.get_session_identity(logon_id) == session_before
        assert len(fixture.generator._pending_ssh_session_closures) == 1
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)
        assert _DuckExactSyslog.marker_reads == 0
        assert _DuckExactSyslog.emit_calls == 0
        assert alias_marker_reads == 0
        if isinstance(target, SyslogEmitter):
            exact = target.exact_candidate_census()
            assert exact.admitted_rows == exact.admitted_bytes == 0
            assert exact.reserved_rows == exact.reserved_bytes == 0
    finally:
        fixture.ecar.close()
        fixture.zeek.close()
        if isinstance(target, SyslogEmitter):
            target.close()


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
    assert after[0] == before[0]
    assert after[2] == before[2]
    assert after[1].lookup_candidates_inspected == before[1].lookup_candidates_inspected + 3
    assert (
        replace(
            after[1],
            lookup_candidates_inspected=before[1].lookup_candidates_inspected,
        )
        == before[1]
    )
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


def _open_exact_ssh_receiver_descendant_graph(
    fixture: _RealSshFixture,
) -> tuple[str, int, int, int]:
    """Open one source-native receiver -> shell -> command lifecycle graph."""

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
    request = replace(
        fixture.request(),
        emit_session_close=True,
        defer_session_close=True,
    )
    _uid, logon_id = SshSessionActionBundle(request, fixture.generator).execute_with_identity()
    session = fixture.state.get_session(logon_id)
    assert session is not None and session.transport_pid is not None
    receiver_pid = session.transport_pid
    receiver_identity = fixture.state.get_process_identity(fixture.target.hostname, receiver_pid)
    assert receiver_identity is not None

    shell_pid = fixture.generator.ensure_linux_ssh_session_shell(
        fixture.user,
        fixture.target,
        logon_id,
        session.start_time,
        _START + timedelta(seconds=5),
    )
    assert shell_pid is not None
    shell = fixture.state.get_process(fixture.target.hostname, shell_pid)
    shell_identity = fixture.state.get_process_identity(fixture.target.hostname, shell_pid)
    assert shell is not None and shell_identity is not None
    child_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=6),
        logon_id,
        "/usr/bin/tail",
        "tail -f /var/log/syslog &",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    child_identity = fixture.state.get_process_identity(fixture.target.hostname, child_pid)
    assert child_identity is not None
    return logon_id, receiver_pid, shell_pid, child_pid


def _open_compatibility_ssh_receiver_descendant_graph(
    fixture: _RealSshFixture,
) -> tuple[str, int, int, int, int]:
    """Open one compatibility receiver -> shell -> command -> child graph."""

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
    fixture.generator._users_by_username = {fixture.user.username: fixture.user}
    fixture.generator.generate_logon(
        fixture.user,
        fixture.source,
        _START,
        logon_type=2,
        source_ip=fixture.source.ip,
        emit_network_evidence=False,
    )
    request_time = _START + timedelta(minutes=5)
    request = replace(
        fixture.request(),
        time=request_time,
        emit_session_close=True,
        defer_session_close=True,
    )
    bundle = SshSessionActionBundle(request, fixture.generator)
    assert not bundle._uses_exact_deferred_publication()
    _uid, logon_id = bundle.execute_with_identity()
    session = fixture.state.get_session(logon_id)
    assert session is not None and session.transport_pid is not None
    receiver_pid = session.transport_pid
    shell_pid = fixture.generator.ensure_linux_ssh_session_shell(
        fixture.user,
        fixture.target,
        logon_id,
        session.start_time,
        request_time + timedelta(seconds=5),
    )
    assert shell_pid is not None
    command_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        request_time + timedelta(seconds=6),
        logon_id,
        "/usr/bin/python3",
        "python3 worker.py",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    child_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        request_time + timedelta(seconds=7),
        logon_id,
        "/usr/bin/sleep",
        "sleep 120",
        parent_pid=command_pid,
        suppress_command_file_effect=True,
    )
    return logon_id, receiver_pid, shell_pid, command_pid, child_pid


def test_compatibility_close_drains_nested_receiver_tree_in_linear_postorder(
    tmp_path: Path,
) -> None:
    """Compatibility SSH teardown closes every nested child before its parent."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, command_pid, child_pid = (
        _open_compatibility_ssh_receiver_descendant_graph(fixture)
    )
    identities = {
        pid: fixture.state.get_process_identity(fixture.target.hostname, pid)
        for pid in (receiver_pid, shell_pid, command_pid, child_pid)
    }
    assert all(identity is not None for identity in identities.values())

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    closed = {
        pid: fixture.generator._lifecycle_authority.registry.get_process(identity.object_id)
        for pid, identity in identities.items()
        if identity is not None
    }
    assert all(
        snapshot is not None and snapshot.closed_at is not None for snapshot in closed.values()
    )
    assert closed[child_pid].closed_at < closed[command_pid].closed_at
    assert closed[command_pid].closed_at < closed[shell_pid].closed_at
    assert closed[shell_pid].closed_at < closed[receiver_pid].closed_at
    assert fixture.state.get_session(logon_id) is None
    assert fixture.generator._ssh_channel_manager.census().open_sessions == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    _ecar_rows, zeek_rows = fixture.close_and_read()
    assert sum(row["id.resp_p"] == 22 for row in zeek_rows) == 1


def test_compatibility_close_rejects_foreign_descendant_before_teardown_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A foreign structural child cannot retire any SSH close owner."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, command_pid, child_pid = (
        _open_compatibility_ssh_receiver_descendant_graph(fixture)
    )
    foreign_logon_id = fixture.generator.generate_logon(
        fixture.user,
        fixture.target,
        _START + timedelta(minutes=6),
        logon_type=2,
        source_ip="-",
        emit_network_evidence=False,
    )
    foreign_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(minutes=6, seconds=1),
        foreign_logon_id,
        "/usr/bin/true",
        "true",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    foreign_identity = fixture.state.get_process_identity(fixture.target.hostname, foreign_pid)
    assert foreign_identity is not None
    foreign_snapshot = fixture.generator._lifecycle_authority.registry.get_process(
        foreign_identity.object_id
    )
    assert foreign_snapshot is not None
    authority = fixture.generator._lifecycle_authority
    original_descendants = authority.live_process_descendant_postorder

    def inject_foreign_descendant(
        process_object_id: str,
        *,
        limit: int = 4_096,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        return (*original_descendants(process_object_id, limit=limit), foreign_snapshot)

    monkeypatch.setattr(
        authority,
        "live_process_descendant_postorder",
        inject_foreign_descendant,
    )
    before = fixture.state.materialization_digest()
    channel_before = fixture.generator._ssh_channel_manager.census()
    tracked = (receiver_pid, shell_pid, command_pid, child_pid)

    with pytest.raises(StateError, match="graph disagrees with session membership"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fixture.state.materialization_digest() == before
    assert all(
        fixture.state.get_process(fixture.target.hostname, pid) is not None for pid in tracked
    )
    assert fixture.state.get_session(logon_id) is not None
    assert fixture.generator._ssh_channel_manager.census() == channel_before
    fixture.close_and_read()


def test_exact_close_freezes_receiver_descendants_children_first_before_parent(
    tmp_path: Path,
) -> None:
    """Exact SSH close freezes and drains target descendants before their parents."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, child_pid = _open_exact_ssh_receiver_descendant_graph(
        fixture
    )
    receiver_identity = fixture.state.get_process_identity(fixture.target.hostname, receiver_pid)
    shell_identity = fixture.state.get_process_identity(fixture.target.hostname, shell_pid)
    child_identity = fixture.state.get_process_identity(fixture.target.hostname, child_pid)
    session_identity = fixture.state.get_session_identity(logon_id)
    assert receiver_identity is not None
    assert shell_identity is not None
    assert child_identity is not None
    assert session_identity is not None
    closed_sibling_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=7),
        logon_id,
        "/usr/bin/true",
        "true",
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    closed_sibling_identity = fixture.state.get_process_identity(
        fixture.target.hostname,
        closed_sibling_pid,
    )
    assert closed_sibling_identity is not None
    fixture.generator.generate_process_termination(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=20),
        closed_sibling_pid,
        closed_sibling_identity.image,
        logon_id,
    )
    closed_sibling = fixture.generator._lifecycle_authority.registry.get_process(
        closed_sibling_identity.object_id
    )
    assert closed_sibling is not None and closed_sibling.closed_at is not None
    assert (
        fixture.generator._lifecycle_authority.process_latest_closed_child_at_for_object(
            shell_identity.object_id
        )
        == closed_sibling.closed_at
    )
    assert [
        snapshot.identity.object_id
        for snapshot in fixture.generator._lifecycle_authority.live_process_descendant_postorder(
            receiver_identity.object_id,
            limit=2,
        )
    ] == [child_identity.object_id, shell_identity.object_id]
    assert [
        child.identity.object_id
        for child in fixture.generator._lifecycle_authority.live_child_process_page_for_object(
            shell_identity.object_id
        )
    ] == [child_identity.object_id]

    assert [
        child.identity.object_id
        for child in fixture.generator._lifecycle_authority.live_child_process_page_for_object(
            receiver_identity.object_id
        )
    ] == [shell_identity.object_id]

    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert fixture.state.get_session(logon_id) is None

    closed_child = fixture.generator._lifecycle_authority.registry.get_process(
        child_identity.object_id
    )
    closed_shell = fixture.generator._lifecycle_authority.registry.get_process(
        shell_identity.object_id
    )
    assert closed_child is not None and closed_child.closed_at is not None
    assert closed_shell is not None and closed_shell.closed_at is not None
    closed_receiver = fixture.generator._lifecycle_authority.registry.get_process(
        receiver_identity.object_id
    )
    assert closed_receiver is not None and closed_receiver.closed_at is not None
    closed_session = fixture.generator._lifecycle_authority.registry.get_session(
        session_identity.object_id
    )
    assert closed_session is not None and closed_session.closed_at is not None
    assert (
        closed_child.closed_at
        < closed_shell.closed_at
        < closed_receiver.closed_at
        < closed_session.closed_at
    )
    assert (
        fixture.generator._lifecycle_authority.live_child_process_page_for_object(
            receiver_identity.object_id
        )
        == ()
    )
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    terminal_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname
        and (
            (
                row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("pid") in {child_pid, shell_pid, receiver_pid}
            )
            or (row.get("object") == "USER_SESSION" and row.get("action") == "LOGOUT")
        )
    ]
    assert [(row["object"], row["action"], row.get("pid")) for row in terminal_rows] == [
        ("PROCESS", "TERMINATE", child_pid),
        ("PROCESS", "TERMINATE", shell_pid),
        ("USER_SESSION", "LOGOUT", None),
        ("PROCESS", "TERMINATE", receiver_pid),
    ]
    expected_process_objects = {
        child_pid: child_identity.object_id,
        shell_pid: shell_identity.object_id,
        receiver_pid: receiver_identity.object_id,
    }
    assert all(
        row.get("objectID") == expected_process_objects[row["pid"]]
        for row in terminal_rows
        if row.get("object") == "PROCESS"
    )
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_close_receiver_descendant_retry_recovers_before_consumed_state(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A descendant sink retry authenticates its receipt before rereading consumed State."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, child_pid = _open_exact_ssh_receiver_descendant_graph(
        fixture
    )
    child_identity = fixture.state.get_process_identity(fixture.target.hostname, child_pid)
    assert child_identity is not None
    original_sink = ExternalSortedLineWriter._commit_exact_row
    target_attempts = 0

    def fail_child_termination(
        writer: ExternalSortedLineWriter,
        key: object,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal target_attempts
        row = json.loads(frozen) if writer.output_path.name == "ecar.json" else {}
        is_target = bool(
            row.get("hostname") == fixture.target.hostname
            and row.get("object") == "PROCESS"
            and row.get("action") == "TERMINATE"
            and row.get("pid") == child_pid
        )
        if is_target:
            target_attempts += 1
            if target_attempts == 1:
                if failure_mode == "lost-return":
                    original_sink(writer, key, digest, frozen)
                raise OSError(f"receiver descendant {failure_mode}")
        original_sink(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_child_termination)
    with pytest.raises(OSError, match=f"receiver descendant {failure_mode}") as raised:
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    receipt = getattr(raised.value, "action_cohort_receipt", None)
    result = getattr(raised.value, "action_cohort_result", None)
    assert receipt is not None
    assert result is not None
    assert result.receipt is receipt
    assert receipt.root_action_id.endswith(f":receiver-descendant:{child_identity.object_id}")
    assert fixture.state.get_process(fixture.target.hostname, child_pid) is None
    assert fixture.state.get_process(fixture.target.hostname, shell_pid) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert fixture.state.get_session(logon_id) is not None
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    assert (
        fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    )
    retained = fixture.generator._pending_ssh_session_closures[0]
    schedule = retained.receiver_descendant_terminations()
    assert schedule is not None
    assert [entry.identity.pid for entry in schedule] == [child_pid, shell_pid]

    original_get_process = StateManager.get_process

    def reject_consumed_child_read(
        manager: StateManager,
        hostname: str,
        pid: int,
    ) -> object:
        if hostname == fixture.target.hostname and pid == child_pid:
            raise AssertionError("retry consulted consumed SSH descendant State")
        return original_get_process(manager, hostname, pid)

    monkeypatch.setattr(StateManager, "get_process", reject_consumed_child_read)
    fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert target_attempts == 2
    assert fixture.generator.ssh_close_journal_census().total_pending == 0
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    ecar_rows, zeek_rows = fixture.close_and_read()
    target_terminates = [
        row
        for row in ecar_rows
        if row.get("hostname") == fixture.target.hostname
        and row.get("object") == "PROCESS"
        and row.get("action") == "TERMINATE"
        and row.get("pid") in {child_pid, shell_pid, receiver_pid}
    ]
    assert sorted(row["pid"] for row in target_terminates) == sorted(
        (child_pid, shell_pid, receiver_pid)
    )
    assert len(target_terminates) == 3
    assert len(zeek_rows) == 1


def test_exact_close_descendant_impossible_window_fails_before_process_mutation(
    tmp_path: Path,
) -> None:
    """A descendant that cannot precede its receiver rejects the whole frozen schedule."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, child_pid = _open_exact_ssh_receiver_descendant_graph(
        fixture
    )
    continuation = fixture.generator._pending_ssh_session_closures[0]
    child_identity = fixture.state.get_process_identity(fixture.target.hostname, child_pid)
    assert child_identity is not None
    fixture.generator._lifecycle_authority.add_process_hold(
        hostname=fixture.target.hostname,
        pid=child_pid,
        acquired_at=child_identity.started_at + timedelta(microseconds=1),
        hold_until=continuation.plan.receiver_terminate_time,
        reason="impossible exact SSH descendant window",
    )
    identities = {
        pid: fixture.state.get_process_identity(fixture.target.hostname, pid)
        for pid in (child_pid, shell_pid, receiver_pid)
    }
    assert all(identity is not None for identity in identities.values())

    with pytest.raises(StateError, match="cannot terminate before its receiver parent"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert continuation.receiver_descendant_terminations() is None
    assert fixture.state.get_session(logon_id) is not None
    for pid, identity in identities.items():
        assert fixture.state.get_process_identity(fixture.target.hostname, pid) == identity
        assert identity is not None
        snapshot = fixture.generator._lifecycle_authority.registry.get_process(identity.object_id)
        assert snapshot is not None
        assert snapshot.close_barrier is None
        assert snapshot.closure_ticket is None
        assert snapshot.closed_at is None
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


def test_exact_close_terminal_census_rejects_a_late_receiver_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target process added after schedule freeze cannot escape the terminal census."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    logon_id, receiver_pid, shell_pid, child_pid = _open_exact_ssh_receiver_descendant_graph(
        fixture
    )
    original_publish = SshSessionActionBundle._publish_exact_receiver_descendant_termination
    injected = False

    def freeze_then_fail(
        owner: SshSessionActionBundle,
        *,
        continuation: object,
        planned: object,
    ) -> None:
        nonlocal injected
        if not injected:
            injected = True
            raise OSError("descendant schedule frozen")
        original_publish(owner, continuation=continuation, planned=planned)

    monkeypatch.setattr(
        SshSessionActionBundle,
        "_publish_exact_receiver_descendant_termination",
        freeze_then_fail,
    )
    with pytest.raises(OSError, match="descendant schedule frozen"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    continuation = fixture.generator._pending_ssh_session_closures[0]
    schedule = continuation.receiver_descendant_terminations()
    assert schedule is not None
    assert [entry.identity.pid for entry in schedule] == [child_pid, shell_pid]
    late_pid = fixture.generator.generate_process(
        fixture.user,
        fixture.target,
        _START + timedelta(seconds=7),
        logon_id,
        "/usr/bin/tail",
        "tail -f /var/log/auth.log",
        parent_pid=receiver_pid,
        suppress_command_file_effect=True,
    )
    late_identity = fixture.state.get_process_identity(fixture.target.hostname, late_pid)
    assert late_identity is not None

    with pytest.raises(StateError, match="terminal census retained live descendants"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))

    assert fixture.state.get_process(fixture.target.hostname, child_pid) is None
    assert fixture.state.get_process(fixture.target.hostname, shell_pid) is None
    assert fixture.state.get_process(fixture.target.hostname, late_pid) is not None
    assert fixture.state.get_process(fixture.target.hostname, receiver_pid) is not None
    assert fixture.state.get_session(logon_id) is not None
    receiver_identity = fixture.state.get_process_identity(
        fixture.target.hostname,
        receiver_pid,
    )
    assert receiver_identity is not None
    assert [
        child.identity.object_id
        for child in fixture.generator._lifecycle_authority.live_child_process_page_for_object(
            receiver_identity.object_id
        )
    ] == [late_identity.object_id]
    assert fixture.generator.ssh_close_journal_census().exact_pending == 1
    _assert_no_dispatcher_residue(fixture.generator.dispatcher)
    fixture.close_and_read()


def test_exact_close_rejects_foreign_session_receiver_descendant_before_target_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A receiver child owned by another live login cannot be swept by SSH close."""

    reset_thread_rng(42)
    fixture = _fixture(tmp_path)
    ssh_logon_id, receiver_pid, shell_pid, child_pid = _open_exact_ssh_receiver_descendant_graph(
        fixture
    )
    foreign_user = User(
        username="operator",
        full_name="Operations User",
        email="operator@example.test",
    )
    foreign_logon_id = fixture.generator.generate_logon(
        foreign_user,
        fixture.target,
        _START + timedelta(seconds=7),
        logon_type=2,
        emit_network_evidence=False,
        session_kind="interactive",
        source="ssh_foreign_descendant_test",
    )
    assert foreign_logon_id != ssh_logon_id
    before_rejected_creation = fixture.state.materialization_digest()
    with pytest.raises(StateError, match="parent crosses session ownership"):
        fixture.generator.generate_process(
            foreign_user,
            fixture.target,
            _START + timedelta(seconds=8),
            foreign_logon_id,
            "/usr/bin/tail",
            "tail -f /var/log/auth.log",
            parent_pid=receiver_pid,
            suppress_command_file_effect=True,
        )
    assert fixture.state.materialization_digest() == before_rejected_creation

    foreign_pid = fixture.generator.generate_process(
        foreign_user,
        fixture.target,
        _START + timedelta(seconds=8),
        foreign_logon_id,
        "/usr/bin/tail",
        "tail -f /var/log/auth.log",
        parent_pid=0,
        suppress_command_file_effect=True,
    )
    ssh_session_identity = fixture.state.get_session_identity(ssh_logon_id)
    foreign_session_identity = fixture.state.get_session_identity(foreign_logon_id)
    assert ssh_session_identity is not None
    assert foreign_session_identity is not None
    assert replace(foreign_session_identity) == foreign_session_identity
    assert foreign_session_identity != ssh_session_identity

    tracked_pids = (receiver_pid, shell_pid, child_pid, foreign_pid)
    before_processes = {
        pid: replace(process)
        for pid in tracked_pids
        if (process := fixture.state.get_process(fixture.target.hostname, pid)) is not None
    }
    assert set(before_processes) == set(tracked_pids)
    before_sessions = {
        logon_id: replace(session)
        for logon_id in (ssh_logon_id, foreign_logon_id)
        if (session := fixture.state.get_session(logon_id)) is not None
    }
    assert set(before_sessions) == {ssh_logon_id, foreign_logon_id}
    before_lifecycles = {
        identity.object_id: fixture.generator._lifecycle_authority.registry.get_process(
            identity.object_id
        )
        for process in before_processes.values()
        if (
            identity := fixture.state.get_process_identity(
                fixture.target.hostname,
                process.pid,
            )
        )
        is not None
    }
    before_state_digest = fixture.state.materialization_digest()
    before_publication = fixture.generator.dispatcher.action_cohort_publication_census()
    continuation = fixture.generator._pending_ssh_session_closures[0]
    authority = fixture.generator._lifecycle_authority
    original_descendants = authority.live_process_descendant_postorder
    foreign_identity = fixture.state.get_process_identity(fixture.target.hostname, foreign_pid)
    assert foreign_identity is not None
    foreign_snapshot = authority.registry.get_process(foreign_identity.object_id)
    assert foreign_snapshot is not None

    def assert_target_state_is_neutral() -> None:
        """Require both session owners and every target process to remain unchanged."""

        assert continuation.receiver_descendant_terminations() is None
        assert fixture.state.materialization_digest() == before_state_digest
        assert fixture.generator.dispatcher.action_cohort_publication_census() == before_publication
        assert fixture.generator.ssh_close_journal_census().exact_pending == 1
        assert (
            fixture.generator.dispatcher.exact_projection_recovery_census().unresolved_recoveries
            == 0
        )
        for pid, expected in before_processes.items():
            assert fixture.state.get_process(fixture.target.hostname, pid) == expected
        for logon_id, expected in before_sessions.items():
            assert fixture.state.get_session(logon_id) == expected
        for object_id, expected in before_lifecycles.items():
            assert (
                fixture.generator._lifecycle_authority.registry.get_process(object_id) == expected
            )
        _assert_no_dispatcher_residue(fixture.generator.dispatcher)

    def inject_foreign_descendant(
        process_object_id: str,
        *,
        limit: int = 4_096,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        return (*original_descendants(process_object_id, limit=limit), foreign_snapshot)

    monkeypatch.setattr(
        authority,
        "live_process_descendant_postorder",
        inject_foreign_descendant,
    )
    with pytest.raises(StateError, match="lifecycle target crossed its session owner"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert_target_state_is_neutral()

    # Even if a copied lifecycle snapshot launders the foreign process through
    # the SSH session's exact membership values, its live State session remains
    # foreign and must independently reject on retry before any cohort claim.
    def copy_ssh_lifecycle_membership(
        process_object_id: str,
        *,
        limit: int = 4_096,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        snapshots = inject_foreign_descendant(process_object_id, limit=limit)
        return tuple(
            replace(
                snapshot,
                token=replace(
                    snapshot.token,
                    logon_id=ssh_session_identity.logon_id,
                    session_id=ssh_session_identity.session_id,
                    logon_type=10,
                ),
                membership=replace(
                    snapshot.membership,
                    owner_kind="session",
                    owner_object_id=ssh_session_identity.object_id,
                    session_object_id=ssh_session_identity.object_id,
                ),
            )
            if snapshot.identity.object_id == foreign_identity.object_id
            else snapshot
            for snapshot in snapshots
        )

    monkeypatch.setattr(
        authority,
        "live_process_descendant_postorder",
        copy_ssh_lifecycle_membership,
    )
    with pytest.raises(StateError, match="lifecycle descendant disagrees with live State"):
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(hours=2))
    assert_target_state_is_neutral()

    ecar_rows, zeek_rows = fixture.close_and_read()
    assert not any(
        row.get("hostname") == fixture.target.hostname
        and row.get("object") == "PROCESS"
        and row.get("action") == "TERMINATE"
        and row.get("pid") in tracked_pids
        for row in ecar_rows
    )
    assert not any(
        row.get("hostname") == fixture.target.hostname
        and row.get("object") == "USER_SESSION"
        and row.get("action") == "LOGOUT"
        for row in ecar_rows
    )
    assert len(zeek_rows) == 1

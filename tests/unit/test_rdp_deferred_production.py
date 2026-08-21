# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public-boundary coverage for exact deferred RDP production ownership."""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.collection_policy import (
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.observation import ObservationDecision, ObservationPolicy
from evidenceforge.events.rdp import RdpSessionState
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG
from evidenceforge.formats import load_format
from evidenceforge.generation.actions.rdp_session import RdpSessionActionBundle
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id
from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import reset_thread_rng

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)
_END = _START + timedelta(days=1)


@dataclass(slots=True)
class _RdpTerminalHarness:
    """Live exact RDP session plus its source sinks and immutable terminal identities."""

    state: StateManager
    dispatcher: EventDispatcher
    generator: ActivityGenerator
    ecar: EcarEmitter
    windows: WindowsEventEmitter
    sysmon: SysmonEventEmitter | None
    zeek: ZeekEmitter
    source_hostname: str
    target_hostname: str
    target_system_process_object_id: str | None
    logon_id: str
    session_object_id: str
    terminal_process_object_ids: tuple[str, ...]
    terminal_process_identities: tuple[ProcessIdentity, ...]
    disconnect_at: datetime
    output_root: Path


def _open_rdp_terminal_harness(
    tmp_path: Path,
    *,
    clock_profile_name: str = "complete",
    output_start_time: datetime | None = None,
    include_sysmon: bool = False,
    modeled_target_pid4: bool = False,
    modeled_source: bool = True,
    session_end_plan: SessionEndPlan | None = None,
    production_timing_runtime: bool = False,
    open_time: datetime = _START,
) -> _RdpTerminalHarness:
    """Open one exact initial RDP generation whose full terminal graph is still pending."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(open_time - timedelta(minutes=5))
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "windows",
        threaded=False,
        source_finalization=True,
    )
    sysmon = None
    emitters = {
        "ecar": ecar,
        "windows_event_security": windows,
        "zeek_conn": zeek,
    }
    dispatcher = EventDispatcher(
        state,
        emitters,
        output_start_time=output_start_time,
        source_timing_planner=SourceTimingPlanner(
            clock_profile_name=clock_profile_name,
            timing_runtime=(
                TimingRuntime(
                    reference_time=_START - timedelta(days=1),
                    namespace="rdp-terminal-production",
                )
                if production_timing_runtime
                else None
            ),
        ),
    )
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_START - timedelta(days=1),
        generation_window_end=_END,
    )
    source = System(
        hostname="WS-01",
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    generator._ip_to_system = (
        {source.ip: source, target.ip: target} if modeled_source else {target.ip: target}
    )
    target_system_process_object_id = None
    if modeled_target_pid4:
        system_plan = state.plan_process_materialization(
            system=target.hostname,
            fixed_pid=4,
            parent_pid=0,
            image="System",
            command_line="",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
            start_time=open_time - timedelta(minutes=5),
        )
        system_process, _receipt = generator._lifecycle_authority.materialize_process(system_plan)
        target_system_process_object_id = system_process.ecar_object_id
    source_identity = None
    source_pid = -1
    source_ip = "198.51.100.25"
    source_system = None
    if modeled_source:
        source_logon = generator.generate_logon(
            user,
            source,
            open_time - timedelta(seconds=30),
            logon_type=2,
        )
        source_pid = generator.generate_process(
            user,
            source,
            open_time - timedelta(seconds=3),
            source_logon,
            r"C:\Windows\System32\mstsc.exe",
            f"mstsc.exe /v:{target.hostname}",
            parent_pid=4,
        )
        source_identity = state.get_process_identity(source.hostname, source_pid)
        assert source_identity is not None
        source_ip = source.ip
        source_system = source
    _uid, logon_id = generator._execute_rdp_session_bundle(
        user=user,
        target_system=target,
        time=open_time,
        source_ip=source_ip,
        source_system=source_system,
        source_pid=source_pid,
        source_port=50_001,
        preserve_explicit_source=not modeled_source,
        session_end_plan=session_end_plan,
    )
    session = state.get_session(logon_id)
    session_identity = state.get_session_identity(logon_id)
    assert session is not None and session_identity is not None
    assert session.network_close_time is not None
    target_pids = (
        session.session_winlogon_pid,
        session.session_user_manager_pid,
        session.explorer_pid,
    )
    assert all(pid is not None for pid in target_pids)
    target_identities = tuple(
        state.get_process_identity(target.hostname, pid) for pid in target_pids if pid is not None
    )
    assert len(target_identities) == 3 and all(
        identity is not None for identity in target_identities
    )
    if include_sysmon:
        # The existing harness intentionally omits the production deployment and
        # host-boot timing setup needed by Sysmon Event 1. Attach the real sink
        # only at the terminal boundary under test so its Event 5 path remains
        # production-identical without weakening those unrelated prerequisites.
        sysmon = SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "sysmon",
            threaded=False,
            source_finalization=True,
        )
        emitters["windows_event_sysmon"] = sysmon
    return _RdpTerminalHarness(
        state=state,
        dispatcher=dispatcher,
        generator=generator,
        ecar=ecar,
        windows=windows,
        sysmon=sysmon,
        zeek=zeek,
        source_hostname=source.hostname if modeled_source else "",
        target_hostname=target.hostname,
        target_system_process_object_id=target_system_process_object_id,
        logon_id=logon_id,
        session_object_id=session_identity.object_id,
        terminal_process_object_ids=(
            *((source_identity.object_id,) if source_identity is not None else ()),
            *(identity.object_id for identity in target_identities if identity is not None),
        ),
        terminal_process_identities=(
            *((source_identity,) if source_identity is not None else ()),
            *(identity for identity in target_identities if identity is not None),
        ),
        disconnect_at=session.network_close_time,
        output_root=tmp_path,
    )


def _rdp_terminal_source(
    format_name: str,
    hostname: str,
    *,
    enabled: bool = True,
) -> SourceInstanceDeployment:
    """Return one exact endpoint source for compiled RDP terminal projection."""

    descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
    return SourceInstanceDeployment(
        identity=SourceInstanceIdentity(
            source_instance=exact_source_instance_id(descriptor.family, hostname),
            hostname=hostname,
            family=descriptor.family,
        ),
        formats=(format_name,),
        policy=SourceCollectionPolicy(
            enabled=enabled,
            capabilities=descriptor.capabilities,
        ),
    )


def _compiled_rdp_terminal_deployment(*, enabled: bool = True) -> CompiledCollectionDeployment:
    """Return exact eCAR and Security instances for both RDP endpoints."""

    return CompiledCollectionDeployment(
        tuple(
            _rdp_terminal_source(format_name, hostname, enabled=enabled)
            for hostname in ("WS-01", "RDS-01")
            for format_name in ("ecar", "windows_event_security")
        )
    )


def _aborted_engine_for_rdp_harness(harness: _RdpTerminalHarness) -> GenerationEngine:
    """Return the real failed-generation terminal path with only RDP work pending."""

    engine = GenerationEngine.__new__(GenerationEngine)
    engine.activity_generator = harness.generator
    engine.dispatcher = harness.dispatcher
    engine.emitters = {}
    engine.end_time = _END
    engine._source_finalization_coordinator = None
    engine._ssh_lifecycles_finalized = True
    engine._rdp_lifecycles_finalized = False
    engine._persistent_smb_terminal_asserted = True
    engine._application_channels_finalized = True
    engine._foreground_lifecycles_finalized = True
    engine._terminal_runtime_cleanup_finalized = True
    engine._exact_projection_recoveries_finalized = True
    engine._terminal_transient_census_asserted = True
    engine._finalization_complete = False
    engine._finalization_aborted = False
    engine._source_coordinator_closed = False
    engine._ids_alert_summary_applied = True
    engine._expected_close_emitters = None
    engine._closed_emitter_names = set()
    engine._exact_projection_recovery_dispatcher = None
    return engine


def _baseline_owner_for_rdp_harness(
    harness: _RdpTerminalHarness,
) -> tuple[GenerationEngine, User, System, ProcessIdentity]:
    """Return the real baseline teardown owner for one pending source-side mstsc."""

    source_identity = next(
        identity
        for identity in harness.terminal_process_identities
        if identity.hostname == harness.source_hostname
    )
    user = User(
        username=source_identity.principal,
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    source = System(
        hostname=harness.source_hostname,
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    engine = GenerationEngine.__new__(GenerationEngine)
    engine.state_manager = harness.state
    engine.activity_generator = harness.generator
    engine.scenario = SimpleNamespace(
        environment=SimpleNamespace(users=[user], systems=[source]),
        personas=[],
    )
    engine._system_pids = {}
    return engine, user, source, source_identity


@pytest.mark.parametrize(
    ("open_time", "output_start_time"),
    (
        (_START, None),
        (_START + timedelta(minutes=59, seconds=30), _END),
    ),
    ids=("within-hour-visible", "cross-hour-warmup-suppressed"),
)
def test_hourly_logoff_drains_exact_rdp_source_before_generic_session_teardown(
    open_time: datetime,
    output_start_time: datetime | None,
    tmp_path: Path,
) -> None:
    """A source logoff cannot consume mstsc/session before the due RDP journal entry."""

    harness = _open_rdp_terminal_harness(
        tmp_path,
        output_start_time=output_start_time,
        open_time=open_time,
    )
    engine, user, source, source_identity = _baseline_owner_for_rdp_harness(harness)
    source_session = harness.state.get_session(source_identity.logon_id)
    assert source_session is not None
    assert source_session.last_activity_time == harness.disconnect_at
    hour_start = open_time.replace(minute=0, second=0, microsecond=0)
    planned_logoff = open_time + timedelta(seconds=15)
    assert planned_logoff < harness.disconnect_at
    if output_start_time is not None:
        assert harness.disconnect_at >= hour_start + timedelta(hours=1)

    BaselineMixin._generate_logoffs_for_hour(
        engine,
        [user],
        hour_start,
        {
            (source.hostname, source_identity.logon_id): (
                planned_logoff - hour_start
            ).total_seconds()
        },
    )

    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert harness.state.get_process(source.hostname, source_identity.pid) is None
    assert harness.state.get_session(source_identity.logon_id) is None
    assert harness.generator.rdp_lifecycle_journal_census().disconnected_generations == 1
    assert harness.generator._rdp_session_lifecycle_frontier() == harness.disconnect_at

    primary = RuntimeError("unrelated generation failure")
    abort_engine = _aborted_engine_for_rdp_harness(harness)
    abort_engine.progress_callback = None
    abort_engine._abort_failed_generation(primary)
    assert not getattr(primary, "__notes__", ())
    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 0

    _close_rdp_terminal_harness(harness)
    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    source_terminations = [
        row
        for row in ecar_rows
        if row.get("object") == "PROCESS"
        and row.get("action") == "TERMINATE"
        and row.get("objectID") == source_identity.object_id
    ]
    assert len(source_terminations) == (0 if output_start_time is not None else 1)


def test_hourly_stale_cleanup_drains_due_rdp_before_consuming_exact_mstsc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stale cleanup delegates a due exact mstsc close to the RDP journal owner."""

    harness = _open_rdp_terminal_harness(tmp_path)
    engine, user, source, source_identity = _baseline_owner_for_rdp_harness(harness)
    stale_frontier = source_identity.started_at + timedelta(hours=12)
    assert harness.disconnect_at < stale_frontier < _END
    monkeypatch.setattr(
        "evidenceforge.generation.engine.baseline._get_rng",
        lambda: random.Random(1),
    )

    BaselineMixin._terminate_stale_processes(engine, stale_frontier)

    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert harness.state.get_process(source.hostname, source_identity.pid) is None
    assert harness.generator.rdp_lifecycle_journal_census().disconnected_generations == 1

    harness.generator.generate_logoff(
        user,
        source,
        stale_frontier + timedelta(seconds=1),
        source_identity.logon_id,
        logon_type=2,
    )
    harness.generator.finalize_rdp_session_lifecycles(_END)
    _close_rdp_terminal_harness(harness)


def test_directly_missing_rdp_source_session_still_fails_closed(
    tmp_path: Path,
) -> None:
    """Bypassing hourly ownership cannot weaken exact source-session identity checks."""

    harness = _open_rdp_terminal_harness(tmp_path)
    _engine, user, source, source_identity = _baseline_owner_for_rdp_harness(harness)
    harness.generator.generate_logoff(
        user,
        source,
        harness.disconnect_at + timedelta(seconds=30),
        source_identity.logon_id,
        logon_type=2,
    )

    with pytest.raises(StateError, match="Action cohort live session target is absent or drifted"):
        harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    _close_rdp_terminal_harness(harness)


@pytest.mark.parametrize("modeled_target_pid4", (False, True), ids=("virtual", "modeled"))
@pytest.mark.parametrize("failure_mode", ("success", "fail-before", "lost-return"))
def test_aborted_rdp_target_drain_reauthenticates_exact_pid4_parent(
    modeled_target_pid4: bool,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Abort cleanup preserves modeled PID-4 ancestry and retry-exact terminal rows."""

    harness = _open_rdp_terminal_harness(
        tmp_path,
        modeled_target_pid4=modeled_target_pid4,
    )
    winlogon = next(
        identity
        for identity in harness.terminal_process_identities
        if identity.image.casefold().endswith("winlogon.exe")
    )
    lifecycle = harness.generator._lifecycle_authority.registry.get_process(winlogon.object_id)
    assert lifecycle is not None
    assert lifecycle.identity.parent_object_id == (harness.target_system_process_object_id or "")

    original_terminate = RdpSessionActionBundle.terminate_exact_rdp_process
    selected_calls = 0

    def faulting_terminate(
        owner: RdpSessionActionBundle,
        continuation: object,
        identity: ProcessIdentity,
        terminate_time: datetime,
    ) -> object:
        nonlocal selected_calls
        if identity.object_id != winlogon.object_id:
            return original_terminate(owner, continuation, identity, terminate_time)
        selected_calls += 1
        if failure_mode == "fail-before" and selected_calls == 1:
            raise OSError("injected modeled-parent RDP fail-before")
        result = original_terminate(owner, continuation, identity, terminate_time)
        if failure_mode == "lost-return" and selected_calls == 1:
            raise OSError("injected modeled-parent RDP lost-return")
        return result

    monkeypatch.setattr(
        RdpSessionActionBundle,
        "terminate_exact_rdp_process",
        faulting_terminate,
    )
    engine = _aborted_engine_for_rdp_harness(harness)
    if failure_mode == "success":
        engine._finalize(generation_succeeded=False)
    else:
        with pytest.raises(OSError, match=f"modeled-parent RDP {failure_mode}"):
            engine._finalize(generation_succeeded=False)
        engine._finalize(generation_succeeded=False)

    assert selected_calls == (1 if failure_mode == "success" else 2)
    assert engine._finalization_complete
    assert harness.state.get_session(harness.logon_id) is None
    live_process_object_ids = {
        process.ecar_object_id
        for hostname in (harness.source_hostname, harness.target_hostname)
        for process in harness.state.get_processes_on_system(hostname)
    }
    assert live_process_object_ids.isdisjoint(harness.terminal_process_object_ids)
    journal = harness.generator.rdp_lifecycle_journal_census()
    assert journal.prepared_reservations == 0
    assert journal.pending_generations == 0
    manager = harness.generator.rdp_session_manager.census()
    assert manager.connected_sessions == 0
    assert manager.disconnected_sessions == 0
    assert manager.logged_out_sessions == 1
    assert manager.active_operations == 0
    assert manager.active_leases == 0

    _close_rdp_terminal_harness(harness)
    recovery = harness.dispatcher.exact_projection_recovery_census()
    cohort = harness.dispatcher.action_cohort_publication_census()
    assert recovery.unresolved_recoveries == 0
    assert recovery.reserved_recoveries == 0
    assert recovery.active_recoveries == 0
    assert recovery.authority.active_batches == 0
    assert recovery.authority.prepared_batches == 0
    assert recovery.authority.retained_rows == 0
    assert cohort.prepared_batches == 0
    assert cohort.claimed_batches == 0
    assert cohort.retained_members == 0
    assert cohort.prepared_projections == 0
    assert cohort.projection_groups == 0

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    for object_id in harness.terminal_process_object_ids:
        assert (
            sum(
                row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("objectID") == object_id
                for row in ecar_rows
            )
            == 1
        )


def test_aborted_rdp_target_drain_rejects_a_lost_modeled_pid4_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A published PID-4 parent may not silently degrade to the virtual-parent shape."""

    harness = _open_rdp_terminal_harness(tmp_path, modeled_target_pid4=True)
    winlogon = next(
        identity
        for identity in harness.terminal_process_identities
        if identity.image.casefold().endswith("winlogon.exe")
    )
    registry = harness.generator._lifecycle_authority.registry
    original_lookup = type(registry).process_for_pid_at

    def hide_target_system_parent(
        owner: object,
        hostname: str,
        pid: int,
        canonical_time: datetime,
    ) -> object:
        if hostname == harness.target_hostname and pid == 4:
            return None
        return original_lookup(owner, hostname, pid, canonical_time)

    engine = _aborted_engine_for_rdp_harness(harness)
    with monkeypatch.context() as fault:
        fault.setattr(type(registry), "process_for_pid_at", hide_target_system_parent)
        with pytest.raises(
            StateError,
            match="registered process has no exact lifecycle parent",
        ):
            engine._finalize(generation_succeeded=False)

    assert not engine._finalization_complete
    assert harness.state.get_process(harness.target_hostname, winlogon.pid) is not None
    retained = registry.get_process(winlogon.object_id)
    assert retained is not None
    assert retained.closed_at is None
    cohort = harness.dispatcher.action_cohort_publication_census()
    assert cohort.prepared_batches == 0
    assert cohort.claimed_batches == 0
    assert cohort.prepared_projections == 0

    engine._finalize(generation_succeeded=False)
    assert engine._finalization_complete
    assert harness.state.get_process(harness.target_hostname, winlogon.pid) is None
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    assert (
        sum(
            row.get("object") == "PROCESS"
            and row.get("action") == "TERMINATE"
            and row.get("objectID") == winlogon.object_id
            for row in ecar_rows
        )
        == 1
    )


@pytest.mark.parametrize("failure_seam", ("action-cohort", "state-neutral"))
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_warmup_suppressed_rdp_terminal_chain_retries_without_rows(
    failure_seam: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fully suppressed RDP terminal chain still closes every canonical owner exactly once."""

    harness = _open_rdp_terminal_harness(
        tmp_path,
        output_start_time=_END,
    )
    original_claim = EventDispatcher.claimed_action_cohort
    original_state_neutral = EventDispatcher.publish_state_neutral_exact_projection
    injected = False

    @contextmanager
    def faulting_claim(
        owner: EventDispatcher,
        batch: object,
    ) -> Iterator[object]:
        nonlocal injected
        if failure_seam == "action-cohort" and not injected and failure_mode == "fail-before":
            injected = True
            raise OSError("injected suppressed RDP action-cohort fail-before")
        with original_claim(owner, batch) as capability:
            yield capability
        result = capability.result
        if (
            failure_seam == "action-cohort"
            and not injected
            and failure_mode == "lost-return"
            and result is not None
            and result.receipt.root_action_id.endswith(":process-terminate")
        ):
            injected = True
            raise OSError("injected suppressed RDP action-cohort lost-return")

    def faulting_state_neutral(owner: EventDispatcher, carrier: object) -> object:
        nonlocal injected
        if failure_seam == "state-neutral" and not injected and failure_mode == "fail-before":
            injected = True
            raise OSError("injected suppressed RDP state-neutral fail-before")
        result = original_state_neutral(owner, carrier)
        if failure_seam == "state-neutral" and not injected and failure_mode == "lost-return":
            injected = True
            error = OSError("injected suppressed RDP state-neutral lost-return")
            error.state_neutral_projection_receipt = result.receipt
            error.state_neutral_projection_result = result
            raise error
        return result

    monkeypatch.setattr(EventDispatcher, "claimed_action_cohort", faulting_claim)
    monkeypatch.setattr(
        EventDispatcher,
        "publish_state_neutral_exact_projection",
        faulting_state_neutral,
    )
    with pytest.raises(OSError, match=f"suppressed RDP {failure_seam} {failure_mode}"):
        harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 0
    manager = harness.generator.rdp_session_manager.census()
    assert manager.connected_sessions == 0
    assert manager.disconnected_sessions == 0
    assert manager.logged_out_sessions == 1
    assert manager.active_operations == 0
    assert manager.active_leases == 0
    live_process_object_ids = {
        process.ecar_object_id
        for hostname in (harness.source_hostname, harness.target_hostname)
        for process in harness.state.get_processes_on_system(hostname)
    }
    assert live_process_object_ids.isdisjoint(harness.terminal_process_object_ids)

    _close_rdp_terminal_harness(harness)
    exact = harness.dispatcher.exact_projection_recovery_census()
    cohort = harness.dispatcher.action_cohort_publication_census()
    assert exact.unresolved_recoveries == 0
    assert exact.reserved_recoveries == 0
    assert exact.active_recoveries == 0
    assert exact.authority.active_batches == 0
    assert exact.authority.prepared_batches == 0
    assert exact.authority.retained_rows == 0
    assert cohort.prepared_batches == 0
    assert cohort.claimed_batches == 0
    assert cohort.retained_members == 0
    assert cohort.prepared_projections == 0
    assert cohort.projection_groups == 0
    assert _read_json_lines(harness.output_root / "ecar", "ecar.json") == []
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "windows").rglob("*.xml")
    )
    assert "<EventID>4689</EventID>" not in rendered_windows
    assert "<EventID>4779</EventID>" not in rendered_windows
    assert "<EventID>4634</EventID>" not in rendered_windows


def test_visible_rdp_process_terminal_rejects_a_zero_row_renderer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A visible process terminal cannot use the warm-up zero-row disposition."""

    harness = _open_rdp_terminal_harness(tmp_path)

    with monkeypatch.context() as fault:
        fault.setattr(EcarEmitter, "emit", lambda _owner, _event: None)
        fault.setattr(WindowsEventEmitter, "emit", lambda _owner, _event: None)
        with pytest.raises(
            EventContractError,
            match="visible terminal projection staged no durable row",
        ):
            harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1
    assert harness.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    assert harness.dispatcher.action_cohort_publication_census().prepared_batches == 0

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    for object_id in harness.terminal_process_object_ids:
        assert (
            sum(
                row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("objectID") == object_id
                for row in ecar_rows
            )
            == 1
        )


def test_visible_rdp_disconnect_rejects_a_zero_row_renderer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A visible 4779 publication must stage a row before its canonical owner commits."""

    harness = _open_rdp_terminal_harness(tmp_path)
    original = EventDispatcher.publish_state_neutral_exact_projection
    injected = False

    def zero_first_disconnect(owner: EventDispatcher, carrier: object) -> object:
        nonlocal injected
        if injected:
            return original(owner, carrier)
        injected = True
        with monkeypatch.context() as fault:
            fault.setattr(EcarEmitter, "emit", lambda _owner, _event: None)
            fault.setattr(WindowsEventEmitter, "emit", lambda _owner, _event: None)
            return original(owner, carrier)

    monkeypatch.setattr(
        EventDispatcher,
        "publish_state_neutral_exact_projection",
        zero_first_disconnect,
    )
    with pytest.raises(
        EventContractError,
        match="visible RDP disconnect staged no durable row",
    ):
        harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1
    assert harness.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    _close_rdp_terminal_harness(harness)
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "windows").rglob("*.xml")
    )
    assert rendered_windows.count("<EventID>4779</EventID>") == 1


@pytest.mark.parametrize("zero_source_shape", ("post-window", "mixed", "dropped", "filtered"))
def test_nonsuppressed_rdp_terminal_zero_source_shape_fails_closed(
    zero_source_shape: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Window, drop, and filter gaps cannot impersonate exact warm-up suppression."""

    harness = _open_rdp_terminal_harness(tmp_path)
    if zero_source_shape in {"post-window", "mixed"}:
        harness.dispatcher.output_end_time = harness.disconnect_at
    elif zero_source_shape == "filtered":
        harness.dispatcher.collection_deployment = _compiled_rdp_terminal_deployment(enabled=False)

    with monkeypatch.context() as fault:
        if zero_source_shape == "mixed":

            def mixed_decision(format_name: str, _event: object) -> ObservationDecision:
                return ObservationDecision(status="dropped" if format_name == "ecar" else "visible")

            fault.setattr(harness.dispatcher.observation_policy, "decide", mixed_decision)
        elif zero_source_shape == "dropped":

            def dropped_decision(_format_name: str, _event: object) -> ObservationDecision:
                return ObservationDecision(status="dropped")

            fault.setattr(harness.dispatcher.observation_policy, "decide", dropped_decision)
        with pytest.raises(
            StateError,
            match="visible RDP terminal timing proof requires source frontiers",
        ):
            harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1
    exact = harness.dispatcher.exact_projection_recovery_census()
    cohort = harness.dispatcher.action_cohort_publication_census()
    assert exact.unresolved_recoveries == 0
    assert exact.authority.active_batches == 0
    assert cohort.prepared_batches == 0
    assert cohort.prepared_projections == 0

    harness.dispatcher.output_end_time = None
    harness.dispatcher.collection_deployment = None
    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    _close_rdp_terminal_harness(harness)


def _close_rdp_terminal_harness(harness: _RdpTerminalHarness) -> None:
    """Finish exact source recovery and close every harness sink in owner order."""

    harness.dispatcher.drain_exact_projection_recoveries()
    harness.dispatcher.assert_exact_projection_recoveries_drained()
    coordinator = SourceFinalizationCoordinator(
        tuple(emitter for emitter in (harness.windows, harness.sysmon) if emitter is not None),
        ExactPublicationAuthority(
            capacity=1,
            row_capacity=256,
            byte_capacity=8 * 1024 * 1024,
        ),
    )
    coordinator.finalize()
    harness.windows.close()
    if harness.sysmon is not None:
        harness.sysmon.close()
    coordinator.mark_closed()
    harness.ecar.close()
    harness.zeek.close()


def _read_json_lines(root: Path, filename: str) -> list[dict[str, object]]:
    """Read every non-empty JSON line under one deterministic test sink."""

    return [
        json.loads(line)
        for output in root.rglob(filename)
        for line in output.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _xml_events(rendered: str, event_id: int) -> tuple[str, ...]:
    """Return complete Windows XML records for one native event identifier."""

    return tuple(
        event
        for event in re.findall(r"<Event\b.*?</Event>", rendered, flags=re.DOTALL)
        if f"<EventID>{event_id}</EventID>" in event
    )


def _windows_security_time(
    rendered: str,
    event_id: int,
    *,
    process_name: str = "",
) -> datetime:
    """Return the one matching rendered Windows Security timestamp."""

    matches: list[datetime] = []
    for event in re.findall(r"<Event\b.*?</Event>", rendered, flags=re.DOTALL):
        if f"<EventID>{event_id}</EventID>" not in event:
            continue
        if process_name and process_name.casefold() not in event.casefold():
            continue
        timestamp = re.search(r'<TimeCreated\s+SystemTime="([^"]+)"', event)
        assert timestamp is not None
        matches.append(datetime.fromisoformat(timestamp.group(1).replace("Z", "+00:00")))
    assert len(matches) == 1
    return matches[0]


def test_exact_rdp_deadline_rejects_insufficient_headroom_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An impossible terminal window rejects before port, State, or journal publication."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(_START)
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "windows",
        threaded=False,
        source_finalization=True,
    )
    emitters = {
        "ecar": ecar,
        "windows_event_security": windows,
        "zeek_conn": zeek,
    }
    dispatcher = EventDispatcher(state, emitters, output_end_time=_END)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_START,
        generation_window_end=_END,
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    generator._ip_to_system = {target.ip: target}
    before_state = state.materialization_digest()
    before_frontier = generator._rdp_session_lifecycle_frontier()
    before_journal = generator.rdp_lifecycle_journal_census()
    before_manager = generator.rdp_session_manager.census()
    before_timing = generator.timing_runtime.state_digest()
    before_source_timing = generator._source_timing_planner.state_digest()
    port_calls = 0
    sinks_closed = False

    def count_port(*_args: object, **_kwargs: object) -> int:
        nonlocal port_calls
        port_calls += 1
        return 50_001

    monkeypatch.setattr(generator, "_allocate_ephemeral_port", count_port)
    try:
        with pytest.raises(StateError, match="no half-open disconnect/logout window"):
            generator._execute_rdp_session_bundle(
                user=user,
                target_system=target,
                time=_END - timedelta(seconds=10),
                source_ip="198.51.100.25",
                source_system=None,
                preserve_explicit_source=True,
            )

        assert port_calls == 0
        assert state.materialization_digest() == before_state
        assert generator._rdp_session_lifecycle_frontier() == before_frontier
        assert generator.rdp_lifecycle_journal_census() == before_journal
        assert generator.rdp_session_manager.census() == before_manager
        assert generator.timing_runtime.state_digest() == before_timing
        assert generator._source_timing_planner.state_digest() == before_source_timing
        assert not state.list_open_connections()
        assert not state.get_sessions_on_system(target.hostname)

        valid_time = _START + timedelta(hours=1)
        uid, logon_id = generator._execute_rdp_session_bundle(
            user=user,
            target_system=target,
            time=valid_time,
            source_ip="198.51.100.25",
            source_system=None,
            preserve_explicit_source=True,
        )
        assert uid
        assert state.get_session(logon_id) is not None
        assert generator._rdp_session_lifecycle_frontier() == valid_time
        assert port_calls == 1

        generator.finalize_rdp_session_lifecycles(_END)
        generator.assert_rdp_session_lifecycles_drained()
        dispatcher.drain_exact_projection_recoveries()
        dispatcher.assert_exact_projection_recoveries_drained()
        coordinator = SourceFinalizationCoordinator(
            (windows,),
            ExactPublicationAuthority(
                capacity=1,
                row_capacity=256,
                byte_capacity=8 * 1024 * 1024,
            ),
        )
        coordinator.finalize()
        windows.close()
        coordinator.mark_closed()
        ecar.close()
        zeek.close()
        sinks_closed = True
    finally:
        if not sinks_closed:
            windows.close()
            ecar.close()
            zeek.close()


def test_compiled_enterprise_rdp_logout_reserves_source_frontiers_before_output_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compiled enterprise logout keeps mandatory endpoint rows inside the output fence."""

    closure_tail = SourceTimingPlanner.max_session_closure_tail(("ecar", "windows_event_security"))
    expected_deadline = _END - closure_tail - timedelta(microseconds=1)
    original_logout = RdpSessionActionBundle.logout_exact_rdp_session
    explicit_storyline_end = SessionEndPlan(
        _END,
        "explicit_storyline",
        "rdp-window-close",
    )
    for modeled_source, explicit_end in ((True, None), (False, explicit_storyline_end)):
        harness = _open_rdp_terminal_harness(
            tmp_path / ("modeled" if modeled_source else "external"),
            clock_profile_name="enterprise_standard",
            modeled_source=modeled_source,
            session_end_plan=explicit_end,
            production_timing_runtime=True,
        )
        snapshot = harness.generator.rdp_session_manager.get(harness.session_object_id)
        assert snapshot is not None
        assert snapshot.identity.hard_deadline == expected_deadline
        state_end_plan = harness.state.get_session_end_plan(harness.logon_id)
        assert state_end_plan is not None
        assert state_end_plan.canonical_end == snapshot.identity.hard_deadline
        assert state_end_plan.authority == (
            explicit_end.authority if explicit_end is not None else "action_bundle"
        )
        assert state_end_plan.storyline_event_id == (
            explicit_end.storyline_event_id if explicit_end is not None else ""
        )
        harness.dispatcher.collection_deployment = _compiled_rdp_terminal_deployment()
        harness.dispatcher.observation_policy = ObservationPolicy("enterprise_standard")
        harness.dispatcher.output_end_time = _END

        if explicit_end is None:
            harness.generator.finalize_rdp_session_lifecycles(_END)
        else:
            logout_calls = 0

            def fail_first_logout(
                owner: RdpSessionActionBundle,
                continuation: object,
                logout_time: datetime,
            ) -> None:
                nonlocal logout_calls
                logout_calls += 1
                if logout_calls == 1:
                    raise OSError("injected bounded explicit RDP logout failure")
                original_logout(owner, continuation, logout_time)

            with monkeypatch.context() as fault:
                fault.setattr(
                    RdpSessionActionBundle,
                    "logout_exact_rdp_session",
                    fail_first_logout,
                )
                with pytest.raises(OSError, match="bounded explicit RDP logout failure"):
                    harness.generator.finalize_rdp_session_lifecycles(_END)
                assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1
                harness.generator.finalize_rdp_session_lifecycles(_END)
            assert logout_calls == 2
        harness.generator.assert_rdp_session_lifecycles_drained()
        assert harness.state.get_session(harness.logon_id) is None
        live_process_object_ids = {
            process.ecar_object_id
            for hostname in tuple(
                item for item in (harness.source_hostname, harness.target_hostname) if item
            )
            for process in harness.state.get_processes_on_system(hostname)
        }
        assert live_process_object_ids.isdisjoint(harness.terminal_process_object_ids)

        terminal = harness.generator.rdp_lifecycle_journal_census()
        manager = harness.generator.rdp_session_manager.census()
        assert terminal.prepared_reservations == 0
        assert terminal.pending_generations == 0
        assert terminal.disconnected_generations == 0
        assert manager.connected_sessions == 0
        assert manager.disconnected_sessions == 0
        assert manager.logged_out_sessions == 1
        assert manager.active_operations == 0
        assert manager.active_leases == 0
        assert manager.application.open_channels == 0
        assert manager.application.active_operations == 0
        assert manager.application.prepared_admissions == 0
        assert manager.application.claimed_admissions == 0

        _close_rdp_terminal_harness(harness)
        recovery = harness.dispatcher.exact_projection_recovery_census()
        cohort = harness.dispatcher.action_cohort_publication_census()
        assert recovery.unresolved_recoveries == 0
        assert recovery.reserved_recoveries == 0
        assert recovery.active_recoveries == 0
        assert recovery.authority.active_batches == 0
        assert recovery.authority.prepared_batches == 0
        assert recovery.authority.retained_rows == 0
        assert cohort.prepared_batches == 0
        assert cohort.claimed_batches == 0
        assert cohort.retained_members == 0
        assert cohort.prepared_projections == 0
        assert cohort.projection_groups == 0

        rendered_windows = "\n".join(
            output.read_text(encoding="utf-8")
            for output in (harness.output_root / "windows").rglob("*.xml")
        )
        assert rendered_windows.count("<EventID>4634</EventID>") == 1
        assert _windows_security_time(rendered_windows, 4634) < _END
        windows_terminations = _xml_events(rendered_windows, 4689)
        assert all(
            datetime.fromisoformat(timestamp.replace("Z", "+00:00")) < _END
            for timestamp in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
        )

        ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
        assert all(
            datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < _END for row in ecar_rows
        )
        ecar_logouts = [
            row
            for row in ecar_rows
            if row.get("object") == "USER_SESSION"
            and row.get("action") == "LOGOUT"
            and row.get("objectID") == harness.session_object_id
        ]
        assert len(ecar_logouts) == 1
        assert datetime.fromtimestamp(ecar_logouts[0]["timestamp_ms"] / 1_000, tz=UTC) < _END

        target_identities = tuple(
            identity
            for identity in harness.terminal_process_identities
            if identity.hostname == harness.target_hostname
        )
        assert len(target_identities) == 3
        for identity in target_identities:
            assert (
                sum(
                    f'<Data Name="ProcessId">0x{identity.pid:x}</Data>' in event
                    and f'<Data Name="ProcessName">{identity.image}</Data>' in event
                    for event in windows_terminations
                )
                == 1
            )
            assert (
                sum(
                    row.get("object") == "PROCESS"
                    and row.get("action") == "TERMINATE"
                    and row.get("objectID") == identity.object_id
                    for row in ecar_rows
                )
                == 1
            )


class _SysmonSubclass(SysmonEventEmitter):
    """Concrete-type impostor that inherits the instance-bound exact marker."""


class _DuckExactSysmon:
    """Duck marker whose descriptor must not authorize an exact sink."""

    marker_reads = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if dispatcher admission executes a foreign marker callback."""

        type(self).marker_reads += 1
        raise AssertionError("duck Sysmon exact marker executed")


def test_rdp_exact_sysmon_admission_requires_bound_concrete_sink(tmp_path: Path) -> None:
    """Direct, subclassed, and duck-marked Sysmon targets remain fail-closed."""

    direct = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "direct",
        threaded=False,
    )
    subclass = _SysmonSubclass(
        load_format("windows_event_sysmon"),
        tmp_path / "subclass",
        threaded=False,
        source_finalization=True,
    )
    duck = _DuckExactSysmon()
    try:
        for emitter in (direct, subclass, duck):
            with pytest.raises(
                EventContractError,
                match="windows_event_sysmon.*unsupported before rendering",
            ):
                EventDispatcher._require_exact_projection_target(
                    "windows_event_sysmon",
                    emitter,
                )
        assert _DuckExactSysmon.marker_reads == 0
    finally:
        direct.close()
        subclass.close()


@pytest.mark.parametrize("failure_mode", ("success", "fail-before", "lost-return"))
def test_visible_rdp_terminal_chain_publishes_exact_sysmon_process_closes(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Visible RDP close owns one correlated Security, Sysmon, and eCAR process terminal."""

    harness = _open_rdp_terminal_harness(tmp_path, include_sysmon=True)
    sysmon = harness.sysmon
    assert sysmon is not None
    original_claim = EventDispatcher.claimed_action_cohort
    injected = False

    @contextmanager
    def faulting_claim(
        owner: EventDispatcher,
        batch: object,
    ) -> Iterator[object]:
        nonlocal injected
        if failure_mode == "fail-before" and not injected:
            injected = True
            raise OSError("injected exact Sysmon RDP fail-before")
        with original_claim(owner, batch) as capability:
            yield capability
        result = capability.result
        if (
            failure_mode == "lost-return"
            and not injected
            and result is not None
            and result.receipt.root_action_id.endswith(":process-terminate")
        ):
            injected = True
            raise OSError("injected exact Sysmon RDP lost-return")

    if failure_mode != "success":
        monkeypatch.setattr(EventDispatcher, "claimed_action_cohort", faulting_claim)
        with pytest.raises(OSError, match=f"exact Sysmon RDP {failure_mode}"):
            harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)
        disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
        assert disconnected is not None
        assert disconnected.state is RdpSessionState.DISCONNECTED
        assert harness.generator.rdp_lifecycle_journal_census().pending_generations == 1

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)

    exact = sysmon.exact_candidate_census()
    assert exact.current_rows == 0
    assert exact.current_bytes == 0
    assert exact.current_participants == 0
    assert exact.high_water_rows >= len(harness.terminal_process_identities)
    assert exact.high_water_participants == len(harness.terminal_process_identities)
    recovery = harness.dispatcher.exact_projection_recovery_census()
    assert recovery.unresolved_recoveries == 0
    assert recovery.authority.active_batches == 0
    assert recovery.authority.prepared_batches == 0
    assert recovery.authority.retained_rows == 0

    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "windows").rglob("*.xml")
    )
    rendered_sysmon = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "sysmon").rglob("*.xml")
    )
    windows_terminations = _xml_events(rendered_windows, 4689)
    sysmon_terminations = _xml_events(rendered_sysmon, 5)
    assert len(windows_terminations) == len(harness.terminal_process_identities)
    assert len(sysmon_terminations) == len(harness.terminal_process_identities)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    for identity in harness.terminal_process_identities:
        assert (
            sum(
                f'<Data Name="ProcessId">0x{identity.pid:x}</Data>' in event
                and f'<Data Name="ProcessName">{identity.image}</Data>' in event
                for event in windows_terminations
            )
            == 1
        )
        assert (
            sum(
                f'<Data Name="ProcessId">{identity.pid}</Data>' in event
                and f'<Data Name="Image">{identity.image}</Data>' in event
                for event in sysmon_terminations
            )
            == 1
        )
        assert (
            sum(
                row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("objectID") == identity.object_id
                for row in ecar_rows
            )
            == 1
        )


def test_activity_generator_uses_injected_shared_rdp_owner() -> None:
    """Production may inject exactly one RDP manager over the shared registry."""

    state = StateManager()
    registry = ApplicationChannelRegistry(window_start=_START, window_end=_END)
    manager = RdpReconnectStateManager(
        application_registry=registry,
        window_start=_START,
        window_end=_END,
    )

    generator = ActivityGenerator(
        state,
        {},
        application_channel_registry=registry,
        rdp_session_manager=manager,
        generation_window_start=_START,
        generation_window_end=_END,
    )

    assert generator.rdp_session_manager is manager
    assert generator.rdp_session_manager.application_registry is registry


def test_windows_security_renders_exact_rdp_reconnect_and_disconnect(tmp_path) -> None:
    """Typed RDP transitions render Security 4778/4779 with one preserved tuple."""

    output = tmp_path / "windows.xml"
    emitter = WindowsEventEmitter(load_format("windows_event_security"), output, buffer_size=1)
    host = HostContext(
        hostname="RDS-01",
        ip="10.20.0.10",
        fqdn="RDS-01.example.test",
        os="Windows Server 2022",
        os_category="windows",
        system_type="server",
        netbios_domain="EXAMPLE",
    )
    auth = AuthContext(
        username="analyst",
        user_sid="S-1-5-21-1000-1000-1000-1105",
        logon_id="0x1234",
        session_id=7,
        logon_type=10,
        source_ip="10.10.0.25",
        source_port=50_001,
        session_kind="rdp",
        auth_protocol="rdp",
    )

    emitter.emit(
        OccurrenceBuilder(
            timestamp=_START,
            event_type="rdp_reconnect",
            dst_host=host,
            auth=auth,
        )
    )
    emitter.emit(
        OccurrenceBuilder(
            timestamp=_START + timedelta(minutes=10),
            event_type="rdp_disconnect",
            dst_host=host,
            auth=auth,
        )
    )
    emitter.close()

    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("<EventID>4778</EventID>") == 1
    assert rendered.count("<EventID>4779</EventID>") == 1
    assert rendered.count('<Data Name="SessionName">RDP-Tcp#7</Data>') == 2
    assert rendered.count('<Data Name="ClientAddress">10.10.0.25</Data>') == 2
    assert rendered.count('<Data Name="ClientPort">50001</Data>') == 2


def test_initial_rdp_session_publishes_one_exact_transport_and_windows_cohort(tmp_path) -> None:
    """The production RDP caller commits transport, State, application, and source rows once."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(_START - timedelta(minutes=5))
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    emitters = {
        "ecar": ecar,
        "zeek_conn": zeek,
    }
    dispatcher = EventDispatcher(state, emitters)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_START - timedelta(days=1),
        generation_window_end=_END,
    )
    source = System(
        hostname="WS-01",
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    source_logon = generator.generate_logon(
        user,
        source,
        _START - timedelta(seconds=30),
        logon_type=2,
    )
    source_pid = generator.generate_process(
        user,
        source,
        _START - timedelta(seconds=3),
        source_logon,
        r"C:\Windows\System32\mstsc.exe",
        f"mstsc.exe /v:{target.hostname}",
        parent_pid=4,
    )

    uid, logon_id = generator._execute_rdp_session_bundle(
        user=user,
        target_system=target,
        time=_START,
        source_ip=source.ip,
        source_system=source,
        source_pid=source_pid,
        source_port=50_001,
    )

    session = state.get_session(logon_id)
    assert uid
    assert session is not None
    assert session.session_kind == "rdp"
    assert session.source_port == 50_001
    assert session.session_winlogon_pid is not None
    assert session.session_user_manager_pid is not None
    assert session.explorer_pid is not None
    snapshot = generator.rdp_session_manager.get(session.ecar_object_id)
    assert snapshot is not None
    assert snapshot.generation.binding.transport_id
    assert snapshot.identity.affinity.logon_id == logon_id.casefold()
    source_process = state.get_process(source.hostname, source_pid)
    assert source_process is not None
    assert source_process.last_activity_time == session.network_close_time

    ecar.close()
    zeek.close()
    ecar_rows = [
        line
        for output in (tmp_path / "ecar").rglob("ecar.json")
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert len(ecar_rows) >= 6
    assert dispatcher.deferred_session_publication_census().prepared_batches == 0


def test_rdp_journal_capacity_rejects_before_transport_or_state_publication(tmp_path) -> None:
    """A full terminal journal rejects the initial exact graph before any owner mutates."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(_START - timedelta(minutes=5))
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    emitters = {"ecar": ecar, "zeek_conn": zeek}
    dispatcher = EventDispatcher(state, emitters)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_START - timedelta(days=1),
        generation_window_end=_END,
    )
    source = System(
        hostname="WS-01",
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    source_logon = generator.generate_logon(
        user,
        source,
        _START - timedelta(seconds=30),
        logon_type=2,
    )
    source_pid = generator.generate_process(
        user,
        source,
        _START - timedelta(seconds=3),
        source_logon,
        r"C:\Windows\System32\mstsc.exe",
        f"mstsc.exe /v:{target.hostname}",
        parent_pid=4,
    )
    generator._rdp_lifecycle_journal_capacity = 0

    with pytest.raises(StateError, match="journal capacity is exhausted"):
        generator._execute_rdp_session_bundle(
            user=user,
            target_system=target,
            time=_START,
            source_ip=source.ip,
            source_system=source,
            source_pid=source_pid,
            source_port=50_001,
        )

    assert generator.rdp_session_manager.census().retained_sessions == 0
    assert generator.rdp_lifecycle_journal_census().prepared_reservations == 0
    assert not [
        connection for connection in state.list_open_connections() if connection.dst_port == 3389
    ]
    assert not [
        session
        for session in state.get_sessions_on_system(target.hostname)
        if session.session_kind == "rdp"
    ]
    ecar.close()
    zeek.close()


@pytest.mark.parametrize("lose_terminal_return", (False, True), ids=("success", "lost-return"))
def test_disconnected_rdp_session_reconnects_through_same_exact_owner(
    lose_terminal_return: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One later transport preserves the logical State identity and emits Security 4778."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(_START - timedelta(minutes=5))
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "windows",
        threaded=False,
        source_finalization=True,
    )
    emitters = {
        "ecar": ecar,
        "windows_event_security": windows,
        "zeek_conn": zeek,
    }
    dispatcher = EventDispatcher(state, emitters)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        generation_window_start=_START - timedelta(days=1),
        generation_window_end=_END,
    )
    source = System(
        hostname="WS-01",
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    source_logon = generator.generate_logon(
        user,
        source,
        _START - timedelta(seconds=30),
        logon_type=2,
    )
    source_pid = generator.generate_process(
        user,
        source,
        _START - timedelta(seconds=3),
        source_logon,
        r"C:\Windows\System32\mstsc.exe",
        f"mstsc.exe /v:{target.hostname}",
        parent_pid=4,
    )
    _uid, logon_id = generator._execute_rdp_session_bundle(
        user=user,
        target_system=target,
        time=_START,
        source_ip=source.ip,
        source_system=source,
        source_pid=source_pid,
        source_port=50_001,
    )
    session = state.get_session(logon_id)
    assert session is not None and session.network_close_time is not None
    logical_id = session.ecar_object_id
    initial = generator.rdp_session_manager.get(logical_id)
    assert initial is not None
    generator.advance_rdp_session_lifecycle_watermark(session.network_close_time)
    disconnected = generator.rdp_session_manager.get(logical_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    assert generator.rdp_lifecycle_journal_census().disconnected_generations == 1
    reconnect_at = session.network_close_time + timedelta(seconds=1)

    reconnect_uid, reconnect_logon_id = generator._execute_rdp_session_bundle(
        user=user,
        target_system=target,
        time=reconnect_at,
        source_ip=source.ip,
        source_system=source,
        source_port=50_002,
        logon_id=logon_id,
    )

    reconnected = generator.rdp_session_manager.get(logical_id)
    assert reconnect_uid
    assert reconnect_logon_id == logon_id
    assert reconnected is not None
    assert reconnected.generation.ordinal == disconnected.generation.ordinal + 1
    updated_session = state.get_session(logon_id)
    assert updated_session is not None
    assert updated_session.source_port == 50_002
    reconnect_clients = [
        process
        for process in state.get_processes_on_system(source.hostname)
        if process.image.casefold().endswith("mstsc.exe")
        and reconnect_at < process.start_time < reconnect_at + timedelta(seconds=2)
    ]
    assert len(reconnect_clients) == 1
    assert reconnect_clients[0].last_activity_time == updated_session.network_close_time
    assert dispatcher.deferred_session_publication_census().prepared_batches == 0

    assert updated_session.network_close_time is not None
    if lose_terminal_return:
        original_claim = EventDispatcher.claimed_action_cohort
        injected = False

        @contextmanager
        def lose_process_close_return(
            owner: EventDispatcher,
            batch: object,
        ) -> Iterator[object]:
            nonlocal injected
            with original_claim(owner, batch) as capability:
                yield capability
            result = capability.result
            if (
                not injected
                and result is not None
                and result.receipt.root_action_id.endswith(":process-terminate")
            ):
                injected = True
                raise OSError("injected RDP terminal claim lost-return")

        monkeypatch.setattr(EventDispatcher, "claimed_action_cohort", lose_process_close_return)
        with pytest.raises(OSError, match="RDP terminal claim lost-return") as caught:
            generator.advance_rdp_session_lifecycle_watermark(updated_session.network_close_time)
        assert caught.value.action_cohort_receipt is not None
        assert generator.rdp_lifecycle_journal_census().pending_generations == 1
    generator.advance_rdp_session_lifecycle_watermark(updated_session.network_close_time)
    second_disconnect = generator.rdp_session_manager.get(logical_id)
    assert second_disconnect is not None
    assert second_disconnect.state is RdpSessionState.DISCONNECTED
    generator.finalize_rdp_session_lifecycles(_END)
    assert state.get_session(logon_id) is None
    assert generator.rdp_lifecycle_journal_census().pending_generations == 0

    dispatcher.drain_exact_projection_recoveries()
    coordinator = SourceFinalizationCoordinator(
        (windows,),
        ExactPublicationAuthority(
            capacity=1,
            row_capacity=256,
            byte_capacity=8 * 1024 * 1024,
        ),
    )
    coordinator.finalize()
    windows.close()
    coordinator.mark_closed()
    ecar.close()
    zeek.close()
    rendered = "\n".join(
        path.read_text(encoding="utf-8") for path in (tmp_path / "windows").rglob("*.xml")
    )
    assert rendered.count("<EventID>4778</EventID>") == 1
    assert rendered.count("<EventID>4779</EventID>") == 2
    assert rendered.count("<EventID>4634</EventID>") == 1
    assert '<Data Name="ClientPort">50002</Data>' in rendered


@pytest.mark.parametrize(
    ("terminal_owner", "clock_profile_name"),
    (
        ("source-process-terminate", "complete"),
        ("4779-disconnect", "enterprise_standard"),
        ("target-logout-4634", "messy_collection"),
    ),
)
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_rdp_terminal_owner_failure_retries_without_duplicate_rows(
    terminal_owner: str,
    clock_profile_name: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every first/middle/last terminal owner retains one exact retryable journal entry."""

    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name=clock_profile_name,
    )
    injected = False
    selected_calls = 0
    owner_calls: list[str] = []
    canonical_times: dict[str, datetime] = {}
    original_terminate = RdpSessionActionBundle.terminate_exact_rdp_process
    original_disconnect = EventDispatcher.publish_state_neutral_exact_projection
    original_logout = RdpSessionActionBundle.logout_exact_rdp_session

    def faulting_source_terminate(
        owner: RdpSessionActionBundle,
        continuation: object,
        identity: ProcessIdentity,
        terminate_time: datetime,
    ) -> object:
        nonlocal injected, selected_calls
        source_owner = identity.hostname == harness.source_hostname
        selected = source_owner and terminal_owner == "source-process-terminate"
        if selected:
            selected_calls += 1
        if selected and not injected:
            injected = True
            if failure_mode == "fail-before":
                raise OSError("injected source process terminate fail-before")
            result = original_terminate(owner, continuation, identity, terminate_time)
            owner_calls.append("source-process-terminate")
            canonical_times.setdefault("source-process-terminate", terminate_time)
            raise OSError("injected source process terminate lost-return")
        result = original_terminate(owner, continuation, identity, terminate_time)
        if source_owner:
            owner_calls.append("source-process-terminate")
            canonical_times.setdefault("source-process-terminate", terminate_time)
        return result

    def faulting_disconnect(owner: EventDispatcher, carrier: object) -> object:
        nonlocal injected, selected_calls
        canonical_time = owner.action_cohort_projection_occurrence(carrier).timestamp
        selected = terminal_owner == "4779-disconnect"
        if selected:
            selected_calls += 1
        if selected and not injected:
            injected = True
            if failure_mode == "fail-before":
                raise OSError("injected 4779 disconnect fail-before")
            result = original_disconnect(owner, carrier)
            owner_calls.append("4779-disconnect")
            canonical_times.setdefault("4779-disconnect", canonical_time)
            error = OSError("injected 4779 disconnect lost-return")
            error.state_neutral_projection_receipt = result.receipt
            error.state_neutral_projection_result = result
            raise error
        result = original_disconnect(owner, carrier)
        owner_calls.append("4779-disconnect")
        canonical_times.setdefault("4779-disconnect", canonical_time)
        return result

    def faulting_logout(
        owner: RdpSessionActionBundle,
        continuation: object,
        logout_time: datetime,
    ) -> None:
        nonlocal injected, selected_calls
        selected = terminal_owner == "target-logout-4634"
        if selected:
            selected_calls += 1
        if selected and not injected:
            injected = True
            if failure_mode == "fail-before":
                raise OSError("injected target logout 4634 fail-before")
            original_logout(owner, continuation, logout_time)
            owner_calls.append("target-logout-4634")
            canonical_times.setdefault("target-logout-4634", logout_time)
            raise OSError("injected target logout 4634 lost-return")
        original_logout(owner, continuation, logout_time)
        owner_calls.append("target-logout-4634")
        canonical_times.setdefault("target-logout-4634", logout_time)

    monkeypatch.setattr(
        RdpSessionActionBundle,
        "terminate_exact_rdp_process",
        faulting_source_terminate,
    )
    monkeypatch.setattr(
        EventDispatcher,
        "publish_state_neutral_exact_projection",
        faulting_disconnect,
    )
    monkeypatch.setattr(
        RdpSessionActionBundle,
        "logout_exact_rdp_session",
        faulting_logout,
    )

    expected_error = f"injected {terminal_owner.replace('-', ' ')} {failure_mode}"
    with pytest.raises(OSError, match=expected_error):
        if terminal_owner == "target-logout-4634":
            harness.generator.finalize_rdp_session_lifecycles(_END)
        else:
            harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)

    retained = harness.generator.rdp_lifecycle_journal_census()
    assert injected
    assert retained.prepared_reservations == 0
    assert retained.pending_generations == 1

    harness.generator.finalize_rdp_session_lifecycles(_END)

    terminal = harness.generator.rdp_lifecycle_journal_census()
    expected_calls = (
        1 if terminal_owner == "4779-disconnect" and failure_mode == "lost-return" else 2
    )
    assert selected_calls == expected_calls
    assert terminal.prepared_reservations == 0
    assert terminal.pending_generations == 0
    assert terminal.disconnected_generations == 0
    manager_census = harness.generator.rdp_session_manager.census()
    assert manager_census.connected_sessions == 0
    assert manager_census.disconnected_sessions == 0
    assert manager_census.logged_out_sessions == 1
    assert manager_census.active_operations == 0
    assert manager_census.active_leases == 0
    assert manager_census.application.open_channels == 0
    assert manager_census.application.active_operations == 0
    assert manager_census.application.prepared_admissions == 0
    assert manager_census.application.claimed_admissions == 0
    assert harness.state.get_session(harness.logon_id) is None
    harness.generator.assert_rdp_session_lifecycles_drained()

    _close_rdp_terminal_harness(harness)
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "windows").rglob("*.xml")
    )
    assert rendered_windows.count("<EventID>4779</EventID>") == 1
    assert rendered_windows.count("<EventID>4634</EventID>") == 1
    _windows_security_time(
        rendered_windows,
        4689,
        process_name="mstsc.exe",
    )
    disconnect_at = _windows_security_time(rendered_windows, 4779)
    logout_at = _windows_security_time(rendered_windows, 4634)
    assert (
        owner_calls.index("source-process-terminate")
        < owner_calls.index("4779-disconnect")
        < owner_calls.index("target-logout-4634")
    ), owner_calls
    assert canonical_times["source-process-terminate"] == harness.disconnect_at
    assert canonical_times["4779-disconnect"] == (
        canonical_times["source-process-terminate"] + timedelta(microseconds=1)
    )
    assert canonical_times["4779-disconnect"] < canonical_times["target-logout-4634"]
    assert disconnect_at < logout_at, (
        clock_profile_name,
        disconnect_at,
        logout_at,
    )

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    for object_id in harness.terminal_process_object_ids:
        assert (
            sum(
                row.get("object") == "PROCESS"
                and row.get("action") == "TERMINATE"
                and row.get("objectID") == object_id
                for row in ecar_rows
            )
            == 1
        )
    assert (
        sum(
            row.get("object") == "USER_SESSION"
            and row.get("action") == "LOGIN"
            and row.get("objectID") == harness.session_object_id
            for row in ecar_rows
        )
        == 1
    )
    assert (
        sum(
            row.get("object") == "USER_SESSION"
            and row.get("action") == "LOGOUT"
            and row.get("objectID") == harness.session_object_id
            for row in ecar_rows
        )
        == 1
    )


class _OrderedEngineLifecycleOwner:
    """Minimal lifecycle owner that loses the first RDP terminal return exactly once."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.rdp_attempts = 0
        self.rdp_drained = False

    def finalize_ssh_session_lifecycles(self, _end_time: datetime) -> None:
        """Record the protocol owner that must run first."""

        self.calls.append("ssh-finalize")

    def assert_ssh_session_lifecycles_drained(self) -> None:
        """Record the SSH terminal assertion."""

        self.calls.append("ssh-assert-drained")

    def finalize_rdp_session_lifecycles(self, _end_time: datetime) -> None:
        """Lose one return, then drain the retained RDP journal on exact retry."""

        self.rdp_attempts += 1
        self.calls.append(f"rdp-finalize-{self.rdp_attempts}")
        if self.rdp_attempts == 1:
            raise OSError("injected engine RDP lost-return")
        self.rdp_drained = True

    def assert_rdp_session_lifecycles_drained(self) -> None:
        """Reject downstream shutdown until the RDP retry has drained."""

        self.calls.append("rdp-assert-drained")
        if not self.rdp_drained:
            raise AssertionError("RDP lifecycle journal remains pending")

    def write_artifacts_manifest(self) -> None:
        """Record successful completion after source close."""

        self.calls.append("manifest")


class _OrderedEngineRecoveryDispatcher:
    """Record the exact dispatcher drain interleaved with protocol journals."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def drain_exact_projection_recoveries(self) -> tuple[object, ...]:
        """Record one recovery drain."""

        self.calls.append("projection-drain")
        return ()

    def assert_exact_projection_recoveries_drained(self) -> None:
        """Record the matching terminal assertion."""

        self.calls.append("projection-assert-drained")


class _OrderedSourceSink:
    """Combined source-finalization and emitter-close double with a live RDP guard."""

    def __init__(self, calls: list[str], owner: _OrderedEngineLifecycleOwner) -> None:
        self.calls = calls
        self.owner = owner

    def _require_rdp_drained(self) -> None:
        if not self.owner.rdp_drained:
            raise AssertionError("source sink reached before RDP journal drain")

    def finalize(self) -> None:
        """Record source finalization after the protocol journals."""

        self._require_rdp_drained()
        self.calls.append("source-finalize")

    def close(self) -> None:
        """Record emitter close after source finalization."""

        self._require_rdp_drained()
        self.calls.append("emitter-close")

    def mark_closed(self) -> None:
        """Record source-finalization acknowledgement."""

        self.calls.append("source-closed")


def test_engine_orders_ssh_before_rdp_and_blocks_source_close_during_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real engine preserves SSH -> RDP -> source-finalization shutdown order."""

    calls: list[str] = []
    owner = _OrderedEngineLifecycleOwner(calls)
    dispatcher = _OrderedEngineRecoveryDispatcher(calls)
    sink = _OrderedSourceSink(calls, owner)
    engine = GenerationEngine.__new__(GenerationEngine)
    engine.activity_generator = owner
    engine.dispatcher = dispatcher
    engine.emitters = {"ordered": sink}
    engine.end_time = _END
    engine._source_finalization_coordinator = sink
    engine._ssh_lifecycles_finalized = False
    engine._rdp_lifecycles_finalized = False
    engine._foreground_lifecycles_finalized = True
    engine._finalization_complete = False
    engine._finalization_aborted = False
    engine._source_coordinator_closed = False
    engine._ids_alert_summary_applied = True
    engine._expected_close_emitters = None
    engine._closed_emitter_names = set()
    engine._exact_projection_recovery_dispatcher = None
    engine.ground_truth_dir = tmp_path
    engine.scenario = object()
    engine.output_target = object()
    engine.workload_estimate = object()
    monkeypatch.setattr(
        "evidenceforge.events.collection_profile.write_collection_profile",
        lambda *_args, **_kwargs: None,
    )

    with pytest.raises(OSError, match="engine RDP lost-return"):
        engine._finalize(generation_succeeded=True)

    assert calls.index("ssh-finalize") < calls.index("rdp-finalize-1")
    assert calls.count("rdp-finalize-1") == 1
    assert calls.count("rdp-finalize-2") == 1
    assert "source-finalize" not in calls
    assert "emitter-close" not in calls
    assert owner.rdp_drained
    assert engine._rdp_lifecycles_finalized
    assert not engine._finalization_complete

    engine._finalize(generation_succeeded=True)

    assert calls.index("rdp-finalize-2") < calls.index("source-finalize")
    assert calls.index("source-finalize") < calls.index("emitter-close")
    assert calls.index("emitter-close") < calls.index("source-closed")
    assert engine._finalization_complete

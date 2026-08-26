# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Public-boundary coverage for exact deferred RDP production ownership."""

from __future__ import annotations

import json
import random
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.collection_policy import (
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    PeVersionInfo,
    SoftwareInstallationIdentity,
)
from evidenceforge.events.contexts import AuthContext, HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.observation import ObservationDecision, ObservationPolicy
from evidenceforge.events.rdp import RdpSessionState
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG
from evidenceforge.formats import load_format
from evidenceforge.generation.actions.rdp_session import (
    RdpSessionActionBundle,
    RdpSessionRequest,
    rdp_action_deadline_source_tail,
    rdp_action_deadline_transport_headroom_seconds,
)
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.activity.timing_profiles import TimingWindow, get_timing_window
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    HostDeploymentSpec,
)
from evidenceforge.generation.emitters.base import ExactPublicationAuthority, ExactPublicationKey
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    LifecyclePreparedNetworkResult,
)
from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
from evidenceforge.generation.rdp_sessions import RdpReconnectStateManager
from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id
from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import reset_thread_rng

pytestmark = pytest.mark.slow

_START = datetime(2026, 1, 5, 9, tzinfo=UTC)
_END = _START + timedelta(days=1)
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

_RDP_WINDOWS_BINARY_PATHS = (
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\userinit.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\mstsc.exe",
)


def _rdp_test_deployment_registry(
    source: System,
    target: System,
) -> DeploymentContentRegistry:
    """Compile exact Windows binary placement for the production Sysmon fixture."""

    releases: list[BinaryReleaseIdentity] = []
    installations: list[SoftwareInstallationIdentity] = []
    host_deployments: list[HostDeploymentSpec] = []
    for system, build, roles in (
        (source, "10.0.22631.3880", ("workstation",)),
        (target, "10.0.20348.2655", ("server", "rdp")),
    ):
        product_id = f"microsoft-windows-rdp-fixture-{system.hostname.casefold()}"
        host_releases = tuple(
            BinaryReleaseIdentity(
                key=BinaryReleaseKey(
                    product_id=product_id,
                    version=build,
                    build=build,
                    architecture="x64",
                    platform="windows",
                    artifact_name=path.rsplit("\\", 1)[-1],
                ),
                pe_version_info=PeVersionInfo(
                    file_version=build,
                    description="Microsoft Windows executable",
                    product="Microsoft Windows Operating System",
                    company="Microsoft Corporation",
                    original_filename=path.rsplit("\\", 1)[-1],
                ),
            )
            for path in _RDP_WINDOWS_BINARY_PATHS
        )
        releases.extend(host_releases)
        installations.append(
            SoftwareInstallationIdentity(
                hostname=system.hostname,
                application_id=product_id,
                release_id=host_releases[0].release_id,
                platform="windows",
                scope="machine",
                install_root=r"C:\Windows",
                image_paths=_RDP_WINDOWS_BINARY_PATHS,
            )
        )
        host_deployments.append(
            HostDeploymentSpec(
                hostname=system.hostname,
                roles=roles,
                platform="windows",
                os_build=build,
                architecture="x64",
            )
        )
    return DeploymentContentRegistry(
        binary_releases=tuple(releases),
        installations=tuple(installations),
        host_deployments=tuple(host_deployments),
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
        "evidenceforge.generation.actions.rdp_session.get_timing_window",
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
        "evidenceforge.generation.actions.rdp_session.get_timing_window",
        overlay_window,
    )


def _install_extreme_cross_host_windows_clocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force the validator-accepted Windows clock extrema on opposite endpoints."""

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
            if hostname == "RDS-01"
            else timedelta(0)
        )

    monkeypatch.setattr(
        SourceTimingPlanner,
        "_runtime_endpoint_clock_time",
        forced_endpoint_clock,
    )
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
            timedelta(seconds=300) if os_category == "windows" else timedelta(0)
        ),
    )


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
    include_sysmon_during_open: bool = False,
    modeled_target_pid4: bool = False,
    modeled_source_pid4: bool = False,
    modeled_source: bool = True,
    session_end_plan: SessionEndPlan | None = None,
    production_timing_runtime: bool = False,
    open_time: datetime = _START,
    expect_exact_initial: bool = True,
    source_process_lead_seconds: float = 3.0,
) -> _RdpTerminalHarness:
    """Open one exact initial RDP generation whose full terminal graph is still pending."""

    reset_thread_rng(42)
    state = StateManager()
    state.set_current_time(open_time - timedelta(minutes=5))
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
    ecar = EcarEmitter(load_format("ecar"), tmp_path / "ecar", threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), tmp_path / "zeek.json", threaded=False)
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "windows",
        threaded=False,
        source_finalization=True,
    )
    sysmon = (
        SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "sysmon",
            threaded=False,
            source_finalization=True,
        )
        if include_sysmon_during_open
        else None
    )
    emitters = {
        "ecar": ecar,
        "windows_event_security": windows,
        "zeek_conn": zeek,
    }
    if sysmon is not None:
        emitters["windows_event_sysmon"] = sysmon
    dispatcher = EventDispatcher(
        state,
        emitters,
        deployment_registry=(
            _rdp_test_deployment_registry(source, target) if include_sysmon_during_open else None
        ),
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
    if modeled_source_pid4:
        source_system_plan = state.plan_process_materialization(
            system=source.hostname,
            fixed_pid=4,
            parent_pid=0,
            image="System",
            command_line="",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
            start_time=open_time - timedelta(minutes=5),
        )
        generator._lifecycle_authority.materialize_process(source_system_plan)
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
            open_time - timedelta(seconds=source_process_lead_seconds),
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
    if expect_exact_initial:
        assert all(pid is not None for pid in target_pids)
    target_identities = tuple(
        state.get_process_identity(target.hostname, pid) for pid in target_pids if pid is not None
    )
    if expect_exact_initial:
        assert len(target_identities) == 3 and all(
            identity is not None for identity in target_identities
        )
    if include_sysmon and sysmon is None:
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
    engine._linux_sudo_logoffs_finalized = False
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


def test_explicit_logoff_delegates_bundle_owned_rdp_graph_to_exact_owner(
    tmp_path: Path,
) -> None:
    """An authored logoff drains its exact RDP owner, including session child apps."""

    end_plan = SessionEndPlan(
        _START + timedelta(hours=2, minutes=35),
        "explicit_storyline",
        "evt-033",
    )
    harness = _open_rdp_terminal_harness(
        tmp_path,
        modeled_source=False,
        session_end_plan=end_plan,
    )
    session = harness.state.get_session(harness.logon_id)
    assert session is not None
    assert session.explorer_pid is not None
    session.storyline_protected = True
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    target = System(
        hostname=harness.target_hostname,
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    child_pid = harness.generator.generate_process(
        user,
        target,
        _START + timedelta(minutes=10),
        harness.logon_id,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile Get-Process",
        parent_pid=session.explorer_pid,
        from_storyline=True,
    )
    child_identity = harness.state.get_process_identity(harness.target_hostname, child_pid)
    assert child_identity is not None

    harness.generator.generate_logoff(
        user,
        target,
        end_plan.canonical_end,
        harness.logon_id,
        logon_type=10,
        from_storyline=True,
        session_end_plan=end_plan,
    )

    assert harness.state.get_session(harness.logon_id) is None
    assert harness.state.get_process(harness.target_hostname, child_pid) is None
    journal = harness.generator.rdp_lifecycle_journal_census()
    assert journal.prepared_reservations == 0
    assert journal.pending_generations == 0
    assert journal.disconnected_generations == 0
    manager = harness.generator.rdp_session_manager.census()
    assert manager.connected_sessions == 0
    assert manager.disconnected_sessions == 0
    assert manager.logged_out_sessions == 1
    assert manager.active_operations == 0
    assert manager.active_leases == 0
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    child_terminations = [
        row
        for row in ecar_rows
        if row.get("object") == "PROCESS"
        and row.get("action") == "TERMINATE"
        and row.get("objectID") == child_identity.object_id
    ]
    target_logouts = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.target_hostname
        and row.get("object") == "USER_SESSION"
        and row.get("action") == "LOGOUT"
    ]
    assert len(child_terminations) == 1
    assert len(target_logouts) == 1
    assert child_terminations[0]["timestamp_ms"] < target_logouts[0]["timestamp_ms"]


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


@pytest.mark.parametrize("tampered_auth_field", ("session_id", "logon_type"))
def test_rdp_target_process_terminal_rejects_tampered_auth_and_retries_exactly(
    tampered_auth_field: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A target child close fails closed on session-auth drift and retries exactly once."""

    harness = _open_rdp_terminal_harness(tmp_path)
    original_terminal_event = RdpSessionActionBundle._terminal_process_event
    injected_identity: ProcessIdentity | None = None

    def tampered_terminal_event(
        owner: RdpSessionActionBundle,
        *,
        identity: ProcessIdentity,
        terminate_time: datetime,
        system: System,
        session_identity: SessionIdentity | None,
    ) -> OccurrenceBuilder:
        nonlocal injected_identity
        event = original_terminal_event(
            owner,
            identity=identity,
            terminate_time=terminate_time,
            system=system,
            session_identity=session_identity,
        )
        if (
            injected_identity is None
            and session_identity is not None
            and session_identity.session_kind == "rdp"
            and session_identity.principal == identity.principal
        ):
            injected_identity = identity
            assert event.auth is not None
            if tampered_auth_field == "session_id":
                event.auth = replace(event.auth, session_id=event.auth.session_id + 1)
            else:
                event.auth = replace(event.auth, logon_type=2)
        return event

    with monkeypatch.context() as fault:
        fault.setattr(
            RdpSessionActionBundle,
            "_terminal_process_event",
            tampered_terminal_event,
        )
        with pytest.raises(
            EventContractError,
            match="Exact RDP process close disagrees with its live process identity",
        ):
            harness.generator.finalize_rdp_session_lifecycles(_END)

    assert injected_identity is not None
    assert harness.state.get_process(injected_identity.hostname, injected_identity.pid) is not None
    retained = harness.generator.rdp_lifecycle_journal_census()
    assert retained.prepared_reservations == 0
    assert retained.pending_generations == 1
    assert harness.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    assert harness.dispatcher.action_cohort_publication_census().prepared_batches == 0

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
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


def test_action_bundle_deadline_caps_full_hour_rdp_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An action-owned final-hour RDP session chooses a complete earlier transport end."""

    class MaximumDurationRng(random.Random):
        """Choose the maximum transport duration while retaining ordinary byte sampling."""

        def uniform(self, a: float, b: float) -> float:
            return b

    deadline = _START + timedelta(hours=1)
    end_plan = SessionEndPlan(deadline, "action_bundle")
    monkeypatch.setattr(
        "evidenceforge.generation.actions.rdp_session._get_rng",
        lambda: MaximumDurationRng(42),
    )

    harness = _open_rdp_terminal_harness(tmp_path, session_end_plan=end_plan)

    assert rdp_action_deadline_transport_headroom_seconds() == 61.5
    logical_deadline = deadline - rdp_action_deadline_source_tail(
        source_deadline=deadline,
        source_timing_planner=harness.dispatcher.source_timing_planner,
        network_observation_planner=harness.dispatcher.network_observation_planner,
        source_ip="10.10.0.25",
        target_ip="10.20.0.10",
    )
    assert logical_deadline - timedelta(milliseconds=1_500) <= harness.disconnect_at
    assert harness.disconnect_at <= logical_deadline - timedelta(milliseconds=100)
    state_end_plan = harness.state.get_session_end_plan(harness.logon_id)
    assert state_end_plan is not None
    assert state_end_plan.canonical_end == logical_deadline
    assert state_end_plan.authority == end_plan.authority
    snapshot = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert snapshot is not None
    assert snapshot.identity.hard_deadline == logical_deadline

    harness.generator.finalize_rdp_session_lifecycles(deadline)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    journal = harness.generator.rdp_lifecycle_journal_census()
    manager = harness.generator.rdp_session_manager.census()
    assert journal.pending_generations == 0
    assert manager.retained_sessions == 0
    assert manager.connected_sessions == 0
    assert manager.disconnected_sessions == 0
    assert manager.logged_out_sessions == 0
    assert manager.active_operations == 0
    assert manager.active_leases == 0
    _close_rdp_terminal_harness(harness)
    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "windows").rglob("*.xml")
    )
    assert all(
        datetime.fromisoformat(timestamp.replace("Z", "+00:00")) < deadline
        for timestamp in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
    )
    zeek_rows = _read_json_lines(harness.output_root, "zeek.json")
    assert len(zeek_rows) == 1
    assert (
        datetime.fromtimestamp(
            zeek_rows[0]["ts"] + zeek_rows[0]["duration"],
            tz=UTC,
        )
        < deadline
    )


def test_process_overlay_finishes_real_rdp_output_before_action_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow endpoint dependents and their logoff gap finalize inside the raw fence."""

    _install_terminal_process_latency_overlay(monkeypatch)
    deadline = _START + timedelta(hours=1)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        include_sysmon=True,
        modeled_source=False,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    assert SourceTimingPlanner.session_closure_tail("ecar") == timedelta(
        seconds=70,
        milliseconds=4,
    )

    harness.generator.finalize_rdp_session_lifecycles(deadline)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for root in (harness.output_root / "windows", harness.output_root / "sysmon")
        for output in root.rglob("*.xml")
    )
    rendered_times = tuple(
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
    )
    assert rendered_times
    assert max(rendered_times) < deadline
    zeek_rows = [
        row
        for row in _read_json_lines(harness.output_root, "zeek.json")
        if row.get("id.resp_p") == 3389
    ]
    assert len(zeek_rows) == 1
    assert datetime.fromtimestamp(zeek_rows[0]["ts"] + zeek_rows[0]["duration"], tz=UTC) < deadline


def test_unmodeled_initial_rdp_reserves_zero_skew_flow_latency_before_dependents(
    tmp_path: Path,
) -> None:
    """A high-delay inbound FLOW must precede every exact initial RDP dependent."""

    open_time = _START + timedelta(seconds=6)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name="complete",
        modeled_source=False,
        open_time=open_time,
    )
    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    inbound_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.target_hostname
        and row.get("object") == "FLOW"
        and row.get("action") == "CONNECT"
    ]
    initial_dependents = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.target_hostname
        and (row.get("object"), row.get("action"))
        in {("USER_SESSION", "LOGIN"), ("PROCESS", "CREATE")}
    ]
    assert len(inbound_flows) == 1
    assert len(initial_dependents) == 4
    flow_timestamp_ms = inbound_flows[0]["timestamp_ms"]
    assert flow_timestamp_ms >= int(open_time.timestamp() * 1_000) + 1_500
    assert all(flow_timestamp_ms < row["timestamp_ms"] for row in initial_dependents)


def test_modeled_rdp_source_positive_clock_omits_flow_actor_and_finalizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late mstsc projection remains lifecycle-owned while its FLOW stays PID-free."""

    _install_extreme_cross_host_windows_clocks(monkeypatch)

    deadline = _START + timedelta(hours=1)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name="messy_collection",
        include_sysmon=True,
        modeled_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
        production_timing_runtime=True,
    )
    harness.generator.finalize_rdp_session_lifecycles(deadline)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    source_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.source_hostname and row.get("object") == "FLOW"
    ]
    assert len(source_flows) == 1
    assert "pid" not in source_flows[0]
    assert "principal" not in source_flows[0]
    target_logins = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.target_hostname
        and row.get("object") == "USER_SESSION"
        and row.get("action") == "LOGIN"
    ]
    assert len(target_logins) == 1
    assert source_flows[0]["timestamp_ms"] < target_logins[0]["timestamp_ms"]
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for root in (harness.output_root / "windows", harness.output_root / "sysmon")
        for output in root.rglob("*.xml")
    )
    rendered_times = tuple(
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
    )
    assert rendered_times
    assert max(rendered_times) < deadline
    zeek_rows = [
        row
        for row in _read_json_lines(harness.output_root, "zeek.json")
        if row.get("id.resp_p") == 3389
    ]
    assert len(zeek_rows) == 1
    assert datetime.fromtimestamp(zeek_rows[0]["ts"] + zeek_rows[0]["duration"], tz=UTC) < deadline


def test_modeled_rdp_compatibility_path_orders_flow_and_logout_before_action_deadline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generic fallback retains cross-host ordering and the narrowed logout plan."""

    _install_terminal_process_latency_overlay(monkeypatch)
    _install_extreme_cross_host_windows_clocks(monkeypatch)
    monkeypatch.setattr(
        RdpSessionActionBundle,
        "_has_exact_deferred_projection_owners",
        lambda _bundle: False,
    )
    deadline = _START + timedelta(hours=1)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name="messy_collection",
        modeled_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
        production_timing_runtime=True,
        expect_exact_initial=False,
    )
    state_end_plan = harness.state.get_session_end_plan(harness.logon_id)
    assert state_end_plan is not None
    assert state_end_plan.authority == "action_bundle"
    assert state_end_plan.canonical_end < deadline
    harness.generator.generate_logoff(
        User(
            username="analyst",
            full_name="Security Analyst",
            email="analyst@example.test",
        ),
        System(
            hostname="RDS-01",
            ip="10.20.0.10",
            os="Windows Server 2022",
            type="server",
            services=["rdp"],
        ),
        state_end_plan.canonical_end,
        harness.logon_id,
        logon_type=10,
    )
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    source_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.source_hostname
        and row.get("object") == "FLOW"
        and row.get("properties", {}).get("dst_port") == "3389"
    ]
    assert len(source_flows) == 1
    assert "pid" not in source_flows[0]
    assert "principal" not in source_flows[0]
    target_sessions = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.target_hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row.get("action") for row in target_sessions] == ["LOGIN", "LOGOUT"]
    assert source_flows[0]["timestamp_ms"] < target_sessions[0]["timestamp_ms"]
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for root in (harness.output_root / "windows", harness.output_root / "sysmon")
        for output in root.rglob("*.xml")
    )
    rendered_times = tuple(
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
    )
    assert rendered_times
    assert max(rendered_times) < deadline
    zeek_rows = [
        row
        for row in _read_json_lines(harness.output_root, "zeek.json")
        if row.get("id.resp_p") == 3389
    ]
    assert len(zeek_rows) == 1
    assert datetime.fromtimestamp(zeek_rows[0]["ts"] + zeek_rows[0]["duration"], tz=UTC) < deadline


def test_rdp_reconnect_omits_late_source_actor_and_orders_flow_before_4778(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconnect keeps a late mstsc lifecycle while publishing its FLOW PID-free."""

    _install_extreme_cross_host_windows_clocks(monkeypatch)
    deadline = _START + timedelta(hours=4)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name="messy_collection",
        modeled_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
        production_timing_runtime=True,
    )
    harness.generator.advance_rdp_session_lifecycle_watermark(harness.disconnect_at)
    disconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert disconnected is not None
    assert disconnected.state is RdpSessionState.DISCONNECTED
    reconnect_at = harness.disconnect_at + timedelta(seconds=1)
    reconnect_uid, reconnect_logon_id = harness.generator._execute_rdp_session_bundle(
        user=User(
            username="analyst",
            full_name="Security Analyst",
            email="analyst@example.test",
        ),
        target_system=System(
            hostname="RDS-01",
            ip="10.20.0.10",
            os="Windows Server 2022",
            type="server",
            services=["rdp"],
        ),
        time=reconnect_at,
        source_ip="10.10.0.25",
        source_system=System(
            hostname="WS-01",
            ip="10.10.0.25",
            os="Windows 11",
            type="workstation",
        ),
        source_port=50_002,
        logon_id=harness.logon_id,
    )
    assert reconnect_uid
    assert reconnect_logon_id == harness.logon_id
    reconnected = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert reconnected is not None
    assert reconnected.generation.ordinal == disconnected.generation.ordinal + 1
    updated_session = harness.state.get_session(harness.logon_id)
    assert updated_session is not None
    assert updated_session.network_close_time is not None
    harness.generator.advance_rdp_session_lifecycle_watermark(updated_session.network_close_time)
    harness.generator.finalize_rdp_session_lifecycles(deadline)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)

    ecar_rows = _read_json_lines(harness.output_root / "ecar", "ecar.json")
    reconnect_flows = [
        row
        for row in ecar_rows
        if row.get("hostname") == harness.source_hostname
        and row.get("object") == "FLOW"
        and row.get("properties", {}).get("dst_port") == "3389"
        and row.get("properties", {}).get("src_port") == "50002"
    ]
    assert len(reconnect_flows) == 1
    assert "pid" not in reconnect_flows[0]
    assert "principal" not in reconnect_flows[0]
    rendered_windows = "\n".join(
        output.read_text(encoding="utf-8")
        for root in (harness.output_root / "windows", harness.output_root / "sysmon")
        for output in root.rglob("*.xml")
    )
    reconnect_render_time = _windows_security_time(rendered_windows, 4778)
    assert (
        datetime.fromtimestamp(reconnect_flows[0]["timestamp_ms"] / 1_000, tz=UTC)
        < reconnect_render_time
        < deadline
    )
    rendered_times = tuple(
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        for value in re.findall(r'<TimeCreated SystemTime="([^"]+)"', rendered_windows)
    )
    assert rendered_times
    assert max(rendered_times) < deadline
    assert all(
        datetime.fromtimestamp(row["timestamp_ms"] / 1_000, tz=UTC) < deadline for row in ecar_rows
    )
    zeek_rows = _read_json_lines(harness.output_root, "zeek.json")
    assert len(zeek_rows) == 2
    assert all(
        datetime.fromtimestamp(row["ts"] + row["duration"], tz=UTC) < deadline for row in zeek_rows
    )


def test_action_bundle_deadline_rejects_too_late_rdp_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow-overlay plan rejects one microsecond below its exact transport support."""

    _install_asymmetric_terminal_process_latency_overlay(monkeypatch)
    assert rdp_action_deadline_source_tail() == timedelta(seconds=70, microseconds=89_001)
    monkeypatch.setattr(
        "evidenceforge.generation.actions.rdp_session._stable_seed",
        lambda *_parts: 0,
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
    registry = SimpleNamespace(window_end=_END)
    manager = SimpleNamespace(application_registry=registry)
    executor = SimpleNamespace(_rdp_session_manager=manager)
    deadline = _START + timedelta(hours=1)
    probe_request = RdpSessionRequest(
        user=user,
        target_system=target,
        time=_START,
        source_ip="198.51.100.25",
        preserve_explicit_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    probe = RdpSessionActionBundle(executor, probe_request)
    probe_cap = probe._hard_deadline_transport_duration_cap()
    assert probe_cap is not None
    exact_start = _START + timedelta(seconds=probe_cap - 60.0)
    exact_request = RdpSessionRequest(
        user=user,
        target_system=target,
        time=exact_start,
        source_ip="198.51.100.25",
        preserve_explicit_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    assert RdpSessionActionBundle(
        executor,
        exact_request,
    )._hard_deadline_transport_duration_cap() == pytest.approx(60.0)
    request = RdpSessionRequest(
        user=user,
        target_system=target,
        time=exact_start + timedelta(microseconds=1),
        source_ip="198.51.100.25",
        preserve_explicit_source=True,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    before = (
        vars(executor).copy(),
        vars(manager).copy(),
        vars(registry).copy(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("RDP deadline admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.rdp_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        RdpSessionActionBundle(executor, request).execute()

    after = (
        vars(executor).copy(),
        vars(manager).copy(),
        vars(registry).copy(),
    )
    assert after == before


def test_action_deadline_extreme_rdp_clock_separation_rejects_before_rng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Modeled-source RDP preflight includes valid cross-host clock extrema."""

    monkeypatch.setattr(
        "evidenceforge.generation.actions.rdp_session._stable_seed",
        lambda *_parts: 0,
    )
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
            timedelta(seconds=300) if os_category == "windows" else timedelta(0)
        ),
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
    registry = SimpleNamespace(window_end=_END)
    manager = SimpleNamespace(application_registry=registry)
    source_timing_planner = SourceTimingPlanner()
    network_observation_planner = SimpleNamespace(
        network_sensor_close_positive_headroom=lambda *_args, **_kwargs: timedelta(0)
    )
    dispatcher = SimpleNamespace(
        source_timing_planner=source_timing_planner,
        network_observation_planner=network_observation_planner,
    )
    executor = SimpleNamespace(
        _rdp_session_manager=manager,
        dispatcher=dispatcher,
        _ip_to_system={source.ip: source, target.ip: target},
    )
    deadline = _START + timedelta(hours=1)
    request = RdpSessionRequest(
        user=user,
        target_system=target,
        time=_START,
        source_ip=source.ip,
        source_system=source,
        session_end_plan=SessionEndPlan(deadline, "action_bundle"),
    )
    probe = RdpSessionActionBundle(executor, request)
    required_transport = probe._hard_deadline_min_transport_seconds()
    assert required_transport > 600
    public_headroom = rdp_action_deadline_transport_headroom_seconds(
        source_deadline=deadline,
        source_timing_planner=source_timing_planner,
        modeled_source=True,
    )
    assert public_headroom == pytest.approx(required_transport + 1.5)
    probe_cap = probe._hard_deadline_transport_duration_cap()
    assert probe_cap is not None
    exact_request = replace(
        request,
        time=request.time + timedelta(seconds=probe_cap - required_transport),
    )
    assert RdpSessionActionBundle(
        executor,
        exact_request,
    )._hard_deadline_transport_duration_cap() == pytest.approx(required_transport)
    short_request = replace(
        exact_request,
        time=exact_request.time + timedelta(microseconds=1),
    )
    before = (
        vars(executor).copy(),
        vars(manager).copy(),
        vars(registry).copy(),
        source_timing_planner.state_digest(),
    )

    def unexpected_rng() -> random.Random:
        raise AssertionError("RDP cross-clock admission consumed RNG")

    monkeypatch.setattr(
        "evidenceforge.generation.actions.rdp_session._get_rng",
        unexpected_rng,
    )
    with pytest.raises(StateError, match="action-bundle deadline.*minimum transport interval"):
        RdpSessionActionBundle(executor, short_request).execute()
    assert (
        vars(executor).copy(),
        vars(manager).copy(),
        vars(registry).copy(),
        source_timing_planner.state_digest(),
    ) == before


def test_explicit_rdp_end_plan_remains_exact_at_registry_boundary(tmp_path: Path) -> None:
    """An authoritative RDP plan keeps its authored State and manager deadline."""

    end_plan = SessionEndPlan(
        _END,
        "explicit_storyline",
        "rdp-window-close",
    )
    harness = _open_rdp_terminal_harness(
        tmp_path,
        modeled_source=False,
        session_end_plan=end_plan,
    )
    snapshot = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert snapshot is not None
    assert snapshot.identity.hard_deadline == end_plan.canonical_end
    assert harness.state.get_session_end_plan(harness.logon_id) == end_plan
    assert harness.disconnect_at < end_plan.canonical_end

    harness.generator.finalize_rdp_session_lifecycles(_END)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)


def test_short_explicit_rdp_end_keeps_legacy_transport_cap(tmp_path: Path) -> None:
    """A sub-minute authored plan caps transport without action minimum admission."""

    end_plan = SessionEndPlan(
        _START + timedelta(seconds=30),
        "explicit_storyline",
        "rdp-short-close",
    )
    harness = _open_rdp_terminal_harness(
        tmp_path,
        modeled_source=False,
        session_end_plan=end_plan,
    )
    snapshot = harness.generator.rdp_session_manager.get(harness.session_object_id)
    assert snapshot is not None
    assert snapshot.identity.hard_deadline == end_plan.canonical_end
    assert harness.state.get_session_end_plan(harness.logon_id) == end_plan
    close_gap = end_plan.canonical_end - harness.disconnect_at
    assert timedelta(milliseconds=100) <= close_gap <= timedelta(milliseconds=1_500)

    harness.generator.finalize_rdp_session_lifecycles(end_plan.canonical_end)
    harness.generator.assert_rdp_session_lifecycles_drained()
    assert harness.state.get_session(harness.logon_id) is None
    _close_rdp_terminal_harness(harness)


def test_compiled_enterprise_rdp_logout_reserves_source_frontiers_before_output_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compiled enterprise logout keeps mandatory endpoint rows inside the output fence."""

    closure_tail = SourceTimingPlanner.max_session_closure_tail(("ecar", "windows_event_security"))
    expected_deadline = _END - closure_tail - timedelta(microseconds=1)
    original_logout = RdpSessionActionBundle.logout_exact_rdp_session
    explicit_storyline_end = SessionEndPlan(
        _END - timedelta(seconds=20),
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
        expected_session_deadline = (
            explicit_end.canonical_end if explicit_end is not None else expected_deadline
        )
        assert snapshot.identity.hard_deadline == expected_session_deadline
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


def test_initial_rdp_with_sysmon_preserves_preoutput_pid4_parent_chain(
    tmp_path: Path,
) -> None:
    """Production RDP Event 1 rows use authenticated staged and boot-parent identities."""

    output_start = _START - timedelta(minutes=1)
    harness = _open_rdp_terminal_harness(
        tmp_path,
        clock_profile_name="enterprise_standard",
        output_start_time=output_start,
        include_sysmon=True,
        include_sysmon_during_open=True,
        modeled_target_pid4=True,
        modeled_source_pid4=True,
        production_timing_runtime=True,
    )
    sysmon = harness.sysmon
    assert sysmon is not None
    target_identities = {
        identity.image.replace("\\", "/").rsplit("/", 1)[-1].casefold(): identity
        for identity in harness.terminal_process_identities
        if identity.hostname == harness.target_hostname
    }
    winlogon = target_identities["winlogon.exe"]
    userinit = target_identities["userinit.exe"]
    explorer = target_identities["explorer.exe"]
    pid4 = harness.state.get_process_identity(harness.target_hostname, 4)
    assert pid4 is not None
    assert pid4.started_at < output_start
    assert winlogon.parent_pid == pid4.pid
    assert userinit.parent_pid == winlogon.pid
    assert explorer.parent_pid == userinit.pid

    planner = harness.dispatcher.source_timing_planner
    parent_object_id = planner._sysmon_process_object_id(
        harness.target_hostname,
        pid4.pid,
        pid4.started_at,
    )
    parent_render_time = planner._sysmon_process_render_create_times.get(
        (f"sysmon:{harness.target_hostname.casefold()}", parent_object_id)
    )
    assert parent_render_time is not None
    expected_pid4_guid = sysmon._generate_process_guid(
        harness.target_hostname,
        pid4.pid,
        parent_render_time,
    )

    _close_rdp_terminal_harness(harness)
    rendered = "\n".join(
        output.read_text(encoding="utf-8")
        for output in (harness.output_root / "sysmon").rglob("*.xml")
    )
    event_one_rows = _xml_events(rendered, 1)
    assert not _xml_events(rendered, 3)

    def _field(event: str, name: str) -> str:
        match = re.search(rf'<Data Name="{name}">(.*?)</Data>', event)
        assert match is not None
        return match.group(1)

    def _event_time(event: str) -> datetime:
        match = re.search(r'<TimeCreated SystemTime="([^"]+)"', event)
        assert match is not None
        return datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))

    target_rows = {
        _field(event, "Image").replace("\\", "/").rsplit("/", 1)[-1].casefold(): event
        for event in event_one_rows
        if _field(event, "Image").replace("\\", "/").rsplit("/", 1)[-1].casefold()
        in {"winlogon.exe", "userinit.exe", "explorer.exe"}
    }
    assert set(target_rows) == {"winlogon.exe", "userinit.exe", "explorer.exe"}
    assert not any(_field(event, "ProcessId") == "4" for event in event_one_rows)
    assert _field(target_rows["winlogon.exe"], "ParentProcessGuid") == expected_pid4_guid
    assert _field(target_rows["userinit.exe"], "ParentProcessGuid") == _field(
        target_rows["winlogon.exe"],
        "ProcessGuid",
    )
    assert _field(target_rows["explorer.exe"], "ParentProcessGuid") == _field(
        target_rows["userinit.exe"],
        "ProcessGuid",
    )
    rendered_times = {
        image: _event_time(target_rows[image])
        for image in ("winlogon.exe", "userinit.exe", "explorer.exe")
    }
    assert (
        parent_render_time
        < rendered_times["winlogon.exe"]
        < rendered_times["userinit.exe"]
        < rendered_times["explorer.exe"]
    )
    for image, identity in target_identities.items():
        assert _field(target_rows[image], "ProcessId") == str(identity.pid)
        assert _field(target_rows[image], "ProcessGuid") == sysmon._generate_process_guid(
            identity.hostname,
            identity.pid,
            rendered_times[image],
        )


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


@pytest.mark.parametrize(
    ("failure_mode", "rebind_after_projection"),
    (
        ("fail-before", False),
        ("lost-return", False),
        ("fail-before", True),
    ),
)
def test_initial_rdp_source_publication_failure_recovers_full_materialization(
    failure_mode: str,
    rebind_after_projection: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed RDP open retains its application receipt and exact close owner."""

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
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0
    public_connection_reads = 0
    projected_application_receipts: list[object] = []

    if rebind_after_projection:
        original_projection = (
            GeneratorLifecycleAuthority.retained_prepared_network_recovery_projection
        )

        def project_then_rebind(
            authority: GeneratorLifecycleAuthority,
            root: PreparedNetworkTransactionRoot,
            result: object,
        ) -> object:
            projection = original_projection(authority, root, result)
            assert projection is not None
            projected_application_receipts.append(projection[1])

            def hostile_connection(_result: LifecyclePreparedNetworkResult) -> object:
                nonlocal public_connection_reads
                public_connection_reads += 1
                raise AssertionError("planner reopened authenticated result descriptors")

            monkeypatch.setattr(
                LifecyclePreparedNetworkResult,
                "connection",
                property(hostile_connection),
            )
            return projection

        monkeypatch.setattr(
            GeneratorLifecycleAuthority,
            "retained_prepared_network_recovery_projection",
            project_then_rebind,
        )

    def inject(
        writer: ExternalSortedLineWriter,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        if writer.output_path.name == "ecar.json" and attempts == 0:
            attempts += 1
            if failure_mode == "lost-return":
                original(writer, key, digest, frozen)
            raise OSError(f"injected RDP source {failure_mode}")
        original(writer, key, digest, frozen)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", inject)
    with pytest.raises(OSError, match=f"RDP source {failure_mode}"):
        generator._execute_rdp_session_bundle(
            user=user,
            target_system=target,
            time=_START,
            source_ip=source.ip,
            source_system=source,
            source_pid=source_pid,
            source_port=50_001,
        )

    target_sessions = [
        session
        for session in state.get_sessions_for_user(user.username)
        if session.system == target.hostname
    ]
    assert attempts == 1
    assert len(target_sessions) == 1
    target_session = target_sessions[0]
    journal = generator.rdp_lifecycle_journal_census()
    assert journal.prepared_reservations == 0
    assert journal.pending_generations == 1
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    lifecycle_authority = generator._lifecycle_authority
    assert lifecycle_authority._prepared_network_receipt_issuances == {}
    assert lifecycle_authority._prepared_network_receipt_issuance_generations == {}
    assert lifecycle_authority._prepared_network_receipt_issuance_receipts == {}
    assert public_connection_reads == 0
    if rebind_after_projection:
        assert len(projected_application_receipts) == 1
        assert generator.rdp_session_manager.authenticates_admission_receipt(
            projected_application_receipts[0]
        )

    recovery_results = dispatcher.drain_exact_projection_recoveries()
    assert len(recovery_results) == 1
    assert all(outcome.status == "succeeded" for outcome in recovery_results[0].projections)
    generator.finalize_rdp_session_lifecycles(_END)

    assert state.get_session(target_session.logon_id) is None
    assert state.get_process(source.hostname, source_pid) is None
    assert generator.rdp_lifecycle_journal_census().pending_generations == 0
    assert dispatcher.deferred_session_publication_census().prepared_batches == 0
    assert generator.rdp_session_manager.census().active_operations == 0
    assert generator.rdp_session_manager.census().active_leases == 0
    assert generator._application_channel_registry.census().open_channels == 0

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
    ecar_rows = [
        json.loads(line)
        for output in (tmp_path / "ecar").rglob("ecar.json")
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    target_session_rows = [
        row
        for row in ecar_rows
        if row.get("hostname") == target.hostname and row.get("object") == "USER_SESSION"
    ]
    assert [row["action"] for row in target_session_rows] == ["LOGIN", "LOGOUT"]
    zeek_rows = [
        json.loads(line)
        for line in (tmp_path / "zeek.json").read_text(encoding="utf-8").splitlines()
    ]
    assert len(zeek_rows) == 1


def test_generic_type10_from_modeled_linux_source_uses_exact_rdp_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic Type 10 preserves a Linux source IP without assigning it mstsc ownership."""

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
        hostname="LT-01",
        ip="10.10.0.25",
        os="Ubuntu 22.04",
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
    original_generate_logon = generator.generate_logon
    generate_logon_calls = 0

    def counted_generate_logon(*args: object, **kwargs: object) -> str:
        nonlocal generate_logon_calls
        generate_logon_calls += 1
        return original_generate_logon(*args, **kwargs)

    monkeypatch.setattr(generator, "generate_logon", counted_generate_logon)

    logon_id = generator.generate_logon(
        user=user,
        system=target,
        time=_START,
        logon_type=10,
        source_ip=source.ip,
    )

    session = state.get_session(logon_id)
    assert generate_logon_calls == 1
    assert session is not None
    assert session.session_kind == "rdp"
    assert session.source_ip == source.ip
    assert session.closure_owned_by_bundle
    with generator._rdp_lifecycle_journal_lock:
        journal_entries = tuple(generator._pending_rdp_lifecycle_continuations.values())
    assert len(journal_entries) == 1
    continuation = journal_entries[0].continuation
    assert continuation.prepared.source_system is None
    assert continuation.prepared.session_identity.object_id == session.ecar_object_id

    ecar.close()
    zeek.close()


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
        production_timing_runtime=clock_profile_name != "complete",
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
    engine._linux_sudo_logoffs_finalized = False
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

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused gates for carrier-independent Sysmon frozen-render timing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    DnsContext,
    FileContext,
    HostContext,
    ImageLoadContext,
    ProcessContext,
    RegistryContext,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import sysmon as sysmon_module
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.source_timing import (
    SourceTimingPlan,
    SourceTimingPlanner,
    endpoint_event_native_key,
    endpoint_event_render_key,
    sysmon_parent_process_render_key,
    sysmon_process_identity_render_key,
    sysmon_process_native_key,
    sysmon_process_render_key,
)
from evidenceforge.generation.timing import TimingRuntime
from tests.network_factories import network_plan

T0 = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


def _host() -> HostContext:
    """Return one canonical Windows endpoint."""

    return HostContext(
        hostname="WIN-01",
        fqdn="win-01.example.test",
        ip="10.20.30.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="example.test",
        netbios_domain="EXAMPLE",
    )


def _process_event(
    *,
    event_type: str = "process_create",
    timestamp: datetime = T0,
    started_at: datetime = T0,
) -> OccurrenceBuilder:
    """Return one process occurrence with stable source identity."""

    parent_started_at = started_at - timedelta(days=7)
    child_identity = ProcessIdentity(
        hostname="WIN-01",
        object_id=f"process-win-01-2012-{started_at.isoformat()}",
        pid=2_012,
        parent_pid=4,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        principal=r"EXAMPLE\analyst",
        logon_id="0x3e7",
        started_at=started_at,
        lifecycle_group_id=f"process-win-01-2012-{started_at.isoformat()}-lifecycle",
    )
    parent_identity = ProcessIdentity(
        hostname="WIN-01",
        object_id=f"process-win-01-4-{parent_started_at.isoformat()}",
        pid=4,
        parent_pid=0,
        image=r"C:\Windows\System32\System",
        command_line="System",
        principal="SYSTEM",
        logon_id="0x3e7",
        started_at=parent_started_at,
        lifecycle_group_id=f"process-win-01-4-{parent_started_at.isoformat()}-lifecycle",
    )
    return OccurrenceBuilder(
        timestamp=timestamp,
        event_type=event_type,
        src_host=_host(),
        process=ProcessContext(
            pid=2_012,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            username=r"EXAMPLE\analyst",
            start_time=started_at,
            parent_start_time=parent_started_at,
        ),
        identity_plan=EventIdentityPlan(subject=child_identity, actor=parent_identity),
    )


def _plan(event: OccurrenceBuilder, planner: SourceTimingPlanner) -> None:
    """Freeze one Sysmon projection through the upstream owner."""

    planner.plan_event(
        event,
        "windows_event_sysmon",
        source_instance="sysmon:win-01",
        source_hostname="win-01",
    )


def test_sysmon_renderer_only_formats_finalized_process_times(tmp_path: Path) -> None:
    """Event 1/5 consume the exact frozen native/envelope pair without replanning."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-render-probe")
    )
    create = _process_event()
    terminate = _process_event(
        event_type="process_terminate",
        timestamp=T0 + timedelta(seconds=4),
    )
    _plan(create, planner)
    _plan(terminate, planner)

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon.xml",
        threaded=False,
    )
    rows: list[dict[str, object]] = []
    emit_event = emitter.emit_event

    def capture(row: dict[str, object]) -> None:
        rows.append(dict(row))
        emit_event(row)

    emitter.emit_event = capture
    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("production Sysmon renderer replanned timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_sysmon_envelope_time",
            side_effect=AssertionError("production Sysmon renderer replanned its envelope"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_process_create_time",
            side_effect=AssertionError("production Sysmon renderer replanned ProcessGuid time"),
        ),
    ):
        emitter.emit(create)
        emitter.emit(terminate)

    for row, lifecycle, event in (
        (rows[0], "create", create),
        (rows[1], "terminate", terminate),
    ):
        assert event.source_timing is not None
        native = event.source_timing.finalized_times[sysmon_process_native_key(lifecycle, "WIN-01")]
        rendered = event.source_timing.finalized_times[
            sysmon_process_render_key(lifecycle, "WIN-01")
        ]
        assert row["TimeCreated"] == rendered
        assert row["UtcTime"] == native.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        assert row["_TimingFinalized"] is sysmon_module._FROZEN_TIMING_MARKER


def test_sysmon_file_create_formats_frozen_native_fields(tmp_path: Path) -> None:
    """Event 11 uses frozen native time for both payload timestamp fields."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-file-probe")
    )
    process_event = _process_event()
    file_event = OccurrenceBuilder(
        timestamp=T0 + timedelta(milliseconds=5),
        event_type="file_create",
        src_host=process_event.src_host,
        process=process_event.process,
        file=FileContext(
            path=r"C:\Users\analyst\AppData\Local\Temp\runtime.zip",
            action="create",
        ),
    )
    _plan(process_event, planner)
    _plan(file_event, planner)
    assert file_event.source_timing is not None
    native = file_event.source_timing.finalized_times[
        endpoint_event_native_key("windows_event_sysmon", "WIN-01", "base")
    ]
    rendered = file_event.source_timing.finalized_times[
        endpoint_event_render_key("windows_event_sysmon", "WIN-01", "base")
    ]

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon-file.xml",
        buffer_size=10,
    )
    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("production endpoint compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_sysmon_envelope_time",
            side_effect=AssertionError("production envelope compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_process_create_time",
            side_effect=AssertionError("production ProcessGuid compatibility timing"),
        ),
    ):
        emitter.emit(file_event)

    row = next(row for row in emitter._event_dicts if row["EventID"] == 11)
    native_text = native.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    assert row["TimeCreated"] == rendered
    assert row["UtcTime"] == native_text
    assert row["CreationUtcTime"] == native_text
    assert row["_TimingFinalized"] is sysmon_module._FROZEN_TIMING_MARKER


def test_sysmon_dependent_uses_frozen_dropped_event_one_guid(tmp_path: Path) -> None:
    """Event 3 uses its frozen Event 1 seed even when Event 1 was not collected."""

    started_at = T0 - timedelta(days=2, seconds=17)
    event = _process_event(event_type="connection", timestamp=T0, started_at=started_at)
    assert event.process is not None
    identity = ProcessIdentity(
        hostname="WIN-01",
        object_id="boot-process-win-01-2012",
        pid=event.process.pid,
        parent_pid=event.process.parent_pid,
        image=event.process.image,
        command_line=event.process.command_line,
        principal=event.process.username,
        logon_id="0x3e7",
        started_at=started_at,
        lifecycle_group_id="boot-process-win-01-2012-lifecycle",
    )
    event.identity_plan = EventIdentityPlan(actor=identity)
    event.network = network_plan(
        src_ip=event.src_host.ip,
        src_port=49_152,
        dst_ip="198.51.100.80",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CSysmonDroppedEventOne",
        duration=0.25,
        source_visible_start_time=T0,
        conn_state="SF",
        initiating_pid=event.process.pid,
    )
    planner = SourceTimingPlanner(
        "enterprise_standard",
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-dropped-event-one"),
    )
    _plan(event, planner)
    assert event.source_timing is not None
    create_render = event.source_timing.finalized_times[
        sysmon_process_identity_render_key("WIN-01", event.process.pid, started_at)
    ]

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon-network.xml",
    )
    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("production endpoint compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_sysmon_envelope_time",
            side_effect=AssertionError("production envelope compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_process_create_time",
            side_effect=AssertionError("production ProcessGuid compatibility timing"),
        ),
    ):
        emitter.emit(event)

    row = next(row for row in emitter._event_dicts if row["EventID"] == 3)
    assert row["ProcessGuid"] == emitter._generate_process_guid(
        "WIN-01", event.process.pid, create_render
    )


def test_sysmon_incomplete_production_plan_fails_closed(tmp_path: Path) -> None:
    """Only an explicitly marked compatibility plan may be extended in the emitter."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon-compatibility.xml",
    )
    production = _process_event()
    production.source_timing = SourceTimingPlan(canonical_timestamp=production.timestamp)
    with pytest.raises(RuntimeError, match="requires frozen endpoint timing"):
        emitter._render_times(production, "process_create")

    compatibility = _process_event(timestamp=T0 + timedelta(seconds=1))
    compatibility.source_timing = SourceTimingPlan(
        canonical_timestamp=compatibility.timestamp,
        compatibility_mode=True,
    )
    native, rendered = emitter._render_times(compatibility, "process_create")
    assert rendered >= native
    assert compatibility.source_timing.compatibility_mode is True


def test_sysmon_production_event_one_requires_frozen_parent_identity(tmp_path: Path) -> None:
    """A production Event 1 cannot replace a missing parent key with canonical time."""

    event = _process_event()
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-parent-required")
    )
    _plan(event, planner)
    assert event.source_timing is not None
    del event.source_timing.finalized_times[sysmon_parent_process_render_key("WIN-01")]
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "missing-parent.xml",
    )

    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("production parent used compatibility timing"),
        ),
        pytest.raises(RuntimeError, match="requires a frozen parent process-create source time"),
    ):
        emitter.emit(event)


def _direct_process_event(
    *,
    pid: int,
    parent_pid: int,
    started_at: datetime,
    parent_started_at: datetime,
) -> OccurrenceBuilder:
    """Return a direct compatibility Event 1 without an engine timing plan."""

    return OccurrenceBuilder(
        timestamp=started_at,
        event_type="process_create",
        src_host=_host(),
        process=ProcessContext(
            pid=pid,
            parent_pid=parent_pid,
            image=rf"C:\Windows\System32\process-{pid}.exe",
            command_line=f"process-{pid}.exe",
            username=r"EXAMPLE\analyst",
            parent_image=rf"C:\Windows\System32\process-{parent_pid}.exe",
            parent_command_line=f"process-{parent_pid}.exe",
            start_time=started_at,
            parent_start_time=parent_started_at,
        ),
    )


@pytest.mark.parametrize("child_first", [False, True])
def test_direct_event_one_parent_guid_correlates_in_either_order(
    tmp_path: Path,
    child_first: bool,
) -> None:
    """Stateless compatibility derives the same GUID for parent and child rows."""

    grandparent_started_at = T0 - timedelta(days=1)
    parent_started_at = T0 - timedelta(minutes=2)
    parent = _direct_process_event(
        pid=4_200,
        parent_pid=4,
        started_at=parent_started_at,
        parent_started_at=grandparent_started_at,
    )
    child = _direct_process_event(
        pid=8_052,
        parent_pid=4_200,
        started_at=T0,
        parent_started_at=parent_started_at,
    )
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / f"direct-parent-{child_first}.xml",
        buffer_size=10,
    )

    for event in (child, parent) if child_first else (parent, child):
        emitter.emit(event)

    parent_row = next(row for row in emitter._event_dicts if row["ProcessId"] == 4_200)
    child_row = next(row for row in emitter._event_dicts if row["ProcessId"] == 8_052)
    assert child_row["ParentProcessGuid"] == parent_row["ProcessGuid"]


def _dns_event(*, with_process: bool, with_actor: bool) -> OccurrenceBuilder:
    """Return one DNS connection with selected carrier-owned process identity."""

    event = _process_event(
        event_type="connection",
        timestamp=T0,
        started_at=T0 - timedelta(seconds=5),
    )
    event.network = network_plan(
        src_ip=event.src_host.ip,
        src_port=49_154,
        dst_ip="10.20.30.53",
        dst_port=53,
        protocol="udp",
        zeek_uid="CSysmonDnsFrozen",
        duration=0.05,
        source_visible_start_time=T0,
        conn_state="SF",
        initiating_pid=event.process.pid,
    )
    event.dns = DnsContext(
        query="example.test",
        rcode="NOERROR",
        answers=["10.20.30.80"],
    )
    if not with_process:
        event.process = None
    if not with_actor:
        event.identity_plan = None
    elif event.identity_plan is not None:
        event.identity_plan = EventIdentityPlan(actor=event.identity_plan.subject)
    return event


@pytest.mark.parametrize("with_process,with_actor", [(True, False), (False, True)])
def test_planned_dns_uses_only_frozen_carrier_process_identity(
    tmp_path: Path,
    with_process: bool,
    with_actor: bool,
) -> None:
    """Event 22 consumes a process identity the upstream planner already froze."""

    event = _dns_event(with_process=with_process, with_actor=with_actor)
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-dns-carrier")
    )
    _plan(event, planner)
    process = event.process
    actor = event.identity_plan.actor if event.identity_plan is not None else None
    pid = process.pid if process is not None else actor.pid
    started_at = process.start_time if process is not None else actor.started_at
    assert event.source_timing is not None
    frozen_identity_time = event.source_timing.finalized_times[
        sysmon_process_identity_render_key("WIN-01", pid, started_at)
    ]
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / f"dns-carrier-{with_process}-{with_actor}.xml",
    )

    with patch.object(
        sysmon_module,
        "compatibility_process_create_time",
        side_effect=AssertionError("planned DNS sampled a ProcessGuid time"),
    ):
        emitter.emit(event)

    row = next(row for row in emitter._event_dicts if row["EventID"] == 22)
    assert row["ProcessId"] == pid
    assert row["ProcessGuid"] == emitter._generate_process_guid("WIN-01", pid, frozen_identity_time)


def test_planned_dns_without_carrier_process_is_omitted_before_rendering(tmp_path: Path) -> None:
    """Production DNS cannot enter an emitter-owned fallback identity path."""

    event = _dns_event(with_process=False, with_actor=False)
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-dns-no-carrier")
    )
    _plan(event, planner)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "dns-no-carrier.xml",
    )

    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("omitted DNS entered compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_process_create_time",
            side_effect=AssertionError("omitted DNS sampled a ProcessGuid time"),
        ),
    ):
        emitter.emit(event)

    assert all(row["EventID"] != 22 for row in emitter._event_dicts)


def test_planned_image_load_without_process_is_omitted_before_fallback(tmp_path: Path) -> None:
    """A production Event 7 cannot synthesize an emitter-owned process identity."""

    event = OccurrenceBuilder(
        timestamp=T0,
        event_type="image_load",
        src_host=_host(),
        image_load=ImageLoadContext(image_loaded=r"C:\Windows\System32\version.dll"),
    )
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-image-no-process")
    )
    _plan(event, planner)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "image-no-process.xml",
    )

    with patch.object(
        sysmon_module,
        "compatibility_process_create_time",
        side_effect=AssertionError("planned image load sampled a ProcessGuid time"),
    ):
        emitter.emit(event)

    assert emitter._event_dicts == []


def _pid_only_event(family: str, *, with_actor: bool) -> OccurrenceBuilder:
    """Return an Event 3/11/13 occurrence whose context carries only a PID."""

    pid = 4_568
    started_at = T0 - timedelta(seconds=8)
    event = OccurrenceBuilder(
        timestamp=T0,
        event_type={
            "network": "connection",
            "file": "file_create",
            "registry": "registry_modify",
        }[family],
        src_host=_host(),
    )
    if family == "network":
        event.network = network_plan(
            src_ip=event.src_host.ip,
            src_port=49_155,
            dst_ip="198.51.100.82",
            dst_port=443,
            protocol="tcp",
            zeek_uid="CSysmonPidOnly",
            duration=0.2,
            source_visible_start_time=T0,
            conn_state="SF",
            initiating_pid=pid,
        )
    elif family == "file":
        event.file = FileContext(
            path=r"C:\Windows\Temp\pid-only.tmp",
            action="create",
            pid=pid,
        )
    else:
        event.registry = RegistryContext(
            key=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\PidOnly",
            value=r"C:\Windows\System32\cmd.exe",
            action="modify",
            pid=pid,
        )
    if with_actor:
        actor = ProcessIdentity(
            hostname="WIN-01",
            object_id="process-win-01-4568-pid-only",
            pid=pid,
            parent_pid=4_000,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe",
            principal=r"EXAMPLE\analyst",
            logon_id="0x3e7",
            started_at=started_at,
            lifecycle_group_id="process-win-01-4568-pid-only-lifecycle",
        )
        event.identity_plan = EventIdentityPlan(actor=actor)
    return event


@pytest.mark.parametrize(
    "family,event_id",
    [("network", 3), ("file", 11), ("registry", 13)],
)
@pytest.mark.parametrize("with_actor", [False, True])
def test_planned_pid_only_rows_use_frozen_actor_or_omit_before_state_fallback(
    tmp_path: Path,
    family: str,
    event_id: int,
    with_actor: bool,
) -> None:
    """Production PID-only rows never derive ProcessGuid timing from StateManager."""

    event = _pid_only_event(family, with_actor=with_actor)
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace=f"sysmon-pid-only-{family}")
    )
    _plan(event, planner)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / f"pid-only-{family}-{with_actor}.xml",
    )
    state_manager = Mock()
    state_manager.get_process.side_effect = AssertionError(
        "production PID-only row consulted StateManager"
    )
    emitter._state_manager = state_manager

    with (
        patch.object(
            sysmon_module,
            "compatibility_endpoint_event_times",
            side_effect=AssertionError("production PID-only row used compatibility timing"),
        ),
        patch.object(
            sysmon_module,
            "compatibility_process_create_time",
            side_effect=AssertionError("production PID-only row sampled ProcessGuid timing"),
        ),
    ):
        emitter.emit(event)

    rows = [row for row in emitter._event_dicts if row["EventID"] == event_id]
    if not with_actor:
        assert rows == []
        return

    actor = event.identity_plan.actor
    assert isinstance(actor, ProcessIdentity)
    assert event.source_timing is not None
    frozen_identity_time = event.source_timing.finalized_times[
        sysmon_process_identity_render_key(
            "WIN-01",
            actor.pid,
            actor.started_at,
        )
    ]
    assert len(rows) == 1
    assert rows[0]["ProcessId"] == actor.pid
    assert rows[0]["Image"] == actor.image
    assert rows[0]["ProcessGuid"] == emitter._generate_process_guid(
        "WIN-01",
        actor.pid,
        frozen_identity_time,
    )


def test_direct_process_compatibility_guid_uses_final_envelope(tmp_path: Path) -> None:
    """A direct Event 1 call derives ProcessGuid from its visible compatibility time."""

    event_time = T0.replace(microsecond=999_900)
    event = _process_event(timestamp=event_time, started_at=event_time)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon-direct.xml",
    )
    emitter.emit(event)

    row = next(row for row in emitter._event_dicts if row["EventID"] == 1)
    rendered = row["TimeCreated"]
    assert isinstance(rendered, datetime)
    assert row["ProcessGuid"] == emitter._generate_process_guid(
        "WIN-01", event.process.pid, rendered
    )


def test_direct_private_renderer_does_not_apply_a_second_envelope(tmp_path: Path) -> None:
    """A private compatibility render carries its planned pair into emit_event once."""

    event = _process_event(event_type="connection")
    event.network = network_plan(
        src_ip=event.src_host.ip,
        src_port=49_153,
        dst_ip="198.51.100.81",
        dst_port=443,
        protocol="tcp",
        zeek_uid="CSysmonDirectCompatibility",
        duration=0.25,
        source_visible_start_time=T0,
        conn_state="SF",
        initiating_pid=event.process.pid,
    )
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "sysmon-private.xml",
    )
    with patch.object(
        sysmon_module,
        "compatibility_sysmon_envelope_time",
        side_effect=AssertionError("direct canonical renderer applied a second envelope"),
    ):
        emitter._render_sysmon_network_connect(event)

    assert event.source_timing is not None
    native = event.source_timing.finalized_times[
        endpoint_event_native_key("windows_event_sysmon", "WIN-01", "network")
    ]
    rendered = event.source_timing.finalized_times[
        endpoint_event_render_key("windows_event_sysmon", "WIN-01", "network")
    ]
    row = next(row for row in emitter._event_dicts if row["EventID"] == 3)
    assert row["_SysmonNativeTime"] == native
    assert row["TimeCreated"] == rendered
    assert row["_TimingFinalized"] is sysmon_module._FROZEN_TIMING_MARKER


def _render_file_output(output_dir: Path, *, threaded: bool, buffer_size: int) -> bytes:
    """Render one frozen Event 11 through a selected writer shape."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-byte-determinism")
    )
    process_event = _process_event()
    file_event = OccurrenceBuilder(
        timestamp=T0 + timedelta(milliseconds=7),
        event_type="file_create",
        src_host=process_event.src_host,
        process=process_event.process,
        file=FileContext(path=r"C:\Windows\Temp\deterministic.tmp", action="create"),
    )
    _plan(file_event, planner)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_dir,
        buffer_size=buffer_size,
        threaded=threaded,
    )
    emitter.emit(file_event)
    emitter.close()
    return (output_dir / "win-01.example.test" / "windows_event_sysmon.xml").read_bytes()


def test_sysmon_frozen_output_is_writer_shape_deterministic(tmp_path: Path) -> None:
    """Threading and buffer size do not change frozen row bytes or record identity."""

    direct = _render_file_output(tmp_path / "direct", threaded=False, buffer_size=1)
    threaded = _render_file_output(tmp_path / "threaded", threaded=True, buffer_size=37)
    assert direct == threaded
    assert direct.count(b"<EventID>11</EventID>") == 1
    assert direct.count(b"<EventRecordID>") == 1


def _render_frozen_snare_output(
    output_dir: Path,
    *,
    threaded: bool,
    buffer_size: int,
) -> bytes:
    """Render one frozen Event 11 through the SOF-ELK Snare path."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="sysmon-snare-determinism")
    )
    event = _process_event(event_type="file_create", timestamp=T0 + timedelta(milliseconds=9))
    event.file = FileContext(path=r"C:\Windows\Temp\snare-deterministic.tmp", action="create")
    _plan(event, planner)
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_dir,
        threaded=threaded,
        buffer_size=buffer_size,
    )
    emitter.configure_output_target("sof-elk")
    emitter.emit(event)
    emitter.close()
    return (
        output_dir / "win-01.example.test" / "2026" / "windows_event_sysmon_snare.log"
    ).read_bytes()


def test_sysmon_frozen_marker_never_reaches_snare_output(tmp_path: Path) -> None:
    """The internal finalized marker is consumed before every output renderer."""

    direct = _render_frozen_snare_output(
        tmp_path / "snare-direct",
        threaded=False,
        buffer_size=1,
    )
    threaded = _render_frozen_snare_output(
        tmp_path / "snare-threaded",
        threaded=True,
        buffer_size=37,
    )
    assert direct == threaded
    assert b"_TimingFinalized" not in direct
    assert b"<object object at" not in direct
    assert b"\t11\tMicrosoft-Windows-Sysmon\t" in direct


def test_sysmon_emitter_has_no_timing_planner_or_sampler() -> None:
    """Sysmon may format frozen times or call only explicit stateless adapters."""

    source = Path(sysmon_module.__file__).read_text(encoding="utf-8")
    forbidden = (
        "SourceTimingPlanner",
        "_SOURCE_TIMING",
        "sample_timing_delta(",
        "sample_packet_timing_delta(",
        "get_timing_window(",
        ".source_time(",
        ".sysmon_envelope_time(",
        ".process_module_source_time(",
    )
    assert [fragment for fragment in forbidden if fragment in source] == []

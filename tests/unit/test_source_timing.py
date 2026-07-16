# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for source-aware timing planning."""

import json
import xml.etree.ElementTree as ET
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.events.authentication import (
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
)
from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    FileContext,
    HostContext,
    NetworkContext,
    ProcessAccessContext,
    ProcessContext,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import NetworkTuple
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    ecar_flow_render_key,
    ecar_session_render_key,
)


def _base_time() -> datetime:
    return datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _network_context(duration: float = 0.05) -> NetworkContext:
    return NetworkContext(
        src_ip="10.0.0.20",
        src_port=49152,
        dst_ip="10.0.0.53",
        dst_port=53,
        protocol="udp",
        service="dns",
        zeek_uid="CsourceTiming01",
        duration=duration,
        conn_state="SF",
        history="Dd",
        orig_bytes=64,
        resp_bytes=128,
        orig_pkts=1,
        resp_pkts=1,
        orig_ip_bytes=92,
        resp_ip_bytes=156,
        ip_proto=17,
    )


def _host_context() -> HostContext:
    return HostContext(
        hostname="WIN-TEST-01",
        ip="10.0.0.20",
        fqdn="WIN-TEST-01.corp.local",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="corp.local",
        netbios_domain="CORP",
    )


def _linux_host_context() -> HostContext:
    return HostContext(
        hostname="LINUX-TEST-01",
        ip="10.0.1.20",
        fqdn="LINUX-TEST-01.corp.local",
        os="Ubuntu Linux",
        os_category="linux",
        system_type="server",
        domain="corp.local",
        netbios_domain="CORP",
    )


def _process_context(start_time: datetime) -> ProcessContext:
    return ProcessContext(
        pid=4242,
        parent_pid=888,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -NoProfile",
        username=r"CORP\alice",
        logon_id="0x12345",
        parent_image=r"C:\Windows\explorer.exe",
        start_time=start_time,
    )


def _process_identity(
    *,
    hostname: str,
    pid: int,
    parent_pid: int,
    started_at: datetime,
    image: str,
) -> ProcessIdentity:
    object_id = f"process-{hostname}-{pid}-{started_at.isoformat()}"
    primary_thread = ThreadIdentity(
        hostname=hostname,
        process_object_id=object_id,
        pid=pid,
        tid=max(4, ((pid + 3) // 4) * 4),
        object_id=f"thread-{object_id}",
        started_at=started_at,
        kind="primary",
    )
    return ProcessIdentity(
        hostname=hostname,
        object_id=object_id,
        pid=pid,
        parent_pid=parent_pid,
        image=image,
        command_line=image,
        principal=r"CORP\alice",
        logon_id="0x12345",
        started_at=started_at,
        lifecycle_group_id=f"lifecycle-{object_id}",
        primary_thread=primary_thread,
    )


def _context_from_identity(identity: ProcessIdentity) -> ProcessContext:
    return ProcessContext(
        pid=identity.pid,
        parent_pid=identity.parent_pid,
        image=identity.image,
        command_line=identity.command_line,
        username=identity.principal,
        logon_id=identity.logon_id,
        start_time=identity.started_at,
    )


def test_source_time_is_deterministic() -> None:
    """The same event/source/seed should produce the same planned source time."""
    planner = SourceTimingPlanner()
    event = SecurityEvent(
        timestamp=_base_time(), event_type="connection", network=_network_context()
    )

    first = planner.source_time(
        event,
        "source.zeek_dns_query",
        seed_parts=("uid", "query", event.timestamp),
    )
    second = planner.source_time(
        event,
        "source.zeek_dns_query",
        seed_parts=("uid", "query", event.timestamp),
    )

    assert first == second


def test_session_closure_follows_same_source_process_termination_with_bounded_tail() -> None:
    """Source timing—not canonical time—orders closure after rendered dependents."""
    planner = SourceTimingPlanner()
    canonical_end = _base_time() + timedelta(hours=1)
    host = _host_context()
    process_start = canonical_end - timedelta(minutes=10)
    process_event = SecurityEvent(
        timestamp=canonical_end - timedelta(milliseconds=200),
        event_type="process_terminate",
        src_host=host,
        process=ProcessContext(
            pid=4242,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="",
            username=r"CORP\alice",
            logon_id="0x12345",
            start_time=process_start,
        ),
        lifecycle=ActionLifecycleContext(
            group_id="process-group",
            canonical_start=process_start,
            phase="closure",
            parent_group_id="session-group",
        ),
    )
    planner.plan_event(process_event, "windows_event_security")
    logoff_event = SecurityEvent(
        timestamp=canonical_end,
        event_type="logoff",
        dst_host=host,
        auth=AuthContext(username=r"CORP\alice", logon_id="0x12345", logon_type=10),
        lifecycle=ActionLifecycleContext(
            group_id="session-group",
            canonical_start=canonical_end - timedelta(hours=1),
            phase="closure",
        ),
    )

    planned = planner.plan_event(logoff_event, "windows_event_security")
    process_source_time = planner.source_time(
        process_event,
        "source.windows_security_process_terminate",
        seed_parts=(host.hostname, 4242, process_start, process_event.timestamp),
        not_before=process_event.timestamp,
    )

    assert planned.source_timing.canonical_timestamp == canonical_end
    assert planned.timestamp > process_source_time
    assert planned.timestamp <= canonical_end + timedelta(seconds=15)


def test_ecar_identity_plan_preserves_parent_create_dependent_terminate_order(
    tmp_path: Path,
) -> None:
    """Dispatcher timing owns visible process lifecycle order before serialization."""

    base = _base_time()
    host = _host_context()
    parent = _process_identity(
        hostname=host.hostname,
        pid=3000,
        parent_pid=4,
        started_at=base,
        image=r"C:\Windows\explorer.exe",
    )
    child = _process_identity(
        hostname=host.hostname,
        pid=4242,
        parent_pid=parent.pid,
        started_at=base + timedelta(milliseconds=15),
        image=r"C:\Windows\System32\cmd.exe",
    )
    parent_event = SecurityEvent(
        timestamp=parent.started_at,
        event_type="process_create",
        src_host=host,
        process=_context_from_identity(parent),
        identity_plan=EventIdentityPlan(subject=parent),
    )
    child_event = SecurityEvent(
        timestamp=child.started_at,
        event_type="process_create",
        src_host=host,
        process=_context_from_identity(child),
        identity_plan=EventIdentityPlan(subject=child, actor=parent),
    )
    file_event = SecurityEvent(
        timestamp=child.started_at + timedelta(milliseconds=25),
        event_type="file_create",
        src_host=host,
        process=_context_from_identity(child),
        file=FileContext(
            path=r"C:\Users\alice\AppData\Local\Temp\result.txt",
            action="create",
            pid=child.pid,
        ),
        identity_plan=EventIdentityPlan(actor=child),
    )
    terminate_event = SecurityEvent(
        timestamp=child.started_at + timedelta(seconds=2),
        event_type="process_terminate",
        src_host=host,
        process=_context_from_identity(child),
        identity_plan=EventIdentityPlan(subject=child),
    )
    planner = SourceTimingPlanner()
    for event in (parent_event, child_event, file_event, terminate_event):
        planner.plan_event(event, format_name="ecar")

    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    for event in (parent_event, child_event, file_event, terminate_event):
        emitter.emit(event)
    emitter.close()

    rows = [
        json.loads(line) for line in (tmp_path / host.fqdn / "ecar.json").read_text().splitlines()
    ]
    parent_create = next(row for row in rows if row.get("objectID") == parent.object_id)
    child_create = next(
        row for row in rows if row.get("objectID") == child.object_id and row["action"] == "CREATE"
    )
    file_create = next(row for row in rows if row["object"] == "FILE")
    child_terminate = next(
        row
        for row in rows
        if row.get("objectID") == child.object_id and row["action"] == "TERMINATE"
    )

    assert parent_create["timestamp_ms"] < child_create["timestamp_ms"]
    assert child_create["timestamp_ms"] < file_create["timestamp_ms"]
    assert file_create["timestamp_ms"] < child_terminate["timestamp_ms"]


def test_nested_action_children_share_host_local_source_offset() -> None:
    """Nested transport children preserve canonical order on one endpoint source."""

    planner = SourceTimingPlanner()
    parent_group_id = "proxy-transaction-1234"
    first_time = _base_time()
    second_time = first_time + timedelta(milliseconds=12)

    def child_event(timestamp: datetime, uid: str) -> SecurityEvent:
        network = _network_context(duration=0.2)
        network.source_visible_start_time = timestamp
        network.source_visible_close_time = timestamp + timedelta(milliseconds=200)
        network.zeek_uid = uid
        network.finalize_transaction(f"network-{uid}")
        return SecurityEvent(
            timestamp=timestamp,
            event_type="connection",
            src_host=_linux_host_context(),
            network=network,
            lifecycle=ActionLifecycleContext(
                group_id=f"network-{uid}",
                canonical_start=timestamp,
                phase="start",
                parent_group_id=parent_group_id,
            ),
        )

    first = child_event(first_time, "CproxyIngress")
    second = child_event(second_time, "CproxyOrigin")
    first_observed = planner.lifecycle_child_source_time(
        first,
        "source.ecar_flow",
        host_key="PROXY-01",
        seed_parts=("inbound", "PROXY-01"),
        within=(first_time, first_time + timedelta(milliseconds=200)),
    )
    second_observed = planner.lifecycle_child_source_time(
        second,
        "source.ecar_flow",
        host_key="PROXY-01",
        seed_parts=("outbound", "PROXY-01"),
        within=(second_time, second_time + timedelta(milliseconds=200)),
    )

    assert first_observed is not None
    assert second_observed is not None
    assert second_observed - first_observed == second_time - first_time


def test_endpoint_sources_share_host_clock_offset() -> None:
    """Windows Security, Sysmon, and host-resident eCAR share one host clock."""
    seed = ("WIN-TEST-01", 4242, _base_time())
    event_kwargs = {
        "timestamp": _base_time(),
        "event_type": "process_create",
        "src_host": _host_context(),
        "process": _process_context(_base_time()),
    }
    complete = SourceTimingPlanner(clock_profile_name="complete")
    enterprise = SourceTimingPlanner(clock_profile_name="enterprise_standard")

    deltas = []
    for source_key in (
        "source.sysmon_process_create",
        "source.windows_security_process_create",
        "source.ecar_process_create",
    ):
        complete_event = SecurityEvent(**event_kwargs)
        enterprise_event = SecurityEvent(**event_kwargs)
        complete_time = complete.source_time(complete_event, source_key, seed_parts=seed)
        enterprise_time = enterprise.source_time(enterprise_event, source_key, seed_parts=seed)
        deltas.append(enterprise_time - complete_time)

    assert len(set(deltas)) == 1
    assert deltas[0] != timedelta(0)


def test_linux_ecar_uses_linux_host_clock_profile() -> None:
    """Linux eCAR receives host-clock adjustment from the Linux endpoint profile."""
    seed = ("LINUX-TEST-01", 4242, _base_time())
    event_kwargs = {
        "timestamp": _base_time(),
        "event_type": "process_create",
        "src_host": _linux_host_context(),
        "process": _process_context(_base_time()),
    }
    complete_event = SecurityEvent(**event_kwargs)
    enterprise_event = SecurityEvent(**event_kwargs)

    complete_time = SourceTimingPlanner(clock_profile_name="complete").source_time(
        complete_event,
        "source.ecar_process_create",
        seed_parts=seed,
    )
    enterprise_time = SourceTimingPlanner(clock_profile_name="enterprise_standard").source_time(
        enterprise_event,
        "source.ecar_process_create",
        seed_parts=seed,
    )

    assert enterprise_time != complete_time


def test_ecar_flow_uses_clock_of_rendering_endpoint() -> None:
    """Inbound and outbound eCAR FLOW rows should use their local endpoint clocks."""

    source = _host_context()
    target = HostContext(
        hostname="WIN-TARGET-01",
        ip="10.0.0.53",
        fqdn="WIN-TARGET-01.corp.local",
        os="Windows Server 2022",
        os_category="windows",
        system_type="server",
        domain="corp.local",
        netbios_domain="CORP",
    )
    event_kwargs = {
        "timestamp": _base_time(),
        "event_type": "connection",
        "src_host": source,
        "dst_host": target,
        "network": _network_context(),
    }
    complete = SourceTimingPlanner(clock_profile_name="complete")
    enterprise = SourceTimingPlanner(clock_profile_name="enterprise_standard")

    for direction, expected_host in (("outbound", source), ("inbound", target)):
        seed = (direction, expected_host.hostname, 49152, _base_time())
        complete_time = complete.source_time(
            SecurityEvent(**event_kwargs),
            "source.ecar_flow",
            seed_parts=seed,
        )
        enterprise_time = enterprise.source_time(
            SecurityEvent(**event_kwargs),
            "source.ecar_flow",
            seed_parts=seed,
        )
        expected_adjustment = enterprise.endpoint_clock_adjustment_for_host(
            hostname=expected_host.hostname,
            os_category="windows",
            timestamp=_base_time(),
        )

        assert enterprise_time - complete_time == expected_adjustment


def test_network_sensor_timing_is_independent_from_endpoint_clock_profile() -> None:
    """Zeek/network sensor source times do not inherit endpoint host clock skew."""
    seed = ("uid", "query", _base_time())
    event_kwargs = {
        "timestamp": _base_time(),
        "event_type": "connection",
        "src_host": _host_context(),
        "network": _network_context(),
    }
    complete_time = SourceTimingPlanner(clock_profile_name="complete").source_time(
        SecurityEvent(**event_kwargs),
        "source.zeek_dns_query",
        seed_parts=seed,
    )
    enterprise_time = SourceTimingPlanner(clock_profile_name="enterprise_standard").source_time(
        SecurityEvent(**event_kwargs),
        "source.zeek_dns_query",
        seed_parts=seed,
    )

    assert enterprise_time == complete_time


def test_windows_endpoint_process_sources_are_not_globally_one_directional() -> None:
    """Security and Sysmon process-create source times can land on either side."""
    planner = SourceTimingPlanner(clock_profile_name="enterprise_standard")
    security_before_sysmon = False
    security_after_sysmon = False
    for index in range(100):
        event = SecurityEvent(
            timestamp=_base_time(),
            event_type="process_create",
            src_host=_host_context(),
            process=_process_context(_base_time()),
        )
        seed = ("WIN-TEST-01", 4242, _base_time(), index)
        sysmon_time = planner.source_time(event, "source.sysmon_process_create", seed_parts=seed)
        security_time = planner.source_time(
            event,
            "source.windows_security_process_create",
            seed_parts=seed,
        )
        security_before_sysmon = security_before_sysmon or security_time < sysmon_time
        security_after_sysmon = security_after_sysmon or security_time > sysmon_time
        if security_before_sysmon and security_after_sysmon:
            break

    assert security_before_sysmon
    assert security_after_sysmon


def test_source_time_clamps_to_declared_bounds() -> None:
    """A sampled source delay should not escape an explicit causal window."""
    planner = SourceTimingPlanner()
    event = SecurityEvent(
        timestamp=_base_time(), event_type="connection", network=_network_context()
    )
    latest = event.timestamp + timedelta(microseconds=1)

    planned = planner.source_time(
        event,
        "source.zeek_conn_start",
        seed_parts=("clamped", event.timestamp),
        within=(event.timestamp, latest),
    )

    assert event.timestamp <= planned <= latest


def test_process_create_sources_keep_texture_after_shared_floor() -> None:
    """A shared visibility floor must not collapse endpoint sources to one instant."""
    planner = SourceTimingPlanner(clock_profile_name="enterprise_standard")
    process_start = _base_time()
    shared_floor = process_start + timedelta(seconds=10)
    event = SecurityEvent(
        timestamp=process_start,
        event_type="process_create",
        src_host=_host_context(),
        process=_process_context(process_start),
    )
    seed = ("WIN-TEST-01", 4242, process_start)

    source_times = {
        source_key: planner.source_time(
            event,
            source_key,
            seed_parts=seed,
            not_before=shared_floor,
        )
        for source_key in (
            "source.windows_security_process_create",
            "source.sysmon_process_create",
            "source.ecar_process_create",
        )
    }
    values = list(source_times.values())
    smallest_gap_ms = min(
        abs((left - right).total_seconds() * 1000)
        for index, left in enumerate(values)
        for right in values[index + 1 :]
    )

    assert all(timestamp > shared_floor for timestamp in values)
    assert len(set(values)) == len(values)
    assert smallest_gap_ms >= 1


def test_equal_canonical_timestamps_can_be_ordered_by_causal_edge() -> None:
    """Equal world times stay orderable when a source relationship requires it."""
    planner = SourceTimingPlanner()
    base = _base_time()
    before = SecurityEvent(timestamp=base, event_type="kerberos_tgt")
    after = SecurityEvent(timestamp=base, event_type="kerberos_service")

    before_ts, after_ts = planner.ordered_pair(
        before, after, "source.windows_security_process_create"
    )

    assert before_ts < after_ts


def test_source_time_after_source_uses_temporal_constraint_graph() -> None:
    """Cross-source dependencies should resolve through a shared graph path."""
    planner = SourceTimingPlanner()
    event = SecurityEvent(
        timestamp=_base_time(),
        event_type="process",
        src_host=_host_context(),
        process=_process_context(_base_time()),
    )
    anchor_seed = ("sysmon", event.timestamp)
    dependent_seed = ("ecar", event.timestamp)

    dependent_time = planner.source_time_after_source(
        event,
        "source.ecar_process_create",
        after_source_key="source.windows_security_process_create",
        gap_key="source.ecar_after_sysmon_process_create_gap",
        seed_parts=dependent_seed,
        after_seed_parts=anchor_seed,
    )
    anchor_time = planner.source_time(
        event,
        "source.windows_security_process_create",
        seed_parts=anchor_seed,
    )
    expected_gap = sample_timing_delta(
        "source.ecar_after_sysmon_process_create_gap",
        seed_parts=dependent_seed,
    )

    assert dependent_time >= anchor_time + expected_gap


def test_windows_security_process_create_tracks_sysmon_source_time(tmp_path: Path) -> None:
    """Security 4688 and Sysmon Event 1 for one process should stay source-native-close."""
    process_start = _base_time()
    event = SecurityEvent(
        timestamp=process_start,
        event_type="process_create",
        src_host=_host_context(),
        process=_process_context(process_start),
        auth=AuthContext(
            username="alice",
            user_sid="S-1-5-21-100-200-300-1101",
            logon_id="0x12345",
        ),
    )
    windows = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "windows_event_security.xml",
        buffer_size=10,
    )
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "windows_event_sysmon.xml",
        buffer_size=10,
    )

    # Render Security first to prove the shared timing plan does not depend on emitter order.
    windows.emit(event)
    sysmon.emit(event)

    security_time = next(row for row in windows._event_dicts if row["EventID"] == 4688)[
        "TimeCreated"
    ]
    sysmon_time = next(row for row in sysmon._event_dicts if row["EventID"] == 1)["TimeCreated"]
    delta_ms = (security_time - sysmon_time).total_seconds() * 1000

    assert 0 < delta_ms <= 700


def test_independent_equal_canonical_timestamps_may_share_source_time() -> None:
    """Independent events are not forced into a global total order."""
    planner = SourceTimingPlanner()
    base = _base_time()
    first = SecurityEvent(timestamp=base, event_type="independent_one")
    second = SecurityEvent(timestamp=base, event_type="independent_two")

    first_ts = planner.source_time(first, "source.unprofiled_zero", seed_parts=("same",))
    second_ts = planner.source_time(second, "source.unprofiled_zero", seed_parts=("same",))

    assert first_ts == second_ts


def test_sensor_observation_time_is_stable_by_sensor_and_path() -> None:
    """Per-sensor Zeek timing should be stable but not mechanically identical."""
    planner = SourceTimingPlanner()
    event = SecurityEvent(
        timestamp=_base_time(), event_type="connection", network=_network_context()
    )
    route_key = "10.0.0.20:49152>10.0.0.53:53"

    core_first = planner.sensor_observation_time(
        event, "zeek-core-01", route_key, "source.zeek_conn_start"
    )
    core_second = planner.sensor_observation_time(
        event, "zeek-core-01", route_key, "source.zeek_conn_start"
    )
    dmz = planner.sensor_observation_time(event, "zeek-dmz-01", route_key, "source.zeek_conn_start")

    assert core_first == core_second
    assert dmz != core_first


def test_ecar_dependent_timestamp_follows_process_create(tmp_path: Path) -> None:
    """eCAR dependent records should render after the planned PROCESS/CREATE time."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    proc = _process_context(base)
    process_event = SecurityEvent(
        timestamp=base,
        event_type="process_create",
        src_host=host,
        process=proc,
    )
    dependent_event = SecurityEvent(
        timestamp=base,
        event_type="file_create",
        src_host=host,
        process=proc,
    )

    process_time = emitter._process_create_timestamp(process_event, proc)
    dependent_time = emitter._after_process_create_timestamp(dependent_event, proc)

    assert dependent_time > process_time


def test_ecar_type3_login_uses_upstream_canonical_transport_order(tmp_path: Path) -> None:
    """eCAR preserves bundle-owned transport-before-auth canonical ordering."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    flow_time = base + timedelta(milliseconds=750)
    event = SecurityEvent(
        timestamp=flow_time + timedelta(milliseconds=1),
        event_type="logon",
        dst_host=host,
        auth=AuthContext(
            username="alice",
            logon_id="0xabc",
            logon_type=3,
            source_ip="10.0.0.30",
            source_port=50123,
        ),
    )

    session_time = emitter._session_timestamp(event, host, "login")

    assert session_time > flow_time
    assert session_time <= flow_time + timedelta(milliseconds=100)


def test_ecar_dependent_timestamp_for_long_running_process_uses_event_time(
    tmp_path: Path,
) -> None:
    """Later eCAR dependent rows for long-running processes should not backdate to startup."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    event_time = base + timedelta(minutes=10)
    host = _host_context()
    proc = _process_context(base)
    dependent_event = SecurityEvent(
        timestamp=event_time,
        event_type="registry_modify",
        src_host=host,
        process=proc,
    )

    dependent_time = emitter._after_process_create_timestamp(dependent_event, proc)

    assert event_time <= dependent_time < event_time + timedelta(milliseconds=40)


def test_ecar_process_terminate_preserves_rendered_lifetime(tmp_path: Path) -> None:
    """Canonical source timing preserves visible process lifetime before rendering."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    identity = _process_identity(
        hostname=host.hostname,
        pid=4242,
        parent_pid=888,
        started_at=base,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    proc = _context_from_identity(identity)
    create_event = SecurityEvent(
        timestamp=base,
        event_type="process_create",
        src_host=host,
        process=proc,
        identity_plan=EventIdentityPlan(subject=identity),
    )
    terminate_event = SecurityEvent(
        timestamp=base + timedelta(seconds=6),
        event_type="process_terminate",
        src_host=host,
        process=proc,
        identity_plan=EventIdentityPlan(subject=identity),
    )
    planner = SourceTimingPlanner()
    planner.plan_event(create_event, format_name="ecar")
    planner.plan_event(terminate_event, format_name="ecar")

    process_time = emitter._process_create_timestamp(create_event, identity)
    terminate_time = emitter._process_terminate_timestamp(terminate_event, identity)

    assert terminate_time >= process_time + timedelta(seconds=6)
    assert terminate_time < process_time + timedelta(seconds=12)


def test_ecar_logon_does_not_render_self_sourced_remote_ip(tmp_path: Path) -> None:
    """Endpoint USER_SESSION rows should not publish the host IP as a remote source."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    host = _host_context()
    event = SecurityEvent(
        timestamp=_base_time(),
        event_type="logon",
        dst_host=host,
        auth=AuthContext(
            username="alice",
            logon_id="0x12345",
            logon_type=3,
            source_ip=host.ip,
            source_port=445,
        ),
    )

    emitter.emit(event)
    emitter.close()

    row = json.loads((tmp_path / host.fqdn / "ecar.json").read_text().splitlines()[0])
    assert row["object"] == "USER_SESSION"
    assert row["properties"]["src_ip"] == "-"


def test_ecar_logoff_does_not_render_orphaned_self_sourced_port(tmp_path: Path) -> None:
    """Endpoint LOGOUT rows should not keep a port after suppressing local source IP."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    host = _host_context()
    event = SecurityEvent(
        timestamp=_base_time(),
        event_type="logoff",
        dst_host=host,
        auth=AuthContext(
            username="alice",
            logon_id="0x12345",
            logon_type=3,
            source_ip=host.ip,
            source_port=60456,
        ),
    )

    emitter.emit(event)
    emitter.close()

    row = json.loads((tmp_path / host.fqdn / "ecar.json").read_text().splitlines()[0])
    assert row["object"] == "USER_SESSION"
    assert row["action"] == "LOGOUT"
    assert "src_ip" not in row["properties"]
    assert "src_port" not in row["properties"]


def _remote_auth_timing_events(
    *,
    outcome: str = "success",
) -> tuple[SecurityEvent, SecurityEvent]:
    """Return one correlated target transport and Windows authentication event."""

    start = _base_time()
    auth_time = start + timedelta(milliseconds=350)
    source = _host_context()
    target = HostContext(
        hostname="FILE-SRV-01",
        ip="10.0.0.40",
        fqdn="FILE-SRV-01.corp.local",
        os="Windows Server 2022",
        os_category="windows",
        system_type="server",
        domain="corp.local",
        netbios_domain="CORP",
    )
    transaction_id = "network-connection-remote-auth"
    action_id = "windows-remote-auth-test"
    network = NetworkContext(
        src_ip=source.ip,
        src_port=53123,
        dst_ip=target.ip,
        dst_port=445,
        protocol="tcp",
        service="smb",
        zeek_uid="CremoteAuthTiming",
        conn_id="conn-remote-auth",
        duration=4.0,
        source_visible_start_time=start,
        source_visible_close_time=start + timedelta(seconds=4),
        orig_bytes=1200,
        resp_bytes=2400,
        orig_pkts=4,
        resp_pkts=5,
        orig_ip_bytes=1360,
        resp_ip_bytes=2600,
        conn_state="SF",
        history="ShADadFf",
        local_orig=True,
        local_resp=True,
    )
    network.finalize_transaction(transaction_id)
    transport = RemoteAuthenticationTransportPlan(
        role="target_service",
        transaction_id=transaction_id,
        tuple=NetworkTuple(
            src_ip=source.ip,
            src_port=53123,
            dst_ip=target.ip,
            dst_port=445,
            protocol="tcp",
        ),
        started_at=start,
        closed_at=start + timedelta(seconds=4),
        primary=True,
    )
    remote_auth = RemoteAuthenticationPlan(
        stable_id=action_id,
        source_hostname=source.hostname,
        target_hostname=target.hostname,
        logon_type=3,
        auth_protocol="NTLM",
        outcome=outcome,
        canonical_auth_time=auth_time,
        transports=(transport,),
        session_object_id="session-remote-auth" if outcome == "success" else "",
        logon_id="0x12345" if outcome == "success" else "",
    )
    flow_event = SecurityEvent(
        timestamp=start,
        event_type="connection",
        src_host=source,
        dst_host=target,
        network=network,
        lifecycle=ActionLifecycleContext(
            group_id=transaction_id,
            canonical_start=start,
            phase="start",
            parent_group_id=action_id,
        ),
    )
    auth_event = SecurityEvent(
        timestamp=auth_time,
        event_type="logon" if outcome == "success" else "failed_logon",
        src_host=source,
        dst_host=target,
        auth=AuthContext(
            username="alice",
            logon_id="0x12345" if outcome == "success" else "",
            logon_type=3,
            result=outcome,
            source_ip=source.ip,
            source_port=53123,
        ),
        remote_auth=remote_auth,
    )
    return flow_event, auth_event


def test_remote_auth_ecar_login_follows_admitted_exact_transport() -> None:
    """Dispatcher timing should place eCAR authentication after its exact FLOW."""

    planner = SourceTimingPlanner()
    flow_event, login_event = _remote_auth_timing_events()

    planner.plan_event(flow_event, "ecar")
    planner.record_admitted_source_event(flow_event, "ecar")
    planner.plan_event(login_event, "ecar")

    flow_time = flow_event.source_timing.finalized_times[
        ecar_flow_render_key("inbound", "FILE-SRV-01")
    ]
    login_time = login_event.source_timing.finalized_times[ecar_session_render_key("login")]
    assert timedelta(milliseconds=8) <= login_time - flow_time <= timedelta(milliseconds=140)


def test_remote_auth_failed_ecar_login_follows_transport_without_session() -> None:
    """Failed authentication should order after FLOW without durable session identity."""

    planner = SourceTimingPlanner()
    flow_event, failed_event = _remote_auth_timing_events(outcome="failure")

    planner.plan_event(flow_event, "ecar")
    planner.record_admitted_source_event(flow_event, "ecar")
    planner.plan_event(failed_event, "ecar")

    flow_time = flow_event.source_timing.finalized_times[
        ecar_flow_render_key("inbound", "FILE-SRV-01")
    ]
    failure_time = failed_event.source_timing.finalized_times[
        ecar_session_render_key("failed_login")
    ]
    assert timedelta(milliseconds=8) <= failure_time - flow_time <= timedelta(milliseconds=140)
    assert failed_event.remote_auth.session_object_id == ""
    assert failed_event.remote_auth.logon_id == ""


def test_remote_auth_timing_does_not_correlate_wrong_transaction() -> None:
    """A different transaction in the same action cannot anchor authentication."""

    planner = SourceTimingPlanner()
    flow_event, login_event = _remote_auth_timing_events()
    flow_event.network.transaction = replace(
        flow_event.network.transaction,
        stable_id="network-connection-unrelated",
    )
    flow_event.lifecycle = replace(
        flow_event.lifecycle,
        group_id="network-connection-unrelated",
    )

    planner.plan_event(flow_event, "ecar")
    planner.record_admitted_source_event(flow_event, "ecar")
    planner.plan_event(login_event, "ecar")

    preferred = planner.source_time(
        login_event,
        "source.ecar_session",
        seed_parts=(
            "login",
            "FILE-SRV-01",
            "alice",
            "10.0.0.20",
            53123,
            "0x12345",
            3,
            "",
            login_event.source_timing.canonical_timestamp,
        ),
    )
    assert login_event.source_timing.finalized_times[ecar_session_render_key("login")] == preferred


def test_remote_auth_timing_does_not_correlate_wrong_exact_tuple() -> None:
    """A reused transaction label with a different tuple cannot anchor authentication."""

    planner = SourceTimingPlanner()
    flow_event, login_event = _remote_auth_timing_events()
    flow_event.network.src_port += 1

    planner.plan_event(flow_event, "ecar")
    planner.record_admitted_source_event(flow_event, "ecar")
    planner.plan_event(login_event, "ecar")

    preferred = planner.source_time(
        login_event,
        "source.ecar_session",
        seed_parts=(
            "login",
            "FILE-SRV-01",
            "alice",
            "10.0.0.20",
            53123,
            "0x12345",
            3,
            "",
            login_event.source_timing.canonical_timestamp,
        ),
    )
    assert login_event.source_timing.finalized_times[ecar_session_render_key("login")] == preferred


def test_remote_auth_windows_logon_follows_admitted_target_wfp() -> None:
    """Visible target 5156 should precede the correlated Windows authentication row."""

    planner = SourceTimingPlanner()
    flow_event, login_event = _remote_auth_timing_events()
    target = flow_event.dst_host
    assert target is not None
    transaction_id = flow_event.network.transaction.stable_id
    wfp_event = SecurityEvent(
        timestamp=flow_event.timestamp,
        event_type="wfp_connection",
        src_host=target,
        network=NetworkContext(
            src_ip=flow_event.network.src_ip,
            src_port=flow_event.network.src_port,
            dst_ip=flow_event.network.dst_ip,
            dst_port=flow_event.network.dst_port,
            protocol="tcp",
            initiating_pid=4,
        ),
        lifecycle=ActionLifecycleContext(
            group_id=transaction_id,
            canonical_start=flow_event.timestamp,
            phase="dependent",
            parent_group_id=login_event.remote_auth.stable_id,
        ),
    )

    planned_wfp = planner.plan_event(wfp_event, "windows_event_security")
    planner.record_admitted_source_event(planned_wfp, "windows_event_security")
    planned_login = planner.plan_event(login_event, "windows_event_security")

    wfp_time = wfp_event.source_timing.finalized_times["windows.wfp_connection"]
    assert (
        timedelta(milliseconds=8)
        <= planned_login.timestamp - wfp_time
        <= timedelta(milliseconds=140)
    )
    assert planned_login.source_timing.canonical_timestamp == login_event.timestamp


def test_sysmon_process_access_timestamp_follows_process_create(tmp_path: Path) -> None:
    """Sysmon Event 10 should render after the source process Event 1."""
    output_path = tmp_path / "sysmon.xml"
    emitter = SysmonEventEmitter(load_format("windows_event_sysmon"), output_path, threaded=False)
    base = _base_time()
    host = _host_context()
    proc = _process_context(base)
    auth = AuthContext(username="alice", logon_id=proc.logon_id)
    process_event = SecurityEvent(
        timestamp=base,
        event_type="process_create",
        src_host=host,
        process=proc,
        auth=auth,
    )
    access_event = SecurityEvent(
        timestamp=base,
        event_type="process_access",
        src_host=host,
        process=proc,
        auth=auth,
        process_access=ProcessAccessContext(
            source_pid=proc.pid,
            source_image=proc.image,
            target_pid=640,
            target_image=r"C:\Windows\System32\lsass.exe",
            granted_access="0x1010",
            source_thread_id=9912,
        ),
    )

    emitter.emit(process_event)
    emitter.emit(access_event)
    emitter.close()

    root = ET.fromstring(output_path.read_text())
    ns = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}
    times: dict[int, tuple[str, str]] = {}
    for event_node in root.findall("evt:Event", ns):
        event_id = int(event_node.findtext("evt:System/evt:EventID", namespaces=ns) or "0")
        system_time = event_node.find("evt:System/evt:TimeCreated", ns).attrib["SystemTime"]
        utc_time = ""
        for data in event_node.findall("evt:EventData/evt:Data", ns):
            if data.attrib.get("Name") == "UtcTime":
                utc_time = data.text or ""
                break
        times[event_id] = (system_time, utc_time)

    process_time, process_utc = times[1]
    access_time, access_utc = times[10]
    assert access_time > process_time
    assert access_utc > process_utc


def test_zeek_dns_timestamp_stays_inside_rendered_conn_lifetime(tmp_path: Path) -> None:
    """Zeek analyzer rows should be bounded by the rendered parent conn row."""
    event = SecurityEvent(
        timestamp=_base_time(),
        event_type="connection",
        network=_network_context(duration=0.05),
        dns=DnsContext(
            query="updates.example.com",
            query_type="A",
            response_ip="10.0.0.53",
            answers=["10.0.0.53"],
            TTLs=[60.0],
            rtt=0.02,
        ),
    )
    conn_path = tmp_path / "conn.json"
    dns_path = tmp_path / "dns.json"
    conn_emitter = ZeekEmitter(load_format("zeek_conn"), conn_path, threaded=False)
    dns_emitter = ZeekDnsEmitter(load_format("zeek_dns"), dns_path, threaded=False)

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    conn_row = json.loads(conn_path.read_text().splitlines()[0])
    dns_row = json.loads(dns_path.read_text().splitlines()[0])

    assert conn_row["ts"] <= dns_row["ts"] <= conn_row["ts"] + event.network.duration
    assert dns_row["ts"] + dns_row["rtt"] <= conn_row["ts"] + conn_row["duration"]


def test_zeek_dns_rtt_fits_exact_rendered_conn_lifetime(tmp_path: Path) -> None:
    """DNS query time should leave room for rtt even when duration equals rtt."""
    event = SecurityEvent(
        timestamp=_base_time(),
        event_type="connection",
        network=_network_context(duration=0.02),
        dns=DnsContext(
            query="updates.example.com",
            query_type="A",
            response_ip="10.0.0.53",
            answers=["10.0.0.53"],
            TTLs=[60.0],
            rtt=0.02,
        ),
    )
    conn_path = tmp_path / "conn.json"
    dns_path = tmp_path / "dns.json"
    conn_emitter = ZeekEmitter(load_format("zeek_conn"), conn_path, threaded=False)
    dns_emitter = ZeekDnsEmitter(load_format("zeek_dns"), dns_path, threaded=False)

    conn_emitter.emit(event)
    dns_emitter.emit(event)
    conn_emitter.close()
    dns_emitter.close()

    conn_row = json.loads(conn_path.read_text().splitlines()[0])
    dns_row = json.loads(dns_path.read_text().splitlines()[0])

    assert conn_row["ts"] <= dns_row["ts"]
    assert dns_row["ts"] + dns_row["rtt"] <= conn_row["ts"] + conn_row["duration"]


def test_migrated_emitters_do_not_use_local_timing_helpers() -> None:
    """Guard the first migrated timing surfaces against local jitter regressions."""
    repo_root = Path(__file__).parents[2]
    migrated_files = [
        repo_root / "src/evidenceforge/generation/emitters/ecar.py",
        repo_root / "src/evidenceforge/generation/emitters/zeek_dns.py",
        repo_root / "src/evidenceforge/generation/emitters/zeek_http.py",
        repo_root / "src/evidenceforge/generation/emitters/zeek_ssl.py",
        repo_root / "src/evidenceforge/generation/emitters/zeek_x509.py",
        repo_root / "src/evidenceforge/generation/emitters/zeek_files.py",
    ]
    forbidden = (
        "sample_timing_delta",
        "sample_packet_timing_delta",
        "ssl_analyzer_delay",
        "certificate_analyzer_delay_ms",
        "zeek-file-delay",
        "def _source_offset",
    )

    for path in migrated_files:
        text = path.read_text(encoding="utf-8")
        assert not any(marker in text for marker in forbidden), path

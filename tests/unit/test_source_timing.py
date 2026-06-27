# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for source-aware timing planning."""

import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    HostContext,
    NetworkContext,
    ProcessAccessContext,
    ProcessContext,
)
from evidenceforge.formats import load_format
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.emitters.zeek_dns import ZeekDnsEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner


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


def test_ecar_type3_login_timestamp_follows_matching_inbound_flow(tmp_path: Path) -> None:
    """eCAR type-3 USER_SESSION rows should not visibly precede same-tuple FLOW rows."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    flow_time = base + timedelta(milliseconds=750)
    emitter._remote_inbound_flow_times[(host.hostname, "10.0.0.30", 50123, host.ip, 445)] = (
        flow_time
    )
    event = SecurityEvent(
        timestamp=base,
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
    """eCAR process-create latency should not collapse visible command duration."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    proc = _process_context(base)
    create_event = SecurityEvent(
        timestamp=base,
        event_type="process_create",
        src_host=host,
        process=proc,
    )
    terminate_event = SecurityEvent(
        timestamp=base + timedelta(seconds=6),
        event_type="process_terminate",
        src_host=host,
        process=proc,
    )

    process_time = emitter._process_create_timestamp(create_event, proc)
    terminate_time = emitter._process_terminate_timestamp(terminate_event, proc)

    assert terminate_time >= process_time + timedelta(seconds=6)
    assert terminate_time < process_time + timedelta(seconds=12)


def test_ecar_process_create_normalization_preserves_canonical_order() -> None:
    """eCAR PROCESS/CREATE rows should not invert canonical same-chain process order."""
    first = {
        "timestamp_ms": 1_710_783_739_979,
        "_canonical_ms": 1_710_783_736_520,
        "id": "event-a",
        "hostname": "dc-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "proc-a",
        "actorID": "parent",
        "pid": 6340,
        "ppid": 6200,
    }
    second = {
        "timestamp_ms": 1_710_783_737_093,
        "_canonical_ms": 1_710_783_737_022,
        "id": "event-b",
        "hostname": "dc-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "proc-b",
        "actorID": "parent",
        "pid": 6352,
        "ppid": 6200,
    }

    normalized = EcarEmitter._normalize_process_create_canonical_order(
        [
            json.dumps(first, separators=(",", ":")),
            json.dumps(second, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[1]["timestamp_ms"] > rows[0]["timestamp_ms"]
    assert "_canonical_ms" not in rows[0]
    assert "_canonical_ms" not in rows[1]


def test_ecar_process_create_normalization_does_not_batch_linux_rows() -> None:
    """Linux process-create rows keep their source-native timestamp texture."""
    first = {
        "timestamp_ms": 1_710_783_755_003,
        "_canonical_ms": 1_710_777_592_000,
        "id": "event-sshd-a",
        "hostname": "WEB-EXT-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "proc-sshd-a",
        "actorID": "init-process",
        "pid": 779693,
        "ppid": 500,
        "properties": {"image_path": "/usr/sbin/sshd"},
    }
    second = {
        "timestamp_ms": 1_710_777_613_250,
        "_canonical_ms": 1_710_777_613_000,
        "id": "event-sshd-b",
        "hostname": "WEB-EXT-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "proc-sshd-b",
        "actorID": "init-process",
        "pid": 779701,
        "ppid": 500,
        "properties": {"image_path": "/usr/sbin/sshd"},
    }

    normalized = EcarEmitter._normalize_process_create_canonical_order(
        [
            json.dumps(first, separators=(",", ":")),
            json.dumps(second, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[0]["timestamp_ms"] == first["timestamp_ms"]
    assert rows[1]["timestamp_ms"] == second["timestamp_ms"]
    assert rows[1]["timestamp_ms"] < rows[0]["timestamp_ms"]
    assert "_canonical_ms" not in rows[0]
    assert "_canonical_ms" not in rows[1]


def test_ecar_linux_shell_foreground_order_serializes_visible_commands() -> None:
    """eCAR should not show one shell foreground command starting before the prior exits."""
    editor_create = {
        "timestamp_ms": 1_710_780_154_204,
        "id": "event-editor-create",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "editor-process",
        "actorID": "bash-process",
        "pid": 785286,
        "ppid": 33760,
        "principal": "lina.nguyen",
        "properties": {
            "image_path": "/usr/bin/emacs",
            "command_line": "emacs -nw deploy.sh",
            "parent_image_path": "/bin/bash",
        },
    }
    next_create = {
        "timestamp_ms": 1_710_780_209_982,
        "id": "event-npm-create",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "npm-process",
        "actorID": "bash-process",
        "pid": 785296,
        "ppid": 33760,
        "principal": "lina.nguyen",
        "properties": {
            "image_path": "/usr/bin/npm",
            "command_line": "npm install",
            "parent_image_path": "/bin/bash",
        },
    }
    editor_terminate = {
        "timestamp_ms": 1_710_780_284_534,
        "id": "event-editor-terminate",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "editor-process",
        "pid": 785286,
        "principal": "lina.nguyen",
        "properties": {"image_path": "/usr/bin/emacs"},
    }
    next_terminate = {
        "timestamp_ms": 1_710_780_230_000,
        "id": "event-npm-terminate",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "npm-process",
        "pid": 785296,
        "principal": "lina.nguyen",
        "properties": {"image_path": "/usr/bin/npm"},
    }
    third_create = {
        "timestamp_ms": 1_710_780_235_000,
        "id": "event-vim-create",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "vim-process",
        "actorID": "bash-process",
        "pid": 785297,
        "ppid": 33760,
        "principal": "lina.nguyen",
        "properties": {
            "image_path": "/usr/bin/vim",
            "command_line": "vim config.yaml",
            "parent_image_path": "/bin/bash",
        },
    }
    third_terminate = {
        "timestamp_ms": 1_710_780_245_000,
        "id": "event-vim-terminate",
        "hostname": "WS-LNGUYEN-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "vim-process",
        "pid": 785297,
        "principal": "lina.nguyen",
        "properties": {"image_path": "/usr/bin/vim"},
    }

    normalized = EcarEmitter._normalize_linux_shell_foreground_order(
        [
            json.dumps(editor_create, separators=(",", ":")),
            json.dumps(next_create, separators=(",", ":")),
            json.dumps(editor_terminate, separators=(",", ":")),
            json.dumps(next_terminate, separators=(",", ":")),
            json.dumps(third_create, separators=(",", ":")),
            json.dumps(third_terminate, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[1]["timestamp_ms"] > rows[2]["timestamp_ms"]
    assert rows[3]["timestamp_ms"] > rows[1]["timestamp_ms"]
    assert rows[4]["timestamp_ms"] > rows[3]["timestamp_ms"]
    assert rows[5]["timestamp_ms"] > rows[4]["timestamp_ms"]


def test_ecar_linux_shell_foreground_order_covers_scp_transfer_chain() -> None:
    """eCAR should serialize bounded foreground transfer commands from one shell."""
    gzip_create = {
        "timestamp_ms": 1_710_782_144_698,
        "id": "gzip-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "gzip-process",
        "actorID": "bash-process",
        "pid": 706031,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/gzip",
            "command_line": "gzip -9 /tmp/rpt_0318.sql",
            "parent_image_path": "/bin/bash",
        },
    }
    scp_create = {
        "timestamp_ms": 1_710_782_165_966,
        "id": "scp-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "scp-process",
        "actorID": "bash-process",
        "pid": 706051,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/scp",
            "command_line": "scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/rpt.sql.gz",
            "parent_image_path": "/bin/bash",
        },
    }
    gzip_terminate = {
        "timestamp_ms": 1_710_782_173_346,
        "id": "gzip-terminate",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "gzip-process",
        "pid": 706031,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/gzip"},
    }
    scp_flow = {
        "timestamp_ms": 1_710_782_166_500,
        "id": "scp-flow",
        "hostname": "DB-PROD-01",
        "object": "FLOW",
        "action": "START",
        "objectID": "flow-1",
        "actorID": "scp-process",
        "pid": 706051,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/scp"},
    }
    scp_terminate = {
        "timestamp_ms": 1_710_782_235_832,
        "id": "scp-terminate",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "scp-process",
        "pid": 706051,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/scp"},
    }

    normalized = EcarEmitter._normalize_linux_shell_foreground_order(
        [
            json.dumps(gzip_create, separators=(",", ":")),
            json.dumps(scp_create, separators=(",", ":")),
            json.dumps(gzip_terminate, separators=(",", ":")),
            json.dumps(scp_flow, separators=(",", ":")),
            json.dumps(scp_terminate, separators=(",", ":")),
        ]
    )
    normalized = EcarEmitter._normalize_process_reference_order(normalized)
    rows = [json.loads(line) for line in normalized]

    assert rows[1]["timestamp_ms"] > rows[2]["timestamp_ms"]
    assert rows[3]["timestamp_ms"] > rows[1]["timestamp_ms"]
    assert rows[4]["timestamp_ms"] > rows[3]["timestamp_ms"]


def test_ecar_flow_reference_order_drops_late_process_identity() -> None:
    """FLOW timing stays near the connection when process attribution is too late."""
    process_create = {
        "timestamp_ms": 1_710_789_025_000,
        "id": "ldap-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "ldap-process",
        "actorID": "bash-process",
        "pid": 699858,
        "ppid": 699820,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/ldapsearch"},
    }
    flow = {
        "timestamp_ms": 1_710_780_340_700,
        "id": "ldap-flow",
        "hostname": "DB-PROD-01",
        "object": "FLOW",
        "action": "CONNECT",
        "objectID": "flow-ldap",
        "actorID": "ldap-process",
        "pid": 699858,
        "principal": "root",
        "properties": {
            "src_ip": "10.10.4.10",
            "src_port": "42430",
            "dst_ip": "10.10.2.10",
            "dst_port": "389",
            "protocol": "tcp",
            "direction": "OUTBOUND",
            "image_path": "/usr/bin/ldapsearch",
            "command_line": "ldapsearch -x -H ldap://DC-01",
        },
    }

    normalized = EcarEmitter._normalize_process_reference_order(
        [
            json.dumps(flow, separators=(",", ":")),
            json.dumps(process_create, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[0]["timestamp_ms"] == flow["timestamp_ms"]
    assert "actorID" not in rows[0]
    assert "pid" not in rows[0]
    assert "principal" not in rows[0]
    assert "image_path" not in rows[0]["properties"]
    assert "command_line" not in rows[0]["properties"]


def test_ecar_flow_connect_keeps_network_time_for_close_process_conflict() -> None:
    """FLOW/CONNECT drops actor identity instead of moving outside the tuple interval."""
    process_create = {
        "timestamp_ms": 1_710_789_025_000,
        "id": "docker-create",
        "hostname": "WEB-EXT-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "docker-process",
        "actorID": "bash-process",
        "pid": 771204,
        "ppid": 771190,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/docker"},
    }
    flow = {
        "timestamp_ms": 1_710_789_000_300,
        "id": "proxy-flow",
        "hostname": "WEB-EXT-01",
        "object": "FLOW",
        "action": "CONNECT",
        "objectID": "flow-proxy",
        "actorID": "docker-process",
        "pid": 771204,
        "principal": "root",
        "properties": {
            "src_ip": "10.10.3.15",
            "src_port": "52844",
            "dst_ip": "10.10.3.20",
            "dst_port": "8080",
            "protocol": "tcp",
            "direction": "OUTBOUND",
            "image_path": "/usr/bin/docker",
            "command_line": "docker ps",
            "parent_image_path": "/bin/bash",
        },
    }

    normalized = EcarEmitter._normalize_process_reference_order(
        [
            json.dumps(flow, separators=(",", ":")),
            json.dumps(process_create, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[0]["timestamp_ms"] == flow["timestamp_ms"]
    assert "actorID" not in rows[0]
    assert "pid" not in rows[0]
    assert "principal" not in rows[0]
    assert "image_path" not in rows[0]["properties"]
    assert "command_line" not in rows[0]["properties"]
    assert "parent_image_path" not in rows[0]["properties"]


def test_ecar_linux_shell_foreground_order_serializes_close_unrelated_commands() -> None:
    """Same-shell commands without an explicit pipeline group should not overlap."""
    sleep_create = {
        "timestamp_ms": 1_000_000,
        "id": "sleep-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "sleep-process",
        "actorID": "bash-process",
        "pid": 706031,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/sleep",
            "command_line": "sleep 5",
            "parent_image_path": "/bin/bash",
        },
    }
    whoami_create = {
        "timestamp_ms": 1_000_500,
        "id": "whoami-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "whoami-process",
        "actorID": "bash-process",
        "pid": 706032,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/whoami",
            "command_line": "whoami",
            "parent_image_path": "/bin/bash",
        },
    }
    sleep_terminate = {
        "timestamp_ms": 1_005_000,
        "id": "sleep-terminate",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "sleep-process",
        "pid": 706031,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/sleep"},
    }

    normalized = EcarEmitter._normalize_linux_shell_foreground_order(
        [
            json.dumps(sleep_create, separators=(",", ":")),
            json.dumps(whoami_create, separators=(",", ":")),
            json.dumps(sleep_terminate, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[1]["timestamp_ms"] > rows[2]["timestamp_ms"]


def test_ecar_linux_shell_foreground_order_keeps_pipeline_children_concurrent() -> None:
    """Pipeline children are concurrent shell work, not sequential foreground prompts."""
    cat_create = {
        "timestamp_ms": 1_710_782_144_000,
        "id": "cat-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "cat-process",
        "_concurrency_group_id": "pipeline-1",
        "actorID": "bash-process",
        "pid": 706031,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/cat",
            "command_line": "cat /etc/passwd",
            "parent_image_path": "/bin/bash",
        },
    }
    head_create = {
        "timestamp_ms": 1_710_782_144_035,
        "id": "head-create",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "head-process",
        "_concurrency_group_id": "pipeline-1",
        "actorID": "bash-process",
        "pid": 706032,
        "ppid": 705932,
        "principal": "root",
        "properties": {
            "image_path": "/usr/bin/head",
            "command_line": "head -5",
            "parent_image_path": "/bin/bash",
        },
    }
    cat_terminate = {
        "timestamp_ms": 1_710_782_147_000,
        "id": "cat-terminate",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "cat-process",
        "pid": 706031,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/cat"},
    }
    head_terminate = {
        "timestamp_ms": 1_710_782_146_500,
        "id": "head-terminate",
        "hostname": "DB-PROD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "head-process",
        "pid": 706032,
        "principal": "root",
        "properties": {"image_path": "/usr/bin/head"},
    }

    normalized = EcarEmitter._normalize_linux_shell_foreground_order(
        [
            json.dumps(cat_create, separators=(",", ":")),
            json.dumps(head_create, separators=(",", ":")),
            json.dumps(head_terminate, separators=(",", ":")),
            json.dumps(cat_terminate, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[1]["timestamp_ms"] == head_create["timestamp_ms"]
    assert "_concurrency_group_id" not in rows[0]
    assert "_concurrency_group_id" not in rows[1]
    assert max(rows[0]["timestamp_ms"], rows[1]["timestamp_ms"]) < min(
        rows[2]["timestamp_ms"], rows[3]["timestamp_ms"]
    )


def test_ecar_linux_shell_foreground_order_preserves_pipeline_stage_order() -> None:
    """Tiny source-timing inversions should not put the pipe reader before the writer."""
    find_create = {
        "timestamp_ms": 1_710_780_034_167,
        "id": "find-create",
        "hostname": "WS-OHADDAD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "find-process",
        "actorID": "bash-process",
        "_concurrency_group_id": "pipeline-1",
        "pid": 470150,
        "ppid": 467288,
        "principal": "omar.haddad",
        "properties": {
            "image_path": "/usr/bin/find",
            "command_line": "find . -name *.csv -o -name *.xlsx",
            "parent_image_path": "/bin/bash",
        },
    }
    head_create = {
        "timestamp_ms": 1_710_780_034_152,
        "id": "head-create",
        "hostname": "WS-OHADDAD-01",
        "object": "PROCESS",
        "action": "CREATE",
        "objectID": "head-process",
        "actorID": "bash-process",
        "_concurrency_group_id": "pipeline-1",
        "pid": 470137,
        "ppid": 467288,
        "principal": "omar.haddad",
        "properties": {
            "image_path": "/usr/bin/head",
            "command_line": "head",
            "parent_image_path": "/bin/bash",
        },
    }
    head_terminate = {
        "timestamp_ms": 1_710_780_038_468,
        "id": "head-terminate",
        "hostname": "WS-OHADDAD-01",
        "object": "PROCESS",
        "action": "TERMINATE",
        "objectID": "head-process",
        "pid": 470137,
        "principal": "omar.haddad",
        "properties": {"image_path": "/usr/bin/head"},
    }

    normalized = EcarEmitter._normalize_linux_shell_foreground_order(
        [
            json.dumps(find_create, separators=(",", ":")),
            json.dumps(head_create, separators=(",", ":")),
            json.dumps(head_terminate, separators=(",", ":")),
        ]
    )
    rows = [json.loads(line) for line in normalized]

    assert rows[0]["timestamp_ms"] < rows[1]["timestamp_ms"]
    assert rows[1]["timestamp_ms"] == rows[0]["timestamp_ms"] + 15
    assert rows[2]["timestamp_ms"] > rows[1]["timestamp_ms"]


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

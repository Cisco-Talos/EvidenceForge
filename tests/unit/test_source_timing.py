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
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
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


def test_ecar_process_terminate_preserves_rendered_lifetime(tmp_path: Path) -> None:
    """eCAR process-create latency should not collapse visible command duration."""
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    base = _base_time()
    host = _host_context()
    proc = _process_context(base)
    terminate_event = SecurityEvent(
        timestamp=base + timedelta(seconds=6),
        event_type="process_terminate",
        src_host=host,
        process=proc,
    )

    process_time = emitter._process_create_timestamp(terminate_event, proc)
    terminate_time = emitter._process_terminate_timestamp(terminate_event, proc)

    assert terminate_time >= process_time + timedelta(seconds=6)


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

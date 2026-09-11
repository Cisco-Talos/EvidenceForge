# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused Sysmon terminal source-finalization tests."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    DnsContext,
    HostContext,
    ProcessAccessContext,
    ProcessContext,
)
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters import sysmon as sysmon_module
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    ExactPublicationKey,
    LogEmitter,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.sysmon import (
    SysmonEventEmitter,
    _sysmon_spool_decode,
    _sysmon_spool_encode,
    _SysmonExactCandidateParticipant,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.source_finalization import (
    ExactChunkPublisher,
    SourceFinalizationCoordinator,
    SourceFinalizationError,
)
from evidenceforge.models import (
    BaselineActivity,
    Environment,
    OutputSpec,
    Scenario,
    System,
    TimeWindow,
    User,
)
from evidenceforge.output_targets import OutputTarget
from tests.network_factories import network_plan

pytestmark = pytest.mark.slow

HOST = "WIN-TEST-01.corp.local"
BASE_TIME = datetime(2024, 1, 15, 10, 30, tzinfo=UTC)


def _format_utc(timestamp: datetime) -> str:
    return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")


def _file_event(
    timestamp: datetime,
    label: str,
    *,
    computer: str = HOST,
) -> dict[str, object]:
    return {
        "EventID": 11,
        "TimeCreated": timestamp,
        "Computer": computer,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "ExecutionProcessID": 2480,
        "ExecutionThreadID": 1844,
        "UtcTime": _format_utc(timestamp),
        "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
        "ProcessId": 4200,
        "Image": rf"C:\Windows\System32\{label}.exe",
        "TargetFilename": rf"C:\Windows\Temp\{label}.tmp",
        "CreationUtcTime": _format_utc(timestamp),
        "User": r"CORP\analyst",
    }


def _process_event(
    timestamp: datetime,
    label: str,
    *,
    process_guid: str,
    parent_guid: str = "{00000000-0000-0000-0000-000000000000}",
    pid: int,
    parent_pid: int = 4,
) -> dict[str, object]:
    return {
        "EventID": 1,
        "TimeCreated": timestamp,
        "Computer": HOST,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "ExecutionProcessID": 2480,
        "ExecutionThreadID": 1844,
        "UtcTime": _format_utc(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": rf"C:\Windows\System32\{label}.exe",
        "CommandLine": f"{label}.exe",
        "User": r"CORP\analyst",
        "ParentProcessGuid": parent_guid,
        "ParentProcessId": parent_pid,
        "ParentImage": r"C:\Windows\System32\services.exe",
        "ParentCommandLine": "services.exe",
    }


def _security_event(timestamp: datetime, username: str) -> dict[str, object]:
    return {
        "EventID": 4624,
        "TimeCreated": timestamp,
        "Computer": HOST,
        "Channel": "Security",
        "Level": 0,
        "ExecutionProcessID": 4,
        "ExecutionThreadID": 100,
        "TargetUserName": username,
        "TargetDomainName": "CORP",
        "TargetLogonId": f"0x{timestamp.second:06x}",
        "LogonType": 2,
        "WorkstationName": "WIN-TEST-01",
        "IpAddress": "192.168.1.100",
        "LogonProcessName": "User32",
        "AuthenticationPackageName": "Negotiate",
    }


def _connection_event(timestamp: datetime, label: str) -> dict[str, object]:
    return {
        "EventID": 3,
        "TimeCreated": timestamp,
        "Computer": HOST,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "ExecutionProcessID": 2480,
        "ExecutionThreadID": 1844,
        "UtcTime": _format_utc(timestamp),
        "ProcessGuid": "{33333333-3333-3333-3333-333333333333}",
        "ProcessId": 4200,
        "Image": r"C:\Windows\System32\OpenSSH\ssh.exe",
        "User": r"CORP\analyst",
        "Protocol": "tcp",
        "Initiated": "true",
        "SourceIsIpv6": "false",
        "SourceIp": "10.0.0.10",
        "SourceHostname": HOST,
        "SourcePort": 49152,
        "SourcePortName": "-",
        "DestinationIsIpv6": "false",
        "DestinationIp": "10.0.0.20",
        "DestinationHostname": f"{label}.corp.local",
        "DestinationPort": 22,
        "DestinationPortName": "ssh",
    }


def _canonical_host() -> HostContext:
    """Build the stable Windows host shared by canonical Sysmon retry probes."""

    return HostContext(
        hostname="WIN-TEST-01",
        ip="10.0.1.10",
        os="Windows 10",
        os_category="windows",
        system_type="workstation",
        domain="corp.local",
        fqdn=HOST,
        netbios_domain="CORP",
    )


def _canonical_connection_event() -> OccurrenceBuilder:
    """Build one canonical Event 3 input with stable process/network ownership."""

    return OccurrenceBuilder(
        timestamp=BASE_TIME,
        event_type="connection",
        src_host=_canonical_host(),
        process=ProcessContext(
            pid=4567,
            parent_pid=1,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd",
            username="admin",
        ),
        auth=AuthContext(username="admin"),
        network=network_plan(
            src_ip="10.0.1.10",
            dst_ip="10.0.2.20",
            src_port=49152,
            dst_port=4444,
            protocol="tcp",
        ),
    )


def _canonical_filtered_connection_event() -> OccurrenceBuilder:
    """Build one canonical connection excluded by the default Event 3 filter."""

    return OccurrenceBuilder(
        timestamp=BASE_TIME,
        event_type="connection",
        src_host=_canonical_host(),
        process=ProcessContext(
            pid=4567,
            parent_pid=1,
            image=r"C:\Windows\System32\notepad.exe",
            command_line="notepad",
            username="admin",
        ),
        auth=AuthContext(username="admin"),
        network=network_plan(
            src_ip="10.0.1.10",
            dst_ip="10.0.2.20",
            src_port=49152,
            dst_port=443,
            protocol="tcp",
        ),
    )


def _canonical_process_create_event(*, session_id: int) -> OccurrenceBuilder:
    """Build one canonical Event 1 input with a stable logon/session key."""

    return OccurrenceBuilder(
        timestamp=BASE_TIME,
        event_type="process_create",
        src_host=_canonical_host(),
        process=ProcessContext(
            pid=1234,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd",
            username="admin",
            start_time=BASE_TIME - timedelta(minutes=1),
            parent_image=r"C:\Windows\System32\services.exe",
        ),
        auth=AuthContext(
            username="admin",
            logon_id="0x123",
            session_id=session_id,
        ),
    )


def _canonical_process_access_event() -> OccurrenceBuilder:
    """Build one canonical Event 10 input that uses fallback CallTrace allocation."""

    return OccurrenceBuilder(
        timestamp=BASE_TIME,
        event_type="process_access",
        src_host=_canonical_host(),
        auth=AuthContext(username="admin", logon_id="0x123"),
        process=ProcessContext(
            pid=4002,
            parent_pid=3000,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd",
            username="admin",
            start_time=BASE_TIME - timedelta(minutes=1),
        ),
        process_access=ProcessAccessContext(
            source_pid=4002,
            source_image=r"C:\Windows\System32\cmd.exe",
            source_thread_id=4200,
            target_pid=500,
            target_image=r"C:\Windows\System32\lsass.exe",
            target_user="SYSTEM",
            granted_access="0x1010",
            call_trace="",
        ),
    )


def _canonical_dns_event() -> OccurrenceBuilder:
    """Build one canonical Event 22 input that uses the DNS-client PID fallback."""

    return OccurrenceBuilder(
        timestamp=BASE_TIME,
        event_type="connection",
        src_host=_canonical_host(),
        network=network_plan(
            src_ip="10.0.1.10",
            dst_ip="10.0.1.53",
            src_port=49152,
            dst_port=53,
            protocol="udp",
            application_layer_only=True,
        ),
        dns=DnsContext(
            query="retry.example.com",
            response_ip="10.0.2.20",
            answers=["10.0.2.20"],
        ),
    )


def _termination_event(
    timestamp: datetime,
    label: str,
    *,
    process_guid: str,
    pid: int,
) -> dict[str, object]:
    return {
        "EventID": 5,
        "TimeCreated": timestamp,
        "Computer": HOST,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Level": 4,
        "ExecutionProcessID": 2480,
        "ExecutionThreadID": 1844,
        "UtcTime": _format_utc(timestamp),
        "ProcessGuid": process_guid,
        "ProcessId": pid,
        "Image": rf"C:\Windows\System32\{label}.exe",
        "User": r"CORP\analyst",
    }


def _authority() -> ExactPublicationAuthority:
    return ExactPublicationAuthority(
        capacity=1,
        row_capacity=512,
        byte_capacity=20 * 1024 * 1024,
    )


def _scenario(*formats: str) -> Scenario:
    return Scenario(
        version="1.0",
        name="sysmon-source-finalization",
        description="Focused terminal source test",
        environment=Environment(
            description="One Windows host",
            users=[
                User(
                    username="testuser",
                    full_name="Test User",
                    email="test@example.com",
                    enabled=True,
                    primary_system="WIN-TEST-01",
                )
            ],
            systems=[
                System(
                    hostname="WIN-TEST-01",
                    ip="10.0.0.1",
                    os="Windows 11",
                    type="workstation",
                )
            ],
        ),
        time_window=TimeWindow(start="2024-01-15T10:00:00Z", duration="1h"),
        baseline_activity=BaselineActivity(
            description="Focused baseline",
            intensity="low",
            variation="low",
        ),
        output=OutputSpec(
            logs=[{"format": format_name} for format_name in formats],
            destination="./output",
            compression=False,
        ),
        personas=[],
    )


def _finalize(emitter: SysmonEventEmitter) -> SourceFinalizationCoordinator:
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()
    return coordinator


def _output_path(root: Path, target: OutputTarget = OutputTarget.DEFAULT) -> Path:
    if target == OutputTarget.SOF_ELK:
        return root / HOST / "2024" / "windows_event_sysmon_snare.log"
    return root / HOST / "windows_event_sysmon.xml"


def test_sysmon_terminal_seal_sorts_late_earlier_row_and_defers_public_output(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=20), "later"))
    emitter.barrier_flush()
    assert not output_root.exists()
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=10), "earlier"))

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    content = _output_path(output_root).read_text(encoding="utf-8")
    assert content.index("earlier.tmp") < content.index("later.tmp")
    assert "</Events>" not in content
    assert coordinator.publisher.census().active_child == 0

    emitter.close()
    coordinator.mark_closed()
    assert _output_path(output_root).read_text(encoding="utf-8").count("</Events>") == 1
    assert emitter.source_finalization_census().state == "closed"
    assert not list(tmp_path.glob("**/.sysmon_event_spool_*.sqlite3"))


@pytest.mark.parametrize(
    ("target", "filename", "expected_digest"),
    [
        (
            OutputTarget.DEFAULT,
            "windows_event_sysmon.xml",
            "45c1580a9b8fd001df4a77eb4560cedade650620c6aa261dd240d80c656f39b2",
        ),
        (
            OutputTarget.SPLUNK,
            "windows_event_sysmon.xml",
            "f34680ab94b5c34bb8af51e8efedac556b1a8214566ad912afbd2b9aaf32478e",
        ),
        (
            OutputTarget.SOF_ELK,
            "windows_event_sysmon_snare.log",
            "30182c0082491dcfe200b4e537f5da3ac8504a4230399959330422cad481c197",
        ),
    ],
)
def test_sysmon_exact_and_direct_bytes_match_parent_behavior(
    tmp_path: Path,
    target: OutputTarget,
    filename: str,
    expected_digest: str,
) -> None:
    events = [
        _file_event(BASE_TIME + timedelta(seconds=10), "earlier"),
        _file_event(BASE_TIME + timedelta(seconds=20), "later"),
    ]
    direct_path = tmp_path / "direct" / "sysmon.xml"
    direct = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        direct_path,
        buffer_size=100,
    )
    direct.configure_output_target(target)
    for event in events:
        direct.emit_event(event)
    direct.close()
    direct_output = (
        direct_path.with_name(filename) if target == OutputTarget.SOF_ELK else direct_path
    )

    exact_root = tmp_path / "exact"
    exact = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        exact_root,
        buffer_size=1,
        source_finalization=True,
    )
    exact.configure_output_target(target)
    for event in events:
        exact.emit_event(event)
    _finalize(exact)
    exact_output = next(exact_root.rglob(filename))

    exact_bytes = exact_output.read_bytes()
    assert exact_bytes == direct_output.read_bytes()
    assert hashlib.sha256(exact_bytes).hexdigest() == expected_digest


@pytest.mark.parametrize(
    ("threaded", "buffer_size"),
    [(False, 1), (False, 100), (True, 1), (True, 100)],
)
def test_sysmon_exact_bytes_are_thread_and_buffer_invariant(
    tmp_path: Path,
    threaded: bool,
    buffer_size: int,
) -> None:
    output_root = tmp_path / f"output-{threaded}-{buffer_size}"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=buffer_size,
        threaded=threaded,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=20), "later"))
    emitter.barrier_flush()
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=10), "earlier"))
    _finalize(emitter)

    digest = hashlib.sha256(_output_path(output_root).read_bytes()).hexdigest()
    assert digest == "45c1580a9b8fd001df4a77eb4560cedade650620c6aa261dd240d80c656f39b2"


def test_sysmon_compatibility_shift_crossing_timestamp_freezes_updated_order(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
    )
    parent_guid = "{11111111-1111-1111-1111-111111111111}"
    child_guid = "{22222222-2222-2222-2222-222222222222}"
    emitter.emit_event(
        _process_event(
            BASE_TIME + timedelta(seconds=5),
            "child",
            process_guid=child_guid,
            parent_guid=parent_guid,
            pid=4201,
            parent_pid=4200,
        )
    )
    unrelated = _file_event(BASE_TIME + timedelta(seconds=8), "unrelated")
    unrelated["ProcessGuid"] = "{33333333-3333-3333-3333-333333333333}"
    emitter.emit_event(unrelated)
    emitter.emit_event(
        _process_event(
            BASE_TIME + timedelta(seconds=10),
            "parent",
            process_guid=parent_guid,
            pid=4200,
        )
    )
    _finalize(emitter)

    content = _output_path(output_root).read_text(encoding="utf-8")
    assert content.index("unrelated.tmp") < content.index("parent.exe") < content.index("child.exe")


def test_sysmon_exact_seal_never_reenters_the_legacy_python_sort(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    emitter.quiesce_source_finalization()

    def reject_second_sort(_all_finalized: bool) -> None:
        raise AssertionError("SQLite-frozen exact order was sorted again")

    monkeypatch.setattr(
        emitter,
        "_freeze_event_order_and_assign_ids_unlocked",
        reject_second_sort,
    )
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


def test_sysmon_offset_aware_candidate_round_trip_matches_direct_bytes(tmp_path: Path) -> None:
    offset_time = BASE_TIME.astimezone(timezone(timedelta(hours=5, minutes=30)))
    event = _file_event(offset_time, "offset-aware")

    direct_path = tmp_path / "direct.xml"
    direct = SysmonEventEmitter(load_format("windows_event_sysmon"), direct_path)
    direct.emit_event(event)
    direct.close()

    exact_root = tmp_path / "exact"
    exact = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        exact_root,
        buffer_size=1,
        source_finalization=True,
    )
    exact.emit_event(event)
    _finalize(exact)

    exact_bytes = _output_path(exact_root).read_bytes()
    assert exact_bytes == direct_path.read_bytes()
    assert b"2024-01-15 10:30" in exact_bytes


def test_sysmon_exact_compatibility_cohort_matches_time_guid_and_termination_bytes(
    tmp_path: Path,
) -> None:
    process_guid = "{44444444-4444-4444-4444-444444444444}"
    create = _process_event(
        BASE_TIME + timedelta(seconds=10),
        "owned-process",
        process_guid=process_guid,
        pid=4300,
    )
    followon = _file_event(BASE_TIME + timedelta(seconds=5), "owned-followon")
    followon.update(
        {
            "ProcessGuid": process_guid,
            "ProcessId": 4300,
            "Image": r"C:\Windows\System32\owned-process.exe",
        }
    )
    termination = _termination_event(
        BASE_TIME + timedelta(seconds=6),
        "owned-process",
        process_guid=process_guid,
        pid=4300,
    )
    events = (termination, followon, create)

    direct_root = tmp_path / "direct"
    direct = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        direct_root,
        buffer_size=100,
    )
    for event in events:
        direct.emit_event(event)
    direct.close()

    exact_root = tmp_path / "exact"
    exact = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        exact_root,
        buffer_size=1,
        source_finalization=True,
    )
    for event in events:
        exact.emit_event(event)
    _finalize(exact)

    direct_bytes = _output_path(direct_root).read_bytes()
    exact_bytes = _output_path(exact_root).read_bytes()
    assert exact_bytes == direct_bytes
    content = exact_bytes.decode("utf-8")
    event_ids = re.findall(r"<EventID>(\d+)</EventID>", content)
    assert event_ids == ["1", "11", "5"]
    process_guids = re.findall(r'<Data Name="ProcessGuid">([^<]+)</Data>', content)
    assert len(process_guids) == 3 and len(set(process_guids)) == 1
    time_created = re.findall(r'<TimeCreated SystemTime="([^"]+)"/>', content)
    utc_times = re.findall(r'<Data Name="UtcTime">([^<]+)</Data>', content)
    assert time_created == sorted(time_created)
    assert utc_times == sorted(utc_times)
    creation_time = re.search(r'<Data Name="CreationUtcTime">([^<]+)</Data>', content)
    assert creation_time is not None and creation_time.group(1) == utc_times[1]


def test_sysmon_equal_time_multihost_rows_keep_global_insertion_and_per_host_ids(
    tmp_path: Path,
) -> None:
    second_host = "WIN-TEST-02.corp.local"
    events = (
        _file_event(BASE_TIME, "first-host-two", computer=second_host),
        _file_event(BASE_TIME, "host-one", computer=HOST),
        _file_event(BASE_TIME, "second-host-two", computer=second_host),
    )
    for event in events:
        event["_TimingFinalized"] = sysmon_module._FROZEN_TIMING_MARKER
    direct_root = tmp_path / "direct"
    direct = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        direct_root,
        buffer_size=100,
    )
    for event in events:
        direct.emit_event(event)
    direct.close()

    exact_root = tmp_path / "exact"
    exact = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        exact_root,
        buffer_size=1,
        source_finalization=True,
    )
    for event in events:
        exact.emit_event(event)
    exact.quiesce_source_finalization()
    epoch = exact.seal_source_finalization()
    with exact._file_lock:
        sealed_rows = exact._spool_conn.execute(
            "SELECT ordinal, route_key, payload FROM events WHERE phase = ? ORDER BY ordinal",
            ("final",),
        ).fetchall()
    assert [ordinal for ordinal, _route, _payload in sealed_rows] == [0, 1, 2]
    assert "first-host-two.tmp" in sealed_rows[0][2]
    assert "host-one.tmp" in sealed_rows[1][2]
    assert "second-host-two.tmp" in sealed_rows[2][2]

    exact.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    exact.close()
    assert (exact_root / HOST / "windows_event_sysmon.xml").read_bytes() == (
        direct_root / HOST / "windows_event_sysmon.xml"
    ).read_bytes()
    exact_host_two = (exact_root / second_host / "windows_event_sysmon.xml").read_bytes()
    assert exact_host_two == (direct_root / second_host / "windows_event_sysmon.xml").read_bytes()
    record_ids = re.findall(rb"<EventRecordID>(\d+)</EventRecordID>", exact_host_two)
    assert len(record_ids) == 2 and int(record_ids[1]) == int(record_ids[0]) + 1


def test_sysmon_exact_admission_detaches_nested_payload_and_typed_timing_marker(
    tmp_path: Path,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
    )
    event = _file_event(BASE_TIME, "detached")
    event["NestedProbe"] = {"members": ["original"]}
    event["_TimingFinalized"] = sysmon_module._FROZEN_TIMING_MARKER
    expected_bytes = len(_sysmon_spool_encode(event).encode("utf-8"))
    emitter.emit_event(event)
    event["NestedProbe"]["members"][0] = "mutated"
    emitter.quiesce_source_finalization()

    with emitter._file_lock:
        retained = emitter._load_candidate_rows_unlocked()
    assert retained[0][1]["NestedProbe"] == {"members": ["original"]}
    assert retained[0][1]["_TimingFinalized"] is sysmon_module._FROZEN_TIMING_MARKER
    assert emitter.source_finalization_census().candidate_bytes == expected_bytes

    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


@pytest.mark.parametrize(
    ("method_name", "phase_name"),
    [
        ("_assign_normalized_times_and_record_ids_unlocked", "normalization"),
        ("_synchronize_event_cohort_unlocked", "synchronization"),
    ],
)
def test_sysmon_intermediate_payload_growth_is_failure_neutral(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    phase_name: str,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    emitter.quiesce_source_finalization()
    with emitter._file_lock:
        before_state = emitter._journal_state_unlocked()
        before_payload = emitter._spool_conn.execute(
            "SELECT sort_key, payload, payload_bytes FROM events WHERE phase = ?",
            ("candidate",),
        ).fetchone()
    original_capacity = emitter._finalization_byte_capacity
    emitter._finalization_byte_capacity = int(before_state[2]) + 1024
    original_method = getattr(emitter, method_name)

    def grow_payload(*args: object, **kwargs: object) -> None:
        original_method(*args, **kwargs)
        emitter._event_dicts[0]["_CapacityProbe"] = "x" * 4096

    monkeypatch.setattr(emitter, method_name, grow_payload)
    with pytest.raises(SourceFinalizationError, match=rf"{phase_name}.*byte capacity"):
        emitter.seal_source_finalization()

    with emitter._file_lock:
        after_state = emitter._journal_state_unlocked()
        after_payload = emitter._spool_conn.execute(
            "SELECT sort_key, payload, payload_bytes FROM events WHERE phase = ?",
            ("candidate",),
        ).fetchone()
    assert after_state == before_state
    assert after_payload == before_payload
    assert emitter._record_id_sequences == {}
    assert emitter._last_time_created_by_computer == {}
    assert emitter._time_collision_count_by_computer == {}
    assert emitter._final_process_guids == {}
    assert emitter._host_writers == {}
    assert emitter._snare_writers == {}
    assert not output_root.exists()

    monkeypatch.setattr(emitter, method_name, original_method)
    emitter._finalization_byte_capacity = original_capacity
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()
    assert _output_path(output_root).read_text(encoding="utf-8").count("once.tmp") == 1


def test_sysmon_final_render_growth_rolls_back_candidate_and_writer_maps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    emitter.quiesce_source_finalization()
    with emitter._file_lock:
        before_state = emitter._journal_state_unlocked()
        before_payload = emitter._spool_conn.execute(
            "SELECT sort_key, payload, payload_bytes FROM events WHERE phase = ?",
            ("candidate",),
        ).fetchone()
    original_capacity = emitter._finalization_byte_capacity
    emitter._finalization_byte_capacity = int(before_state[2]) + 2048
    original_finalize = emitter._finalize_event_for_output

    def grow_render(
        event: dict[str, object],
    ) -> tuple[str, str, _SingleHostWriter, str] | None:
        final = original_finalize(event)
        if final is None:
            return None
        return final[0], final[1], final[2], final[3] + ("x" * 4096)

    monkeypatch.setattr(emitter, "_finalize_event_for_output", grow_render)
    with pytest.raises(SourceFinalizationError, match="finalization byte capacity"):
        emitter.seal_source_finalization()

    with emitter._file_lock:
        after_state = emitter._journal_state_unlocked()
        after_payload = emitter._spool_conn.execute(
            "SELECT sort_key, payload, payload_bytes FROM events WHERE phase = ?",
            ("candidate",),
        ).fetchone()
    assert after_state == before_state
    assert after_payload == before_payload
    assert emitter._host_writers == {}
    assert emitter._snare_writers == {}
    assert emitter._source_finalization_routes == {}
    assert emitter._source_finalization_route_ids == {}
    assert not output_root.exists()

    monkeypatch.setattr(emitter, "_finalize_event_for_output", original_finalize)
    emitter._finalization_byte_capacity = original_capacity
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


def test_sysmon_nonthreaded_spool_failure_rolls_back_current_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=2,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "retained"))
    original_spool = emitter._spool_event_dicts_unlocked

    def fail_spool() -> None:
        raise OSError("spool failed before durable adoption")

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", fail_spool)
    before = emitter.source_finalization_census()
    with pytest.raises(OSError, match="spool failed"):
        emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=1), "rejected"))
    after = emitter.source_finalization_census()
    assert (after.candidate_rows, after.candidate_bytes) == (
        before.candidate_rows,
        before.candidate_bytes,
    )
    assert [event["TargetFilename"] for event in emitter._event_dicts] == [
        r"C:\Windows\Temp\retained.tmp"
    ]

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", original_spool)
    _finalize(emitter)
    content = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert "retained.tmp" in content
    assert "rejected.tmp" not in content


def test_sysmon_seal_and_checkpoint_lost_returns_reconcile_without_duplicate_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    emitter.quiesce_source_finalization()
    original_commit = emitter._commit_journal_unlocked
    seal_return_lost = True
    checkpoint_return_lost = True

    def commit_then_raise() -> None:
        nonlocal seal_return_lost, checkpoint_return_lost
        original_commit()
        state = emitter._journal_state_unlocked()
        if state[0] == "sealed" and state[6] == 0 and seal_return_lost:
            seal_return_lost = False
            raise RuntimeError("seal commit return lost")
        if state[0] == "sealed" and state[6] > 0 and checkpoint_return_lost:
            checkpoint_return_lost = False
            raise RuntimeError("checkpoint commit return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", commit_then_raise)
    epoch = emitter.seal_source_finalization()
    assert emitter.seal_source_finalization() is epoch
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()

    content = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert content.count("once.tmp") == 1
    assert not seal_return_lost
    assert not checkpoint_return_lost


def test_sysmon_cross_thread_publish_retry_and_concurrent_owner_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    emitter.quiesce_source_finalization()
    epoch = emitter.seal_source_finalization()
    publisher = ExactChunkPublisher(_authority())
    original_commit = ExactPublicationBatch.commit
    commit_entered = Event()
    release_commit = Event()
    lost_return = True

    def commit_then_raise(batch: ExactPublicationBatch) -> object:
        nonlocal lost_return
        result = original_commit(batch)
        commit_entered.set()
        if not release_commit.wait(timeout=5):
            raise AssertionError("commit release timed out")
        if lost_return:
            lost_return = False
            raise RuntimeError("cross-thread commit return lost")
        return result

    monkeypatch.setattr(ExactPublicationBatch, "commit", commit_then_raise)
    errors: list[BaseException] = []

    def first_publish() -> None:
        try:
            emitter.publish_source_finalization(epoch, publisher)
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=first_publish)
    worker.start()
    assert commit_entered.wait(timeout=5)
    with pytest.raises(SourceFinalizationError, match="active owner operation"):
        emitter.publish_source_finalization(epoch, publisher)
    release_commit.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(errors) == 1 and "cross-thread commit return lost" in str(errors[0])

    emitter.publish_source_finalization(epoch, publisher)
    emitter.close()
    assert _output_path(tmp_path / "output").read_text(encoding="utf-8").count("once.tmp") == 1
    assert publisher.census().active_child == 0


def test_sysmon_quiesce_fences_late_input_barrier_and_close(tmp_path: Path) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "first"))
    emitter.quiesce_source_finalization()

    with pytest.raises(RuntimeError, match="closing or closed"):
        emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=1), "late"))
    with pytest.raises(SourceFinalizationError, match="barrier after quiescence"):
        emitter.barrier_flush()
    with pytest.raises(SourceFinalizationError, match="unpublished sealed cohort"):
        emitter.close()

    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()


def test_sysmon_footer_lost_return_retries_once_and_cleans_private_spool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    original_footer = _SingleHostWriter.write_footer
    lost_return = True

    def footer_then_raise(writer: _SingleHostWriter, footer: str) -> None:
        nonlocal lost_return
        original_footer(writer, footer)
        if lost_return:
            lost_return = False
            raise RuntimeError("footer return lost")

    monkeypatch.setattr(_SingleHostWriter, "write_footer", footer_then_raise)
    with pytest.raises(RuntimeError, match="footer return lost"):
        emitter.close()
    emitter.close()
    coordinator.mark_closed()

    content = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert content.count("once.tmp") == 1
    assert content.count("</Events>") == 1
    assert emitter.source_finalization_census().state == "closed"
    assert not list(tmp_path.glob("**/.sysmon_event_spool_*.sqlite3"))


def test_sysmon_exact_validation_finishes_before_thread_super_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    super_called = False

    def forbidden_super(*args: object, **kwargs: object) -> None:
        nonlocal super_called
        super_called = True
        raise AssertionError("thread-capable super constructor ran")

    monkeypatch.setattr(LogEmitter, "__init__", forbidden_super)
    with pytest.raises(ValueError, match="positive exact int"):
        SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "output",
            threaded=True,
            source_finalization=True,
            finalization_row_capacity=True,
        )
    assert not super_called

    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(tmp_path / "output"))
    with pytest.raises(ExactPublicationError, match="outside public output"):
        SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "output",
            threaded=True,
            source_finalization=True,
        )
    assert not super_called

    monkeypatch.delenv("EFORGE_SPOOL_DIR")

    def refuse_capability() -> None:
        raise ExactPublicationError("capability refused before worker start")

    monkeypatch.setattr(
        sysmon_module,
        "_require_windows_source_finalization_capabilities",
        refuse_capability,
    )
    with pytest.raises(ExactPublicationError, match="capability refused"):
        SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "output",
            threaded=True,
            source_finalization=True,
        )
    assert not super_called


@pytest.mark.parametrize("capacity_delta", [-1, 0, 1])
def test_sysmon_candidate_utf8_byte_admission_boundary_is_exact_and_neutral(
    tmp_path: Path,
    capacity_delta: int,
) -> None:
    event = _file_event(BASE_TIME, "boundary-é")
    probe = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "probe-output",
        buffer_size=100,
        source_finalization=True,
    )
    probe.emit_event(event)
    exact_bytes = probe.source_finalization_census().candidate_bytes
    probe.close()
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
        finalization_byte_capacity=exact_bytes + capacity_delta,
    )

    if capacity_delta < 0:
        with pytest.raises(SourceFinalizationError, match="byte capacity"):
            emitter.emit_event(event)
        expected = (0, 0)
    else:
        emitter.emit_event(event)
        expected = (1, exact_bytes)
        with pytest.raises(SourceFinalizationError, match="byte capacity"):
            emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=1), "extra"))

    census = emitter.source_finalization_census()
    assert (census.candidate_rows, census.candidate_bytes) == expected
    assert (census.high_water_rows, census.high_water_bytes) == expected
    emitter.close()


def test_sysmon_candidate_commit_lost_return_adopts_rows_and_scalar_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=100,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))
    original_commit = emitter._commit_journal_unlocked
    lost_return = True

    def commit_then_raise() -> None:
        nonlocal lost_return
        original_commit()
        state = emitter._journal_state_unlocked()
        if state[0] == "candidate" and state[1] == 1 and lost_return:
            lost_return = False
            raise RuntimeError("candidate commit return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", commit_then_raise)
    emitter.quiesce_source_finalization()
    assert not lost_return
    assert emitter._spool_sequence == 1
    assert emitter._event_dicts == []

    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()
    assert _output_path(tmp_path / "output").read_text(encoding="utf-8").count("once.tmp") == 1


def test_sysmon_route_cap_rolls_back_strings_writers_and_retry_state(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
        finalization_route_capacity=1,
    )
    emitter.emit_event(_file_event(BASE_TIME, "first", computer=HOST))
    emitter.emit_event(
        _file_event(
            BASE_TIME + timedelta(seconds=1),
            "second",
            computer="WIN-TEST-02.corp.local",
        )
    )
    emitter.quiesce_source_finalization()
    with pytest.raises(SourceFinalizationError, match="route capacity"):
        emitter.seal_source_finalization()

    with emitter._file_lock:
        state = emitter._journal_state_unlocked()
        final_rows = emitter._spool_conn.execute(
            "SELECT COUNT(*) FROM events WHERE phase = ?",
            ("final",),
        ).fetchone()
    assert state[0] == "candidate"
    assert final_rows == (0,)
    assert emitter._host_writers == {}
    assert emitter._source_finalization_routes == {}
    assert emitter._source_finalization_route_ids == {}
    assert not output_root.exists()

    emitter._finalization_route_capacity = 2
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()
    assert len(list(output_root.rglob("windows_event_sysmon.xml"))) == 2


@pytest.mark.parametrize("missing_host", [False, True])
def test_sysmon_empty_or_unrouted_cohort_has_no_public_output(
    tmp_path: Path,
    missing_host: bool,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    if missing_host:
        emitter.emit_event(_file_event(BASE_TIME, "unrouted", computer=""))
    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    coordinator.finalize()
    assert emitter.source_finalization_census().final_rows == 0
    assert not output_root.exists()
    emitter.close()
    coordinator.mark_closed()
    assert coordinator.complete


def test_sysmon_multi_chunk_publication_is_bounded_and_releases_authority(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=50,
        source_finalization=True,
    )
    for index in range(513):
        emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=index), f"row-{index}"))
    authority = _authority()
    coordinator = SourceFinalizationCoordinator((emitter,), authority)
    coordinator.finalize()
    publisher_census = coordinator.publisher.census()
    authority_census = authority.census()

    assert publisher_census.active_child == 0
    assert publisher_census.high_water_rows == 512
    assert publisher_census.high_water_bytes <= publisher_census.byte_capacity
    assert publisher_census.high_water_routes <= publisher_census.route_capacity
    assert authority_census.high_water_batches == 1
    assert (
        authority_census.active_batches,
        authority_census.prepared_batches,
        authority_census.retained_rows,
        authority_census.retained_bytes,
    ) == (0, 0, 0, 0)

    emitter.close()
    coordinator.mark_closed()
    census = emitter.source_finalization_census()
    assert (
        census.candidate_rows,
        census.candidate_bytes,
        census.final_rows,
        census.final_bytes,
        census.routes,
        census.published_rows,
    ) == (0, 0, 0, 0, 0, 0)
    assert (
        _output_path(output_root).read_text(encoding="utf-8").count("<EventID>11</EventID>") == 513
    )


def test_sysmon_private_sqlite_spool_is_owner_only_and_cleaned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool_root = tmp_path / "private-spool"
    output_root = tmp_path / "output"
    monkeypatch.setenv("EFORGE_SPOOL_DIR", os.fspath(spool_root))
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        source_finalization=True,
    )
    emitter.emit_event(_file_event(BASE_TIME, "once"))

    assert emitter._spool_dir is not None
    assert emitter._spool_path is not None
    assert emitter._spool_dir.parent == spool_root
    assert emitter._spool_path.parent == emitter._spool_dir
    assert (emitter._spool_dir.stat().st_mode & 0o777) == 0o700
    assert (emitter._spool_path.stat().st_mode & 0o777) == 0o600
    assert not output_root.exists()

    _finalize(emitter)
    assert list(spool_root.iterdir()) == []


@pytest.mark.parametrize("target", [OutputTarget.DEFAULT, OutputTarget.SOF_ELK])
def test_sysmon_direct_mode_canonicalizes_one_writer_per_physical_path(
    tmp_path: Path,
    target: OutputTarget,
) -> None:
    direct_path = tmp_path / "direct" / "sysmon.xml"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        direct_path,
        buffer_size=100,
    )
    emitter.configure_output_target(target)
    emitter.emit_event(_file_event(BASE_TIME, "first", computer=HOST))
    emitter.emit_event(
        _file_event(
            BASE_TIME + timedelta(seconds=1),
            "second",
            computer="WIN-TEST-02.corp.local",
        )
    )
    emitter.close()

    writers = emitter._snare_writers if target == OutputTarget.SOF_ELK else emitter._host_writers
    assert set(writers) == {""}
    output = (
        direct_path.with_name("windows_event_sysmon_snare.log")
        if target == OutputTarget.SOF_ELK
        else direct_path
    )
    content = output.read_text(encoding="utf-8")
    assert content.count("first") > 0
    assert content.count("second") > 0


def test_sysmon_threaded_direct_barrier_retains_legacy_terminal_cohort(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        buffer_size=1,
        threaded=True,
    )
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=20), "later"))
    emitter.barrier_flush()
    assert not output_root.exists()
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=10), "earlier"))
    emitter.close()

    content = _output_path(output_root).read_text(encoding="utf-8")
    assert content.index("earlier.tmp") < content.index("later.tmp")


def test_sysmon_nonthreaded_direct_barrier_flushes_writer_to_disk(tmp_path: Path) -> None:
    """The exact-admission fence preserves the legacy non-threaded barrier contract."""

    output_path = tmp_path / "sysmon.xml"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_path,
        buffer_size=100,
    )
    emitter.emit_event(_connection_event(BASE_TIME, "barrier-durable"))

    emitter.barrier_flush()

    assert output_path.read_text(encoding="utf-8").count("barrier-durable.corp.local") == 1
    emitter.close()


def test_sysmon_threaded_spool_failure_is_terminal_and_retains_later_fifo_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=1,
        threaded=True,
        source_finalization=True,
    )
    entered_spool = Event()
    release_spool = Event()

    def failing_spool() -> None:
        entered_spool.set()
        if not release_spool.wait(timeout=5):
            raise AssertionError("spool failure release timed out")
        raise OSError("spool failure")

    monkeypatch.setattr(emitter, "_spool_event_dicts_unlocked", failing_spool)
    emitter.emit_event(_file_event(BASE_TIME, "first"))
    assert entered_spool.wait(timeout=5)
    emitter.emit_event(_file_event(BASE_TIME + timedelta(seconds=1), "later"))
    release_spool.set()
    emitter._thread.join(timeout=5)
    assert not emitter._thread.is_alive()

    coordinator = SourceFinalizationCoordinator((emitter,), _authority())
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        coordinator.finalize()
    with pytest.raises(RuntimeError, match="emitter thread failed"):
        coordinator.finalize()
    assert emitter._event_queue.qsize() == 1
    assert len(emitter._event_dicts) == 1
    assert not (tmp_path / "output").exists()


def test_engine_binds_sysmon_exact_mode_only_for_engine_setup(tmp_path: Path) -> None:
    direct = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "direct.xml",
    )
    assert not direct._source_finalization_bound
    assert direct._spool_conn is None and direct._spool_path is None
    direct.close()
    assert not list(tmp_path.glob("**/.sysmon_event_spool_*.sqlite3"))

    engine = GenerationEngine(
        _scenario("windows_event_sysmon"),
        tmp_path / "output",
        scenario_root=tmp_path,
    )
    engine._initialize()
    emitter = engine.emitters["windows_event_sysmon"]
    assert emitter._source_finalization_bound
    assert engine._source_finalization_coordinator is not None
    assert engine._source_finalization_coordinator._participants == (emitter,)
    engine._finalize(generation_succeeded=False)


def test_engine_seals_security_and_sysmon_before_publishing_either(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(
        _scenario("windows_event_security", "windows_event_sysmon"),
        tmp_path / "output",
        scenario_root=tmp_path,
    )
    baseline_calls = 0
    fail_sysmon_seal = True

    def focused_baseline(**_kwargs: object) -> None:
        nonlocal baseline_calls
        baseline_calls += 1
        security = engine.emitters["windows_event_security"]
        sysmon = engine.emitters["windows_event_sysmon"]
        security.emit_event(_security_event(engine.start_time + timedelta(seconds=1), "once"))
        sysmon.emit_event(_file_event(engine.start_time + timedelta(seconds=2), "once"))
        original_seal = sysmon.seal_source_finalization

        def seal_then_fail() -> object:
            nonlocal fail_sysmon_seal
            if fail_sysmon_seal:
                fail_sysmon_seal = False
                raise RuntimeError("sysmon seal failure")
            return original_seal()

        monkeypatch.setattr(sysmon, "seal_source_finalization", seal_then_fail)

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    with pytest.raises(RuntimeError, match="sysmon seal failure"):
        engine.generate()

    security = engine.emitters["windows_event_security"]
    sysmon = engine.emitters["windows_event_sysmon"]
    assert security.source_finalization_census().state == "sealed"
    assert sysmon.source_finalization_census().state == "quiesced"
    assert not _output_path(tmp_path / "output").exists()
    security_path = tmp_path / "output" / HOST / "windows_event_security.xml"
    assert not security_path.exists()
    coordinator = engine._source_finalization_coordinator
    authority = engine._source_finalization_authority
    assert coordinator is not None and coordinator._published == 0
    assert coordinator.publisher.census().active_child == 0
    assert authority is not None and authority.census().active_batches == 0

    engine.generate()
    assert baseline_calls == 1
    assert security_path.read_text(encoding="utf-8").count("once") == 1
    assert _output_path(tmp_path / "output").read_text(encoding="utf-8").count("once.tmp") == 1


def test_engine_retries_sysmon_checkpoint_after_security_publication_without_duplicates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = GenerationEngine(
        _scenario("windows_event_security", "windows_event_sysmon"),
        tmp_path / "output",
        scenario_root=tmp_path,
    )
    baseline_calls = 0
    checkpoint_return_lost = True

    def focused_baseline(**_kwargs: object) -> None:
        nonlocal baseline_calls
        baseline_calls += 1
        security = engine.emitters["windows_event_security"]
        sysmon = engine.emitters["windows_event_sysmon"]
        security.emit_event(_security_event(engine.start_time + timedelta(seconds=1), "once"))
        sysmon.emit_event(_file_event(engine.start_time + timedelta(seconds=2), "once"))
        original_checkpoint = sysmon._checkpoint_source_chunk

        def checkpoint_then_raise(start: int, end: int) -> None:
            nonlocal checkpoint_return_lost
            original_checkpoint(start, end)
            if checkpoint_return_lost:
                checkpoint_return_lost = False
                raise RuntimeError("sysmon checkpoint return lost")

        monkeypatch.setattr(sysmon, "_checkpoint_source_chunk", checkpoint_then_raise)

    monkeypatch.setattr(engine, "_generate_baseline", focused_baseline)
    with pytest.raises(RuntimeError, match="sysmon checkpoint return lost"):
        engine.generate()

    security_path = tmp_path / "output" / HOST / "windows_event_security.xml"
    sysmon_path = _output_path(tmp_path / "output")
    assert security_path.read_text(encoding="utf-8").count("once") == 1
    assert sysmon_path.read_text(encoding="utf-8").count("once.tmp") == 1
    assert "</Events>" not in security_path.read_text(encoding="utf-8")
    assert "</Events>" not in sysmon_path.read_text(encoding="utf-8")
    coordinator = engine._source_finalization_coordinator
    assert coordinator is not None and coordinator._published == 1
    assert coordinator.publisher.census().active_child == 1
    assert engine.emitters["windows_event_security"].source_finalization_census().state == (
        "published"
    )
    assert engine.emitters["windows_event_sysmon"].source_finalization_census().state == "sealed"

    engine.generate()
    assert baseline_calls == 1
    assert security_path.read_text(encoding="utf-8").count("once") == 1
    assert sysmon_path.read_text(encoding="utf-8").count("once.tmp") == 1
    assert security_path.read_text(encoding="utf-8").count("</Events>") == 1
    assert sysmon_path.read_text(encoding="utf-8").count("</Events>") == 1
    coordinator = engine._source_finalization_coordinator
    authority = engine._source_finalization_authority
    assert coordinator is not None and coordinator.complete
    assert authority is not None
    assert coordinator.publisher.census().active_child == 0
    census = authority.census()
    assert (
        census.active_batches,
        census.prepared_batches,
        census.retained_rows,
        census.retained_bytes,
    ) == (0, 0, 0, 0)


@pytest.mark.parametrize(
    "key",
    [
        ("A" * 32, 1, 0),
        ("a" * 31, 1, 0),
        ("a" * 32, True, 0),
        ("a" * 32, 2**63, 0),
        ("a" * 32, 1, 2**63),
    ],
)
def test_sysmon_exact_candidate_key_rejects_unbounded_or_noncanonical_values(
    key: object,
) -> None:
    """Sysmon journal receipt keys are exact, canonical, and SQLite-safe."""

    with pytest.raises(ExactPublicationError, match="key is malformed"):
        SysmonEventEmitter._validate_exact_candidate_key(key)  # type: ignore[arg-type]


def test_sysmon_exact_projection_capability_requires_source_finalization(tmp_path: Path) -> None:
    """Dispatcher preflight sees exact support only on journal-bound Sysmon emitters."""

    direct = SysmonEventEmitter(load_format("windows_event_sysmon"), tmp_path / "direct")
    exact = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "exact",
        source_finalization=True,
    )

    assert direct.supports_exact_candidate_publication is False
    assert direct.supports_exact_projection_publication is False
    assert exact.supports_exact_candidate_publication is True
    assert exact.supports_exact_projection_publication is True

    direct.close()
    exact.close()


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_exact_candidate_prepare_is_inert_and_cancel_is_neutral(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Prepared Event 3 rows reserve capacity without list, FIFO, or journal admission."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit_event(_connection_event(BASE_TIME, "prepare-one")),
            emitter.emit_event(_connection_event(BASE_TIME + timedelta(seconds=1), "prepare-two")),
        )
    )

    assert emitter._event_dicts == []
    assert emitter._event_queue is None or emitter._event_queue.empty()
    assert emitter._spool_conn is None
    assert emitter._spool_sequence == 0
    source = emitter.source_finalization_census()
    exact = emitter.exact_candidate_census()
    assert (source.candidate_rows, exact.current_rows, exact.current_participants) == (2, 2, 1)
    assert source.candidate_bytes == exact.current_bytes > 0

    batch.cancel()

    source = emitter.source_finalization_census()
    exact = emitter.exact_candidate_census()
    assert (source.candidate_rows, source.candidate_bytes) == (0, 0)
    assert (exact.current_rows, exact.current_bytes, exact.current_participants) == (0, 0, 0)
    assert emitter._event_dicts == []
    assert emitter._event_queue is None or emitter._event_queue.empty()
    assert emitter._spool_conn is None
    assert emitter._spool_sequence == 0
    emitter.close()


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_canonical_event3_prepare_cancel_restores_thread_allocator(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Repeated canonical retries freeze identical bytes and leave no allocator state."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    authority = _authority()
    event = _canonical_connection_event()
    payloads: list[str] = []
    thread_ids: list[int] = []

    for _ in range(12):
        batch = authority.issue_batch()
        batch.prepare(lambda: emitter.emit(event))
        prepared_rows = batch._prepared_rows
        assert prepared_rows is not None and len(prepared_rows) == 1
        payload = prepared_rows[0].frozen_content
        assert type(payload) is str
        payloads.append(payload)
        thread_ids.append(_sysmon_spool_decode(payload)["ExecutionThreadID"])
        batch.cancel()

    assert len(set(payloads)) == 1
    assert len(set(thread_ids)) == 1
    assert not hasattr(emitter, "_sysmon_thread_pools")
    assert not hasattr(emitter, "_sysmon_thread_counters")
    assert not hasattr(emitter, "_sysmon_last_thread_by_host")
    assert not hasattr(emitter, "_sysmon_pids")
    assert "_filters" not in emitter.__dict__
    assert emitter.exact_candidate_census().current_participants == 0
    emitter.close()


def test_sysmon_canonical_event1_cancel_restores_terminal_session_state(
    tmp_path: Path,
) -> None:
    """Canceled Event 1 session ownership cannot influence a later canonical render."""

    reference = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "reference",
        source_finalization=True,
    )
    reference_batch = _authority().issue_batch()
    reference_batch.prepare(lambda: reference.emit(_canonical_process_create_event(session_id=0)))
    reference_rows = reference_batch._prepared_rows
    assert reference_rows is not None and len(reference_rows) == 1
    expected_payload = reference_rows[0].frozen_content
    assert _sysmon_spool_decode(expected_payload)["TerminalSessionId"] == 0
    reference_batch.cancel()
    reference.close()

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    canceled_batch = _authority().issue_batch()
    canceled_batch.prepare(lambda: emitter.emit(_canonical_process_create_event(session_id=7)))
    canceled_rows = canceled_batch._prepared_rows
    assert canceled_rows is not None and len(canceled_rows) == 1
    assert _sysmon_spool_decode(canceled_rows[0].frozen_content)["TerminalSessionId"] == 7
    canceled_batch.cancel()

    assert emitter._terminal_session_ids_by_logon == {}
    assert not hasattr(emitter, "_sysmon_pids")
    assert not hasattr(emitter, "_sysmon_thread_counters")

    retry_batch = _authority().issue_batch()
    retry_batch.prepare(lambda: emitter.emit(_canonical_process_create_event(session_id=0)))
    retry_rows = retry_batch._prepared_rows
    assert retry_rows is not None and len(retry_rows) == 1
    assert retry_rows[0].frozen_content == expected_payload
    retry_batch.cancel()
    emitter.close()


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_canonical_event10_prepare_cancel_restores_call_trace_sequence(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Canceled Event 10 fallback traces retry with identical cache and sequence bytes."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    authority = _authority()
    payloads: list[str] = []
    call_traces: list[str] = []
    for _ in range(12):
        batch = authority.issue_batch()
        batch.prepare(lambda: emitter.emit(_canonical_process_access_event()))
        prepared_rows = batch._prepared_rows
        assert prepared_rows is not None and len(prepared_rows) == 1
        payload = prepared_rows[0].frozen_content
        assert type(payload) is str
        payloads.append(payload)
        call_traces.append(_sysmon_spool_decode(payload)["CallTrace"])
        batch.cancel()

    assert len(set(payloads)) == 1
    assert len(set(call_traces)) == 1
    assert emitter._call_trace_cache == {}
    assert not hasattr(emitter, "_call_trace_counters")
    assert not hasattr(emitter, "_sysmon_pids")
    assert not hasattr(emitter, "_sysmon_thread_counters")
    emitter.close()


def test_sysmon_canonical_event22_cancel_restores_lazy_filter_and_pid_caches(
    tmp_path: Path,
) -> None:
    """Canceled Event 22 fallback rendering leaves every lazy emitter cache neutral."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    authority = _authority()
    payloads: list[str] = []
    for _ in range(6):
        batch = authority.issue_batch()
        batch.prepare(lambda: emitter.emit(_canonical_dns_event()))
        prepared_rows = batch._prepared_rows
        assert prepared_rows is not None and len(prepared_rows) == 1
        payload = prepared_rows[0].frozen_content
        assert type(payload) is str
        assert _sysmon_spool_decode(payload)["EventID"] == 22
        payloads.append(payload)
        batch.cancel()

    assert len(set(payloads)) == 1
    assert "_filters" not in emitter.__dict__
    assert not hasattr(emitter, "_dns_client_pids")
    assert not hasattr(emitter, "_sysmon_pids")
    assert not hasattr(emitter, "_sysmon_thread_counters")
    emitter.close()


def test_sysmon_exact_renderer_receipts_reject_terminal_and_call_trace_tamper(
    tmp_path: Path,
) -> None:
    """Lazy renderer receipts fail closed instead of overwriting conflicting state."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit(_canonical_process_create_event(session_id=7)),
            emitter.emit(_canonical_process_access_event()),
        )
    )
    participant_key = batch._participant_key
    terminal_key = ("WIN-TEST-01", "0x123")
    expected_counter = emitter._call_trace_counters["WIN-TEST-01"]

    emitter._terminal_session_ids_by_logon[terminal_key] = 8
    with pytest.raises(ExactPublicationError, match="terminal-session receipt"):
        emitter._abort_exact_publication_batch(participant_key)
    emitter._terminal_session_ids_by_logon[terminal_key] = 7

    emitter._call_trace_counters["WIN-TEST-01"] = expected_counter + 1
    with pytest.raises(ExactPublicationError, match="call-trace receipt"):
        emitter._abort_exact_publication_batch(participant_key)
    emitter._call_trace_counters["WIN-TEST-01"] = expected_counter

    batch.cancel()
    assert emitter._terminal_session_ids_by_logon == {}
    assert emitter._call_trace_cache == {}
    assert not hasattr(emitter, "_call_trace_counters")
    emitter.close()


def test_sysmon_exact_commit_tamper_is_retryable_before_journal_admission(
    tmp_path: Path,
) -> None:
    """Renderer authentication fails before admission and succeeds after repair."""

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit(_canonical_process_create_event(session_id=7)))
    participant_key = batch._participant_key
    terminal_key = ("WIN-TEST-01", "0x123")
    emitter._terminal_session_ids_by_logon[terminal_key] = 8

    with pytest.raises(ExactPublicationError, match="terminal-session receipt"):
        batch.commit()

    assert batch.state == "ready"
    assert emitter._spool_conn is None
    assert emitter._spool_sequence == 0
    participant = emitter._exact_candidate_participants[participant_key]
    reservation = emitter._exact_candidate_reservations[participant.reservation_keys[0]]
    assert participant.admitted_rows == 0
    assert reservation.admitted is False
    assert participant_key in emitter._active_exact_publication_keys

    emitter._terminal_session_ids_by_logon[terminal_key] = 7
    batch.commit()
    batch.release_no_fail()
    _finalize(emitter)

    output = _output_path(output_root).read_text(encoding="utf-8")
    assert output.count("<EventID>1</EventID>") == 1


@pytest.mark.parametrize("lost_return", [False, True])
def test_sysmon_exact_completion_faults_recover_through_row_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """A detached completion callback cannot orphan its retained row retry owner."""

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    original_complete = emitter._complete_exact_publication_batch
    faulted = False

    def complete_then_raise(key: tuple[str, int]) -> None:
        nonlocal faulted
        if not faulted:
            faulted = True
            if lost_return:
                original_complete(key)
            raise RuntimeError("Sysmon exact completion callback failed")
        original_complete(key)

    monkeypatch.setattr(emitter, "_complete_exact_publication_batch", complete_then_raise)
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit(_canonical_process_create_event(session_id=7)))

    with pytest.raises(RuntimeError, match="completion callback failed"):
        batch.commit()

    assert batch.state == "committed"
    assert batch._participant_key in emitter._active_exact_publication_keys
    batch.release_no_fail()
    assert batch.released
    assert emitter._active_exact_publication_keys == set()
    _finalize(emitter)
    output = _output_path(output_root).read_text(encoding="utf-8")
    assert output.count("<EventID>1</EventID>") == 1


@pytest.mark.parametrize("lost_return", [False, True])
def test_sysmon_exact_renderer_finalization_faults_retry_in_row_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    """Receipt finalization stays retryable until row release advances its cursor."""

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    original_finalize = emitter._finalize_exact_render_state_receipts_unlocked
    faulted = False

    def finalize_then_raise(participant: _SysmonExactCandidateParticipant) -> None:
        nonlocal faulted
        if not faulted:
            faulted = True
            if lost_return:
                original_finalize(participant)
            raise RuntimeError("Sysmon exact renderer finalization failed")
        original_finalize(participant)

    monkeypatch.setattr(
        emitter,
        "_finalize_exact_render_state_receipts_unlocked",
        finalize_then_raise,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit(_canonical_process_create_event(session_id=7)))
    batch.commit()

    with pytest.raises(RuntimeError, match="renderer finalization failed"):
        batch.release_no_fail()

    assert batch.state == "releasing"
    assert batch._participant_key in emitter._active_exact_publication_keys
    batch.release_no_fail()
    assert batch.released
    assert emitter._active_exact_publication_keys == set()
    _finalize(emitter)
    output = _output_path(output_root).read_text(encoding="utf-8")
    assert output.count("<EventID>1</EventID>") == 1


def test_sysmon_filtered_zero_row_completion_skips_fallible_renderer_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proactively reserved filtered target completes without a row retry carrier."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )

    def fail_before_finalize(_participant: object) -> None:
        raise RuntimeError("zero-row finalizer must not run")

    monkeypatch.setattr(
        emitter,
        "_finalize_exact_render_state_receipts_unlocked",
        fail_before_finalize,
    )
    batch = _authority().issue_batch()
    batch.reserve_participants((emitter,))
    batch.prepare(lambda: emitter.emit(_canonical_filtered_connection_event()))

    assert batch._prepared_rows == ()
    assert "_filters" not in emitter.__dict__
    batch.commit()
    batch.release_no_fail()
    assert emitter._active_exact_publication_keys == set()
    assert emitter.exact_candidate_census().current_participants == 0
    emitter.close()
    assert not (tmp_path / "output").exists()


def test_sysmon_filtered_zero_row_completion_lost_return_leaves_no_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A zero-row completion lost return still retires its only participant owner."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    original_complete = emitter._complete_exact_publication_batch

    def complete_then_raise(key: tuple[str, int]) -> None:
        original_complete(key)
        raise RuntimeError("zero-row completion return lost")

    monkeypatch.setattr(emitter, "_complete_exact_publication_batch", complete_then_raise)
    batch = _authority().issue_batch()
    batch.reserve_participants((emitter,))
    batch.prepare(lambda: emitter.emit(_canonical_filtered_connection_event()))

    with pytest.raises(RuntimeError, match="zero-row completion return lost"):
        batch.commit()

    assert batch.state == "committed"
    assert emitter._active_exact_publication_keys == set()
    assert emitter.exact_candidate_census().current_participants == 0
    batch.release_no_fail()
    emitter.close()
    assert not (tmp_path / "output").exists()


def test_sysmon_canonical_exact_commit_retains_all_renderer_sequences(
    tmp_path: Path,
) -> None:
    """Committed Event 1/Event 10 renderer state matches the same direct sequence."""

    reference_root = tmp_path / "reference"
    reference = SysmonEventEmitter(load_format("windows_event_sysmon"), reference_root)
    reference.emit(_canonical_process_create_event(session_id=7))
    reference.emit(_canonical_process_access_event())
    reference.emit(_canonical_process_create_event(session_id=0))
    reference.emit(_canonical_process_access_event())
    reference.close()

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: (
            emitter.emit(_canonical_process_create_event(session_id=7)),
            emitter.emit(_canonical_process_access_event()),
        )
    )
    batch.commit()
    batch.release_no_fail()
    emitter.emit(_canonical_process_create_event(session_id=0))
    emitter.emit(_canonical_process_access_event())
    _finalize(emitter)

    assert _output_path(output_root).read_bytes() == _output_path(reference_root).read_bytes()


def test_sysmon_later_target_prepare_failure_retries_identical_event3_bytes(
    tmp_path: Path,
) -> None:
    """A failure after Sysmon staging restores its renderer state before retry."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    authority = _authority()
    event = _canonical_connection_event()

    reference_batch = authority.issue_batch()
    reference_batch.prepare(lambda: emitter.emit(event))
    reference_rows = reference_batch._prepared_rows
    assert reference_rows is not None and len(reference_rows) == 1
    expected_payload = reference_rows[0].frozen_content
    reference_batch.cancel()

    def fail_after_sysmon_prepare() -> None:
        emitter.emit(event)
        raise RuntimeError("later target prepare failed")

    failed_batch = authority.issue_batch()
    with pytest.raises(RuntimeError, match="later target prepare failed"):
        failed_batch.prepare(fail_after_sysmon_prepare)
    failed_batch.cancel()
    assert not hasattr(emitter, "_sysmon_thread_counters")
    assert not hasattr(emitter, "_sysmon_last_thread_by_host")

    retry_batch = authority.issue_batch()
    retry_batch.prepare(lambda: emitter.emit(event))
    retry_rows = retry_batch._prepared_rows
    assert retry_rows is not None and len(retry_rows) == 1
    assert retry_rows[0].frozen_content == expected_payload
    retry_batch.cancel()
    emitter.close()


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_exact_event3_fences_concurrent_ordinary_thread_allocation(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Ordinary admission waits so exact rollback cannot clobber its allocator advance."""

    reference_root = tmp_path / "reference"
    reference = SysmonEventEmitter(load_format("windows_event_sysmon"), reference_root)
    reference.emit(_canonical_connection_event())
    reference.close()

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit(_canonical_connection_event()))
    assert emitter._sysmon_thread_counters["WIN-TEST-01"] == 1
    started = Event()
    completed = Event()
    failures: list[BaseException] = []

    def emit_ordinary() -> None:
        started.set()
        try:
            emitter.emit(_canonical_connection_event())
        except BaseException as error:
            failures.append(error)
        finally:
            completed.set()

    thread = Thread(target=emit_ordinary)
    thread.start()
    try:
        assert started.wait(timeout=1.0)
        assert not completed.wait(timeout=0.1)
        assert emitter._sysmon_thread_counters["WIN-TEST-01"] == 1
    finally:
        batch.cancel()

    assert completed.wait(timeout=2.0)
    thread.join(timeout=1.0)
    assert failures == []
    assert emitter._sysmon_thread_counters["WIN-TEST-01"] == 1
    _finalize(emitter)
    assert _output_path(output_root).read_bytes() == _output_path(reference_root).read_bytes()


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_canonical_exact_commit_retains_thread_sequence_and_direct_bytes(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Committed exact Event 3 allocation advances the ordinary sequence exactly once."""

    reference_root = tmp_path / "reference"
    reference = SysmonEventEmitter(load_format("windows_event_sysmon"), reference_root)
    reference.emit(_canonical_connection_event())
    reference.emit(_canonical_connection_event())
    reference.close()

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit(_canonical_connection_event()))
    batch.commit()
    batch.release_no_fail()
    emitter.emit(_canonical_connection_event())
    _finalize(emitter)

    assert _output_path(output_root).read_bytes() == _output_path(reference_root).read_bytes()


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("lost_return", [False, True])
def test_sysmon_exact_candidate_commit_resumes_without_duplicate_event3(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    threaded: bool,
    lost_return: bool,
) -> None:
    """A second-row failure resumes the same journal tail, including a lost return."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    original_commit = emitter._commit_exact_candidate_row
    faulted = False

    def fail_second_once(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal faulted
        if key[2] == 1 and not faulted:
            faulted = True
            if lost_return:
                original_commit(key, digest, frozen)
            raise RuntimeError("second Sysmon candidate return lost")
        original_commit(key, digest, frozen)

    monkeypatch.setattr(emitter, "_commit_exact_candidate_row", fail_second_once)
    batch.prepare(
        lambda: (
            emitter.emit_event(_connection_event(BASE_TIME, "commit-one")),
            emitter.emit_event(_connection_event(BASE_TIME + timedelta(seconds=1), "commit-two")),
        )
    )

    with pytest.raises(RuntimeError, match="second Sysmon candidate return lost"):
        batch.commit()
    assert batch.state == "ready"
    batch.commit()
    batch.release_no_fail()
    _finalize(emitter)

    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("<EventID>3</EventID>") == 2
    assert output.count("commit-one.corp.local") == 1
    assert output.count("commit-two.corp.local") == 1
    exact = emitter.exact_candidate_census()
    assert (
        exact.current_rows,
        exact.current_bytes,
        exact.current_participants,
        exact.released_rows,
        exact.released_bytes,
        exact.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)


def test_sysmon_exact_candidate_release_and_journal_commit_lost_returns_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both journal commit and receipt release adopt call-original-then-raise results."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    original_journal_commit = emitter._commit_journal_unlocked
    journal_lost = True

    def journal_commit_then_raise() -> None:
        nonlocal journal_lost
        original_journal_commit()
        if journal_lost:
            journal_lost = False
            raise RuntimeError("Sysmon journal commit return lost")

    original_release = emitter._release_exact_candidate_row
    release_lost = True

    def release_then_raise(key: ExactPublicationKey) -> None:
        nonlocal release_lost
        original_release(key)
        if release_lost:
            release_lost = False
            raise RuntimeError("Sysmon candidate release return lost")

    monkeypatch.setattr(emitter, "_commit_journal_unlocked", journal_commit_then_raise)
    monkeypatch.setattr(emitter, "_release_exact_candidate_row", release_then_raise)
    batch.prepare(lambda: emitter.emit_event(_connection_event(BASE_TIME, "lost-return")))
    batch.commit()
    assert not journal_lost

    with pytest.raises(RuntimeError, match="candidate release return lost"):
        batch.release_no_fail()
    assert batch.state == "releasing"
    batch.release_no_fail()
    assert not release_lost
    _finalize(emitter)
    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("lost-return.corp.local") == 1


@pytest.mark.parametrize("tamper", ["payload", "sort_key"])
def test_sysmon_seal_reauthenticates_post_release_exact_candidate(
    tmp_path: Path,
    tamper: str,
) -> None:
    """Seal refuses a released Event 3 receipt whose payload or ordering key changed."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit_event(_connection_event(BASE_TIME, "exact-one")))
    batch.commit()
    batch.release_no_fail()
    emitter.quiesce_source_finalization()

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        retained = emitter._spool_conn.execute(
            "SELECT sequence, payload, sort_key FROM events WHERE route_kind = ?",
            ("exact-candidate-v1",),
        ).fetchone()
        assert retained is not None
        sequence, payload, sort_key = retained
        if tamper == "payload":
            changed = payload.replace("exact-one", "exact-two", 1)
            assert changed != payload
            assert len(changed.encode("utf-8")) == len(payload.encode("utf-8"))
            assert _sysmon_spool_decode(changed)["DestinationHostname"] == "exact-two.corp.local"
            emitter._spool_conn.execute(
                "UPDATE events SET payload = ? WHERE sequence = ?",
                (changed, sequence),
            )
        else:
            emitter._spool_conn.execute(
                "UPDATE events SET sort_key = ? WHERE sequence = ?",
                (sort_key + "0", sequence),
            )
        emitter._commit_journal_unlocked()

    with pytest.raises(ExactPublicationError, match="changed payload or sort key"):
        emitter.seal_source_finalization()
    retained_exact = emitter.exact_candidate_census()
    assert (retained_exact.current_rows, retained_exact.released_rows) == (1, 1)

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ?, sort_key = ? WHERE sequence = ?",
            (payload, sort_key, sequence),
        )
        emitter._commit_journal_unlocked()
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()
    assert (
        _output_path(tmp_path / "output").read_text(encoding="utf-8").count("exact-one.corp.local")
        == 1
    )


def _released_sysmon_abort_emitter(
    tmp_path: Path,
    *,
    threaded: bool = False,
) -> SysmonEventEmitter:
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        threaded=threaded,
        source_finalization=True,
    )
    emitter.emit_event(_connection_event(BASE_TIME, "ordinary-first"))
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(
            _connection_event(BASE_TIME + timedelta(seconds=1), "exact-second")
        )
    )
    batch.commit()
    batch.release_no_fail()
    return emitter


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_exact_abort_close_matches_direct_event3_bytes(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Authenticated abort-close retains ordinary plus exact Event 3 bytes exactly once."""

    reference_root = tmp_path / "reference"
    reference = SysmonEventEmitter(load_format("windows_event_sysmon"), reference_root)
    reference.emit_event(_connection_event(BASE_TIME, "ordinary-first"))
    reference.emit_event(_connection_event(BASE_TIME + timedelta(seconds=1), "exact-second"))
    reference.close()

    emitter = _released_sysmon_abort_emitter(tmp_path, threaded=threaded)
    emitter.close()

    assert (
        _output_path(tmp_path / "output").read_bytes() == _output_path(reference_root).read_bytes()
    )
    assert emitter.source_finalization_census().state == "aborted"
    exact = emitter.exact_candidate_census()
    assert (
        exact.current_rows,
        exact.current_bytes,
        exact.current_participants,
        exact.released_rows,
        exact.released_bytes,
        exact.completed_participants,
    ) == (0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize("tamper", ["payload", "sort_key"])
def test_sysmon_exact_abort_close_rejects_post_release_tamper(
    tmp_path: Path,
    tamper: str,
) -> None:
    """Abort-close authenticates released rows before any public bytes are written."""

    emitter = _released_sysmon_abort_emitter(tmp_path)
    with emitter._file_lock:
        assert emitter._spool_conn is not None
        retained = emitter._spool_conn.execute(
            "SELECT sequence, payload, sort_key FROM events WHERE route_kind = ?",
            ("exact-candidate-v1",),
        ).fetchone()
        assert retained is not None
        sequence, payload, sort_key = retained
        if tamper == "payload":
            changed = payload.replace("exact-second", "exact-secind", 1)
            assert len(changed) == len(payload) and changed != payload
            emitter._spool_conn.execute(
                "UPDATE events SET payload = ? WHERE sequence = ?",
                (changed, sequence),
            )
        else:
            emitter._spool_conn.execute(
                "UPDATE events SET sort_key = ? WHERE sequence = ?",
                (sort_key + "0", sequence),
            )
        emitter._commit_journal_unlocked()

    with pytest.raises(ExactPublicationError, match="changed payload or sort key"):
        emitter.close()
    assert not (tmp_path / "output").exists()

    with emitter._file_lock:
        assert emitter._spool_conn is not None
        emitter._spool_conn.execute(
            "UPDATE events SET payload = ?, sort_key = ? WHERE sequence = ?",
            (payload, sort_key, sequence),
        )
        emitter._commit_journal_unlocked()
    emitter.close()
    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("ordinary-first.corp.local") == 1
    assert output.count("exact-second.corp.local") == 1


@pytest.mark.parametrize("fault_point", ["commit", "checkpoint", "release"])
@pytest.mark.parametrize("lost_return", [False, True])
def test_sysmon_abort_close_exact_row_failures_resume_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
    lost_return: bool,
) -> None:
    """Abort final-writer commit, cursor, and release retries never duplicate an Event 3."""

    emitter = _released_sysmon_abort_emitter(tmp_path)
    faulted = False

    if fault_point == "commit":
        original = _SingleHostWriter._commit_exact_row

        def commit_then_raise(
            writer: _SingleHostWriter,
            key: ExactPublicationKey,
            digest: str,
            frozen: object,
        ) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original(writer, key, digest, frozen)
                raise RuntimeError("Sysmon abort row commit failed")
            original(writer, key, digest, frozen)

        monkeypatch.setattr(_SingleHostWriter, "_commit_exact_row", commit_then_raise)
    elif fault_point == "checkpoint":
        original_checkpoint = emitter._checkpoint_source_chunk

        def checkpoint_then_raise(start: int, end: int) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original_checkpoint(start, end)
                raise RuntimeError("Sysmon abort row checkpoint failed")
            original_checkpoint(start, end)

        monkeypatch.setattr(emitter, "_checkpoint_source_chunk", checkpoint_then_raise)
    else:
        original_release = _SingleHostWriter._release_exact_row

        def release_then_raise(writer: _SingleHostWriter, key: ExactPublicationKey) -> None:
            nonlocal faulted
            if not faulted:
                faulted = True
                if lost_return:
                    original_release(writer, key)
                raise RuntimeError("Sysmon abort row release failed")
            original_release(writer, key)

        monkeypatch.setattr(_SingleHostWriter, "_release_exact_row", release_then_raise)

    with pytest.raises(RuntimeError, match=rf"Sysmon abort row {fault_point} failed"):
        emitter.close()
    exact = emitter.exact_candidate_census()
    assert (exact.current_rows, exact.released_rows) == (1, 1)
    assert emitter._exact_candidate_abort_pending_row is not None
    assert emitter.source_finalization_census().state == "open"

    emitter.close()
    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("ordinary-first.corp.local") == 1
    assert output.count("exact-second.corp.local") == 1
    assert output.count("</Events>") == 1
    assert emitter._exact_candidate_abort_pending_row is None
    assert emitter.exact_candidate_census().current_rows == 0


def test_sysmon_exact_candidate_capacity_failure_releases_all_reservations(
    tmp_path: Path,
) -> None:
    """A later exact Event 3 capacity failure leaves no journal or scalar ownership."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
        finalization_row_capacity=1,
    )
    batch = _authority().issue_batch()

    with pytest.raises(SourceFinalizationError, match="row capacity"):
        batch.prepare(
            lambda: (
                emitter.emit_event(_connection_event(BASE_TIME, "capacity-one")),
                emitter.emit_event(
                    _connection_event(BASE_TIME + timedelta(seconds=1), "capacity-two")
                ),
            )
        )

    source = emitter.source_finalization_census()
    exact = emitter.exact_candidate_census()
    assert (source.candidate_rows, source.candidate_bytes) == (0, 0)
    assert (exact.current_rows, exact.current_bytes, exact.current_participants) == (0, 0, 0)
    assert emitter._spool_conn is None
    batch.cancel()
    emitter.close()


def test_sysmon_exact_candidate_release_fences_concurrent_quiesce(tmp_path: Path) -> None:
    """Terminal quiescence cannot overtake an unresolved exact Event 3 receipt."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit_event(_connection_event(BASE_TIME, "concurrent")))
    batch.commit()
    started = Event()
    completed = Event()

    def quiesce() -> None:
        started.set()
        emitter.quiesce_source_finalization()
        completed.set()

    thread = Thread(target=quiesce)
    thread.start()
    assert started.wait(timeout=1.0)
    assert not completed.wait(timeout=0.1)

    batch.release_no_fail()
    assert completed.wait(timeout=2.0)
    thread.join(timeout=1.0)
    epoch = emitter.seal_source_finalization()
    emitter.publish_source_finalization(epoch, ExactChunkPublisher(_authority()))
    emitter.close()
    assert (
        _output_path(tmp_path / "output").read_text(encoding="utf-8").count("concurrent.corp.local")
        == 1
    )


@pytest.mark.parametrize("threaded", [False, True])
def test_sysmon_prior_equal_time_ordinary_row_precedes_exact_candidate(
    tmp_path: Path,
    threaded: bool,
) -> None:
    """Exact registration drains earlier list/FIFO work before reserving its sequence range."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        buffer_size=1,
        threaded=threaded,
        source_finalization=True,
    )
    emitter.emit_event(_connection_event(BASE_TIME, "ordinary-first"))
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit_event(_connection_event(BASE_TIME, "exact-second")))
    batch.commit()
    batch.release_no_fail()
    _finalize(emitter)

    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.index("ordinary-first.corp.local") < output.index("exact-second.corp.local")


def test_sysmon_exact_candidate_seal_matches_direct_event3_bytes(tmp_path: Path) -> None:
    """Normal source sealing preserves direct bytes across ordinary and exact admissions."""

    reference_root = tmp_path / "reference"
    reference = SysmonEventEmitter(load_format("windows_event_sysmon"), reference_root)
    reference.emit_event(_connection_event(BASE_TIME, "ordinary-first"))
    reference.emit_event(_connection_event(BASE_TIME + timedelta(seconds=1), "exact-second"))
    reference.close()

    output_root = tmp_path / "output"
    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        output_root,
        source_finalization=True,
    )
    emitter.emit_event(_connection_event(BASE_TIME, "ordinary-first"))
    batch = _authority().issue_batch()
    batch.prepare(
        lambda: emitter.emit_event(
            _connection_event(BASE_TIME + timedelta(seconds=1), "exact-second")
        )
    )
    batch.commit()
    batch.release_no_fail()
    _finalize(emitter)

    exact_bytes = _output_path(output_root).read_bytes()
    direct_bytes = _output_path(reference_root).read_bytes()
    assert exact_bytes == direct_bytes
    assert hashlib.sha256(exact_bytes).digest() == hashlib.sha256(direct_bytes).digest()


def test_sysmon_exact_candidate_release_fences_concurrent_close(tmp_path: Path) -> None:
    """Close cannot discard or render a committed Event 3 before its receipt releases."""

    emitter = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        tmp_path / "output",
        source_finalization=True,
    )
    batch = _authority().issue_batch()
    batch.prepare(lambda: emitter.emit_event(_connection_event(BASE_TIME, "close-fence")))
    batch.commit()
    started = Event()
    completed = Event()
    failures: list[BaseException] = []

    def close() -> None:
        started.set()
        try:
            emitter.close()
        except BaseException as error:
            failures.append(error)
        finally:
            completed.set()

    thread = Thread(target=close)
    thread.start()
    assert started.wait(timeout=1.0)
    assert not completed.wait(timeout=0.1)

    batch.release_no_fail()
    assert completed.wait(timeout=3.0)
    thread.join(timeout=1.0)
    assert failures == []
    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("close-fence.corp.local") == 1
    assert emitter.source_finalization_census().state == "aborted"


def test_sysmon_force_flush_cannot_bypass_released_exact_receipts(tmp_path: Path) -> None:
    """Legacy force rendering cannot retire a released candidate without authentication."""

    emitter = _released_sysmon_abort_emitter(tmp_path)
    with pytest.raises(
        SourceFinalizationError,
        match="released exact candidates require authenticated abort close",
    ):
        emitter.flush(force=True)
    emitter.close()
    output = _output_path(tmp_path / "output").read_text(encoding="utf-8")
    assert output.count("exact-second.corp.local") == 1


def test_sysmon_exact_candidate_abort_bytes_ignore_pythonhashseed(tmp_path: Path) -> None:
    """Exact candidate metadata cannot leak Python hash randomization into public bytes."""

    repository = Path(__file__).resolve().parents[2]
    probe = r"""
import hashlib
import sys
from datetime import UTC, datetime
from pathlib import Path

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.base import ExactPublicationAuthority
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter

root = Path(sys.argv[1])
emitter = SysmonEventEmitter(
    load_format("windows_event_sysmon"), root, source_finalization=True
)
event = {
    "EventID": 3,
    "TimeCreated": datetime(2024, 1, 15, 10, 30, tzinfo=UTC),
    "Computer": "WIN-TEST-01.corp.local",
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Level": 4,
    "ExecutionProcessID": 2480,
    "ExecutionThreadID": 1844,
    "UtcTime": "2024-01-15 10:30:00.000000",
    "ProcessGuid": "{33333333-3333-3333-3333-333333333333}",
    "ProcessId": 4200,
    "Image": r"C:\Windows\System32\OpenSSH\ssh.exe",
    "User": r"CORP\analyst",
    "Protocol": "tcp",
    "Initiated": "true",
    "SourceIsIpv6": "false",
    "SourceIp": "10.0.0.10",
    "SourceHostname": "WIN-TEST-01.corp.local",
    "SourcePort": 49152,
    "SourcePortName": "-",
    "DestinationIsIpv6": "false",
    "DestinationIp": "10.0.0.20",
    "DestinationHostname": "hashseed.corp.local",
    "DestinationPort": 22,
    "DestinationPortName": "ssh",
}
authority = ExactPublicationAuthority(
    capacity=1, row_capacity=8, byte_capacity=1024 * 1024
)
batch = authority.issue_batch()
batch.prepare(lambda: emitter.emit_event(event))
batch.commit()
batch.release_no_fail()
emitter.close()
payload = (root / "WIN-TEST-01.corp.local" / "windows_event_sysmon.xml").read_bytes()
print(hashlib.sha256(payload).hexdigest())
"""
    digests: list[str] = []
    for seed in ("1", "777"):
        environment = {
            **os.environ,
            "PYTHONHASHSEED": seed,
            "PYTHONPATH": os.fspath(repository / "src"),
        }
        completed = subprocess.run(
            [sys.executable, "-c", probe, os.fspath(tmp_path / f"hashseed-{seed}")],
            cwd=repository,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        digests.append(completed.stdout.strip())

    assert digests[0] == digests[1]

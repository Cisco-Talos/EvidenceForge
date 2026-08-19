# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused Sysmon terminal source-finalization tests."""

from __future__ import annotations

import hashlib
import os
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters import sysmon as sysmon_module
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationError,
    LogEmitter,
)
from evidenceforge.generation.emitters.host_base import _SingleHostWriter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter, _sysmon_spool_encode
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

    def focused_baseline() -> None:
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

    def focused_baseline() -> None:
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

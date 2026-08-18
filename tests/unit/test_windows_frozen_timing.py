# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused gates for engine-owned Windows Security render timing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext, SmbContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters import windows as windows_module
from evidenceforge.generation.emitters.windows import WindowsEventEmitter
from evidenceforge.generation.source_timing import (
    SourceTimingPlan,
    SourceTimingPlanner,
    endpoint_event_render_key,
)
from evidenceforge.generation.timing import TimingRuntime

T0 = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)


def _host() -> HostContext:
    """Return one canonical Windows endpoint."""

    return HostContext(
        hostname="WIN-01",
        fqdn="WIN-01.example.test",
        ip="10.20.30.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="example.test",
        netbios_domain="EXAMPLE",
    )


def _auth(*, elevated: bool = False) -> AuthContext:
    """Return one source-ready Windows authentication context."""

    return AuthContext(
        username="analyst",
        user_sid="S-1-5-21-1000-1001",
        logon_id="0x4a51",
        logon_type=2,
        auth_package="Negotiate",
        elevated=elevated,
        subject_sid="S-1-5-18",
        subject_username="SYSTEM",
        subject_domain="NT AUTHORITY",
        subject_logon_id="0x3e7",
        process_pid=784,
        process_name=r"C:\Windows\System32\winlogon.exe",
    )


def _process_event(
    *,
    event_type: str = "process_create",
    timestamp: datetime = T0,
) -> OccurrenceBuilder:
    """Return one canonical Security process occurrence."""

    return OccurrenceBuilder(
        timestamp=timestamp,
        event_type=event_type,
        src_host=_host(),
        auth=_auth(),
        process=ProcessContext(
            pid=2_012,
            parent_pid=784,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
            username=r"EXAMPLE\analyst",
            logon_id="0x4a51",
            parent_image=r"C:\Windows\System32\winlogon.exe",
            start_time=T0,
        ),
    )


def _logon_event(*, elevated: bool = True) -> OccurrenceBuilder:
    """Return one canonical Security logon occurrence."""

    return OccurrenceBuilder(
        timestamp=T0,
        event_type="logon",
        dst_host=_host(),
        auth=_auth(elevated=elevated),
    )


def _smb_open_event() -> OccurrenceBuilder:
    """Return one high-audit SMB open that renders 5145 and 4656."""

    return OccurrenceBuilder(
        timestamp=T0,
        event_type="smb_file_open",
        dst_host=_host(),
        auth=_auth(),
        smb=SmbContext(
            phase="open",
            operation="open",
            purpose="user_file_access",
            session_id="smb-session-1",
            tree_id="tree-1",
            share_ref="share-1",
            share_name="Engineering",
            result="success",
            requested_access="read",
            share_path=r"Projects\plan.docx",
            server_path=r"C:\Shares\Engineering\Projects\plan.docx",
            share_local_path=r"C:\Shares\Engineering",
            file_id="file-1",
            handle_id="handle-1",
            audit="high",
        ),
    )


def _plan(event: OccurrenceBuilder, *, namespace: str) -> None:
    """Freeze one Windows Security projection through the upstream owner."""

    SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace=namespace)
    ).plan_event(
        event,
        "windows_event_security",
        source_instance="windows_security:win-01",
        source_hostname="WIN-01",
    )


def _render_time(event: OccurrenceBuilder, phase: str) -> datetime:
    """Return one exact frozen Windows Security envelope timestamp."""

    assert event.source_timing is not None
    return event.source_timing.finalized_times[
        endpoint_event_render_key("windows_event_security", "WIN-01", phase)
    ]


def test_windows_security_consumes_frozen_logon_and_smb_phases(tmp_path: Path) -> None:
    """Multi-row Security events use their exact pre-render phase timestamps."""

    logon = _logon_event()
    smb_open = _smb_open_event()
    _plan(logon, namespace="windows-logon-phases")
    _plan(smb_open, namespace="windows-smb-phases")
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "security.xml",
        buffer_size=100,
    )

    with patch.object(
        windows_module,
        "compatibility_endpoint_event_times",
        side_effect=AssertionError("production Windows renderer replanned timing"),
    ):
        emitter.emit(logon)
        emitter.emit(smb_open)

    rows = {int(row["EventID"]): dict(row) for row in emitter._event_dicts}
    assert rows[4624]["TimeCreated"] == _render_time(logon, "base")
    assert rows[4672]["TimeCreated"] == _render_time(logon, "privilege")
    assert rows[5145]["TimeCreated"] == _render_time(smb_open, "base")
    assert rows[4656]["TimeCreated"] == _render_time(smb_open, "smb_object_open")
    assert all(
        row["_TimingFinalized"] == windows_module._FROZEN_TIMING_MARKER for row in rows.values()
    )
    emitter.close()


def test_windows_security_consumes_frozen_process_termination(tmp_path: Path) -> None:
    """Security 4689 formats the exact upstream process-termination phase."""

    event = _process_event(
        event_type="process_terminate",
        timestamp=T0 + timedelta(seconds=5),
    )
    _plan(event, namespace="windows-process-terminate")
    expected = _render_time(event, "process_terminate")
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "termination.xml",
        buffer_size=100,
    )

    with patch.object(
        windows_module,
        "compatibility_endpoint_event_times",
        side_effect=AssertionError("production Windows renderer replanned timing"),
    ):
        emitter.emit(event)

    assert emitter._event_dicts[0]["EventID"] == 4689
    assert emitter._event_dicts[0]["TimeCreated"] == expected
    emitter.close()


@pytest.mark.parametrize("buffer_size", [100, 1], ids=["memory", "sqlite-spool"])
def test_windows_security_flush_preserves_frozen_process_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    buffer_size: int,
) -> None:
    """Neither flush implementation normalizes an exact frozen timestamp."""

    event = _process_event()
    _plan(event, namespace=f"windows-flush-{buffer_size}")
    expected = _render_time(event, "process_create")
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / f"security-{buffer_size}.xml",
        buffer_size=buffer_size,
    )
    rendered_rows: list[dict[str, object]] = []

    def capture(row: dict[str, object]) -> str:
        rendered_rows.append(dict(row))
        return ""

    monkeypatch.setattr(emitter, "_render_event", capture)
    emitter.emit(event)
    emitter.close()

    row = next(row for row in rendered_rows if row["EventID"] == 4688)
    assert row["TimeCreated"] == expected
    assert "_TimingFinalized" not in row


@pytest.mark.parametrize("buffer_size", [100, 1], ids=["memory", "sqlite-spool"])
def test_windows_security_mixed_raw_batch_does_not_repair_frozen_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    buffer_size: int,
) -> None:
    """Legacy raw-row ordering scans leave a canonical row exact in mixed batches."""

    event = _process_event()
    _plan(event, namespace=f"windows-mixed-{buffer_size}")
    expected = _render_time(event, "process_create")
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / f"mixed-{buffer_size}.xml",
        buffer_size=buffer_size,
    )
    rendered_rows: list[dict[str, object]] = []
    monkeypatch.setattr(
        emitter,
        "_render_event",
        lambda row: rendered_rows.append(dict(row)) or "",
    )

    emitter.emit(event)
    emitter.emit_raw(
        {
            "EventID": 4624,
            "TimeCreated": expected + timedelta(seconds=5),
            "Computer": _host().fqdn,
            "TargetLogonId": "0x4a51",
            "LogonType": 2,
        }
    )
    emitter.close()

    row = next(row for row in rendered_rows if row["EventID"] == 4688)
    assert row["TimeCreated"] == expected


@pytest.mark.parametrize("buffer_size", [100, 1], ids=["memory", "sqlite-spool"])
def test_windows_security_raw_marker_cannot_bypass_legacy_repairs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    buffer_size: int,
) -> None:
    """A raw caller cannot spoof the private carrier marker."""

    logon_time = T0 + timedelta(seconds=5, microseconds=100)
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / f"raw-{buffer_size}.xml",
        buffer_size=buffer_size,
    )
    rendered_rows: list[dict[str, object]] = []
    monkeypatch.setattr(
        emitter,
        "_render_event",
        lambda row: rendered_rows.append(dict(row)) or "",
    )
    emitter.emit_raw(
        {
            "EventID": 4688,
            "TimeCreated": T0,
            "Computer": _host().fqdn,
            "SubjectLogonId": "0x4a51",
            "NewProcessId": "0x7dc",
            "ProcessId": "0x310",
            "_TimingFinalized": windows_module._FROZEN_TIMING_MARKER,
        }
    )
    emitter.emit_raw(
        {
            "EventID": 4624,
            "TimeCreated": logon_time,
            "Computer": _host().fqdn,
            "TargetLogonId": "0x4a51",
            "LogonType": 2,
        }
    )
    emitter.close()

    row = next(row for row in rendered_rows if row["EventID"] == 4688)
    assert row["TimeCreated"] == logon_time + timedelta(milliseconds=1)
    assert "_TimingFinalized" not in row


def test_windows_security_incomplete_production_plan_fails_closed(tmp_path: Path) -> None:
    """Only an explicitly marked compatibility plan may be extended in the emitter."""

    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / "compatibility.xml",
        buffer_size=100,
    )
    production = _process_event()
    production.source_timing = SourceTimingPlan(canonical_timestamp=production.timestamp)
    with pytest.raises(RuntimeError, match="requires frozen endpoint timing"):
        emitter.emit(production)

    compatibility = _process_event(timestamp=T0 + timedelta(seconds=1))
    compatibility.source_timing = SourceTimingPlan(
        canonical_timestamp=compatibility.timestamp,
        compatibility_mode=True,
    )
    emitter.emit(compatibility)
    assert emitter._event_dicts[-1]["_TimingFinalized"] == windows_module._FROZEN_TIMING_MARKER
    assert compatibility.source_timing.compatibility_mode is True
    emitter.close()


@pytest.mark.parametrize("target", ["default", "splunk", "sof-elk"])
def test_windows_security_strips_timing_marker_before_every_render_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    """Internal timing metadata never reaches XML, Splunk, or Snare renderers."""

    event = _logon_event(elevated=False)
    _plan(event, namespace=f"windows-marker-{target}")
    emitter = WindowsEventEmitter(
        load_format("windows_event_security"),
        tmp_path / target,
        buffer_size=100,
    )
    emitter.configure_output_target(target)
    rendered_rows: list[dict[str, object]] = []
    if target == "sof-elk":
        monkeypatch.setattr(
            windows_module,
            "render_windows_security_snare_syslog",
            lambda row: rendered_rows.append(dict(row)) or "",
        )
    else:
        monkeypatch.setattr(
            emitter,
            "_render_event",
            lambda row: rendered_rows.append(dict(row)) or "",
        )

    emitter.emit(event)
    emitter.close()

    assert rendered_rows
    assert all("_TimingFinalized" not in row for row in rendered_rows)


def test_windows_security_frozen_output_is_writer_shape_deterministic(tmp_path: Path) -> None:
    """In-memory and SQLite-spooled writers serialize identical frozen truth."""

    outputs: list[bytes] = []
    for buffer_size in (100, 1):
        event = _process_event()
        _plan(event, namespace="windows-writer-shape")
        output = tmp_path / f"security-{buffer_size}.xml"
        emitter = WindowsEventEmitter(
            load_format("windows_event_security"),
            output,
            buffer_size=buffer_size,
        )
        emitter.emit(event)
        emitter.close()
        outputs.append(output.read_bytes())

    assert outputs[0] == outputs[1]
    assert windows_module._FROZEN_TIMING_MARKER.encode() not in outputs[0]


def test_windows_security_emitter_has_no_timing_planner_or_direct_sampler() -> None:
    """The Security emitter only consumes frozen truth or stateless adapters."""

    source = Path(windows_module.__file__).read_text(encoding="utf-8")
    forbidden = (
        "SourceTimingPlanner",
        "_SOURCE_TIMING",
        "sample_timing_delta(",
        "sample_packet_timing_delta(",
        "get_timing_window(",
        ".source_time(",
    )
    assert not [token for token in forbidden if token in source]

"""Invented SSH ULF inputs exercise identity scope and closed-output privacy."""

import json
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import macos_ssh_startup_reference as startup
from scripts import macos_ssh_unified_reference as kit

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_ssh_startup_reference import (
    test_mocked_capture_cleans_up_and_only_persists_proved_rows_after_success as _capture_test,
)
from tests.unit.test_macos_ulf_launchd_reference import _row

SECRET = "invented-private-ssh-canary"
IMAGE = "/usr/libexec/sshd-session"
NONCE = "b" * 32


@pytest.fixture(autouse=True)
def no_native_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("SSH ULF tests cannot start native operations")

    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(startup.os, "execve", forbidden)


@requires_posix_reference
@pytest.mark.parametrize("failure", ["ulf_stream", "ulf_cleanup", "ulf_binding"])
def test_unified_capture_failure_never_writes_native_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    _capture_test(tmp_path, monkeypatch, failure, True)


@pytest.mark.parametrize("nonce", [SECRET, '" OR TRUE OR "', "b" * 33])
def test_invalid_nonce_never_reaches_a_collector(nonce: str) -> None:
    with pytest.raises(ValueError, match="ULF_BINDING"):
        kit.Collector(Path("/private/tmp/invented"), nonce)


def _process(pid: int, version: int, role: str, image: str, birth: int = 1) -> dict:
    return {
        "pid": pid,
        "version": version,
        "birth": birth,
        "role": role,
        "executable": {"path": image},
    }


def _es(kind: int, second: int, before: dict, after: dict | None = None) -> dict:
    event = (
        {"exec": {"target": after}}
        if kind == 9
        else {"fork": {"child": after}}
        if kind == 11
        else {"exit": {"stat": 0}}
    )
    return {
        "event_type": kind,
        "time": f"2026-11-03T12:00:{second:02d}+00:00",
        "process": before,
        "event": event,
    }


def _identity(process: dict) -> tuple[int, int, int]:
    return process["pid"], process["version"], process["birth"]


def _windows() -> tuple[kit.ExecutionWindow, ...]:
    boot = _process(1, 1, "LAUNCHD", "/sbin/launchd")
    first = _process(100, 1, "SSHD", "/usr/sbin/sshd")
    session = _process(100, 2, "SESSION", IMAGE)
    child = _process(101, 1, "SESSION", IMAGE)
    auth = _process(101, 2, "AUTH", "/usr/libexec/sshd-auth")
    rows = [
        _es(11, 1, boot, first),
        _es(9, 2, first, session),
        _es(11, 3, session, child),
        _es(9, 4, child, auth),
        _es(15, 5, auth),
        _es(15, 6, session),
    ]
    return kit.execution_windows(rows, identity=_identity, role_of=lambda p: p["role"])


def _ulf(second: int = 3, *, pid: int = 100, image: str = IMAGE) -> dict:
    return _row(f"Accepted password for {SECRET} from 127.0.0.1 port 50000 ssh2") | {
        "timestamp": f"2026-11-03 12:00:{second:02d}.000000+0000",
        "processID": pid,
        "processImagePath": image,
        "senderImagePath": "/usr/lib/system/libsystem_asl.dylib",
        "category": SECRET,
        "subsystem": SECRET,
    }


def test_closed_exec_windows_keep_forks_and_image_replacements_distinct() -> None:
    windows = _windows()
    assert [(w.pid, w.role, w.start.second, w.end.second) for w in windows] == [
        (100, "SSHD", 1, 2),
        (101, "SESSION", 3, 4),
        (101, "AUTH", 4, 5),
        (100, "SESSION", 2, 6),
    ]
    assert all(w.pid != 1 for w in windows)


@pytest.mark.parametrize("damage", ["version", "birth", "time"])
def test_mismatched_terminal_identity_does_not_authenticate_a_window(damage: str) -> None:
    first = _process(100, 1, "SESSION", IMAGE)
    end = first | ({damage: 99} if damage != "time" else {})
    rows = [
        _es(11, 2, _process(1, 1, "LAUNCHD", "/sbin/launchd"), first),
        _es(15, 1 if damage == "time" else 3, end),
    ]
    with pytest.raises(ValueError, match="ULF_BINDING"):
        kit.execution_windows(rows, identity=_identity, role_of=lambda p: p["role"])


def test_same_pid_image_and_time_are_all_required_and_end_is_exclusive() -> None:
    rows = [
        _ulf(3),
        _ulf(1),
        _ulf(6),
        _ulf(3, pid=999),
        _ulf(3, pid=True),
        _ulf(3, image="/invented/other"),
        _ulf(3) | {"timestamp": SECRET},
    ]
    assert kit.select_rows(rows, _windows()) == [rows[0]]


def test_pid_reuse_gap_and_unclosed_executions_never_match() -> None:
    windows = _windows() + (
        kit.ExecutionWindow(
            pid=100,
            image=IMAGE,
            role="SESSION",
            start=datetime(2026, 11, 3, 12, 0, 8, tzinfo=UTC),
            end=datetime(2026, 11, 3, 12, 0, 9, tzinfo=UTC),
        ),
    )
    assert kit.select_rows([_ulf(7), _ulf(8), _ulf(9)], windows) == [_ulf(8)]
    unclosed = _process(102, 1, "SESSION", IMAGE)
    with pytest.raises(ValueError, match="ULF_BINDING"):
        kit.execution_windows(
            [_es(11, 1, _process(1, 1, "LAUNCHD", "/sbin/launchd"), unclosed)],
            identity=_identity,
            role_of=lambda p: p["role"],
        )


def test_closed_summary_does_not_export_observed_names_text_or_values() -> None:
    rows = [_ulf(), _ulf() | {"eventMessage": "in pam_sm_open_session(): " + SECRET}]
    report = kit.summarize(rows, _windows(), SECRET)
    assert report.native_shapes == "PASS"
    assert report.messages.accepted_local_password == report.messages.pam_open == 1
    assert report.senders == ("SYSTEM_ASL",) and report.roles == ("SESSION",)
    assert report.static_formats == ("PUBLIC_C_STRING",)
    assert report.message_redaction == "ABSENT_ALL" and report.message_types == ("Default",)
    assert report.gate_status == "NOT_EVALUATED"
    text = report.model_dump_json()
    assert all(value not in text for value in (SECRET, IMAGE, "127.0.0.1", "50000"))


def test_unknown_shape_and_empty_retention_remain_unqualified() -> None:
    report = kit.summarize([_ulf() | {SECRET: SECRET}], _windows(), SECRET)
    assert report.native_shapes == "FAIL" and SECRET not in report.model_dump_json()
    empty = kit.summarize([_ulf(pid=999)], _windows(), SECRET)
    assert empty.retained_rows == 0 and empty.native_shapes == "INCONCLUSIVE"
    assert empty.reference_result == "NO_MATCHING_ROWS"
    assert empty.readiness_scope == "OWN_PROCESS_MARKER_ONLY"


def test_activity_entries_cannot_poison_valid_logs_or_claim_log_shape_coverage() -> None:
    activity = _ulf() | {"eventType": "activityCreateEvent", SECRET: SECRET}
    summary = kit.summarize([activity, _ulf()], _windows(), SECRET)
    assert summary.native_shapes == "PASS"
    assert summary.retained_rows == 2
    assert summary.log_event_rows == summary.other_event_rows == summary.classified_log_rows == 1
    assert summary.invalid_log_rows == 0
    assert summary.messages.accepted_local_password == 1
    assert summary.shape_scope == "LOG_EVENT_ROWS_ONLY"
    only_activity = kit.summarize([activity], _windows(), SECRET)
    assert only_activity.native_shapes == "INCONCLUSIVE"
    assert only_activity.classified_log_rows == 0
    assert SECRET not in summary.model_dump_json()


def test_bad_log_does_not_hide_valid_subset_and_still_fails_overall_shape() -> None:
    summary = kit.summarize([_ulf() | {SECRET: SECRET}, _ulf()], _windows(), SECRET)
    assert summary.native_shapes == "FAIL"
    assert summary.log_event_rows == 2
    assert summary.invalid_log_rows == summary.classified_log_rows == 1
    assert summary.messages.accepted_local_password == 1
    assert SECRET not in summary.model_dump_json()


def test_redacted_native_messages_stay_redacted_and_never_become_auth_success() -> None:
    row = _ulf() | {
        "eventMessage": "Accepted password for <private> from <private> port <private> ssh2"
    }
    summary = kit.summarize([row], _windows(), SECRET)
    assert summary.message_redaction == "PRESENT_ALL"
    assert summary.messages.accepted_local_password == 0
    assert summary.messages.other_controlled == 1
    assert SECRET not in summary.model_dump_json()


def test_ambiguous_windows_and_excessive_retention_fail_closed() -> None:
    with pytest.raises(ValueError, match="ULF_BINDING"):
        kit.select_rows([_ulf()], _windows() * 2)
    with pytest.raises(ValueError, match="ULF_LIMIT"):
        kit.select_rows([_ulf()] * 257, _windows())


def test_ambient_ring_is_memory_only_bounded_and_marker_checks_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collector = kit.Collector.__new__(kit.Collector)
    collector.marker = "EFORGE_SSH_ULF_READY " + NONCE
    collector.marker_image = "/private/tmp/invented/ssh-marker"
    collector.ready = collector.evicted = False
    collector.total = collector.size = 0
    collector.rows = deque()
    monkeypatch.setattr(kit, "MAX_ROWS", 2)
    collector.accept(
        json.dumps(
            {"eventMessage": collector.marker, "processImagePath": "/invented/foreign"}
        ).encode()
    )
    assert not collector.ready
    collector.accept(
        json.dumps(
            {"eventMessage": collector.marker, "processImagePath": collector.marker_image}
        ).encode()
    )
    assert collector.ready
    for _ in range(3):
        collector.accept(json.dumps(_ulf(pid=999)).encode())
    assert collector.evicted and len(collector.rows) == 2
    assert kit.select_rows([row for _size, row in collector.rows], _windows()) == []


@requires_posix_reference
def test_unified_prepare_only_copies_code_and_frozen_opt_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        startup.subprocess, "run", lambda *args, **kwargs: pytest.fail("no native command")
    )
    monkeypatch.setattr(
        startup.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("no native process")
    )
    root = startup.prepare(tmp_path / "fresh", unified_log=True)
    assert {p.name for p in root.iterdir()} == set(startup.CODE) | {
        "PRIVATE-RUN.md",
        "ULF-EXPERIMENT.json",
        startup.UNIFIED_CODE,
    }
    assert startup._unified_experiment(root) == startup.reference._digest(
        root / "ULF-EXPERIMENT.json"
    )
    assert not list(root.glob("*LOCK")) and not list(root.glob("run-*"))
    assert "SHAREABLE-SSH-ULF-REPORT.json" in (root / "PRIVATE-RUN.md").read_text()


@requires_posix_reference
def test_saved_ulf_report_starts_no_command_and_opens_no_native_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    startup.reference._write(
        tmp_path / "SHAREABLE-SSH-ULF-REPORT.json", kit.Summary().model_dump_json().encode()
    )
    monkeypatch.setattr(startup, "_root", lambda: tmp_path)
    monkeypatch.setattr(startup.reference, "_active", lambda root: root)
    monkeypatch.setattr(startup, "_unified_module", lambda: kit)
    monkeypatch.setattr(
        startup.sys, "argv", ["private_ssh_startup.py", "ulf-report", "--private-run"]
    )
    monkeypatch.setattr(
        startup.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("no native process")
    )
    monkeypatch.setattr(
        startup.subprocess, "run", lambda *args, **kwargs: pytest.fail("no native command")
    )
    startup.main()
    assert json.loads(capsys.readouterr().out)["purpose"] == "SSH_UNIFIED_LOG_DIAGNOSTIC"


def test_collector_registration_failure_stops_its_process_and_closes_pipes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    def fail(*args: object) -> None:
        raise OSError("invented failure")

    selector = SimpleNamespace(register=fail, close=lambda: closed.append("selector"))
    process = SimpleNamespace(
        stdout=SimpleNamespace(fileno=lambda: 17, close=lambda: closed.append("stdout")),
        poll=lambda: None,
        terminate=lambda: closed.append("terminate"),
        wait=lambda timeout: 0,
    )
    commands: list[list[str]] = []

    def popen(arguments: list[str], **kwargs: object) -> object:
        commands.append(arguments)
        return process

    monkeypatch.setattr(kit.selectors, "DefaultSelector", lambda: selector)
    monkeypatch.setattr(kit.subprocess, "Popen", popen)
    monkeypatch.setattr(kit.os, "set_blocking", lambda *args: None)
    with pytest.raises(OSError, match="invented failure"):
        kit.Collector(Path("/private/tmp/invented"), NONCE)
    assert set(closed) == {"selector", "stdout", "terminate"}
    assert commands[0][:6] == ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "info"]

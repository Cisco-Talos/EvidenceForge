"""Privacy/containment of the new diagnostic using invented records, never native data."""

import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import macos_ulf_launchd_reference as kit

NONCE = "a" * 32
LABEL = "org.evidenceforge.reference.launchd." + NONCE
SECRET = "invented-private-canary-do-not-export"


def _row(message: str) -> dict:
    return {
        "eventType": "logEvent",
        "messageType": "Default",
        "timezoneName": "",
        "timestamp": "2026-11-02 12:00:00.000000+0000",
        "machTimestamp": 123,
        "bootUUID": "12345678-1234-4234-8234-123456789abc",
        "processID": 1,
        "userID": 0,
        "threadID": 42,
        "processImagePath": "/sbin/launchd",
        "processImageUUID": "12345678-1234-4234-8234-123456789abc",
        "senderImagePath": "/sbin/launchd",
        "senderImageUUID": "12345678-1234-4234-8234-123456789abc",
        "senderProgramCounter": 123,
        "activityIdentifier": 0,
        "parentActivityIdentifier": 0,
        "traceID": 123,
        "subsystem": "com.apple.xpc.launchd",
        "category": "",
        "formatString": "%{public}s",
        "eventMessage": message,
    }


def test_preparation_copies_only_public_code_without_native_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Code preparation must never run native operations")

    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    root = kit.prepare(tmp_path)
    assert {p.name for p in root.iterdir()} == {"private_ulf_launchd.py", "ready.c", "job_guard.c"}
    assert root.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o077 == 0 for p in root.iterdir())


def test_fixed_analysis_never_exports_unknown_strings_or_native_values() -> None:
    rows = [_row(LABEL + " service state: spawning"), _row(LABEL + " exited due to exit(0)")]
    rows[1].update(category=SECRET, formatString=SECRET, personaName=SECRET)
    report = kit.analyze(rows, LABEL, kit.Report(stage="COMPLETE"))
    assert report.native_shapes == "PASS"
    assert report.messages.spawning == report.messages.exited_zero == 1
    assert report.static_format == "MIXED"
    text = report.model_dump_json()
    assert all(value not in text for value in (SECRET, LABEL, NONCE, "/sbin/launchd"))


def test_empty_capture_and_unknown_envelope_are_not_qualification() -> None:
    assert kit.analyze([], LABEL, kit.Report()).native_shapes == "INCONCLUSIVE"
    row = _row(LABEL + " " + SECRET) | {SECRET: SECRET}
    report = kit.analyze([row], LABEL, kit.Report())
    assert report.native_shapes == "FAIL"
    assert SECRET not in report.model_dump_json()


def test_analysis_rejects_an_unrelated_record_and_excessive_retention() -> None:
    with pytest.raises(kit.PrivateError, match="CONTROL"):
        kit.analyze([_row(SECRET)], LABEL, kit.Report())
    with pytest.raises(kit.PrivateError, match="LIMIT"):
        kit.analyze([_row(LABEL)] * 257, LABEL, kit.Report())


@pytest.mark.parametrize("unsafe", ["symlink", "permissions", "extent"])
def test_private_input_rejects_unsafe_files(tmp_path: Path, unsafe: str) -> None:
    target = tmp_path / "data"
    kit._write(target, b"safe")
    if unsafe == "symlink":
        link = tmp_path / "link"
        link.symlink_to(target)
        target = link
    elif unsafe == "permissions":
        target.chmod(0o644)
    else:
        with target.open("r+b") as stream:
            stream.truncate(kit.MAX_BYTES + 1)
    with pytest.raises((kit.PrivateError, OSError)):
        kit._read(target)


def test_report_only_reads_saved_fixed_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    kit._write(
        tmp_path / "SHAREABLE-ULF-REPORT.json",
        kit.Report(stage="COMPLETE").model_dump_json().encode(),
    )
    monkeypatch.setattr(kit, "_root", lambda path: tmp_path)
    monkeypatch.setattr(kit.sys, "argv", ["private_ulf_launchd.py", "report", "--private-run"])
    monkeypatch.setattr(
        kit.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("no collector")
    )
    monkeypatch.setattr(kit.subprocess, "run", lambda *args, **kwargs: pytest.fail("no commands"))
    assert kit.main() == 0
    assert json.loads(capsys.readouterr().out)["stage"] == "COMPLETE"


def test_capture_filters_unrelated_input_and_closes_both_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        def __init__(self, data: bytes, *, running: bool) -> None:
            read_fd, write_fd = os.pipe()
            os.write(write_fd, data)
            os.close(write_fd)
            self.stdout = os.fdopen(read_fd, "rb")
            self.stdin = io.BytesIO()
            self.running = running
            self.stopped = False

        def poll(self) -> int | None:
            return None if self.running else 0

        def terminate(self) -> None:
            self.stopped = True

        def wait(self, timeout: int) -> int:
            self.stopped = True
            return 0

    marker = {"eventMessage": "EFORGE_ULF_READY " + NONCE}
    rows = [marker, _row(SECRET), _row(LABEL + " service state: running")]
    collector = Process(b"".join((json.dumps(r) + "\n").encode() for r in rows), running=True)
    job = Process(b"REGISTERED\nACTIVATED\nREMOVED\nFILES_REMOVED\n", running=False)
    calls: list[list[str]] = []

    def popen(arguments: list[str], **kwargs: object) -> Process:
        calls.append(arguments)
        return collector if len(calls) == 1 else job

    ticks = iter(i / 10 for i in range(1000))
    monkeypatch.setattr(kit, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    monkeypatch.setattr(kit, "_config", lambda root: kit.Config(nonce=NONCE, hashes={}))
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(kit.subprocess, "Popen", popen)
    monkeypatch.setattr(
        kit.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0)
    )
    report = kit.capture(tmp_path)
    assert report.collector_ready == report.collector_cleanup == "PASS"
    assert report.job_activated == report.job_removed == report.temporary_files_removed == "PASS"
    assert report.native_shapes == "PASS" and report.retained_rows == 1
    assert collector.stopped and job.stopped
    assert calls[0][:3] == ["/usr/bin/log", "stream", "--style"]
    assert LABEL in calls[0][-1]
    assert calls[1] == ["/usr/bin/sudo", "-n", str(tmp_path / "job-guard"), "run", NONCE]
    assert SECRET not in (tmp_path / "records.ndjson").read_text()
    assert SECRET not in (tmp_path / "SHAREABLE-ULF-REPORT.json").read_text()


@pytest.mark.parametrize(
    "major,architecture,uid",
    [("26", "arm64", 501), ("28", "arm64", 501), ("27", "x86_64", 501), ("27", "arm64", 0)],
)
def test_native_operations_reject_other_targets(
    major: str, architecture: str, uid: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        kit,
        "platform",
        SimpleNamespace(
            system=lambda: "Darwin", machine=lambda: architecture, mac_ver=lambda: (major, (), "")
        ),
    )
    monkeypatch.setattr(kit.os, "getuid", lambda: uid)
    with pytest.raises(kit.PrivateError, match="PLATFORM"):
        kit._platform()


def test_recovery_uses_only_the_exact_guard_cleanup_and_never_exports_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(kit, "_config", lambda root: kit.Config(nonce=NONCE, hashes={}))
    calls: list[list[str]] = []

    def run(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout=b"REMOVED\nFILES_REMOVED\n" + SECRET.encode())

    monkeypatch.setattr(kit.subprocess, "run", run)
    report = kit.cleanup(tmp_path)
    assert report.job_removed == report.temporary_files_removed == "PASS"
    assert SECRET not in report.model_dump_json()
    assert calls == [["/usr/bin/sudo", "-n", str(tmp_path / "job-guard"), "cleanup", NONCE]]

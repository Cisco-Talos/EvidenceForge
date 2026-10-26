# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented fixed descriptors only. Never execute SSH, a native probe or preflight."""

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_ssh_descriptor_reference as kit

_CANARY = "INVENTED_PRIVATE_CANARY_never_export"


def _observation(*, pipe: bool = False) -> kit.Observation:
    return kit.Observation(
        inventory_complete="PASS",
        instrument_verified="PASS",
        only_standard_descriptors="PASS",
        stdio_open="PASS",
        stat_type_agreement="PASS",
        stdio_close_on_exec_clear="PASS",
        stdin_kind="PIPE" if pipe else "VNODE",
        stdout_kind="PIPE" if pipe else "VNODE",
        stderr_kind="PIPE" if pipe else "VNODE",
        stdin_access="READ" if pipe else "READ_WRITE",
        stdout_access="WRITE" if pipe else "READ_WRITE",
        stderr_access="WRITE" if pipe else "READ_WRITE",
        tty_streams="NONE" if pipe else "ALL",
        stdout_stderr_object="DIFFERENT" if pipe else "SAME",
        stdin_stdout_object="DIFFERENT" if pipe else "SAME",
    )


@pytest.mark.parametrize("field", tuple(kit.Observation.model_fields))
def test_native_diagnostic_cannot_export_arbitrary_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Observation.model_validate({field: _CANARY})


@pytest.mark.parametrize("field", tuple(kit.Report.model_fields))
def test_shared_report_cannot_export_arbitrary_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A synthetic test attempted native execution/preflight or SSH")

    monkeypatch.setattr(kit, "_preflight", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.os, "execve", forbidden)
    return kit.prepare(tmp_path / "invented-kit")


def test_prepare_copies_only_reviewed_code_and_instructions(prepared: Path) -> None:
    assert {path.name for path in prepared.iterdir()} == {
        "private_ssh_descriptors.py",
        "ssh_descriptor_probe.c",
        "RUN-LOCAL.sh",
        "PRIVATE-RUN.md",
    }
    assert prepared.stat().st_mode & 0o077 == 0
    assert all(path.stat().st_mode & 0o077 == 0 for path in prepared.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(prepared)


@pytest.mark.parametrize("marker", ["directory", "file", "symlink"])
def test_prepare_refuses_git_locations(tmp_path: Path, marker: str) -> None:
    path = tmp_path / ".git"
    if marker == "directory":
        path.mkdir()
    elif marker == "file":
        path.write_text("gitdir: invented")
    else:
        path.symlink_to(tmp_path / "missing")
    with pytest.raises(kit.PrivateError, match="LOCATION"):
        kit.prepare(tmp_path / "new-kit")
    assert not (tmp_path / "new-kit").exists()


def test_prepare_refuses_paths_unsafe_in_the_literal_remote_command(tmp_path: Path) -> None:
    with pytest.raises(kit.PrivateError, match="LOCATION"):
        kit.prepare(tmp_path / "bad kit;$()")


def test_repo_source_cannot_compile_collect_or_review() -> None:
    for operation in (kit.setup, kit.report, lambda: kit.record("local")):
        with pytest.raises(kit.PrivateError, match="LOCATION"):
            operation()


@pytest.fixture
def synthetic(prepared: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(kit, "__file__", str(prepared / "private_ssh_descriptors.py"))
    monkeypatch.setattr(kit, "_preflight", lambda: None)

    def compile_only(args: list[str], **kwargs: object) -> SimpleNamespace:
        assert args[0] == "/usr/bin/clang"
        assert kwargs["env"] == kit.SAFE_ENV
        assert kwargs["stdin"] == kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 30 and kwargs["check"] is True
        (prepared / "descriptor-probe").write_bytes(b"INVENTED_BINARY")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", compile_only)
    kit.setup()
    return prepared


def test_exec_preserves_standard_streams_and_adds_only_private_report_instrumentation(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def exec_only(path: str, arguments: list[str], env: dict[str, str]) -> None:
        assert path == arguments[0] == str(synthetic / "descriptor-probe")
        assert len(arguments) == 2 and env == kit.SAFE_ENV
        descriptor = int(arguments[1])
        assert descriptor > 2 and os.get_inheritable(descriptor)
        assert os.fstat(descriptor).st_mode & 0o777 == 0o600
        os.write(descriptor, _observation().model_dump_json().encode())

    monkeypatch.setattr(kit.os, "execve", exec_only)
    for slot in kit.SLOTS:
        kit.record(slot, ssh_context=slot != "local")
    result = kit.report()
    assert result.contexts == "COMPLETE" and result.provenance == "PASS"
    assert result.pty.tty_streams == "ALL"
    assert result.gate_status == "NOT_EVALUATED"
    assert result.endpoint_security_export == "NOT_COLLECTED"
    assert "INVENTED_BINARY" not in result.model_dump_json()
    with pytest.raises(kit.PrivateError, match="DUPLICATE"):
        kit.record("local")


def test_report_keeps_distinct_observations_and_ignores_unrelated_files(synthetic: Path) -> None:
    assert kit.report().contexts == "INCOMPLETE"
    for slot in kit.SLOTS:
        kit._write(
            synthetic / "private" / f"{slot}.json",
            _observation(pipe=slot == "no_pty").model_dump_json().encode(),
        )
    (synthetic / "private" / "unrelated.txt").write_text(_CANARY)
    (synthetic / "known_hosts").write_text(_CANARY)
    result = kit.report()
    assert result.no_pty.stdin_kind == "PIPE"
    assert result.pty.stdin_kind == result.local.stdin_kind == "VNODE"
    assert _CANARY not in result.model_dump_json()


@pytest.mark.parametrize(
    "value", [b"{}", b'{"private":"INVENTED_PRIVATE_CANARY_never_export"}', b"not-json"]
)
def test_partial_or_unknown_probe_data_cannot_pass(synthetic: Path, value: bytes) -> None:
    kit._write(synthetic / "private" / "local.json", value)
    with pytest.raises((kit.PrivateError, ValidationError)):
        kit.report()


@pytest.mark.parametrize("slot", ["no_pty", "pty"])
def test_remote_context_requires_explicit_attestation(synthetic: Path, slot: kit.Slot) -> None:
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit.record(slot)
    assert not (synthetic / "private" / f"{slot}.json").exists()
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit.record("local", ssh_context=True)


def test_changed_code_blocks_collection_and_reporting(synthetic: Path) -> None:
    (synthetic / "ssh_descriptor_probe.c").write_text(_CANARY)
    for operation in (kit.report, lambda: kit.record("local")):
        with pytest.raises(kit.PrivateError, match="DATA"):
            operation()


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "permissions", "size", "fifo"])
def test_owner_only_regular_bounded_file_boundary(tmp_path: Path, damage: str) -> None:
    path = tmp_path / "input"
    if damage == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b"x" * 8193 if damage == "size" else b"invented")
        path.chmod(0o600)
        if damage == "symlink":
            link = tmp_path / "link"
            link.symlink_to(path)
            path = link
        elif damage == "hardlink":
            (tmp_path / "other").hardlink_to(path)
        elif damage == "permissions":
            path.chmod(0o644)
    with pytest.raises((kit.PrivateError, OSError)):
        kit._read(path)


@pytest.mark.parametrize(
    "error", [OSError(_CANARY), ValueError(_CANARY), KeyboardInterrupt(_CANARY)]
)
def test_failure_diagnostics_redact_every_native_detail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: BaseException
) -> None:
    def fail() -> kit.Report:
        raise error

    monkeypatch.setattr(kit, "report", fail)
    assert kit.main(["report", "--private-run"]) == 2
    captured = capsys.readouterr()
    assert _CANARY not in captured.out + captured.err and captured.err == ""
    kit.Report.model_validate_json(captured.out)


def test_parser_redacts_input(capsys: pytest.CaptureFixture[str]) -> None:
    assert kit.main(["record", _CANARY, "--private-run"]) == 2
    captured = capsys.readouterr()
    assert _CANARY not in captured.out + captured.err
    assert kit.Report.model_validate_json(captured.out).error == "INPUT"


def test_probe_uses_only_self_fd_metadata_and_no_content_or_process_inventory() -> None:
    code = (kit.SOURCES / "ssh_descriptor_probe.c").read_text()
    assert "proc_pidinfo(getpid(), PROC_PIDLISTFDS" in code
    assert "proc_pidfdinfo(getpid()," in code
    for forbidden in (
        "read(",
        "fread(",
        "getenv(",
        "proc_listallpids",
        "proc_listpids",
        "eslogger",
        "task_for_pid",
        "system(",
        "popen(",
    ):
        assert forbidden not in code
    launcher = (kit.SOURCES / "RUN-LOCAL.sh").read_text()
    assert launcher.count("127.0.0.1") == 2
    assert " -T " in launcher and " -tt " in launcher
    assert "-F /dev/null -a -x" in launcher
    assert "StrictHostKeyChecking=ask" in launcher
    assert "ClearAllForwardings=yes" in launcher
    assert "sudo" not in launcher

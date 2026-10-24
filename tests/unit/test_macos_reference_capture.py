# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Privacy/delivery tests with invented records only; never invoke native tools."""

import io
import json
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_reference_capture as kit

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.unit.test_macos_endpoint_security_contracts import _file, _process

_PROBE = Path("/private/tmp/invented-kit/private-run-example/process-probe")
_SECRET = "INVENTED_PRIVATE_CANARY_never_export"


def _process_view(pid: int, version: int = 1, path: str | None = None) -> dict[str, object]:
    process = _process(10, pid, 100)
    process["audit_token"][7] = version
    process["parent_audit_token"][7] = 1
    process["executable"] = _file(path or str(_PROBE))
    return process


def _row(family: str, process: dict[str, object], payload: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": 10,
        "event_type": {"fork": 11, "exec": 9, "exit": 15}[family],
        "action_type": 1,
        "action": {"result": {"result_type": 0, "result": {"auth": 0}}},
        "time": "2026-10-24T12:00:00.123456789Z",
        "mach_time": 1,
        "seq_num": 0,
        "global_seq_num": 0,
        "thread": {"thread_id": 1},
        "process": process,
        "event": {family: payload},
    }


def _experiment() -> tuple[list[dict[str, object]], list[kit.Control]]:
    root = _process_view(100)
    rows: list[dict[str, object]] = []
    controls: list[kit.Control] = []
    for index, case in enumerate(("exit7", "signal", "failed_exec", "apple_true")):
        pid = 101 + index
        child = _process_view(pid)
        rows.append(_row("fork", deepcopy(root), {"child": deepcopy(child)}))
        if case != "failed_exec":
            target = _process_view(pid, 2, "/usr/bin/true" if case == "apple_true" else None)
            path = target["executable"]["path"]
            rows.append(
                _row(
                    "exec",
                    child,
                    {
                        "target": deepcopy(target),
                        "script": None,
                        "cwd": _file(str(_PROBE.parent)),
                        "args": [path] if case == "apple_true" else [path, case],
                        "env": [f"{key}={value}" for key, value in kit.SAFE_ENV.items()],
                        "fds": [
                            {"fd": 0, "fdtype": 6, "pipe": {"pipe_id": 123}},
                            {"fd": 1, "fdtype": 1},
                            {"fd": 2, "fdtype": 1},
                        ],
                        "last_fd": 2,
                        "image_cputype": 16777228,
                        "image_cpusubtype": 0,
                        "dyld_exec_path": path,
                    },
                )
            )
            child = target
        status = {"exit7": 1792, "signal": 15, "failed_exec": 768, "apple_true": 0}[case]
        rows.append(_row("exit", child, {"stat": status}))
        controls.append(kit.Control(kind="wait", case=case, pid=pid, value=status))
        if case == "failed_exec":
            controls.append(kit.Control(kind="failed_return", case=case, pid=pid, value=2))
    rows.append(_row("exit", root, {"stat": 0}))
    sequences: dict[int, int] = {}
    for index, row in enumerate(rows):
        event_type = row["event_type"]
        row["mach_time"] = index + 1
        row["global_seq_num"] = index + 1
        row["seq_num"] = sequences.get(event_type, 0)
        sequences[event_type] = row["seq_num"] + 1
    return rows, controls


def _tracker(rows: list[dict[str, object]]) -> kit.StreamFilter:
    tracker = kit.StreamFilter(100, _PROBE)
    tracker.tests_started = True
    for row in rows:
        assert tracker.accept(json.dumps(row).encode())
    return tracker


def test_candidate_checks_pass_complete_invented_experiment_without_opening_gate() -> None:
    rows, controls = _experiment()
    report = kit.analyze(_tracker(rows), controls, complete=True)
    data = report.model_dump()
    assert all(
        value == "PASS"
        for key, value in data.items()
        if key not in {"kit_version", "reference_review", "gate_status", "error", "wire_profile"}
    )
    assert report.reference_review == "REQUIRED"
    assert report.gate_status == "NOT_EVALUATED"
    assert report.wire_profile == "V10_CANDIDATE"
    # Candidate validation cannot change the production v10 event allowlist.
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(rows[1]))


def test_filter_discards_unrelated_records_before_retention() -> None:
    rows, _controls = _experiment()
    ambient = deepcopy(rows[0])
    ambient["process"] = _process_view(999, path=f"/Users/{_SECRET}/app")
    ambient["private_extra"] = {"environment": [_SECRET]}
    tracker = kit.StreamFilter(100, _PROBE)
    assert not tracker.accept(json.dumps(ambient).encode())
    assert tracker.records == []
    assert _SECRET not in kit.analyze(tracker, [], False).model_dump_json()


@pytest.mark.parametrize("change", ["pidversion", "start_time", "root_path"])
def test_filter_rejects_pid_only_or_wrong_root_executable(change: str) -> None:
    rows, _controls = _experiment()
    tracker = kit.StreamFilter(100, _PROBE)
    if change == "root_path":
        rows[0]["process"]["executable"]["path"] = f"/Users/{_SECRET}/other"
        assert not tracker.accept(json.dumps(rows[0]).encode())
    else:
        assert tracker.accept(json.dumps(rows[0]).encode())
        if change == "pidversion":
            rows[1]["process"]["audit_token"][7] += 100
        else:
            rows[1]["process"]["start_time"] = "2026-10-24T12:00:00.123456Z"
        assert not tracker.accept(json.dumps(rows[1]).encode())
    assert len(tracker.records) == (0 if change == "root_path" else 1)


@pytest.mark.parametrize("change", ["target_pid", "target_path", "target_start"])
def test_filter_rejects_unowned_exec_targets(change: str) -> None:
    rows, _controls = _experiment()
    target = rows[1]["event"]["exec"]["target"]
    if change == "target_pid":
        target["audit_token"][5] += 1
    elif change == "target_path":
        target["executable"]["path"] = f"/Users/{_SECRET}/other"
    else:
        target["start_time"] = "2026-10-24T12:00:00.123456Z"
    tracker = kit.StreamFilter(100, _PROBE)
    assert tracker.accept(json.dumps(rows[0]).encode())
    with pytest.raises(kit.PrivateCaptureError, match="^DATA$"):
        tracker.accept(json.dumps(rows[1]).encode())
    assert len(tracker.records) == 1


@pytest.mark.parametrize("change", ["gap", "duplicate", "global_reversal"])
def test_sequence_anomalies_cannot_pass(change: str) -> None:
    rows, controls = _experiment()
    if change == "gap":
        rows[3]["seq_num"] += 1
    elif change == "duplicate":
        rows[3]["seq_num"] = rows[0]["seq_num"]
    else:
        rows[3]["global_seq_num"] = 0
    assert kit.analyze(_tracker(rows), controls, True).sequence_continuity == "FAIL"


@pytest.mark.parametrize(
    "change", ["extra", "missing_null", "version", "boolean", "token", "category", "calendar"]
)
def test_unknown_candidate_shapes_do_not_become_reference_passes(change: str) -> None:
    rows, controls = _experiment()
    row = rows[1]
    if change == "extra":
        row["private_extra"] = _SECRET
    elif change == "missing_null":
        del row["event"]["exec"]["script"]
    elif change == "version":
        row["version"] = 11
    elif change == "boolean":
        row["schema_version"] = True
    elif change == "token":
        row["process"]["parent_audit_token"] = {"pid": 100}
    elif change == "category":
        del row["process"]["cs_validation_category"]
    else:
        row["time"] = "2026-99-99T12:00:00.123456789Z"
    report = kit.analyze(_tracker(rows), controls, True)
    if change == "version":
        assert report.wire_profile == "MIXED"
        assert report.message_shapes == "INCONCLUSIVE"
        assert report.candidate_v10_shapes == "INCONCLUSIVE"
        assert report.error == "WIRE_PROFILE"
    elif change == "boolean":
        assert report.wire_profile == "INVALID"
        assert report.message_shapes == "FAIL"
    else:
        assert report.message_shapes == "FAIL"
        assert report.candidate_v10_shapes == "FAIL"
    assert _SECRET not in report.model_dump_json()


@pytest.mark.parametrize(
    ("schema", "version", "profile"),
    [
        (1, 11, "V11_UNQUALIFIED"),
        (1, 12, "OTHER_UNQUALIFIED"),
        (1, 9, "OTHER_UNQUALIFIED"),
        (2, 10, "SCHEMA_UNQUALIFIED"),
        (1, True, "INVALID"),
        (1, 0, "INVALID"),
    ],
)
def test_observed_versions_are_preserved_without_unqualified_native_passes(
    schema: int, version: object, profile: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(_raw: bytes) -> bool:
        pytest.fail("An unqualified wire profile must not enter the v10 validator")

    monkeypatch.setattr(kit, "_candidate_shape", forbidden)
    rows, controls = _experiment()
    for row in rows:
        row["schema_version"] = schema
        row["version"] = version
        row["new_private_field"] = _SECRET
    tracker = _tracker(rows)
    assert tracker.records == rows
    report = kit.analyze(tracker, controls, True)
    assert report.kit_version == 3
    assert report.wire_profile == profile
    assert report.error == "WIRE_PROFILE"
    assert report.message_shapes == ("FAIL" if profile == "INVALID" else "INCONCLUSIVE")
    assert report.candidate_v10_shapes == "INCONCLUSIVE"
    assert report.gate_status == "NOT_EVALUATED"
    assert report.fork_exec_exit_linkage == "PASS"
    assert _SECRET not in report.model_dump_json()


def test_foreign_executable_cannot_enter_tracked_process_family() -> None:
    rows, _controls = _experiment()
    tracker = kit.StreamFilter(100, _PROBE)
    assert tracker.accept(json.dumps(rows[0]).encode())
    rows[1]["process"]["executable"]["path"] = f"/Users/{_SECRET}/foreign"
    with pytest.raises(kit.PrivateCaptureError, match="^DATA$"):
        tracker.accept(json.dumps(rows[1]).encode())
    assert len(tracker.records) == 1


@pytest.mark.parametrize(
    "change",
    [
        "wait",
        "exit",
        "errno",
        "argv",
        "env",
        "cwd",
        "fd",
        "parent",
        "credentials",
        "missing",
        "incomplete",
    ],
)
def test_control_mismatches_or_incomplete_capture_fail(change: str) -> None:
    rows, controls = _experiment()
    if change == "wait":
        controls[0] = controls[0].model_copy(update={"value": 0})
    elif change == "exit":
        rows[2]["event"]["exit"]["stat"] = 0
    elif change == "errno":
        controls[3] = controls[3].model_copy(update={"value": 13})
    elif change == "argv":
        rows[1]["event"]["exec"]["args"] = [_SECRET]
    elif change == "env":
        rows[1]["event"]["exec"]["env"].append(f"SECRET={_SECRET}")
    elif change == "cwd":
        rows[1]["event"]["exec"]["cwd"]["path"] = f"/Users/{_SECRET}"
    elif change == "fd":
        rows[1]["event"]["exec"]["fds"][0] = {"fd": 0, "fdtype": 1}
    elif change == "parent":
        rows[1]["event"]["exec"]["target"]["parent_audit_token"][7] += 1
    elif change == "credentials":
        rows[1]["event"]["exec"]["target"]["audit_token"][1] += 1
    elif change == "missing":
        rows = rows[:-1]
    report = kit.analyze(_tracker(rows), controls, change != "incomplete")
    assert "FAIL" in report.model_dump().values()
    assert _SECRET not in report.model_dump_json()


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"value":NaN}', b"[]", b"not JSON"])
def test_malformed_json_never_enters_retained_records(raw: bytes) -> None:
    tracker = kit.StreamFilter(100, _PROBE)
    with pytest.raises((ValueError, kit.PrivateCaptureError)):
        tracker.accept(raw)
    assert tracker.records == []


def test_input_and_retention_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    rows, _controls = _experiment()
    tracker = kit.StreamFilter(100, _PROBE)
    monkeypatch.setattr(kit, "MAX_LINE_BYTES", 4)
    with pytest.raises(kit.PrivateCaptureError, match="^DATA$"):
        tracker.accept(json.dumps(rows[0]).encode())
    monkeypatch.setattr(kit, "MAX_LINE_BYTES", 1_048_576)
    monkeypatch.setattr(kit, "MAX_RETAINED", 0)
    with pytest.raises(kit.PrivateCaptureError, match="^DATA$"):
        tracker.accept(json.dumps(rows[0]).encode())
    assert tracker.records == []


def test_prepare_copies_only_code_and_does_not_call_native_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Native operation during preparation")

    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    target = kit.prepare(tmp_path / "kit")
    assert {item.name for item in target.iterdir()} == {
        "private_capture.py",
        "process_probe.c",
        "PRIVATE-RUN.md",
    }
    assert target.stat().st_mode & 0o777 == 0o700
    assert all(item.stat().st_mode & 0o777 == 0o600 for item in target.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(target)


@pytest.mark.parametrize("marker", ["directory", "file", "broken_link"])
def test_prepare_rejects_git_checkout_or_worktree(tmp_path: Path, marker: str) -> None:
    if marker == "directory":
        (tmp_path / ".git").mkdir()
    elif marker == "file":
        (tmp_path / ".git").write_text("gitdir: invented\n")
    else:
        (tmp_path / ".git").symlink_to(tmp_path / "missing-git")
    with pytest.raises(kit.PrivateCaptureError, match="^LOCATION$"):
        kit.prepare(tmp_path / "kit")
    assert not (tmp_path / "kit").exists()


def test_capture_from_checkout_is_rejected_before_host_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> None:
        pytest.fail("Host inspection inside Git")

    monkeypatch.setattr(kit.platform, "system", forbidden)
    with pytest.raises(kit.PrivateCaptureError, match="^LOCATION$"):
        kit.capture()


@pytest.mark.parametrize("command", ["preflight", "capture"])
@pytest.mark.parametrize(
    ("uid", "family", "architecture", "version", "code"),
    [
        (0, "Darwin", "arm64", "26.0", "ROOT_USER"),
        (123, _SECRET, "arm64", "26.0", "OS_FAMILY"),
        (123, "Darwin", _SECRET, "26.0", "PYTHON_ARCH"),
        (123, "Darwin", "arm64", f"25.{_SECRET}", "OS_VERSION"),
    ],
)
def test_platform_failures_have_distinct_fixed_codes_before_any_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    uid: int,
    family: str,
    architecture: str,
    version: str,
    code: str,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Platform failure attempted to build, collect or create output")

    tmp_path.chmod(0o700)
    monkeypatch.setattr(kit, "__file__", str(tmp_path / "private_capture.py"))
    monkeypatch.setattr(kit.os, "geteuid", (lambda: uid) if family == "Darwin" else forbidden)
    monkeypatch.setattr(kit.platform, "system", lambda: family)
    monkeypatch.setattr(kit.platform, "machine", lambda: architecture)
    monkeypatch.setattr(kit, "_quiet_command", lambda _args, _cwd: version.encode())
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.tempfile, "mkdtemp", forbidden)
    monkeypatch.setattr(kit, "_private_file", forbidden)
    monkeypatch.setattr(kit, "_collect", forbidden)
    args = [command] + (["--private-run"] if command == "capture" else [])
    assert kit.main(args) == 2
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    report = kit.Report.model_validate_json(output.out)
    assert report.error == code
    assert report.target_platform == "INCONCLUSIVE"
    assert report.gate_status == "NOT_EVALUATED"


@pytest.mark.parametrize("version", ["26.0", "27.0.1", "15.7", "28.987654321"])
def test_successful_preflight_never_builds_collects_or_writes_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    version: str,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Preflight must not build, collect or create output")

    def fake_version(args: list[str], cwd: Path) -> bytes:
        assert args == ["/usr/bin/sw_vers", "-productVersion"]
        assert cwd == tmp_path
        return version.encode()

    tmp_path.chmod(0o700)
    monkeypatch.setattr(kit, "__file__", str(tmp_path / "private_capture.py"))
    monkeypatch.setattr(kit.os, "geteuid", lambda: 123)
    monkeypatch.setattr(kit.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(kit.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(kit, "_quiet_command", fake_version)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.tempfile, "mkdtemp", forbidden)
    monkeypatch.setattr(kit, "_private_file", forbidden)
    monkeypatch.setattr(kit, "_collect", forbidden)
    assert kit.main(["preflight"]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert version not in output.out
    report = kit.Report.model_validate_json(output.out)
    assert report.error == "NONE"
    assert report.target_platform == "PASS"
    assert report.probe_controls == "INCONCLUSIVE"
    assert report.gate_status == "NOT_EVALUATED"


@pytest.mark.parametrize("args", [[], ["capture"], ["capture", "--private-run", _SECRET]])
def test_cli_requires_explicit_private_run_and_never_echoes_arguments(
    args: list[str], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "capture", lambda: pytest.fail("Unexpected live execution"))
    assert kit.main(args) == 2
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert kit.Report.model_validate_json(output.out).error == "INPUT"


@pytest.mark.parametrize(
    "exception",
    [
        OSError(_SECRET),
        ValueError(_SECRET),
        KeyError(_SECRET),
        subprocess.CalledProcessError(1, [_SECRET]),
    ],
)
def test_cli_exceptions_do_not_expose_values(
    exception: BaseException, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail() -> kit.Report:
        raise exception

    monkeypatch.setattr(kit, "capture", fail)
    assert kit.main(["capture", "--private-run"]) == 2
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert kit.Report.model_validate_json(output.out).error == "INTERNAL"


def test_unexpected_exception_hook_never_formats_exception(
    capfd: pytest.CaptureFixture[str],
) -> None:
    class DangerousError(RuntimeError):
        def __str__(self) -> str:
            pytest.fail("Exception must not be formatted")

    kit._private_exception_hook(DangerousError, DangerousError(_SECRET), None)
    output = capfd.readouterr()
    assert output.err == "PRIVATE_REFERENCE_INTERNAL_ERROR\n"
    assert not output.out


def test_report_cannot_include_native_fields_or_free_text() -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({"pid": 100, "path": _SECRET})
    with pytest.raises(ValidationError):
        kit.Report.model_validate({"error": _SECRET})


def test_unqualified_wire_report_is_not_a_success_exit(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    report = kit.Report(error="WIRE_PROFILE", wire_profile="V11_UNQUALIFIED")
    monkeypatch.setattr(kit, "capture", lambda: report)
    assert kit.main(["capture", "--private-run"]) == 1
    exported = kit.Report.model_validate_json(capsys.readouterr().out)
    assert exported.message_shapes == "INCONCLUSIVE"
    assert exported.gate_status == "NOT_EVALUATED"


def test_legacy_fixed_report_remains_readable() -> None:
    report = kit.Report.model_validate({"kit_version": 1, "error": "OS_MAJOR"})
    assert report.wire_profile == "NOT_OBSERVED"
    assert report.message_shapes == "INCONCLUSIVE"


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "malformed",
        "interrupted",
        "read_error",
        "startup",
        "partial",
        "unqualified",
        "no_stream",
        "no_identity",
        "no_image",
        "missing_warmup_exit",
        "late_ready",
        "timeout",
    ],
)
def test_collect_filters_before_disk_and_cleans_up_even_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    rows, controls = _experiment()
    if failure == "unqualified":
        for row in rows:
            row["version"] = 11
            row["new_private_field"] = "INVENTED_RELATED_ONLY"
    ambient = deepcopy(rows[0])
    ambient["process"] = _process_view(999)
    ambient["private_extra"] = _SECRET
    ready_child = _process_view(199)
    warmup = [
        _row("fork", _process_view(100), {"child": ready_child}),
        _row("exit", ready_child, {"stat": 0}),
    ]
    if failure == "missing_warmup_exit":
        warmup.pop()
    all_rows = [ambient, *warmup, *rows]
    if failure == "no_identity":
        for row in all_rows:
            row["process"]["audit_token"] = {"private_unknown": _SECRET}
    if failure == "no_image":
        for row in all_rows:
            row["process"]["executable"]["path"] = f"/Users/{_SECRET}/other"
    sequences: dict[int, int] = {}
    for index, row in enumerate(all_rows):
        family = row["event_type"]
        row["seq_num"] = sequences.get(family, 0)
        sequences[family] = row["seq_num"] + 1
        row["global_seq_num"] = row["mach_time"] = index + 1
    original = [json.dumps(row, separators=(", ", ": ")).encode() + b"\n" for row in rows]
    source = tmp_path / "invented-input"
    source.write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in [ambient, *warmup])
        + b"".join(original)
    )
    if failure == "malformed":
        source.write_bytes(_SECRET.encode() + b"\n")
    elif failure == "partial":
        source.write_bytes(b'{"private_partial":"' + _SECRET.encode())
    elif failure == "no_stream":
        source.write_bytes(b"")
    elif failure == "missing_warmup_exit":
        source.write_bytes(json.dumps(warmup[0]).encode() + b"\n")
    source_file = source.open("rb")

    class Collector:
        stdout = source_file
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def send_signal(self, value: int) -> None:
            assert value == kit.signal.SIGINT
            self.returncode = 0

        def wait(self, timeout: int) -> int:
            return 0

    class Child:
        pid = 100
        returncode: int | None = None
        stdin: io.BytesIO | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: int) -> int:
            assert self.returncode is not None
            return self.returncode

        def terminate(self) -> None:
            self.returncode = -kit.signal.SIGTERM

        def kill(self) -> None:
            self.returncode = -kit.signal.SIGKILL

    child = Child()
    protocol: io.BufferedWriter | None = None

    class Commands(io.BytesIO):
        readiness_count: int = 0

        def write(self, value: bytes) -> int:
            assert value in (b"R", b"G")
            if value == b"R":
                self.readiness_count += 1
            else:
                # The fake probe also refuses to run until the native warm-up
                # has been consumed, not just because a timer has expired.
                assert self.getvalue().startswith(b"R")
                assert protocol is not None
                for control in controls:
                    protocol.write(control.model_dump_json().encode() + b"\n")
                child.returncode = 0
            return super().write(value)

    commands = Commands()
    child.stdin = commands

    class Selector:
        def __enter__(self) -> "Selector":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def register(self, *_args: object) -> None:
            return None

        def select(self, timeout: float) -> list[tuple[SimpleNamespace, int]]:
            if failure == "timeout" or (failure == "late_ready" and commands.readiness_count < 2):
                return []
            return [(SimpleNamespace(fd=source_file.fileno()), 1)]

    collector = Collector()
    if failure == "startup":
        collector.returncode = 1

    def fake_popen(args: list[str], **kwargs: object) -> object:
        assert kwargs["env"] == kit.SAFE_ENV
        assert kwargs["stderr"] == subprocess.DEVNULL
        if args[0] == "/usr/bin/sudo":
            assert kwargs["start_new_session"] is False
            assert args == ["/usr/bin/sudo", "-n", "/usr/bin/eslogger", "fork", "exec", "exit"]
            return collector
        assert args == [str(_PROBE)]
        nonlocal protocol
        protocol = kwargs["stdout"]
        return child

    monkeypatch.setattr(kit.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(kit.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(
        kit,
        "_owned_images",
        lambda _probe: {
            str(_PROBE): kit.OwnedImage(path=str(_PROBE)),
            "/usr/bin/true": kit.OwnedImage(path="/usr/bin/true"),
        },
    )
    monkeypatch.setattr(kit, "CAPTURE_SECONDS", 0.01)
    monkeypatch.setattr(kit, "READINESS_SECONDS", 0.01)
    if failure in {"late_ready", "timeout"}:
        elapsed = 0.0

        def monotonic() -> float:
            nonlocal elapsed
            elapsed += 0.1
            return elapsed

        monkeypatch.setattr(kit.time, "monotonic", monotonic)
        monkeypatch.setattr(kit, "READINESS_SECONDS", 10.0)
    if failure in ("interrupted", "read_error"):

        def broken_read(_fd: int, _size: int) -> bytes:
            if failure == "interrupted":
                raise KeyboardInterrupt
            raise OSError(_SECRET)

        monkeypatch.setattr(kit.os, "read", broken_read)
    early = {"partial", "no_stream", "no_identity", "no_image", "missing_warmup_exit", "timeout"}
    if failure not in (None, "unqualified", "late_ready", *early):
        with pytest.raises((ValueError, KeyboardInterrupt, OSError)):
            kit._collect(tmp_path, _PROBE)
        assert source_file.closed
        assert collector.returncode == (1 if failure == "startup" else 0)
        assert _SECRET.encode() not in (tmp_path / "probe-events.jsonl").read_bytes()
        if failure != "startup":
            assert child.returncode == -kit.signal.SIGKILL
            assert child.stdin.closed
        return
    tracker, observed, complete = kit._collect(tmp_path, _PROBE)
    retained = (tmp_path / "probe-events.jsonl").read_bytes()
    assert retained == (b"" if failure in early else b"".join(original))
    assert _SECRET.encode() not in retained
    assert kit.analyze(tracker, observed, complete).bounded_delivery == (
        "FAIL" if failure in early else "PASS"
    )
    assert collector.returncode == 0
    report = kit.analyze(tracker, observed, complete)
    assert report.collector_ready == ("FAIL" if failure in early else "PASS")
    assert child.stdin.closed
    if failure in early:
        assert observed == []
        assert report.probe_controls == report.fork_exec_exit_linkage == "INCONCLUSIVE"
        assert report.stream_delivery == (
            "FAIL" if failure in {"no_stream", "partial", "timeout"} else "PASS"
        )
        assert report.probe_identity_seen == (
            "FAIL" if failure in {"no_stream", "partial", "no_identity", "timeout"} else "PASS"
        )
        assert report.probe_image_seen == ("PASS" if failure == "missing_warmup_exit" else "FAIL")
    if failure == "late_ready":
        assert commands.readiness_count == 2
    elif failure == "timeout":
        assert commands.readiness_count == kit.MAX_READINESS_PROBES
    if failure == "unqualified":
        assert b"INVENTED_RELATED_ONLY" in retained
        assert "INVENTED_RELATED_ONLY" not in report.model_dump_json()
        assert report.wire_profile == "V11_UNQUALIFIED"
        assert report.message_shapes == "INCONCLUSIVE"
    assert (tmp_path / "probe-events.jsonl").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("token_form", ["array", "named", "val"])
@pytest.mark.parametrize("birth_form", ["string", "timeval"])
def test_explicit_identity_forms_preserve_scope_without_qualifying_unknown_wire(
    token_form: str, birth_form: str
) -> None:
    names = ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")

    def convert(value: object) -> object:
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key.endswith("audit_token"):
                if token_form == "named":
                    item = dict(zip(names, item, strict=True))
                elif token_form == "val":
                    item = {"val": item}
                result[key] = item
            elif key == "start_time" and birth_form == "timeval":
                result[key] = {"tv_sec": 1234567890, "tv_usec": 123456}
            else:
                result[key] = convert(item)
        return result

    rows, controls = _experiment()
    rows = convert(rows)
    for row in rows:
        row["version"] = 11
    tracker = _tracker(rows)
    report = kit.analyze(tracker, controls, True)
    assert tracker.records == rows
    assert report.probe_identity_seen == report.probe_image_seen == "PASS"
    assert report.fork_exec_exit_linkage == report.controlled_exec_inputs == "PASS"
    assert report.bounded_delivery == "PASS"
    assert report.message_shapes == "INCONCLUSIVE"
    assert report.wire_profile == "V11_UNQUALIFIED"
    assert report.gate_status == "NOT_EVALUATED"


@pytest.mark.parametrize(
    "mutation",
    [
        "pid_only",
        "partial_named",
        "extra_named",
        "short_array",
        "bool_word",
        "bad_word",
        "no_birth",
        "partial_birth",
        "extra_birth",
        "bool_birth",
        "bad_microseconds",
    ],
)
def test_identity_never_falls_back_to_partial_tokens_or_pid_only(mutation: str) -> None:
    process = _process_view(100)
    names = ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")
    if mutation == "pid_only":
        process["audit_token"] = {"pid": 100}
    elif mutation in {"partial_named", "extra_named"}:
        token = dict(zip(names, process["audit_token"], strict=True))
        if mutation == "partial_named":
            del token["pidversion"]
        else:
            token["private_extra"] = _SECRET
        process["audit_token"] = token
    elif mutation == "short_array":
        process["audit_token"].pop()
    elif mutation in {"bool_word", "bad_word"}:
        process["audit_token"][0] = True if mutation == "bool_word" else -1
    elif mutation == "no_birth":
        del process["start_time"]
    else:
        birth = {"tv_sec": 1234567890, "tv_usec": 123456}
        if mutation == "partial_birth":
            del birth["tv_usec"]
        elif mutation == "extra_birth":
            birth["private_extra"] = _SECRET
        elif mutation == "bool_birth":
            birth["tv_sec"] = True
        else:
            birth["tv_usec"] = 1_000_000
        process["start_time"] = birth
    with pytest.raises((kit.PrivateCaptureError, ValidationError)):
        kit._identity(process)


def test_owned_image_alias_uses_exact_file_objects_without_resolving_native_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sampled: list[Path] = []

    def stat(path: Path) -> SimpleNamespace:
        sampled.append(path)
        assert path in {_PROBE, Path("/usr/bin/true")}
        return SimpleNamespace(st_dev=123, st_ino=9002 if path.name == "true" else 9001)

    monkeypatch.setattr(Path, "stat", stat)
    images = kit._owned_images(_PROBE)
    assert sampled == [_PROBE, Path("/usr/bin/true")]
    rows, controls = _experiment()

    def alias(value: object) -> None:
        if isinstance(value, list):
            for item in value:
                alias(item)
        elif isinstance(value, dict):
            if "executable" in value:
                executable = value["executable"]
                if executable["path"] == "/usr/bin/true":
                    executable["stat"]["st_ino"] = 9002
                executable["path"] = f"/invented-alias/{_SECRET}"
            for item in value.values():
                alias(item)

    alias(rows)
    tracker = kit.StreamFilter(100, _PROBE, images)
    tracker.tests_started = True
    for row in rows:
        assert tracker.accept(json.dumps(row).encode())
    assert kit.analyze(tracker, controls, True).controlled_exec_inputs == "PASS"
    assert _SECRET not in kit.analyze(tracker, controls, True).model_dump_json()
    # A matching path cannot override a mismatched object or truncation flag.
    process = _process_view(100)
    process["executable"]["stat"]["st_ino"] = 9999
    assert not kit._matches_image(process, images[str(_PROBE)])
    process["executable"]["stat"]["st_ino"] = 9001
    process["executable"]["path_truncated"] = True
    assert not kit._matches_image(process, images[str(_PROBE)])
    assert sampled == [_PROBE, Path("/usr/bin/true")]

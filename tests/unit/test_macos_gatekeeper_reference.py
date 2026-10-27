# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented inputs only: no native preflight, binary execution, collectors or sockets."""

import io
import json
import os
import shutil
import signal
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_gatekeeper_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _record
from tests.unit.test_macos_native_contracts import _log_record

_CANARY = "INVENTED_PRIVATE_CANARY_never_export"
_TOKEN = "b" * 32
_HASH = "a" * 40


def _shape_row() -> dict[str, object]:
    row = _log_record()
    row["processImagePath"] = "/usr/libexec/syspolicyd"
    row["eventMessage"] = f"{_CANARY} {_config().app_name}"
    return row


@pytest.fixture
def shape_capture(synthetic: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    summary = kit.Report(
        provenance="PASS",
        target_platform="PASS",
        bounded_collection="PASS",
        collector_cleanup="PASS",
        test_item_policy_records="OBSERVED",
        unified_log_shapes="FAIL",
    ).model_dump()
    summary["kit_version"] = 1
    kit._write(synthetic / "private/capture.json", json.dumps(summary).encode())
    row = _shape_row()
    row["eventMessage"] = f"{_CANARY} {kit._config(synthetic).app_name}"
    kit._write(synthetic / "private/test-ul.jsonl", json.dumps(row).encode() + b"\n")

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline review attempted a native operation")

    monkeypatch.setattr(kit, "_command", forbidden)
    monkeypatch.setattr(kit, "_preflight", forbidden)
    monkeypatch.setattr(kit, "_platform_info", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    return synthetic


def _config() -> kit.Config:
    return kit.Config(token=_TOKEN, cdhash=_HASH, os_release="27.0", os_build="26A123", digests={})


@pytest.mark.parametrize("field", tuple(kit.Report.model_fields))
def test_report_leaves_cannot_contain_arbitrary_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A synthetic kit test attempted native execution or a network listener")

    monkeypatch.setattr(kit, "_preflight", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit, "HTTPServer", forbidden)
    return kit.prepare(tmp_path / "invented-kit")


def test_prepare_copies_only_code_and_instructions(prepared: Path) -> None:
    assert {path.name for path in prepared.iterdir()} == set(kit.CODE_FILES)
    assert prepared.stat().st_mode & 0o077 == 0
    assert all(path.stat().st_mode & 0o077 == 0 for path in prepared.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(prepared)


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_prepare_refuses_git_ancestors(tmp_path: Path, kind: str) -> None:
    marker = tmp_path / ".git"
    if kind == "file":
        marker.write_text("gitdir: invented")
    elif kind == "directory":
        marker.mkdir()
    else:
        marker.symlink_to(tmp_path / "missing")
    with pytest.raises(kit.PrivateError, match="LOCATION"):
        kit.prepare(tmp_path / "never-created")
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize(
    "operation",
    [
        kit.setup,
        kit.serve,
        kit.control,
        lambda: kit.capture(browser_download=True),
        lambda: kit.report("BLOCK_ALERT"),
    ],
)
def test_repo_copy_cannot_run_private_operations(operation: object) -> None:
    with pytest.raises(kit.PrivateError, match="LOCATION"):
        operation()


@pytest.fixture
def synthetic(prepared: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(kit, "__file__", str(prepared / "private_gatekeeper.py"))
    monkeypatch.setattr(kit, "_preflight", lambda: None)
    monkeypatch.setattr(kit, "_platform_info", lambda _root: ("27.0", "26A123"))

    def command(args: list[str], **kwargs: object) -> SimpleNamespace:
        assert kwargs["cwd"] == prepared
        assert kwargs["env"] == kit.SAFE_ENV
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["timeout"] == 30 and kwargs["check"] is True
        if args[0] == "/usr/bin/clang":
            Path(args[-1]).write_bytes(b"INVENTED_BINARY_" + Path(args[-1]).name.encode())
        elif args[0] == "/usr/bin/ditto":
            Path(args[-1]).write_bytes(b"INVENTED_ARCHIVE")
        else:
            assert args[0] == "/usr/bin/codesign"
        return SimpleNamespace(stdout=b"", stderr=f"CDHash={_HASH}\n".encode())

    monkeypatch.setattr(kit.subprocess, "run", command)
    kit.setup()
    return prepared


def _delivery(root: Path, monkeypatch: pytest.MonkeyPatch) -> kit.Config:
    config = kit._config(root)
    original = root / "private/original" / config.app_name
    shutil.copytree(original, root / "private/downloads" / config.app_name)
    shutil.copyfile(root / "private/probe.zip", root / "private/downloads/probe.zip")
    kit._write(root / "private/delivered", b"ARCHIVE_SERVED\n")
    monkeypatch.setattr(
        kit, "_quarantine", lambda _root, path: "ABSENT" if "original" in path.parts else "PRESENT"
    )
    return config


def test_setup_has_one_fresh_identity_and_no_launch_or_listener(synthetic: Path) -> None:
    config = kit._config(synthetic)
    assert len(config.token) == 32 and config.cdhash == _HASH
    assert len(config.digests) == len(kit.CODE_FILES) + 5
    assert not (synthetic / "private/marker").exists()
    with pytest.raises(FileExistsError):
        kit.setup()


@pytest.mark.parametrize(
    "name",
    [
        "private_gatekeeper.py",
        "marker_probe.c",
        "metadata_probe.m",
        "collector_guard.c",
        "private/metadata-probe",
        "private/collector-guard",
        "private/probe.zip",
    ],
)
def test_changed_code_or_binaries_fail_provenance(synthetic: Path, name: str) -> None:
    (synthetic / name).write_bytes(b"INVENTED_CHANGED")
    with pytest.raises(kit.PrivateError, match="DATA"):
        kit._config(synthetic)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "oversize", "fifo"])
def test_private_reader_rejects_unsafe_files(tmp_path: Path, kind: str) -> None:
    source, path = tmp_path / "source", tmp_path / "input"
    source.write_bytes(b"invented")
    source.chmod(0o600)
    if kind == "symlink":
        path.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b"x" * 100)
        path.chmod(0o644 if kind == "public" else 0o600)
    with pytest.raises((kit.PrivateError, OSError)):
        kit._read(path, 32)


@pytest.mark.parametrize(
    "method,target,host,origin",
    [
        ("GET", "/", "127.0.0.1:1234", None),
        ("GET", "/../private/config.json", "127.0.0.1:1234", None),
        ("GET", f"/{_TOKEN}/probe.zip?secret", "127.0.0.1:1234", None),
        ("POST", f"/{_TOKEN}/probe.zip", "127.0.0.1:1234", None),
        ("GET", f"/{_TOKEN}/probe.zip", "attacker.example:1234", None),
        ("GET", f"/{_TOKEN}/probe.zip", "127.0.0.1:1234", "https://attacker.example"),
    ],
)
def test_server_policy_has_no_listing_traversal_uploads_or_foreign_origins(
    method: str, target: str, host: str, origin: str | None
) -> None:
    status, headers, body = kit.response(
        method, target, host, origin, port=1234, token=_TOKEN, archive=b"invented"
    )
    assert status == 404 and body == b""
    assert headers == {"Content-Length": "0", "Connection": "close"}


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_server_policy_serves_exact_bytes_without_cache_or_external_content(method: str) -> None:
    status, headers, body = kit.response(
        method,
        f"/{_TOKEN}/probe.zip",
        "127.0.0.1:1234",
        None,
        port=1234,
        token=_TOKEN,
        archive=b"invented",
    )
    assert status == 200 and body == (b"invented" if method == "GET" else b"")
    assert headers["Content-Length"] == "8" and headers["Cache-Control"] == "no-store"
    assert "Access-Control-Allow-Origin" not in headers


def test_server_binds_only_loopback_and_suppresses_handler_diagnostics(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    class Server:
        def __init__(self, address: tuple, handler: type) -> None:
            assert address == ("127.0.0.1", 0)
            self.server_address = ("127.0.0.1", 1234)
            instance = object.__new__(handler)
            instance.log_message(_CANARY)
            self.handle_error(None, _CANARY)

        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def handle_request(self) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(kit, "HTTPServer", Server)
    assert kit.main(["serve", "--private-run"]) == 0
    output = capsys.readouterr().out
    assert "http://127.0.0.1:1234/" in output
    assert "PRIVATE_SERVER_STOPPED" in output and _CANARY not in output


def test_download_requires_delivery_exact_content_signature_and_quarantine(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _delivery(synthetic, monkeypatch)
    app, result = kit._download(synthetic, config)
    assert app.parent == synthetic / "private/downloads"
    assert result.same_executable == result.signature_integrity == "PASS"
    assert result.archive_quarantine == result.app_quarantine == "PRESENT"
    monkeypatch.setattr(kit, "_quarantine", lambda *_args: "ABSENT")
    with pytest.raises(kit.PrivateError, match="QUARANTINE"):
        kit._download(synthetic, config)


@pytest.mark.parametrize("item", ["probe.zip", "app_binary", "app_symlink"])
def test_changed_or_relocated_download_is_never_launched(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, item: str
) -> None:
    config = _delivery(synthetic, monkeypatch)
    app = synthetic / "private/downloads" / config.app_name
    if item == "probe.zip":
        (app.parent / "probe.zip").write_bytes(b"changed")
    elif item == "app_binary":
        (app / "Contents/MacOS/Probe").write_bytes(b"changed")
    else:
        shutil.rmtree(app)
        app.symlink_to(synthetic / "private/original" / config.app_name)
    with pytest.raises(kit.PrivateError):
        kit.capture(browser_download=True)
    assert not (synthetic / "private/test-ul.jsonl").exists()


def _ul(config: kit.Config, *, readiness: bool = False) -> dict:
    row = _log_record()
    row["processImagePath"] = (
        "/private/tmp/invented/metadata-probe" if readiness else "/usr/libexec/syspolicyd"
    )
    row["eventMessage"] = (
        config.readiness_tag
        if readiness
        else f"Invented test-item message {config.app_name} {_CANARY}"
    )
    return row


def _es(config: kit.Config, *, family: str = "exec", helper: bool = False) -> dict:
    row = _record(11, family)
    view = row["event"]["exec"]["target"] if family == "exec" else row["process"]
    view["executable"]["path"] = (
        "/private/tmp/invented/metadata-probe"
        if helper
        else f"/private/tmp/invented/{config.app_name}/Contents/MacOS/Probe"
    )
    view["cdhash"] = config.cdhash
    # Match the post-exec identity for exit.
    if family == "exit":
        view["audit_token"]["pidversion"] += 1
    return row


def test_readiness_requires_both_own_ul_message_and_own_exec_exit_identity() -> None:
    config = _config()
    tracker = kit.Tracker(config, Path("/private/tmp/invented/metadata-probe"))
    tracker.ready_pids.add(1200)
    assert not tracker.accept("ul", json.dumps(_ul(config, readiness=True)).encode())
    assert tracker.ul_ready and not tracker.es_ready
    assert not tracker.accept("es", json.dumps(_es(config, helper=True)).encode())
    assert not tracker.es_ready
    assert not tracker.accept("es", json.dumps(_es(config, helper=True, family="exit")).encode())
    assert tracker.es_ready and not any(tracker.retained.values())


@pytest.mark.parametrize(
    "change", ["unrelated", "writer", "redacted", "hash_only_in_unknown_field"]
)
def test_unified_filter_discards_unrelated_or_uncorrelated_rows(change: str) -> None:
    config = _config()
    tracker = kit.Tracker(config, Path("/private/tmp/invented/metadata-probe"))
    tracker.started = True
    row = _ul(config)
    if change == "writer":
        row["processImagePath"] = (
            "/Applications/InventedPersonal.app/Contents/MacOS/InventedPersonal"
        )
    else:
        row["eventMessage"] = "<private>" if change == "redacted" else _CANARY
        if change == "hash_only_in_unknown_field":
            row["unrelated"] = config.cdhash
    assert not tracker.accept("ul", json.dumps(row).encode())
    assert not tracker.retained["ul"]


def test_filter_retains_original_item_bytes_and_known_shapes_without_disclosing_values() -> None:
    config = _config()
    tracker = kit.Tracker(config, Path("/private/tmp/invented/metadata-probe"))
    tracker.started = True
    assert tracker.accept("ul", json.dumps(_ul(config)).encode())
    assert tracker.accept("es", json.dumps(_es(config)).encode())
    assert tracker.accept("es", json.dumps(_es(config, family="exit")).encode())
    assert tracker.exec_seen and tracker.exit_seen
    assert kit._shape(tracker.ul_valid) == kit._shape(tracker.es_valid) == "PASS"
    assert _CANARY not in kit.Report().model_dump_json()


@pytest.mark.parametrize("change", ["pid_reuse", "wrong_hash", "wrong_image", "actor_only"])
def test_es_filter_does_not_adopt_other_processes_or_reused_pids(change: str) -> None:
    config = _config()
    tracker = kit.Tracker(config, Path("/private/tmp/invented/metadata-probe"))
    tracker.started = True
    assert tracker.accept("es", json.dumps(_es(config)).encode())
    row = _es(config, family="exit")
    if change == "pid_reuse":
        row["process"]["audit_token"]["pidversion"] += 1
        row["process"]["executable"]["path"] = "/unrelated"
    elif change == "wrong_hash":
        row = _es(config)
        row["event"]["exec"]["target"]["cdhash"] = "c" * 40
    elif change == "wrong_image":
        row = _es(config)
        row["event"]["exec"]["target"]["executable"]["path"] = "/unrelated"
    else:
        row = _es(config)
        row["process"] = deepcopy(row["event"]["exec"]["target"])
        row["event"]["exec"]["target"]["executable"]["path"] = "/unrelated"
    assert not tracker.accept("es", json.dumps(row).encode())


def test_limits_and_malformed_rows_cannot_become_diagnostics_or_unbounded_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = kit.Tracker(_config(), Path("/invented/helper"))
    tracker.started = True
    for data in (b"[]", b"{bad", b'{"a":1,"a":2}', b'{"x":NaN}', b"\xff"):
        assert not tracker.accept("ul", data)
    monkeypatch.setattr(kit, "MAX_RETAINED", 1)
    assert tracker.accept("ul", json.dumps(_ul(_config())).encode())
    with pytest.raises(kit.PrivateError, match="DATA"):
        tracker.accept("ul", json.dumps(_ul(_config())).encode())
    monkeypatch.setattr(kit, "MAX_STREAMED", tracker.streamed)
    with pytest.raises(kit.PrivateError, match="DATA"):
        tracker.accept("ul", b"{}")


def _capture_result() -> kit.Report:
    return kit.Report(
        target_platform="PASS",
        provenance="PASS",
        browser_delivery="HUMAN_ATTESTED",
        same_executable="PASS",
        signature_integrity="PASS",
        archive_quarantine="PRESENT",
        app_quarantine="PRESENT",
        es_ready="PASS",
        unified_log_ready="PASS",
        bounded_collection="PASS",
        collector_cleanup="PASS",
        downloaded_launch="RETURNED_ERROR",
        downloaded_marker="ABSENT",
        test_item_policy_records="OBSERVED",
        unified_log_shapes="PASS",
    )


def test_capture_control_report_flow_opens_no_records_in_report(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _delivery(synthetic, monkeypatch)
    monkeypatch.setattr(kit, "_collect", lambda *_args: _capture_result())
    assert kit.capture(browser_download=True).gate_status == "NOT_EVALUATED"

    class Process:
        returncode = 0

        def __init__(self, args: list[str], **_kwargs: object) -> None:
            assert args[:3] == ["/usr/bin/open", "-n", "-W"]
            assert "/private/original/" in args[3]
            kit._write(synthetic / "private/marker", b"EXECUTED\n")

        def wait(self, *, timeout: int) -> int:
            assert timeout == 15
            return 0

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(kit.subprocess, "Popen", Process)
    assert kit.control().local_control_marker == "PRESENT"
    original = kit._read

    def read(path: Path, *args: object, **kwargs: object) -> bytes:
        assert path.name not in {"test-ul.jsonl", "test-es.jsonl"}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(kit, "_read", read)
    result = kit.report("BLOCK_ALERT")
    assert result.denial_conclusion == "PRIVATE_REVIEW_CANDIDATE"
    assert result.gate_status == "NOT_EVALUATED"
    assert _CANARY not in result.model_dump_json()
    assert kit.report("CONSENT_PROMPT").denial_conclusion == "NOT_ESTABLISHED"


def test_incomplete_control_is_reportable_but_not_qualified(synthetic: Path) -> None:
    kit._write(synthetic / "private/capture.json", _capture_result().model_dump_json().encode())
    result = kit.report("BLOCK_ALERT")
    assert result.local_control_marker == "INCONCLUSIVE"
    assert result.denial_conclusion == "NOT_ESTABLISHED"


@pytest.mark.parametrize("code", ["BUILD", "COLLECTOR", "ES_READINESS", "UL_READINESS", "DATA"])
def test_errors_are_fixed_reports_and_never_echo_native_exceptions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture, code: kit.Code
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise kit.PrivateError(code) from OSError(_CANARY)

    monkeypatch.setattr(kit, "setup", fail)
    assert kit.main(["setup", "--private-run"]) == 2
    output = capsys.readouterr().out
    assert _CANARY not in output
    assert kit.Report.model_validate_json(output).error == code


@pytest.mark.parametrize(
    "args",
    [
        ["capture", "--private-run"],
        ["capture", "--private-run", "--browser-download", _CANARY],
        ["report", "--private-run", "--outcome", _CANARY],
    ],
)
def test_invalid_cli_inputs_do_not_echo_argument_values(
    args: list[str], capsys: pytest.CaptureFixture
) -> None:
    assert kit.main(args) == 2
    output = capsys.readouterr().out
    assert _CANARY not in output and kit.Report.model_validate_json(output).error == "INPUT"


def test_root_guard_source_is_fixed_bounded_and_has_no_external_inputs() -> None:
    source = (kit.SOURCES / "collector_guard.c").read_text()
    assert '"/usr/bin/eslogger", "exec", "exit"' in source
    assert "alarm(55)" in source and "setpgid" in source
    assert "kill(-child, SIGTERM)" in source and "waitpid(child" in source
    assert "argc != 1" in source and "geteuid() != 0" in source


def test_stop_only_targets_owned_child_and_does_not_print_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Process:
        pid = 4321
        returncode = 0

        def poll(self) -> None:
            return None

        def send_signal(self, value: int) -> None:
            assert value == signal.SIGINT
            raise PermissionError(_CANARY)

        def wait(self, *, timeout: int) -> int:
            assert timeout == 3
            return 0

    def command(args: list[str], **kwargs: object) -> None:
        assert args == ["/usr/bin/sudo", "-n", "/bin/kill", "-INT", "4321"]
        assert kwargs["stdout"] == kwargs["stderr"] == subprocess.DEVNULL

    monkeypatch.setattr(kit.subprocess, "run", command)
    assert kit._stop(Process(), privileged=True)


def test_pump_retains_exact_bytes_only_after_item_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config()
    tracker = kit.Tracker(config, Path("/invented/helper"))
    tracker.started = True
    relevant = json.dumps(_ul(config)).encode()
    unrelated = json.dumps({"eventMessage": _CANARY, "processImagePath": "/other"}).encode()
    monkeypatch.setattr(kit.os, "read", lambda *_args: unrelated + b"\n" + relevant + b"\n")
    selector = SimpleNamespace(select=lambda **_kwargs: [(SimpleNamespace(data="ul", fd=99), 1)])
    output = io.BytesIO()
    kit._pump(selector, {"ul": b""}, tracker, {"ul": output})
    assert output.getvalue() == relevant + b"\n"


@pytest.mark.parametrize("mode", ["complete", "es_unready", "ul_unready", "interrupted"])
def test_mocked_collection_requires_readiness_and_always_stops_both_sources(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    config = _delivery(synthetic, monkeypatch)
    calls: list[list[str]] = []
    stopped: list[bool] = []
    clock = [0.0]

    def now() -> float:
        clock[0] += 0.05
        return clock[0]

    class Process:
        def __init__(self, args: list[str], **kwargs: object) -> None:
            calls.append(args)
            assert kwargs["env"] == kit.SAFE_ENV and kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["stderr"] == subprocess.DEVNULL
            self.pid = 1200 + len(calls)
            self.returncode = None if args[0] in {"/usr/bin/log", "/usr/bin/sudo"} else 0
            self.stdout = io.BytesIO() if self.returncode is None else None
            if args[0] == "/usr/bin/log":
                assert args[1:3] == ["stream", "--style"]
                assert "--privacy" not in args and "show" not in args
            elif args[0] == "/usr/bin/sudo":
                assert args == ["/usr/bin/sudo", "-n", str(synthetic / "private/collector-guard")]
            elif args[0] == "/usr/bin/open":
                assert args[1:3] == ["-n", "-W"]
            else:
                assert args == [
                    str(synthetic / "private/metadata-probe"),
                    "ready",
                    config.readiness_tag,
                ]

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, *, timeout: int) -> int:
            assert timeout == 3
            return 0

    class Selector:
        def __enter__(self) -> object:
            return self

        def __exit__(self, *_args: object) -> None:
            pass

        def register(self, _stream: object, _events: int, source: str) -> None:
            assert source in {"ul", "es"}

    def pump(_selector: object, _buffers: dict, tracker: kit.Tracker, files: dict) -> None:
        if not tracker.started:
            tracker.es_ready = mode != "es_unready"
            tracker.ul_ready = mode != "ul_unready"
        elif mode == "interrupted":
            raise kit.PrivateError("DATA")
        elif not tracker.retained["ul"]:
            for source, row in (("ul", _ul(config)), ("es", _es(config))):
                raw = json.dumps(row).encode()
                assert tracker.accept(source, raw)
                files[source].write(raw + b"\n")

    def stop(process: Process, *, privileged: bool = False) -> bool:
        stopped.append(privileged)
        process.returncode = 0
        return True

    monkeypatch.setattr(kit.subprocess, "Popen", Process)
    monkeypatch.setattr(kit.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(kit.time, "monotonic", now)
    monkeypatch.setattr(kit, "READINESS_SECONDS", 0.5)
    monkeypatch.setattr(kit, "CAPTURE_SECONDS", 0.5)
    monkeypatch.setattr(kit, "_pump", pump)
    monkeypatch.setattr(kit, "_stop", stop)
    if mode == "complete":
        result = kit.capture(browser_download=True)
        assert result.es_ready == result.unified_log_ready == "PASS"
        assert result.bounded_collection == result.collector_cleanup == "PASS"
        assert result.downloaded_marker == "ABSENT"
        assert result.test_item_policy_records == result.es_exec_records == "OBSERVED"
    else:
        code = {"es_unready": "ES_READINESS", "ul_unready": "UL_READINESS", "interrupted": "DATA"}[
            mode
        ]
        with pytest.raises(kit.PrivateError, match=code):
            kit.capture(browser_download=True)
        if mode != "interrupted":
            assert not any(args[0] == "/usr/bin/open" for args in calls)
    assert stopped == [False, True]
    with pytest.raises(kit.PrivateError, match="DUPLICATE"):
        kit.capture(browser_download=True)


def test_download_page_has_only_static_local_link() -> None:
    status, headers, body = kit.response(
        "GET", f"/{_TOKEN}/", "127.0.0.1:1234", None, port=1234, token=_TOKEN, archive=b"invented"
    )
    assert status == 200 and headers["Content-Type"] == "text/html; charset=utf-8"
    assert b'href="probe.zip"' in body and b"http" not in body and b"script" not in body
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")


@pytest.mark.parametrize("change", ["late_marker", "bad_cleanup", "timeout"])
def test_control_refuses_ambiguous_or_unfinished_capture(synthetic: Path, change: str) -> None:
    result = _capture_result()
    if change == "late_marker":
        kit._write(synthetic / "private/marker", b"EXECUTED\n")
    else:
        result = result.model_copy(
            update={"collector_cleanup": "FAIL"}
            if change == "bad_cleanup"
            else {"downloaded_launch": "TIMED_OUT"}
        )
    kit._write(synthetic / "private/capture.json", result.model_dump_json().encode())
    with pytest.raises(kit.PrivateError, match="CONTROL"):
        kit.control()


def test_provenance_refuses_original_parent_symlinks(synthetic: Path) -> None:
    original = synthetic / "private/original"
    held = synthetic / "private/held-original"
    original.rename(held)
    original.symlink_to(held)
    with pytest.raises(kit.PrivateError, match="LOCATION"):
        kit._config(synthetic)


def test_exact_platform_provenance_stays_private_and_build_drift_stops_collection(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    config = kit._config(synthetic)
    assert (config.os_release, config.os_build, config.architecture) == ("27.0", "26A123", "arm64")
    monkeypatch.setattr(kit, "_platform_info", lambda _root: ("27.1", "26B999"))
    assert kit.main(["capture", "--private-run", "--browser-download"]) == 2
    output = capsys.readouterr().out.splitlines()
    report = kit.Report.model_validate_json("\n".join(output[output.index("{") :]))
    assert report.error == "PLATFORM"
    assert "26B999" not in "\n".join(output)
    assert not (synthetic / "private/capture-started").exists()


def test_matched_record_byte_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    tracker = kit.Tracker(_config(), Path("/invented/helper"))
    tracker.started = True
    monkeypatch.setattr(kit, "MAX_RETAINED_BYTES", 8)
    with pytest.raises(kit.PrivateError, match="DATA"):
        tracker.accept("ul", json.dumps(_ul(_config())).encode())


@pytest.mark.parametrize("field", tuple(kit.VerificationReport.model_fields))
def test_verification_report_cannot_expose_native_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.VerificationReport.model_validate({field: _CANARY})


def test_read_only_diagnosis_accepts_existing_kit_without_reading_records_or_writing(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    config = _delivery(synthetic, monkeypatch)
    # The private config format is unchanged from v1; old code hashes remain valid.
    old_source = synthetic / "private_gatekeeper.py"
    old_source.write_bytes(b"INVENTED_VERSION_ONE_SOURCE")
    updated = config.model_copy(update={"digests": kit._provenance(synthetic, config.app_name)})
    (synthetic / "private/config.json").write_bytes(updated.model_dump_json().encode())
    for name in ("test-ul.jsonl", "test-es.jsonl", "capture.json", "control.json"):
        kit._write(synthetic / "private" / name, _CANARY.encode())
    before = {
        str(p.relative_to(synthetic)): p.read_bytes() for p in synthetic.rglob("*") if p.is_file()
    }
    original_read = kit._read

    def read(path: Path, *args: object, **kwargs: object) -> bytes:
        assert path.name not in {"test-ul.jsonl", "test-es.jsonl", "capture.json", "control.json"}
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(kit, "_read", read)
    monkeypatch.setattr(kit, "_hidden_existing_root", lambda: synthetic)
    capsys.readouterr()
    assert kit.main(["diagnose", "--private-run"]) == 0
    output = capsys.readouterr().out
    report = kit.VerificationReport.model_validate_json(output)
    assert report.step == "COMPLETE" and report.verification == "PASS"
    assert report.native_record_files == "NOT_OPENED"
    assert _CANARY not in output and config.token not in output and config.os_build not in output
    assert before == {
        str(p.relative_to(synthetic)): p.read_bytes() for p in synthetic.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    "missing,step",
    [
        ("delivered", "DELIVERY_MARKER"),
        ("archive", "ARCHIVE_CONTENT"),
        ("app", "APP_BUNDLE"),
        ("binary", "APP_BINARY"),
        ("metadata", "APP_METADATA"),
    ],
)
def test_missing_download_inputs_report_exact_step_without_leaking_names(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, missing: str, step: str
) -> None:
    config = _delivery(synthetic, monkeypatch)
    app = synthetic / "private/downloads" / config.app_name
    target = {
        "delivered": synthetic / "private/delivered",
        "archive": synthetic / "private/downloads/probe.zip",
        "app": app,
        "binary": app / "Contents/MacOS/Probe",
        "metadata": app / "Contents/Info.plist",
    }[missing]
    shutil.rmtree(target) if missing == "app" else target.unlink()
    result = kit.diagnose(synthetic)
    assert result.step == step and result.error == "FILE_MISSING"
    assert config.token not in result.model_dump_json()
    assert not (synthetic / "private/capture-started").exists()


@pytest.mark.parametrize(
    "fault,step,code",
    [
        ("permission", "ARCHIVE_CONTENT", "FILE_ACCESS"),
        ("signature", "SIGNATURE", "BUILD"),
        ("archive_quarantine", "ARCHIVE_QUARANTINE", "QUARANTINE"),
        ("app_quarantine", "APP_QUARANTINE", "QUARANTINE"),
        ("native_type_error", "ARCHIVE_QUARANTINE", "INTERNAL"),
    ],
)
def test_native_verification_faults_are_classified_without_error_text(
    synthetic: Path, monkeypatch: pytest.MonkeyPatch, fault: str, step: str, code: str
) -> None:
    _delivery(synthetic, monkeypatch)
    if fault == "permission":
        original = kit._read

        def read(path: Path, *args: object, **kwargs: object) -> bytes:
            if path.name == "probe.zip" and path.parent.name == "downloads":
                raise PermissionError(_CANARY)
            return original(path, *args, **kwargs)

        monkeypatch.setattr(kit, "_read", read)
    elif fault == "signature":

        def command(*_args: object, **_kwargs: object) -> bytes:
            raise kit.PrivateError("BUILD") from OSError(_CANARY)

        monkeypatch.setattr(kit, "_command", command)
    else:

        def quarantine(_root: Path, path: Path) -> str:
            if fault == "native_type_error":
                raise TypeError(_CANARY)
            return (
                "ABSENT"
                if (path.name == "probe.zip") == (fault == "archive_quarantine")
                else "PRESENT"
            )

        monkeypatch.setattr(kit, "_quarantine", quarantine)
    result = kit.diagnose(synthetic)
    assert (result.step, result.error) == (step, code)
    assert _CANARY not in result.model_dump_json()


def test_hidden_root_prompt_never_falls_back_to_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kit.sys, "stdin", SimpleNamespace(isatty=lambda: True))

    def prompt(_message: str) -> str:
        kit.warnings.warn(_CANARY, kit.getpass.GetPassWarning)
        pytest.fail("Echo fallback must not reach input reading")

    monkeypatch.setattr(kit.getpass, "getpass", prompt)
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit._hidden_existing_root()
    monkeypatch.setattr(kit.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit._hidden_existing_root()


def test_source_copy_cannot_diagnose_a_private_kit() -> None:
    result = kit.diagnose(Path("/invented-private-location-never-opened"))
    assert result.step == "INPUT" and result.error == "LOCATION"


def test_offline_shape_review_is_bounded_read_only_and_accepts_v1(
    shape_capture: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    capsys.readouterr()
    before = {path: path.read_bytes() for path in shape_capture.rglob("*") if path.is_file()}
    read = kit._read

    def restricted(path: Path, *args: object, **kwargs: object) -> bytes:
        assert path.name not in {"test-es.jsonl", "control.json", "marker", "control-marker"}
        return read(path, *args, **kwargs)

    monkeypatch.setattr(kit, "_read", restricted)
    assert kit.main(["review-shapes", "--private-run", "--existing-kit", str(shape_capture)]) == 0
    output = capsys.readouterr()
    result = kit.ShapeReport.model_validate_json(output.out)
    assert not output.err and _CANARY not in output.out
    assert result.review_complete == result.provenance == result.retained_scope == "PASS"
    assert result.unified_log_shapes == "PASS"
    assert result.fields["source"].presence == "ABSENT_ALL"
    assert result.fields["source"].validation == "INCONCLUSIVE"
    assert result.gate_status == "NOT_EVALUATED" and result.message_meaning == "NOT_REVIEWED"
    assert before == {
        path: path.read_bytes() for path in shape_capture.rglob("*") if path.is_file()
    }


def test_shape_diagnostic_field_names_match_the_closed_native_schema() -> None:
    assert set(kit.UL_FIELDS) == {
        field.alias or name for name, field in kit.UnifiedLogRecord.model_fields.items()
    }


@pytest.mark.parametrize("field", tuple(kit.ShapeReport.model_fields))
def test_shape_report_rejects_unbounded_leaves(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.ShapeReport.model_validate({field: _CANARY})


def test_shape_report_rejects_discovered_field_names() -> None:
    with pytest.raises(ValidationError):
        kit.ShapeReport(fields={_CANARY: kit.ULFieldShape()})
    with pytest.raises(ValidationError):
        kit.ShapeReport(candidate_fields={_CANARY: kit.ULFieldShape()})


def test_candidate_probes_classify_only_predeclared_names_without_admitting_them() -> None:
    row = _shape_row()
    row.update({"processUniqueID": 1234, "timeToLive": 0, "process": _CANARY})
    result = kit._ul_shape_report([json.dumps(row).encode()])
    assert result.additional_fields == "PRESENT_ALL"
    assert result.unrecognized_fields == "ABSENT_ALL"
    assert result.candidate_fields["processUniqueID"].value_type == "INTEGER"
    assert result.candidate_fields["process"].value_type == "STRING"
    assert result.candidate_fields["processUniqueID"].validation == "INCONCLUSIVE"
    assert result.candidate_fields["sender"].presence == "ABSENT_ALL"
    assert result.unified_log_shapes == "FAIL" and result.gate_status == "NOT_EVALUATED"
    assert _CANARY not in result.model_dump_json()


@pytest.mark.parametrize(
    "field,value,kind",
    [
        ("processID", True, "TYPE"),
        ("userID", "501", "TYPE"),
        ("traceID", -1, "VALUE"),
        ("eventType", _CANARY, "UNSUPPORTED"),
        ("messageType", _CANARY, "UNSUPPORTED"),
        ("timestamp", "2026-02-30 14:00:00.123456+0000", "VALUE"),
        ("timestamp", _CANARY, "VALUE"),
        ("senderImageUUID", None, "TYPE"),
        ("source", {_CANARY: _CANARY}, "TYPE"),
        ("backtrace", {"frames": [{"imageOffset": -1, "imageUUID": ""}]}, "VALUE"),
        ("backtrace", {"frames": [], _CANARY: _CANARY}, "UNSUPPORTED"),
    ],
)
def test_offline_shape_failures_are_fixed_field_classifications(
    field: str, value: object, kind: str
) -> None:
    row = _shape_row()
    row[field] = value
    result = kit._ul_shape_report([json.dumps(row).encode()])
    assert result.unified_log_shapes == "FAIL"
    assert result.fields[field].failure_kind == kind
    assert result.fields[field].validation == "FAIL"
    assert _CANARY not in result.model_dump_json()


def test_shape_diagnostic_distinguishes_missing_mixed_and_additional_fields() -> None:
    row, other = _shape_row(), _shape_row()
    del row["timezoneName"]
    other["userID"] = "501"
    row[_CANARY] = {_CANARY: _CANARY}
    result = kit._ul_shape_report([json.dumps(item).encode() for item in (row, other)])
    assert result.fields["timezoneName"].presence == "MIXED"
    assert result.fields["timezoneName"].failure_kind == "MISSING"
    assert result.fields["userID"].value_type == "MIXED"
    assert result.additional_fields == "MIXED"
    assert result.additional_value_types == "OBJECT"
    assert _CANARY not in result.model_dump_json()


@pytest.mark.parametrize(
    "fault",
    [
        "uncorrelated",
        "wrong_writer",
        "non_object",
        "duplicate_key",
        "invalid_json",
        "overlong_line",
        "unterminated",
        "too_many",
        "too_large",
        "too_deep",
        "symlink",
        "hardlink",
        "permissions",
        "fifo",
        "missing",
        "changed_source",
        "bad_summary",
        "bool_version",
    ],
)
def test_offline_review_refuses_unsafe_or_unqualified_inputs(
    shape_capture: Path, fault: str
) -> None:
    path = shape_capture / "private/test-ul.jsonl"
    row = _shape_row()
    row["eventMessage"] = f"{_CANARY} {kit._config(shape_capture).app_name}"
    if fault == "uncorrelated":
        row["eventMessage"] = _CANARY
    elif fault == "wrong_writer":
        row["processImagePath"] = f"/invented/{_CANARY}"
    elif fault == "non_object":
        path.write_bytes(b"[]\n")
    elif fault == "duplicate_key":
        path.write_bytes(b'{"eventType": "logEvent", "eventType": "logEvent"}\n')
    elif fault == "invalid_json":
        path.write_bytes(b'{"invented": NaN}\n')
    elif fault == "overlong_line":
        path.write_bytes(b" " * (kit.MAX_LINE + 1) + b"\n")
    elif fault == "unterminated":
        path.write_bytes(json.dumps(row).encode())
    elif fault == "too_many":
        path.write_bytes((json.dumps(row).encode() + b"\n") * (kit.MAX_RETAINED + 1))
    elif fault == "too_large":
        path.write_bytes(b" " * (kit.MAX_RETAINED_BYTES + 1))
    elif fault == "too_deep":
        nested: object = None
        for _ in range(40):
            nested = [nested]
        row[_CANARY] = nested
    elif fault in {"symlink", "hardlink", "fifo", "missing"}:
        path.unlink()
        if fault == "symlink":
            path.symlink_to(shape_capture / "private/capture.json")
        elif fault == "hardlink":
            os.link(shape_capture / "private/capture.json", path)
        elif fault == "fifo":
            os.mkfifo(path, 0o600)
    elif fault == "permissions":
        path.chmod(0o644)
    elif fault == "changed_source":
        (shape_capture / "private_gatekeeper.py").write_text(_CANARY)
    elif fault in {"bad_summary", "bool_version"}:
        summary_path = shape_capture / "private/capture.json"
        summary = json.loads(summary_path.read_bytes())
        summary["collector_cleanup" if fault == "bad_summary" else "kit_version"] = (
            "FAIL" if fault == "bad_summary" else True
        )
        summary_path.write_text(json.dumps(summary))
    if fault in {"uncorrelated", "wrong_writer", "too_deep"}:
        path.write_bytes(json.dumps(row).encode() + b"\n")
    result = kit.review_shapes(shape_capture)
    assert result.error != "NONE" and result.review_complete == "INCONCLUSIVE"
    assert not result.fields and _CANARY not in result.model_dump_json()


def test_offline_review_never_leaks_native_exception_text(
    shape_capture: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    read = kit._read

    def denied(path: Path, *args: object, **kwargs: object) -> bytes:
        if path.name == "test-ul.jsonl":
            raise PermissionError(_CANARY)
        return read(path, *args, **kwargs)

    monkeypatch.setattr(kit, "_read", denied)
    result = kit.review_shapes(shape_capture)
    assert result.error == "FILE_ACCESS" and _CANARY not in result.model_dump_json()


def test_repo_copy_cannot_review_retained_records() -> None:
    result = kit.review_shapes(Path("/invented-private-location-never-opened"))
    assert result.error == "LOCATION" and not result.fields


@pytest.mark.parametrize("input_tty,output_tty", [(False, False), (True, False), (False, True)])
def test_private_name_inspection_refuses_agent_or_redirected_output_before_reading(
    input_tty: bool, output_tty: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit.sys.stdin, "isatty", lambda: input_tty)
    monkeypatch.setattr(kit.sys.stdout, "isatty", lambda: output_tty)

    def forbidden(_path: Path) -> list[bytes]:
        pytest.fail("Non-TTY name inspection must not open any private input")

    monkeypatch.setattr(kit, "_shape_inputs", forbidden)
    with pytest.raises(kit.PrivateError, match="INPUT"):
        kit.inspect_field_names(Path("/invented-never-opened"))


def test_private_terminal_inspection_shows_names_only_from_verified_rows(
    shape_capture: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    capsys.readouterr()
    monkeypatch.setattr(kit.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(kit.sys.stdout, "isatty", lambda: True)
    path = shape_capture / "private/test-ul.jsonl"
    row = json.loads(path.read_bytes())
    row["inventedTechnicalField"] = _CANARY
    path.write_bytes(json.dumps(row).encode() + b"\n")
    kit.inspect_field_names(shape_capture)
    output = capsys.readouterr()
    assert json.loads(output.out.splitlines()[-1]) == ["inventedTechnicalField"]
    assert _CANARY not in output.out and not output.err


@pytest.mark.parametrize("fault", ["control", "escape", "long", "count", "uncorrelated"])
def test_private_name_inspection_refuses_unbounded_or_uncorrelated_names_before_printing(
    shape_capture: Path,
    fault: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    capsys.readouterr()
    monkeypatch.setattr(kit.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(kit.sys.stdout, "isatty", lambda: True)
    path = shape_capture / "private/test-ul.jsonl"
    row = json.loads(path.read_bytes())
    if fault == "count":
        row.update({f"invented{index}": _CANARY for index in range(33)})
    elif fault == "uncorrelated":
        row["eventMessage"] = _CANARY
    else:
        row[{"control": "bad\nname", "escape": "bad\x1bname", "long": "a" * 65}[fault]] = _CANARY
    path.write_bytes(json.dumps(row).encode() + b"\n")
    with pytest.raises(kit.PrivateError, match="DATA"):
        kit.inspect_field_names(shape_capture)
    output = capsys.readouterr()
    assert not output.out and not output.err

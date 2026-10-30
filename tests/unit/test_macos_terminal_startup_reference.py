# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented records only; never launch a real app, marker or collector."""

import hashlib
import json
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_terminal_startup_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _process, _record

_CANARY = "INVENTED_PRIVATE_TERMINAL_CANARY"


@pytest.fixture(autouse=True)
def no_live_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Private reference tests must never execute native commands")

    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)


def _manifest(terminal: kit.Terminal = "apple") -> kit.Manifest:
    return kit.Manifest(
        terminal=terminal,
        os_version="27.0",
        os_build="inventedbuild",
        app=kit.reference.Image(device=123, inode=7001, sha256="a" * 64),
        marker=kit.reference.Image(device=123, inode=7002, sha256="b" * 64),
        guard_sha256="c" * 64,
        codec_sha256="d" * 64,
        code_sha256={},
        own_uid=501,
        own_gid=20,
        own_username=_CANARY,
        own_home=f"/Users/{_CANARY}",
    )


def _chain(terminal: kit.Terminal = "apple") -> list[dict]:
    rows: list[dict] = []
    boot = _process(11, 1, 0)
    boot["executable"]["path"] = "/sbin/launchd"

    def fork(parent: dict, pid: int) -> dict:
        child = deepcopy(parent)
        child["audit_token"]["pid"] = pid
        child["audit_token"]["pidversion"] = pid + 10000
        child["parent_audit_token"] = deepcopy(parent["audit_token"])
        child["ppid"] = child["original_ppid"] = parent["audit_token"]["pid"]
        row = _record(11, "fork")
        row["process"], row["event"]["fork"]["child"] = deepcopy(parent), deepcopy(child)
        rows.append(row)
        return child

    def execute(
        before: dict, path: str, *, inode: int = 8001, args: list[str] | None = None
    ) -> dict:
        target = deepcopy(before)
        target["audit_token"]["pidversion"] += 1
        target["executable"]["path"] = path
        target["executable"]["stat"]["st_ino"] = inode
        target["responsible_audit_token"] = deepcopy(target["audit_token"])
        row = _record(11, "exec")
        row["process"] = deepcopy(before)
        row["event"]["exec"].update(
            target=deepcopy(target),
            args=args or [path],
            env=[f"PRIVATE={_CANARY}"],
            fds=[{"fd": fd, "fdtype": 1} for fd in range(3)],
            last_fd=2,
            dyld_exec_path=path,
        )
        rows.append(row)
        return target

    before = fork(boot, 1200)
    launcher = execute(before, "/usr/libexec/xpcproxy")
    # Runtime credentials can change between the retained target and next exec.
    launcher["audit_token"]["euid"] = 0
    app = execute(launcher, kit.PATHS[terminal], inode=7001)
    login = execute(fork(app, 1300), "/usr/bin/login")
    shell = execute(login, "/bin/zsh")
    marker = execute(
        fork(shell, 1400),
        f"/private/tmp/{_CANARY}/terminal-marker",
        inode=7002,
        args=[f"/private/tmp/{_CANARY}/terminal-marker", "--sample"],
    )
    end = _record(11, "exit")
    end["process"], end["event"]["exit"]["stat"] = marker, 0
    rows.append(end)
    sequence: dict[int, int] = {}
    for index, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"] = sequence.get(kind, 0)
        sequence[kind] = row["seq_num"] + 1
        row["global_seq_num"] = index + 1
    return rows


@pytest.mark.parametrize("terminal", ["apple", "iterm2"])
def test_lineage_retains_same_pid_execs_and_excludes_unrelated_candidates(
    terminal: kit.Terminal,
) -> None:
    rows = _chain(terminal)
    noise = _record(11, "exec")
    noise["event"]["exec"]["target"]["audit_token"]["pid"] = 9999
    rows.insert(3, noise)
    sample = len(rows) - 2
    indexes = kit.select_lineage(rows, sample, _manifest(terminal).app)
    assert 3 not in indexes and len(indexes) == 8
    tracker = kit.Tracker(_manifest(terminal))
    tracker.collecting = True
    for row in _chain(terminal):
        assert tracker.accept(json.dumps(row).encode()) == []
    assert tracker.exit_zero and tracker.sample_count == 1
    assert len(tracker.retained) == 9 and tracker.sequence_ok
    phases = kit.analyze(tracker.retained, _manifest(terminal))
    assert [phase.role for phase in phases] == [
        "XPCPROXY",
        "APPLE_TERMINAL" if terminal == "apple" else "ITERM2",
        "LOGIN",
        "ZSH",
        "MARKER",
    ]
    assert phases[2].fork_linkage == "PASS"
    assert phases[3].fork_linkage == "INCONCLUSIVE"
    assert all(phase.same_pid_replacement == "PASS" for phase in phases)
    assert all(phase.native_shape == "PASS" for phase in phases)
    assert all(phase.only_standard_descriptors == "PASS" for phase in phases)
    report = kit.Report(terminal=terminal, phases=phases)
    assert _CANARY not in report.model_dump_json()
    assert "1400" not in report.model_dump_json()


@pytest.mark.parametrize("mutation", ["app_inode", "app_version", "parent_version", "marker_inode"])
def test_identity_mismatch_cannot_retain_a_false_chain(mutation: str) -> None:
    rows = _chain()
    if mutation == "app_inode":
        rows[2]["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] += 1
    elif mutation == "app_version":
        rows[2]["event"]["exec"]["target"]["audit_token"]["pidversion"] += 1
    elif mutation == "parent_version":
        rows[3]["process"]["audit_token"]["pidversion"] += 1
    else:
        rows[-2]["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] += 1
    tracker = kit.Tracker(_manifest())
    tracker.collecting = True
    for row in rows:
        tracker.accept(json.dumps(row).encode())
    assert not tracker.retained


def test_unmatched_fork_is_not_claimed_from_a_parent_token_only_edge() -> None:
    rows = _chain()
    rows[3]["event"]["fork"]["child"]["start_time"] = "2026-10-19T12:28:59Z"
    indexes = kit.select_lineage(rows, len(rows) - 2, _manifest().app)
    assert indexes and 3 not in indexes
    phases = kit.analyze([json.dumps(rows[i]).encode() for i in indexes], _manifest())
    assert phases[2].role == "LOGIN" and phases[2].fork_linkage == "INCONCLUSIVE"


def test_responsibility_can_link_a_reparented_helper_without_claiming_ancestry() -> None:
    rows = _chain("iterm2")
    app = rows[2]["event"]["exec"]["target"]
    # The login's parent is now a pre-existing helper outside this sample.
    rows[3]["process"] = _process(11, 9990)
    rows[-2]["event"]["exec"]["target"]["responsible_audit_token"] = deepcopy(app["audit_token"])
    assert not kit.select_lineage(rows, len(rows) - 2, _manifest("iterm2").app)
    tracker = kit.Tracker(_manifest("iterm2"))
    tracker.collecting = True
    for row in rows:
        tracker.accept(json.dumps(row).encode())
    assert tracker.retained and tracker.app_link == "RESPONSIBILITY"
    phases = kit.analyze(tracker.retained, _manifest("iterm2"))
    assert any(phase.role == "ITERM2" for phase in phases)


def test_sequence_loss_and_input_limits_remain_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    tracker = kit.Tracker(_manifest())
    rows = _chain()
    tracker.accept(json.dumps(rows[0]).encode())
    row = deepcopy(rows[1])
    row["global_seq_num"] = 0
    tracker.accept(json.dumps(row).encode())
    assert not tracker.sequence_ok
    monkeypatch.setattr(kit.reference, "MAX_STREAM", 1)
    with pytest.raises(kit.reference.PrivateError, match="LIMIT"):
        kit.Tracker(_manifest()).accept(json.dumps(rows[0]).encode())


def test_reused_app_or_eviction_cannot_prove_initial_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kit, "MAX_RING_ROWS", 2)
    tracker = kit.Tracker(_manifest())
    tracker.collecting = True
    for row in _chain():
        tracker.accept(json.dumps(row).encode())
    assert tracker.evicted and not tracker.retained


def test_marker_exit_is_bound_to_birth_and_ready_exit_to_controlled_pid() -> None:
    tracker = kit.Tracker(_manifest())
    tracker.collecting = True
    rows = _chain()
    for row in rows[:-1]:
        tracker.accept(json.dumps(row).encode())
    exit_row = deepcopy(rows[-1])
    exit_row["process"]["start_time"] = "2026-10-19T12:28:59Z"
    tracker.accept(json.dumps(exit_row).encode())
    assert tracker.exit_zero is None
    ready = deepcopy(rows[-2])
    ready["event"]["exec"]["args"][-1] = "--ready"
    ready_tracker = kit.Tracker(_manifest())
    ready_tracker.accept(json.dumps(ready).encode())
    ready_tracker.accept(json.dumps(rows[-1]).encode())
    assert not ready_tracker.ready


@pytest.mark.parametrize(
    "field,value",
    [("error", _CANARY), ("step", _CANARY), ("terminal", _CANARY), ("phases", [{"role": _CANARY}])],
)
def test_shareable_schema_cannot_export_arbitrary_native_text(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({"terminal": "apple", field: value})


def test_version_one_fixed_report_remains_readable_without_a_step_label() -> None:
    original = kit.Report(kit_version=1, terminal="apple", error="IO")
    legacy = original.model_dump_json(exclude={"step"})
    restored = kit.Report.model_validate_json(legacy)
    assert restored.kit_version == 1 and restored.error == "IO" and restored.step == "INPUT"


def test_prepare_copies_only_code_and_instructions(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "prepared")
    assert {path.name for path in root.iterdir()} == {*kit.CODE, "PRIVATE-RUN.md"}
    assert root.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
    assert not (root / "SETUP.json").exists()


@pytest.mark.parametrize("system_owned", [False, True])
def test_installed_app_accepts_normal_permissions_without_weakening_private_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system_owned: bool
) -> None:
    app = tmp_path / "invented-app"
    app.write_bytes(b"invented executable")
    app.chmod(0o755)
    # This reproduces the original setup failure using only an invented file.
    with pytest.raises(kit.reference.PrivateError, match="LOCATION"):
        kit.reference._image(app)
    if system_owned:
        original_fstat = kit.os.fstat

        def system_stat(fd: int) -> SimpleNamespace:
            value = original_fstat(fd)
            fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_mode",
                "st_nlink",
            )
            return SimpleNamespace(**{name: getattr(value, name) for name in fields}, st_uid=0)

        monkeypatch.setattr(kit.os, "fstat", system_stat)
    image = kit._installed_image(app)
    assert image.sha256 == hashlib.sha256(b"invented executable").hexdigest()
    assert image.inode == app.stat().st_ino
    with pytest.raises(kit.reference.PrivateError, match="LOCATION"):
        kit.reference._image(app)


@pytest.mark.parametrize("mode", [0o775, 0o777])
def test_installed_app_rejects_other_writers(tmp_path: Path, mode: int) -> None:
    app = tmp_path / "invented-app"
    app.write_bytes(b"invented executable")
    app.chmod(mode)
    with pytest.raises(kit.reference.PrivateError, match="BUILD"):
        kit._installed_image(app)


def test_installed_app_rejects_symlinks_growth_and_oversized_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "invented-app"
    app.write_bytes(b"invented executable")
    app.chmod(0o755)
    link = tmp_path / "link"
    link.symlink_to(app)
    with pytest.raises(OSError):
        kit._installed_image(link)
    original_fstat = kit.os.fstat
    calls = 0

    def changed_stat(fd: int) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        value = original_fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode", "st_uid")
        return SimpleNamespace(
            **{name: getattr(value, name) for name in fields}, st_ctime_ns=value.st_ctime_ns + calls
        )

    with monkeypatch.context() as patch:
        patch.setattr(kit.os, "fstat", changed_stat)
        with pytest.raises(kit.reference.PrivateError, match="BUILD"):
            kit._installed_image(app)
    monkeypatch.setattr(kit, "MAX_INSTALLED_IMAGE_BYTES", 1)
    with pytest.raises(kit.reference.PrivateError, match="LIMIT"):
        kit._installed_image(app)


def test_installed_app_hashing_does_not_use_the_small_private_record_limit(tmp_path: Path) -> None:
    app = tmp_path / "invented-large-app"
    with app.open("wb") as stream:
        stream.truncate(17 * 1_048_576)
    app.chmod(0o755)
    image = kit._installed_image(app)
    assert len(image.sha256) == 64


def test_setup_and_verification_accept_an_installed_public_app_without_running_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "kit"
    root.mkdir(mode=0o700)
    for name in kit.CODE:
        (root / name).write_bytes(b"invented code")
        (root / name).chmod(0o600)
    app = tmp_path / "invented-app"
    app.write_bytes(b"invented public executable")
    app.chmod(0o755)
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "inventedbuild"))
    monkeypatch.setattr(kit.reference, "_codec_digest", lambda: "a" * 64)
    monkeypatch.setitem(kit.PATHS, "apple", str(app))
    monkeypatch.setattr(
        kit.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(
            pw_uid=501, pw_gid=20, pw_name=_CANARY, pw_dir=f"/Users/{_CANARY}"
        ),
    )
    commands: list[str] = []

    def compile_only(args: list[str], _root: Path) -> None:
        commands.append(args[0])
        if args[0] == "/usr/bin/clang":
            Path(args[-1]).write_bytes(b"invented compiled binary")

    monkeypatch.setattr(kit.reference, "_command", compile_only)
    report = kit.setup("apple")
    assert report.kit_version == 2 and report.stage == "SETUP_READY" and report.error == "NONE"
    assert report.step == "COMPLETE"
    assert commands == ["/usr/bin/clang", "/usr/bin/clang", "/usr/bin/codesign"]
    assert kit._manifest(root).app == kit._installed_image(app)
    assert _CANARY not in report.model_dump_json()
    with pytest.raises(kit.DiagnosticError) as failure:
        kit.setup("apple")
    assert (failure.value.code, failure.value.step) == ("KIT_ALREADY_USED", "SETUP_LOCK")


def test_missing_setup_rejects_capture_before_platform_commands_or_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(
        kit.sys,
        "argv",
        ["private_terminal_startup.py", "capture", "--fresh-launch", "--private-run"],
    )
    with pytest.raises(SystemExit) as stopped:
        kit.main()
    assert stopped.value.code == 2
    report = kit.Report.model_validate_json(capsys.readouterr().out)
    assert report.kit_version == 2
    assert (report.error, report.step) == ("SETUP_REQUIRED", "SETUP_MANIFEST")
    assert not (tmp_path / "SESSION-LOCK").exists()


@pytest.mark.parametrize(
    "exception,expected",
    [
        (kit.reference.PrivateError("LOCATION"), "LOCATION"),
        (kit.reference.PrivateError("BUILD"), "BUILD"),
        (PermissionError(_CANARY), "IO"),
    ],
)
def test_fixed_diagnostics_preserve_known_error_codes_without_messages(
    exception: BaseException, expected: str
) -> None:
    assert kit._failure(exception) == expected

    def fail() -> None:
        raise exception

    with pytest.raises(kit.DiagnosticError) as failure:
        kit._at_step("INSTALLED_APP", fail)
    assert (failure.value.code, failure.value.step) == (expected, "INSTALLED_APP")
    assert _CANARY not in str(failure.value)


def test_collector_failure_reports_cleanup_and_writes_no_native_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(kit, "_manifest", lambda _root: _manifest())
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "inventedbuild"))
    stopped: list[object] = []
    collector = SimpleNamespace(stdout=SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *_args, **_kwargs: collector)
    monkeypatch.setattr(kit.reference, "_stop_collector", lambda item: stopped.append(item) is None)

    def failed_pump(*_args: object) -> None:
        raise kit.reference.PrivateError("COLLECTOR")

    monkeypatch.setattr(kit.reference, "Pump", failed_pump)
    report = kit.capture()
    assert report.error == "COLLECTOR" and report.collector_cleanup == "PASS"
    assert stopped == [collector]
    assert not list(tmp_path.rglob("launch-chain-events.jsonl"))
    saved = next(tmp_path.rglob("SHAREABLE-REPORT.json"))
    assert kit.Report.model_validate_json(saved.read_bytes()) == report


def test_successful_controller_writes_only_proved_rows_after_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    monkeypatch.setattr(kit, "_root", lambda: tmp_path)
    monkeypatch.setattr(kit, "_manifest", lambda _root: _manifest())
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "inventedbuild"))
    collector = SimpleNamespace(stdout=SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *_args, **_kwargs: collector)
    monkeypatch.setattr(kit.reference, "_start", lambda *_args: SimpleNamespace(pid=9001))
    monkeypatch.setattr(kit.reference, "_stop_probe", lambda _probe: None)
    cleaned = False

    def stop(_collector: object) -> bool:
        nonlocal cleaned
        cleaned = True
        return True

    monkeypatch.setattr(kit.reference, "_stop_collector", stop)

    class Pump:
        def __init__(self, _collector: object, tracker: kit.Tracker, _files: dict) -> None:
            self.tracker = tracker
            self.selector = SimpleNamespace(close=lambda: None)

        def tick(self) -> None:
            if not self.tracker.collecting:
                self.tracker.ready = True
            else:
                for row in _chain():
                    self.tracker.accept(json.dumps(row).encode())

    monkeypatch.setattr(kit.reference, "Pump", Pump)
    original_write = kit.reference._write

    def checked_write(path: Path, raw: bytes) -> None:
        if path.name == "launch-chain-events.jsonl":
            assert cleaned
        original_write(path, raw)

    monkeypatch.setattr(kit.reference, "_write", checked_write)
    report = kit.capture()
    assert report.error == "NONE" and report.collector_cleanup == "PASS"
    assert report.app_link == "ANCESTRY" and report.wire_profile == "V11"
    assert len(report.phases) == 5
    path = next(tmp_path.rglob("launch-chain-events.jsonl"))
    assert len(path.read_bytes().splitlines()) == 9
    assert kit.report_existing() == report


def test_main_never_prints_failure_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(kit.sys, "argv", ["private_terminal_startup.py", "setup", "--private-run"])

    def failed_setup(_terminal: str) -> None:
        raise subprocess.CalledProcessError(2, _CANARY, output=_CANARY, stderr=_CANARY)

    monkeypatch.setattr(kit, "setup", failed_setup)
    with pytest.raises(SystemExit) as stopped:
        kit.main()
    assert stopped.value.code == 2
    output = capsys.readouterr()
    assert _CANARY not in output.out + output.err
    assert kit.Report.model_validate_json(output.out).error == "IO"

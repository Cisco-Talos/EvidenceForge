# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented inputs only: never run a probe, native preflight, app or collector."""

import io
import json
import os
import stat
import subprocess
import warnings
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_gui_launch_reference as kit

from tests.unit.test_macos_endpoint_security_contracts import _process, _record

_CANARY = "INVENTED_PRIVATE_CANARY_DO_NOT_EXPORT"
_IMAGE = kit.Image(device=123, inode=9001, sha256="a" * 64)


@pytest.fixture(autouse=True)
def no_native_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Tests must never execute a native command, probe or collector")

    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)


def _rows(pid: int = 1200, image: kit.Image = _IMAGE) -> list[dict]:
    fork = _record(11, "fork")
    before = _process(11, pid=pid)
    fork["process"] = _process(11, pid=1190)
    fork["event"]["fork"]["child"] = deepcopy(before)
    execute = _record(11, "exec")
    execute["process"] = deepcopy(before)
    target = deepcopy(before)
    target["audit_token"]["pidversion"] += 1
    target["executable"]["stat"].update(st_dev=image.device, st_ino=image.inode)
    payload = execute["event"]["exec"]
    payload.update(
        target=target,
        args=[f"/private/tmp/{_CANARY}/GUIProbe.app/Contents/MacOS/Probe"],
        env=[f"PRIVATE={_CANARY}"],
        fds=[{"fd": fd, "fdtype": 1} for fd in range(3)],
        last_fd=2,
    )
    end = _record(11, "exit")
    end["process"] = deepcopy(target)
    end["event"]["exit"]["stat"] = 0
    for i, row in enumerate((fork, execute, end)):
        row["seq_num"] = 0
        row["global_seq_num"] = i + 1
    return [fork, execute, end]


def _raws(rows: list[dict]) -> list[bytes]:
    return [json.dumps(row).encode() for row in rows]


def _own(rows: list[dict]) -> kit.OwnSnapshot:
    payload = rows[1]["event"]["exec"]
    target = payload["target"]
    start = kit._birth(target)
    return kit.OwnSnapshot(
        phase="MAIN_ENTRY",
        token=kit._token(target),
        ppid=target["ppid"],
        sid=target["session_id"],
        pgid=target["group_id"],
        start_seconds=start // 1_000_000,
        start_microseconds=start % 1_000_000,
        inventory_complete=True,
        fds=tuple(
            kit.OwnFD(fd=i, kind=1, flags=0, access=0 if i == 0 else 1, tty=False) for i in range(3)
        ),
        arguments_hex=tuple(s.encode().hex() for s in payload["args"]),
        environment_hex=tuple(s.encode().hex() for s in payload["env"]),
    )


def test_fixed_case_report_retains_relationships_without_private_values() -> None:
    rows = _rows()
    report = kit.analyze_case(_raws(rows), _own(rows), True, _IMAGE)
    assert report.native_shapes == report.one_exec_and_exit == report.fork_linkage == "PASS"
    assert report.own_identity_agreement == report.image_identity_agreement == "PASS"
    assert report.exec_identity_transition == report.audit_identity_agreement == "PASS"
    assert report.parent_agreement == report.posix_session_agreement == "PASS"
    assert report.responsible_identity == "OTHER"
    assert report.descriptor_inventory_agreement == "PASS"
    assert report.argument_vector_agreement == report.environment_vector_agreement == "PASS"
    assert report.exit_status_agreement == "PASS"
    assert report.stdio_kinds == ("VNODE",) * 3
    assert report.stdio_access == ("READ", "WRITE", "WRITE")
    serialized = kit.Report(control=report, finder=report).model_dump_json()
    for forbidden in (_CANARY, _CANARY.encode().hex(), "9001", "1200", "100001", "a" * 64):
        assert forbidden not in serialized


@pytest.mark.parametrize("relation", ["SELF", "PARENT", "OTHER", "UNSET"])
def test_responsibility_is_observed_not_assumed(relation: str) -> None:
    rows = _rows()
    target = rows[1]["event"]["exec"]["target"]
    if relation == "SELF":
        target["responsible_audit_token"] = deepcopy(target["audit_token"])
    elif relation == "PARENT":
        target["responsible_audit_token"] = deepcopy(target["parent_audit_token"])
    elif relation == "UNSET":
        target["responsible_audit_token"] = dict.fromkeys(target["audit_token"], 0)
        target["parent_audit_token"] = dict.fromkeys(target["audit_token"], 0)
    assert kit.analyze_case(_raws(rows), _own(rows), True, _IMAGE).responsible_identity == relation


@pytest.mark.parametrize(
    ("damage", "field"),
    [
        ("pidversion", "own_identity_agreement"),
        ("birth", "own_identity_agreement"),
        ("parent", "parent_agreement"),
        ("session", "posix_session_agreement"),
        ("fds", "descriptor_inventory_agreement"),
        ("duplicate_fd", "descriptor_inventory_agreement"),
        ("args", "argument_vector_agreement"),
        ("env", "environment_vector_agreement"),
        ("exit", "exit_status_agreement"),
        ("image", "image_identity_agreement"),
    ],
)
def test_inconsistent_observations_are_not_promoted(damage: str, field: str) -> None:
    rows = _rows()
    own = _own(rows)
    payload = rows[1]["event"]["exec"]
    if damage == "pidversion":
        token = list(own.token)
        token[7] += 1
        own = own.model_copy(update={"token": tuple(token)})
    elif damage == "birth":
        own = own.model_copy(update={"start_microseconds": 1})
    elif damage == "parent":
        own = own.model_copy(update={"ppid": 77})
    elif damage == "session":
        own = own.model_copy(update={"sid": 77})
    elif damage == "fds":
        own = own.model_copy(update={"inventory_complete": False})
    elif damage == "duplicate_fd":
        payload["fds"].append(deepcopy(payload["fds"][0]))
    elif damage in {"args", "env"}:
        payload[damage] = [_CANARY]
    elif damage == "image":
        payload["target"]["executable"]["stat"]["st_ino"] += 1
    else:
        rows[2]["event"]["exit"]["stat"] = 9
    report = kit.analyze_case(_raws(rows), own, True, _IMAGE)
    assert getattr(report, field) == "FAIL"
    assert _CANARY not in report.model_dump_json()


def test_unknown_v11_layout_is_a_fixed_shape_failure() -> None:
    rows = _rows()
    rows[1]["event"]["exec"]["entitlements"] = {_CANARY: _CANARY}
    report = kit.analyze_case(_raws(rows), _own(rows), True, _IMAGE)
    assert report.native_shapes == "FAIL"
    assert _CANARY not in report.model_dump_json()


def test_missing_and_duplicate_phases_do_not_pass() -> None:
    rows = _rows()
    assert kit.analyze_case([], None, False).one_exec_and_exit == "INCONCLUSIVE"
    assert kit.analyze_case(_raws(rows[:2]), _own(rows), False).one_exec_and_exit == "FAIL"
    assert kit.analyze_case(_raws(rows[1:]), _own(rows), True).fork_linkage == "INCONCLUSIVE"
    assert kit.analyze_case(_raws([rows[0], *rows]), _own(rows), True).fork_linkage == "FAIL"


def test_filter_holds_ambient_fork_until_exact_owned_exec_and_never_pid_only() -> None:
    rows = _rows()
    tracker = kit.Tracker(_IMAGE)
    tracker.phase = "finder"
    assert tracker.accept(_raws(rows[:1])[0]) == []
    foreign = deepcopy(rows[1])
    foreign["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] = 777
    # Same path, PID and lifetime are insufficient without the file object.
    assert tracker.accept(_raws([foreign])[0]) == []
    accepted = tracker.accept(_raws(rows[1:2])[0])
    assert [kit._decode(raw)["event_type"] for _, raw in accepted] == [11, 9]
    assert tracker.accept(_raws(rows[2:])[0])[0][0] == "finder"
    assert tracker.records["control"] == []
    assert len(tracker.records["finder"]) == 3
    reused = deepcopy(rows[2])
    reused["process"]["audit_token"]["pidversion"] += 100
    assert tracker.accept(_raws([reused])[0]) == []


@pytest.mark.parametrize("status", [0, 9, 256, -9, False, "0", None])
def test_readiness_requires_known_probe_and_matching_successful_exit(status: object) -> None:
    rows = _rows()
    rows[1]["event"]["exec"]["args"].append("--ready")
    tracker = kit.Tracker(_IMAGE)
    tracker.ready_pids.add(1200)
    tracker.accept(_raws(rows[1:2])[0])
    assert not tracker.ready
    rows[2]["event"]["exit"]["stat"] = status
    tracker.accept(_raws(rows[2:])[0])
    assert tracker.ready is (type(status) is int and status == 0)
    assert not any(tracker.records.values())
    tracker.phase = "control"
    assert tracker.accept(_raws(rows[1:2])[0]) == []


def test_fork_buffer_is_bounded_and_unrelated_data_never_retained() -> None:
    tracker = kit.Tracker(_IMAGE)
    for index in range(100):
        row = _rows(2000 + index)[0]
        row.update(seq_num=index, global_seq_num=index)
        row[_CANARY] = _CANARY * 1000
        assert tracker.accept(_raws([row])[0]) == []
    assert len(tracker.forks) <= 64
    assert tracker.ring_bytes <= kit.MAX_RING_BYTES
    assert not any(tracker.records.values())


@pytest.mark.parametrize("field", tuple(kit.Report.model_fields))
def test_public_report_rejects_arbitrary_native_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@pytest.mark.parametrize("field", tuple(kit.CaseReport.model_fields))
def test_public_case_rejects_arbitrary_native_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.CaseReport.model_validate({field: _CANARY})


@pytest.mark.parametrize("value", [True, "1", 3, None])
def test_public_version_is_an_exact_integer(value: object) -> None:
    with pytest.raises(ValidationError):
        kit.Report(kit_version=value)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"x":NaN}', b"[]", b"broken"])
def test_private_decoder_fails_closed_without_value_output(raw: bytes) -> None:
    with pytest.raises(kit.PrivateError, match="^DATA$"):
        kit._decode(raw)


@pytest.mark.parametrize("version", [True, "11", 10, 12])
def test_profile_never_inferred_from_platform_or_boolean(version: object) -> None:
    rows = _rows()
    rows[0]["version"] = version
    assert kit._wire_profile(_raws(rows)) != "V11"


def test_prepare_only_copies_reviewable_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit.subprocess, "run", lambda *a, **k: pytest.fail("native command"))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **k: pytest.fail("collector/app"))
    root = kit.prepare(tmp_path / "kit")
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert set(p.name for p in root.iterdir()) == {*kit.CODE, "PRIVATE-RUN.md", "LAUNCH-CHAIN.md"}
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in root.iterdir())
    assert not (root / "GUIProbe.app").exists()
    with pytest.raises(FileExistsError):
        kit.prepare(root)


@pytest.mark.parametrize("git_kind", ["file", "directory"])
def test_prepare_refuses_any_git_tree(tmp_path: Path, git_kind: str) -> None:
    if git_kind == "file":
        (tmp_path / ".git").write_text("gitdir: invented")
    else:
        (tmp_path / ".git").mkdir()
    with pytest.raises(kit.PrivateError, match="^LOCATION$"):
        kit.prepare(tmp_path / "kit")


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = kit.prepare(tmp_path / "kit")
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit, "_preflight", lambda: ("27.0", "27INVENTED"))

    def command(args: list[str], _root: Path) -> None:
        if "-o" in args:
            kit._write(Path(args[args.index("-o") + 1]), b"INVENTED BINARY")

    monkeypatch.setattr(kit, "_command", command)
    assert kit.setup().stage == "SETUP_READY"
    return root


@pytest.mark.parametrize("target", ["Probe", "guard", "plist", "source", "codec"])
def test_setup_manifest_binds_code_binary_and_codec(
    prepared: Path, target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert kit._manifest(prepared).image == kit._image(kit._executable(prepared))
    path = {
        "Probe": kit._executable(prepared),
        "guard": prepared / "collector-guard",
        "plist": prepared / "GUIProbe.app/Contents/Info.plist",
        "source": prepared / kit.CODE[1],
    }.get(target)
    if path:
        path.write_bytes(b"CHANGED")
    else:
        monkeypatch.setattr(kit, "_codec_digest", lambda: "c" * 64)
    with pytest.raises(kit.PrivateError, match="^BUILD$"):
        kit._manifest(prepared)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions", "fifo", "size"])
def test_private_file_reader_does_not_follow_or_open_unbounded_sources(
    tmp_path: Path, kind: str
) -> None:
    target = tmp_path / "target"
    kit._write(target, _CANARY.encode())
    source = tmp_path / "source"
    if kind == "symlink":
        source.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, source)
    elif kind == "fifo":
        os.mkfifo(source, 0o600)
    else:
        kit._write(source, _CANARY.encode())
        if kind == "permissions":
            source.chmod(0o644)
    with pytest.raises((kit.PrivateError, OSError)):
        kit._read(source, 1 if kind == "size" else kit.MAX_LINE)


@pytest.mark.parametrize("command", ["setup", "capture", "report", "review-existing"])
def test_human_commands_require_flags_and_never_echo_inputs(
    command: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_root", lambda: pytest.fail("private action"))
    assert kit.main([command, "--private-path", _CANARY]) == 2
    result = capsys.readouterr()
    assert _CANARY not in result.out + result.err
    assert json.loads(result.out)["error"] == "INPUT"


@pytest.mark.parametrize("failure", [None, "interrupt", "cleanup", "finder-timeout"])
def test_mock_collection_cleans_up_and_persists_only_owned_rows(
    prepared: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    image = kit._manifest(prepared).image
    if failure == "finder-timeout":
        counter = iter(range(1000))
        monkeypatch.setattr(kit.time, "monotonic", lambda: next(counter))
    monkeypatch.setattr(kit, "_role", lambda *args: "FINDER")
    processes: list[SimpleNamespace] = []

    def start(_path: Path, *args: str) -> SimpleNamespace:
        process = SimpleNamespace(pid=1200, poll=lambda: 0, wait=lambda **kw: 0)
        processes.append(process)
        return process

    collector = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO())

    def wait(**_kw: object) -> int:
        if failure == "cleanup":
            raise subprocess.TimeoutExpired(_CANARY, 4)
        return 0

    collector.wait = wait
    monkeypatch.setattr(kit, "_start", start)
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **kw: collector)

    class Pump:
        def __init__(self, _process: object, tracker: kit.Tracker, files: dict) -> None:
            self.tracker, self.files = tracker, files
            self.selector = SimpleNamespace(close=lambda: None)
            self.fed: set[str] = set()

        def tick(self) -> None:
            case = self.tracker.phase
            if case == "ready":
                self.tracker.ready = True
                return
            if failure == "interrupt" and case == "finder":
                raise KeyboardInterrupt
            if failure == "finder-timeout" and case == "finder":
                return
            if case in self.fed:
                return
            self.fed.add(case)
            rows = _rows(1200 if case == "control" else 1300, image)
            for row in rows:
                row["seq_num"] += 0 if case == "control" else 1
                row["global_seq_num"] += 0 if case == "control" else 3
                for dest, raw in self.tracker.accept(json.dumps(row).encode()):
                    self.files[dest].write(raw + b"\n")
            run = kit._active(prepared)
            kit._write(run / f"{case}-self.json", _own(rows).model_dump_json().encode())
            kit._write(run / f"{case}-complete", b"RETURN_ZERO\n")

    monkeypatch.setattr(kit, "Pump", Pump)
    report = kit.capture()
    assert report.collector_cleanup == ("FAIL" if failure == "cleanup" else "PASS")
    assert (
        report.error
        == {
            None: "NONE",
            "cleanup": "COLLECTOR",
            "interrupt": "INTERRUPTED",
            "finder-timeout": "FINDER_TIMEOUT",
        }[failure]
    )
    if failure in {"interrupt", "finder-timeout"}:
        assert report.stage == "FINDER_READY"
    assert (prepared / "SESSION-LOCK").exists() == (failure == "cleanup")
    assert _CANARY not in report.model_dump_json()
    assert kit._read(kit._active(prepared) / "ACTIVE-CASE") == b"CLOSED\n"
    assert report.gate_status == "NOT_EVALUATED"
    if failure is None:
        assert report.control.native_shapes == report.finder.native_shapes == "PASS"
        assert kit.offline_report().stage == "OFFLINE_REPORT"


@pytest.mark.parametrize("launch_chain", [False, True])
def test_existing_session_lock_returns_specific_error_without_reading_or_collecting(
    prepared: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    launch_chain: bool,
) -> None:
    manifest = kit._manifest(prepared).model_copy(
        update={
            "kit_version": 2 if launch_chain else 1,
            "collection_mode": "launch_chain" if launch_chain else "app",
        }
    )
    monkeypatch.setattr(kit, "_manifest", lambda _root: manifest)
    monkeypatch.setattr(kit, "_read", lambda *_args: pytest.fail("No private files may be read"))
    lock = prepared / "SESSION-LOCK"
    kit._write(lock, _CANARY.encode())
    before = set(prepared.iterdir())
    assert kit.main(["capture", "--finder", "--private-run"]) == 2
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["error"] == "SESSION_LOCKED"
    assert report["kit_version"] == manifest.kit_version
    assert report["target_platform"] == report["provenance"] == "PASS"
    assert report["collector_ready"] == report["collector_cleanup"] == "INCONCLUSIVE"
    assert report["context"] == "NOT_ATTESTED"
    assert report["collection"] == (
        "CONTROLLED_TEST_APP_AND_LINKED_LAUNCHER" if launch_chain else "CONTROLLED_TEST_APP_ONLY"
    )
    assert set(prepared.iterdir()) == before
    assert lock.read_bytes() == _CANARY.encode()
    assert _CANARY not in output.out + output.err


@pytest.mark.parametrize(
    "status,expected", [(-9, "PROBE_KILLED"), (2, "PROBE_FAILED"), (None, "PROBE_TIMEOUT")]
)
def test_probe_preflight_failure_reaps_without_starting_collection_or_creating_run_files(
    prepared: Path, monkeypatch: pytest.MonkeyPatch, status: int | None, expected: str
) -> None:
    def wait(**_kwargs: object) -> int:
        if status is None:
            raise subprocess.TimeoutExpired(_CANARY, 3)
        return status

    probe = SimpleNamespace(wait=wait)
    stopped: list[object] = []
    monkeypatch.setattr(kit, "_start", lambda *_args: probe)
    monkeypatch.setattr(kit, "_stop_probe", stopped.append)
    before = set(prepared.iterdir())
    report = kit.capture()
    assert report.error == expected and report.stage == "PROBE_CHECK"
    assert report.collector_ready == "INCONCLUSIVE"
    assert report.collector_cleanup == "PASS" and report.wire_profile == "NOT_OBSERVED"
    assert report.sequence_continuity == "INCONCLUSIVE"
    assert set(prepared.iterdir()) == before
    assert stopped == [probe]
    assert _CANARY not in report.model_dump_json()


@pytest.mark.parametrize("reply", [b"FINDER\n", b"LAUNCHD\n", _CANARY.encode(), b"1234\n"])
def test_role_lookup_uses_exact_private_token_pipe_and_fixed_output(
    prepared: Path, monkeypatch: pytest.MonkeyPatch, reply: bytes
) -> None:
    calls = []

    def run(args: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((args, kwargs))
        return SimpleNamespace(stdout=reply)

    monkeypatch.setattr(kit.subprocess, "run", run)
    token = kit._token(_process(11, 99))
    role = kit._role(prepared, token, kit._token(_process(11, 100)))
    assert role == (
        reply.decode().strip() if reply in {b"FINDER\n", b"LAUNCHD\n"} else "UNAVAILABLE"
    )
    args, kwargs = calls[0]
    assert args == [str(kit._executable(prepared)), "--classify"]
    assert len(kwargs["input"]) == 32
    assert kwargs["timeout"] == 3 and kwargs["stderr"] == subprocess.DEVNULL
    assert _CANARY not in kit.CaseReport(responsible_image_role=role).model_dump_json()


def test_pump_writes_no_ambient_rows_and_backfills_only_proven_fork() -> None:
    read_fd, write_fd = os.pipe()
    stream = os.fdopen(read_fd, "rb")
    process = SimpleNamespace(stdout=stream, poll=lambda: None)
    tracker = kit.Tracker(_IMAGE)
    tracker.phase = "finder"
    files = {"control": io.BytesIO(), "finder": io.BytesIO()}
    pump = kit.Pump(process, tracker, files)
    rows = _rows()
    try:
        os.write(write_fd, _raws(rows[:1])[0] + b"\n")
        pump.tick()
        assert files["finder"].getvalue() == b""
        os.write(write_fd, _raws(rows[1:2])[0] + b"\n")
        pump.tick()
        saved = [kit._decode(raw) for raw in files["finder"].getvalue().splitlines()]
        assert [r["event_type"] for r in saved] == [11, 9]
        assert files["control"].getvalue() == b""
    finally:
        pump.selector.close()
        stream.close()
        os.close(write_fd)


@pytest.mark.parametrize(
    ("native", "main", "comparison"),
    [
        ((b"A=1", b"B=2"), (b"A=1", b"B=2"), "IDENTICAL"),
        ((b"A=1", b"B=2"), (b"B=2", b"A=1"), "ORDER_ONLY"),
        ((b"A=1", b"A=2"), (b"A=2", b"A=1"), "ORDER_ONLY"),
        ((b"A=1",), (b"A=1", b"B=2"), "MAIN_ADDITIONS_ONLY"),
        ((b"A=1", b"B=2"), (b"A=1",), "MAIN_REMOVALS_ONLY"),
        ((b"A=1",), (b"A=2",), "COMMON_VALUES_CHANGED"),
        ((b"A=1",), (b"A=1", b"A=1"), "COMMON_VALUES_CHANGED"),
        ((b"A=1", b"B=2"), (b"A=3", b"C=4"), "MIXED"),
        ((), (), "IDENTICAL"),
        ((b"A=",), (b"A=",), "IDENTICAL"),
        ((b"A=1=2",), (b"A=1=2",), "IDENTICAL"),
    ],
)
def test_private_environment_comparison_distinguishes_order_from_mutation(
    native: tuple[bytes, ...], main: tuple[bytes, ...], comparison: str
) -> None:
    report = kit.compare_environment(native, main)
    assert report.vectors_well_formed == "PASS"
    assert report.comparison == comparison
    assert report.controlled_initial_vector == "INCONCLUSIVE"


@pytest.mark.parametrize("malformed", [b"NO_ASSIGNMENT", b"=value", b"A=\0", "A=value", 7])
def test_environment_comparison_rejects_malformed_vectors(malformed: object) -> None:
    report = kit.compare_environment((malformed,), (b"A=value",))
    assert report.vectors_well_formed == "FAIL"
    assert report.comparison == report.controlled_initial_vector == "INCONCLUSIVE"


def test_fixed_known_environment_diagnostic_exports_no_arbitrary_names_or_values() -> None:
    native = (f"{_CANARY}={_CANARY}".encode(),)
    report = kit.compare_environment(native, (*native, b"__CF_USER_TEXT_ENCODING=PRIVATE_VALUE"))
    assert report.cf_text_encoding == "ADDED_AT_MAIN"
    assert report.only_cf_text_encoding_differs == "PASS"
    assert report.duplicate_key_structure == "SAME"
    changed = kit.compare_environment(native, (f"{_CANARY}=CHANGED".encode(),))
    assert changed.comparison == "COMMON_VALUES_CHANGED"
    assert changed.cf_text_encoding == "UNCHANGED"
    assert changed.only_cf_text_encoding_differs == "FAIL"
    for result in (report, changed):
        serialized = result.model_dump_json()
        for forbidden in (
            _CANARY,
            _CANARY.encode().hex(),
            "PRIVATE_VALUE",
            "__CF_USER_TEXT_ENCODING",
        ):
            assert forbidden not in serialized


@pytest.mark.parametrize(
    ("before", "after", "label", "duplicates"),
    [
        ((b"x",), (), "REMOVED_AT_MAIN", "SAME"),
        ((b"x",), (b"y",), "VALUE_CHANGED", "SAME"),
        ((b"x", b"y"), (b"y", b"x"), "UNCHANGED", "SAME"),
        ((b"x",), (b"x", b"x"), "VALUE_CHANGED", "DIFFERENT"),
    ],
)
def test_known_environment_field_preserves_duplicate_and_order_semantics(
    before: tuple[bytes, ...], after: tuple[bytes, ...], label: str, duplicates: str
) -> None:
    native = tuple(b"__CF_USER_TEXT_ENCODING=" + value for value in before)
    main = tuple(b"__CF_USER_TEXT_ENCODING=" + value for value in after)
    report = kit.compare_environment(native, main)
    assert report.cf_text_encoding == label
    assert report.duplicate_key_structure == duplicates


def test_controlled_environment_is_checked_against_exec_time_not_main_entry() -> None:
    controlled = tuple(f"{key}={value}".encode() for key, value in kit.SAFE_ENV.items())
    report = kit.compare_environment(
        tuple(reversed(controlled)), (*controlled, b"NEW=INVENTED"), controlled=True
    )
    assert report.controlled_initial_vector == "PASS"
    assert report.comparison == "MAIN_ADDITIONS_ONLY"
    assert kit.compare_environment((), (), controlled=True).controlled_initial_vector == "FAIL"


@pytest.mark.parametrize(
    "model",
    [
        kit.EnvironmentDifference,
        kit.AuditTokenFieldRelations,
        kit.ExistingLaunchFacts,
        kit.ExistingReviewReport,
    ],
)
def test_supplemental_report_schema_rejects_arbitrary_data(model: type[kit.Model]) -> None:
    for field in model.model_fields:
        with pytest.raises(ValidationError):
            model.model_validate({field: _CANARY})


@pytest.mark.parametrize("value", [True, "5", 1, 2, 3, 4, None])
def test_supplemental_version_rejects_coercion(value: object) -> None:
    with pytest.raises(ValidationError):
        kit.ExistingReviewReport(review_version=value)


@pytest.fixture
def existing_capture(prepared: Path) -> tuple[Path, Path]:
    manifest = kit._manifest(prepared)
    run = prepared / ("run-" + "1" * 32)
    run.mkdir(mode=0o700)
    kit._write(prepared / "ACTIVE-RUN", (run.name + "\n").encode())
    kit._write(
        run / "provenance.json",
        json.dumps({"setup": manifest.model_dump(mode="json"), "method": "finder"}).encode(),
    )
    cases: dict = {}
    for case in ("control", "finder"):
        rows = _rows(1200 if case == "control" else 1300, manifest.image)
        if case == "control":
            rows[1]["event"]["exec"]["env"] = [f"{k}={v}" for k, v in kit.SAFE_ENV.items()]
        own = _own(rows)
        own = own.model_copy(
            update={
                "environment_hex": (
                    *own.environment_hex,
                    f"__CF_USER_TEXT_ENCODING={_CANARY}".encode().hex(),
                )
            }
        )
        if case == "finder":
            rows = rows[1:]
        kit._write(run / f"{case}-events.jsonl", b"\n".join(_raws(rows)) + b"\n")
        kit._write(run / f"{case}-self.json", own.model_dump_json().encode())
        kit._write(run / f"{case}-complete", b"RETURN_ZERO\n")
        cases[case] = kit.analyze_case(_raws(rows), own, True, manifest.image)
    original = kit.Report(
        stage="COMPLETE",
        context="HUMAN_ATTESTED_FINDER",
        target_platform="PASS",
        provenance="PASS",
        collector_ready="PASS",
        collector_cleanup="PASS",
        bounded_collection="PASS",
        sequence_continuity="PASS",
        wire_profile="V11",
        **cases,
    )
    kit._write(run / "SHAREABLE-REPORT.json", original.model_dump_json().encode())
    return prepared, run


def test_existing_reviewer_is_read_only_and_does_not_launch_or_query(
    existing_capture: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _run = existing_capture
    files = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline review must not modify evidence, preflight, launch or query")

    for name in ("_role", "_start", "_preflight", "_write", "_replace"):
        monkeypatch.setattr(kit, name, forbidden)
    report = kit.review_existing(root)
    assert report.error == "NONE"
    assert report.provenance == report.original_collection_controls == "PASS"
    assert report.control_environment.controlled_initial_vector == "PASS"
    assert report.finder_environment.controlled_initial_vector == "INCONCLUSIVE"
    assert report.control_environment.only_cf_text_encoding_differs == "PASS"
    assert report.finder_environment.only_cf_text_encoding_differs == "PASS"
    assert report.control_fork == "RETAINED_MATCH"
    assert report.finder_fork == "NOT_RETAINED"
    assert report.finder_launch.signature_matches_control == "PASS"
    assert report.finder_launch.controlling_terminal_target == "ABSENT"
    assert report.finder_launch.only_standard_descriptors == "PASS"
    assert report.fork_absence_proves_no_fork == "NO"
    assert report.collectors == "NOT_STARTED" and report.apps == "NOT_LAUNCHED"
    serialized = report.model_dump_json()
    for private in (_CANARY, str(root), str(_run), _CANARY.encode().hex(), "a" * 64):
        assert private not in serialized
    assert {p: p.read_bytes() for p in root.rglob("*") if p.is_file()} == files


@pytest.mark.parametrize(
    "birth,label",
    [
        ("2026-10-19T12:29:58.000000Z", "BEFORE_CONTROL_BIRTH"),
        ("2026-10-19T12:29:59.500000Z", "BETWEEN_CONTROL_BIRTH_AND_EXIT"),
        ("2026-10-19T12:30:01.000000Z", "AFTER_CONTROL_EXIT"),
    ],
)
def test_chain_reviewer_uses_retained_app_lifetime_and_preserves_its_unknown_prefix(
    existing_capture: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    birth: str,
    label: str,
) -> None:
    root, run = existing_capture
    setup_path = root / "SETUP.json"
    manifest = json.loads(setup_path.read_bytes())
    manifest.update(kit_version=2, collection_mode="launch_chain", synthetic_entitlement=False)
    setup_path.write_text(json.dumps(manifest))
    provenance_path = run / "provenance.json"
    provenance = json.loads(provenance_path.read_bytes())
    provenance["setup"] = manifest
    provenance_path.write_text(json.dumps(provenance))
    summary_path = run / "SHAREABLE-REPORT.json"
    summary = json.loads(summary_path.read_bytes())
    summary.update(
        kit_version=2,
        collection="CONTROLLED_TEST_APP_AND_LINKED_LAUNCHER",
        synthetic_entitlement=False,
    )
    summary_path.write_text(json.dumps(summary))
    rows_path = run / "finder-events.jsonl"
    rows = [json.loads(line) for line in rows_path.read_bytes().splitlines()]
    for row in rows:
        row["time"] = "2026-10-19T12:30:05.123456789Z"
        row["process"]["start_time"] = birth
        if row["event_type"] == 9:
            row["process"]["executable"]["path"] = "/usr/libexec/xpcproxy"
            row["event"]["exec"]["target"]["start_time"] = birth
    rows_path.write_bytes(b"\n".join(_raws(rows)))
    own_path = run / "finder-self.json"
    own = json.loads(own_path.read_bytes())
    micros = kit._timestamp_microseconds(birth)
    own.update(start_seconds=micros // 1_000_000, start_microseconds=micros % 1_000_000)
    own_path.write_text(json.dumps(own))
    files = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("No native operations or writes during offline review")

    for name in ("_role", "_start", "_preflight", "_write", "_replace"):
        monkeypatch.setattr(kit, name, forbidden)
    report = kit.review_existing(root)
    assert report.review_version == 5
    assert report.finder_launch.before_image_role == "XPCPROXY"
    assert report.finder_preimage_birth == label
    assert report.launch_chain.launcher_retained == "NONE"
    assert report.finder_fork == "NOT_RETAINED"
    assert report.collectors == "NOT_STARTED" and report.live_role_queries == "NOT_PERFORMED"
    assert _CANARY not in report.model_dump_json()
    assert str(root) not in report.model_dump_json()
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == files


@pytest.mark.parametrize("damage", ["helper", "provenance", "own", "wire", "duplicate_exec"])
def test_existing_reviewer_rejects_invalid_provenance_and_observations(
    existing_capture: tuple[Path, Path], damage: str
) -> None:
    root, run = existing_capture
    if damage == "helper":
        (root / kit.CODE[0]).write_bytes(_CANARY.encode())
    elif damage == "provenance":
        (run / "provenance.json").write_text(json.dumps({"setup": _CANARY, "method": "finder"}))
    elif damage == "own":
        path = run / "finder-self.json"
        raw = json.loads(path.read_bytes())
        raw["token"][7] += 1
        path.write_text(json.dumps(raw))
    else:
        path = run / "finder-events.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        if damage == "wire":
            rows[0]["version"] = 10
        else:
            rows.append(deepcopy(rows[0]))
        path.write_bytes(b"\n".join(_raws(rows)))
    with pytest.raises(kit.PrivateError, match="^(BUILD|DATA)$"):
        kit.review_existing(root)


def test_failed_original_collection_controls_leave_supplemental_checks_inconclusive(
    existing_capture: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, run = existing_capture
    path = run / "SHAREABLE-REPORT.json"
    raw = json.loads(path.read_bytes())
    raw["sequence_continuity"] = "FAIL"
    path.write_text(json.dumps(raw))
    monkeypatch.setattr(kit, "_own", lambda *a: pytest.fail("Must stop at failed controls"))
    report = kit.review_existing(root)
    assert report.original_collection_controls == "FAIL"
    assert report.control_environment.comparison == report.finder_fork == "INCONCLUSIVE"


def test_hidden_original_location_never_allows_echo_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(kit.sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(kit.sys, "stderr", SimpleNamespace(isatty=lambda: True))

    def unsafe_prompt(_prompt: str) -> str:
        warnings.warn("invented fallback", kit.getpass.GetPassWarning, stacklevel=2)
        pytest.fail("Do not reach a fallback that could echo a path")

    monkeypatch.setattr(kit.getpass, "getpass", unsafe_prompt)
    with pytest.raises(kit.PrivateError, match="^INPUT$"):
        kit._hidden_existing_root()
    monkeypatch.setattr(kit.sys, "stdin", SimpleNamespace(isatty=lambda: False))
    with pytest.raises(kit.PrivateError, match="^INPUT$"):
        kit._hidden_existing_root()


def test_human_existing_review_cli_returns_only_fixed_diagnostics(
    existing_capture: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    root, run = existing_capture
    monkeypatch.setattr(kit, "_hidden_existing_root", lambda: root)
    assert kit.main(["review-existing", "--private-run"]) == 0
    result = capsys.readouterr()
    report = json.loads(result.out)
    assert report["purpose"] == "GUI_ENVIRONMENT_AND_FORK_DIAGNOSTIC"
    assert report["finder_fork"] == "NOT_RETAINED"
    assert _CANARY not in result.out + result.err
    assert str(run) not in result.out + result.err


@pytest.mark.parametrize("membership", ["PROCESS_LEADER", "PARENT_PID", "ZERO", "OTHER"])
def test_existing_native_membership_is_reported_as_a_relationship(membership: str) -> None:
    rows = _rows()
    before = rows[1]["process"]
    payload = rows[1]["event"]["exec"]
    target = payload["target"]
    value = {"PROCESS_LEADER": 1200, "PARENT_PID": 1190, "ZERO": 0, "OTHER": 42}[membership]
    target.update(session_id=value, group_id=value)
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.session_identity == result.group_identity == membership
    assert result.posix_membership_preserved == (
        "PASS" if (before["session_id"], before["group_id"]) == (value, value) else "FAIL"
    )
    assert _CANARY not in result.model_dump_json()


@pytest.mark.parametrize("role", ["TEST_APP", "LAUNCHD", "XPCPROXY", "OTHER"])
def test_before_image_classification_does_not_export_its_path(role: str) -> None:
    rows = _rows()
    before = rows[1]["process"]
    before["executable"]["path"] = (
        "/sbin/launchd"
        if role == "LAUNCHD"
        else "/usr/libexec/xpcproxy"
        if role == "XPCPROXY"
        else f"/tmp/{_CANARY}"
    )
    if role != "TEST_APP":
        before["executable"]["stat"]["st_ino"] += 1
    report = kit.inspect_existing_launch(before, rows[1]["event"]["exec"], _IMAGE)
    assert report.before_image_role == role
    assert report.before_target_file_object == ("PASS" if role == "TEST_APP" else "FAIL")
    assert _CANARY not in report.model_dump_json()


@pytest.mark.parametrize("location", ["ROOT", "DECLARED_HOME", "OTHER", "INCONCLUSIVE"])
def test_working_directory_classification_uses_only_private_relationships(location: str) -> None:
    rows = _rows()
    payload = rows[1]["event"]["exec"]
    payload["env"].append(f"HOME=/Users/{_CANARY}")
    payload["cwd"]["path"] = (
        "/"
        if location == "ROOT"
        else f"/Users/{_CANARY}"
        if location == "DECLARED_HOME"
        else _CANARY
    )
    payload["cwd"]["path_truncated"] = location == "INCONCLUSIVE"
    report = kit.inspect_existing_launch(rows[1]["process"], payload, _IMAGE)
    assert report.working_directory == location
    assert _CANARY not in report.model_dump_json()


def test_launch_diagnostics_preserve_tty_signature_and_descriptor_unknowns() -> None:
    rows = _rows()
    payload = rows[1]["event"]["exec"]
    target, before = payload["target"], rows[1]["process"]
    # Std streams can be non-TTY even while a controlling tty exists.
    target["tty"] = deepcopy(target["executable"])
    payload["fds"].reverse()
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.controlling_terminal_before == "ABSENT"
    assert result.controlling_terminal_target == "PRESENT"
    assert result.only_standard_descriptors == "PASS"
    assert result.native_last_fd_standard == "PASS"
    target["cdhash"] = "b" * 40
    payload["fds"].append({"fd": 9, "fdtype": 1})
    payload["last_fd"] = 9
    result = kit.inspect_existing_launch(
        before, payload, _IMAGE, control_signature=kit._signature(before)
    )
    assert result.before_target_signature == result.signature_matches_control == "FAIL"
    assert result.only_standard_descriptors == result.native_last_fd_standard == "FAIL"
    assert "b" * 40 not in result.model_dump_json()


def test_native_relationship_checks_bind_before_after_and_exact_parent_tokens() -> None:
    rows = _rows()
    before, payload = rows[1]["process"], rows[1]["event"]["exec"]
    target = payload["target"]
    target["ppid"] = target["original_ppid"] = 1
    target["parent_audit_token"]["pid"] = 1
    payload["dyld_exec_path"] = target["executable"]["path"]
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.parent_is_boot_pid == result.audit_origin_preserved == "PASS"
    assert result.posix_credentials_preserved == "PASS"
    assert result.parentage_preserved == "FAIL"
    assert result.dyld_path_matches_target == "PASS"
    target["parent_audit_token"]["pid"] = 2
    target["audit_token"]["asid"] += 1
    target["audit_token"]["euid"] += 1
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.parent_is_boot_pid == result.audit_origin_preserved == "FAIL"
    assert result.posix_credentials_preserved == "FAIL"


@pytest.mark.parametrize(
    "origin", ["UNATTRIBUTED_SENTINEL", "ROOT_USER", "REAL_USER", "TARGET_AUDIT_USER", "OTHER"]
)
def test_before_audit_user_diagnostic_reveals_only_a_relationship(origin: str) -> None:
    rows = _rows()
    before, payload = rows[1]["process"], rows[1]["event"]["exec"]
    token = before["audit_token"]
    token["auid"] = {
        "UNATTRIBUTED_SENTINEL": 2**32 - 1,
        "ROOT_USER": 0,
        "REAL_USER": token["ruid"],
        "TARGET_AUDIT_USER": 600,
        "OTHER": 700,
    }[origin]
    payload["target"]["audit_token"]["auid"] = 600
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.before_audit_user == origin
    assert result.target_audit_user_is_real_user == "FAIL"
    assert _CANARY not in result.model_dump_json()


@pytest.mark.parametrize("origin", ["DEFAULT_ZERO", "TARGET_SESSION", "OTHER"])
@pytest.mark.parametrize(
    "responsibility",
    ["SELF", "PARENT", "TARGET_EXECUTION", "SAME_PID_OTHER_IDENTITY", "UNSET", "OTHER"],
)
def test_before_audit_session_and_responsibility_never_export_native_identifiers(
    origin: str, responsibility: str
) -> None:
    rows = _rows()
    before, payload = rows[1]["process"], rows[1]["event"]["exec"]
    before["audit_token"]["asid"] = {
        "DEFAULT_ZERO": 0,
        "TARGET_SESSION": payload["target"]["audit_token"]["asid"],
        "OTHER": 77,
    }[origin]
    if responsibility == "SELF":
        before["responsible_audit_token"] = deepcopy(before["audit_token"])
    elif responsibility == "PARENT":
        before["responsible_audit_token"] = deepcopy(before["parent_audit_token"])
    elif responsibility == "UNSET":
        before["responsible_audit_token"] = dict.fromkeys(before["audit_token"], 0)
    elif responsibility == "TARGET_EXECUTION":
        before["responsible_audit_token"] = deepcopy(payload["target"]["audit_token"])
    elif responsibility == "SAME_PID_OTHER_IDENTITY":
        before["responsible_audit_token"] = deepcopy(before["audit_token"])
        before["responsible_audit_token"]["pidversion"] += 100
    result = kit.inspect_existing_launch(before, payload, _IMAGE)
    assert result.before_audit_session == origin
    assert result.before_responsibility == responsibility
    assert _CANARY not in result.model_dump_json()


def test_responsible_token_field_comparison_explains_mixed_snapshots_without_values() -> None:
    before = (2**32 - 1, 501, 20, 501, 20, 31001, 77, 41)
    target = (501, 501, 20, 501, 20, 31001, 88, 43)
    responsible = (2**32 - 1, 0, 0, 501, 20, 31001, 88, 42)
    result = kit.compare_responsible_token_fields(responsible, before, target)
    assert result.model_dump() == {
        "audit_user": "BEFORE",
        "effective_user": "ZERO",
        "effective_group": "ZERO",
        "real_user": "BOTH",
        "real_group": "BOTH",
        "pid": "BOTH",
        "audit_session": "TARGET",
        "pid_version": "OTHER",
        "same_pid_version_position": "BETWEEN",
    }
    assert not any(isinstance(value, int) for value in result.model_dump().values())


@pytest.mark.parametrize(
    "version,label",
    [
        (40, "LESS_THAN_BOTH"),
        (41, "BEFORE"),
        (42, "BETWEEN"),
        (43, "TARGET"),
        (44, "GREATER_THAN_BOTH"),
    ],
)
def test_responsible_token_numeric_position_does_not_assert_execution_order(
    version: int, label: str
) -> None:
    before = (501, 501, 20, 501, 20, 31001, 77, 41)
    target = (*before[:-1], 43)
    result = kit.compare_responsible_token_fields((*before[:-1], version), before, target)
    assert result.same_pid_version_position == label
    foreign = (*before[:5], 31002, before[6], version)
    assert (
        kit.compare_responsible_token_fields(foreign, before, target).same_pid_version_position
        == "INCONCLUSIVE"
    )


@pytest.mark.parametrize("token", [(0,) * 7, (0,) * 9, (True,) * 8, (-1,) * 8, (2**32,) * 8])
def test_responsible_token_comparison_rejects_invalid_words(token: tuple) -> None:
    with pytest.raises(ValueError, match="eight validated unsigned words"):
        kit.compare_responsible_token_fields(token, (0,) * 8, (0,) * 8)


def test_maximum_word_comparison_does_not_assign_audit_user_semantics_to_other_fields() -> None:
    result = kit.compare_responsible_token_fields((2**32 - 1,) * 8, (0,) * 8, (1,) * 8)
    assert set(result.model_dump(exclude={"same_pid_version_position"}).values()) == {"MAX_WORD"}
    assert result.same_pid_version_position == "INCONCLUSIVE"

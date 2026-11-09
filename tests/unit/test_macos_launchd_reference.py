# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented launchd records and mocked commands only; never run a native job."""

import importlib.util
import io
import json
import plistlib
import re
import sys
from copy import deepcopy
from itertools import count
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_launchd_reference as kit

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_endpoint_security_contracts import _process, _record

_CANARY = "INVENTED_PRIVATE_LAUNCHD_CANARY"
_SUCCESS = b"REGISTERED\nACTIVATED\nREMOVED\nFILES_REMOVED\n"


@pytest.fixture(autouse=True)
def no_native_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Launchd reference tests cannot run any native command")

    monkeypatch.setattr(kit.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.os, "execve", forbidden)


def _manifest() -> kit.Manifest:
    image = kit.reference.Image
    return kit.Manifest(
        os_version="27.0",
        os_build="invented",
        marker=image(device=123, inode=19001, sha256="a" * 64),
        images={
            role: image(device=123, inode=7000 + i, sha256="b" * 64)
            for i, role in enumerate(kit.PATHS)
        },
        ready_marker=image(device=123, inode=19002, sha256="c" * 64),
        guard_sha256="c" * 64,
        job_guard_sha256="e" * 64,
        codec_sha256="d" * 64,
        code_sha256={},
        nonce="e" * 32,
        username=_CANARY,
        home=f"/Users/{_CANARY}",
        uid=501,
        gid=20,
    )


def _chain(*, proxy: bool = True) -> list[dict]:
    manifest = _manifest()

    def image(process: dict, role: str) -> dict:
        value = manifest.marker if role == "TARGET" else manifest.images[role]
        process["executable"]["path"] = kit.PROGRAM if role == "TARGET" else kit.PATHS[role]
        process["executable"]["stat"].update(st_dev=value.device, st_ino=value.inode)
        return process

    boot = image(_process(11, 1, 0), "LAUNCHD")
    boot["audit_token"].update(auid=2**32 - 1, euid=0, egid=0, ruid=0, rgid=0)
    boot["group_id"] = boot["session_id"] = 1
    boot["responsible_audit_token"] = deepcopy(boot["audit_token"])
    before = deepcopy(boot)
    before["audit_token"].update(pid=1200, pidversion=1300)
    before["parent_audit_token"] = deepcopy(boot["audit_token"])
    before["ppid"] = before["original_ppid"] = 1
    fork = _record(11, "fork")
    fork["process"], fork["event"]["fork"]["child"] = boot, deepcopy(before)
    rows = [fork]
    for role in (["XPCPROXY"] if proxy else []) + ["TARGET"]:
        target = image(deepcopy(before), role)
        target["audit_token"]["pidversion"] += 1
        target["group_id"] = 1200
        row = _record(11, "exec")
        payload = row["event"]["exec"]
        row["process"] = deepcopy(before)
        payload.update(
            target=deepcopy(target),
            args=kit._arguments(manifest)
            if role == "TARGET"
            else ["xpcproxy", kit._label(manifest)],
            env=[
                "PATH=/usr/bin:/bin",
                "LANG=C",
                "LC_ALL=C",
                f"EFORGE_LAUNCHD_REFERENCE_TOKEN={manifest.nonce}",
                f"XPC_SERVICE_NAME={kit._label(manifest)}",
                "XPC_FLAGS=0x0",
                f"PRIVATE={_CANARY}",
            ],
            entitlements=None,
            fds=[{"fd": fd, "fdtype": 1} for fd in range(3)],
            last_fd=2,
            dyld_exec_path=target["executable"]["path"],
        )
        payload["cwd"]["path"] = "/"
        rows.append(row)
        before = target
    end = _record(11, "exit")
    end["process"], end["event"]["exit"]["stat"] = deepcopy(before), 0
    rows.append(end)
    _sequence(rows)
    return rows


def _sequence(rows: list[dict]) -> None:
    sequences: dict[int, int] = {}
    for i, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"] = sequences.get(kind, 0)
        sequences[kind] = row["seq_num"] + 1
        row["global_seq_num"] = i + 1


def _track(rows: list[dict]) -> kit.Tracker:
    tracker = kit.Tracker(_manifest())
    tracker.collecting = True
    for row in rows:
        assert tracker.accept(json.dumps(row).encode()) == []
    return tracker


@pytest.mark.parametrize("proxy", [False, True])
def test_exact_job_spine_excludes_launchd_siblings_and_all_native_values(proxy: bool) -> None:
    rows = _chain(proxy=proxy)
    noise = deepcopy(rows[0])
    noise["event"]["fork"]["child"]["audit_token"].update(pid=9000, pidversion=9900)
    rows.insert(1, noise)
    _sequence(rows)
    tracker = _track(rows)
    retained = tracker.retained()
    assert len(retained) == len(rows) - 1
    phases, graph = kit.analyze(retained, _manifest(), Path("/private/tmp") / _CANARY)
    assert [phase.role for phase in phases] == (["XPCPROXY"] if proxy else []) + ["TARGET"]
    assert [event.kind for event in graph] == ["FORK"] + ["EXEC"] * len(phases) + ["EXIT"]
    assert graph[0].before.life == "BOOT" and graph[0].after.life == "L0"
    assert graph[0].fork_parent_token == "PASS"
    assert graph[-1].exit_outcome == "ZERO"
    assert all(phase.native_shape == "PASS" for phase in phases)
    assert all(event.native_shape == "PASS" for event in graph)
    assert all(phase.arguments_match_template == "PASS" for phase in phases)
    assert all(phase.credentials == ("ZERO",) * 4 for phase in phases)
    assert all(phase.environment.controlled_values == "PASS" for phase in phases)
    assert all(phase.environment.other_keys == "PRESENT" for phase in phases)
    assert all(phase.environment.xpc_service_name == "TEST_LABEL" for phase in phases)
    report = kit.Report(phases=phases, graph=graph)
    value = report.model_dump_json()
    for secret in (_CANARY, _manifest().nonce, "/usr/bin/true", "1200", "1300", "9000", "19001"):
        assert secret not in value
    assert kit.Report.model_validate_json(value) == report


@pytest.mark.parametrize(
    "damage",
    [
        "nonce",
        "environment",
        "duplicate_env",
        "inode",
        "no_root",
        "fork_token",
        "birth",
        "exit_birth",
        "exit_token",
        "duplicate_exec",
        "duplicate_exit",
        "duplicate_fork",
        "exit_failure",
        "sequence",
        "global_sequence",
        "root_image",
    ],
)
def test_unproved_or_ambiguous_jobs_never_release_records(damage: str) -> None:
    rows = _chain()
    payload = rows[-2]["event"]["exec"]
    if damage == "nonce":
        payload["args"][-1] = "f" * 32
    elif damage == "environment":
        payload["env"] = ["OTHER=unproved"]
    elif damage == "duplicate_env":
        payload["env"].append("PATH=/usr/bin:/bin")
    elif damage == "inode":
        payload["target"]["executable"]["stat"]["st_ino"] += 1
    elif damage == "no_root":
        rows.pop(0)
    elif damage == "root_image":
        rows[0]["process"]["executable"]["stat"]["st_ino"] += 1
    elif damage == "fork_token":
        rows[0]["event"]["fork"]["child"]["parent_audit_token"]["pidversion"] += 1
    elif damage == "birth":
        rows[1]["process"]["start_time"] = "2026-10-19T10:00:00Z"
    elif damage == "exit_birth":
        rows[-1]["process"]["start_time"] = "2026-10-19T10:00:00Z"
    elif damage == "exit_token":
        rows[-1]["process"]["audit_token"]["pidversion"] += 1
    elif damage == "exit_failure":
        rows[-1]["event"]["exit"]["stat"] = 256
    elif damage == "duplicate_exec":
        rows.insert(-1, deepcopy(rows[-2]))
    elif damage == "duplicate_exit":
        rows.append(deepcopy(rows[-1]))
    elif damage == "duplicate_fork":
        rows.insert(1, deepcopy(rows[0]))
    _sequence(rows)
    if damage == "sequence":
        rows[-1]["seq_num"] += 1
        rows.insert(-1, deepcopy(rows[-1]))
    elif damage == "global_sequence":
        rows[-1]["global_seq_num"] = rows[-2]["global_seq_num"]
    assert not _track(rows).retained()


def test_readiness_requires_own_spawned_marker_exec_and_matching_zero_exit() -> None:
    tracker = kit.Tracker(_manifest())
    marker = _process(11, 8888)
    marker["executable"]["stat"].update(st_dev=123, st_ino=19002)
    start, end = _record(11, "exec"), _record(11, "exit")
    start["event"]["exec"].update(target=marker, args=["ready-marker", "--ready"])
    end["process"], end["event"]["exit"]["stat"] = deepcopy(marker), 0
    _sequence([start, end])
    tracker.accept(json.dumps(start).encode())
    tracker.accept(json.dumps(end).encode())
    assert not tracker.ready
    tracker = kit.Tracker(_manifest())
    tracker.ready_pids.add(8888)
    tracker.accept(json.dumps(start).encode())
    assert not tracker.ready
    tracker.accept(json.dumps(end).encode())
    assert tracker.ready and not tracker.ring


def test_memory_and_report_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kit, "MAX_ROWS", 2)
    tracker = _track(_chain())
    assert tracker.evicted and len(tracker.ring) == 2 and not tracker.retained()
    monkeypatch.setattr(kit, "MAX_STREAM", 1)
    with pytest.raises(kit.CaptureLimit) as caught:
        kit.Tracker(_manifest()).accept(json.dumps(_chain()[0]).encode())
    assert caught.value.scope == "STREAM_BYTES"
    with pytest.raises(kit.CaptureLimit, match="LIMIT"):
        kit.analyze([json.dumps(_chain()[0]).encode()] * 33, _manifest(), Path("/private/tmp"))


def test_changed_launch_environment_is_measured_instead_of_discarding_the_reference() -> None:
    rows = _chain()
    rows[-2]["event"]["exec"]["env"][0] = "PATH=/usr/bin"
    retained = _track(rows).retained()
    assert retained
    phases, _ = kit.analyze(retained, _manifest(), Path("/private/tmp"))
    assert phases[-1].environment.controlled_values == "FAIL"
    assert phases[-1].environment_from_previous_exec.comparison == "COMMON_VALUES_CHANGED"


@pytest.mark.parametrize(
    "field", ["purpose", "error", "stage", "step", "job_removed", "wire_profile"]
)
def test_report_rejects_untrusted_text(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@requires_posix_reference
def test_prepare_is_code_only_exclusive_and_loads_all_shared_comparisons(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "fresh")
    assert set(path.name for path in root.iterdir()) == set(kit.CODE) | {"PRIVATE-RUN.md"}
    assert root.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in root.iterdir())
    spec = importlib.util.spec_from_file_location("_prepared_launchd_test", root / kit.CODE[0])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    phases, graph = module.analyze(
        [json.dumps(row).encode() for row in _chain()],
        module.Manifest.model_validate_json(_manifest().model_dump_json()),
        root,
    )
    assert phases[-1].role == "TARGET" and graph[0].before.role == "LAUNCHD"
    with pytest.raises(FileExistsError):
        kit.prepare(root)


@requires_posix_reference
def test_setup_and_manifest_bind_guards_code_codec_and_installed_images(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = kit.prepare(tmp_path / "fresh")
    monkeypatch.setattr(kit, "__file__", str(root / kit.CODE[0]))
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "invented"))
    owner = root.stat()
    monkeypatch.setattr(
        kit,
        "_current_account",
        lambda: SimpleNamespace(
            pw_name=_CANARY,
            pw_dir=f"/Users/{_CANARY}",
            pw_uid=owner.st_uid,
            pw_gid=owner.st_gid,
        ),
    )
    manifest = _manifest()
    monkeypatch.setattr(
        kit.support,
        "_installed_image",
        lambda path: (
            manifest.marker
            if str(path) == kit.PROGRAM
            else manifest.images[
                next(role for role, value in kit.PATHS.items() if str(path) == value)
            ]
        ),
    )
    monkeypatch.setattr(kit.support, "_image", lambda _path: manifest.ready_marker)
    commands = []

    def command(args: list[str], _root: Path) -> None:
        commands.append(args[0])
        if args[0] == "/usr/bin/clang":
            Path(args[-1]).write_bytes(b"invented executable")

    monkeypatch.setattr(kit.reference, "_command", command)
    report = kit.setup()
    assert report.stage == "SETUP_READY"
    assert commands == ["/usr/bin/clang"] * 3 + ["/usr/bin/codesign"]
    assert kit._manifest(root).username == _CANARY
    assert kit._manifest(root).uid == owner.st_uid
    for name in ("job-guard", "collector-guard", "job_guard.c", "ssh_analysis_support.py"):
        path = root / name
        original = path.read_bytes()
        path.write_bytes(b"tampered")
        with pytest.raises(kit.reference.PrivateError, match="BUILD"):
            kit._manifest(root)
        path.write_bytes(original)
    with pytest.raises(FileExistsError):
        kit.setup()


def test_guard_contract_uses_fixed_program_exact_targets_and_no_persistent_settings() -> None:
    code = (
        Path(kit.__file__).parents[1]
        / "docs/design/macos-workstation-feasibility/launchd-reference/job_guard.c"
    ).read_text()
    body = code.split("int plen = snprintf(plist, sizeof(plist),", 1)[1].split(
        "argv[2], argv[2], argv[2]);", 1
    )[0]
    text = "".join(json.loads(match) for match in re.findall(r'"(?:[^"\\]|\\.)*"', body))
    text = text.replace("%s", "a" * 32)
    plist = plistlib.loads(text.encode())
    assert plist["ProgramArguments"] == [kit.PROGRAM, "--eforge-launchd-reference", "a" * 32]
    assert plist["RunAtLoad"] is False and plist["KeepAlive"] is False
    assert all(
        plist[key] == "/dev/null"
        for key in ("StandardInPath", "StandardOutPath", "StandardErrorPath")
    )
    assert '"bootstrap", "system", path, NULL' in code
    assert '"kickstart", service, NULL' in code and '"bootout", service, NULL' in code
    assert '"system/org.evidenceforge.reference.launchd.%s"' in code
    assert "O_NOFOLLOW" in code and "O_EXCL" in code and "info.st_uid != 0" in code
    assert "signal(SIGPIPE, SIG_IGN)" in code
    assert "cancelled()" in code and "alarm(22)" in code and "current - start > 5" in code
    assert "command(bootout, 1)" in code
    assert "execve(args[0]" not in code and "system(" not in code
    for forbidden in (
        '"enable"',
        '"disable"',
        '"print"',
        '"list"',
        '"-k"',
        '"-p"',
        '"/Library/LaunchDaemons',
    ):
        assert forbidden not in code


@pytest.mark.parametrize(
    "output,status", [(_SUCCESS, 0), (b"REGISTRATION_FAIL\nREMOVAL_FAIL\n", 2), (_SUCCESS, -9)]
)
def test_guard_fixed_statuses_preserve_failure_and_cleanup_separately(
    output: bytes, status: int
) -> None:
    job = SimpleNamespace(
        stdin=io.BytesIO(), stdout=io.BytesIO(output), wait=lambda **_kwargs: status
    )
    values = kit._finish_job(job, cancel=True)
    assert job.stdin.closed
    assert values["job_guard"] == ("PASS" if status == 0 else "FAIL")
    assert values["job_removed"] == ("PASS" if b"REMOVED\n" in output else "FAIL")


@pytest.mark.parametrize("output", [b"", b"REMOVED\n" * 2, _CANARY.encode(), b"a" * 257])
def test_guard_untrusted_or_truncated_statuses_never_escape(output: bytes) -> None:
    job = SimpleNamespace(stdout=io.BytesIO(output), wait=lambda **_kwargs: 0)
    with pytest.raises(kit.reference.PrivateError, match="JOB"):
        kit._finish_job(job, cancel=False)


def test_guard_timeout_does_not_claim_cleanup_and_closes_cancellation_pipe() -> None:
    def timeout(**_kwargs: object) -> None:
        raise kit.subprocess.TimeoutExpired("invented", 8)

    job = SimpleNamespace(stdin=io.BytesIO(), wait=timeout)
    assert kit._finish_job(job, cancel=True) == {
        "job_removed": "FAIL",
        "temporary_files_removed": "INCONCLUSIVE",
    }
    assert job.stdin.closed


@requires_posix_reference
@pytest.mark.parametrize(
    "failure",
    [
        None,
        "collector",
        "job",
        "interrupted",
        "analysis",
        "limit",
        "job_cleanup",
        "collector_cleanup",
        "job_stream_close",
        "collector_stop_exception",
    ],
)
def test_capture_is_automatic_single_use_and_cleans_before_native_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    root = tmp_path / "fresh"
    root.mkdir(mode=0o700)
    manifest = _manifest()
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit, "_manifest", lambda _root: manifest)
    monkeypatch.setattr(kit.reference, "_preflight", lambda: ("27.0", "invented"))
    clock = count()
    monkeypatch.setattr(kit.time, "monotonic", lambda: float(next(clock)))
    closed, commands = [], []
    collector = SimpleNamespace(stdout=SimpleNamespace(close=lambda: closed.append("stdout")))
    job = SimpleNamespace(
        stdin=io.BytesIO(), stdout=io.BytesIO(_SUCCESS), poll=lambda: 0, wait=lambda **_kwargs: 0
    )

    def popen(args: list[str], **_kwargs: object) -> object:
        commands.append(args)
        return job if "job-guard" in args[2] else collector

    class Pump:
        def __init__(self, _guard: object, tracker: kit.Tracker, files: dict) -> None:
            assert files == {}
            self.tracker = tracker
            self.sent = False
            self.selector = SimpleNamespace(close=lambda: closed.append("selector"))

        def tick(self) -> None:
            if failure == "collector":
                raise kit.reference.PrivateError("COLLECTOR")
            if not self.tracker.ready:
                self.tracker.ready = True
            elif failure == "interrupted":
                raise KeyboardInterrupt(_CANARY)
            elif not self.sent:
                for row in _chain():
                    self.tracker.accept(json.dumps(row).encode())
                self.sent = True

    monkeypatch.setattr(kit.subprocess, "Popen", popen)
    monkeypatch.setattr(kit.reference, "Pump", Pump)
    monkeypatch.setattr(kit.reference, "_start", lambda *_args: SimpleNamespace(pid=77))
    monkeypatch.setattr(kit.reference, "_stop_probe", lambda _probe: closed.append("probe"))
    monkeypatch.setattr(
        kit.reference,
        "_stop_collector",
        lambda _guard: closed.append("collector") or failure != "collector_cleanup",
    )
    if failure == "collector_stop_exception":

        def stop_error(_guard: object) -> None:
            closed.append("collector")
            raise OSError(_CANARY)

        monkeypatch.setattr(kit.reference, "_stop_collector", stop_error)
    if failure == "job_stream_close":
        real_close = kit._close_job

        def close_error(value: object) -> None:
            real_close(value)
            raise kit.reference.PrivateError("JOB")

        monkeypatch.setattr(kit, "_close_job", close_error)
    if failure in {"job", "job_cleanup"}:
        job.stdout = io.BytesIO(b"REGISTRATION_FAIL\nREMOVAL_FAIL\n")
        job.wait = lambda **_kwargs: 2
    if failure in {"analysis", "limit"}:

        def fail(*_args: object) -> None:
            raise kit.CaptureLimit("FIXED_REPORT") if failure == "limit" else ValueError(_CANARY)

        monkeypatch.setattr(kit, "analyze", fail)
    report = kit.capture()
    assert commands[0] == ["/usr/bin/sudo", "-n", str(root / "collector-guard")]
    if failure != "collector":
        assert commands[1] == [
            "/usr/bin/sudo",
            "-n",
            str(root / "job-guard"),
            "run",
            manifest.nonce,
        ]
        assert job.stdin.closed and job.stdout.closed
    assert set(closed) >= {"collector", "stdout", "selector"}
    assert _CANARY not in report.model_dump_json()
    assert bool(list(root.rglob("launchd-chain-events.jsonl"))) is (failure is None)
    assert (
        report.error
        == {
            None: "NONE",
            "collector": "COLLECTOR",
            "job": "JOB",
            "interrupted": "INTERRUPTED",
            "analysis": "INTERNAL",
            "limit": "LIMIT",
            "job_cleanup": "JOB",
            "collector_cleanup": "COLLECTOR",
            "job_stream_close": "JOB",
            "collector_stop_exception": "COLLECTOR",
        }[failure]
    )
    assert _CANARY not in next(root.rglob("SHAREABLE-REPORT.json")).read_text()
    with pytest.raises(FileExistsError):
        kit.capture()


@requires_posix_reference
def test_report_only_reads_fixed_saved_json_and_never_native_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "kit"
    root.mkdir(mode=0o700)
    run = root / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    kit.reference._write(root / "ACTIVE-RUN", (run.name + "\n").encode())
    kit.reference._write(run / "SHAREABLE-REPORT.json", kit.Report().model_dump_json().encode())
    kit.reference._write(run / "launchd-chain-events.jsonl", _CANARY.encode())
    monkeypatch.setattr(kit, "_root", lambda: root)
    monkeypatch.setattr(kit.sys, "argv", ["private_launchd.py", "report", "--private-run"])
    kit.main()
    output = capsys.readouterr().out
    assert _CANARY not in output and kit.Report.model_validate_json(output).error == "NONE"


@pytest.mark.parametrize(
    "args",
    [
        ["capture"],
        ["setup", "--private-run"],
        ["capture", "--private-run"],
        ["report", "--private-run"],
        ["cleanup", "--private-run"],
        [_CANARY],
    ],
)
def test_repo_source_refuses_live_operations_and_untrusted_parser_output(
    args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(kit.sys, "argv", ["macos_launchd_reference.py", *args])
    kit.main()
    output = capsys.readouterr()
    assert _CANARY not in output.out + output.err
    assert kit.Report.model_validate_json(output.out).error in {"LOCATION", "INPUT"}

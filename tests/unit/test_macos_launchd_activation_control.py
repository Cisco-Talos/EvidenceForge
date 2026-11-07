"""Collector-free activation uses mocked commands and a C harness with fake job syscalls."""

import io
import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts import macos_ulf_launchd_reference as kit

from tests.support.platforms import requires_posix_reference

NONCE = "a" * 32
SECRET = "invented-private-activation-canary"
SUCCESS = (
    b"DIRECTORY_CREATED\nLEASE_WRITTEN\nREGISTRATION_ATTEMPTED\nREGISTERED\n"
    b"ACTIVATION_ATTEMPTED\nACTIVATED\nREMOVAL_ATTEMPTED\nREMOVED\nFILES_REMOVED\n"
)


@requires_posix_reference
def test_fresh_setup_hashes_the_detailed_guard_protocol_without_executing_controls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    commands: list[list[str]] = []

    def compile_only(arguments: list[str], **kwargs: object) -> SimpleNamespace:
        commands.append(arguments)
        assert arguments[0] == "/usr/bin/cc"
        Path(arguments[-1]).write_bytes(b"synthetic non-executable compiler output")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", compile_only)
    monkeypatch.setattr(
        kit.subprocess, "Popen", lambda *a, **k: pytest.fail("no control execution")
    )
    root = kit.prepare(tmp_path)
    result = kit.setup(root)
    assert result.stage == "SETUP_READY" and result.error == "NONE"
    config = kit._config(root)
    assert config.guard_protocol == "detailed-v1"
    assert kit._guard_operation(config) == "run-diagnostic"
    assert kit._guard_operation(config, recovery=True) == "cleanup-diagnostic"
    assert len(commands) == 2 and not (root / "CONTROL-TEST-ATTEMPTED.json").exists()


@pytest.mark.parametrize(
    "output,returncode,timed_out,expected",
    [
        (SUCCESS, 0, False, "PASS"),
        (SUCCESS, 2, False, "FAIL"),
        (SUCCESS, -9, False, "FAIL"),
        (SUCCESS, 0, True, "INCONCLUSIVE"),
        (b"LOCATION_FAIL\nFAILURE_DIRECTORY_CREATE_PERMISSION_DENIED\n", 2, False, "FAIL"),
        (SUCCESS + SECRET.encode(), 0, False, "FAIL"),
        (SUCCESS + b"ACTIVATED\n", 0, False, "FAIL"),
        (SECRET.encode(), 1, False, "FAIL"),
        (b"X" * 4097, 2, False, "FAIL"),
    ],
)
def test_control_test_keeps_cancellation_open_and_never_starts_a_collector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    output: bytes,
    returncode: int,
    timed_out: bool,
    expected: str,
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(
        kit,
        "_config",
        lambda root: kit.Config(nonce=NONCE, hashes={}, guard_protocol="detailed-v1"),
    )
    monkeypatch.setattr(kit, "_read", lambda *a: pytest.fail("no native records"))
    monkeypatch.setattr(
        kit.subprocess,
        "run",
        lambda args, **kwargs: (
            SimpleNamespace(returncode=0)
            if args == ["/usr/bin/sudo", "-n", "-v"]
            else pytest.fail("no other commands")
        ),
    )
    commands: list[list[str]] = []

    class Job:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(output)
            self.waits: list[int] = []

        def wait(self, *, timeout: int) -> int:
            self.waits.append(timeout)
            if len(self.waits) == 1:
                assert not self.stdin.closed
                if timed_out:
                    raise subprocess.TimeoutExpired("invented-guard", timeout)
            else:
                assert self.stdin.closed
            return returncode

    job = Job()

    def popen(arguments: list[str], **kwargs: object) -> Job:
        commands.append(arguments)
        assert kwargs["stdin"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.DEVNULL
        return job

    monkeypatch.setattr(kit.subprocess, "Popen", popen)
    report = kit.self_test(tmp_path)
    assert report.result == expected
    assert report.error == (
        "NONE" if expected == "PASS" else "LIMIT" if len(output) > 4096 else "CONTROL"
    )
    assert report.collection == "NONE" and report.collectors == "NOT_STARTED"
    assert report.native_record_files == "NOT_OPENED"
    assert report.native_execution_evidence == "NOT_COLLECTED"
    assert job.stdin.closed and job.stdout.closed
    assert job.waits == ([30, 12] if timed_out else [30])
    assert commands == [
        ["/usr/bin/sudo", "-n", str(tmp_path / "job-guard"), "run-diagnostic", NONCE]
    ]
    assert SECRET not in report.model_dump_json() and NONCE not in report.model_dump_json()
    assert {path.name for path in tmp_path.iterdir()} == {
        "CONTROL-TEST-ATTEMPTED.json",
        "SHAREABLE-ACTIVATION-REPORT.json",
    }
    if b"FAILURE_DIRECTORY_CREATE_PERMISSION_DENIED" in output:
        assert report.directory_created == "FAIL"
        assert [(f.stage, f.reason) for f in report.control_failures] == [
            ("DIRECTORY_CREATE", "PERMISSION_DENIED")
        ]


@pytest.mark.parametrize("used", ["legacy", "attempted", "report", "records"])
def test_control_test_refuses_old_or_previously_used_kits_before_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, used: str
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(
        kit,
        "_config",
        lambda root: kit.Config(
            nonce=NONCE, hashes={}, guard_protocol="legacy" if used == "legacy" else "detailed-v1"
        ),
    )
    name = {
        "attempted": "CONTROL-TEST-ATTEMPTED.json",
        "report": "SHAREABLE-ACTIVATION-REPORT.json",
        "records": "records.ndjson",
    }.get(used)
    if name:
        (tmp_path / name).write_text(SECRET)
    monkeypatch.setattr(kit.subprocess, "run", lambda *a, **k: pytest.fail("no command"))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **k: pytest.fail("no job"))
    report = kit.self_test(tmp_path)
    assert report.error == "CONTROL" and report.guard_exit == "NOT_RUN"
    assert SECRET not in report.model_dump_json()


def test_control_test_without_sudo_does_not_consume_or_start_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(
        kit,
        "_config",
        lambda root: kit.Config(nonce=NONCE, hashes={}, guard_protocol="detailed-v1"),
    )
    monkeypatch.setattr(kit.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **k: pytest.fail("no job"))
    report = kit.self_test(tmp_path)
    assert report.sudo_credentials == "FAIL" and report.guard_exit == "NOT_RUN"
    assert not list(tmp_path.iterdir())


def test_capture_cannot_reuse_a_control_test_kit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "CONTROL-TEST-ATTEMPTED.json").write_text("{}")
    monkeypatch.setattr(kit, "_platform", lambda: None)
    monkeypatch.setattr(kit, "_config", lambda root: kit.Config(nonce=NONCE, hashes={}))
    monkeypatch.setattr(kit.subprocess, "Popen", lambda *a, **k: pytest.fail("no collector"))
    with pytest.raises(kit.PrivateError, match="CONTROL"):
        kit.capture(tmp_path)


def test_legacy_guard_commands_and_reports_stay_readable() -> None:
    legacy = kit.Config(nonce=NONCE, hashes={})
    assert kit._guard_operation(legacy) == "run"
    assert kit._guard_operation(legacy, recovery=True) == "cleanup"
    assert kit.Report.model_validate_json('{"kit_version":3}').control_failures == ()
    flags = kit._guard_flags(b"LOCATION_FAIL\nFAILURE_LEASE_WRITE_NO_SPACE\n" + SECRET.encode())
    assert [(v.stage, v.reason) for v in kit._guard_failures(flags)] == [
        ("LEASE_WRITE", "NO_SPACE")
    ]


def test_cli_control_test_uses_only_the_fresh_local_kit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(kit.sys, "argv", ["private_ulf_launchd.py", "self-test", "--private-run"])
    monkeypatch.setattr(kit, "_root", lambda root: tmp_path)
    monkeypatch.setattr(
        kit, "self_test", lambda root: kit.ActivationReport(stage="COMPLETE", result="PASS")
    )
    assert kit.main() == 0
    assert json.loads(capsys.readouterr().out)["collection"] == "NONE"


@pytest.fixture(scope="module")
def synthetic_guard(tmp_path_factory: pytest.TempPathFactory) -> Path:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("C compiler unavailable; Python privacy contracts still run")
    root = tmp_path_factory.mktemp("synthetic-activation-guard")
    guard = Path(
        "docs/design/macos-workstation-feasibility/launchd-reference/job_guard.c"
    ).resolve()
    harness = Path(__file__).parent.parent / "support" / "launchd_guard_harness.c"
    binary = root / "synthetic-guard"
    compiled = subprocess.run(
        [
            compiler,
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DEFORGE_GUARD_SOURCE=" + json.dumps(str(guard)),
            str(harness),
            "-o",
            str(binary),
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr.decode()
    return binary


@requires_posix_reference
@pytest.mark.parametrize(
    "fault,stage,reason",
    [
        ("directory_create", "DIRECTORY_CREATE", "PERMISSION_DENIED"),
        ("directory_open", "DIRECTORY_OPEN", "PERMISSION_DENIED"),
        ("directory_stat", "DIRECTORY_STAT", "OTHER_SYSTEM_ERROR"),
        ("directory_metadata", "DIRECTORY_VALIDATE", "UNSAFE_METADATA"),
        ("lease_create", "LEASE_CREATE", "PERMISSION_DENIED"),
        ("lease_write", "LEASE_WRITE", "NO_SPACE"),
        ("short_write", "LEASE_WRITE", "SHORT_WRITE"),
        ("lease_close", "LEASE_CLOSE", "OTHER_SYSTEM_ERROR"),
        ("registration", "REGISTRATION", "COMMAND_EXIT"),
        ("activation", "ACTIVATION", "COMMAND_EXIT"),
        ("removal", "REMOVAL", "COMMAND_EXIT"),
        ("file_removal", "FILE_REMOVAL", "PERMISSION_DENIED"),
        ("timeout", "REGISTRATION", "TIMED_OUT"),
        ("cancel", "REGISTRATION", "CANCELLED"),
        ("spawn", "REGISTRATION", "SPAWN_ERROR"),
        ("signal", "REGISTRATION", "COMMAND_SIGNAL"),
        ("clock", "REGISTRATION", "CLOCK_ERROR"),
    ],
)
def test_c_guard_reports_the_original_failure_stage_without_running_native_commands(
    tmp_path: Path, synthetic_guard: Path, fault: str, stage: str, reason: str
) -> None:
    target = tmp_path / "synthetic-control"
    result = subprocess.run(
        [str(synthetic_guard), str(target), fault, "run-diagnostic", NONCE],
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode == 2
    flags = kit._guard_flags(result.stdout)
    failures = kit._guard_failures(flags)
    assert (stage, reason) in [(failure.stage, failure.reason) for failure in failures]
    assert str(target).encode() not in result.stdout and NONCE.encode() not in result.stdout
    assert b"NATIVE_COMMAND_ATTEMPTED" not in result.stderr


@requires_posix_reference
@pytest.mark.parametrize("mode", ["run", "run-diagnostic"])
def test_c_guard_success_keeps_legacy_wire_output_and_removes_only_synthetic_controls(
    tmp_path: Path, synthetic_guard: Path, mode: str
) -> None:
    target = tmp_path / "synthetic-control"
    result = subprocess.run(
        [str(synthetic_guard), str(target), "none", mode, NONCE],
        capture_output=True,
        timeout=5,
        check=True,
    )
    assert not target.exists()
    assert result.stdout == (
        SUCCESS if mode == "run-diagnostic" else b"REGISTERED\nACTIVATED\nREMOVED\nFILES_REMOVED\n"
    )

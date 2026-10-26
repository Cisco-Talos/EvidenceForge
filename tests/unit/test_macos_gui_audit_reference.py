# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented inputs only. Never run the probe, a native preflight or a collector."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from scripts import macos_gui_audit_reference as kit

_CANARY = "INVENTED_PRIVATE_CANARY_never_export"


def _sample(slot: kit.Slot = "window_a", index: int = 0) -> kit.Sample:
    pid = 1000 + index * 10
    root = kit.Snapshot(
        pid=pid,
        ppid=700 + index,
        sid=800 + index,
        pgid=pid,
        uid=501,
        euid=501,
        gid=20,
        egid=20,
        auid=501,
        asid=12345,
        token_pid=pid,
        token_uid=501,
        token_euid=501,
        token_gid=20,
        token_egid=20,
    )
    child = root.model_copy(update={"pid": pid + 1, "token_pid": pid + 1, "ppid": pid})
    return kit.Sample(
        slot=slot,
        shell_pid=600 + index,
        source_sha256="a" * 64,
        helper_sha256="b" * 64,
        binary_sha256="c" * 64,
        same_boot_gui_relogin_attested=slot == "fresh_login",
        probe=kit.Probe(root=root, forked=child, executed=child),
    )


def _samples() -> tuple[kit.Sample, ...]:
    return tuple(_sample(slot, index) for index, slot in enumerate(kit.SLOTS[:3]))


def _audit_session(sample: kit.Sample, value: int) -> kit.Sample:
    return sample.model_copy(
        update={
            "probe": kit.Probe(
                **{
                    name: getattr(sample.probe, name).model_copy(update={"asid": value})
                    for name in ("root", "forked", "executed")
                }
            )
        }
    )


def test_controlled_identity_comparison_exports_no_ids_or_digests() -> None:
    report = kit.analyze(_samples())
    assert report.terminal_contexts == "COMPLETE"
    assert report.provenance_agreement == "PASS"
    assert report.own_token_agreement == "PASS"
    assert report.attributed_audit_identity == "PASS"
    assert report.audit_user_matches_real_user == "PASS"
    assert report.fork_linkage == "PASS"
    assert report.fork_preserves_audit_identity == "PASS"
    assert report.exec_preserves_audit_identity == "PASS"
    assert report.fork_exec_preserve_posix_session == "PASS"
    assert report.distinct_terminal_shells == "PASS"
    assert report.same_real_user == "PASS"
    assert report.terminal_audit_user == report.terminal_audit_session == "SAME"
    assert report.terminal_posix_session == "DIFFERENT"
    assert report.fresh_login_context == "NOT_COLLECTED"
    assert report.fresh_gui_login_audit_session == "INCONCLUSIVE"
    assert report.gate_status == "NOT_EVALUATED"
    assert report.reference_review == "REQUIRED"
    assert report.gui_startup_log_layout == report.endpoint_security_export == "NOT_COLLECTED"
    serialized = report.model_dump_json()
    for sample in _samples():
        assert str(sample.probe.root.asid) not in serialized
        assert sample.binary_sha256 not in serialized
    assert all(
        isinstance(value, str) for key, value in report.model_dump().items() if key != "kit_version"
    )


@pytest.mark.parametrize(
    ("values", "relationship"),
    [((100, 100, 100), "SAME"), ((100, 200, 300), "DIFFERENT"), ((100, 200, 100), "MIXED")],
)
def test_native_relationships_are_observations_not_expected_outcomes(
    values: tuple[int, int, int], relationship: str
) -> None:
    samples = tuple(_audit_session(s, value) for s, value in zip(_samples(), values, strict=True))
    assert kit.analyze(samples).terminal_audit_session == relationship


@pytest.mark.parametrize(
    "damage", ["token", "parent", "source", "default_asid", "unset_auid", "shell", "user"]
)
def test_failed_controls_prevent_cross_context_claims(damage: str) -> None:
    samples = list(_samples())
    first = samples[0]
    updates: dict[str, object] = {}
    if damage == "token":
        updates["root"] = first.probe.root.model_copy(update={"token_pid": 77})
    elif damage == "parent":
        updates["forked"] = first.probe.forked.model_copy(update={"ppid": 77})
    elif damage == "source":
        first = first.model_copy(update={"source_sha256": "d" * 64})
    elif damage == "shell":
        first = first.model_copy(update={"shell_pid": samples[1].shell_pid})
    elif damage == "user":
        updates["root"] = first.probe.root.model_copy(update={"uid": 502, "token_uid": 502})
    else:
        updates["root"] = first.probe.root.model_copy(
            update={"asid": 0} if damage == "default_asid" else {"auid": 2**32 - 1}
        )
    if updates:
        first = first.model_copy(update={"probe": first.probe.model_copy(update=updates)})
    samples[0] = first
    report = kit.analyze(tuple(samples))
    assert report.terminal_audit_user == "INCONCLUSIVE"
    assert report.terminal_audit_session == "INCONCLUSIVE"
    assert report.terminal_posix_session == "INCONCLUSIVE"


def test_inheritance_failures_remain_visible() -> None:
    samples = list(_samples())
    first = samples[0]
    child = first.probe.forked.model_copy(update={"asid": 456, "sid": 789})
    executed = child.model_copy(update={"asid": 457})
    samples[0] = first.model_copy(
        update={"probe": kit.Probe(root=first.probe.root, forked=child, executed=executed)}
    )
    report = kit.analyze(tuple(samples))
    assert report.fork_preserves_audit_identity == "FAIL"
    assert report.exec_preserves_audit_identity == "FAIL"
    assert report.fork_exec_preserve_posix_session == "FAIL"


def test_fresh_gui_login_requires_attestation_and_comparable_initial_context() -> None:
    fresh = _audit_session(_sample("fresh_login", 3), 98765)
    report = kit.analyze((*_samples(), fresh))
    assert report.fresh_login_context == "HUMAN_ATTESTED_SAME_BOOT"
    assert report.fresh_gui_login_audit_user == "SAME"
    assert report.fresh_gui_login_audit_session == "DIFFERENT"
    mixed = (_audit_session(_samples()[0], 555), *_samples()[1:], fresh)
    assert kit.analyze(mixed).fresh_gui_login_audit_session == "INCONCLUSIVE"
    with pytest.raises(kit.PrivateError, match="^DATA$"):
        kit.analyze(
            (*_samples(), fresh.model_copy(update={"same_boot_gui_relogin_attested": False}))
        )


def test_empty_partial_and_duplicate_inputs() -> None:
    assert kit.analyze(()).terminal_contexts == "INCOMPLETE"
    assert kit.analyze((_sample(),)).terminal_audit_session == "INCONCLUSIVE"
    with pytest.raises(kit.PrivateError, match="^DATA$"):
        kit.analyze((_sample(), _sample()))
    with pytest.raises(kit.PrivateError, match="^DATA$"):
        kit.analyze((object(),))


@pytest.mark.parametrize("field", tuple(kit.Report.model_fields))
def test_public_report_rejects_arbitrary_values(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@pytest.mark.parametrize("field", ["pid", "sid", "asid", "token_pid", "uid"])
@pytest.mark.parametrize("value", [True, -1, 2**32, "501"])
def test_private_input_requires_bounded_native_integer_shapes(field: str, value: object) -> None:
    data = _sample().probe.root.model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        kit.Snapshot.model_validate(data)


def test_unknown_private_fields_are_rejected() -> None:
    data = _sample().model_dump()
    data[_CANARY] = _CANARY
    with pytest.raises(ValidationError):
        kit.Sample.model_validate(data)


@pytest.fixture
def prepared(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A synthetic test attempted native preflight/execution")

    monkeypatch.setattr(kit, "_preflight", forbidden)
    monkeypatch.setattr(kit.subprocess, "run", forbidden)
    return kit.prepare(tmp_path / "invented-kit")


def test_preparation_is_code_only_and_refuses_overwrite(prepared: Path) -> None:
    assert {path.name for path in prepared.iterdir()} == {
        "private_gui_audit.py",
        "gui_audit_probe.c",
        "PRIVATE-RUN.md",
    }
    assert prepared.stat().st_mode & 0o077 == 0
    assert all(path.stat().st_mode & 0o077 == 0 for path in prepared.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(prepared)


@pytest.mark.parametrize("marker", ["file", "directory", "symlink"])
def test_preparation_refuses_git_locations(tmp_path: Path, marker: str) -> None:
    if marker == "file":
        (tmp_path / ".git").write_text("gitdir: invented")
    elif marker == "directory":
        (tmp_path / ".git").mkdir()
    else:
        (tmp_path / ".git").symlink_to(tmp_path / "missing-marker")
    with pytest.raises(kit.PrivateError, match="^LOCATION$"):
        kit.prepare(tmp_path / "new-kit")
    assert not (tmp_path / "new-kit").exists()


def test_repo_source_cannot_record_or_review() -> None:
    with pytest.raises(kit.PrivateError, match="^LOCATION$"):
        kit.record("window_a")
    with pytest.raises(kit.PrivateError, match="^LOCATION$"):
        kit.report()


@pytest.mark.parametrize("damage", ["symlink", "hardlink", "permissions", "size", "fifo"])
def test_private_file_boundary(tmp_path: Path, damage: str) -> None:
    path = tmp_path / "invented.json"
    if damage == "fifo":
        os.mkfifo(path, 0o600)
    else:
        path.write_bytes(b"x" * (kit.MAX_BYTES + 1) if damage == "size" else b"invented")
        path.chmod(0o600)
        if damage == "symlink":
            link = tmp_path / "link.json"
            link.symlink_to(path)
            path = link
        elif damage == "hardlink":
            (tmp_path / "other.json").hardlink_to(path)
        elif damage == "permissions":
            path.chmod(0o644)
    with pytest.raises((kit.PrivateError, OSError)):
        kit._read(path)


def test_mock_record_and_report_use_only_invented_data(
    prepared: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(kit, "__file__", str(prepared / "private_gui_audit.py"))
    monkeypatch.setattr(kit, "_preflight", lambda: None)
    current = [_sample()]
    monkeypatch.setattr(kit.os, "getppid", lambda: current[0].shell_pid)

    def command(args: list[str], _root: Path, code: kit.Code, _timeout: int) -> bytes:
        if code == "BUILD":
            assert args[0] == "/usr/bin/clang"
            (prepared / "audit-probe").write_bytes(b"INVENTED_BINARY")
            return b""
        assert code == "PROBE"
        assert args == [str(prepared / "audit-probe")]
        return current[0].probe.model_dump_json().encode()

    monkeypatch.setattr(kit, "_command", command)
    for sample in _samples():
        current[0] = sample
        kit.record(sample.slot)
    # Reports must not enumerate unrelated files or scan the directory.
    (prepared / "private" / "unrelated.txt").write_text(_CANARY)
    result = kit.report()
    assert result.terminal_audit_session == "SAME"
    assert result.distinct_terminal_shells == "PASS"
    assert _CANARY not in result.model_dump_json()
    with pytest.raises(kit.PrivateError, match="^DUPLICATE$"):
        kit.record("window_a")
    with pytest.raises(kit.PrivateError, match="^INPUT$"):
        kit.record("fresh_login")
    with pytest.raises(kit.PrivateError, match="^INPUT$"):
        kit.record("tab", same_boot_gui_relogin=True)
    (prepared / "gui_audit_probe.c").write_bytes(b"INVENTED_CHANGED_CODE")
    with pytest.raises(kit.PrivateError, match="^DATA$"):
        kit.record("fresh_login", same_boot_gui_relogin=True)


def test_subprocesses_have_fixed_environment_and_private_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(args: list[str], **kwargs: object) -> SimpleNamespace:
        assert args == ["/invented/probe"]
        assert kwargs == {
            "cwd": Path("/invented"),
            "env": kit.SAFE_ENV,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "timeout": 12,
            "check": True,
        }
        return SimpleNamespace(stdout=b"invented")

    monkeypatch.setattr(kit.subprocess, "run", run)
    assert kit._command(["/invented/probe"], Path("/invented"), "PROBE", 12) == b"invented"


@pytest.mark.parametrize(
    "error", [OSError(_CANARY), ValueError(_CANARY), KeyboardInterrupt(_CANARY)]
)
def test_main_redacts_all_failure_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: BaseException
) -> None:
    def fail() -> kit.Report:
        raise error

    monkeypatch.setattr(kit, "report", fail)
    assert kit.main(["report", "--private-run"]) == 2
    captured = capsys.readouterr()
    assert _CANARY not in captured.out + captured.err
    assert captured.err == ""
    assert kit.Report.model_validate_json(captured.out).error in {"INTERNAL", "INTERRUPTED"}


def test_parser_never_echoes_unknown_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert kit.main(["record", _CANARY, "--private-run"]) == 2
    captured = capsys.readouterr()
    assert _CANARY not in captured.out + captured.err
    assert json.loads(captured.out)["error"] == "INPUT"


def test_probe_source_is_self_only_not_a_system_log_reader() -> None:
    source = (kit.SOURCES / "gui_audit_probe.c").read_text()
    assert "task_info(mach_task_self(), TASK_AUDIT_TOKEN" in source
    for forbidden in (
        "task_for_pid(",
        "getenv(",
        "eslogger",
        "auditon(",
        "setaudit",
        "system(",
        "popen(",
    ):
        assert forbidden not in source

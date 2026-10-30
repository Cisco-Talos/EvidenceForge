# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented terminal evidence only; no native commands, apps, probes or captures."""

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_terminal_startup_review as review

from tests.unit.test_macos_endpoint_security_contracts import _file, _process, _record
from tests.unit.test_macos_terminal_startup_reference import _manifest

_CANARY = "INVENTED_PRIVATE_REVIEW_CANARY"


@pytest.fixture(autouse=True)
def no_live_activity(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("The offline reviewer must never run commands or inspect installed apps")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(review.capture, "_installed_image", forbidden)


def _chain(manifest: review.capture.Manifest) -> list[dict]:
    rows: list[dict] = []
    boot = _process(11, 1, 0)
    boot["executable"]["path"] = "/sbin/launchd"
    boot["audit_token"].update(auid=2**32 - 1, euid=0, ruid=0, egid=0, rgid=0, asid=100000)
    boot["group_id"] = boot["session_id"] = 1

    def fork(parent: dict, pid: int) -> dict:
        child = deepcopy(parent)
        child["audit_token"].update(pid=pid, pidversion=pid + 10000)
        child["parent_audit_token"] = deepcopy(parent["audit_token"])
        child["ppid"] = child["original_ppid"] = parent["audit_token"]["pid"]
        row = _record(11, "fork")
        row["process"], row["event"]["fork"]["child"] = deepcopy(parent), deepcopy(child)
        rows.append(row)
        return child

    def execute(before: dict, path: str, inode: int, *, arguments: list[str] | None = None) -> dict:
        target = deepcopy(before)
        target["audit_token"]["pidversion"] += 1
        target["executable"]["path"] = path
        target["executable"]["stat"].update(st_dev=123, st_ino=inode)
        row = _record(11, "exec")
        row["process"] = deepcopy(before)
        row["event"]["exec"].update(
            target=target,
            args=arguments or [path],
            env=[f"PRIVATE={_CANARY}"],
            fds=[{"fd": fd, "fdtype": 1} for fd in range(3)],
            last_fd=2,
            dyld_exec_path=path,
        )
        rows.append(row)
        return target

    proxy = execute(fork(boot, 1200), "/usr/libexec/xpcproxy", 8000)
    before_app = deepcopy(proxy)
    before_app["audit_token"].update(euid=501, ruid=501, egid=20, rgid=20)
    app = execute(before_app, review.capture.PATHS[manifest.terminal], manifest.app.inode)
    app["audit_token"].update(auid=501, asid=100001)
    app["group_id"] = 1200
    app["responsible_audit_token"] = deepcopy(app["audit_token"])
    rows[-1]["event"]["exec"]["entitlements"] = {
        f"KEY_{_CANARY}": True,
        "invented.array": [_CANARY],
    }
    before_login = fork(app, 1300)
    before_login["group_id"] = before_login["session_id"] = 1300
    before_login["tty"] = _file("/dev/ttys000")
    login = execute(
        before_login, "/usr/bin/login", 8001, arguments=["login", "-pfl", manifest.own_username]
    )
    login["audit_token"]["euid"] = 0
    login["responsible_audit_token"] = deepcopy(app["audit_token"])
    rows[-1]["event"]["exec"]["fds"].append({"fd": 3, "fdtype": 5})
    rows[-1]["event"]["exec"]["last_fd"] = 4
    before_shell = fork(login, 1350)
    before_shell["audit_token"]["euid"] = 501
    shell = execute(before_shell, "/bin/zsh", 8002, arguments=["-zsh"])
    shell["responsible_audit_token"] = deepcopy(app["audit_token"])
    before_marker = fork(shell, 1400)
    before_marker["group_id"] = 1400
    marker = execute(
        before_marker,
        f"/private/tmp/{_CANARY}/terminal-marker",
        manifest.marker.inode,
        arguments=[f"/private/tmp/{_CANARY}/terminal-marker", "--sample"],
    )
    marker["executable"]["stat"]["st_dev"] = manifest.marker.device
    marker["responsible_audit_token"] = deepcopy(app["audit_token"])
    end = _record(11, "exit")
    end["process"], end["event"]["exit"]["stat"] = deepcopy(marker), 0
    rows.append(end)
    counts: dict[int, int] = {}
    for index, row in enumerate(rows):
        kind = row["event_type"]
        row["seq_num"], row["global_seq_num"] = counts.get(kind, 0), index + 1
        counts[kind] = row["seq_num"] + 1
    return rows


def _raws(rows: list[dict]) -> list[bytes]:
    return [json.dumps(row).encode() for row in rows]


@pytest.mark.parametrize("terminal", ["apple", "iterm2"])
def test_fixed_review_distinguishes_forks_credentials_arguments_and_descriptor_extents(
    terminal: str,
) -> None:
    manifest = _manifest(terminal)
    phases = review.analyze(_raws(_chain(manifest)), manifest)
    assert [phase.role for phase in phases] == [
        "XPCPROXY",
        "APPLE_TERMINAL" if terminal == "apple" else "ITERM2",
        "LOGIN",
        "ZSH",
        "MARKER",
    ]
    app, login, shell, marker = phases[1:]
    assert app.entitlements.top_level_types == ("ARRAY", "BOOLEAN")
    assert app.entitlements.array_element_types == ("STRING",)
    assert app.entitlements.flat_boolean_object == "FAIL" and app.entitlements.bounded == "PASS"
    assert login.target.credentials.effective_uid == "ZERO"
    assert login.target.credentials.real_uid == "LOCAL_ACCOUNT"
    assert login.fork_child_to_before_membership == "FAIL"
    assert login.fork_child is not None and shell.fork_child is not None
    assert login.fork_parent_role == app.role and shell.fork_parent_role == "LOGIN"
    assert marker.fork_parent_role == "ZSH"
    assert login.fork_parent_to_child_credentials == shell.fork_parent_to_child_membership == "PASS"
    assert shell.fork_child_to_before_credentials == "FAIL"
    assert shell.target.group == shell.target.session == "LOGIN"
    assert shell.target.responsibility == marker.target.responsibility == "TERMINAL"
    assert shell.target.responsible_token_exact == "PASS"
    assert login.arguments[1].kind == "LOGIN_FLAGS" and login.arguments[1].flags == ("P", "F", "L")
    assert login.arguments[2].kind == "LOCAL_USERNAME"
    assert login.descriptors["FD_3"] == "TYPE_5"
    assert login.last_fd_slot == "FD_4" and login.last_fd_relative_to_inventory == "HIGHER"
    assert marker.target.group == "SELF" and marker.target.session == "LOGIN"
    report = review.ReviewReport(phases=phases)
    assert _CANARY not in report.model_dump_json()
    assert manifest.own_username not in report.model_dump_json()


@pytest.mark.parametrize(
    "value,types,bounded",
    [
        (None, (), "PASS"),
        ({"private": False}, ("BOOLEAN",), "PASS"),
        ({"private": [False, 1, 1.25, None, {"nested": _CANARY}]}, ("ARRAY",), "PASS"),
        ({"private": "\0"}, ("STRING",), "FAIL"),
        ({"private": float("inf")}, ("REAL",), "FAIL"),
    ],
)
def test_entitlement_layout_exports_types_only(
    value: object, types: tuple[str, ...], bounded: str
) -> None:
    report = review.entitlement_layout(value)
    assert report.top_level_types == types and report.bounded == bounded
    assert _CANARY not in report.model_dump_json() and "private" not in report.model_dump_json()


def test_entitlement_depth_and_argument_bounds_are_explicit() -> None:
    value: dict = {"leaf": _CANARY}
    for _ in range(10):
        value = {"nested": value}
    assert review.entitlement_layout(value).bounded == "FAIL"
    assert review._argument(_CANARY, "/bin/zsh", _manifest()).kind == "OTHER"


def _bundle(root: Path) -> tuple[review.capture.Manifest, Path]:
    root.mkdir(mode=0o700)
    for name, source in review._source_paths().items():
        shutil.copyfile(source, root / name)
        (root / name).chmod(0o600)
    for name in ("terminal-marker", "collector-guard"):
        (root / name).write_bytes(b"invented controlled executable")
        (root / name).chmod(0o700)
    manifest = _manifest().model_copy(
        update={
            "marker": review.capture._image(root / "terminal-marker"),
            "guard_sha256": review.reference._digest(root / "collector-guard"),
            "codec_sha256": review.reference._codec_digest(),
            "code_sha256": {
                name: review.reference._digest(root / name) for name in review.capture.CODE
            },
        }
    )
    rows = _chain(manifest)
    run = root / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    summary = review.capture.Report(
        terminal="apple",
        stage="COMPLETE",
        step="COMPLETE",
        provenance="PASS",
        target_platform="PASS",
        collector_ready="PASS",
        collector_cleanup="PASS",
        bounded_collection="PASS",
        sequence_continuity="PASS",
        app_exec_retained="PASS",
        app_link="ANCESTRY",
        wire_profile="V11",
        marker_exit_zero="PASS",
        phases=review.capture.analyze(_raws(rows), manifest),
    )
    for path, raw in (
        (root / "SETUP.json", manifest.model_dump_json().encode()),
        (root / "ACTIVE-RUN", (run.name + "\n").encode()),
        (run / "provenance.json", manifest.model_dump_json().encode()),
        (run / "SHAREABLE-REPORT.json", summary.model_dump_json().encode()),
        (run / "launch-chain-events.jsonl", b"\n".join(_raws(rows)) + b"\n"),
    ):
        review.reference._write(path, raw)
    return manifest, run


def test_offline_review_verifies_controlled_bundle_without_writing_or_installed_app_reads(
    tmp_path: Path,
) -> None:
    root = tmp_path / "invented-capture"
    _, _run = _bundle(root)
    before = {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }
    report = review.review_existing(root)
    assert report.error == "NONE" and report.step == "COMPLETE"
    assert (
        report.provenance == report.original_collection_controls == report.retained_chain == "PASS"
    )
    assert len(report.phases) == 5
    assert before == {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }
    assert _CANARY not in report.model_dump_json()


@pytest.mark.parametrize(
    "mutation",
    ["provenance", "code", "guard", "codec", "control", "extra_row", "exit", "public_records"],
)
def test_offline_review_rejects_broken_provenance_scope_and_permissions(
    tmp_path: Path, mutation: str
) -> None:
    root = tmp_path / "invented-capture"
    manifest, run = _bundle(root)
    if mutation == "provenance":
        (run / "provenance.json").write_text(
            manifest.model_copy(update={"own_home": f"/Users/{_CANARY}"}).model_dump_json()
        )
    elif mutation == "code":
        (root / review.capture.CODE[0]).write_text(_CANARY)
    elif mutation == "guard":
        (root / "collector-guard").write_text(_CANARY)
    elif mutation == "codec":
        changed = manifest.model_copy(update={"codec_sha256": "f" * 64})
        (root / "SETUP.json").write_text(changed.model_dump_json())
        (run / "provenance.json").write_text(changed.model_dump_json())
    elif mutation == "control":
        path = run / "SHAREABLE-REPORT.json"
        summary = review.capture.Report.model_validate_json(path.read_bytes())
        path.write_text(summary.model_copy(update={"collector_cleanup": "FAIL"}).model_dump_json())
    elif mutation == "public_records":
        (run / "launch-chain-events.jsonl").chmod(0o644)
    else:
        path = run / "launch-chain-events.jsonl"
        rows = _chain(manifest)
        if mutation == "extra_row":
            rows.insert(0, _record(11, "exec"))
        else:
            rows[-1]["event"]["exit"]["stat"] = 256
        path.write_bytes(b"\n".join(_raws(rows)) + b"\n")
    report = review.review_existing(root)
    assert report.error != "NONE" and not report.phases
    assert _CANARY not in report.model_dump_json()


def test_prepare_only_copies_code_and_offline_instructions(tmp_path: Path) -> None:
    root = review.prepare(tmp_path / "reviewer")
    assert (root / "private_terminal_review.py").is_file()
    assert (root / "OFFLINE-REVIEW.md").is_file()
    assert not (root / "SETUP.json").exists()


def test_output_schema_cannot_export_arbitrary_names_or_values() -> None:
    with pytest.raises(ValidationError):
        review.ReviewReport.model_validate({"step": _CANARY})
    with pytest.raises(ValidationError):
        review.Argument(kind=_CANARY)

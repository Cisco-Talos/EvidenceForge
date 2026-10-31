# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented offline data only. Never read a real kit or start commands/live queries."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_ssh_startup_review as kit

from tests.unit.test_macos_ssh_startup_reference import _CANARY, _chain, _manifest


@pytest.fixture(autouse=True)
def no_live_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline review must never start a command or inspect installed vendor files")

    monkeypatch.setattr(kit.capture.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.capture.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.capture.os, "execve", forbidden)
    monkeypatch.setattr(kit.capture.support, "_installed_image", forbidden)


def _saved(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "original"
    root.mkdir(mode=0o700)
    expected = {}
    for name in kit.capture.CODE:
        raw = f"invented trusted code {name}".encode()
        kit.reference._write(root / name, raw)
        expected[name] = hashlib.sha256(raw).hexdigest()
    for name in ("collector-guard", "ssh-marker"):
        kit.reference._write(root / name, f"invented {name}".encode())
    original = _manifest().model_dump()
    original.update(
        code_sha256=expected,
        guard_sha256=kit.reference._digest(root / "collector-guard"),
        codec_sha256=kit.reference._codec_digest(),
    )
    original["marker"]["sha256"] = kit.reference._digest(root / "ssh-marker")
    manifest = kit.capture.Manifest.model_validate(original)
    kit.reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    run = root / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    kit.reference._write(root / "ACTIVE-RUN", (run.name + "\n").encode())
    kit.reference._write(run / "provenance.json", manifest.model_dump_json().encode())
    report = kit.capture.Report(
        stage="COMPLETE",
        provenance="PASS",
        collector_ready="PASS",
        collector_cleanup="PASS",
        bounded_collection="PASS",
        sequence_continuity="PASS",
        client_control="PASS",
        receiver_lineage="PASS",
        marker_exit_zero="PASS",
        wire_profile="V11",
    )
    kit.reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json().encode())
    kit.reference._write(
        run / "ssh-chain-events.jsonl",
        b"\n".join(json.dumps(row).encode() for row in _chain()) + b"\n",
    )
    kit.reference._write(
        root / "CLIENT-CONTROL.json", json.dumps({"pid": 8800, "nonce": manifest.nonce}).encode()
    )
    return root, expected


def test_offline_review_is_read_only_exports_core_aliases_and_keeps_fork_only_children(
    tmp_path: Path,
) -> None:
    root, expected = _saved(tmp_path)
    before = {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    report = kit.review_existing(root, expected)
    after = {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    assert before == after
    assert report.error == "NONE" and report.core_lineage == "PASS"
    assert {event.after.role for event in report.events if event.kind == "EXEC"} == {
        "WRAPPER",
        "SSHD",
        "SESSION",
        "AUTH",
        "ZSH",
        "MARKER",
    }
    assert "SSH_CLIENT" not in {event.before.role for event in report.events}
    assert any(event.fork_only_closed == "PASS" for event in report.events)
    text = report.model_dump_json()
    for private in (_CANARY, "8800", "1400", "pidversion", "PRIVATE=", "e" * 32):
        assert private not in text
    assert report.commands == report.collectors == "NOT_STARTED"
    assert report.live_queries == "NOT_PERFORMED" and report.writes == "NONE"


@pytest.mark.parametrize(
    "damage",
    [
        "code",
        "expected",
        "guard",
        "marker",
        "provenance",
        "controls",
        "pid",
        "nonce",
        "bad_shape",
        "marker_link",
    ],
)
def test_changed_or_unproved_private_artifacts_are_rejected_without_live_queries(
    tmp_path: Path,
    damage: str,
) -> None:
    root, expected = _saved(tmp_path)
    run = kit.reference._active(root)
    if damage == "code":
        (root / kit.capture.CODE[0]).write_bytes(b"changed code")
    elif damage == "expected":
        expected[kit.capture.CODE[0]] = "f" * 64
    elif damage in {"guard", "marker"}:
        (root / ("collector-guard" if damage == "guard" else "ssh-marker")).write_bytes(
            b"changed binary"
        )
    elif damage == "provenance":
        raw = json.loads((run / "provenance.json").read_bytes())
        raw["nonce"] = "f" * 32
        (run / "provenance.json").write_text(json.dumps(raw))
    elif damage == "controls":
        raw = json.loads((run / "SHAREABLE-REPORT.json").read_bytes())
        raw["collector_cleanup"] = "FAIL"
        (run / "SHAREABLE-REPORT.json").write_text(json.dumps(raw))
    elif damage in {"pid", "nonce"}:
        raw = json.loads((root / "CLIENT-CONTROL.json").read_bytes())
        raw[damage] = True if damage == "pid" else "f" * 32
        (root / "CLIENT-CONTROL.json").write_text(json.dumps(raw))
    else:
        rows = _chain()
        if damage == "bad_shape":
            rows[0]["version"] = 999
        else:
            rows[-5]["process"]["audit_token"]["pidversion"] += 10
        (run / "ssh-chain-events.jsonl").write_bytes(
            b"\n".join(json.dumps(row).encode() for row in rows)
        )
    with pytest.raises((ValueError, ValidationError)):
        kit.review_existing(root, expected)


@pytest.mark.parametrize(
    "arguments,expected",
    [
        (["xpcproxy", "com.openssh.sshd"], "XPCPROXY_SSH_LABEL"),
        (["xpcproxy", "com.openssh.sshd.private"], "XPCPROXY_SSH_INSTANCE"),
        (["sshd-keygen-wrapper"], "WRAPPER_BASENAME_ONLY"),
        (["/usr/libexec/sshd-keygen-wrapper", "-i"], "WRAPPER_PATH_INETD"),
        ([_CANARY], "OTHER"),
    ],
)
def test_public_argument_candidates_export_only_fixed_layout_labels(
    arguments: list, expected: str
) -> None:
    role = "XPCPROXY" if arguments[0] == "xpcproxy" else "WRAPPER"
    result = kit._argument_layout(
        role, {"args": arguments}, _manifest(), Path("/private/tmp/invented")
    )
    assert result == expected and _CANARY not in result


def test_personal_shell_startup_descendants_are_not_in_the_core_graph() -> None:
    rows = _chain()
    noise = deepcopy(rows[-5])
    noise["process"] = deepcopy(rows[-5]["process"])
    noise["process"]["audit_token"]["pid"] = 9900
    noise["event"]["exec"]["target"]["audit_token"]["pid"] = 9900
    noise["event"]["exec"]["target"]["executable"]["path"] = _CANARY
    noise["event"]["exec"]["target"]["executable"]["stat"]["st_ino"] = 991234
    noise["event"]["exec"]["args"] = [_CANARY]
    rows.insert(-5, noise)
    report = kit.classify(rows, _manifest(), Path("/private/tmp/invented"))
    assert all(event.before.role != "OTHER" for event in report.events)
    assert _CANARY not in report.model_dump_json()


def test_preparation_copies_code_only_and_does_not_open_existing_kits(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "review")
    assert (root / "private_ssh_review.py").is_file()
    expected = json.loads((root / "OFFLINE-EXPECTED.json").read_bytes())
    assert set(expected) == set(kit.capture.CODE)
    assert not (root / "SETUP.json").exists() and not (root / "ACTIVE-RUN").exists()


def test_parser_error_cannot_echo_private_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(kit.sys, "argv", ["private_ssh_review.py", _CANARY])
    kit.main()
    output = capsys.readouterr()
    assert _CANARY not in output.out + output.err
    assert json.loads(output.out)["error"] == "INPUT"

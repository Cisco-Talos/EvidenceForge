# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented offline launchd data only, no real kits, native commands or live queries."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_launchd_review as kit

from tests.support.platforms import requires_posix_reference
from tests.unit.test_macos_launchd_reference import _CANARY, _chain, _manifest


@pytest.fixture(autouse=True)
def no_live_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline launchd review cannot start commands or inspect installed images")

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
    for name in ("collector-guard", "job-guard", "ready-marker"):
        kit.reference._write(root / name, f"invented {name}".encode())
    fields = _manifest().model_dump()
    fields.update(
        code_sha256=expected,
        guard_sha256=kit.reference._digest(root / "collector-guard"),
        job_guard_sha256=kit.reference._digest(root / "job-guard"),
        codec_sha256=kit.reference._codec_digest(),
    )
    fields["ready_marker"]["sha256"] = kit.reference._digest(root / "ready-marker")
    manifest = kit.capture.Manifest.model_validate(fields)
    kit.reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    run = root / ("run-" + "a" * 32)
    run.mkdir(mode=0o700)
    kit.reference._write(root / "ACTIVE-RUN", (run.name + "\n").encode())
    kit.reference._write(run / "provenance.json", manifest.model_dump_json().encode())
    rows = _chain()
    # Mimic launchd's extra public root values without using a captured environment.
    rows[-2]["event"]["exec"]["env"] += [
        "HOME=/var/root",
        "USER=root",
        "LOGNAME=root",
        "SHELL=/bin/sh",
        "TMPDIR=/var/folders/zz/invented/T/",
    ]
    raws = [json.dumps(row).encode() for row in rows]
    phases, graph = kit.capture.analyze(raws, manifest, root)
    report = kit.capture.Report(
        stage="COMPLETE",
        step="COMPLETE",
        wire_profile="V11",
        phases=phases,
        graph=graph,
        **{
            key: "PASS"
            for key in (
                "provenance",
                "target_platform",
                "collector_ready",
                "collector_cleanup",
                "job_guard",
                "job_registered",
                "job_activated",
                "job_removed",
                "temporary_files_removed",
                "bounded_collection",
                "sequence_continuity",
                "target_control",
                "root_lineage",
                "target_exit_zero",
            )
        },
    )
    kit.reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json().encode())
    kit.reference._write(run / "launchd-chain-events.jsonl", b"\n".join(raws) + b"\n")
    return root, expected


@requires_posix_reference
def test_offline_review_is_read_only_and_exports_only_fixed_public_key_classes(
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
    assert (
        report.provenance
        == report.original_collection_controls
        == report.exact_retained_graph
        == "PASS"
    )
    entries = {entry.key: entry.value for entry in report.target.entries}
    assert entries["CONTROL_TOKEN"] == "CONTROLLED"
    assert entries["XPC_FLAGS"] == "HEX_ZERO"
    assert entries["HOME"] == "ROOT_HOME" and entries["SHELL"] == "SYSTEM_SH"
    assert entries["TMPDIR"] == "ROOT_TEMP_DIRECTORY"
    assert report.target.only_known_keys == "FAIL"  # Invented PRIVATE canary is omitted.
    assert report.environment_vectors_identical == "FAIL"
    assert report.collectors == report.commands == "NOT_STARTED"
    assert report.live_queries == "NOT_PERFORMED" and report.writes == "NONE"
    text = report.model_dump_json()
    for secret in (_CANARY, "PRIVATE", "e" * 32, "/var/root", "/var/folders", "invented", "1200"):
        assert secret not in text
    assert kit.Report.model_validate_json(text) == report


@requires_posix_reference
@pytest.mark.parametrize(
    "damage",
    [
        "code",
        "expected",
        "collector_guard",
        "job_guard",
        "ready_marker",
        "provenance",
        "controls",
        "nonce",
        "extra_row",
        "shape",
        "graph",
        "saved_phase",
        "symlink",
    ],
)
def test_changed_or_unproved_private_inputs_reject_before_output(
    tmp_path: Path, damage: str
) -> None:
    root, expected = _saved(tmp_path)
    run = kit.reference._active(root)
    if damage == "code":
        (root / kit.capture.CODE[0]).write_bytes(b"changed")
    elif damage == "expected":
        expected[kit.capture.CODE[0]] = "f" * 64
    elif damage in {"collector_guard", "job_guard", "ready_marker"}:
        (root / damage.replace("_", "-")).write_bytes(b"changed")
    elif damage == "provenance":
        path = run / "provenance.json"
        raw = json.loads(path.read_bytes())
        raw["nonce"] = "f" * 32
        path.write_text(json.dumps(raw))
    elif damage in {"controls", "saved_phase"}:
        path = run / "SHAREABLE-REPORT.json"
        raw = json.loads(path.read_bytes())
        if damage == "controls":
            raw["job_removed"] = "FAIL"
        else:
            raw["phases"][0]["same_lifetime"] = "FAIL"
        path.write_text(json.dumps(raw))
    elif damage == "symlink":
        path = run / "launchd-chain-events.jsonl"
        path.rename(run / "other")
        path.symlink_to(run / "other")
    else:
        path = run / "launchd-chain-events.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        if damage == "nonce":
            rows[-2]["event"]["exec"]["args"][-1] = "f" * 32
        elif damage == "extra_row":
            rows.append(rows[0])
        elif damage == "shape":
            rows[0]["version"] = 999
        elif damage == "graph":
            rows[0]["event"]["fork"]["child"]["parent_audit_token"]["pidversion"] += 1
        path.write_bytes(b"\n".join(json.dumps(row).encode() for row in rows))
    with pytest.raises((ValueError, OSError, ValidationError)):
        kit.review_existing(root, expected)


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("XPC_FLAGS", "1", "DECIMAL_ONE"),
        ("XPC_FLAGS", "0x1", "HEX_ONE"),
        ("XPC_FLAGS", "0", "DECIMAL_ZERO"),
        ("XPC_FLAGS", "0x0", "HEX_ZERO"),
        ("XPC_FLAGS", _CANARY, "OTHER"),
        ("HOME", "/var/root", "ROOT_HOME"),
        ("SHELL", "/bin/zsh", "SYSTEM_ZSH"),
        ("SHELL", _CANARY, "OTHER"),
        ("COMMAND_MODE", "unix2003", "UNIX2003"),
        ("__CF_USER_TEXT_ENCODING", "0x0:0:0", "ROOT_ENCODING"),
        ("OSLogRateLimit", "64", "DECIMAL_SIXTY_FOUR"),
        ("OSLogRateLimit", _CANARY, "OTHER"),
    ],
)
def test_public_candidates_use_fixed_comparisons_and_do_not_echo_values(
    key: str, value: str, expected: str
) -> None:
    report = kit.classify({"env": [f"{key}={value}"]}, _manifest())
    assert report.entries[0].value == expected
    assert _CANARY not in report.model_dump_json()


def test_unknown_keys_and_duplicates_never_echo_observed_strings() -> None:
    report = kit.classify({"env": [f"{_CANARY}=private", "USER=root", "USER=root"]}, _manifest())
    assert report.only_known_keys == "FAIL" and report.duplicate_keys == "PRESENT"
    assert len(report.entries) == 1 and _CANARY not in report.model_dump_json()


@pytest.mark.parametrize("field", ["purpose", "error", "mode", "writes", "commands"])
def test_closed_report_rejects_native_text(field: str) -> None:
    with pytest.raises(ValidationError):
        kit.Report.model_validate({field: _CANARY})


@requires_posix_reference
def test_prepare_does_not_open_existing_private_kit_and_binds_source_digests(
    tmp_path: Path,
) -> None:
    root = kit.prepare(tmp_path / "new-review")
    assert (root / "private_launchd_review.py").stat().st_mode & 0o777 == 0o600
    expected = json.loads((root / "OFFLINE-EXPECTED.json").read_bytes())
    assert expected == {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in kit.capture.CODE
    }
    assert set(path.name for path in root.iterdir()) == set(kit.capture.CODE) | {
        "PRIVATE-RUN.md",
        "private_launchd_review.py",
        "OFFLINE-EXPECTED.json",
    }


def test_source_cli_refuses_native_reads_and_never_echoes_parser_input(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for args in (["review-existing", "--source-kit", _CANARY], [_CANARY]):
        monkeypatch.setattr(kit.sys, "argv", ["macos_launchd_review.py", *args])
        kit.main()
        output = capsys.readouterr()
        assert _CANARY not in output.out + output.err
        assert kit.Report.model_validate_json(output.out).error == "INPUT"

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Offline diagnostic/privacy contracts using invented inputs only."""

import base64
import getpass
import hashlib
import json
import os
import socket
import subprocess
import warnings
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts import macos_reference_review as kit

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from tests.unit.test_macos_reference_capture import _experiment

_SECRET = "INVENTED_PRIVATE_CANARY_never_export"
_DIGEST = b"\xab" * 20 + b"\xcd" * 12


def _views(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for row in rows:
        result.append(row["process"])
        if row["event_type"] == 11:
            result.append(row["event"]["fork"]["child"])
        elif row["event_type"] == 9:
            result.append(row["event"]["exec"]["target"])
    return result


def _rows(value: object = _DIGEST.hex()) -> list[dict[str, object]]:
    rows, _controls = _experiment()
    for row in rows:
        row["version"] = 11
    for process in _views(rows):
        process["cdhash"] = _DIGEST[:20].hex()
        process["cdhash_full"] = deepcopy(value)
    return rows


def _summary() -> dict[str, object]:
    return {
        "kit_version": 3,
        "reference_review": "REQUIRED",
        "gate_status": "NOT_EVALUATED",
        "error": "WIRE_PROFILE",
        "target_platform": "PASS",
        "stream_delivery": "PASS",
        "probe_identity_seen": "PASS",
        "probe_image_seen": "PASS",
        "collector_ready": "PASS",
        "wire_profile": "V11_UNQUALIFIED",
        "message_shapes": "INCONCLUSIVE",
        "probe_controls": "PASS",
        "bounded_delivery": "PASS",
        "candidate_v10_shapes": "INCONCLUSIVE",
        "fork_exec_exit_linkage": "PASS",
        "controlled_exec_inputs": "PASS",
        "controlled_descriptors": "PASS",
        "exit_status_agreement": "PASS",
        "failed_exec_control": "PASS",
        "sequence_continuity": "PASS",
    }


def _run(tmp_path: Path, rows: list[dict[str, object]] | None = None) -> Path:
    run = tmp_path / "invented-private-run"
    run.mkdir(mode=0o700)
    (run / "SHAREABLE-REPORT.json").write_text(json.dumps(_summary()))
    native = rows if rows is not None else _rows()
    (run / "probe-events.jsonl").write_bytes(
        b"".join(json.dumps(row).encode() + b"\n" for row in native)
    )
    for name in ("SHAREABLE-REPORT.json", "probe-events.jsonl"):
        (run / name).chmod(0o600)
    return run


def test_known_v11_shape_diagnostics_cannot_qualify_wire_or_modify_rows() -> None:
    rows = _rows()
    original = deepcopy(rows)
    report = kit.analyze(rows)
    assert report.review_complete == "PASS"
    assert report.capture_summary == "INCONCLUSIVE"  # No file/report was read.
    assert report.wire_profile == "V11_UNQUALIFIED"
    for key in (
        "retained_families",
        "envelope_fields",
        "envelope_values",
        "process_fields",
        "process_values",
        "fork_payload",
        "exec_fields",
        "exec_values",
        "exit_payload",
    ):
        assert getattr(report, key) == "PASS"
    assert report.full_hash.presence == "PRESENT_ALL"
    assert report.full_hash.representation == "STRING"
    assert report.full_hash.hex_decoding == "PASS"
    assert report.full_hash.hex_extent == "BYTES_32"
    assert report.full_hash.hex_legacy_prefix == "PASS"
    # Hex text can also be valid base64, with a different interpretation.
    assert report.full_hash.base64_decoding == "PASS"
    assert report.full_hash.base64_extent == "BYTES_48"
    assert report.full_hash.base64_legacy_prefix == "FAIL"
    assert report.full_hash.hex_declared_size == "INCONCLUSIVE"
    assert report.full_hash.array_decoding == "FAIL"
    assert report.audit_token_form == "ARRAY"
    assert report.process_start_form == "TIMESTAMP_STRING"
    assert report.message_shapes == "INCONCLUSIVE"
    assert report.reference_review == "REQUIRED"
    assert report.gate_status == "NOT_EVALUATED"
    assert rows == original
    with pytest.raises(ValidationError):
        decode_endpoint_security_record(json.dumps(rows[1]))


@pytest.mark.parametrize("encoding", ["hex", "base64", "array"])
@pytest.mark.parametrize("sized", [False, True])
def test_hash_candidate_representations_and_explicit_size(encoding: str, sized: bool) -> None:
    value = {
        "hex": _DIGEST.hex(),
        "base64": base64.b64encode(_DIGEST).decode(),
        "array": list(_DIGEST),
    }[encoding]
    if sized:
        value = {"size": len(_DIGEST), "data": value}
    report = kit.analyze(_rows(value)).full_hash
    assert getattr(report, f"{encoding}_decoding") == "PASS"
    assert getattr(report, f"{encoding}_extent") == "BYTES_32"
    assert getattr(report, f"{encoding}_legacy_prefix") == "PASS"
    assert getattr(report, f"{encoding}_declared_size") == ("PASS" if sized else "INCONCLUSIVE")
    assert report.representation == (
        "SIZE_DATA_OBJECT" if sized else "BYTE_ARRAY" if encoding == "array" else "STRING"
    )
    assert report.object_keys == ("PASS" if sized else "INCONCLUSIVE")
    assert report.declared_size_type == ("PASS" if sized else "INCONCLUSIVE")


@pytest.mark.parametrize("case", ["absent", "null", "empty", "mixed", "other_extent", "short"])
def test_absence_null_empty_and_mixed_are_distinct(case: str) -> None:
    value = {"null": None, "empty": "", "other_extent": "ab" * 21, "short": "ab" * 2}.get(
        case, _DIGEST.hex()
    )
    rows = _rows(value)
    if case == "absent":
        for process in _views(rows):
            del process["cdhash_full"]
    elif case == "mixed":
        rows[0]["process"]["cdhash_full"] = None
        del rows[-1]["process"]["cdhash_full"]
    report = kit.analyze(rows).full_hash
    if case == "absent":
        assert report.presence == "ABSENT_ALL"
        assert report.representation == "ABSENT"
        assert report.hex_decoding == "INCONCLUSIVE"
    elif case == "null":
        assert report.presence == "PRESENT_ALL"
        assert report.representation == "NULL"
        assert report.hex_decoding == "INCONCLUSIVE"
    elif case == "mixed":
        assert report.presence == report.representation == "MIXED"
        assert report.hex_decoding == "PASS"  # Applicable nonnull values only.
    else:
        assert report.hex_extent == ("EMPTY" if case == "empty" else "OTHER")
        assert report.hex_legacy_prefix == ("PASS" if case == "other_extent" else "INCONCLUSIVE")


@pytest.mark.parametrize("size", [31, -1, True, "32", None])
def test_sized_hash_does_not_coerce_size_or_assume_encoding(size: object) -> None:
    report = kit.analyze(_rows({"size": size, "data": _DIGEST.hex()})).full_hash
    assert report.representation == "SIZE_DATA_OBJECT"
    assert report.hex_decoding == "PASS"
    assert report.declared_size_type == ("PASS" if size == 31 else "FAIL")
    assert report.hex_declared_size == ("FAIL" if size == 31 else "INCONCLUSIVE")


@pytest.mark.parametrize(
    "value",
    [
        _SECRET,
        [True],
        [256],
        [-1],
        {"size": 32, "data": _SECRET, _SECRET: _SECRET},
        {"size": 32},
        123,
        True,
    ],
)
def test_unknown_hash_values_and_keys_are_never_exported(value: object) -> None:
    report = kit.analyze(_rows(value))
    assert _SECRET not in report.model_dump_json()
    assert report.message_shapes == "INCONCLUSIVE"
    assert report.full_hash.hex_decoding == "FAIL"
    assert report.full_hash.base64_decoding == "FAIL"
    assert report.full_hash.array_decoding == "FAIL"


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ("envelope_extra", "envelope_fields"),
        ("envelope_missing", "envelope_fields"),
        ("process_extra", "process_fields"),
        ("nullable_missing", "process_fields"),
        ("category_missing", "process_fields"),
        ("category_null", "process_values"),
        ("nested_stat_extra", "process_values"),
        ("exec_extra", "exec_fields"),
        ("exec_script_missing", "exec_fields"),
        ("exec_fd_extra", "exec_values"),
        ("exit_extra", "exit_payload"),
        ("fork_extra", "fork_payload"),
        ("bad_calendar", "envelope_values"),
    ],
)
def test_unknown_missing_and_invalid_fields_remain_diagnostic_failures(
    change: str, field: str
) -> None:
    rows = _rows()
    if change == "envelope_extra":
        rows[0][_SECRET] = _SECRET
    elif change == "envelope_missing":
        del rows[0]["thread"]
    elif change == "process_extra":
        rows[0]["process"][_SECRET] = _SECRET
    elif change == "nullable_missing":
        del rows[0]["process"]["signing_id"]
    elif change == "category_missing":
        del rows[0]["process"]["cs_validation_category"]
    elif change == "category_null":
        rows[0]["process"]["cs_validation_category"] = None
    elif change == "nested_stat_extra":
        rows[0]["process"]["executable"]["stat"][_SECRET] = _SECRET
    elif change == "exec_extra":
        rows[1]["event"]["exec"][_SECRET] = _SECRET
    elif change == "exec_script_missing":
        del rows[1]["event"]["exec"]["script"]
    elif change == "exec_fd_extra":
        rows[1]["event"]["exec"]["fds"][0][_SECRET] = _SECRET
    elif change == "exit_extra":
        rows[2]["event"]["exit"][_SECRET] = _SECRET
    elif change == "fork_extra":
        rows[0]["event"]["fork"][_SECRET] = _SECRET
    else:
        rows[0]["time"] = "2026-99-99T12:00:00.000000000Z"
    report = kit.analyze(rows)
    assert getattr(report, field) == "FAIL"
    assert _SECRET not in report.model_dump_json()
    assert report.message_shapes == "INCONCLUSIVE"


@pytest.mark.parametrize(
    ("version", "schema", "profile"),
    [
        (10, 1, "V10_CANDIDATE"),
        (12, 1, "OTHER_UNQUALIFIED"),
        (11, 2, "SCHEMA_UNQUALIFIED"),
        (True, 1, "INVALID"),
        (11, True, "INVALID"),
        (None, 1, "INVALID"),
        (0, 1, "INVALID"),
    ],
)
def test_headers_are_classified_without_retagging(
    version: object, schema: object, profile: str
) -> None:
    rows = _rows()
    for row in rows:
        row["version"], row["schema_version"] = version, schema
    original = deepcopy(rows)
    report = kit.analyze(rows)
    assert report.wire_profile == profile
    assert report.envelope_values == "FAIL"
    assert report.message_shapes == "INCONCLUSIVE"
    assert rows == original


@pytest.mark.parametrize("form", ["named", "val", "timeval", "unknown", "missing", "null"])
def test_identity_shapes_are_classified_without_normalization(form: str) -> None:
    rows = _rows()
    names = ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")
    for process in _views(rows):
        if form in {"named", "val", "unknown", "missing", "null"}:
            for key in ("audit_token", "parent_audit_token", "responsible_audit_token"):
                if form == "missing":
                    process.pop(key, None)
                elif form == "named":
                    if isinstance(process[key], list):
                        process[key] = dict(zip(names, process[key], strict=True))
                elif form == "val":
                    if isinstance(process[key], list):
                        process[key] = {"val": process[key]}
                else:
                    process[key] = None if form == "null" else {_SECRET: _SECRET}
        else:
            process["start_time"] = {"tv_sec": 1234567890, "tv_usec": 123456}
    original = deepcopy(rows)
    report = kit.analyze(rows)
    expected = {
        "named": "NAMED",
        "val": "VAL_WRAPPER",
        "unknown": "UNRECOGNIZED",
        "missing": "ABSENT",
        "null": "NULL",
        "timeval": "ARRAY",
    }
    assert report.audit_token_form == expected[form]
    assert report.process_start_form == ("TIMEVAL" if form == "timeval" else "TIMESTAMP_STRING")
    assert report.process_values == ("PASS" if form == "named" else "FAIL")
    assert rows == original
    assert _SECRET not in report.model_dump_json()


def test_review_reads_only_two_files_without_writes_commands_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _run(tmp_path)
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in run.iterdir()}
    original_open = os.open
    opened: list[str] = []

    def read_only_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
        assert flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) == 0
        if kwargs.get("dir_fd") is not None:
            assert path in {"SHAREABLE-REPORT.json", "probe-events.jsonl"}
            opened.append(path)
        else:
            assert Path(path) == run
        return original_open(path, flags, *args, **kwargs)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Offline review must not execute commands, connect, or modify files")

    with monkeypatch.context() as guard:
        guard.setattr(kit.os, "open", read_only_open)
        guard.setattr(subprocess, "Popen", forbidden)
        guard.setattr(subprocess, "run", forbidden)
        guard.setattr(socket.socket, "connect", forbidden)
        guard.setattr(Path, "write_bytes", forbidden)
        guard.setattr(Path, "write_text", forbidden)
        guard.setattr(Path, "chmod", forbidden)
        report = kit.review(run)
    assert opened == ["SHAREABLE-REPORT.json", "probe-events.jsonl"]
    assert report.capture_summary == report.review_complete == "PASS"
    assert report.error == "NONE"
    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in run.iterdir()}
    assert before == after


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("directory_mode", "PERMISSIONS"),
        ("file_mode", "PERMISSIONS"),
        ("hardlink", "LOCATION"),
        ("git", "LOCATION"),
        ("git_symlink", "LOCATION"),
        ("bad_summary", "SOURCE"),
        ("empty", "DATA"),
        ("partial", "DATA"),
        ("malformed", "DATA"),
        ("duplicate_keys", "DATA"),
        ("nonfinite", "DATA"),
        ("array_record", "DATA"),
        ("too_many", "LIMIT"),
        ("oversized_line", "LIMIT"),
        ("oversized_summary", "LIMIT"),
    ],
)
def test_private_input_guards_are_bounded_and_fixed(tmp_path: Path, change: str, code: str) -> None:
    run = _run(tmp_path)
    native = run / "probe-events.jsonl"
    if change == "directory_mode":
        run.chmod(0o755)
    elif change == "file_mode":
        native.chmod(0o644)
    elif change == "hardlink":
        os.link(native, tmp_path / "invented-link")
    elif change == "git":
        (tmp_path / ".git").mkdir()
    elif change == "git_symlink":
        (tmp_path / ".git").symlink_to(tmp_path / "invented-missing")
    elif change == "bad_summary":
        (run / "SHAREABLE-REPORT.json").write_text(json.dumps({"private": _SECRET}))
    elif change == "oversized_summary":
        (run / "SHAREABLE-REPORT.json").write_bytes(b" " * (kit.MAX_SUMMARY_BYTES + 1))
    elif change == "empty":
        native.write_bytes(b"")
    elif change == "partial":
        native.write_bytes(native.read_bytes().rstrip(b"\n"))
    elif change == "malformed":
        native.write_bytes(_SECRET.encode() + b"\n")
    elif change == "duplicate_keys":
        native.write_bytes(b'{"private":1,"private":2}\n')
    elif change == "nonfinite":
        native.write_bytes(b'{"private":NaN}\n')
    elif change == "array_record":
        native.write_bytes(b'[{"private":"' + _SECRET.encode() + b'"}]\n')
    elif change == "too_many":
        native.write_bytes(native.read_bytes().splitlines(keepends=True)[0] * (kit.MAX_RECORDS + 1))
    else:
        native.write_bytes(b" " * (kit.MAX_LINE_BYTES + 1))
    with pytest.raises(kit.PrivateReviewError) as raised:
        kit.review(run)
    assert raised.value.code == code


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory"])
def test_nonregular_or_linked_inputs_are_never_read(tmp_path: Path, kind: str) -> None:
    run = _run(tmp_path)
    native = run / "probe-events.jsonl"
    native.unlink()
    if kind == "symlink":
        native.symlink_to(tmp_path / "invented-absent-secret")
    elif kind == "fifo":
        os.mkfifo(native, 0o600)
    else:
        native.mkdir(mode=0o700)
    with pytest.raises((kit.PrivateReviewError, OSError)):
        kit.review(run)


def test_selected_report_and_headers_must_agree(tmp_path: Path) -> None:
    rows = _rows()
    rows[0]["version"] = 10
    report = kit.review(_run(tmp_path, rows))
    assert report.wire_profile == "MIXED"
    assert report.error == "SOURCE"
    assert report.message_shapes == "INCONCLUSIVE"


def test_prepare_stages_only_offline_code_and_instructions(tmp_path: Path) -> None:
    target = kit.prepare(tmp_path / "fresh-review-kit")
    assert {path.name for path in target.iterdir()} == {"private_review.py", "OFFLINE-REVIEW.md"}
    assert target.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in target.iterdir())
    with pytest.raises(FileExistsError):
        kit.prepare(target)


def test_prepare_rejects_git_before_copying(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    with pytest.raises(kit.PrivateReviewError, match="^LOCATION$"):
        kit.prepare(tmp_path / "uncreated")
    assert not (tmp_path / "uncreated").exists()


@pytest.mark.parametrize("args", [[], ["review"], ["review", "--private-run", _SECRET]])
def test_cli_errors_never_echo_paths_or_arguments(
    args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(kit, "_human_review", lambda: pytest.fail("Unexpected private execution"))
    assert kit.main(args) == 2
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert kit.ReviewReport.model_validate_json(output.out).error == "INPUT"


@pytest.mark.parametrize("failure", ["warning", "eof", "no_tty", "git", "empty"])
def test_human_input_stays_hidden_and_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr(kit, "__file__", str(tmp_path / "private_review.py"))
    monkeypatch.setattr(kit.sys.stdin, "isatty", lambda: failure != "no_tty")
    if failure == "git":
        (tmp_path / ".git").mkdir()

    def prompt(message: str) -> str:
        assert message == "Private run directory (input hidden): "
        assert failure not in {"git", "no_tty"}
        if failure == "warning":
            warnings.warn(_SECRET, getpass.GetPassWarning, stacklevel=2)
        if failure == "eof":
            raise EOFError(_SECRET)
        return ""

    monkeypatch.setattr(kit.getpass, "getpass", prompt)
    with pytest.raises(kit.PrivateReviewError) as raised:
        kit._human_review()
    assert raised.value.code == ("LOCATION" if failure == "git" else "INPUT")


@pytest.mark.parametrize("error", [OSError, ValueError, KeyError, TypeError, RecursionError])
def test_exception_details_never_reach_output(
    error: type[Exception], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class SecretError(error):
        def __str__(self) -> str:
            pytest.fail("Exception must not be formatted")

    def fail() -> kit.ReviewReport:
        raise SecretError(_SECRET)

    monkeypatch.setattr(kit, "_human_review", fail)
    assert kit.main(["review", "--private-run"]) == 2
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert kit.ReviewReport.model_validate_json(output.out).error == "INTERNAL"


def test_report_vocabulary_cannot_export_native_fields_or_claim_qualification() -> None:
    for value in (
        {"private": _SECRET},
        {"error": _SECRET},
        {"message_shapes": "PASS"},
        {"gate_status": "PASS"},
        {"review_version": True},
        {"full_hash": {"hex_extent": _SECRET}},
    ):
        with pytest.raises(ValidationError):
            kit.ReviewReport.model_validate(value)


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


def test_human_cli_reviews_only_invented_run_and_exports_no_paths_or_digests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    run = _run(tmp_path)
    stage = tmp_path / "invented-review-kit"
    stage.mkdir(mode=0o700)
    monkeypatch.setattr(kit, "__file__", str(stage / "private_review.py"))
    monkeypatch.setattr(kit.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(kit.getpass, "getpass", lambda _prompt: str(run))
    assert kit.main(["review", "--private-run"]) == 0
    output = capsys.readouterr()
    assert not output.err
    assert str(run) not in output.out
    assert _DIGEST.hex() not in output.out
    assert _DIGEST[:20].hex() not in output.out
    report = kit.ReviewReport.model_validate_json(output.out)
    assert report.review_complete == report.capture_summary == "PASS"
    assert report.message_shapes == "INCONCLUSIVE"


@pytest.mark.parametrize(
    ("error", "code", "status"),
    [
        (FileNotFoundError, "LOCATION", 2),
        (NotADirectoryError, "LOCATION", 2),
        (PermissionError, "PERMISSIONS", 2),
        (KeyboardInterrupt, "INTERRUPTED", 130),
    ],
)
def test_cli_location_permission_and_interrupt_errors_are_fixed(
    error: type[BaseException],
    code: str,
    status: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail() -> kit.ReviewReport:
        raise error(_SECRET)

    monkeypatch.setattr(kit, "_human_review", fail)
    assert kit.main(["review", "--private-run"]) == status
    output = capsys.readouterr()
    assert not output.err
    assert _SECRET not in output.out
    assert kit.ReviewReport.model_validate_json(output.out).error == code


@pytest.mark.parametrize(
    "raw",
    [b"\xff", b'{"x":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}", b'{"x":1e999}'],
    ids=["unicode", "nesting", "overflow_float"],
)
def test_bad_unicode_and_excessive_nesting_stay_fixed_data_errors(raw: bytes) -> None:
    with pytest.raises(kit.PrivateReviewError, match="^DATA$"):
        kit._decode(raw)

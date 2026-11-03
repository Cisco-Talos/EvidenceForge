"""Offline invented captures only; every native/live operation is forbidden."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import get_args

import pytest
from scripts import macos_ssh_unified_review as kit

from tests.unit.test_macos_ssh_startup_reference import _CANARY
from tests.unit.test_macos_ssh_startup_review import _saved
from tests.unit.test_macos_ssh_unified_reference import SECRET, _ulf, _windows
from tests.unit.test_macos_ulf_launchd_reference import _row


@pytest.fixture(autouse=True)
def no_native_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Offline shape review cannot start commands or query installed code")

    monkeypatch.setattr(kit.capture.subprocess, "Popen", forbidden)
    monkeypatch.setattr(kit.capture.subprocess, "run", forbidden)
    monkeypatch.setattr(kit.capture.os, "execve", forbidden)
    monkeypatch.setattr(kit.capture.support, "_installed_image", forbidden)


def test_field_labels_cover_the_current_declared_codec_and_no_native_keys() -> None:
    public = set(get_args(kit.FieldName.__value__))
    assert {
        info.alias or name for name, info in kit.UnifiedLogRecord.model_fields.items()
    } <= public


def test_all_log_errors_are_reported_without_native_values_context_or_unknown_keys() -> None:
    rows = [
        _ulf() | {"source": {"file": SECRET, SECRET: SECRET}, "userID": -1},
        _ulf() | {"formatString": None, SECRET: {SECRET: SECRET}},
        _ulf(),
    ]
    report = kit.diagnose(rows, _windows(), SECRET)
    assert report.native_shapes == "FAIL"
    assert report.log_event_rows == 3 and report.invalid_log_rows == 2
    assert report.classified_log_rows == 1
    assert {item.field for item in report.failed_fields} == {
        "source",
        "userID",
        "formatString",
        "OTHER_FIELD",
    }
    uid = next(item for item in report.failed_fields if item.field == "userID")
    assert uid.problems == ("NUMERIC_RANGE",) and "NEGATIVE_ONE" in uid.integer_forms
    source = next(item for item in report.failed_fields if item.field == "source")
    assert source.value_types == ("OBJECT",) and set(source.object_members) == {"file", "OTHER"}
    assert report.valid_subset.messages.accepted_local_password == 1
    assert len(report.families) == 1
    assert report.families[0].family == "accepted_local_password"
    assert SECRET not in report.model_dump_json()
    assert report.gate_status == "NOT_EVALUATED"


def test_activity_records_do_not_poison_valid_log_classification() -> None:
    activity = _ulf() | {"eventType": "activityCreateEvent"}
    del activity["formatString"]
    report = kit.diagnose([activity, _ulf()], _windows(), SECRET)
    assert report.retained_rows == 2 and report.log_event_rows == report.other_event_rows == 1
    assert report.other_event_kinds == ("ACTIVITY_CREATE",)
    assert report.native_shapes == "PASS" and report.classified_log_rows == 1
    assert report.shape_scope == "LOG_EVENT_ROWS_ONLY" and report.gate_status == "NOT_EVALUATED"


def test_grouped_families_do_not_misattribute_another_messages_sender_or_format() -> None:
    accepted = _ulf()
    unrelated = _ulf() | {"eventMessage": SECRET, "senderImagePath": SECRET, "formatString": SECRET}
    report = kit.diagnose([accepted, unrelated], _windows(), SECRET)
    families = {item.family: item for item in report.families}
    assert families["accepted_local_password"].summary.senders == ("SYSTEM_ASL",)
    assert families["accepted_local_password"].summary.static_formats == ("PUBLIC_C_STRING",)
    assert families["other_controlled"].summary.senders == ("OTHER",)
    assert families["other_controlled"].summary.static_formats == ("OTHER",)
    assert SECRET not in report.model_dump_json()


@pytest.mark.parametrize("dynamic", [False, True])
def test_callsite_shapes_expose_only_public_flags_and_comparisons(dynamic: bool) -> None:
    pc = 65536
    code = pc | 0x80000000 if dynamic else 131072
    row = _ulf() | {
        "traceID": (code << 32) | (0x0002 << 16) | (1 << 8) | 4,
        "senderProgramCounter": pc,
        "formatString": "" if dynamic else "%.500s",
        "messageType": "Info",
    }
    report = kit.diagnose([row], _windows(), SECRET)
    shape = report.families[0].callsite_shape
    assert shape.log_namespace == shape.level_agreement == "PASS"
    assert shape.pc_styles == ("MAIN_IMAGE",) and shape.flags == ()
    assert shape.dynamic_format == ("PRESENT" if dynamic else "ABSENT")
    assert shape.format_forms == (("EMPTY",) if dynamic else ("SSH_SYSLOG_PRECISION",))
    assert shape.dynamic_code_matches_pc == ("PASS" if dynamic else "FAIL")
    assert shape.static_offset_range == ("FAIL" if dynamic else "PASS")
    assert shape.pc_range == shape.pc_alignment == shape.source_absent == "PASS"
    assert SECRET not in report.model_dump_json()


def test_unrecognized_trace_bits_and_text_are_suppressed() -> None:
    row = _ulf() | {
        "traceID": (123 << 32) | (0x8001 << 16) | (1 << 8) | 3,
        "formatString": SECRET,
        "senderProgramCounter": 2**40 + 1,
    }
    report = kit.diagnose([row], _windows(), SECRET)
    shape = report.families[0].callsite_shape
    assert shape.flags == ("ACTIVITY", "UNKNOWN_BITS")
    assert shape.format_forms == ("OTHER",)
    assert shape.log_namespace == shape.level_agreement == shape.pc_alignment == "FAIL"
    assert shape.pc_range == "FAIL"
    assert SECRET not in report.model_dump_json()


@pytest.mark.parametrize(
    "kind,expected", [(None, "MISSING"), (SECRET, "OTHER"), ({SECRET: SECRET}, "OTHER")]
)
def test_unimplemented_kinds_remain_unqualified_and_private(kind: object, expected: str) -> None:
    row = _ulf()
    if kind is None:
        del row["eventType"]
    else:
        row["eventType"] = kind
    report = kit.diagnose([row], _windows(), SECRET)
    assert report.other_event_kinds == (expected,)
    assert report.native_shapes == "INCONCLUSIVE" and report.classified_log_rows == 0
    assert SECRET not in report.model_dump_json()


def test_presence_counts_rows_instead_of_number_of_unknown_keys() -> None:
    first = _ulf() | {SECRET: 1, SECRET + "2": 2}
    report = kit.diagnose([first, _ulf()], _windows(), SECRET)
    assert report.failed_fields[0].presence == "MIXED"


def test_missing_known_fields_are_distinguished_from_null_or_bad_types() -> None:
    row = _ulf()
    del row["processImageUUID"]
    report = kit.diagnose([row], _windows(), SECRET)
    failure = report.failed_fields[0]
    assert failure.field == "processImageUUID" and failure.problems == ("MISSING",)
    assert failure.presence == "ABSENT_ALL" and failure.value_types == ()


def _fixture(tmp_path: Path) -> tuple[Path, kit.Expected]:
    root, code = _saved(tmp_path)
    run = kit.reference._active(root)
    kit.reference._write(root / kit.capture.UNIFIED_CODE, b"invented trusted ULF support")
    kit.reference._write(root / "ULF-EXPERIMENT.json", b'{"collect_unified_log":true}')
    manifest = json.loads((root / "SETUP.json").read_bytes())
    unified_hash = kit.reference._digest(root / kit.capture.UNIFIED_CODE)
    manifest.update(
        unified_code_sha256=unified_hash,
        unified_experiment_sha256=kit.reference._digest(root / "ULF-EXPERIMENT.json"),
    )
    encoded = kit.capture.Manifest.model_validate(manifest).model_dump_json().encode()
    (root / "SETUP.json").write_bytes(encoded)
    (run / "provenance.json").write_bytes(encoded)
    report = json.loads((run / "SHAREABLE-REPORT.json").read_bytes())
    report["unified_log"] = "FIXED_REPORT_AVAILABLE"
    (run / "SHAREABLE-REPORT.json").write_text(json.dumps(report))
    rows = [json.loads(line) for line in (run / "ssh-chain-events.jsonl").read_bytes().splitlines()]
    for index, row in enumerate(rows):
        row["time"] = (datetime(2026, 11, 3, 12, tzinfo=UTC) + timedelta(seconds=index)).isoformat()
    (run / "ssh-chain-events.jsonl").write_bytes(
        b"\n".join(json.dumps(row).encode() for row in rows) + b"\n"
    )
    native = _row(f"Accepted password for {_CANARY} from 127.0.0.1 port 50000 ssh2") | {
        "processID": 1200,
        "processImagePath": kit.capture.PATHS["SESSION"],
        "timestamp": "2026-11-03 12:00:05.500000+0000",
    }
    activity = native | {"eventType": "activityCreateEvent"}
    bad = native | {"source": {"file": SECRET}}
    kit.reference._write(
        run / "ssh-unified-events.ndjson",
        b"\n".join(json.dumps(row).encode() for row in (activity, bad, native)) + b"\n",
    )
    summary = kit.unified.Summary(
        collector_ready="PASS",
        collector_cleanup="PASS",
        execution_binding="PASS",
        retained_rows=3,
        native_shapes="FAIL",
        reference_result="RECORDS_REQUIRE_REVIEW",
    )
    kit.reference._write(run / "SHAREABLE-SSH-ULF-REPORT.json", summary.model_dump_json().encode())
    return root, kit.Expected(code=code, unified_code=unified_hash)


def test_verified_review_preserves_all_files_and_rebinds_every_stored_row(tmp_path: Path) -> None:
    root, expected = _fixture(tmp_path)
    before = {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    result = kit.review_existing(root, expected)
    after = {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }
    assert before == after
    assert (
        result.provenance
        == result.original_collection_controls
        == result.execution_binding
        == "PASS"
    )
    assert result.retained_rows == 3 and result.invalid_log_rows == result.classified_log_rows == 1
    assert result.collectors == result.commands == "NOT_STARTED"
    assert result.live_queries == "NOT_PERFORMED" and result.writes == "NONE"
    assert _CANARY not in result.model_dump_json() and SECRET not in result.model_dump_json()


@pytest.mark.parametrize(
    "damage",
    ["support", "provenance", "controls", "client", "tree", "binding", "count", "ring", "symlink"],
)
def test_changed_or_out_of_scope_inputs_fail_before_any_result(tmp_path: Path, damage: str) -> None:
    root, expected = _fixture(tmp_path)
    run = kit.reference._active(root)
    if damage == "support":
        (root / kit.capture.UNIFIED_CODE).write_bytes(b"changed support")
    elif damage == "provenance":
        raw = json.loads((run / "provenance.json").read_bytes())
        raw["nonce"] = "f" * 32
        (run / "provenance.json").write_text(json.dumps(raw))
    elif damage == "controls":
        raw = json.loads((run / "SHAREABLE-REPORT.json").read_bytes())
        raw["collector_cleanup"] = "FAIL"
        (run / "SHAREABLE-REPORT.json").write_text(json.dumps(raw))
    elif damage == "client":
        raw = json.loads((root / "CLIENT-CONTROL.json").read_bytes())
        raw["pid"] = True
        (root / "CLIENT-CONTROL.json").write_text(json.dumps(raw))
    elif damage == "tree":
        raw = (run / "ssh-chain-events.jsonl").read_bytes().splitlines()
        (run / "ssh-chain-events.jsonl").write_bytes(b"\n".join(raw[2:]) + b"\n")
    elif damage == "binding":
        rows = [
            json.loads(line)
            for line in (run / "ssh-unified-events.ndjson").read_bytes().splitlines()
        ]
        rows[0]["processID"] = 99999
        (run / "ssh-unified-events.ndjson").write_text(
            "\n".join(json.dumps(row) for row in rows) + "\n"
        )
    elif damage in {"count", "ring"}:
        raw = json.loads((run / "SHAREABLE-SSH-ULF-REPORT.json").read_bytes())
        raw["retained_rows" if damage == "count" else "ring_evicted"] = (
            4 if damage == "count" else True
        )
        (run / "SHAREABLE-SSH-ULF-REPORT.json").write_text(json.dumps(raw))
    else:
        (run / "ssh-unified-events.ndjson").unlink()
        (run / "ssh-unified-events.ndjson").symlink_to(root / "SETUP.json")
    with pytest.raises((kit.reference.PrivateError, OSError, ValueError)):
        kit.review_existing(root, expected)


def test_preparation_does_not_open_an_existing_capture(tmp_path: Path) -> None:
    root = kit.prepare(tmp_path / "reviewer")
    assert (root / "private_ssh_ulf_review.py").is_file()
    expected = kit.Expected.model_validate_json((root / "OFFLINE-ULF-EXPECTED.json").read_bytes())
    assert (
        expected.unified_code
        == hashlib.sha256((root / kit.capture.UNIFIED_CODE).read_bytes()).hexdigest()
    )
    assert not list(root.glob("run-*")) and not list(root.glob("*LOCK"))


def test_cli_never_exposes_validator_or_filesystem_error_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    expected = kit.Expected(code={}, unified_code="a" * 64)
    kit.reference._write(
        tmp_path / "OFFLINE-ULF-EXPECTED.json", expected.model_dump_json().encode()
    )
    monkeypatch.setattr(kit, "__file__", str(tmp_path / "private_ssh_ulf_review.py"))
    monkeypatch.setattr(
        kit.sys,
        "argv",
        [
            "private_ssh_ulf_review.py",
            "review-existing",
            "--private-run",
            "--source-kit",
            "/private/tmp/invented",
        ],
    )

    def fail(*args: object) -> None:
        raise ValueError(SECRET)

    monkeypatch.setattr(kit, "review_existing", fail)
    kit.main()
    output = capsys.readouterr()
    assert SECRET not in output.out + output.err
    assert json.loads(output.out)["error"] == "INTERNAL"

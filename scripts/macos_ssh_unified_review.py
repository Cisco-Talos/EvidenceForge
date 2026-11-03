# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare an offline-only SSH ULF shape review; never open a capture at preparation.

Review needs separate local-log permission. All errors, fields and value-shape
labels are closed vocabulary. Native values, unknown keys and validator messages
never leave private memory. No collector, command, live query or write is started.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Literal, get_args

from pydantic import Field, ValidationError

from evidenceforge.formats.macos_unified_log import UnifiedLogRecord


def _load(filename: str, fallback: str, name: str) -> ModuleType:
    path = Path(__file__).resolve().with_name(filename)
    if not path.exists():
        path = path.with_name(fallback)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


graph = _load("ssh_graph_support.py", "macos_ssh_startup_review.py", "_eforge_ulf_graph")
unified = _load("ssh_unified_support.py", "macos_ssh_unified_reference.py", "_eforge_ulf_shapes")
capture, reference = graph.capture, graph.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type FieldName = Literal[
    "eventType",
    "messageType",
    "timezoneName",
    "timestamp",
    "machTimestamp",
    "bootUUID",
    "processID",
    "userID",
    "threadID",
    "processImagePath",
    "processImageUUID",
    "senderImagePath",
    "senderImageUUID",
    "senderProgramCounter",
    "activityIdentifier",
    "parentActivityIdentifier",
    "traceID",
    "subsystem",
    "category",
    "formatString",
    "eventMessage",
    "source",
    "backtrace",
    "personaID",
    "personaName",
    "personaType",
    "launchPersonaID",
    "launchPersonaName",
    "launchPersonaType",
    "OTHER_FIELD",
    "MODEL",
]
type ValueType = Literal["NULL", "BOOLEAN", "INTEGER", "NUMBER", "STRING", "ARRAY", "OBJECT"]
type Problem = Literal[
    "MISSING",
    "ADDITIONAL_FIELD",
    "TYPE_MISMATCH",
    "ENUM_VALUE",
    "STRING_PATTERN",
    "NUMERIC_RANGE",
    "VALUE_VALIDATOR",
    "OTHER_VALIDATION",
]
type StringForm = Literal[
    "EMPTY", "DECIMAL", "HEX", "UUID", "NATIVE_TIMESTAMP", "ISO_TIMESTAMP", "OTHER"
]
type IntegerForm = Literal[
    "NEGATIVE_ONE",
    "NEGATIVE_OTHER",
    "ZERO",
    "U32_MAX",
    "U64_MAX",
    "ABOVE_U64_MAX",
    "POSITIVE_OTHER",
]
type ObjectMember = Literal[
    "frames", "imageOffset", "imageUUID", "file", "function", "line", "column", "path", "OTHER"
]


class Expected(reference.Model):
    code: dict[str, str]
    unified_code: str = Field(pattern=r"^[a-f0-9]{64}$")


class FieldFailure(reference.Model):
    field: FieldName
    problems: tuple[Problem, ...]
    affected_rows: int = Field(ge=1, le=256)
    presence: Literal["ABSENT_ALL", "PRESENT_ALL", "MIXED"]
    value_types: tuple[ValueType, ...] = ()
    string_forms: tuple[StringForm, ...] = ()
    integer_forms: tuple[IntegerForm, ...] = ()
    object_members: tuple[ObjectMember, ...] = ()


class Report(reference.Model):
    review_version: Literal[1] = 1
    purpose: Literal["SSH_UNIFIED_LOG_SHAPE_REVIEW"] = "SSH_UNIFIED_LOG_SHAPE_REVIEW"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: capture.Error = "NONE"
    provenance: Check = "INCONCLUSIVE"
    original_collection_controls: Check = "INCONCLUSIVE"
    execution_binding: Check = "INCONCLUSIVE"
    shape_scope: Literal["LOG_EVENT_ROWS_ONLY"] = "LOG_EVENT_ROWS_ONLY"
    retained_rows: int = Field(default=0, ge=0, le=256)
    log_event_rows: int = Field(default=0, ge=0, le=256)
    other_event_rows: int = Field(default=0, ge=0, le=256)
    other_event_kinds: tuple[
        Literal[
            "ACTIVITY_CREATE",
            "ACTIVITY_TRANSITION",
            "TRACE",
            "SIGNPOST",
            "STATE_DUMP",
            "SIMPLE_DUMP",
            "LOSS",
            "MISSING",
            "OTHER",
        ],
        ...,
    ] = ()
    invalid_log_rows: int = Field(default=0, ge=0, le=256)
    classified_log_rows: int = Field(default=0, ge=0, le=256)
    native_shapes: Check = "INCONCLUSIVE"
    failed_fields: tuple[FieldFailure, ...] = Field(default=(), max_length=32)
    valid_subset: unified.Summary | None = None
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    commands: Literal["NOT_STARTED"] = "NOT_STARTED"
    live_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    writes: Literal["NONE"] = "NONE"


def _problem(kind: str) -> Problem:
    if kind == "missing":
        return "MISSING"
    if kind == "extra_forbidden":
        return "ADDITIONAL_FIELD"
    if kind == "literal_error":
        return "ENUM_VALUE"
    if kind == "string_pattern_mismatch":
        return "STRING_PATTERN"
    if kind in {"greater_than", "greater_than_equal", "less_than", "less_than_equal"}:
        return "NUMERIC_RANGE"
    if kind == "value_error":
        return "VALUE_VALIDATOR"
    return (
        "TYPE_MISMATCH"
        if kind.endswith("_type") or kind in {"none_required", "is_instance_of", "is_subclass_of"}
        else "OTHER_VALIDATION"
    )


def _value_type(value: object) -> ValueType:
    if value is None:
        return "NULL"
    return {
        bool: "BOOLEAN",
        int: "INTEGER",
        float: "NUMBER",
        str: "STRING",
        list: "ARRAY",
        dict: "OBJECT",
    }[type(value)]


def _string_form(value: str) -> StringForm:
    if not value:
        return "EMPTY"
    if re.fullmatch(r"[+-]?[0-9]+", value):
        return "DECIMAL"
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", value):
        return "HEX"
    if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        return "UUID"
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+[+-][0-9]{4}", value):
        return "NATIVE_TIMESTAMP"
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9:]+)?", value):
        return "ISO_TIMESTAMP"
    return "OTHER"


def _integer_form(value: int) -> IntegerForm:
    if value == -1:
        return "NEGATIVE_ONE"
    if value < 0:
        return "NEGATIVE_OTHER"
    if value == 0:
        return "ZERO"
    if value == 2**32 - 1:
        return "U32_MAX"
    if value == 2**64 - 1:
        return "U64_MAX"
    return "ABOVE_U64_MAX" if value > 2**64 - 1 else "POSITIVE_OTHER"


def diagnose(rows: list[dict], windows: tuple, username: str) -> Report:
    """Diagnose every log record; unrelated event kinds cannot poison classification."""
    if len(rows) > 256 or unified.select_rows(rows, windows) != rows:
        raise reference.PrivateError("DATA")
    aliases = {info.alias or name for name, info in UnifiedLogRecord.model_fields.items()}
    public_fields = set(get_args(FieldName.__value__))
    errors: dict[str, set[Problem]] = {}
    affected: dict[str, set[int]] = {}
    logs = [row for row in rows if row.get("eventType") == "logEvent"]
    valid: list[dict] = []
    for index, row in enumerate(logs):
        try:
            UnifiedLogRecord.model_validate_json(json.dumps(row))
        except ValidationError as error:
            for item in error.errors(include_input=False, include_context=False, include_url=False):
                location = item["loc"]
                name = location[0] if location else "MODEL"
                field = name if name in public_fields else "OTHER_FIELD"
                errors.setdefault(field, set()).add(_problem(item["type"]))
                affected.setdefault(field, set()).add(index)
        else:
            valid.append(row)
    failures: list[FieldFailure] = []
    object_keys = set(get_args(ObjectMember.__value__)) - {"OTHER"}
    for field, problems in sorted(errors.items()):
        values = (
            [value for row in logs for key, value in row.items() if key not in aliases]
            if field == "OTHER_FIELD"
            else [row[field] for row in logs if field in row]
            if field != "MODEL"
            else list(logs)
        )
        present_rows = (
            sum(any(key not in aliases for key in row) for row in logs)
            if field == "OTHER_FIELD"
            else len(logs)
            if field == "MODEL"
            else sum(field in row for row in logs)
        )
        presence = (
            "ABSENT_ALL"
            if not present_rows
            else "PRESENT_ALL"
            if present_rows == len(logs)
            else "MIXED"
        )
        failures.append(
            FieldFailure.model_validate(
                {
                    "field": field,
                    "problems": tuple(sorted(problems)),
                    "affected_rows": len(affected[field]),
                    "presence": presence,
                    "value_types": tuple(sorted({_value_type(value) for value in values})),
                    "string_forms": tuple(
                        sorted({_string_form(value) for value in values if type(value) is str})
                    ),
                    "integer_forms": tuple(
                        sorted({_integer_form(value) for value in values if type(value) is int})
                    ),
                    "object_members": tuple(
                        sorted(
                            {
                                key if key in object_keys else "OTHER"
                                for value in values
                                if type(value) is dict
                                for key in value
                            }
                        )
                    ),
                }
            )
        )
    kind_labels = {
        "activityCreateEvent": "ACTIVITY_CREATE",
        "activityTransitionEvent": "ACTIVITY_TRANSITION",
        "traceEvent": "TRACE",
        "signpostEvent": "SIGNPOST",
        "statedumpEvent": "STATE_DUMP",
        "simpledumpEvent": "SIMPLE_DUMP",
        "lossEvent": "LOSS",
    }
    other_kinds = tuple(
        sorted(
            {
                "MISSING"
                if "eventType" not in row
                else kind_labels.get(row["eventType"], "OTHER")
                if type(row["eventType"]) is str
                else "OTHER"
                for row in rows
                if row.get("eventType") != "logEvent"
            }
        )
    )
    return Report(
        retained_rows=len(rows),
        log_event_rows=len(logs),
        other_event_rows=len(rows) - len(logs),
        other_event_kinds=other_kinds,
        invalid_log_rows=len(logs) - len(valid),
        classified_log_rows=len(valid),
        native_shapes="FAIL" if errors else "PASS" if logs else "INCONCLUSIVE",
        failed_fields=tuple(failures),
        valid_subset=unified.summarize(valid, windows, username),
    )


def _model(path: Path, model: type) -> object:
    raw = reference._read(path)
    reference._decode(raw)
    return model.model_validate_json(raw)


def _verified(root: Path, expected: Expected) -> tuple[object, list[dict]]:
    """Authenticate frozen controls and re-prove the selected tree; query no installed code."""
    reference._outside_git(root)
    reference._directory(root)
    manifest = _model(root / "SETUP.json", capture.Manifest)
    run = reference._active(root)
    provenance = _model(run / "provenance.json", capture.Manifest)
    report = _model(run / "SHAREABLE-REPORT.json", capture.Report)
    if (
        manifest != provenance
        or set(expected.code) != set(capture.CODE)
        or manifest.code_sha256 != expected.code
        or any(reference._digest(root / name) != digest for name, digest in expected.code.items())
        or manifest.unified_code_sha256 != expected.unified_code
        or reference._digest(root / capture.UNIFIED_CODE) != expected.unified_code
        or manifest.unified_experiment_sha256 is None
        or manifest.unified_experiment_sha256 != capture._unified_experiment(root)
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.marker.sha256 != reference._digest(root / "ssh-marker")
        or manifest.codec_sha256 != reference._codec_digest()
        or set(manifest.images) != set(capture.PATHS)
        or (manifest.terminal_mode, manifest.experiment_sha256) != capture._experiment(root)
    ):
        raise reference.PrivateError("BUILD")
    controls = (
        report.provenance,
        report.collector_ready,
        report.collector_cleanup,
        report.bounded_collection,
        report.sequence_continuity,
        report.client_control,
        report.receiver_lineage,
        report.marker_exit_zero,
    )
    if (
        report.error != "NONE"
        or report.stage != "COMPLETE"
        or report.wire_profile != "V11"
        or report.unified_log != "FIXED_REPORT_AVAILABLE"
        or any(value != "PASS" for value in controls)
    ):
        raise reference.PrivateError("DATA")
    raw = reference._read(run / "ssh-chain-events.jsonl", capture.MAX_BYTES)
    lines = raw.splitlines()
    if not 1 <= len(lines) <= capture.MAX_RETAINED or any(
        not line or len(line) > reference.MAX_LINE for line in lines
    ):
        raise reference.PrivateError("LIMIT")
    tracker = capture.Tracker(manifest)
    tracker.collecting = True
    for line in lines:
        tracker.accept(line)
    if tracker.retained() != lines:
        raise reference.PrivateError("DATA")
    control = reference._decode(reference._read(root / "CLIENT-CONTROL.json"))
    if (
        tracker.client is None
        or type(control.get("pid")) is not int
        or control["pid"] != tracker.client[0]
        or control.get("nonce") != manifest.nonce
    ):
        raise reference.PrivateError("DATA")
    return manifest, [reference._decode(line) for line in lines]


def review_existing(root: Path, expected: Expected) -> Report:
    """AUTHORIZED READ ONLY: open only the one capture's bounded files and controls."""
    manifest, es_rows = _verified(root, expected)
    run = reference._active(root)
    stored = _model(run / "SHAREABLE-SSH-ULF-REPORT.json", unified.Summary)
    if (
        stored.collector_ready != "PASS"
        or stored.collector_cleanup != "PASS"
        or stored.execution_binding != "PASS"
        or stored.ring_evicted
    ):
        raise reference.PrivateError("DATA")
    raw = reference._read(run / "ssh-unified-events.ndjson", unified.MAX_BYTES)
    lines = raw.splitlines()
    if (
        len(lines) != stored.retained_rows
        or not 1 <= len(lines) <= 256
        or any(not line or len(line) > 6 * unified.MAX_LINE for line in lines)
    ):
        raise reference.PrivateError("LIMIT")
    rows = [reference._decode(line) for line in lines]
    windows = unified.execution_windows(
        es_rows,
        identity=reference._identity,
        role_of=lambda process: capture._role(process, manifest),
    )
    result = diagnose(rows, windows, manifest.username)
    return result.model_copy(
        update={
            "provenance": "PASS",
            "original_collection_controls": "PASS",
            "execution_binding": "PASS",
        }
    )


def prepare(destination: Path | None = None) -> Path:
    """Copy public code and expected hashes only; inspect no existing capture."""
    root = capture.prepare(destination, unified_log=True)
    shutil.copyfile(Path(__file__).resolve(), root / "private_ssh_ulf_review.py")
    (root / "private_ssh_ulf_review.py").chmod(0o600)
    expected = Expected(
        code={
            name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in capture.CODE
        },
        unified_code=hashlib.sha256((root / capture.UNIFIED_CODE).read_bytes()).hexdigest(),
    )
    reference._write(root / "OFFLINE-ULF-EXPECTED.json", expected.model_dump_json().encode())
    return root


def main() -> None:
    try:
        parser = reference.QuietParser(description=__doc__)
        parser.add_argument("operation", choices=("prepare", "review-existing"))
        parser.add_argument("--private-run", action="store_true")
        parser.add_argument("--source-kit", type=Path)
        args = parser.parse_args()
        if args.operation == "prepare":
            if args.private_run or args.source_kit is not None:
                raise reference.PrivateError("INPUT")
            print(prepare())
            return
        if not args.private_run or args.source_kit is None:
            raise reference.PrivateError("INPUT")
        own_root = Path(__file__).resolve().parent
        reference._outside_git(own_root)
        reference._directory(own_root)
        expected = Expected.model_validate_json(
            reference._read(own_root / "OFFLINE-ULF-EXPECTED.json")
        )
        report = review_existing(args.source_kit, expected)
    except (
        reference.PrivateError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
        KeyboardInterrupt,
    ) as error:
        report = Report(error=capture._failure(error))
    print(report.model_dump_json(indent=2), flush=True)


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: print(
        Report(error="INTERNAL").model_dump_json()
    )
    main()

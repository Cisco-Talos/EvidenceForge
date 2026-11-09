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

from evidenceforge.events.macos_logging import UnifiedLogCallsite
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


class CallsiteShape(reference.Model):
    """Public trace-header comparisons; never offsets, addresses or native text."""

    log_namespace: Check
    level_agreement: Check
    pc_styles: tuple[
        Literal[
            "NONE",
            "MAIN_IMAGE",
            "SHARED_CACHE",
            "PLUGIN",
            "ABSOLUTE",
            "UUID_RELATIVE",
            "LARGE_SHARED_CACHE",
            "UNUSED",
        ],
        ...,
    ]
    flags: tuple[
        Literal[
            "ACTIVITY",
            "UNIQUE_PID",
            "LARGE_OFFSET",
            "PRIVATE_DATA",
            "SUBSYSTEM",
            "RULES",
            "OVERSIZE",
            "CONTEXT_DATA",
            "UNKNOWN_BITS",
        ],
        ...,
    ]
    dynamic_format: Literal["PRESENT", "ABSENT", "MIXED"]
    format_forms: tuple[
        Literal[
            "EMPTY",
            "PUBLIC_C_STRING",
            "C_STRING",
            "SSH_SYSLOG_PRECISION",
            "MATCHES_MESSAGE",
            "OTHER",
        ],
        ...,
    ]
    static_offset_range: Check
    pc_range: Check
    pc_alignment: Check
    dynamic_code_matches_pc: Check
    source_absent: Check
    backtrace_absent: Check


class FamilyProfile(reference.Model):
    """Group the approved fixed classifications, never the underlying row values."""

    family: Literal[
        "accepted_local_password",
        "accepted_local_pam",
        "pam_open",
        "pam_close",
        "disconnected_local",
        "other_controlled",
    ]
    summary: unified.Summary
    root_writer: Check
    main_image_sender: Check
    main_image_callsite: Check
    zero_trace: Check
    zero_program_counter: Check
    zero_mach_timestamp: Check
    zero_thread: Check
    zero_activity: Check
    rules_flag: Literal["PRESENT", "ABSENT", "MIXED"]
    callsite_shape: CallsiteShape


class Report(reference.Model):
    review_version: Literal[1, 2, 3] = 3
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
    families: tuple[FamilyProfile, ...] = Field(default=(), max_length=6)
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


def _main_callsite(row: UnifiedLogRecord) -> bool:
    try:
        modeled = UnifiedLogCallsite(
            message_type=row.message_type,
            subsystem=row.subsystem,
            category=row.category,
            format_string=row.format_string,
            format_string_offset=row.trace_id >> 32,
            program_counter=row.sender_program_counter,
            has_rules=bool((row.trace_id >> 16) & 0x0400),
        )
    except ValueError:
        return False
    return modeled.trace_id == row.trace_id


def _callsite_shape(rows: list[UnifiedLogRecord]) -> CallsiteShape:
    # Apple's public firehose_types_private.h defines these protocol bits. This
    # enumerates public semantics only; unrecognized bits never leave as numbers.
    styles = (
        "NONE",
        "MAIN_IMAGE",
        "SHARED_CACHE",
        "PLUGIN",
        "ABSOLUTE",
        "UUID_RELATIVE",
        "LARGE_SHARED_CACHE",
        "UNUSED",
    )
    flags = {
        0x0001: "ACTIVITY",
        0x0010: "UNIQUE_PID",
        0x0020: "LARGE_OFFSET",
        0x0100: "PRIVATE_DATA",
        0x0200: "SUBSYSTEM",
        0x0400: "RULES",
        0x0800: "OVERSIZE",
        0x1000: "CONTEXT_DATA",
    }
    names: set[str] = set()
    for row in rows:
        bits = (row.trace_id >> 16) & 0xFFFF
        names.update(name for mask, name in flags.items() if bits & mask)
        if bits & ~(0x000E | sum(flags)):
            names.add("UNKNOWN_BITS")
    formats: set[str] = set()
    for row in rows:
        formats.add(
            {
                "": "EMPTY",
                "%s": "C_STRING",
                "%{public}s": "PUBLIC_C_STRING",
                "%.500s": "SSH_SYSLOG_PRECISION",
            }.get(
                row.format_string,
                "MATCHES_MESSAGE" if row.format_string == row.event_message else "OTHER",
            )
        )
    dynamic = {bool(row.trace_id & (1 << 63)) for row in rows}
    types = {"Default": 0, "Info": 1, "Debug": 2, "Error": 16, "Fault": 17}
    return CallsiteShape.model_validate(
        {
            "log_namespace": "PASS" if all(row.trace_id & 0xFF == 4 for row in rows) else "FAIL",
            "level_agreement": "PASS"
            if all((row.trace_id >> 8) & 0xFF == types[row.message_type] for row in rows)
            else "FAIL",
            "pc_styles": tuple(sorted({styles[(row.trace_id >> 17) & 7] for row in rows})),
            "flags": tuple(sorted(names)),
            "dynamic_format": "MIXED"
            if len(dynamic) > 1
            else "PRESENT"
            if True in dynamic
            else "ABSENT",
            "format_forms": tuple(sorted(formats)),
            "static_offset_range": "PASS"
            if all(0 < row.trace_id >> 32 < 2**31 for row in rows)
            else "FAIL",
            "pc_range": "PASS"
            if all(0 < row.sender_program_counter < 2**32 for row in rows)
            else "FAIL",
            "pc_alignment": "PASS"
            if all(row.sender_program_counter % 4 == 0 for row in rows)
            else "FAIL",
            "dynamic_code_matches_pc": "PASS"
            if all(row.trace_id >> 32 == row.sender_program_counter | 0x80000000 for row in rows)
            else "FAIL",
            "source_absent": "PASS" if all(row.source is None for row in rows) else "FAIL",
            "backtrace_absent": "PASS" if all(row.backtrace is None for row in rows) else "FAIL",
        }
    )


def _families(rows: list[dict], windows: tuple, username: str) -> tuple[FamilyProfile, ...]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        one = unified.summarize([row], windows, username)
        family = next(name for name in unified.Messages.model_fields if getattr(one.messages, name))
        grouped.setdefault(family, []).append(row)
    result: list[FamilyProfile] = []
    for family, members in sorted(grouped.items()):
        records = [UnifiedLogRecord.model_validate_json(json.dumps(row)) for row in members]
        rules = {bool((row.trace_id >> 16) & 0x0400) for row in records}
        result.append(
            FamilyProfile.model_validate(
                {
                    "family": family,
                    "summary": unified.summarize(members, windows, username),
                    "root_writer": "PASS" if all(row.user_id == 0 for row in records) else "FAIL",
                    "main_image_sender": "PASS"
                    if all(
                        row.sender_image_path == row.process_image_path
                        and row.process_image_uuid
                        and row.sender_image_uuid == row.process_image_uuid
                        for row in records
                    )
                    else "FAIL",
                    "main_image_callsite": "PASS"
                    if all(_main_callsite(row) for row in records)
                    else "FAIL",
                    "zero_trace": "PASS" if all(row.trace_id == 0 for row in records) else "FAIL",
                    "zero_program_counter": "PASS"
                    if all(row.sender_program_counter == 0 for row in records)
                    else "FAIL",
                    "zero_mach_timestamp": "PASS"
                    if all(row.mach_timestamp == 0 for row in records)
                    else "FAIL",
                    "zero_thread": "PASS" if all(row.thread_id == 0 for row in records) else "FAIL",
                    "zero_activity": "PASS"
                    if all(
                        row.activity_identifier == row.parent_activity_identifier == 0
                        for row in records
                    )
                    else "FAIL",
                    "rules_flag": "MIXED"
                    if len(rules) > 1
                    else "PRESENT"
                    if True in rules
                    else "ABSENT",
                    "callsite_shape": _callsite_shape(records),
                }
            )
        )
    return tuple(result)


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
        families=_families(valid, windows, username),
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

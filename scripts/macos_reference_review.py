# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Human-only offline diagnostics for an existing private bounded ES capture.

Agents may prepare this code and test invented inputs, never run a private
review. No collector, native command, network request or record-value output
exists in this tool. Diagnostics do not qualify a wire profile or open a gate.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import logging
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evidenceforge.formats.macos_endpoint_security import (
    ESAction,
    ESExec,
    ESExitEvent,
    ESProcess,
    ESThread,
    NativeTime,
    UInt64,
)

logger = logging.getLogger(__name__)

MAX_LINE_BYTES = 1_048_576
MAX_RECORDS = 32
MAX_SUMMARY_BYTES = 32_768
MAX_TOKEN_BYTES = 4_096
MAX_JSON_DEPTH = 32
INSTRUCTIONS = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/native-reference-capture/OFFLINE-REVIEW.md"
)
_MISSING = object()
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type ErrorCode = Literal[
    "NONE", "INPUT", "LOCATION", "PERMISSIONS", "SOURCE", "DATA", "LIMIT", "INTERNAL", "INTERRUPTED"
]
type WireProfile = Literal[
    "NOT_OBSERVED",
    "V10_CANDIDATE",
    "V11_UNQUALIFIED",
    "OTHER_UNQUALIFIED",
    "SCHEMA_UNQUALIFIED",
    "MIXED",
    "INVALID",
]
type Extent = Literal[
    "EMPTY", "BYTES_20", "BYTES_32", "BYTES_48", "BYTES_64", "OTHER", "MIXED", "INCONCLUSIVE"
]


class PrivateReviewError(ValueError):
    """A constant diagnostic code, never a native value or error description."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(code)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @field_validator(
        "schema_version",
        "version",
        "event_type",
        "action_type",
        "review_version",
        "kit_version",
        mode="before",
        check_fields=False,
    )
    @classmethod
    def integer_discriminants(cls, value: object) -> object:
        """Reject booleans and strings for literal integer tags."""
        if type(value) is not int:
            raise ValueError("DATA")
        return value


class FullHashReport(_Model):
    """Only fixed classifications and candidate checks; never a digest or count."""

    presence: Literal["PRESENT_ALL", "ABSENT_ALL", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    representation: Literal[
        "STRING",
        "BYTE_ARRAY",
        "SIZE_DATA_OBJECT",
        "OTHER_OBJECT",
        "NULL",
        "ABSENT",
        "UNRECOGNIZED",
        "MIXED",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    object_keys: Check = "INCONCLUSIVE"
    declared_size_type: Check = "INCONCLUSIVE"
    hex_decoding: Check = "INCONCLUSIVE"
    hex_extent: Extent = "INCONCLUSIVE"
    hex_declared_size: Check = "INCONCLUSIVE"
    hex_legacy_prefix: Check = "INCONCLUSIVE"
    base64_decoding: Check = "INCONCLUSIVE"
    base64_extent: Extent = "INCONCLUSIVE"
    base64_declared_size: Check = "INCONCLUSIVE"
    base64_legacy_prefix: Check = "INCONCLUSIVE"
    array_decoding: Check = "INCONCLUSIVE"
    array_extent: Extent = "INCONCLUSIVE"
    array_declared_size: Check = "INCONCLUSIVE"
    array_legacy_prefix: Check = "INCONCLUSIVE"


class ReviewReport(_Model):
    """The complete public vocabulary, independent of record keys and values."""

    review_version: Literal[1] = 1
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    purpose: Literal["SHAPE_DIAGNOSTIC_ONLY"] = "SHAPE_DIAGNOSTIC_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    message_shapes: Literal["INCONCLUSIVE"] = "INCONCLUSIVE"
    error: ErrorCode = "NONE"
    review_complete: Check = "INCONCLUSIVE"
    capture_summary: Check = "INCONCLUSIVE"
    wire_profile: WireProfile = "NOT_OBSERVED"
    retained_families: Check = "INCONCLUSIVE"
    envelope_fields: Check = "INCONCLUSIVE"
    envelope_values: Check = "INCONCLUSIVE"
    process_fields: Check = "INCONCLUSIVE"
    process_values: Check = "INCONCLUSIVE"
    fork_payload: Check = "INCONCLUSIVE"
    exec_fields: Check = "INCONCLUSIVE"
    exec_values: Check = "INCONCLUSIVE"
    exit_payload: Check = "INCONCLUSIVE"
    audit_token_form: Literal[
        "ARRAY", "NAMED", "VAL_WRAPPER", "ABSENT", "NULL", "UNRECOGNIZED", "MIXED", "INCONCLUSIVE"
    ] = "INCONCLUSIVE"
    process_start_form: Literal[
        "TIMESTAMP_STRING", "TIMEVAL", "ABSENT", "NULL", "UNRECOGNIZED", "MIXED", "INCONCLUSIVE"
    ] = "INCONCLUSIVE"
    full_hash: FullHashReport = Field(default_factory=FullHashReport)


class CaptureSummary(_Model):
    """Require the successful v3/v11 bounded-run report, not arbitrary logs."""

    kit_version: Literal[3]
    reference_review: Literal["REQUIRED"]
    gate_status: Literal["NOT_EVALUATED"]
    error: Literal["WIRE_PROFILE"]
    target_platform: Literal["PASS"]
    stream_delivery: Literal["PASS"]
    probe_identity_seen: Literal["PASS"]
    probe_image_seen: Literal["PASS"]
    collector_ready: Literal["PASS"]
    wire_profile: Literal["V11_UNQUALIFIED"]
    message_shapes: Literal["INCONCLUSIVE"]
    probe_controls: Literal["PASS"]
    bounded_delivery: Literal["PASS"]
    candidate_v10_shapes: Literal["INCONCLUSIVE"]
    fork_exec_exit_linkage: Literal["PASS"]
    controlled_exec_inputs: Literal["PASS"]
    controlled_descriptors: Literal["PASS"]
    exit_status_agreement: Literal["PASS"]
    failed_exec_control: Literal["PASS"]
    sequence_continuity: Literal["PASS"]


class _Envelope(_Model):
    """Known envelope fields with the original v11 discriminant, not retagged v10."""

    schema_version: Literal[1]
    version: Literal[11]
    event_type: Literal[9, 11, 15]
    action_type: Literal[1]
    action: ESAction
    time: NativeTime
    mach_time: UInt64
    seq_num: UInt64
    global_seq_num: UInt64
    thread: ESThread

    @field_validator("time")
    @classmethod
    def calendar_time(cls, value: str) -> str:
        """Validate calendar values without exporting native timestamps."""
        datetime.fromisoformat(value)
        return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PrivateReviewError("DATA")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise PrivateReviewError("DATA")


def _decode(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, RecursionError):
        raise PrivateReviewError("DATA") from None
    if not isinstance(value, dict):
        raise PrivateReviewError("DATA")
    pending: list[tuple[dict[str, object] | list[object], int]] = [(value, 1)]
    while pending:
        container, depth = pending.pop()
        if depth > MAX_JSON_DEPTH:
            raise PrivateReviewError("DATA")
        children = container.values() if isinstance(container, dict) else container
        for child in children:
            if isinstance(child, (dict, list)):
                pending.append((child, depth + 1))
            elif isinstance(child, float) and not math.isfinite(child):
                raise PrivateReviewError("DATA")
    return value


def _mapping(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


def _check(values: list[bool]) -> Check:
    return ("PASS" if all(values) else "FAIL") if values else "INCONCLUSIVE"


def _uniform(values: list[str], empty: str = "INCONCLUSIVE") -> str:
    return (values[0] if len(set(values)) == 1 else "MIXED") if values else empty


def _valid(model: type[BaseModel], value: object) -> bool:
    try:
        model.model_validate_json(json.dumps(value, allow_nan=False))
    except ValidationError:
        return False
    return True


def _process_baseline(process: dict[str, object]) -> dict[str, object]:
    # A separate diagnostic view only; original rows are never changed, retagged
    # or written. Extra keys and absent required keys are reported separately.
    return {key: value for key, value in process.items() if key in ESProcess.model_fields}


def _audit_form(value: object) -> str:
    if value is _MISSING:
        return "ABSENT"
    if value is None:
        return "NULL"
    form = "ARRAY"
    if isinstance(value, dict):
        names = ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")
        if set(value) == set(names):
            value = [value[key] for key in names]
            form = "NAMED"
        elif set(value) == {"val"}:
            value = value["val"]
            form = "VAL_WRAPPER"
        else:
            return "UNRECOGNIZED"
    if (
        not isinstance(value, list)
        or len(value) != 8
        or any(type(word) is not int or not 0 <= word <= 0xFFFFFFFF for word in value)
    ):
        return "UNRECOGNIZED"
    return form


def _birth_form(value: object) -> str:
    if value is _MISSING:
        return "ABSENT"
    if value is None:
        return "NULL"
    if isinstance(value, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value
    ):
        try:
            datetime.fromisoformat(value)
        except ValueError:
            return "UNRECOGNIZED"
        return "TIMESTAMP_STRING"
    if (
        isinstance(value, dict)
        and set(value) == {"tv_sec", "tv_usec"}
        and type(value["tv_sec"]) is int
        and value["tv_sec"] >= 0
        and type(value["tv_usec"]) is int
        and 0 <= value["tv_usec"] < 1_000_000
    ):
        return "TIMEVAL"
    return "UNRECOGNIZED"


def _hash_form(value: object) -> str:
    if value is _MISSING:
        return "ABSENT"
    if value is None:
        return "NULL"
    if isinstance(value, str):
        return "STRING"
    if isinstance(value, list):
        return "BYTE_ARRAY" if _hash_bytes(value, "array") is not None else "UNRECOGNIZED"
    if isinstance(value, dict):
        return "SIZE_DATA_OBJECT" if set(value) == {"size", "data"} else "OTHER_OBJECT"
    return "UNRECOGNIZED"


def _hash_bytes(value: object, encoding: Literal["hex", "base64", "array"]) -> bytes | None:
    if isinstance(value, dict):
        if set(value) != {"size", "data"}:
            return None
        value = value["data"]
    if encoding == "array":
        if (
            not isinstance(value, list)
            or len(value) > MAX_TOKEN_BYTES
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)
        ):
            return None
        return bytes(value)
    if not isinstance(value, str) or len(value) > MAX_TOKEN_BYTES * 2:
        return None
    if encoding == "hex":
        if len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]*", value) is None:
            return None
        return bytes.fromhex(value)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) > MAX_TOKEN_BYTES or base64.b64encode(decoded).decode("ascii") != value:
        return None
    return decoded


def _extent(value: bytes) -> str:
    return {0: "EMPTY", 20: "BYTES_20", 32: "BYTES_32", 48: "BYTES_48", 64: "BYTES_64"}.get(
        len(value), "OTHER"
    )


def _full_hash(processes: list[dict[str, object]]) -> FullHashReport:
    values = [process.get("cdhash_full", _MISSING) for process in processes]
    present = [value is not _MISSING for value in values]
    presence = "NOT_OBSERVED"
    if present:
        presence = "PRESENT_ALL" if all(present) else "MIXED" if any(present) else "ABSENT_ALL"
    candidates = [
        (process, value)
        for process, value in zip(processes, values, strict=True)
        if value is not _MISSING and value is not None
    ]
    objects = [value for _process, value in candidates if isinstance(value, dict)]
    sized = (
        bool(candidates)
        and len(objects) == len(candidates)
        and all(
            set(value) == {"size", "data"}
            and type(value["size"]) is int
            and 0 <= value["size"] <= MAX_TOKEN_BYTES
            for value in objects
        )
    )
    result: dict[str, object] = {
        "presence": presence,
        "representation": _uniform([_hash_form(value) for value in values]),
        "object_keys": _check([set(value) == {"size", "data"} for value in objects]),
        "declared_size_type": _check(
            [
                type(value.get("size")) is int and 0 <= value["size"] <= MAX_TOKEN_BYTES
                for value in objects
            ]
        ),
    }
    for encoding in ("hex", "base64", "array"):
        decoded = [_hash_bytes(value, encoding) for _process, value in candidates]
        valid = bool(decoded) and all(value is not None for value in decoded)
        result[f"{encoding}_decoding"] = _check([value is not None for value in decoded])
        result[f"{encoding}_extent"] = (
            _uniform([_extent(value) for value in decoded if value is not None])
            if valid
            else "INCONCLUSIVE"
        )
        result[f"{encoding}_declared_size"] = (
            _check(
                [
                    len(value) == original["size"]
                    for value, (_process, original) in zip(decoded, candidates, strict=True)
                    if value is not None
                ]
            )
            if valid and sized
            else "INCONCLUSIVE"
        )
        prefixes: list[bool] = []
        for value, (process, _original) in zip(decoded, candidates, strict=True):
            legacy = process.get("cdhash")
            if (
                value is None
                or len(value) < 20
                or not isinstance(legacy, str)
                or re.fullmatch(r"[0-9a-fA-F]{40}", legacy) is None
            ):
                prefixes = []
                break
            prefixes.append(value[:20] == bytes.fromhex(legacy))
        result[f"{encoding}_legacy_prefix"] = _check(prefixes)
    return FullHashReport.model_validate(result)


def _wire_profile(rows: list[dict[str, object]]) -> WireProfile:
    if not rows:
        return "NOT_OBSERVED"
    headers: set[tuple[int, int]] = set()
    for row in rows:
        schema, version = row.get("schema_version"), row.get("version")
        if type(schema) is not int or type(version) is not int or schema <= 0 or version <= 0:
            return "INVALID"
        headers.add((schema, version))
    if len(headers) != 1:
        return "MIXED"
    schema, version = next(iter(headers))
    if schema != 1:
        return "SCHEMA_UNQUALIFIED"
    return {10: "V10_CANDIDATE", 11: "V11_UNQUALIFIED"}.get(version, "OTHER_UNQUALIFIED")


def analyze(rows: list[dict[str, object]]) -> ReviewReport:
    """Inspect invented or human-private rows without claiming a qualified codec."""
    envelope_fields: list[bool] = []
    envelope_values: list[bool] = []
    processes: list[dict[str, object]] = []
    forks: list[bool] = []
    exec_fields: list[bool] = []
    exec_values: list[bool] = []
    exits: list[bool] = []
    families: set[int] = set()
    for row in rows:
        envelope_fields.append(set(row) == set(_Envelope.model_fields) | {"process", "event"})
        envelope_values.append(
            _valid(
                _Envelope,
                {key: value for key, value in row.items() if key in _Envelope.model_fields},
            )
        )
        processes.append(_mapping(row.get("process")))
        family = row.get("event_type")
        if type(family) is not int:
            continue
        families.add(family)
        event = _mapping(row.get("event"))
        if family == 11:
            payload = _mapping(event.get("fork"))
            forks.append(set(event) == {"fork"} and set(payload) == {"child"})
            processes.append(_mapping(payload.get("child")))
        elif family == 9:
            payload = _mapping(event.get("exec"))
            processes.append(_mapping(payload.get("target")))
            exec_fields.append(set(event) == {"exec"} and set(payload) == set(ESExec.model_fields))
            baseline = {key: value for key, value in payload.items() if key in ESExec.model_fields}
            baseline["target"] = _process_baseline(_mapping(payload.get("target")))
            exec_values.append(
                _valid(ESExec, baseline) and isinstance(payload.get("dyld_exec_path"), str)
            )
        elif family == 15:
            exits.append(_valid(ESExitEvent, event))
    process_keys = set(ESProcess.model_fields)
    return ReviewReport(
        review_complete="PASS",
        wire_profile=_wire_profile(rows),
        retained_families="PASS" if families == {9, 11, 15} else "FAIL",
        envelope_fields=_check(envelope_fields),
        envelope_values=_check(envelope_values),
        process_fields=_check(
            [
                process_keys <= set(process) <= process_keys | {"cdhash_full"}
                for process in processes
            ]
        ),
        process_values=_check(
            [
                _valid(ESProcess, _process_baseline(process))
                and process.get("cs_validation_category") is not None
                for process in processes
            ]
        ),
        fork_payload=_check(forks),
        exec_fields=_check(exec_fields),
        exec_values=_check(exec_values),
        exit_payload=_check(exits),
        audit_token_form=_uniform(
            [
                _audit_form(process.get(key, _MISSING))
                for process in processes
                for key in ("audit_token", "parent_audit_token", "responsible_audit_token")
            ]
        ),
        process_start_form=_uniform(
            [_birth_form(process.get("start_time", _MISSING)) for process in processes]
        ),
        full_hash=_full_hash(processes),
    )


def _outside_git(path: Path) -> None:
    if any(
        (parent / ".git").exists() or (parent / ".git").is_symlink()
        for parent in (path, *path.parents)
    ):
        raise PrivateReviewError("LOCATION")


def _private_metadata(metadata: os.stat_result, *, directory: bool = False) -> None:
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        raise PrivateReviewError("LOCATION")
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise PrivateReviewError("PERMISSIONS")
    if not directory and metadata.st_nlink != 1:
        raise PrivateReviewError("LOCATION")


@contextmanager
def _private_reader(directory: int, name: str, limit: int) -> Iterator[BinaryIO]:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        _private_metadata(metadata)
        if metadata.st_size > limit:
            raise PrivateReviewError("LIMIT")
        yield source


def review(run: Path) -> ReviewReport:
    """HUMAN ONLY: read exactly two existing private files; never write anything."""
    if not run.is_absolute():
        raise PrivateReviewError("LOCATION")
    _outside_git(run)
    run = run.resolve(strict=True)
    _outside_git(run)
    directory = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _private_metadata(os.fstat(directory), directory=True)
        with _private_reader(directory, "SHAREABLE-REPORT.json", MAX_SUMMARY_BYTES) as source:
            summary = source.read(MAX_SUMMARY_BYTES + 1)
            if len(summary) > MAX_SUMMARY_BYTES:
                raise PrivateReviewError("LIMIT")
            if not _valid(CaptureSummary, _decode(summary)):
                raise PrivateReviewError("SOURCE")
        rows: list[dict[str, object]] = []
        with _private_reader(
            directory, "probe-events.jsonl", MAX_RECORDS * MAX_LINE_BYTES
        ) as source:
            while raw := source.readline(MAX_LINE_BYTES + 1):
                if len(raw) > MAX_LINE_BYTES or len(rows) >= MAX_RECORDS:
                    raise PrivateReviewError("LIMIT")
                if not raw.endswith(b"\n") or not raw.strip():
                    raise PrivateReviewError("DATA")
                rows.append(_decode(raw))
        if not rows:
            raise PrivateReviewError("DATA")
    finally:
        os.close(directory)
    report = analyze(rows)
    return report.model_copy(
        update={
            "capture_summary": "PASS",
            "error": "NONE" if report.wire_profile == "V11_UNQUALIFIED" else "SOURCE",
        }
    )


def _human_review() -> ReviewReport:
    kit = Path(__file__).resolve().parent
    _outside_git(kit)
    _private_metadata(kit.stat(), directory=True)
    if not sys.stdin.isatty():
        raise PrivateReviewError("INPUT")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            text = getpass.getpass("Private run directory (input hidden): ")
    except (EOFError, getpass.GetPassWarning):
        raise PrivateReviewError("INPUT") from None
    if not text or len(text) > 4096 or "\0" in text:
        raise PrivateReviewError("INPUT")
    return review(Path(text))


def prepare(destination: Path | None) -> Path:
    """Copy only offline-review code and instructions into a fresh private kit."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    if destination is None:
        target = Path(tempfile.mkdtemp(prefix="eforge-native-review-kit-", dir=parent))
    else:
        target = parent / destination.name
        target.mkdir(mode=0o700)
    shutil.copyfile(Path(__file__).resolve(), target / "private_review.py")
    shutil.copyfile(INSTRUCTIONS, target / "OFFLINE-REVIEW.md")
    (target / "private_review.py").chmod(0o600)
    (target / "OFFLINE-REVIEW.md").chmod(0o600)
    return target


class QuietParser(argparse.ArgumentParser):
    """Never echo user-supplied arguments, paths or exception strings."""

    def error(self, _message: str) -> None:
        raise PrivateReviewError("INPUT")


def _emit(report: ReviewReport) -> None:
    sys.stdout.write(report.model_dump_json(indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    """Prepare code or select a human-only, read-only offline review."""
    parser = QuietParser(prog="private-es-review", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True, parser_class=QuietParser)
    stage = commands.add_parser("prepare", help="Copy code/instructions only")
    stage.add_argument("--destination", type=Path)
    inspect = commands.add_parser("review", help="HUMAN ONLY: offline review; no collection")
    inspect.add_argument("--private-run", action="store_true", required=True)
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
            return 0
        report = _human_review()
        _emit(report)
        return 0 if report.error == "NONE" else 1
    except PrivateReviewError as error:
        _emit(ReviewReport(error=error.code))
    except KeyboardInterrupt:
        _emit(ReviewReport(error="INTERRUPTED"))
        return 130
    except (FileNotFoundError, NotADirectoryError):
        _emit(ReviewReport(error="LOCATION"))
    except PermissionError:
        _emit(ReviewReport(error="PERMISSIONS"))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        _emit(ReviewReport(error="INTERNAL"))
    return 2


def _private_exception_hook(_kind: object, _value: object, _traceback: object) -> None:
    os.write(2, b"PRIVATE_REFERENCE_INTERNAL_ERROR\n")


if __name__ == "__main__":
    sys.excepthook = _private_exception_hook
    raise SystemExit(main())

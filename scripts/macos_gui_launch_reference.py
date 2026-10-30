# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a HUMAN-ONLY Finder launch reference kit.

Agents may prepare/help, compile without execution, and test invented inputs.
Never run setup/capture/report/review-existing on a real kit or inspect its private output.
"""

from __future__ import annotations

import argparse
import calendar
import getpass
import hashlib
import inspect
import json
import logging
import os
import platform
import plistlib
import re
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import warnings
from collections import Counter, deque
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, BinaryIO, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationError,
    model_serializer,
    model_validator,
)

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record

logger = logging.getLogger(__name__)
SOURCES = (
    Path(__file__).resolve().parents[1]
    / "docs/design/macos-workstation-feasibility/gui-launch-reference"
)
SAFE_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
CODE = ("private_gui_launch.py", "gui_launch_probe.m", "collector_guard.c")
MAX_LINE = 1_048_576
MAX_STREAM = 32 * MAX_LINE
MAX_RETAINED = 16
MAX_RING_BYTES = 4 * MAX_LINE
ENTITLEMENT_MARKER = "org.evidenceforge.reference.synthetic"
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Case = Literal["control", "finder"]
type Code = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "ROOT_USER",
    "PLATFORM",
    "BUILD",
    "DATA",
    "LIMIT",
    "INCOMPLETE",
    "SESSION_LOCKED",
    "PROBE_KILLED",
    "PROBE_FAILED",
    "PROBE_TIMEOUT",
    "CONTROL_KILLED",
    "CONTROL_FAILED",
    "CONTROL_TIMEOUT",
    "CONTROL_INCOMPLETE",
    "FINDER_TIMEOUT",
    "COLLECTOR",
    "INTERRUPTED",
    "INTERNAL",
]
type Stage = Literal[
    "SETUP_READY",
    "PROBE_CHECK",
    "COLLECTOR_READY",
    "FINDER_READY",
    "COMPLETE",
    "OFFLINE_REPORT",
    "ERROR",
]
type Role = Literal["SELF", "PARENT", "OTHER", "UNSET", "INCONCLUSIVE"]
type Kind = Literal["VNODE", "PIPE", "SOCKET", "OTHER", "CLOSED", "INCONCLUSIVE"]
type Access = Literal["READ", "WRITE", "READ_WRITE", "OTHER", "CLOSED", "INCONCLUSIVE"]
type ImageRole = Literal[
    "LAUNCHD",
    "FINDER",
    "DOCK",
    "SPOTLIGHT",
    "TERMINAL",
    "OTHER",
    "UNAVAILABLE",
    "UNSET",
    "SELF",
    "NOT_OBSERVED",
]
type UInt = Annotated[int, Field(strict=True, ge=0, lt=2**64)]
type Word = Annotated[int, Field(strict=True, ge=0, lt=2**32)]
type Hex = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2}){0,8192}$")]
type Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class PrivateError(ValueError):
    """Fixed diagnostic only; never attach an input, path or exception text."""

    def __init__(self, code: Code) -> None:
        self.code = code
        super().__init__(code)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class OwnFD(Model):
    fd: Annotated[int, Field(strict=True, ge=0, lt=2**31)]
    kind: Word
    flags: Word
    access: Word
    tty: bool


class OwnSnapshot(Model):
    """Private observation at main entry, not a claim about the kernel exec instant."""

    phase: Literal["MAIN_ENTRY"]
    token: tuple[Word, Word, Word, Word, Word, Word, Word, Word]
    ppid: Word
    sid: Word
    pgid: Word
    start_seconds: UInt
    start_microseconds: Annotated[int, Field(strict=True, ge=0, lt=1_000_000)]
    inventory_complete: bool
    fds: Annotated[tuple[OwnFD, ...], Field(max_length=255)]
    arguments_hex: Annotated[tuple[Hex, ...], Field(max_length=512)]
    environment_hex: Annotated[tuple[Hex, ...], Field(max_length=512)]


class Image(Model):
    device: int
    inode: UInt
    sha256: Digest


class Manifest(Model):
    kit_version: Annotated[int, Field(strict=True, ge=1, le=2)] = 1
    collection_mode: Literal["app", "launch_chain"] = "app"
    synthetic_entitlement: bool | None = None
    image: Image
    guard_sha256: Digest
    plist_sha256: Digest
    code_sha256: dict[str, Digest]
    codec_sha256: Digest

    @model_validator(mode="after")
    def coherent_variant(self) -> Manifest:
        """Bind the new collection scope to an explicit versioned setup choice."""
        if (self.kit_version == 2) != (self.collection_mode == "launch_chain"):
            raise ValueError("Private kit collection variant and version disagree")
        if self.synthetic_entitlement is not None and self.collection_mode != "launch_chain":
            raise ValueError("Synthetic entitlement choice requires launcher collection mode")
        return self

    @model_serializer(mode="wrap")
    def serialize_compatible(self, handler: SerializerFunctionWrapHandler) -> dict:
        """Preserve original setup/provenance shapes for existing private kits."""
        data = handler(self)
        if self.collection_mode == "app":
            data.pop("collection_mode", None)
        if self.synthetic_entitlement is None:
            data.pop("synthetic_entitlement", None)
        return data


class EntitlementShape(Model):
    """Fixed representation classes; no native keys or values are exported."""

    representation: Literal[
        "NULL",
        "OBJECT",
        "STRING_JSON_OBJECT",
        "STRING_PLIST_OBJECT",
        "STRING_OTHER",
        "OTHER",
        "NOT_OBSERVED",
        "ABSENT",
    ] = "NOT_OBSERVED"
    marker: Literal["BOOLEAN_TRUE", "INTEGER_ONE", "ABSENT", "OTHER", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    only_controlled_marker: Check = "INCONCLUSIVE"


type CandidateSelection = Literal[
    "NOT_RECORDED",
    "NO_CANDIDATES",
    "NO_EXECUTION_MATCH",
    "TOKEN_MISMATCH",
    "IMAGE_MISMATCH",
    "MATCHED",
]


class LaunchChainDiagnostic(Model):
    """Supplementary diagnostic only; never a native generation qualification."""

    purpose: Literal["CONTROLLED_LAUNCHER_AND_ENTITLEMENT_DIAGNOSTIC"] = (
        "CONTROLLED_LAUNCHER_AND_ENTITLEMENT_DIAGNOSTIC"
    )
    launcher_retained: Literal["ONE", "NONE", "MULTIPLE"] = "NONE"
    candidate_selection: CandidateSelection = "NOT_RECORDED"
    candidate_ring_evicted: bool | None = None
    launcher_linkage: Check = "INCONCLUSIVE"
    launcher_fork_linkage: Literal["RETAINED_MATCH", "NOT_RETAINED", "MULTIPLE", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    launcher_shape_excluding_entitlements: Check = "INCONCLUSIVE"
    probe_shape_excluding_entitlements: Check = "INCONCLUSIVE"
    probe_entitlements: EntitlementShape = Field(default_factory=EntitlementShape)
    launcher_entitlements: EntitlementShape = Field(default_factory=EntitlementShape)
    launcher_before_image: Literal["LAUNCHD", "XPCPROXY", "OTHER", "NOT_OBSERVED"] = "NOT_OBSERVED"
    launcher_signing_identifier: Literal["EXPECTED_XPCPROXY", "OTHER", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    launcher_modeled_security_agreement: Check = "INCONCLUSIVE"
    launcher_posix_credentials: Literal["ROOT", "APP_USER", "OTHER", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    launcher_argv: Literal["TARGET_ONLY", "TARGET_AND_ARGUMENTS", "OTHER", "NOT_OBSERVED"] = (
        "NOT_OBSERVED"
    )
    launcher_fds_only_standard: Check = "INCONCLUSIVE"
    launcher_fds_match_app: Check = "INCONCLUSIVE"
    launcher_environment_to_app: EnvironmentDifference | None = None
    launcher_launch: ExistingLaunchFacts | None = None


class CaseReport(Model):
    """Fixed labels only. No native identifiers, strings, counts or fragments."""

    native_shapes: Check = "INCONCLUSIVE"
    one_exec_and_exit: Check = "INCONCLUSIVE"
    fork_linkage: Check = "INCONCLUSIVE"
    own_identity_agreement: Check = "INCONCLUSIVE"
    image_identity_agreement: Check = "INCONCLUSIVE"
    exec_identity_transition: Check = "INCONCLUSIVE"
    audit_identity_agreement: Check = "INCONCLUSIVE"
    parent_agreement: Check = "INCONCLUSIVE"
    original_parent: Literal["SAME_AS_PARENT", "DIFFERENT", "INCONCLUSIVE"] = "INCONCLUSIVE"
    responsible_identity: Role = "INCONCLUSIVE"
    parent_image_role: ImageRole = "NOT_OBSERVED"
    responsible_image_role: ImageRole = "NOT_OBSERVED"
    posix_session_agreement: Check = "INCONCLUSIVE"
    descriptor_inventory_agreement: Check = "INCONCLUSIVE"
    stdio_kinds: tuple[Kind, Kind, Kind] = ("INCONCLUSIVE",) * 3
    stdio_access: tuple[Access, Access, Access] = ("INCONCLUSIVE",) * 3
    tty_streams: Literal["ALL", "NONE", "MIXED", "INCONCLUSIVE"] = "INCONCLUSIVE"
    argument_vector_agreement: Check = "INCONCLUSIVE"
    environment_vector_agreement: Check = "INCONCLUSIVE"
    test_completion: Check = "INCONCLUSIVE"
    exit_status_agreement: Check = "INCONCLUSIVE"


class Report(Model):
    kit_version: Annotated[int, Field(strict=True, ge=1, le=2)] = 1
    synthetic_entitlement: bool | None = None
    purpose: Literal["GUI_LAUNCH_RELATIONSHIP_DIAGNOSTIC"] = "GUI_LAUNCH_RELATIONSHIP_DIAGNOSTIC"
    collection: Literal["CONTROLLED_TEST_APP_ONLY", "CONTROLLED_TEST_APP_AND_LINKED_LAUNCHER"] = (
        "CONTROLLED_TEST_APP_ONLY"
    )
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Code = "NONE"
    stage: Stage = "ERROR"
    context: Literal["NOT_ATTESTED", "HUMAN_ATTESTED_FINDER"] = "NOT_ATTESTED"
    target_platform: Check = "INCONCLUSIVE"
    provenance: Check = "INCONCLUSIVE"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"
    wire_profile: Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    control: CaseReport = Field(default_factory=CaseReport)
    finder: CaseReport = Field(default_factory=CaseReport)
    unified_log: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    other_launch_methods: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    launch_chain: LaunchChainDiagnostic | None = None


class EnvironmentDifference(Model):
    """Relationship labels only: never names, values, counts, lengths or hashes."""

    vectors_well_formed: Check = "INCONCLUSIVE"
    comparison: Literal[
        "IDENTICAL",
        "ORDER_ONLY",
        "MAIN_ADDITIONS_ONLY",
        "MAIN_REMOVALS_ONLY",
        "COMMON_VALUES_CHANGED",
        "MIXED",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    duplicate_key_structure: Literal["SAME", "DIFFERENT", "INCONCLUSIVE"] = "INCONCLUSIVE"
    cf_text_encoding: Literal[
        "UNCHANGED",
        "ADDED_AT_MAIN",
        "REMOVED_AT_MAIN",
        "VALUE_CHANGED",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    only_cf_text_encoding_differs: Check = "INCONCLUSIVE"
    controlled_initial_vector: Check = "INCONCLUSIVE"


TokenRelation = Literal["BOTH", "BEFORE", "TARGET", "ZERO", "MAX_WORD", "OTHER", "INCONCLUSIVE"]
TokenPosition = Literal[
    "BOTH", "BEFORE", "TARGET", "LESS_THAN_BOTH", "GREATER_THAN_BOTH", "BETWEEN", "INCONCLUSIVE"
]


class AuditTokenFieldRelations(Model):
    """Predefined field comparisons only; no token numbers or native keys are exported."""

    audit_user: TokenRelation = "INCONCLUSIVE"
    effective_user: TokenRelation = "INCONCLUSIVE"
    effective_group: TokenRelation = "INCONCLUSIVE"
    real_user: TokenRelation = "INCONCLUSIVE"
    real_group: TokenRelation = "INCONCLUSIVE"
    pid: TokenRelation = "INCONCLUSIVE"
    audit_session: TokenRelation = "INCONCLUSIVE"
    pid_version: TokenRelation = "INCONCLUSIVE"
    same_pid_version_position: TokenPosition = "INCONCLUSIVE"


class ExistingLaunchFacts(Model):
    """Existing native relationship classes needed for birth/exec planning, never values."""

    before_image_role: Literal["TEST_APP", "LAUNCHD", "XPCPROXY", "OTHER", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    before_audit_user: Literal[
        "UNATTRIBUTED_SENTINEL",
        "ROOT_USER",
        "REAL_USER",
        "TARGET_AUDIT_USER",
        "OTHER",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    before_audit_session: Literal["DEFAULT_ZERO", "TARGET_SESSION", "OTHER", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    before_responsibility: Literal[
        "SELF",
        "PARENT",
        "TARGET_EXECUTION",
        "SAME_PID_OTHER_IDENTITY",
        "OTHER",
        "UNSET",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    before_responsibility_fields: AuditTokenFieldRelations = Field(
        default_factory=AuditTokenFieldRelations
    )
    target_responsibility_fields: AuditTokenFieldRelations = Field(
        default_factory=AuditTokenFieldRelations
    )
    before_session_identity: Literal[
        "PROCESS_LEADER", "PARENT_PID", "ZERO", "OTHER", "INCONCLUSIVE"
    ] = "INCONCLUSIVE"
    before_group_identity: Literal[
        "PROCESS_LEADER", "PARENT_PID", "ZERO", "OTHER", "INCONCLUSIVE"
    ] = "INCONCLUSIVE"
    target_audit_user_is_real_user: Check = "INCONCLUSIVE"
    before_target_file_object: Check = "INCONCLUSIVE"
    before_target_signature: Check = "INCONCLUSIVE"
    signature_matches_control: Check = "INCONCLUSIVE"
    parent_is_boot_pid: Check = "INCONCLUSIVE"
    audit_origin_preserved: Check = "INCONCLUSIVE"
    posix_credentials_preserved: Check = "INCONCLUSIVE"
    parentage_preserved: Check = "INCONCLUSIVE"
    session_identity: Literal["PROCESS_LEADER", "PARENT_PID", "ZERO", "OTHER", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    group_identity: Literal["PROCESS_LEADER", "PARENT_PID", "ZERO", "OTHER", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    posix_membership_preserved: Check = "INCONCLUSIVE"
    controlling_terminal_before: Literal["ABSENT", "PRESENT", "INCONCLUSIVE"] = "INCONCLUSIVE"
    controlling_terminal_target: Literal["ABSENT", "PRESENT", "INCONCLUSIVE"] = "INCONCLUSIVE"
    only_standard_descriptors: Check = "INCONCLUSIVE"
    native_last_fd_standard: Check = "INCONCLUSIVE"
    working_directory: Literal["ROOT", "DECLARED_HOME", "OTHER", "INCONCLUSIVE"] = "INCONCLUSIVE"
    working_directory_untruncated: Check = "INCONCLUSIVE"
    script_absent: Check = "INCONCLUSIVE"
    native_slice: Literal["ARM64_GENERIC", "ARM64_OTHER", "OTHER", "INCONCLUSIVE"] = "INCONCLUSIVE"
    entitlements: Literal["NULL", "OTHER", "INCONCLUSIVE"] = "INCONCLUSIVE"
    dyld_path_matches_target: Check = "INCONCLUSIVE"


class ExistingReviewReport(Model):
    """Offline-only supplemental diagnostic for an unchanged original private kit."""

    review_version: Annotated[int, Field(strict=True, ge=5, le=5)] = 5
    purpose: Literal["GUI_ENVIRONMENT_AND_FORK_DIAGNOSTIC"] = "GUI_ENVIRONMENT_AND_FORK_DIAGNOSTIC"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    error: Code = "NONE"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    provenance: Check = "INCONCLUSIVE"
    original_collection_controls: Check = "INCONCLUSIVE"
    control_environment: EnvironmentDifference = Field(default_factory=EnvironmentDifference)
    finder_environment: EnvironmentDifference = Field(default_factory=EnvironmentDifference)
    control_launch: ExistingLaunchFacts = Field(default_factory=ExistingLaunchFacts)
    finder_launch: ExistingLaunchFacts = Field(default_factory=ExistingLaunchFacts)
    finder_preimage_birth: Literal[
        "BEFORE_CONTROL_BIRTH",
        "BETWEEN_CONTROL_BIRTH_AND_EXIT",
        "AFTER_CONTROL_EXIT",
        "INCONCLUSIVE",
    ] = "INCONCLUSIVE"
    launch_chain: LaunchChainDiagnostic | None = None
    control_fork: Literal["RETAINED_MATCH", "NOT_RETAINED", "INCONSISTENT", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    finder_fork: Literal["RETAINED_MATCH", "NOT_RETAINED", "INCONSISTENT", "INCONCLUSIVE"] = (
        "INCONCLUSIVE"
    )
    fork_absence_proves_no_fork: Literal["NO"] = "NO"
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    apps: Literal["NOT_LAUNCHED"] = "NOT_LAUNCHED"
    live_role_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"


LaunchChainDiagnostic.model_rebuild()
Report.model_rebuild()


def entitlement_shape(value: object, *, present: bool = True) -> EntitlementShape:
    """Classify only the controlled marker, never arbitrary entitlement keys/values."""
    if not present:
        return EntitlementShape(representation="ABSENT")
    representation = "NULL" if value is None else "OBJECT" if type(value) is dict else "OTHER"
    if type(value) is str:
        representation = "STRING_OTHER"
        try:
            decoded = _decode(value.encode())
        except PrivateError:
            try:
                decoded = plistlib.loads(value.encode())
            except (ValueError, TypeError, plistlib.InvalidFileException):
                decoded = None
            if type(decoded) is dict:
                representation = "STRING_PLIST_OBJECT"
        else:
            representation = "STRING_JSON_OBJECT"
        value = decoded
    if type(value) is not dict:
        return EntitlementShape(representation=representation, marker="ABSENT")
    marker = value.get(ENTITLEMENT_MARKER)
    return EntitlementShape(
        representation=representation,
        marker="BOOLEAN_TRUE"
        if marker is True
        else "INTEGER_ONE"
        if type(marker) is int and marker == 1
        else "ABSENT"
        if ENTITLEMENT_MARKER not in value
        else "OTHER",
        only_controlled_marker=_check(set(value) == {ENTITLEMENT_MARKER}),
    )


def _shape_without_entitlements(row: dict) -> Check:
    """Diagnostic isolation only; deliberately not a source admission predicate."""
    candidate = deepcopy(row)
    payload = candidate.get("event", {}).get("exec", {})
    if "entitlements" in payload:
        payload["entitlements"] = None
    try:
        decode_endpoint_security_record(json.dumps(candidate))
    except (ValueError, TypeError, ValidationError):
        return "FAIL"
    return "PASS"


def _same_loaded_image(left: dict, right: dict) -> bool:
    """Match the linked launcher's native file object and code identity in memory."""
    lstat, rstat = left["executable"]["stat"], right["executable"]["stat"]
    return all(lstat[key] == rstat[key] for key in ("st_dev", "st_ino")) and all(
        left.get(key) == right.get(key) for key in ("cdhash", "signing_id", "team_id")
    )


def analyze_launch_chain(raws: list[bytes], image: Image) -> LaunchChainDiagnostic:
    """Inspect only already-retained controlled-chain rows, exporting fixed labels."""
    rows = [_decode(raw) for raw in raws]
    apps = [
        row
        for row in rows
        if row.get("event_type") == 9 and _owned(row["event"]["exec"]["target"], image)
    ]
    if len(apps) != 1:
        return LaunchChainDiagnostic()
    app = apps[0]
    app_exec, app_before = app["event"]["exec"], app["process"]
    launchers = [
        row
        for row in rows
        if row.get("event_type") == 9
        and row is not app
        and row["event"]["exec"]["target"]["executable"]["path"] == "/usr/libexec/xpcproxy"
    ]
    values: dict = {
        "launcher_retained": "ONE" if len(launchers) == 1 else "MULTIPLE" if launchers else "NONE",
        "probe_shape_excluding_entitlements": _shape_without_entitlements(app),
        "probe_entitlements": entitlement_shape(
            app_exec.get("entitlements"), present="entitlements" in app_exec
        ),
    }
    if len(launchers) != 1:
        return LaunchChainDiagnostic(**values)
    launcher = launchers[0]
    values["launcher_shape_excluding_entitlements"] = _shape_without_entitlements(launcher)
    if (
        values["launcher_shape_excluding_entitlements"] != "PASS"
        or values["probe_shape_excluding_entitlements"] != "PASS"
    ):
        return LaunchChainDiagnostic(**values)
    payload, before = launcher["event"]["exec"], launcher["process"]
    target = payload["target"]
    linked = (
        _identity(target) == _identity(app_before)
        and _token(target) == _token(app_before)
        and _same_loaded_image(target, app_before)
    )
    forks = [
        row
        for row in rows
        if row.get("event_type") == 11
        and _identity(row["event"]["fork"]["child"]) == _identity(before)
        and _token(row["event"]["fork"]["child"]) == _token(before)
    ]
    argv = payload.get("args")
    fds = payload.get("fds")
    token, app_token = _token(target), _token(app_before)
    values.update(
        launcher_linkage=_check(linked),
        launcher_fork_linkage="RETAINED_MATCH"
        if len(forks) == 1
        else "MULTIPLE"
        if forks
        else "NOT_RETAINED",
        launcher_shape_excluding_entitlements=_shape_without_entitlements(launcher),
        launcher_entitlements=entitlement_shape(
            payload.get("entitlements"), present="entitlements" in payload
        ),
        launcher_modeled_security_agreement=_check(
            target.get("codesigning_flags") == 0x24000001
            and target.get("is_platform_binary") is True
            and target.get("cs_validation_category") == 1
        ),
        launcher_before_image="LAUNCHD"
        if before["executable"]["path"] == "/sbin/launchd"
        else "XPCPROXY"
        if before["executable"]["path"] == "/usr/libexec/xpcproxy"
        else "OTHER",
        launcher_signing_identifier="EXPECTED_XPCPROXY"
        if target.get("signing_id") == "com.apple.xpcproxy"
        else "OTHER",
        launcher_posix_credentials="ROOT"
        if all(token[index] == 0 for index in (1, 2, 3, 4))
        else "APP_USER"
        if all(token[index] == app_token[index] for index in (1, 2, 3, 4))
        else "OTHER",
        launcher_argv="TARGET_ONLY"
        if argv == ["/usr/libexec/xpcproxy"]
        else "TARGET_AND_ARGUMENTS"
        if type(argv) is list and argv and argv[0] == "/usr/libexec/xpcproxy"
        else "OTHER",
        launcher_fds_only_standard=_check(
            type(fds) is list
            and {fd.get("fd") for fd in fds if type(fd) is dict} == {0, 1, 2}
            and len(fds) == 3
        ),
        launcher_fds_match_app=_check(
            fds == app_exec.get("fds") and payload.get("last_fd") == app_exec.get("last_fd")
        ),
        launcher_environment_to_app=compare_environment(
            tuple(item.encode() for item in payload["env"]),
            tuple(item.encode() for item in app_exec["env"]),
        ),
        launcher_launch=inspect_existing_launch(before, payload, image),
    )
    return LaunchChainDiagnostic(**values)


def _preserve_candidate_selection(
    analyzed: LaunchChainDiagnostic, recorded: LaunchChainDiagnostic | None
) -> LaunchChainDiagnostic:
    """Preserve fixed capture-time labels; discarded candidates cannot be reconstructed."""
    if recorded is None:
        return analyzed
    return analyzed.model_copy(
        update={
            "candidate_selection": recorded.candidate_selection,
            "candidate_ring_evicted": recorded.candidate_ring_evicted,
        }
    )


def compare_environment(
    native: tuple[bytes, ...], main: tuple[bytes, ...], *, controlled: bool = False
) -> EnvironmentDifference:
    """Compare private vectors without returning their data or arbitrary key names."""
    maps: list[dict[bytes, list[bytes]]] = []
    for vector in (native, main):
        grouped: dict[bytes, list[bytes]] = {}
        for entry in vector:
            if type(entry) is not bytes or b"\0" in entry or b"=" not in entry:
                return EnvironmentDifference(vectors_well_formed="FAIL")
            key, value = entry.split(b"=", 1)
            if not key:
                return EnvironmentDifference(vectors_well_formed="FAIL")
            grouped.setdefault(key, []).append(value)
        maps.append(grouped)
    before, after = maps
    added, removed = after.keys() - before.keys(), before.keys() - after.keys()
    changed = {
        key for key in before.keys() & after.keys() if Counter(before[key]) != Counter(after[key])
    }
    if native == main:
        comparison = "IDENTICAL"
    elif Counter(native) == Counter(main):
        comparison = "ORDER_ONLY"
    elif added and not removed and not changed:
        comparison = "MAIN_ADDITIONS_ONLY"
    elif removed and not added and not changed:
        comparison = "MAIN_REMOVALS_ONLY"
    elif changed and not added and not removed:
        comparison = "COMMON_VALUES_CHANGED"
    else:
        comparison = "MIXED"
    key = b"__CF_USER_TEXT_ENCODING"
    cf_change = (
        "UNCHANGED"
        if Counter(before.get(key, ())) == Counter(after.get(key, ()))
        else "ADDED_AT_MAIN"
        if key not in before
        else "REMOVED_AT_MAIN"
        if key not in after
        else "VALUE_CHANGED"
    )
    return EnvironmentDifference(
        vectors_well_formed="PASS",
        comparison=comparison,
        duplicate_key_structure="SAME"
        if {k: len(v) for k, v in before.items() if len(v) > 1}
        == {k: len(v) for k, v in after.items() if len(v) > 1}
        else "DIFFERENT",
        cf_text_encoding=cf_change,
        only_cf_text_encoding_differs=_check(added | removed | changed == {key}),
        controlled_initial_vector=_check(
            Counter(native) == Counter(f"{k}={v}".encode() for k, v in SAFE_ENV.items())
        )
        if controlled
        else "INCONCLUSIVE",
    )


def _signature(process: dict) -> tuple:
    return tuple(
        process[key]
        for key in (
            "codesigning_flags",
            "is_platform_binary",
            "cs_validation_category",
            "signing_id",
            "team_id",
            "cdhash",
        )
    )


def compare_responsible_token_fields(
    responsible: tuple[int, ...], before: tuple[int, ...], target: tuple[int, ...]
) -> AuditTokenFieldRelations:
    """Explain an otherwise ambiguous same-PID token without sharing any identifiers.

    Numeric position is classified only for a token with the controlled process PID.
    It makes no assertion about execution chronology, counter wrapping or sampling cause.
    """
    for token in (responsible, before, target):
        if len(token) != 8 or any(
            type(value) is not int or not 0 <= value < 2**32 for value in token
        ):
            raise ValueError("Token comparison requires eight validated unsigned words")
    fields = (
        "audit_user",
        "effective_user",
        "effective_group",
        "real_user",
        "real_group",
        "pid",
        "audit_session",
        "pid_version",
    )
    relations: dict[str, str] = {}
    for field, value, old, new in zip(fields, responsible, before, target, strict=True):
        relations[field] = (
            "BOTH"
            if value == old == new
            else "BEFORE"
            if value == old
            else "TARGET"
            if value == new
            else "ZERO"
            if value == 0
            else "MAX_WORD"
            if value == 2**32 - 1
            else "OTHER"
        )
    if responsible[5] == before[5] == target[5]:
        value, old, new = responsible[7], before[7], target[7]
        relations["same_pid_version_position"] = (
            "BOTH"
            if value == old == new
            else "BEFORE"
            if value == old
            else "TARGET"
            if value == new
            else "LESS_THAN_BOTH"
            if value < min(old, new)
            else "GREATER_THAN_BOTH"
            if value > max(old, new)
            else "BETWEEN"
        )
    return AuditTokenFieldRelations.model_validate(relations)


def inspect_existing_launch(
    before: dict, payload: dict, image: Image, *, control_signature: tuple | None = None
) -> ExistingLaunchFacts:
    """Classify already validated private v11 data without names, IDs, flags or paths."""
    target = payload["target"]
    pid = _token(target)[5]

    def membership(value: int, ppid: int) -> str:
        return (
            "ZERO"
            if value == 0
            else "PROCESS_LEADER"
            if value == pid
            else "PARENT_PID"
            if value == ppid
            else "OTHER"
        )

    old_file, new_file = before["executable"]["stat"], target["executable"]["stat"]
    old_token, new_token = _token(before), _token(target)
    responsible, parent = (
        _token(before, "responsible_audit_token"),
        _token(before, "parent_audit_token"),
    )
    homes = [entry.split("=", 1)[1] for entry in payload["env"] if entry.startswith("HOME=")]
    cwd = payload["cwd"]["path"]
    return ExistingLaunchFacts(
        before_audit_user=(
            "UNATTRIBUTED_SENTINEL"
            if old_token[0] == 2**32 - 1
            else "ROOT_USER"
            if old_token[0] == 0
            else "REAL_USER"
            if old_token[0] == old_token[3]
            else "TARGET_AUDIT_USER"
            if old_token[0] == new_token[0]
            else "OTHER"
        ),
        before_audit_session=(
            "DEFAULT_ZERO"
            if old_token[6] == 0
            else "TARGET_SESSION"
            if old_token[6] == new_token[6]
            else "OTHER"
        ),
        before_responsibility=(
            "UNSET"
            if not any(responsible)
            else "SELF"
            if responsible == old_token
            else "PARENT"
            if responsible == parent
            else "TARGET_EXECUTION"
            if responsible == new_token
            else "SAME_PID_OTHER_IDENTITY"
            if responsible[5] == old_token[5]
            else "OTHER"
        ),
        before_responsibility_fields=compare_responsible_token_fields(
            responsible, old_token, new_token
        ),
        target_responsibility_fields=compare_responsible_token_fields(
            _token(target, "responsible_audit_token"), old_token, new_token
        ),
        before_session_identity=membership(before["session_id"], before["ppid"]),
        before_group_identity=membership(before["group_id"], before["ppid"]),
        target_audit_user_is_real_user=_check(new_token[0] == new_token[3]),
        before_image_role=(
            "TEST_APP"
            if _owned(before, image)
            else "LAUNCHD"
            if before["executable"]["path"] == "/sbin/launchd"
            and before["executable"]["path_truncated"] is False
            else "XPCPROXY"
            if before["executable"]["path"] == "/usr/libexec/xpcproxy"
            and before["executable"]["path_truncated"] is False
            else "OTHER"
        ),
        before_target_file_object=_check(
            (old_file["st_dev"], old_file["st_ino"]) == (new_file["st_dev"], new_file["st_ino"])
        ),
        before_target_signature=_check(_signature(before) == _signature(target)),
        signature_matches_control=_check(_signature(target) == control_signature)
        if control_signature is not None
        else "INCONCLUSIVE",
        parent_is_boot_pid=_check(
            target["ppid"] == 1 and _token(target, "parent_audit_token")[5] == 1
        ),
        audit_origin_preserved=_check(
            (_token(before)[0], _token(before)[6]) == (_token(target)[0], _token(target)[6])
        ),
        posix_credentials_preserved=_check(_token(before)[1:5] == _token(target)[1:5]),
        parentage_preserved=_check(
            (before["ppid"], before["original_ppid"]) == (target["ppid"], target["original_ppid"])
            and _token(before, "parent_audit_token") == _token(target, "parent_audit_token")
        ),
        session_identity=membership(target["session_id"], target["ppid"]),
        group_identity=membership(target["group_id"], target["ppid"]),
        posix_membership_preserved=_check(
            (before["session_id"], before["group_id"]) == (target["session_id"], target["group_id"])
        ),
        controlling_terminal_before="ABSENT" if before["tty"] is None else "PRESENT",
        controlling_terminal_target="ABSENT" if target["tty"] is None else "PRESENT",
        only_standard_descriptors=_check(
            len(payload["fds"]) == 3 and {fd["fd"] for fd in payload["fds"]} == {0, 1, 2}
        ),
        native_last_fd_standard=_check(payload["last_fd"] == 2),
        working_directory="INCONCLUSIVE"
        if payload["cwd"]["path_truncated"]
        else "ROOT"
        if cwd == "/"
        else "DECLARED_HOME"
        if len(homes) == 1 and cwd == homes[0]
        else "OTHER",
        working_directory_untruncated=_check(payload["cwd"]["path_truncated"] is False),
        script_absent=_check(payload["script"] is None),
        native_slice="OTHER"
        if payload["image_cputype"] != 16777228
        else "ARM64_GENERIC"
        if payload["image_cpusubtype"] == 0
        else "ARM64_OTHER",
        entitlements="NULL" if payload["entitlements"] is None else "OTHER",
        dyld_path_matches_target=_check(
            payload["dyld_exec_path"] == target["executable"]["path"]
            and target["executable"]["path_truncated"] is False
        ),
    )


def _check(value: bool) -> Check:
    return "PASS" if value else "FAIL"


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise PrivateError("DATA")
        result[key] = value
    return result


def _constant(_value: str) -> None:
    raise PrivateError("DATA")


def _decode(raw: bytes) -> dict:
    if len(raw) > MAX_LINE:
        raise PrivateError("LIMIT")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise PrivateError("DATA") from error
    if type(value) is not dict:
        raise PrivateError("DATA")
    return value


def _token(process: dict, field: str = "audit_token") -> tuple[int, ...]:
    value = process.get(field)
    if type(value) is not dict or set(value) != {
        "auid",
        "euid",
        "egid",
        "ruid",
        "rgid",
        "pid",
        "asid",
        "pidversion",
    }:
        raise PrivateError("DATA")
    words = tuple(
        value[key] for key in ("auid", "euid", "egid", "ruid", "rgid", "pid", "asid", "pidversion")
    )
    if any(type(word) is not int or not 0 <= word < 2**32 for word in words):
        raise PrivateError("DATA")
    return words


def _timestamp_microseconds(value: object) -> int:
    """Compare validated timestamps locally without exporting values or durations."""
    if type(value) is not str or len(value) > 64:
        raise PrivateError("DATA")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise PrivateError("DATA")
    parsed = parsed.astimezone(UTC)
    return calendar.timegm(parsed.utctimetuple()) * 1_000_000 + parsed.microsecond


def _birth(process: dict) -> int:
    return _timestamp_microseconds(process.get("start_time"))


def _identity(process: dict) -> tuple[int, int, int]:
    token = _token(process)
    return token[5], token[7], _birth(process)


def _owned(process: dict, image: Image) -> bool:
    executable = process.get("executable", {})
    metadata = executable.get("stat", {}) if type(executable) is dict else {}
    return (
        type(metadata) is dict
        and type(metadata.get("st_dev")) is int
        and type(metadata.get("st_ino")) is int
        and metadata["st_dev"] == image.device
        and metadata["st_ino"] == image.inode
    )


def _app_case_rows(raws: list[bytes], image: Image) -> list[bytes]:
    """Keep app-only labels separate from the explicitly reported launcher phases."""
    decoded = [(raw, _decode(raw)) for raw in raws]
    apps = [
        row
        for _, row in decoded
        if row.get("event_type") == 9 and _owned(row["event"]["exec"]["target"], image)
    ]
    if len(apps) != 1:
        return raws
    before, after = apps[0]["process"], apps[0]["event"]["exec"]["target"]
    return [
        raw
        for raw, row in decoded
        if (row.get("event_type") == 9 and row is apps[0])
        or (
            row.get("event_type") == 11
            and _identity(row["event"]["fork"]["child"]) == _identity(before)
        )
        or (row.get("event_type") == 15 and _identity(row["process"]) == _identity(after))
    ]


class Tracker:
    """Filter in memory; persist forks only after an exact owned exec proves linkage."""

    def __init__(self, image: Image, *, launch_chain: bool = False) -> None:
        self.image = image
        self.launch_chain = launch_chain
        self.launchers: deque[tuple[bytes, dict]] = deque()
        self.launcher_bytes = 0
        self.launcher_selection: CandidateSelection = "NOT_RECORDED"
        self.launcher_ring_evicted = False
        self.phase: Literal["ready", "control", "finder"] = "ready"
        self.ready_pids: set[int] = set()
        self.ready_ids: set[tuple[int, int, int]] = set()
        self.ready = False
        self.records: dict[Case, list[bytes]] = {"control": [], "finder": []}
        self.live: dict[tuple[int, int, int], Case] = {}
        self.forks: deque[tuple[bytes, tuple[int, int, int]]] = deque()
        self.ring_bytes = 0
        self.total_bytes = 0
        self.sequence_ok = True
        self.sequence: dict[int, int] = {}
        self.global_sequence = -1

    def accept(self, raw: bytes) -> list[tuple[Case, bytes]]:
        """Return only authenticated app-family rows; no PID/path-only admission."""
        self.total_bytes += len(raw)
        if self.total_bytes > MAX_STREAM:
            raise PrivateError("LIMIT")
        row = _decode(raw)
        kind, sequence, global_sequence = (
            row.get("event_type"),
            row.get("seq_num"),
            row.get("global_seq_num"),
        )
        if (
            type(kind) is not int
            or kind not in (9, 11, 15)
            or any(type(value) is not int or value < 0 for value in (sequence, global_sequence))
        ):
            raise PrivateError("DATA")
        if (
            kind in self.sequence and sequence != self.sequence[kind] + 1
        ) or global_sequence <= self.global_sequence:
            self.sequence_ok = False
        self.sequence[kind], self.global_sequence = sequence, global_sequence
        process, event = row.get("process"), row.get("event")
        if type(process) is not dict or type(event) is not dict:
            return []
        try:
            if kind == 11:
                child = event.get("fork", {}).get("child", {})
                identity = _identity(child)
                self.forks.append((raw, identity))
                self.ring_bytes += len(raw)
                while len(self.forks) > 64 or self.ring_bytes > MAX_RING_BYTES:
                    removed, _ = self.forks.popleft()
                    self.ring_bytes -= len(removed)
                return []
            if kind == 9:
                payload = event.get("exec", {})
                target = payload.get("target", {})
                identity = _identity(target)
                if (
                    self.launch_chain
                    and target.get("executable", {}).get("path") == "/usr/libexec/xpcproxy"
                ):
                    self.launchers.append((raw, target))
                    self.launcher_bytes += len(raw)
                    while len(self.launchers) > 64 or self.launcher_bytes > MAX_RING_BYTES:
                        removed, _ = self.launchers.popleft()
                        self.launcher_bytes -= len(removed)
                        self.launcher_ring_evicted = True
                    return []
                if not _owned(target, self.image):
                    return []
                readiness = payload.get("args", [])[1:] == ["--ready"]
                if payload.get("args", [])[1:] == ["--classify"]:
                    return []
                if self.phase == "ready":
                    if readiness and identity[0] in self.ready_pids:
                        self.ready_ids.add(identity)
                    return []
                if readiness:
                    return []
                case = self.phase
                before = _identity(process)
                if identity[0] != before[0] or identity[2] != before[2]:
                    raise PrivateError("DATA")
                self.live[identity] = case
                linked = [(case, data) for data, child_id in self.forks if child_id == before]
                if self.launch_chain and case == "finder":
                    progress = 1 if self.launchers else 0
                    for data, launcher in self.launchers:
                        try:
                            if _identity(launcher) != before:
                                continue
                            progress = max(progress, 2)
                            if _token(launcher) != _token(process):
                                continue
                            progress = max(progress, 3)
                            if not _same_loaded_image(launcher, process):
                                continue
                        except (AttributeError, TypeError, ValueError, KeyError):
                            continue
                        launcher_before = _decode(data)["process"]
                        linked.extend(
                            (case, fork_raw)
                            for fork_raw, child_id in self.forks
                            if child_id == _identity(launcher_before)
                            and _token(_decode(fork_raw)["event"]["fork"]["child"])
                            == _token(launcher_before)
                        )
                        linked.append((case, data))
                        progress = 4
                    self.launcher_selection = (
                        "NO_CANDIDATES",
                        "NO_EXECUTION_MATCH",
                        "TOKEN_MISMATCH",
                        "IMAGE_MISMATCH",
                        "MATCHED",
                    )[progress]
                    linked = list(dict.fromkeys(linked))
                    linked.sort(key=lambda item: _decode(item[1])["global_seq_num"])
                rows = [*linked, (case, raw)]
            else:
                identity = _identity(process)
                if (
                    self.phase == "ready"
                    and identity in self.ready_ids
                    and _owned(process, self.image)
                    and type(event.get("exit", {}).get("stat")) is int
                    and event["exit"]["stat"] == 0
                ):
                    self.ready = True
                    return []
                case = self.live.get(identity)
                if case is None or not _owned(process, self.image):
                    return []
                rows = [(case, raw)]
        except (AttributeError, TypeError, ValueError, KeyError):
            # Ambient unknown shapes never become persisted evidence.
            return []
        for case, data in rows:
            if len(self.records[case]) >= MAX_RETAINED:
                raise PrivateError("LIMIT")
            self.records[case].append(data)
        return rows

    def launch_chain_report(self) -> LaunchChainDiagnostic:
        """Export only fixed matching outcomes, never unretained candidate contents."""
        return analyze_launch_chain(self.records["finder"], self.image).model_copy(
            update={
                "candidate_selection": self.launcher_selection,
                "candidate_ring_evicted": self.launcher_ring_evicted,
            }
        )


def analyze_case(
    raws: list[bytes],
    own: OwnSnapshot | None,
    completed: bool,
    image: Image | None = None,
    *,
    launch_chain: bool = False,
) -> CaseReport:
    """Offline fixed-label diagnostics. Unexpected shapes cannot silently qualify."""
    if launch_chain and image is not None:
        raws = _app_case_rows(raws, image)
    if not raws or own is None:
        return CaseReport(test_completion=_check(completed))
    rows = [_decode(raw) for raw in raws]
    valid = True
    for raw in raws:
        try:
            decode_endpoint_security_record(raw.decode("utf-8"))
        except (ValueError, TypeError, ValidationError):
            valid = False
    execs = [r for r in rows if r["event_type"] == 9]
    exits = [r for r in rows if r["event_type"] == 15]
    if len(execs) != 1 or len(exits) != 1:
        return CaseReport(
            native_shapes=_check(valid), one_exec_and_exit="FAIL", test_completion=_check(completed)
        )
    payload = execs[0]["event"]["exec"]
    target, before = payload["target"], execs[0]["process"]
    token = _token(target)
    parent, responsible = (
        _token(target, "parent_audit_token"),
        _token(target, "responsible_audit_token"),
    )
    exact = (
        token == own.token
        and _birth(target) == own.start_seconds * 1_000_000 + own.start_microseconds
    )
    forks = [r for r in rows if r["event_type"] == 11]
    fork_match = len(forks) == 1 and _identity(forks[0]["event"]["fork"]["child"]) == _identity(
        before
    )
    descriptors = {fd.fd: fd for fd in own.fds}
    inventory = len(descriptors) == len(own.fds) and own.inventory_complete
    native_fds = {fd["fd"]: fd["fdtype"] for fd in payload.get("fds", [])}
    stdio_kinds = tuple(
        {1: "VNODE", 6: "PIPE", 2: "SOCKET"}.get(descriptors[fd].kind, "OTHER")
        if fd in descriptors
        else "CLOSED"
        for fd in range(3)
    )
    stdio_access = tuple(
        {0: "READ", 1: "WRITE", 2: "READ_WRITE"}.get(descriptors[fd].access, "OTHER")
        if fd in descriptors
        else "CLOSED"
        for fd in range(3)
    )
    tty = [fd.tty for fd in own.fds if fd.fd in (0, 1, 2)]
    role: Role = (
        "UNSET"
        if not any(responsible)
        else "SELF"
        if responsible == token
        else "PARENT"
        if responsible == parent
        else "OTHER"
    )
    return CaseReport(
        native_shapes=_check(valid),
        one_exec_and_exit="PASS",
        fork_linkage="PASS" if fork_match else "FAIL" if forks else "INCONCLUSIVE",
        own_identity_agreement=_check(exact),
        image_identity_agreement=_check(_owned(target, image))
        if image is not None
        else "INCONCLUSIVE",
        exec_identity_transition=_check(
            _identity(before)[0] == _identity(target)[0]
            and _identity(before)[2] == _identity(target)[2]
            and _identity(before)[1] != _identity(target)[1]
        ),
        audit_identity_agreement=_check(token[:5] == own.token[:5] and token[6] == own.token[6]),
        parent_agreement=_check(target["ppid"] == own.ppid and parent[5] == own.ppid),
        original_parent="SAME_AS_PARENT"
        if target["original_ppid"] == target["ppid"]
        else "DIFFERENT",
        responsible_identity=role,
        posix_session_agreement=_check(
            target["session_id"] == own.sid and target["group_id"] == own.pgid
        ),
        descriptor_inventory_agreement=_check(
            inventory
            and len(native_fds) == len(payload.get("fds", []))
            and native_fds == {fd.fd: fd.kind for fd in own.fds}
        ),
        stdio_kinds=stdio_kinds,
        stdio_access=stdio_access,
        tty_streams="ALL" if len(tty) == 3 and all(tty) else "NONE" if not any(tty) else "MIXED",
        argument_vector_agreement=_check(
            tuple(s.encode().hex() for s in payload.get("args", [])) == own.arguments_hex
        ),
        environment_vector_agreement=_check(
            tuple(s.encode().hex() for s in payload.get("env", [])) == own.environment_hex
        ),
        test_completion=_check(completed),
        exit_status_agreement=_check(
            completed
            and exits[0]["event"]["exit"]["stat"] == 0
            and _identity(exits[0]["process"]) == _identity(target)
        ),
    )


def _wire_profile(raws: list[bytes]) -> Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"]:
    profiles: set[tuple[int, int]] = set()
    for raw in raws:
        row = _decode(raw)
        schema, version = row.get("schema_version"), row.get("version")
        if type(schema) is not int or type(version) is not int:
            return "UNQUALIFIED"
        profiles.add((schema, version))
    if not profiles:
        return "NOT_OBSERVED"
    return "MIXED" if len(profiles) > 1 else "V11" if profiles == {(1, 11)} else "UNQUALIFIED"


def _outside_git(path: Path) -> None:
    if any((parent / ".git").exists() for parent in (path, *path.parents)):
        raise PrivateError("LOCATION")


def _directory(path: Path) -> None:
    value = path.lstat()
    if (
        not stat.S_ISDIR(value.st_mode)
        or value.st_uid != os.getuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        raise PrivateError("LOCATION")


def _read(path: Path, limit: int = MAX_LINE) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        value = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.getuid()
            or value.st_nlink != 1
            or value.st_mode & 0o077
        ):
            raise PrivateError("LOCATION")
        result = stream.read(limit + 1)
    if len(result) > limit:
        raise PrivateError("LIMIT")
    return result


def _write(path: Path, raw: bytes) -> None:
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600),
        "wb",
    ) as stream:
        stream.write(raw)


def _replace(path: Path, raw: bytes) -> None:
    temporary = path.with_name(f".{path.name}-{uuid.uuid4().hex}")
    _write(temporary, raw)
    os.replace(temporary, path)


def _root() -> Path:
    root = Path(__file__).resolve().parent
    _outside_git(root)
    _directory(root)
    return root


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy code and instructions; never compile, collect or launch."""
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    _outside_git(parent)
    root = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-gui-launch-kit-", dir=parent))
    )
    if destination:
        root.mkdir(mode=0o700)
    else:
        root.chmod(0o700)
    for source, name in (
        (Path(__file__).resolve(), CODE[0]),
        *((SOURCES / name, name) for name in CODE[1:]),
        (SOURCES / "PRIVATE-RUN.md", "PRIVATE-RUN.md"),
        (SOURCES / "LAUNCH-CHAIN.md", "LAUNCH-CHAIN.md"),
    ):
        shutil.copyfile(source, root / name)
        (root / name).chmod(0o600)
    return root


def _preflight() -> tuple[str, str]:
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise PrivateError("ROOT_USER")
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise PrivateError("PLATFORM")
    values: list[str] = []
    for option in ("-productVersion", "-buildVersion"):
        result = subprocess.run(
            ["/usr/bin/sw_vers", option],
            env={**SAFE_ENV, "SYSTEM_VERSION_COMPAT": "0"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=True,
        )
        if len(result.stdout) > 128:
            raise PrivateError("PLATFORM")
        values.append(result.stdout.decode("ascii").strip())
    if not re.fullmatch(r"27(?:\.[0-9]+){0,2}", values[0]) or not re.fullmatch(
        r"[0-9A-Za-z]+", values[1]
    ):
        raise PrivateError("PLATFORM")
    return values[0], values[1]


def _command(args: list[str], root: Path) -> None:
    try:
        subprocess.run(
            args,
            cwd=root,
            env=SAFE_ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PrivateError("BUILD") from error


def _digest(path: Path) -> str:
    return hashlib.sha256(_read(path, 16 * MAX_LINE)).hexdigest()


def _executable(root: Path) -> Path:
    return root / "GUIProbe.app/Contents/MacOS/Probe"


def _image(path: Path) -> Image:
    info = path.lstat()
    return Image(device=info.st_dev, inode=info.st_ino, sha256=_digest(path))


def _codec_digest() -> str:
    return hashlib.sha256(
        Path(inspect.getfile(decode_endpoint_security_record)).read_bytes()
    ).hexdigest()


def setup(*, launch_chain: bool = False, synthetic_entitlement: bool = False) -> Report:
    """HUMAN ONLY: compile/sign the controlled app; launch nothing."""
    if synthetic_entitlement and not launch_chain:
        raise PrivateError("INPUT")
    root = _root()
    _preflight()
    app = root / "GUIProbe.app"
    app.mkdir(mode=0o700)
    (app / "Contents").mkdir(mode=0o700)
    (app / "Contents/MacOS").mkdir(mode=0o700)
    info = plistlib.dumps(
        {
            "CFBundleIdentifier": f"org.evidenceforge.reference.gui.{uuid.uuid4().hex}",
            "CFBundleName": "EvidenceForge GUI Reference",
            "CFBundleExecutable": "Probe",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
            "NSHighResolutionCapable": True,
        }
    )
    _write(app / "Contents/Info.plist", info)
    _command(
        [
            "/usr/bin/clang",
            "-fobjc-arc",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-framework",
            "Cocoa",
            str(root / CODE[1]),
            "-o",
            str(_executable(root)),
        ],
        root,
    )
    _executable(root).chmod(0o700)
    signing = ["/usr/bin/codesign", "--force", "--sign", "-"]
    if synthetic_entitlement:
        entitlements = root / "CONTROLLED-ENTITLEMENTS.plist"
        _write(entitlements, plistlib.dumps({ENTITLEMENT_MARKER: True}))
        signing.extend(["--entitlements", str(entitlements)])
    _command([*signing, str(app)], root)
    _command(["/usr/bin/codesign", "--verify", "--strict", str(app)], root)
    _command(
        [
            "/usr/bin/clang",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(root / CODE[2]),
            "-o",
            str(root / "collector-guard"),
        ],
        root,
    )
    (root / "collector-guard").chmod(0o700)
    manifest = Manifest(
        kit_version=2 if launch_chain else 1,
        collection_mode="launch_chain" if launch_chain else "app",
        synthetic_entitlement=synthetic_entitlement if launch_chain else None,
        image=_image(_executable(root)),
        guard_sha256=_digest(root / "collector-guard"),
        plist_sha256=_digest(app / "Contents/Info.plist"),
        code_sha256={name: _digest(root / name) for name in CODE},
        codec_sha256=_codec_digest(),
    )
    _write(root / "SETUP.json", manifest.model_dump_json().encode())
    return Report(
        kit_version=manifest.kit_version,
        synthetic_entitlement=manifest.synthetic_entitlement,
        stage="SETUP_READY",
        target_platform="PASS",
        provenance="PASS",
    )


def _manifest(root: Path) -> Manifest:
    for directory in (
        root / "GUIProbe.app",
        root / "GUIProbe.app/Contents",
        root / "GUIProbe.app/Contents/MacOS",
    ):
        _directory(directory)
    raw = _read(root / "SETUP.json")
    _decode(raw)
    manifest = Manifest.model_validate_json(raw)
    if (
        manifest.image != _image(_executable(root))
        or manifest.guard_sha256 != _digest(root / "collector-guard")
        or manifest.plist_sha256 != _digest(root / "GUIProbe.app/Contents/Info.plist")
        or manifest.code_sha256 != {name: _digest(root / name) for name in CODE}
        or manifest.codec_sha256 != _codec_digest()
    ):
        raise PrivateError("BUILD")
    return manifest


def _active(root: Path) -> Path:
    name = _read(root / "ACTIVE-RUN", 64).decode("ascii").strip()
    if not re.fullmatch(r"run-[a-f0-9]{32}", name):
        raise PrivateError("LOCATION")
    run = root / name
    _directory(run)
    return run


def _own(run: Path, case: Case) -> OwnSnapshot | None:
    path = run / f"{case}-self.json"
    if not path.exists():
        return None
    raw = _read(path)
    _decode(raw)
    return OwnSnapshot.model_validate_json(raw)


def _complete(run: Path, case: Case) -> bool:
    path = run / f"{case}-complete"
    return path.exists() and _read(path, 32) == b"RETURN_ZERO\n"


class Pump:
    """Bounded nonblocking stream reader; only tracker-accepted rows reach files."""

    def __init__(
        self, process: subprocess.Popen[bytes], tracker: Tracker, files: dict[Case, BinaryIO]
    ) -> None:
        self.process, self.tracker, self.files = process, tracker, files
        self.buffer = b""
        self.selector = selectors.DefaultSelector()
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def tick(self) -> None:
        if not self.selector.select(0.1):
            if self.process.poll() is not None:
                raise PrivateError("COLLECTOR")
            return
        assert self.process.stdout is not None
        chunk = os.read(self.process.stdout.fileno(), 65536)
        if not chunk:
            raise PrivateError("COLLECTOR")
        self.buffer += chunk
        while b"\n" in self.buffer:
            raw, self.buffer = self.buffer.split(b"\n", 1)
            if not raw:
                continue
            for case, retained in self.tracker.accept(raw):
                self.files[case].write(retained + b"\n")
        if len(self.buffer) > MAX_LINE:
            raise PrivateError("LIMIT")


def _start(executable: Path, *args: str) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [str(executable), *args],
        env=SAFE_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _stop_probe(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1)


def _stop_collector(process: subprocess.Popen[bytes]) -> bool:
    if process.stdin is not None:
        try:
            process.stdin.close()
        except OSError:
            pass
    try:
        return process.wait(timeout=4) == 0
    except subprocess.TimeoutExpired:
        # Root watchdog remains bounded even if the pipe/cleanup path failed.
        return False


def _emit(report: Report | ExistingReviewReport) -> None:
    print(report.model_dump_json(indent=2), flush=True)


def _progress(report: Report) -> None:
    print(report.model_dump_json(include={"purpose", "stage", "error"}), flush=True)


def _role(root: Path, token: tuple[int, ...], own: tuple[int, ...]) -> ImageRole:
    if not any(token):
        return "UNSET"
    if token == own:
        return "SELF"
    try:
        result = subprocess.run(
            [str(_executable(root)), "--classify"],
            input=struct.pack("=8I", *token),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=SAFE_ENV,
            timeout=3,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return "UNAVAILABLE"
    value = result.stdout
    roles: dict[bytes, ImageRole] = {
        name.encode() + b"\n": name
        for name in ("LAUNCHD", "FINDER", "DOCK", "SPOTLIGHT", "TERMINAL", "OTHER", "UNAVAILABLE")
    }
    return roles.get(value, "UNAVAILABLE")


def _role_report(root: Path, raws: list[bytes], report: CaseReport) -> CaseReport:
    execs = [_decode(raw) for raw in raws if _decode(raw).get("event_type") == 9]
    if len(execs) != 1:
        return report
    target = execs[0]["event"]["exec"]["target"]
    own = _token(target)
    return report.model_copy(
        update={
            "parent_image_role": _role(root, _token(target, "parent_audit_token"), own),
            "responsible_image_role": _role(root, _token(target, "responsible_audit_token"), own),
        }
    )


def capture() -> Report:
    """HUMAN ONLY: direct control, then a human-attested Finder launch; no ULF."""
    root = _root()
    os_version, os_build = _preflight()
    manifest = _manifest(root)
    lock = root / "SESSION-LOCK"
    try:
        _write(lock, b"ACTIVE\n")
    except FileExistsError:
        return Report(
            kit_version=manifest.kit_version,
            synthetic_entitlement=manifest.synthetic_entitlement,
            collection="CONTROLLED_TEST_APP_AND_LINKED_LAUNCHER"
            if manifest.collection_mode == "launch_chain"
            else "CONTROLLED_TEST_APP_ONLY",
            error="SESSION_LOCKED",
            target_platform="PASS",
            provenance="PASS",
        )
    run = root / f"run-{uuid.uuid4().hex}"
    collector: subprocess.Popen[bytes] | None = None
    probes: list[subprocess.Popen[bytes]] = []
    files: dict[Case, BinaryIO] = {}
    pump: Pump | None = None
    chain = manifest.collection_mode == "launch_chain"
    report = Report(
        kit_version=manifest.kit_version,
        synthetic_entitlement=manifest.synthetic_entitlement,
        collection="CONTROLLED_TEST_APP_AND_LINKED_LAUNCHER"
        if chain
        else "CONTROLLED_TEST_APP_ONLY",
        target_platform="PASS",
        provenance="PASS",
        context="HUMAN_ATTESTED_FINDER",
    )
    tracker = Tracker(manifest.image, launch_chain=chain)
    try:
        report = report.model_copy(update={"stage": "PROBE_CHECK"})
        check = _start(_executable(root), "--ready")
        probes.append(check)
        try:
            status = check.wait(timeout=3)
        except subprocess.TimeoutExpired as error:
            raise PrivateError("PROBE_TIMEOUT") from error
        if status != 0:
            raise PrivateError("PROBE_KILLED" if status < 0 else "PROBE_FAILED")
        run.mkdir(mode=0o700)
        _replace(root / "ACTIVE-RUN", (run.name + "\n").encode())
        _write(
            run / "provenance.json",
            json.dumps(
                {
                    "setup": manifest.model_dump(),
                    "os_version": os_version,
                    "os_build": os_build,
                    "method": "finder",
                }
            ).encode(),
        )
        for case in ("control", "finder"):
            fd = os.open(
                run / f"{case}-events.jsonl",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            files[case] = os.fdopen(fd, "wb")
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(root / "collector-guard")],
            env=SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        pump = Pump(collector, tracker, files)
        deadline, next_probe, attempts = time.monotonic() + 10, 0.0, 0
        while time.monotonic() < deadline and not tracker.ready:
            if time.monotonic() >= next_probe and attempts < 8:
                probe = _start(_executable(root), "--ready")
                probes.append(probe)
                tracker.ready_pids.add(probe.pid)
                attempts += 1
                next_probe = time.monotonic() + 1
            pump.tick()
        if not tracker.ready:
            raise PrivateError("COLLECTOR")
        report = report.model_copy(update={"collector_ready": "PASS", "stage": "COLLECTOR_READY"})
        _progress(report)
        for probe in probes:
            status = probe.wait(timeout=1)
            if status != 0:
                raise PrivateError("PROBE_KILLED" if status < 0 else "PROBE_FAILED")
        _replace(run / "ACTIVE-CASE", b"control\n")
        tracker.phase = "control"
        control = _start(_executable(root))
        probes.append(control)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            pump.tick()
            if control.poll() is not None and any(
                _decode(r)["event_type"] == 15 for r in tracker.records["control"]
            ):
                break
        status = control.poll()
        if status is None:
            raise PrivateError("CONTROL_TIMEOUT")
        if status != 0:
            raise PrivateError("CONTROL_KILLED" if status < 0 else "CONTROL_FAILED")
        if not _complete(run, "control"):
            raise PrivateError("CONTROL_INCOMPLETE")
        _replace(run / "ACTIVE-CASE", b"finder\n")
        tracker.phase = "finder"
        report = report.model_copy(update={"stage": "FINDER_READY"})
        _progress(report)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            pump.tick()
            if _complete(run, "finder") and any(
                _decode(r)["event_type"] == 15 for r in tracker.records["finder"]
            ):
                break
        else:
            raise PrivateError("FINDER_TIMEOUT")
        _manifest(root)
        report = report.model_copy(update={"stage": "COMPLETE", "bounded_collection": "PASS"})
    except KeyboardInterrupt:
        report = report.model_copy(update={"error": "INTERRUPTED"})
    except PrivateError as error:
        report = report.model_copy(
            update={
                "error": error.code,
                **({"provenance": "FAIL"} if error.code == "BUILD" else {}),
            }
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError):
        report = report.model_copy(update={"error": "INTERNAL"})
    finally:
        probe_cleanup = True
        for probe in probes:
            try:
                _stop_probe(probe)
            except (OSError, subprocess.SubprocessError):
                probe_cleanup = False
        try:
            cleaned = _stop_collector(collector) if collector is not None else True
        except (OSError, subprocess.SubprocessError):
            cleaned = False
        if run.is_dir():
            _replace(run / "ACTIVE-CASE", b"CLOSED\n")
        if pump is not None:
            pump.selector.close()
        for stream in files.values():
            stream.close()
        if collector is not None and collector.stdout is not None:
            collector.stdout.close()
        if cleaned and probe_cleanup:
            lock.unlink()
    if not (cleaned and probe_cleanup) and report.error == "NONE":
        report = report.model_copy(update={"error": "COLLECTOR", "stage": "ERROR"})
    wire = _wire_profile([raw for raws in tracker.records.values() for raw in raws])
    report = report.model_copy(
        update={
            "collector_cleanup": _check(cleaned and probe_cleanup),
            "sequence_continuity": _check(tracker.sequence_ok)
            if tracker.sequence
            else "INCONCLUSIVE",
            "wire_profile": wire,
            "control": analyze_case(
                tracker.records["control"],
                _own(run, "control"),
                _complete(run, "control"),
                manifest.image,
                launch_chain=chain,
            ),
            "finder": analyze_case(
                tracker.records["finder"],
                _own(run, "finder"),
                _complete(run, "finder"),
                manifest.image,
                launch_chain=chain,
            ),
            "launch_chain": tracker.launch_chain_report() if chain else None,
        }
    )
    if cleaned and probe_cleanup:
        for case in ("control", "finder"):
            report = report.model_copy(
                update={
                    case: _role_report(
                        root,
                        _app_case_rows(tracker.records[case], manifest.image)
                        if chain
                        else tracker.records[case],
                        getattr(report, case),
                    )
                }
            )
    if run.is_dir():
        _write(run / "SHAREABLE-REPORT.json", report.model_dump_json(indent=2).encode())
    return report


def offline_report() -> Report:
    """HUMAN ONLY: reopen the latest kit-owned run; no path prompt or collector."""
    root = _root()
    manifest = _manifest(root)
    run = _active(root)
    provenance = _decode(_read(run / "provenance.json"))
    if (
        provenance.get("setup") != manifest.model_dump(mode="json")
        or provenance.get("method") != "finder"
    ):
        raise PrivateError("BUILD")
    raw = _read(run / "SHAREABLE-REPORT.json")
    _decode(raw)
    report = Report.model_validate_json(raw)
    for case in ("control", "finder"):
        raw = _read(run / f"{case}-events.jsonl", MAX_RETAINED * (MAX_LINE + 1))
        rows = [line for line in raw.splitlines() if line]
        if len(rows) > MAX_RETAINED:
            raise PrivateError("LIMIT")
        original = getattr(report, case)
        analyzed = analyze_case(
            rows,
            _own(run, case),
            _complete(run, case),
            manifest.image,
            launch_chain=manifest.collection_mode == "launch_chain",
        )
        report = report.model_copy(
            update={
                case: analyzed.model_copy(
                    update={
                        "parent_image_role": original.parent_image_role,
                        "responsible_image_role": original.responsible_image_role,
                    }
                )
            }
        )
        if case == "finder" and manifest.collection_mode == "launch_chain":
            report = report.model_copy(
                update={
                    "launch_chain": _preserve_candidate_selection(
                        analyze_launch_chain(rows, manifest.image), report.launch_chain
                    )
                }
            )
    return report.model_copy(update={"stage": "OFFLINE_REPORT"})


def review_existing(root: Path) -> ExistingReviewReport:
    """HUMAN ONLY: diagnose unchanged private evidence; no subprocess or writes."""
    _directory(root)
    root = root.resolve(strict=True)
    _outside_git(root)
    manifest = _manifest(root)
    run = _active(root)
    provenance = _decode(_read(run / "provenance.json"))
    if (
        provenance.get("setup") != manifest.model_dump(mode="json")
        or provenance.get("method") != "finder"
    ):
        raise PrivateError("BUILD")
    raw = _read(run / "SHAREABLE-REPORT.json")
    _decode(raw)
    original = Report.model_validate_json(raw)
    controls = (
        original.error == "NONE"
        and original.stage in {"COMPLETE", "OFFLINE_REPORT"}
        and original.context == "HUMAN_ATTESTED_FINDER"
        and original.wire_profile == "V11"
        and all(
            getattr(original, name) == "PASS"
            for name in (
                "target_platform",
                "provenance",
                "collector_ready",
                "collector_cleanup",
                "bounded_collection",
                "sequence_continuity",
            )
        )
    )
    values: dict = {"provenance": "PASS", "original_collection_controls": _check(controls)}
    if not controls:
        return ExistingReviewReport(**values)
    control_signature = None
    control_birth: int | None = None
    control_exit: int | None = None
    for case in ("control", "finder"):
        raw = _read(run / f"{case}-events.jsonl", MAX_RETAINED * (MAX_LINE + 1))
        rows = [line for line in raw.splitlines() if line]
        if len(rows) > MAX_RETAINED:
            raise PrivateError("LIMIT")
        own = _own(run, case)
        app_rows = (
            _app_case_rows(rows, manifest.image)
            if manifest.collection_mode == "launch_chain"
            else rows
        )
        checked = analyze_case(app_rows, own, _complete(run, case), manifest.image)
        required = (
            "native_shapes",
            "one_exec_and_exit",
            "own_identity_agreement",
            "image_identity_agreement",
            "audit_identity_agreement",
            "exec_identity_transition",
            "test_completion",
            "exit_status_agreement",
        )
        if (
            own is None
            or _wire_profile(rows) != "V11"
            or any(getattr(checked, name) != "PASS" for name in required)
        ):
            raise PrivateError("DATA")
        decoded = [_decode(line) for line in app_rows]
        execs = [row for row in decoded if row.get("event_type") == 9]
        environment = tuple(entry.encode("utf-8") for entry in execs[0]["event"]["exec"]["env"])
        main = tuple(bytes.fromhex(entry) for entry in own.environment_hex)
        values[f"{case}_environment"] = compare_environment(
            environment, main, controlled=case == "control"
        )
        values[f"{case}_launch"] = inspect_existing_launch(
            execs[0]["process"],
            execs[0]["event"]["exec"],
            manifest.image,
            control_signature=control_signature,
        )
        if case == "control":
            control_signature = _signature(execs[0]["event"]["exec"]["target"])
            control_birth = _birth(execs[0]["event"]["exec"]["target"])
            exit_row = next(row for row in decoded if row.get("event_type") == 15)
            control_exit = _timestamp_microseconds(exit_row["time"])
        elif (
            control_birth is not None and control_exit is not None and control_birth <= control_exit
        ):
            birth = _birth(execs[0]["process"])
            values["finder_preimage_birth"] = (
                "BEFORE_CONTROL_BIRTH"
                if birth < control_birth
                else "BETWEEN_CONTROL_BIRTH_AND_EXIT"
                if birth <= control_exit
                else "AFTER_CONTROL_EXIT"
            )
        if case == "finder" and manifest.collection_mode == "launch_chain":
            values["launch_chain"] = _preserve_candidate_selection(
                analyze_launch_chain(rows, manifest.image), original.launch_chain
            )
        values[f"{case}_fork"] = (
            "RETAINED_MATCH"
            if checked.fork_linkage == "PASS"
            else "NOT_RETAINED"
            if checked.fork_linkage == "INCONCLUSIVE"
            else "INCONSISTENT"
        )
    return ExistingReviewReport(**values)


def _hidden_existing_root() -> Path:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise PrivateError("INPUT")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            path = getpass.getpass(
                "Private ORIGINAL KIT folder (hidden; outer kit, not run folder): "
            )
        except (getpass.GetPassWarning, EOFError) as error:
            raise PrivateError("INPUT") from error
    if not path:
        raise PrivateError("LOCATION")
    return Path(path).expanduser()


class QuietParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise PrivateError("INPUT")


def main(argv: list[str] | None = None) -> int:
    parser = QuietParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser("prepare", help="Copy code only; safe for an agent")
    stage.add_argument("--destination", type=Path)
    for name in ("setup", "capture", "report", "review-existing"):
        stage = commands.add_parser(name, help="HUMAN private use only")
        stage.add_argument("--private-run", action="store_true", required=True)
        if name == "setup":
            stage.add_argument(
                "--launch-chain",
                action="store_true",
                help="Opt into controlled launcher diagnostics without adding entitlements",
            )
            stage.add_argument(
                "--synthetic-entitlement",
                action="store_true",
                help="Separate opt-in marker experiment; requires --launch-chain",
            )
        if name == "capture":
            stage.add_argument(
                "--finder", action="store_true", required=True, help="Attest a manual Finder launch"
            )
    reviewing = False
    try:
        args = parser.parse_args(argv)
        if args.command == "prepare":
            print(prepare(args.destination))
            return 0
        reviewing = args.command == "review-existing"
        if reviewing:
            _root()  # The reviewer itself must also be a prepared outside-Git copy.
            report = review_existing(_hidden_existing_root())
        else:
            report = (
                setup(
                    launch_chain=args.launch_chain,
                    synthetic_entitlement=args.synthetic_entitlement,
                )
                if args.command == "setup"
                else capture()
                if args.command == "capture"
                else offline_report()
            )
    except PrivateError as error:
        report = ExistingReviewReport(error=error.code) if reviewing else Report(error=error.code)
    except KeyboardInterrupt:
        report = (
            ExistingReviewReport(error="INTERRUPTED") if reviewing else Report(error="INTERRUPTED")
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError):
        report = ExistingReviewReport(error="INTERNAL") if reviewing else Report(error="INTERNAL")
    _emit(report)
    return 0 if report.error == "NONE" else 2


def _quiet_exception(_kind: object, _value: object, _traceback: object) -> None:
    _emit(Report(error="INTERNAL"))


if __name__ == "__main__":
    sys.excepthook = _quiet_exception
    raise SystemExit(main())

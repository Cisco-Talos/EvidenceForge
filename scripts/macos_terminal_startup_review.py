# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare an offline-only, fixed-output review of existing terminal captures.

Agents may prepare and test invented inputs. Reading a real capture requires
the user's separate permission. No review operation executes commands, queries
live processes, opens installed apps, starts collectors or writes files.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import importlib.util
import math
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field


def _load_capture() -> ModuleType:
    path = Path(__file__).resolve().with_name("private_terminal_startup.py")
    if not path.exists():
        if __package__ == "scripts":
            from scripts import macos_terminal_startup_reference

            return macos_terminal_startup_reference
        path = Path(__file__).resolve().with_name("macos_terminal_startup_reference.py")
    spec = importlib.util.spec_from_file_location("_terminal_review_capture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("REFERENCE_SUPPORT")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


capture = _load_capture()
reference = capture.reference
# Exact revision-359 codec source used by the completed version-2 Terminal capture.
# Only its qualified successor adds Boolean/string-array entitlement decoding.
BOOLEAN_PREDECESSOR_CODEC = "8317f64282a9d79153565e6c4e21b4489ef4840982b1577bfcfed9b49fdc75f8"
# Independent reference oracles from verified Apple-shipped static signatures.
# These are vendor definitions, never copied from the private capture.
APPLE_TERMINAL_VENDOR_ENTITLEMENTS = {
    "com.apple.private.CFPasteboard.get-paste-source": True,
    "com.apple.private.kernel.global-proc-info": True,
    "com.apple.private.quarantine.control-add": True,
    "com.apple.private.responsibility.set-to-other": True,
    "com.apple.private.responsibility.set-to-self": True,
    "com.apple.private.tcc.allow-prompting": ["kTCCServiceAll"],
}
LOGIN_VENDOR_ENTITLEMENTS = {
    "com.apple.private.endpoint-security.submit.login": True,
    "com.apple.private.security.clear-library-validation": True,
}
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type ValueType = Literal["BOOLEAN", "STRING", "INTEGER", "REAL", "NULL", "ARRAY", "OBJECT", "OTHER"]
type AccountWord = Literal["ZERO", "LOCAL_ACCOUNT", "ZERO_AND_LOCAL_ACCOUNT", "OTHER"]
type MemberReference = Literal["SELF", "TERMINAL", "LOGIN", "SHELL", "PARENT", "ONE", "OTHER"]
type ResponsibleRole = Literal["SELF", "TERMINAL", "LOGIN", "SHELL", "UNSET", "OTHER"]
type Slot = Literal[
    "FD_0",
    "FD_1",
    "FD_2",
    "FD_3",
    "FD_4",
    "FD_5",
    "FD_6",
    "FD_7",
    "FD_8",
    "FD_9",
    "FD_10",
    "FD_11",
    "FD_12",
    "FD_13",
    "FD_14",
    "FD_15",
]
type DescriptorKind = Literal[
    "VNODE",
    "SOCKET",
    "PIPE",
    "TYPE_0",
    "TYPE_3",
    "TYPE_4",
    "TYPE_5",
    "TYPE_7",
    "TYPE_8",
    "TYPE_9",
    "TYPE_10",
    "TYPE_11",
    "TYPE_12",
    "TYPE_13",
    "TYPE_14",
    "TYPE_15",
    "OTHER",
]


class EntitlementLayout(capture.Model):
    representation: Literal["OBJECT", "NULL", "MISSING", "OTHER"]
    bounded: Check
    flat_boolean_object: Check
    top_level_types: tuple[ValueType, ...] = ()
    array_element_types: tuple[ValueType, ...] = ()
    nested_object_value_types: tuple[ValueType, ...] = ()


class PipeTopology(capture.Model):
    """Equivalence groups of fixed descriptor slots, without native pipe IDs."""

    complete: Check
    groups: tuple[tuple[Slot, ...], ...] = Field(default=(), max_length=16)


class Credentials(capture.Model):
    real_uid: AccountWord
    effective_uid: AccountWord
    real_gid: AccountWord
    effective_gid: AccountWord


class ProcessFacts(capture.Model):
    credentials: Credentials
    audit_user: Literal["LOCAL_ACCOUNT", "UNATTRIBUTED", "ZERO", "OTHER"]
    audit_session_matches_terminal: Check
    group: MemberReference
    session: MemberReference
    responsibility: ResponsibleRole
    responsible_token_exact: Check
    terminal: Literal["PRESENT", "ABSENT", "UNKNOWN"]


class Argument(capture.Model):
    kind: Literal[
        "EXECUTABLE_PATH",
        "LOCAL_USERNAME",
        "LOCAL_HOME",
        "LOGIN_NAME",
        "LOGIN_PATH",
        "ZSH_PATH",
        "BASH_PATH",
        "ZSH_NAME",
        "BASH_NAME",
        "LOGIN_ZSH_ARG0",
        "LOGIN_BASH_ARG0",
        "FLAG_C",
        "FLAG_L",
        "FLAG_LA",
        "FLAG_A",
        "FLAG_LOGIN",
        "DASHDASH",
        "LOGIN_FLAGS",
        "EXEC",
        "EXEC_LOGIN_ZSH",
        "EXEC_LOGIN_BASH",
        "MARKER_SAMPLE",
        "OTHER",
    ]
    flags: tuple[Literal["F", "P", "Q", "L", "H"], ...] = ()


class PhaseDetail(capture.Model):
    role: capture.Role
    before_role: capture.Role
    before: ProcessFacts
    target: ProcessFacts
    fork_parent: ProcessFacts | None = None
    fork_child: ProcessFacts | None = None
    fork_parent_role: capture.Role | None = None
    fork_child_role: capture.Role | None = None
    fork_parent_to_child_credentials: Check = "INCONCLUSIVE"
    fork_parent_to_child_membership: Check = "INCONCLUSIVE"
    fork_child_to_before_audit: Check = "INCONCLUSIVE"
    fork_child_to_before_credentials: Check = "INCONCLUSIVE"
    fork_child_to_before_membership: Check = "INCONCLUSIVE"
    arguments_complete: Check
    arguments: tuple[Argument, ...] = Field(max_length=32)
    descriptors: dict[Slot, DescriptorKind]
    descriptors_unique: Check
    higher_descriptor_present: Check
    last_fd_slot: Slot | Literal["HIGHER", "INVALID"]
    last_fd_relative_to_inventory: Literal["SAME", "HIGHER", "LOWER", "INVALID"]
    pipe_fd_4_5: Literal["SAME", "DIFFERENT", "NOT_OBSERVED", "INCONCLUSIVE"]
    pipes: PipeTopology
    entitlements: EntitlementLayout
    vendor_entitlements: Check = "INCONCLUSIVE"


class ReviewReport(capture.Model):
    review_version: Literal[3] = 3
    purpose: Literal["TERMINAL_STARTUP_DETAIL_REVIEW"] = "TERMINAL_STARTUP_DETAIL_REVIEW"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: capture.ErrorCode = "NONE"
    step: Literal[
        "INPUT", "LOCATION", "PROVENANCE", "CONTROLS", "RECORDS", "ANALYSIS", "COMPLETE"
    ] = "INPUT"
    provenance: Check = "INCONCLUSIVE"
    codec_lineage: Literal[
        "CURRENT", "QUALIFIED_BOOLEAN_PREDECESSOR", "UNQUALIFIED", "NOT_REVIEWED"
    ] = "NOT_REVIEWED"
    original_collection_controls: Check = "INCONCLUSIVE"
    retained_chain: Check = "INCONCLUSIVE"
    terminal: capture.Terminal | None = None
    phases: tuple[PhaseDetail, ...] = Field(default=(), max_length=capture.MAX_CHAIN_ROWS)
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    apps: Literal["NOT_LAUNCHED"] = "NOT_LAUNCHED"
    live_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    files: Literal["UNCHANGED"] = "UNCHANGED"


def _type(value: object) -> ValueType:
    return {
        bool: "BOOLEAN",
        str: "STRING",
        int: "INTEGER",
        float: "REAL",
        type(None): "NULL",
        list: "ARRAY",
        dict: "OBJECT",
    }.get(type(value), "OTHER")


def entitlement_layout(value: object, *, present: bool = True) -> EntitlementLayout:
    """Describe value types only; never return keys, values, counts or lengths."""
    representation = (
        "MISSING"
        if not present
        else "NULL"
        if value is None
        else "OBJECT"
        if type(value) is dict
        else "OTHER"
    )
    if type(value) is not dict:
        return EntitlementLayout(
            representation=representation,
            bounded="PASS" if value is None and present else "FAIL",
            flat_boolean_object="FAIL",
        )
    top = {_type(item) for item in value.values()}
    arrays: set[ValueType] = set()
    nested: set[ValueType] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    bounded = True
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 8:
            bounded = False
            break
        if type(item) is dict:
            if len(item) > 128 or any(
                type(key) is not str or not key.strip() or len(key) > 512 or "\0" in key
                for key in item
            ):
                bounded = False
            if depth:
                nested.update(_type(child) for child in item.values())
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 128:
                bounded = False
            arrays.update(_type(child) for child in item)
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            bounded &= len(item) <= 16384 and "\0" not in item
        elif type(item) is float:
            bounded &= math.isfinite(item)
        elif type(item) not in (bool, int, type(None)):
            bounded = False
    return EntitlementLayout(
        representation=representation,
        bounded=capture._check(bounded),
        flat_boolean_object=capture._check(
            bool(value) and all(type(item) is bool for item in value.values())
        ),
        top_level_types=tuple(sorted(top)),
        array_element_types=tuple(sorted(arrays)),
        nested_object_value_types=tuple(sorted(nested)),
    )


def _account(value: int, local: int) -> AccountWord:
    return (
        "ZERO_AND_LOCAL_ACCOUNT"
        if value == local == 0
        else "ZERO"
        if value == 0
        else "LOCAL_ACCOUNT"
        if value == local
        else "OTHER"
    )


def _member(value: int, process: dict, anchors: dict[str, dict]) -> MemberReference:
    if value == reference._token(process)[5]:
        return "SELF"
    for name, anchor in anchors.items():
        if value == reference._token(anchor)[5]:
            return name
    return (
        "PARENT"
        if value == reference._token(process, "parent_audit_token")[5]
        else "ONE"
        if value == 1
        else "OTHER"
    )


def _facts(process: dict, manifest: capture.Manifest, anchors: dict[str, dict]) -> ProcessFacts:
    token = reference._token(process)
    responsible = reference._token(process, "responsible_audit_token")
    candidates = {"SELF": process, **anchors}
    role: ResponsibleRole = "OTHER"
    exact: Check = "INCONCLUSIVE"
    if not any(responsible):
        role = "UNSET"
    else:
        for name, anchor in candidates.items():
            expected = reference._token(anchor)
            if responsible[5::2] == expected[5::2]:
                role, exact = name, capture._check(responsible == expected)
                break
    app = anchors.get("TERMINAL")
    return ProcessFacts(
        credentials=Credentials(
            real_uid=_account(token[3], manifest.own_uid),
            effective_uid=_account(token[1], manifest.own_uid),
            real_gid=_account(token[4], manifest.own_gid),
            effective_gid=_account(token[2], manifest.own_gid),
        ),
        audit_user="LOCAL_ACCOUNT"
        if token[0] == manifest.own_uid
        else "UNATTRIBUTED"
        if token[0] == 2**32 - 1
        else "ZERO"
        if token[0] == 0
        else "OTHER",
        audit_session_matches_terminal="INCONCLUSIVE"
        if app is None
        else capture._check(token[6] == reference._token(app)[6]),
        group=_member(process["group_id"], process, anchors),
        session=_member(process["session_id"], process, anchors),
        responsibility=role,
        responsible_token_exact=exact,
        terminal="UNKNOWN"
        if "tty" not in process
        else "ABSENT"
        if process["tty"] is None
        else "PRESENT",
    )


def _argument(value: str, image: str, manifest: capture.Manifest) -> Argument:
    known = {
        "login": "LOGIN_NAME",
        "/usr/bin/login": "LOGIN_PATH",
        "/bin/zsh": "ZSH_PATH",
        "/bin/bash": "BASH_PATH",
        "zsh": "ZSH_NAME",
        "bash": "BASH_NAME",
        "-zsh": "LOGIN_ZSH_ARG0",
        "-bash": "LOGIN_BASH_ARG0",
        "-c": "FLAG_C",
        "-l": "FLAG_L",
        "-la": "FLAG_LA",
        "-a": "FLAG_A",
        "--login": "FLAG_LOGIN",
        "--": "DASHDASH",
        "exec": "EXEC",
        "--sample": "MARKER_SAMPLE",
        "exec -la zsh /bin/zsh": "EXEC_LOGIN_ZSH",
        "exec -la bash /bin/bash": "EXEC_LOGIN_BASH",
    }
    if value == manifest.own_username:
        return Argument(kind="LOCAL_USERNAME")
    if value == manifest.own_home:
        return Argument(kind="LOCAL_HOME")
    if value == image:
        return Argument(kind="EXECUTABLE_PATH")
    if value in known:
        return Argument(kind=known[value])
    if (
        1 < len(value) <= 6
        and value.startswith("-")
        and all(letter in "fpqlh" for letter in value[1:])
    ):
        return Argument(kind="LOGIN_FLAGS", flags=tuple(letter.upper() for letter in value[1:]))
    return Argument(kind="OTHER")


def _pipe_pair(fds: list[dict]) -> str:
    pair = [item for item in fds if item.get("fd") in (4, 5)]
    if not pair:
        return "NOT_OBSERVED"
    if len(pair) != 2 or {item["fd"] for item in pair} != {4, 5}:
        return "INCONCLUSIVE"
    if any(
        item.get("fdtype") != 6
        or type(item.get("pipe")) is not dict
        or type(item["pipe"].get("pipe_id")) is not int
        or not 0 <= item["pipe"]["pipe_id"] < 2**64
        for item in pair
    ):
        return "INCONCLUSIVE"
    return "SAME" if pair[0]["pipe"]["pipe_id"] == pair[1]["pipe"]["pipe_id"] else "DIFFERENT"


def _pipe_topology(fds: list[dict]) -> PipeTopology:
    """Compare all bounded pipe slots while keeping native identities in memory."""
    groups: dict[int, list[int]] = {}
    slots: set[int] = set()
    for item in fds:
        fd = item.get("fd")
        if type(fd) is not int or fd < 0 or fd in slots:
            return PipeTopology(complete="FAIL")
        slots.add(fd)
        if item.get("fdtype") != 6:
            continue
        pipe = item.get("pipe")
        if (
            type(pipe) is not dict
            or type(pipe.get("pipe_id")) is not int
            or not 0 <= pipe["pipe_id"] < 2**64
        ):
            return PipeTopology(complete="FAIL")
        if fd >= 16:
            return PipeTopology(complete="INCONCLUSIVE")
        groups.setdefault(pipe["pipe_id"], []).append(fd)
    return PipeTopology(
        complete="PASS",
        groups=tuple(
            tuple(f"FD_{fd}" for fd in group)
            for group in sorted(sorted(members) for members in groups.values())
        ),
    )


def _vendor_entitlements(role: capture.Role, value: object) -> Check:
    expected = (
        APPLE_TERMINAL_VENDOR_ENTITLEMENTS
        if role == "APPLE_TERMINAL"
        else LOGIN_VENDOR_ENTITLEMENTS
        if role == "LOGIN"
        else None
    )
    if expected is None:
        return "INCONCLUSIVE"
    return capture._check(
        type(value) is dict
        and value == expected
        and all(
            type(value[key]) is type(item)
            and (type(item) is bool or all(type(element) is str for element in value[key]))
            for key, item in expected.items()
        )
    )


def analyze(raws: list[bytes], manifest: capture.Manifest) -> tuple[PhaseDetail, ...]:
    """Classify immutable native relationships in memory, without native values."""
    rows = [reference._decode(raw) for raw in raws]
    anchors: dict[str, dict] = {}
    for row in rows:
        if row["event_type"] != 9:
            continue
        target = row["event"]["exec"]["target"]
        role = capture._role(target, manifest.marker)
        name = (
            "TERMINAL"
            if reference._owned(target, manifest.app)
            else "LOGIN"
            if role == "LOGIN"
            else "SHELL"
            if role in ("ZSH", "BASH")
            else None
        )
        if name is not None:
            if name in anchors:
                raise reference.PrivateError("DATA")
            anchors[name] = target
    if "TERMINAL" not in anchors or "SHELL" not in anchors:
        raise reference.PrivateError("DATA")
    phases: list[PhaseDetail] = []
    for row in rows:
        if row["event_type"] != 9:
            continue
        before, payload = row["process"], row["event"]["exec"]
        target = payload["target"]
        role = capture._role(target, manifest.marker)
        forks = [
            item
            for item in rows
            if item["event_type"] == 11
            and capture._matches_execution(item["event"]["fork"]["child"], before)
        ]
        if len(forks) > 1:
            raise reference.PrivateError("DATA")
        child = forks[0]["event"]["fork"]["child"] if forks else None
        fds = payload["fds"]
        numbers = [item["fd"] for item in fds]
        last = payload["last_fd"]
        descriptor_kinds = {
            1: "VNODE",
            2: "SOCKET",
            6: "PIPE",
            **{index: f"TYPE_{index}" for index in range(16) if index not in (1, 2, 6)},
        }
        descriptors = {
            f"FD_{item['fd']}": descriptor_kinds.get(item["fdtype"], "OTHER")
            for item in fds
            if 0 <= item["fd"] < 16
        }
        phases.append(
            PhaseDetail(
                role=role,
                before_role=capture._role(before, manifest.marker),
                before=_facts(before, manifest, anchors),
                target=_facts(target, manifest, anchors),
                fork_parent=_facts(forks[0]["process"], manifest, anchors) if forks else None,
                fork_child=_facts(child, manifest, anchors) if child else None,
                fork_parent_role=capture._role(forks[0]["process"], manifest.marker)
                if forks
                else None,
                fork_child_role=capture._role(child, manifest.marker) if child else None,
                fork_parent_to_child_credentials=capture._check(
                    reference._token(forks[0]["process"])[1:5] == reference._token(child)[1:5]
                )
                if child
                else "INCONCLUSIVE",
                fork_parent_to_child_membership=capture._check(
                    (forks[0]["process"]["group_id"], forks[0]["process"]["session_id"])
                    == (child["group_id"], child["session_id"])
                )
                if child
                else "INCONCLUSIVE",
                fork_child_to_before_audit=capture._check(
                    (reference._token(child)[0], reference._token(child)[6])
                    == (reference._token(before)[0], reference._token(before)[6])
                )
                if child
                else "INCONCLUSIVE",
                fork_child_to_before_credentials=capture._check(
                    reference._token(child)[1:5] == reference._token(before)[1:5]
                )
                if child
                else "INCONCLUSIVE",
                fork_child_to_before_membership=capture._check(
                    (child["group_id"], child["session_id"])
                    == (before["group_id"], before["session_id"])
                )
                if child
                else "INCONCLUSIVE",
                arguments_complete=capture._check(len(payload["args"]) <= 32),
                arguments=tuple(
                    _argument(item, target["executable"]["path"], manifest)
                    for item in payload["args"][:32]
                ),
                descriptors=descriptors,
                descriptors_unique=capture._check(len(numbers) == len(set(numbers))),
                higher_descriptor_present=capture._check(any(number >= 16 for number in numbers)),
                last_fd_slot=f"FD_{last}"
                if 0 <= last < 16
                else "HIGHER"
                if last >= 16
                else "INVALID",
                last_fd_relative_to_inventory="INVALID"
                if not numbers or last < 0
                else "SAME"
                if last == max(numbers)
                else "HIGHER"
                if last > max(numbers)
                else "LOWER",
                pipe_fd_4_5=_pipe_pair(fds),
                pipes=_pipe_topology(fds),
                entitlements=entitlement_layout(
                    payload.get("entitlements"), present="entitlements" in payload
                ),
                vendor_entitlements=_vendor_entitlements(role, payload.get("entitlements")),
            )
        )
    return tuple(phases)


def _source_paths() -> dict[str, Path]:
    root = Path(__file__).resolve().parent
    if (root / capture.CODE[0]).exists():
        return {name: root / name for name in capture.CODE}
    docs = root.parent / "docs/design/macos-workstation-feasibility"
    return {
        capture.CODE[0]: Path(capture.__file__),
        capture.CODE[1]: Path(reference.__file__),
        capture.CODE[2]: docs / "terminal-startup-reference/terminal_marker.c",
        capture.CODE[3]: docs / "gui-launch-reference/collector_guard.c",
    }


def review_existing(root: Path) -> ReviewReport:
    """Read only this kit's bounded records, provenance and controlled code metadata."""
    report = ReviewReport()
    step = "LOCATION"
    try:
        reference._directory(root)
        root = root.resolve(strict=True)
        reference._outside_git(root)
        step = "PROVENANCE"
        manifest = capture.Manifest.model_validate_json(reference._read(root / "SETUP.json"))
        run = reference._active(root)
        provenance = capture.Manifest.model_validate_json(reference._read(run / "provenance.json"))
        expected = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in _source_paths().items()
        }
        codec_lineage = (
            "CURRENT"
            if manifest.codec_sha256 == reference._codec_digest()
            else "QUALIFIED_BOOLEAN_PREDECESSOR"
            if manifest.codec_sha256 == BOOLEAN_PREDECESSOR_CODEC
            else "UNQUALIFIED"
        )
        report = report.model_copy(update={"codec_lineage": codec_lineage})
        if (
            provenance != manifest
            or manifest.code_sha256 != expected
            or manifest.code_sha256
            != {name: reference._digest(root / name) for name in capture.CODE}
            or codec_lineage == "UNQUALIFIED"
            or manifest.marker != capture._image(root / "terminal-marker")
            or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        ):
            raise reference.PrivateError("BUILD")
        report = report.model_copy(update={"provenance": "PASS", "terminal": manifest.terminal})
        step = "CONTROLS"
        original = capture.Report.model_validate_json(
            reference._read(run / "SHAREABLE-REPORT.json")
        )
        controls = (
            original.kit_version == 2
            and original.terminal == manifest.terminal
            and original.error == "NONE"
            and original.stage == "COMPLETE"
            and original.wire_profile == "V11"
            and not original.candidate_ring_evicted
            and all(
                getattr(original, name) == "PASS"
                for name in (
                    "provenance",
                    "target_platform",
                    "collector_ready",
                    "collector_cleanup",
                    "bounded_collection",
                    "sequence_continuity",
                    "app_exec_retained",
                    "marker_exit_zero",
                )
            )
        )
        report = report.model_copy(
            update={"original_collection_controls": capture._check(controls)}
        )
        if not controls:
            raise reference.PrivateError("DATA")
        step = "RECORDS"
        raws = reference._read(run / "launch-chain-events.jsonl", reference.MAX_STREAM).splitlines()
        if not 1 <= len(raws) <= capture.MAX_CHAIN_ROWS + 1:
            raise reference.PrivateError("LIMIT")
        rows = [reference._decode(raw) for raw in raws]
        if any(
            reference._shape_without_entitlements(row) != "PASS"
            or row.get("schema_version") != 1
            or row.get("version") != 11
            or row.get("event_type") not in (9, 11, 15)
            for row in rows
        ):
            raise reference.PrivateError("DATA")
        samples = [
            index
            for index, row in enumerate(rows)
            if row["event_type"] == 9
            and reference._owned(row["event"]["exec"]["target"], manifest.marker)
            and row["event"]["exec"]["args"][1:] == ["--sample"]
        ]
        if len(samples) != 1:
            raise reference.PrivateError("DATA")
        selected = capture.select_lineage(
            rows,
            samples[0],
            manifest.app,
            responsibility_links=original.app_link == "RESPONSIBILITY",
        )
        if set(selected) != {index for index, row in enumerate(rows) if row["event_type"] != 15}:
            raise reference.PrivateError("DATA")
        sample = rows[samples[0]]["event"]["exec"]["target"]
        ends = [row for row in rows if row["event_type"] == 15]
        if (
            len(ends) != 1
            or not capture._matches_execution(ends[0]["process"], sample)
            or ends[0]["event"]["exit"]["stat"] != 0
        ):
            raise reference.PrivateError("DATA")
        report = report.model_copy(update={"retained_chain": "PASS"})
        step = "ANALYSIS"
        return report.model_copy(update={"step": "COMPLETE", "phases": analyze(raws, manifest)})
    except (
        reference.PrivateError,
        capture.DiagnosticError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ) as error:
        return report.model_copy(update={"error": capture._failure(error), "step": step})


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy only reviewed source code and instructions."""
    root = capture.prepare(destination)
    docs = (
        Path(__file__).resolve().parents[1]
        / "docs/design/macos-workstation-feasibility/terminal-startup-reference"
    )
    for original, name in (
        (Path(__file__), "private_terminal_review.py"),
        (docs / "OFFLINE-REVIEW.md", "OFFLINE-REVIEW.md"),
        (docs / "ITERM2-RUN.md", "ITERM2-RUN.md"),
    ):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "review-existing"))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--private-run", action="store_true")
    args = parser.parse_args()
    if args.operation == "prepare":
        print(prepare(args.destination))
        return
    report = ReviewReport(error="INPUT")
    try:
        if args.private_run and sys.stdin.isatty():
            value = getpass.getpass("Original terminal kit (hidden): ")
            if not value or len(value) > 4096:
                raise reference.PrivateError("INPUT")
            report = review_existing(Path(value))
    except (
        reference.PrivateError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
    ) as error:
        report = report.model_copy(update={"error": capture._failure(error)})
    except (KeyboardInterrupt, EOFError):
        report = report.model_copy(update={"error": "INTERRUPTED"})
    print(report.model_dump_json(indent=2), flush=True)
    if report.error != "NONE":
        raise SystemExit(2)


if __name__ == "__main__":
    main()

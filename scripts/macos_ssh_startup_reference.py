# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a human-only loopback SSH reference; never collect in an agent session.

The marker authenticates one receiver tree; a separate random environment marker
authenticates the controlled client. Ambient ES rows remain in a bounded memory
ring. Only the proved connection tree and client may reach private disk.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections import deque
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field, ValidationError


def _support() -> ModuleType:
    path = Path(__file__).resolve().with_name("terminal_support.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_terminal_startup_reference.py")
    name = "_eforge_ssh_startup_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


support = _support()
reference = support.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Role = Literal[
    "LAUNCHD",
    "XPCPROXY",
    "SSH_CLIENT",
    "WRAPPER",
    "SSHD",
    "SESSION",
    "AUTH",
    "ZSH",
    "BASH",
    "MARKER",
    "OTHER",
]
type WordClass = Literal[
    "ZERO", "LOCAL_USER", "LOCAL_GROUP", "SSHD_ACCOUNT", "UNATTRIBUTED", "OTHER"
]
type Error = Literal[
    "NONE",
    "INPUT",
    "LOCATION",
    "PLATFORM",
    "ROOT_USER",
    "BUILD",
    "COLLECTOR",
    "TIMEOUT",
    "LIMIT",
    "DATA",
    "IO",
    "INTERRUPTED",
    "INTERNAL",
]
PATHS: dict[Role, str] = {
    "LAUNCHD": "/sbin/launchd",
    "XPCPROXY": "/usr/libexec/xpcproxy",
    "SSH_CLIENT": "/usr/bin/ssh",
    "WRAPPER": "/usr/libexec/sshd-keygen-wrapper",
    "SSHD": "/usr/sbin/sshd",
    "SESSION": "/usr/libexec/sshd-session",
    "AUTH": "/usr/libexec/sshd-auth",
    "ZSH": "/bin/zsh",
    "BASH": "/bin/bash",
}
# Public Apple OpenSSH definitions, independently compared with static vendor code.
TEMPLATES: dict[Role, dict] = {
    "SSH_CLIENT": {
        "keychain-access-groups": ["com.apple.ssh.passphrases"],
        "com.apple.private.amfi.version-restriction": 1,
    },
    "WRAPPER": {
        "com.apple.keystore.class.wku": True,
        "com.apple.private.security.storage.ssh": True,
    },
    "SSHD": {
        "com.apple.private.security.clear-library-validation": True,
        "com.apple.private.endpoint-security.submit.openssh": True,
    },
    "SESSION": {
        "com.apple.private.security.clear-library-validation": True,
        "com.apple.private.endpoint-security.submit.openssh": True,
        "com.apple.private.xpc.launchd.reboot-pivot-root": True,
    },
    "AUTH": {
        "com.apple.private.security.clear-library-validation": True,
        "com.apple.private.endpoint-security.submit.openssh": True,
        "com.apple.private.xpc.launchd.reboot-pivot-root": True,
    },
}
CODE = (
    "private_ssh_startup.py",
    "terminal_support.py",
    "reference_support.py",
    "ssh_marker.c",
    "collector_guard.c",
)
MAX_ROWS, MAX_BYTES, MAX_STREAM, MAX_RETAINED = 2048, 32 * 1_048_576, 128 * 1_048_576, 96


class Manifest(reference.Model):
    """Private provenance, never included in the shareable report."""

    os_version: str = Field(pattern=r"^27(?:\.[0-9]+){0,2}$")
    os_build: str = Field(pattern=r"^[0-9A-Za-z]+$")
    marker: reference.Image
    images: dict[Role, reference.Image]
    guard_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    codec_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    code_sha256: dict[str, str]
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    username: str = Field(min_length=1, max_length=1024)
    home: str = Field(min_length=1, max_length=4096)
    uid: int = Field(ge=1, lt=2**32 - 1)
    gid: int = Field(ge=0, lt=2**32)


class Descriptor(reference.Model):
    """Only fixed slots/types and local pipe equivalence classes leave the kit."""

    slot: Literal[
        "FD0",
        "FD1",
        "FD2",
        "FD3",
        "FD4",
        "FD5",
        "FD6",
        "FD7",
        "FD8",
        "FD9",
        "FD10",
        "FD11",
        "FD12",
        "FD13",
        "FD14",
        "FD15",
        "OTHER",
    ]
    kind: Literal["VNODE", "PIPE", "SOCKET", "OTHER"]
    pipe_group: Literal[
        "NOT_PIPE",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "OTHER",
    ]


class Phase(reference.Model):
    """One exec's fixed relationship/schema facts, with no observed identifiers."""

    role: Role
    before_role: Role
    native_shape: Check
    shape_excluding_entitlements: Check
    retained_fork: Check
    same_lifetime: Check
    parent_role: Role
    credentials: tuple[WordClass, WordClass, WordClass, WordClass]
    audit_user: WordClass
    audit_origin_preserved: Check
    parentage_preserved: Check
    parent_is_boot_pid: Check
    original_parent_matches_parent: Check
    group: Literal["SELF", "PARENT", "BOOT", "OTHER"]
    session: Literal["SELF", "PARENT", "BOOT", "OTHER"]
    membership_preserved: Check
    responsibility: Literal["SELF", "PARENT", "UNSET", "OTHER"]
    before_responsibility_fields: reference.AuditTokenFieldRelations
    target_responsibility_fields: reference.AuditTokenFieldRelations
    security: reference.NativeSecurityFacts
    slice: reference.NativeSliceFacts
    entitlement_template: Check
    entitlement_types: tuple[Literal["BOOLEAN", "INTEGER", "STRING", "ARRAY", "NULL", "OTHER"], ...]
    arguments_match_template: Check
    descriptors: tuple[Descriptor, ...] = Field(max_length=64)
    descriptor_inventory_complete: Check
    last_fd_matches_maximum: Check
    terminal: Literal["PRESENT", "ABSENT", "UNKNOWN"]
    cwd: Literal["ROOT", "HOME", "KIT", "OTHER", "UNKNOWN"]
    script_absent: Check
    dyld_matches_target: Check
    environment_from_previous_exec: reference.EnvironmentDifference | None = None


class Fork(reference.Model):
    """Fixed linkage facts, including a child that never performs an exec."""

    parent_role: Role
    next_child_exec: Role | Literal["NOT_RETAINED"]
    parent_audit_user: WordClass
    child_audit_user: WordClass
    child_credentials: tuple[WordClass, WordClass, WordClass, WordClass]
    audit_origin_preserved: Check
    credentials_preserved: Check
    membership_preserved: Check


class Exit(reference.Model):
    """Fixed status and final credential classes, including the pre-auth drop."""

    role: Role
    audit_user: WordClass
    credentials: tuple[WordClass, WordClass, WordClass, WordClass]
    outcome: Literal["ZERO", "EXIT_ONE", "EXIT_255", "OTHER_EXIT_CODE", "SIGNALLED", "OTHER"]


class Report(reference.Model):
    """The sole shareable output; all strings are closed vocabulary."""

    kit_version: Literal[1] = 1
    purpose: Literal["SSH_STARTUP_CHAIN_DIAGNOSTIC"] = "SSH_STARTUP_CHAIN_DIAGNOSTIC"
    collection: Literal["MARKER_AUTHENTICATED_LOOPBACK_CONNECTION_ONLY"] = (
        "MARKER_AUTHENTICATED_LOOPBACK_CONNECTION_ONLY"
    )
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Error = "NONE"
    stage: Literal["SETUP_READY", "COLLECTOR_READY", "COMPLETE", "ERROR"] = "ERROR"
    step: Literal["INPUT", "SETUP", "COLLECTOR", "CONNECTION", "ANALYSIS", "COMPLETE"] = "INPUT"
    provenance: Check = "INCONCLUSIVE"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"
    client_control: Check = "INCONCLUSIVE"
    receiver_lineage: Check = "INCONCLUSIVE"
    marker_exit_zero: Check = "INCONCLUSIVE"
    candidate_ring_evicted: bool = False
    wire_profile: Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    phases: tuple[Phase, ...] = Field(default=(), max_length=32)
    fork_roles: tuple[Role, ...] = Field(default=(), max_length=32)
    forks: tuple[Fork, ...] = Field(default=(), max_length=32)
    exits: tuple[Exit, ...] = Field(default=(), max_length=32)
    unified_log: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    pty: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"


def _role(process: dict, manifest: Manifest) -> Role:
    if reference._owned(process, manifest.marker):
        return "MARKER"
    path = process.get("executable", {}).get("path")
    return next(
        (
            role
            for role, value in PATHS.items()
            if path == value and reference._owned(process, manifest.images[role])
        ),
        "OTHER",
    )


def select_receiver(rows: list[dict], sample: int, manifest: Manifest) -> list[int]:
    """Authenticate a marker ancestry, then include only that fork-root's descendants."""
    lineage = {sample}

    def walk(process: dict, limit: int) -> bool:
        if len(lineage) > MAX_RETAINED:
            raise reference.PrivateError("LIMIT")
        if _role(process, manifest) == "LAUNCHD" and reference._token(process)[5] == 1:
            return True
        for i in range(limit - 1, -1, -1):
            row = rows[i]
            kind = row["event_type"]
            subject = (
                row["event"]["exec"]["target"]
                if kind == 9
                else row["event"]["fork"]["child"]
                if kind == 11
                else None
            )
            if subject is None or not support._matches_execution(subject, process):
                continue
            before = row["process"]
            if kind == 9 and (
                reference._token(before)[5] != reference._token(subject)[5]
                or reference._birth(before) != reference._birth(subject)
            ):
                return False
            if (
                kind == 11
                and reference._token(subject, "parent_audit_token")[5::2]
                != reference._token(before)[5::2]
            ):
                return False
            lineage.add(i)
            return walk(before, i)
        return False

    if not walk(rows[sample]["process"], sample):
        return []
    # Never seed reachability from launchd: that would include unrelated children.
    roots = [
        i
        for i in lineage
        if rows[i]["event_type"] == 11 and _role(rows[i]["process"], manifest) == "LAUNCHD"
    ]
    if len(roots) != 1 or not any(
        rows[i]["event_type"] == 9
        and _role(rows[i]["event"]["exec"]["target"], manifest) in {"WRAPPER", "SSHD", "SESSION"}
        for i in lineage
    ):
        return []
    root = roots[0]
    executions = {reference._identity(rows[root]["event"]["fork"]["child"])}
    selected = {root}
    for i in range(root + 1, len(rows)):
        row = rows[i]
        if reference._identity(row["process"]) not in executions:
            continue
        selected.add(i)
        if row["event_type"] == 9:
            executions.add(reference._identity(row["event"]["exec"]["target"]))
        elif row["event_type"] == 11:
            executions.add(reference._identity(row["event"]["fork"]["child"]))
        if len(selected) > MAX_RETAINED:
            raise reference.PrivateError("LIMIT")
    return sorted(selected) if sample in selected and set(lineage) <= selected else []


class Tracker:
    """Bounded ambient memory only; no live rows are written by the stream pump."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self.ring: deque[tuple[bytes, dict]] = deque()
        self.size = self.total = 0
        self.evicted = False
        self.sequence: dict[int, int] = {}
        self.global_sequence = -1
        self.sequence_ok = True
        self.ready_pids: set[int] = set()
        self.ready_tokens: set[tuple[int, ...]] = set()
        self.ready = False
        self.collecting = False
        self.client: tuple[int, int, int] | None = None
        self.client_count = self.marker_count = 0
        self.marker: tuple[int, int, int] | None = None
        self.marker_exit: bool | None = None
        self.client_exit = False

    def accept(self, raw: bytes) -> list[tuple[str, bytes]]:
        row = reference._decode(raw)
        self.total += len(raw)
        if self.total > MAX_STREAM:
            raise reference.PrivateError("LIMIT")
        kind, seq, glob = row.get("event_type"), row.get("seq_num"), row.get("global_seq_num")
        if (
            type(kind) is not int
            or kind not in (9, 11, 15)
            or type(seq) is not int
            or seq < 0
            or type(glob) is not int
            or glob < 0
        ):
            raise reference.PrivateError("DATA")
        if (
            kind in self.sequence and seq != self.sequence[kind] + 1
        ) or glob <= self.global_sequence:
            self.sequence_ok = False
        self.sequence[kind], self.global_sequence = seq, glob
        if kind == 9:
            payload = row["event"]["exec"]
            target, args = payload["target"], payload.get("args")
            if reference._owned(target, self.manifest.marker):
                if (
                    args
                    and args[1:] == ["--ready"]
                    and reference._token(target)[5] in self.ready_pids
                ):
                    self.ready_tokens.add(reference._token(target))
                if self.collecting and args and args[1:] == ["--sample", self.manifest.nonce]:
                    self.marker_count += 1
                    self.marker = reference._identity(target)
            if (
                self.collecting
                and _role(target, self.manifest) == "SSH_CLIENT"
                and type(payload.get("env")) is list
                and f"EFORGE_SSH_REFERENCE_TOKEN={self.manifest.nonce}" in payload["env"]
            ):
                self.client_count += 1
                self.client = reference._identity(target)
        elif kind == 15:
            process = row["process"]
            if (
                reference._token(process) in self.ready_tokens
                and row["event"]["exit"].get("stat") == 0
            ):
                self.ready = True
            if self.collecting and reference._identity(process) == self.marker:
                self.marker_exit = row["event"]["exit"].get("stat") == 0
            if self.collecting and reference._identity(process) == self.client:
                self.client_exit = True
        if self.collecting:
            self.ring.append((raw, row))
            self.size += len(raw)
            while len(self.ring) > MAX_ROWS or self.size > MAX_BYTES:
                old, _ = self.ring.popleft()
                self.size -= len(old)
                self.evicted = True
        return []

    def retained(self) -> list[bytes]:
        """Persist nothing unless both controlled endpoints and the root are proved."""
        if self.client_count != 1 or self.marker_count != 1 or not self.marker_exit:
            return []
        rows = [row for _, row in self.ring]
        sample = next(
            (
                i
                for i, row in enumerate(rows)
                if row["event_type"] == 9
                and reference._identity(row["event"]["exec"]["target"]) == self.marker
            ),
            None,
        )
        if sample is None:
            return []
        receiver = select_receiver(rows, sample, self.manifest)
        if not receiver:
            return []
        client = [
            i
            for i, row in enumerate(rows)
            if (
                row["event_type"] == 9
                and reference._identity(row["event"]["exec"]["target"]) == self.client
            )
            or (row["event_type"] == 15 and reference._identity(row["process"]) == self.client)
        ]
        selected = sorted(set(receiver + client))
        if len(selected) > MAX_RETAINED:
            raise reference.PrivateError("LIMIT")
        return [self.ring[i][0] for i in selected]


def _word(value: int, manifest: Manifest, *, group: bool = False) -> WordClass:
    if value == 0:
        return "ZERO"
    if value == (manifest.gid if group else manifest.uid):
        return "LOCAL_GROUP" if group else "LOCAL_USER"
    return "SSHD_ACCOUNT" if value == 75 else "UNATTRIBUTED" if value == 2**32 - 1 else "OTHER"


def _descriptors(
    payload: dict, pipes: dict[int, str] | None = None
) -> tuple[tuple[Descriptor, ...], Check, Check]:
    fds = payload.get("fds")
    if type(fds) is not list or len(fds) > 64:
        return (), "FAIL", "INCONCLUSIVE"
    if pipes is None:
        pipes = {}
    result = []
    slots = []
    for value in fds:
        fd, kind = value.get("fd"), value.get("fdtype")
        if type(fd) is not int or fd < 0 or fd in slots:
            return (), "FAIL", "INCONCLUSIVE"
        slots.append(fd)
        group = "NOT_PIPE"
        if kind == 6:
            pipe = value.get("pipe", {}).get("pipe_id")
            if type(pipe) is not int or not 0 <= pipe < 2**64:
                return (), "FAIL", "INCONCLUSIVE"
            group = pipes.setdefault(
                pipe, tuple("ABCDEFGHIJKLMNOP")[len(pipes)] if len(pipes) < 16 else "OTHER"
            )
        result.append(
            Descriptor(
                slot=f"FD{fd}" if fd <= 15 else "OTHER",
                kind={1: "VNODE", 2: "SOCKET", 6: "PIPE"}.get(kind, "OTHER"),
                pipe_group=group,
            )
        )
    last = payload.get("last_fd")
    return (
        tuple(result),
        "PASS",
        reference._check(type(last) is int and last == max(slots, default=-1)),
    )


def _arguments(role: Role, payload: dict, manifest: Manifest, root: Path) -> Check:
    if role == "SSH_CLIENT":
        return reference._check(payload.get("args") == _client_arguments(root, manifest))
    expected = {
        "WRAPPER": [PATHS["WRAPPER"]],
        "SSHD": [PATHS["SSHD"], "-i"],
        "SESSION": [PATHS["SESSION"], "-i", "-R"],
        "AUTH": [PATHS["AUTH"], "-i", "-R"],
        "ZSH": ["-zsh"],
        "BASH": ["-bash"],
        "MARKER": [str(root / "ssh-marker"), "--sample", manifest.nonce],
    }.get(role)
    return "INCONCLUSIVE" if expected is None else reference._check(payload.get("args") == expected)


def _membership(value: object, pid: int, parent: int) -> Literal["SELF", "PARENT", "BOOT", "OTHER"]:
    return (
        "SELF"
        if value == pid
        else "PARENT"
        if value == parent
        else "BOOT"
        if value == 1
        else "OTHER"
    )


def _environment(value: object) -> tuple[bytes, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise reference.PrivateError("DATA")
    return tuple(item.encode() for item in value)


def analyze(raws: list[bytes], manifest: Manifest, root: Path) -> tuple[Phase, ...]:
    """Classify all needed exec facts together without exporting native values."""
    rows = [reference._decode(raw) for raw in raws]
    phases = []
    environments: dict[tuple[int, int, int], tuple[bytes, ...]] = {}
    pipes: dict[int, str] = {}
    for row in rows:
        if row["event_type"] != 9:
            continue
        payload, before = row["event"]["exec"], row["process"]
        target = payload["target"]
        role = _role(target, manifest)
        old, new, parent = (
            reference._token(before),
            reference._token(target),
            reference._token(target, "parent_audit_token"),
        )
        responsible = reference._token(target, "responsible_audit_token")
        descriptors, complete, maximum = _descriptors(payload, pipes)
        parent_process = next(
            (
                item["process"]
                for item in rows
                if reference._token(item["process"])[5::2] == parent[5::2]
            ),
            None,
        )
        value = payload.get("entitlements")
        template = TEMPLATES.get(role)
        template_matches = (
            type(value) is dict
            and template is not None
            and set(value) == set(template)
            and all(
                type(value[key]) is type(expected) and value[key] == expected
                for key, expected in template.items()
            )
        )
        types = (
            tuple(
                sorted(
                    {
                        {
                            bool: "BOOLEAN",
                            int: "INTEGER",
                            str: "STRING",
                            list: "ARRAY",
                            type(None): "NULL",
                        }.get(type(item), "OTHER")
                        for item in value.values()
                    }
                )
            )
            if type(value) is dict
            else ("NULL",)
            if value is None
            else ("OTHER",)
        )
        cwd = payload.get("cwd")
        path = cwd.get("path") if type(cwd) is dict else None

        try:
            reference.decode_endpoint_security_record(json.dumps(row))
        except (ValueError, TypeError, ValidationError):
            shape: Check = "FAIL"
        else:
            shape = "PASS"

        phases.append(
            Phase(
                role=role,
                before_role=_role(before, manifest),
                native_shape=shape,
                shape_excluding_entitlements=reference._shape_without_entitlements(row),
                retained_fork="PASS"
                if any(
                    item["event_type"] == 11
                    and support._matches_execution(item["event"]["fork"]["child"], before)
                    for item in rows
                )
                else "INCONCLUSIVE",
                same_lifetime=reference._check(
                    old[5] == new[5] and reference._birth(before) == reference._birth(target)
                ),
                parent_role=_role(parent_process, manifest)
                if parent_process is not None
                else "OTHER",
                credentials=tuple(_word(new[i], manifest, group=i in (2, 4)) for i in (1, 2, 3, 4)),
                audit_user=_word(new[0], manifest),
                audit_origin_preserved=reference._check((old[0], old[6]) == (new[0], new[6])),
                parentage_preserved=reference._check(
                    reference._token(before, "parent_audit_token") == parent
                ),
                parent_is_boot_pid=reference._check(parent[5] == 1),
                original_parent_matches_parent=reference._check(
                    target.get("original_ppid") == target.get("ppid")
                ),
                group=_membership(target.get("group_id"), new[5], parent[5]),
                session=_membership(target.get("session_id"), new[5], parent[5]),
                membership_preserved=reference._check(
                    (before.get("group_id"), before.get("session_id"))
                    == (target.get("group_id"), target.get("session_id"))
                ),
                responsibility="SELF"
                if responsible == new
                else "PARENT"
                if responsible == parent
                else "UNSET"
                if not any(responsible)
                else "OTHER",
                before_responsibility_fields=reference.compare_responsible_token_fields(
                    reference._token(before, "responsible_audit_token"), old, new
                ),
                target_responsibility_fields=reference.compare_responsible_token_fields(
                    responsible, old, new
                ),
                security=reference.inspect_native_security(target),
                slice=reference.inspect_native_slice(payload),
                entitlement_template="INCONCLUSIVE"
                if template is None
                else reference._check(template_matches),
                entitlement_types=types,
                arguments_match_template=_arguments(role, payload, manifest, root),
                descriptors=descriptors,
                descriptor_inventory_complete=complete,
                last_fd_matches_maximum=maximum,
                terminal="UNKNOWN"
                if "tty" not in target
                else "ABSENT"
                if target["tty"] is None
                else "PRESENT",
                cwd="ROOT"
                if path == "/"
                else "HOME"
                if path == manifest.home
                else "KIT"
                if path == str(root)
                else "UNKNOWN"
                if path is None
                else "OTHER",
                script_absent=reference._check(payload.get("script", "UNKNOWN") is None),
                dyld_matches_target=reference._check(
                    payload.get("dyld_exec_path") == target.get("executable", {}).get("path")
                ),
                environment_from_previous_exec=reference.compare_environment(
                    environments[reference._identity(before)], _environment(payload.get("env"))
                )
                if reference._identity(before) in environments
                else None,
            )
        )
        environments[reference._identity(target)] = _environment(payload.get("env"))
    return tuple(phases)


def analyze_forks(raws: list[bytes], manifest: Manifest) -> tuple[Fork, ...]:
    """Describe each actual fork without exporting lifetime or execution identifiers."""
    rows = [reference._decode(raw) for raw in raws]
    result = []
    for i, row in enumerate(rows):
        if row["event_type"] != 11:
            continue
        parent, child = row["process"], row["event"]["fork"]["child"]
        old, new = reference._token(parent), reference._token(child)
        next_exec = next(
            (
                item["event"]["exec"]["target"]
                for item in rows[i + 1 :]
                if item["event_type"] == 9 and support._matches_execution(item["process"], child)
            ),
            None,
        )
        result.append(
            Fork(
                parent_role=_role(parent, manifest),
                parent_audit_user=_word(old[0], manifest),
                child_audit_user=_word(new[0], manifest),
                child_credentials=tuple(
                    _word(new[i], manifest, group=i in (2, 4)) for i in (1, 2, 3, 4)
                ),
                next_child_exec=_role(next_exec, manifest)
                if next_exec is not None
                else "NOT_RETAINED",
                audit_origin_preserved=reference._check((old[0], old[6]) == (new[0], new[6])),
                credentials_preserved=reference._check(old[1:5] == new[1:5]),
                membership_preserved=reference._check(
                    (parent.get("group_id"), parent.get("session_id"))
                    == (child.get("group_id"), child.get("session_id"))
                ),
            )
        )
    return tuple(result)


def analyze_exits(raws: list[bytes], manifest: Manifest) -> tuple[Exit, ...]:
    """Classify terminal outcomes without exporting an observed status integer."""
    result = []
    for raw in raws:
        row = reference._decode(raw)
        if row["event_type"] != 15:
            continue
        token = reference._token(row["process"])
        status = row["event"]["exit"].get("stat")
        outcome = "OTHER"
        if type(status) is int and 0 <= status < 2**16:
            if os.WIFEXITED(status):
                outcome = {0: "ZERO", 1: "EXIT_ONE", 255: "EXIT_255"}.get(
                    os.WEXITSTATUS(status), "OTHER_EXIT_CODE"
                )
            elif os.WIFSIGNALED(status):
                outcome = "SIGNALLED"
        result.append(
            Exit(
                role=_role(row["process"], manifest),
                audit_user=_word(token[0], manifest),
                credentials=tuple(
                    _word(token[i], manifest, group=i in (2, 4)) for i in (1, 2, 3, 4)
                ),
                outcome=outcome,
            )
        )
    return tuple(result)


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy reviewed code only, with no commands or native reads."""
    source = Path(__file__).resolve()
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    reference._outside_git(parent)
    root = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-ssh-startup-kit-", dir=parent))
    )
    if destination:
        root.mkdir(mode=0o700)
    root.chmod(0o700)
    docs = source.parents[1] / "docs/design/macos-workstation-feasibility"
    for original, name in (
        (source, CODE[0]),
        (Path(support.__file__), CODE[1]),
        (Path(reference.__file__), CODE[2]),
        (docs / "ssh-startup-reference/ssh_marker.c", CODE[3]),
        (docs / "gui-launch-reference/collector_guard.c", CODE[4]),
        (docs / "ssh-startup-reference/PRIVATE-RUN.md", "PRIVATE-RUN.md"),
    ):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    guard = root / "collector_guard.c"
    code = guard.read_text()
    if code.count("alarm(55);") != 1:
        raise reference.PrivateError("BUILD")
    guard.write_text(
        code.replace("at most 55 seconds", "at most 180 seconds").replace(
            "alarm(55);", "alarm(180);"
        )
    )
    return root


def _root() -> Path:
    root = Path(__file__).resolve().parent
    reference._outside_git(root)
    reference._directory(root)
    if Path(__file__).name != CODE[0]:
        raise reference.PrivateError("LOCATION")
    return root


def setup() -> Report:
    """HUMAN ONLY: compile/sign local controls, query no processes and launch nothing."""
    root = _root()
    version, build = reference._preflight()
    reference._write(root / "SETUP-LOCK", b"SETUP\n")
    for source, output in (
        ("ssh_marker.c", "ssh-marker"),
        ("collector_guard.c", "collector-guard"),
    ):
        reference._command(
            [
                "/usr/bin/clang",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(root / source),
                "-o",
                str(root / output),
            ],
            root,
        )
        (root / output).chmod(0o700)
    reference._command(
        ["/usr/bin/codesign", "--force", "--sign", "-", str(root / "ssh-marker")], root
    )
    account = pwd.getpwuid(os.getuid())
    manifest = Manifest(
        os_version=version,
        os_build=build,
        marker=support._image(root / "ssh-marker"),
        images={role: support._installed_image(Path(path)) for role, path in PATHS.items()},
        guard_sha256=reference._digest(root / "collector-guard"),
        codec_sha256=reference._codec_digest(),
        code_sha256={name: reference._digest(root / name) for name in CODE},
        nonce=uuid.uuid4().hex,
        username=account.pw_name,
        home=account.pw_dir,
        uid=account.pw_uid,
        gid=account.pw_gid,
    )
    reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    return Report(stage="SETUP_READY", step="COMPLETE", provenance="PASS")


def _manifest(root: Path) -> Manifest:
    manifest = Manifest.model_validate_json(reference._read(root / "SETUP.json"))
    if (
        manifest.code_sha256 != {name: reference._digest(root / name) for name in CODE}
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.codec_sha256 != reference._codec_digest()
        or manifest.marker != support._image(root / "ssh-marker")
        or any(
            image != support._installed_image(Path(PATHS[role]))
            for role, image in manifest.images.items()
        )
        or set(manifest.images) != set(PATHS)
    ):
        raise reference.PrivateError("BUILD")
    return manifest


def _client_arguments(root: Path, manifest: Manifest) -> list[str]:
    return [
        "/usr/bin/ssh",
        "-F",
        "/dev/null",
        "-T",
        "-o",
        "IdentityAgent=none",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "HostbasedAuthentication=no",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        "PreferredAuthentications=keyboard-interactive,password",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "ProxyCommand=none",
        "-o",
        "ProxyJump=none",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ControlPersist=no",
        "-o",
        "StrictHostKeyChecking=ask",
        "-o",
        f"UserKnownHostsFile={root / 'known_hosts'}",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-l",
        manifest.username,
        "--",
        "127.0.0.1",
    ]


def connect() -> None:
    """HUMAN ONLY: replace this helper with the controlled client, preserving stdio."""
    root = _root()
    manifest = _manifest(root)
    reference._read(root / "COLLECTOR-READY")
    reference._write(
        root / "CLIENT-CONTROL.json",
        json.dumps({"pid": os.getpid(), "nonce": manifest.nonce}).encode(),
    )
    remote = shlex.join(["exec", str(root / "ssh-marker"), "--sample", manifest.nonce])
    print("PRIVATE_REMOTE_COMMAND (paste this after SSH authentication):\n" + remote, flush=True)
    args = _client_arguments(root, manifest)
    os.execve(args[0], args, dict(os.environ) | {"EFORGE_SSH_REFERENCE_TOKEN": manifest.nonce})


def capture() -> Report:
    """HUMAN ONLY: collect once, keeping unrelated rows off disk and out of reports."""
    root = _root()
    manifest = _manifest(root)
    if reference._preflight() != (manifest.os_version, manifest.os_build):
        raise reference.PrivateError("PLATFORM")
    reference._write(root / "SESSION-LOCK", b"ACTIVE\n")
    run = root / f"run-{uuid.uuid4().hex}"
    run.mkdir(mode=0o700)
    reference._write(root / "ACTIVE-RUN", (run.name + "\n").encode())
    reference._write(run / "provenance.json", manifest.model_dump_json().encode())
    tracker = Tracker(manifest)
    report = Report(provenance="PASS")
    step = "COLLECTOR"
    collector = None
    pump = None
    probes = []
    try:
        collector = subprocess.Popen(
            ["/usr/bin/sudo", "-n", str(root / "collector-guard")],
            env=reference.SAFE_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        pump = reference.Pump(collector, tracker, {})
        deadline, next_probe = time.monotonic() + 10, 0.0
        while time.monotonic() < deadline and not tracker.ready:
            if time.monotonic() >= next_probe and len(probes) < 8:
                probe = reference._start(root / "ssh-marker", "--ready")
                probes.append(probe)
                tracker.ready_pids.add(probe.pid)
                next_probe = time.monotonic() + 1
            pump.tick()
        if not tracker.ready:
            raise reference.PrivateError("COLLECTOR")
        tracker.collecting = True
        step = "CONNECTION"
        reference._write(root / "COLLECTOR-READY", b"READY\n")
        print(
            Report(stage="COLLECTOR_READY", collector_ready="PASS").model_dump_json(
                include={"purpose", "stage", "error"}
            ),
            flush=True,
        )
        deadline = time.monotonic() + 140
        while time.monotonic() < deadline and not (
            tracker.marker_exit is not None and tracker.client_exit
        ):
            pump.tick()
        if tracker.marker_exit is None or not tracker.client_exit:
            raise reference.PrivateError("TIMEOUT")
        # Drain server termination rows without starting another connection.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pump.tick()
        step = "ANALYSIS"
        control = reference._decode(reference._read(root / "CLIENT-CONTROL.json"))
        if (
            tracker.client is None
            or type(control.get("pid")) is not int
            or control["pid"] != tracker.client[0]
            or control.get("nonce") != manifest.nonce
        ):
            raise reference.PrivateError("DATA")
        raws = tracker.retained()
        if not raws or not tracker.sequence_ok:
            raise reference.PrivateError("DATA")
        _manifest(root)
        report = Report(
            stage="COMPLETE",
            step="COMPLETE",
            provenance="PASS",
            collector_ready="PASS",
            bounded_collection="PASS",
            sequence_continuity="PASS",
            client_control="PASS",
            receiver_lineage="PASS",
            marker_exit_zero=reference._check(tracker.marker_exit is True),
            candidate_ring_evicted=tracker.evicted,
            wire_profile=reference._wire_profile(raws),
            phases=analyze(raws, manifest, root),
            forks=analyze_forks(raws, manifest),
            exits=analyze_exits(raws, manifest),
            fork_roles=tuple(
                _role(reference._decode(raw)["event"]["fork"]["child"], manifest)
                for raw in raws
                if reference._decode(raw)["event_type"] == 11
            ),
        )
    except (
        reference.PrivateError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ) as error:
        report = report.model_copy(
            update={
                "error": _failure(error),
                "stage": "ERROR",
                "step": step,
                "collector_ready": reference._check(tracker.ready),
                "candidate_ring_evicted": tracker.evicted,
            }
        )
        raws = []
    finally:
        (root / "COLLECTOR-READY").unlink(missing_ok=True)
        cleaned = reference._stop_collector(collector) if collector is not None else False
        if pump is not None:
            pump.selector.close()
        for probe in probes:
            reference._stop_probe(probe)
        if collector is not None and collector.stdout is not None:
            collector.stdout.close()
    report = report.model_copy(update={"collector_cleanup": reference._check(cleaned)})
    if report.error == "NONE" and cleaned:
        reference._write(run / "ssh-chain-events.jsonl", b"\n".join(raws) + b"\n")
    elif report.error == "NONE":
        report = report.model_copy(update={"error": "COLLECTOR", "stage": "ERROR"})
    reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json(indent=2).encode())
    return report


def _failure(error: BaseException) -> Error:
    if isinstance(error, reference.PrivateError) and error.code in {
        "INPUT",
        "LOCATION",
        "PLATFORM",
        "ROOT_USER",
        "BUILD",
        "COLLECTOR",
        "LIMIT",
        "DATA",
    }:
        return error.code
    return (
        "INTERRUPTED"
        if isinstance(error, KeyboardInterrupt)
        else "IO"
        if isinstance(error, OSError)
        else "INTERNAL"
    )


def main() -> None:
    """Keep malformed input and every native failure inside the fixed report schema."""
    try:
        parser = reference.QuietParser(description=__doc__)
        parser.add_argument(
            "operation", choices=("prepare", "setup", "capture", "connect", "report")
        )
        parser.add_argument("--destination", type=Path)
        parser.add_argument("--private-run", action="store_true")
        args = parser.parse_args()
        if args.operation == "prepare":
            if args.private_run:
                raise reference.PrivateError("INPUT")
            print(prepare(args.destination))
            return
        if not args.private_run or args.destination is not None:
            raise reference.PrivateError("INPUT")
        if args.operation == "connect":
            connect()
            return
        if args.operation == "report":
            root = _root()
            report = Report.model_validate_json(
                reference._read(reference._active(root) / "SHAREABLE-REPORT.json")
            )
        else:
            report = setup() if args.operation == "setup" else capture()
    except (
        reference.PrivateError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
    ) as error:
        report = Report(error=_failure(error))
    print(report.model_dump_json(indent=2), flush=True)


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: print(
        Report(error="INTERNAL").model_dump_json()
    )
    main()

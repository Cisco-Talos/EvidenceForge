# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepare a human-only transient system-launchd reference, never collect as an agent.

Only the nonce-authenticated /usr/bin/true execution and its exact ancestry may
reach private disk. Ambient machine-wide ES input stays in bounded memory.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pwd
import re
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

from pydantic import Field


def _support() -> ModuleType:
    path = Path(__file__).resolve().with_name("ssh_analysis_support.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_ssh_startup_reference.py")
    name = "_eforge_launchd_analysis_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


shared = _support()
support, reference = shared.support, shared.reference
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type Role = Literal["LAUNCHD", "XPCPROXY", "TARGET", "OTHER"]
type LimitScope = Literal["NOT_REACHED", "STREAM_BYTES", "ANCESTRY_ROWS", "FIXED_REPORT"]
type Error = shared.Error | Literal["JOB"]
PATHS = {"LAUNCHD": "/sbin/launchd", "XPCPROXY": "/usr/libexec/xpcproxy"}
PROGRAM = "/usr/bin/true"
CODE = (
    "private_launchd.py",
    "ssh_analysis_support.py",
    "terminal_support.py",
    "reference_support.py",
    "ready_marker.c",
    "collector_guard.c",
    "job_guard.c",
)
MAX_ROWS, MAX_BYTES, MAX_STREAM, MAX_RETAINED = 2048, 32 * 1_048_576, 128 * 1_048_576, 32


class CaptureLimit(reference.PrivateError):
    """A fixed acquisition/analysis limit, with no native detail."""

    def __init__(self, scope: LimitScope) -> None:
        super().__init__("LIMIT")
        self.scope = scope


class Manifest(shared.Manifest):
    """Private immutable controls; marker identifies the system true executable."""

    ready_marker: reference.Image
    job_guard_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Environment(reference.Model):
    """Compare public/controlled environment keys locally; never export values."""

    controlled_values: Check
    duplicate_keys: Literal["ABSENT", "PRESENT"]
    other_keys: Literal["ABSENT", "PRESENT"]
    xpc_service_name: Literal["ABSENT", "TEST_LABEL", "OTHER"]
    xpc_flags: Literal["ABSENT", "ZERO", "NONZERO_HEX", "OTHER"]
    cf_text_encoding: Literal["ABSENT", "ROOT_DEFAULT", "OTHER"]


class Phase(shared.Phase):
    """Shared native execution comparisons with launchd-specific role vocabulary."""

    role: Role
    before_role: Role
    parent_role: Role
    environment: Environment
    entitlements: reference.EntitlementShape
    launcher_entitlements: reference.LauncherEntitlementFacts | None = None


class Snapshot(reference.Model):
    """Native graph facts expressed only through closed aliases and classes."""

    life: shared.Life
    role: Role
    credentials: tuple[shared.WordClass, shared.WordClass, shared.WordClass, shared.WordClass]
    audit_user: shared.WordClass
    audit_session: Literal["BOOT_ORIGIN", "JOB_ORIGIN", "OTHER"]
    audit_session_zero: Check
    group: shared.Life
    session: shared.Life
    parent: shared.Life
    responsible: shared.Life
    responsible_token: Literal["EXACT", "SAME_PID_VERSION_OTHER_WORDS", "UNSET", "OTHER"]
    parent_token_form: Literal[
        "ALL_ZERO", "DEFAULT_UNATTRIBUTED_KERNEL", "KNOWN_EXECUTION", "OTHER"
    ]
    parent_pid_agreement: Check
    original_parent_matches_parent: Check
    zero_parent_ids: Check
    signing_identifier: Literal[
        "TRUE_TEMPLATE", "LAUNCHD_TEMPLATE", "XPCPROXY_TEMPLATE", "NULL", "OTHER"
    ]
    team_identifier: Literal["NULL", "EMPTY", "NONEMPTY", "ABSENT", "OTHER"]
    cdhash_form: Check
    terminal: Literal["ABSENT", "PRESENT", "UNKNOWN"]
    security: reference.NativeSecurityFacts


class GraphEvent(reference.Model):
    """Every retained native fork/exec/exit on the exact controlled spine."""

    kind: Literal["FORK", "EXEC", "EXIT"]
    before: Snapshot
    after: Snapshot | None = None
    native_shape: Check
    arguments: Literal["CONTROLLED_TARGET", "XPCPROXY_JOB_LABEL", "OTHER"] | None = None
    fork_parent_token: Check | None = None
    fork_image_preserved: Check | None = None
    exec_pid_version: Literal["NEXT", "SAME", "OTHER"] | None = None
    exit_outcome: Literal["ZERO", "OTHER_EXIT_CODE", "SIGNALLED", "OTHER"] | None = None


class Report(reference.Model):
    """The only shareable data; no free-text native fields or identifiers."""

    kit_version: Literal[1] = 1
    purpose: Literal["LAUNCHD_ACTIVATION_DIAGNOSTIC"] = "LAUNCHD_ACTIVATION_DIAGNOSTIC"
    collection: Literal["NONCE_AUTHENTICATED_SYSTEM_JOB_ONLY"] = (
        "NONCE_AUTHENTICATED_SYSTEM_JOB_ONLY"
    )
    program: Literal["SYSTEM_TRUE"] = "SYSTEM_TRUE"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: Error = "NONE"
    stage: Literal["ERROR", "SETUP_READY", "COLLECTOR_READY", "COMPLETE", "CLEANUP_COMPLETE"] = (
        "ERROR"
    )
    step: Literal["INPUT", "SETUP", "COLLECTOR", "JOB", "ANALYSIS", "CLEANUP", "COMPLETE"] = "INPUT"
    limit_scope: LimitScope = "NOT_REACHED"
    provenance: Check = "INCONCLUSIVE"
    target_platform: Check = "INCONCLUSIVE"
    collector_ready: Check = "INCONCLUSIVE"
    collector_cleanup: Check = "INCONCLUSIVE"
    job_guard: Check = "INCONCLUSIVE"
    job_registered: Check = "INCONCLUSIVE"
    job_activated: Check = "INCONCLUSIVE"
    job_removed: Check = "INCONCLUSIVE"
    temporary_files_removed: Check = "INCONCLUSIVE"
    bounded_collection: Check = "INCONCLUSIVE"
    sequence_continuity: Check = "INCONCLUSIVE"
    candidate_ring_evicted: bool = False
    target_control: Check = "INCONCLUSIVE"
    root_lineage: Check = "INCONCLUSIVE"
    target_exit_zero: Check = "INCONCLUSIVE"
    wire_profile: Literal["V11", "UNQUALIFIED", "MIXED", "NOT_OBSERVED"] = "NOT_OBSERVED"
    phases: tuple[Phase, ...] = Field(default=(), max_length=8)
    graph: tuple[GraphEvent, ...] = Field(default=(), max_length=MAX_RETAINED)
    unified_log: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"
    other_domains_and_triggers: Literal["NOT_COLLECTED"] = "NOT_COLLECTED"


def _label(manifest: Manifest) -> str:
    return f"org.evidenceforge.reference.launchd.{manifest.nonce}"


def _arguments(manifest: Manifest) -> list[str]:
    return [PROGRAM, "--eforge-launchd-reference", manifest.nonce]


def _role(process: dict, manifest: Manifest) -> shared.Role:
    if process.get("executable", {}).get("path") == PROGRAM and reference._owned(
        process, manifest.marker
    ):
        return "MARKER"
    return next(
        (
            role
            for role, path in PATHS.items()
            if process.get("executable", {}).get("path") == path
            and reference._owned(process, manifest.images[role])
        ),
        "OTHER",
    )


def _public_role(process: dict, manifest: Manifest) -> Role:
    value = _role(process, manifest)
    return "TARGET" if value == "MARKER" else value


def _argument_layout(payload: dict, manifest: Manifest) -> str:
    role = _role(payload["target"], manifest)
    args = payload.get("args")
    if role == "MARKER" and args == _arguments(manifest):
        return "CONTROLLED_TARGET"
    if role == "XPCPROXY" and args in (
        ["xpcproxy", _label(manifest)],
        [PATHS["XPCPROXY"], _label(manifest)],
    ):
        return "XPCPROXY_JOB_LABEL"
    return "OTHER"


def _argument_check(_role: str, payload: dict, manifest: Manifest, _root: Path) -> Check:
    return reference._check(_argument_layout(payload, manifest) != "OTHER")


def _environment(payload: dict, manifest: Manifest) -> Environment:
    values = shared._environment(payload.get("env"))
    pairs = [value.decode().split("=", 1) for value in values]
    if any(len(pair) != 2 or not pair[0] for pair in pairs):
        raise reference.PrivateError("DATA")
    items = dict(pairs)
    controls = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "EFORGE_LAUNCHD_REFERENCE_TOKEN": manifest.nonce,
    }
    flags = items.get("XPC_FLAGS")
    return Environment(
        controlled_values=reference._check(
            all(items.get(key) == value for key, value in controls.items())
        ),
        duplicate_keys="PRESENT" if len(items) != len(pairs) else "ABSENT",
        other_keys="PRESENT"
        if set(items) - set(controls) - {"XPC_SERVICE_NAME", "XPC_FLAGS", "__CF_USER_TEXT_ENCODING"}
        else "ABSENT",
        xpc_service_name="ABSENT"
        if "XPC_SERVICE_NAME" not in items
        else "TEST_LABEL"
        if items["XPC_SERVICE_NAME"] == _label(manifest)
        else "OTHER",
        xpc_flags="ABSENT"
        if flags is None
        else "ZERO"
        if flags in {"0", "0x0"}
        else "NONZERO_HEX"
        if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", flags)
        else "OTHER",
        cf_text_encoding="ABSENT"
        if "__CF_USER_TEXT_ENCODING" not in items
        else "ROOT_DEFAULT"
        if items["__CF_USER_TEXT_ENCODING"] == "0x0:0:0"
        else "OTHER",
    )


def _controlled(payload: dict, manifest: Manifest) -> bool:
    if _role(payload["target"], manifest) != "MARKER" or payload.get("args") != _arguments(
        manifest
    ):
        return False
    environment = _environment(payload, manifest)
    return (
        f"EFORGE_LAUNCHD_REFERENCE_TOKEN={manifest.nonce}" in payload["env"]
        and environment.duplicate_keys == "ABSENT"
    )


def _life(process: dict) -> tuple[int, int]:
    return reference._token(process)[5], reference._birth(process)


def select(rows: list[dict], sample: int, manifest: Manifest) -> list[int]:
    """Trace only exact execution ancestry; never traverse launchd's other children."""
    selected = {sample}

    def walk(process: dict, limit: int) -> bool:
        if len(selected) > MAX_RETAINED:
            raise CaptureLimit("ANCESTRY_ROWS")
        if _role(process, manifest) == "LAUNCHD" and reference._token(process)[5] == 1:
            return True
        matches = []
        for index in range(limit):
            row = rows[index]
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
            matches.append((index, subject))
        if len(matches) != 1:
            return False
        index, subject = matches[0]
        row = rows[index]
        kind, before = row["event_type"], row["process"]
        if kind == 9 and _life(before) != _life(subject):
            return False
        if (
            kind == 11
            and reference._token(subject, "parent_audit_token")[5::2]
            != reference._token(before)[5::2]
        ):
            return False
        selected.add(index)
        return walk(before, index)

    if not walk(rows[sample]["process"], sample):
        return []
    target = rows[sample]["event"]["exec"]["target"]
    if reference._token(target)[5] <= 1:
        return []
    exits = [
        i
        for i, row in enumerate(rows)
        if i > sample
        and row["event_type"] == 15
        and support._matches_execution(row["process"], target)
    ]
    if len(exits) != 1:
        return []
    selected.add(exits[0])
    if len(selected) > MAX_RETAINED:
        raise CaptureLimit("ANCESTRY_ROWS")
    return sorted(selected)


class Tracker:
    """Bounded ambient ring; Pump always receives an empty write selection."""

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
        self.ready = self.collecting = False
        self.target: tuple[int, int, int] | None = None
        self.target_count = 0
        self.target_exit: bool | None = None

    def accept(self, raw: bytes) -> list[tuple[str, bytes]]:
        row = reference._decode(raw)
        self.total += len(raw)
        if self.total > MAX_STREAM:
            raise CaptureLimit("STREAM_BYTES")
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
            target = payload["target"]
            if (
                reference._owned(target, self.manifest.ready_marker)
                and payload.get("args", [])[1:] == ["--ready"]
                and reference._token(target)[5] in self.ready_pids
            ):
                self.ready_tokens.add(reference._token(target))
            if self.collecting and _controlled(payload, self.manifest):
                self.target_count += 1
                self.target = reference._identity(target)
        elif kind == 15:
            process = row["process"]
            if (
                reference._token(process) in self.ready_tokens
                and row["event"]["exit"].get("stat") == 0
            ):
                self.ready = True
            if self.collecting and reference._identity(process) == self.target:
                self.target_exit = row["event"]["exit"].get("stat") == 0
        if self.collecting:
            self.ring.append((raw, row))
            self.size += len(raw)
            while len(self.ring) > MAX_ROWS or self.size > MAX_BYTES:
                old, _ = self.ring.popleft()
                self.size -= len(old)
                self.evicted = True
        return []

    def retained(self) -> list[bytes]:
        """Release exactly one successful nonce-authenticated target and its spine."""
        if self.target_count != 1 or not self.target_exit or not self.sequence_ok or self.evicted:
            return []
        rows = [row for _, row in self.ring]
        samples = [
            i
            for i, row in enumerate(rows)
            if row["event_type"] == 9 and _controlled(row["event"]["exec"], self.manifest)
        ]
        if len(samples) != 1:
            return []
        return [self.ring[i][0] for i in select(rows, samples[0], self.manifest)]


def analyze(
    raws: list[bytes], manifest: Manifest, root: Path
) -> tuple[tuple[Phase, ...], tuple[GraphEvent, ...]]:
    """Compute fixed exec metadata and exact topology together, before human handoff."""
    rows = [reference._decode(raw) for raw in raws]
    execs = [row for row in rows if row["event_type"] == 9]
    if not rows or len(execs) > 8 or len(rows) > MAX_RETAINED:
        raise CaptureLimit("FIXED_REPORT")
    phases = []
    common = shared.analyze(raws, manifest, root, role_of=_role, arguments_of=_argument_check)
    for phase, row in zip(common, execs, strict=True):
        fields = phase.model_dump()
        for key in ("role", "before_role", "parent_role"):
            if fields[key] == "MARKER":
                fields[key] = "TARGET"
        payload = row["event"]["exec"]
        phases.append(
            Phase(
                **fields,
                environment=_environment(payload, manifest),
                entitlements=reference.entitlement_shape(
                    payload.get("entitlements"), present="entitlements" in payload
                ),
                launcher_entitlements=reference.inspect_launcher_entitlements(payload)
                if fields["role"] == "XPCPROXY"
                else None,
            )
        )
    boot = rows[0]["process"]
    target = next(
        row["event"]["exec"]["target"]
        for row in execs
        if _controlled(row["event"]["exec"], manifest)
    )
    snapshots = [row["process"] for row in rows]
    snapshots += [
        row["event"]["exec"]["target"] if row["event_type"] == 9 else row["event"]["fork"]["child"]
        for row in rows
        if row["event_type"] in (9, 11)
    ]
    aliases: dict[tuple[int, int], shared.Life] = {_life(boot): "BOOT"}
    for process in snapshots:
        if _life(process) not in aliases:
            if len(aliases) > 8:
                raise CaptureLimit("FIXED_REPORT")
            aliases[_life(process)] = f"L{len(aliases) - 1}"

    def by_pid(value: object) -> shared.Life:
        matches = {
            alias for (pid, _), alias in aliases.items() if type(value) is int and pid == value
        }
        return next(iter(matches)) if len(matches) == 1 else "OTHER"

    def by_token(token: tuple[int, ...]) -> tuple[shared.Life, str]:
        if not any(token):
            return "NONE", "UNSET"
        candidates = [item for item in snapshots if reference._token(item)[5::2] == token[5::2]]
        matches = {aliases[_life(item)] for item in candidates}
        if len(matches) != 1:
            return "OTHER", "OTHER"
        return next(iter(matches)), "EXACT" if any(
            reference._token(item) == token for item in candidates
        ) else "SAME_PID_VERSION_OTHER_WORDS"

    def snapshot(process: dict) -> Snapshot:
        words = reference._token(process)
        responsible, agreement = by_token(reference._token(process, "responsible_audit_token"))
        parent, _ = by_token(reference._token(process, "parent_audit_token"))
        parent_token = reference._token(process, "parent_audit_token")
        signing = process.get("signing_id")
        team = process.get("team_id")
        return Snapshot(
            life=aliases[_life(process)],
            role=_public_role(process, manifest),
            credentials=tuple(
                shared._word(words[i], manifest, group=i in (2, 4)) for i in (1, 2, 3, 4)
            ),
            audit_user=shared._word(words[0], manifest),
            audit_session="BOOT_ORIGIN"
            if words[6] == reference._token(boot)[6]
            else "JOB_ORIGIN"
            if words[6] == reference._token(target)[6]
            else "OTHER",
            audit_session_zero=reference._check(words[6] == 0),
            group=by_pid(process.get("group_id")),
            session=by_pid(process.get("session_id")),
            parent=parent,
            responsible=responsible,
            responsible_token=agreement,
            parent_token_form="ALL_ZERO"
            if parent_token == (0,) * 8
            else "DEFAULT_UNATTRIBUTED_KERNEL"
            if parent_token == (2**32 - 1, 0, 0, 0, 0, 0, 0, 0)
            else "KNOWN_EXECUTION"
            if parent not in {"OTHER", "NONE"}
            else "OTHER",
            parent_pid_agreement=reference._check(process.get("ppid") == parent_token[5]),
            original_parent_matches_parent=reference._check(
                process.get("original_ppid") == process.get("ppid")
            ),
            zero_parent_ids=reference._check(
                process.get("ppid") == process.get("original_ppid") == 0
            ),
            signing_identifier="TRUE_TEMPLATE"
            if signing == "com.apple.true"
            else "LAUNCHD_TEMPLATE"
            if signing == "com.apple.xpc.launchd"
            else "XPCPROXY_TEMPLATE"
            if signing == reference.XPCPROXY_SIGNING_ID
            else "NULL"
            if signing is None and "signing_id" in process
            else "OTHER",
            team_identifier="ABSENT"
            if "team_id" not in process
            else "NULL"
            if team is None
            else "EMPTY"
            if team == ""
            else "NONEMPTY"
            if type(team) is str
            else "OTHER",
            cdhash_form=reference._check(
                type(process.get("cdhash")) is str
                and re.fullmatch(r"[0-9a-fA-F]{40}", process["cdhash"]) is not None
            ),
            terminal="UNKNOWN"
            if "tty" not in process
            else "ABSENT"
            if process["tty"] is None
            else "PRESENT",
            security=reference.inspect_native_security(process),
        )

    graph = []
    for row in rows:
        kind = row["event_type"]
        try:
            reference.decode_endpoint_security_record(json.dumps(row))
        except (ValueError, TypeError):
            shape: Check = "FAIL"
        else:
            shape = "PASS"
        fields = {"before": snapshot(row["process"]), "native_shape": shape}
        if kind == 9:
            payload = row["event"]["exec"]
            graph.append(
                GraphEvent(
                    kind="EXEC",
                    **fields,
                    after=snapshot(payload["target"]),
                    arguments=_argument_layout(payload, manifest),
                    exec_pid_version="NEXT"
                    if reference._token(payload["target"])[7]
                    == reference._token(row["process"])[7] + 1
                    else "SAME"
                    if reference._token(payload["target"])[7] == reference._token(row["process"])[7]
                    else "OTHER",
                )
            )
        elif kind == 11:
            child = row["event"]["fork"]["child"]
            graph.append(
                GraphEvent(
                    kind="FORK",
                    **fields,
                    after=snapshot(child),
                    fork_parent_token=reference._check(
                        reference._token(child, "parent_audit_token")
                        == reference._token(row["process"])
                    ),
                    fork_image_preserved=reference._check(
                        all(
                            row["process"]["executable"]["stat"].get(key)
                            == child["executable"]["stat"].get(key)
                            for key in ("st_dev", "st_ino")
                        )
                        and all(
                            row["process"].get(key) == child.get(key)
                            for key in ("cdhash", "signing_id", "team_id")
                        )
                    ),
                )
            )
        else:
            status = row["event"]["exit"].get("stat")
            outcome = (
                "ZERO"
                if type(status) is int and status == 0
                else "SIGNALLED"
                if type(status) is int and os.WIFSIGNALED(status)
                else "OTHER_EXIT_CODE"
                if type(status) is int and os.WIFEXITED(status)
                else "OTHER"
            )
            graph.append(GraphEvent(kind="EXIT", **fields, exit_outcome=outcome))
    return tuple(phases), tuple(graph)


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: copy source/instructions only into an exclusively new private kit."""
    source = Path(__file__).resolve()
    parent = (destination.parent if destination else Path("/private/tmp")).resolve(strict=True)
    reference._outside_git(parent)
    root = (
        parent / destination.name
        if destination
        else Path(tempfile.mkdtemp(prefix="eforge-launchd-kit-", dir=parent))
    )
    if destination:
        root.mkdir(mode=0o700)
    root.chmod(0o700)
    docs = source.parents[1] / "docs/design/macos-workstation-feasibility"
    for original, name in (
        (source, CODE[0]),
        (Path(shared.__file__), CODE[1]),
        (Path(support.__file__), CODE[2]),
        (Path(reference.__file__), CODE[3]),
        (docs / "ssh-startup-reference/ssh_marker.c", CODE[4]),
        (docs / "gui-launch-reference/collector_guard.c", CODE[5]),
        (docs / "launchd-reference/job_guard.c", CODE[6]),
        (docs / "launchd-reference/PRIVATE-RUN.md", "PRIVATE-RUN.md"),
    ):
        shutil.copyfile(original, root / name)
        (root / name).chmod(0o600)
    return root


def _root() -> Path:
    root = Path(__file__).resolve().parent
    reference._outside_git(root)
    reference._directory(root)
    if Path(__file__).name != CODE[0]:
        raise reference.PrivateError("LOCATION")
    return root


def setup() -> Report:
    """HUMAN ONLY: compile/sign controls and hash public images, without running jobs."""
    root = _root()
    version, build = reference._preflight()
    reference._write(root / "SETUP-LOCK", b"SETUP\n")
    for source, output in (
        ("ready_marker.c", "ready-marker"),
        ("collector_guard.c", "collector-guard"),
        ("job_guard.c", "job-guard"),
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
        ["/usr/bin/codesign", "--force", "--sign", "-", str(root / "ready-marker")], root
    )
    account = pwd.getpwuid(os.getuid())
    manifest = Manifest(
        os_version=version,
        os_build=build,
        marker=support._installed_image(Path(PROGRAM)),
        images={role: support._installed_image(Path(path)) for role, path in PATHS.items()},
        ready_marker=support._image(root / "ready-marker"),
        guard_sha256=reference._digest(root / "collector-guard"),
        job_guard_sha256=reference._digest(root / "job-guard"),
        codec_sha256=reference._codec_digest(),
        code_sha256={name: reference._digest(root / name) for name in CODE},
        nonce=uuid.uuid4().hex,
        username=account.pw_name,
        home=account.pw_dir,
        uid=account.pw_uid,
        gid=account.pw_gid,
    )
    reference._write(root / "SETUP.json", manifest.model_dump_json().encode())
    return Report(stage="SETUP_READY", step="COMPLETE", provenance="PASS", target_platform="PASS")


def _manifest(root: Path) -> Manifest:
    manifest = Manifest.model_validate_json(reference._read(root / "SETUP.json"))
    if (
        manifest.code_sha256 != {name: reference._digest(root / name) for name in CODE}
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.job_guard_sha256 != reference._digest(root / "job-guard")
        or manifest.codec_sha256 != reference._codec_digest()
        or manifest.marker != support._installed_image(Path(PROGRAM))
        or manifest.ready_marker != support._image(root / "ready-marker")
        or set(manifest.images) != set(PATHS)
        or any(
            image != support._installed_image(Path(PATHS[role]))
            for role, image in manifest.images.items()
        )
        or manifest.uid != os.getuid()
        or manifest.gid != os.getgid()
        or manifest.terminal_mode != "NON_PTY"
        or manifest.experiment_sha256 is not None
    ):
        raise reference.PrivateError("BUILD")
    return manifest


def _start_job(
    root: Path, manifest: Manifest, *, recovery: bool = False
) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "/usr/bin/sudo",
            "-n",
            str(root / "job-guard"),
            "cleanup" if recovery else "run",
            manifest.nonce,
        ],
        env=reference.SAFE_ENV,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def _finish_job(job: subprocess.Popen[bytes], *, cancel: bool) -> dict[str, Check]:
    """Close cancellation pipe, wait boundedly and parse only literal guard statuses."""
    if cancel and job.stdin is not None:
        try:
            job.stdin.close()
        except OSError:
            pass
    try:
        status = job.wait(timeout=8)
    except subprocess.TimeoutExpired:
        return {"job_removed": "FAIL", "temporary_files_removed": "INCONCLUSIVE"}
    if job.stdout is None:
        raise reference.PrivateError("JOB")
    raw = job.stdout.read(257)
    lines = raw.splitlines()
    allowed = {
        b"REGISTERED",
        b"ACTIVATED",
        b"REMOVED",
        b"FILES_REMOVED",
        b"LOCATION_FAIL",
        b"REGISTRATION_FAIL",
        b"ACTIVATION_FAIL",
        b"REMOVAL_FAIL",
        b"FILES_FAIL",
    }
    if (
        len(raw) > 256
        or len(lines) != len(set(lines))
        or any(line not in allowed for line in lines)
    ):
        raise reference.PrivateError("JOB")
    if status == 0 and not {b"REMOVED", b"FILES_REMOVED"} <= set(lines):
        raise reference.PrivateError("JOB")
    return {"job_guard": reference._check(status == 0)} | {
        key: reference._check(value in lines)
        for key, value in (
            ("job_registered", b"REGISTERED"),
            ("job_activated", b"ACTIVATED"),
            ("job_removed", b"REMOVED"),
            ("temporary_files_removed", b"FILES_REMOVED"),
        )
    }


def _close_job(job: subprocess.Popen[bytes]) -> None:
    failed = False
    for stream in (job.stdin, job.stdout):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                failed = True
    if failed:
        raise reference.PrivateError("JOB")


def cleanup() -> Report:
    """HUMAN ONLY: retry exact job removal using its root-owned content-verified lease."""
    root = _root()
    manifest = _manifest(root)
    job = _start_job(root, manifest, recovery=True)
    try:
        values = _finish_job(job, cancel=False)
    finally:
        _close_job(job)
    passed = all(
        values.get(key) == "PASS" for key in ("job_guard", "job_removed", "temporary_files_removed")
    )
    return Report(
        **values,
        provenance="PASS",
        error="NONE" if passed else "JOB",
        stage="CLEANUP_COMPLETE" if passed else "ERROR",
        step="CLEANUP",
    )


def capture() -> Report:
    """HUMAN ONLY: one automatic bounded collection and transient system-job activation."""
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
    report = Report(provenance="PASS", target_platform="PASS")
    step = "COLLECTOR"
    collector = job = pump = None
    probes = []
    raws: list[bytes] = []
    job_values: dict[str, Check] = {}
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
                probe = reference._start(root / "ready-marker", "--ready")
                probes.append(probe)
                tracker.ready_pids.add(probe.pid)
                next_probe = time.monotonic() + 1
            pump.tick()
        if not tracker.ready:
            raise reference.PrivateError("COLLECTOR")
        print(
            Report(stage="COLLECTOR_READY").model_dump_json(include={"purpose", "stage", "error"}),
            flush=True,
        )
        tracker.collecting = True
        step = "JOB"
        job = _start_job(root, manifest)
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline and job.poll() is None:
            pump.tick()
        if job.poll() is None:
            raise reference.PrivateError("TIMEOUT")
        job_values = _finish_job(job, cancel=False)
        if any(
            job_values.get(key) != "PASS"
            for key in (
                "job_guard",
                "job_registered",
                "job_activated",
                "job_removed",
                "temporary_files_removed",
            )
        ):
            raise reference.PrivateError("JOB")
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            pump.tick()
        step = "ANALYSIS"
        raws = tracker.retained()
        if not raws:
            raise reference.PrivateError("DATA")
        _manifest(root)
        phases, graph = analyze(raws, manifest, root)
        report = Report(
            stage="COMPLETE",
            step="COMPLETE",
            provenance="PASS",
            target_platform="PASS",
            collector_ready="PASS",
            bounded_collection="PASS",
            sequence_continuity="PASS",
            target_control="PASS",
            root_lineage="PASS",
            target_exit_zero="PASS",
            wire_profile=reference._wire_profile(raws),
            phases=phases,
            graph=graph,
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
                "limit_scope": error.scope if isinstance(error, CaptureLimit) else "NOT_REACHED",
            }
        )
        raws = []
    finally:
        try:
            if job is not None and not job_values:
                job_values = _finish_job(job, cancel=True)
        except (reference.PrivateError, OSError, subprocess.SubprocessError):
            job_values = {"job_removed": "FAIL", "temporary_files_removed": "INCONCLUSIVE"}
        finally:
            if job is not None:
                try:
                    _close_job(job)
                except (reference.PrivateError, OSError):
                    report = report.model_copy(
                        update={"error": "JOB", "stage": "ERROR", "step": "CLEANUP"}
                    )
            try:
                cleaned = reference._stop_collector(collector) if collector is not None else False
            except (OSError, subprocess.SubprocessError):
                cleaned = False
            if pump is not None:
                try:
                    pump.selector.close()
                except OSError:
                    cleaned = False
            for probe in probes:
                try:
                    reference._stop_probe(probe)
                except (OSError, subprocess.SubprocessError):
                    cleaned = False
            if collector is not None and collector.stdout is not None:
                try:
                    collector.stdout.close()
                except OSError:
                    cleaned = False
    report = report.model_copy(
        update={
            **job_values,
            "collector_cleanup": reference._check(cleaned),
            "collector_ready": reference._check(tracker.ready),
            "sequence_continuity": reference._check(tracker.sequence_ok),
            "candidate_ring_evicted": tracker.evicted,
        }
    )
    if report.error == "NONE" and not cleaned:
        report = report.model_copy(
            update={"error": "COLLECTOR", "stage": "ERROR", "step": "CLEANUP"}
        )
    if report.error == "NONE":
        reference._write(run / "launchd-chain-events.jsonl", b"\n".join(raws) + b"\n")
    reference._write(run / "SHAREABLE-REPORT.json", report.model_dump_json(indent=2).encode())
    return report


def _failure(error: BaseException) -> Error:
    if isinstance(error, reference.PrivateError) and error.code == "JOB":
        return "JOB"
    return shared._failure(error)


def main() -> None:
    """Expose fixed diagnostics only; prepare is the only agent-safe operation."""
    operation = None
    try:
        parser = reference.QuietParser(description=__doc__)
        parser.add_argument(
            "operation", choices=("prepare", "setup", "capture", "report", "cleanup")
        )
        parser.add_argument("--destination", type=Path)
        parser.add_argument("--private-run", action="store_true")
        args = parser.parse_args()
        operation = args.operation
        if operation == "prepare":
            if args.private_run:
                raise reference.PrivateError("INPUT")
            print(prepare(args.destination))
            return
        if not args.private_run or args.destination is not None:
            raise reference.PrivateError("INPUT")
        if operation == "report":
            report = Report.model_validate_json(
                reference._read(reference._active(_root()) / "SHAREABLE-REPORT.json")
            )
        else:
            report = (
                setup()
                if operation == "setup"
                else cleanup()
                if operation == "cleanup"
                else capture()
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
        report = Report(
            error=_failure(error),
            limit_scope=error.scope if isinstance(error, CaptureLimit) else "NOT_REACHED",
        )
    print(
        report.model_dump_json(
            include={
                "purpose",
                "stage",
                "step",
                "error",
                "limit_scope",
                "job_removed",
                "temporary_files_removed",
                "collector_cleanup",
            }
        )
        if operation == "capture"
        else report.model_dump_json(indent=2),
        flush=True,
    )


if __name__ == "__main__":
    main()

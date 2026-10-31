# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Code-only preparation and explicitly authorized, read-only SSH capture classification."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Literal

from pydantic import Field


def _load_capture() -> ModuleType:
    path = Path(__file__).resolve().with_name("private_ssh_startup.py")
    if not path.exists():
        path = Path(__file__).resolve().with_name("macos_ssh_startup_reference.py")
    name = "_eforge_offline_ssh_capture_support"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("BUILD")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


capture = _load_capture()
reference = capture.reference
type Life = Literal[
    "BOOT",
    "L0",
    "L1",
    "L2",
    "L3",
    "L4",
    "L5",
    "L6",
    "L7",
    "L8",
    "L9",
    "L10",
    "L11",
    "L12",
    "L13",
    "L14",
    "L15",
    "NONE",
    "OTHER",
]
type Check = Literal["PASS", "FAIL", "INCONCLUSIVE"]
type ArgumentLayout = Literal[
    "XPCPROXY_SSH_LABEL",
    "XPCPROXY_SSH_INSTANCE",
    "WRAPPER_PATH_ONLY",
    "WRAPPER_BASENAME_ONLY",
    "WRAPPER_PATH_INETD",
    "WRAPPER_BASENAME_INETD",
    "CATALOG_MATCH",
    "LOGIN_SHELL",
    "OTHER",
]


class Snapshot(reference.Model):
    """Opaque local aliases express relationships; no native identifier is exported."""

    life: Life
    role: capture.Role
    credentials: tuple[capture.WordClass, capture.WordClass, capture.WordClass, capture.WordClass]
    audit_user: capture.WordClass
    audit_session: Literal["BOOT_ORIGIN", "LOGIN_ORIGIN", "OTHER"]
    group: Life
    session: Life
    parent: Life
    responsible: Life
    responsible_token: Literal["EXACT", "SAME_PID_VERSION_OTHER_WORDS", "UNSET", "OTHER"]


class Event(reference.Model):
    """Order and exact lifetime aliases for the bounded SSH core only."""

    kind: Literal["FORK", "EXEC", "EXIT"]
    before: Snapshot
    after: Snapshot | None = None
    arguments: ArgumentLayout | None = None
    fork_only_closed: Check | None = None
    exit_outcome: (
        Literal["ZERO", "EXIT_ONE", "EXIT_255", "OTHER_EXIT_CODE", "SIGNALLED", "OTHER"] | None
    ) = None


class Report(reference.Model):
    review_version: Literal[1] = 1
    purpose: Literal["SSH_CORE_GRAPH_OFFLINE_REVIEW"] = "SSH_CORE_GRAPH_OFFLINE_REVIEW"
    mode: Literal["OFFLINE_ONLY"] = "OFFLINE_ONLY"
    reference_review: Literal["REQUIRED"] = "REQUIRED"
    gate_status: Literal["NOT_EVALUATED"] = "NOT_EVALUATED"
    error: capture.Error = "NONE"
    provenance: Check = "INCONCLUSIVE"
    original_collection_controls: Check = "INCONCLUSIVE"
    core_lineage: Check = "INCONCLUSIVE"
    events: tuple[Event, ...] = Field(default=(), max_length=64)
    collectors: Literal["NOT_STARTED"] = "NOT_STARTED"
    commands: Literal["NOT_STARTED"] = "NOT_STARTED"
    live_queries: Literal["NOT_PERFORMED"] = "NOT_PERFORMED"
    writes: Literal["NONE"] = "NONE"
    other_shell_startup: Literal["NOT_CLASSIFIED"] = "NOT_CLASSIFIED"


def _life(process: dict) -> tuple[int, int]:
    return reference._token(process)[5], reference._birth(process)


def _image_key(process: dict) -> tuple[object, ...]:
    executable = process["executable"]
    metadata = executable["stat"]
    return (
        executable["path"],
        metadata["st_dev"],
        metadata["st_ino"],
        process["cdhash"],
        process["signing_id"],
        process["team_id"],
    )


def _read_model(path: Path, model: type) -> object:
    raw = reference._read(path)
    reference._decode(raw)
    return model.model_validate_json(raw)


def _verified(root: Path, expected: dict[str, str]) -> tuple[object, list[dict]]:
    reference._outside_git(root)
    reference._directory(root)
    manifest = _read_model(root / "SETUP.json", capture.Manifest)
    run = reference._active(root)
    provenance = _read_model(run / "provenance.json", capture.Manifest)
    report = _read_model(run / "SHAREABLE-REPORT.json", capture.Report)
    if (
        manifest != provenance
        or set(expected) != set(capture.CODE)
        or manifest.code_sha256 != expected
        or any(reference._digest(root / name) != digest for name, digest in expected.items())
        or manifest.guard_sha256 != reference._digest(root / "collector-guard")
        or manifest.marker.sha256 != reference._digest(root / "ssh-marker")
        or manifest.codec_sha256 != reference._codec_digest()
        or set(manifest.images) != set(capture.PATHS)
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
        or report.candidate_ring_evicted
        or any(value != "PASS" for value in controls)
    ):
        raise reference.PrivateError("DATA")
    raw = reference._read(run / "ssh-chain-events.jsonl", 32 * reference.MAX_LINE)
    lines = raw.splitlines()
    if not 1 <= len(lines) <= capture.MAX_RETAINED or any(
        not line or len(line) > reference.MAX_LINE for line in lines
    ):
        raise reference.PrivateError("LIMIT")
    rows = [reference._decode(line) for line in lines]
    for line in lines:
        reference.decode_endpoint_security_record(line.decode())
    control = reference._decode(reference._read(root / "CLIENT-CONTROL.json"))
    clients = [
        row
        for row in rows
        if row["event_type"] == 9
        and capture._role(row["event"]["exec"]["target"], manifest) == "SSH_CLIENT"
        and f"EFORGE_SSH_REFERENCE_TOKEN={manifest.nonce}" in row["event"]["exec"]["env"]
    ]
    if (
        len(clients) != 1
        or type(control.get("pid")) is not int
        or control["pid"] != reference._token(clients[0]["event"]["exec"]["target"])[5]
        or control.get("nonce") != manifest.nonce
    ):
        raise reference.PrivateError("DATA")
    return manifest, rows


def _argument_layout(
    role: capture.Role, payload: dict, manifest: object, root: Path
) -> ArgumentLayout:
    args = payload["args"]
    if role == "XPCPROXY" and len(args) == 2 and args[0] in ("xpcproxy", capture.PATHS["XPCPROXY"]):
        if args[1] == "com.openssh.sshd":
            return "XPCPROXY_SSH_LABEL"
        if args[1].startswith("com.openssh.sshd."):
            return "XPCPROXY_SSH_INSTANCE"
    if role == "WRAPPER":
        choices = (
            ([capture.PATHS["WRAPPER"]], "WRAPPER_PATH_ONLY"),
            (["sshd-keygen-wrapper"], "WRAPPER_BASENAME_ONLY"),
            ([capture.PATHS["WRAPPER"], "-i"], "WRAPPER_PATH_INETD"),
            (["sshd-keygen-wrapper", "-i"], "WRAPPER_BASENAME_INETD"),
        )
        return next((label for candidate, label in choices if args == candidate), "OTHER")
    if role in {"ZSH", "BASH"} and args == ["-zsh" if role == "ZSH" else "-bash"]:
        return "LOGIN_SHELL"
    return (
        "CATALOG_MATCH" if capture._arguments(role, payload, manifest, root) == "PASS" else "OTHER"
    )


def classify(rows: list[dict], manifest: object, root: Path) -> Report:
    """Select exact SSH ancestry plus closed fork-only/auth siblings, excluding startup commands."""
    samples = [
        i
        for i, row in enumerate(rows)
        if row["event_type"] == 9
        and reference._owned(row["event"]["exec"]["target"], manifest.marker)
        and row["event"]["exec"]["args"][1:] == ["--sample", manifest.nonce]
    ]
    if len(samples) != 1 or not capture.select_receiver(rows, samples[0], manifest):
        raise reference.PrivateError("DATA")
    sample = samples[0]
    marker = rows[sample]["event"]["exec"]["target"]
    shells = [
        i
        for i, row in enumerate(rows[:sample])
        if row["event_type"] == 9
        and _life(row["event"]["exec"]["target"]) == _life(marker)
        and capture._role(row["event"]["exec"]["target"], manifest) in {"ZSH", "BASH"}
    ]
    if len(shells) != 1:
        raise reference.PrivateError("DATA")
    spine = {shells[0]}
    process, limit = rows[shells[0]]["process"], shells[0]
    while not (capture._role(process, manifest) == "LAUNCHD" and reference._token(process)[5] == 1):
        previous = next(
            (
                i
                for i in range(limit - 1, -1, -1)
                if rows[i]["event_type"] in (9, 11)
                and capture.support._matches_execution(
                    rows[i]["event"]["exec"]["target"]
                    if rows[i]["event_type"] == 9
                    else rows[i]["event"]["fork"]["child"],
                    process,
                )
            ),
            None,
        )
        if previous is None:
            raise reference.PrivateError("DATA")
        spine.add(previous)
        process, limit = rows[previous]["process"], previous
    boot = process
    core = {_life(rows[i]["process"]) for i in spine}
    core.update(
        _life(
            rows[i]["event"]["exec"]["target"]
            if rows[i]["event_type"] == 9
            else rows[i]["event"]["fork"]["child"]
        )
        for i in spine
    )
    for row in rows:
        if (
            row["event_type"] != 11
            or _life(row["process"]) not in core
            or capture._role(row["process"], manifest) not in {"SSHD", "SESSION"}
        ):
            continue
        child = row["event"]["fork"]["child"]
        replacements = [
            item["event"]["exec"]["target"]
            for item in rows
            if item["event_type"] == 9 and _life(item["process"]) == _life(child)
        ]
        if not replacements or all(
            capture._role(item, manifest) == "AUTH" for item in replacements
        ):
            core.add(_life(child))
    allowed = {"LAUNCHD", "XPCPROXY", "WRAPPER", "SSHD", "SESSION", "AUTH", "ZSH", "BASH", "MARKER"}
    selected = []
    for row in rows:
        kind = row["event_type"]
        subject = (
            row["event"]["fork"]["child"]
            if kind == 11
            else row["event"]["exec"]["target"]
            if kind == 9
            else row["process"]
        )
        if _life(subject) not in core or _life(row["process"]) not in core:
            continue
        if (
            capture._role(row["process"], manifest) not in allowed
            or capture._role(subject, manifest) not in allowed
        ):
            raise reference.PrivateError("DATA")
        selected.append(row)
    aliases: dict[tuple[int, int], Life] = {_life(boot): "BOOT"}
    snapshots = []
    for row in selected:
        snapshots.append(row["process"])
        if row["event_type"] in (9, 11):
            snapshots.append(
                row["event"]["exec"]["target"]
                if row["event_type"] == 9
                else row["event"]["fork"]["child"]
            )
    for process in snapshots:
        if _life(process) not in aliases:
            if len(aliases) > 16:
                raise reference.PrivateError("LIMIT")
            aliases[_life(process)] = f"L{len(aliases) - 1}"
    boot_origin = reference._token(boot)[6]
    login_origin = reference._token(marker)[6]

    def by_pid(value: object) -> Life:
        matches = {
            alias for (pid, _birth), alias in aliases.items() if type(value) is int and pid == value
        }
        return next(iter(matches)) if len(matches) == 1 else "OTHER"

    def by_token(token: tuple[int, ...]) -> tuple[Life, str]:
        if not any(token):
            return "NONE", "UNSET"
        candidates = [item for item in snapshots if reference._token(item)[5::2] == token[5::2]]
        labels = {aliases[_life(item)] for item in candidates}
        if len(labels) != 1:
            return "OTHER", "OTHER"
        return next(iter(labels)), "EXACT" if any(
            reference._token(item) == token for item in candidates
        ) else "SAME_PID_VERSION_OTHER_WORDS"

    def snapshot(process: dict) -> Snapshot:
        words = reference._token(process)
        responsible, match = by_token(reference._token(process, "responsible_audit_token"))
        parent, _ = by_token(reference._token(process, "parent_audit_token"))
        return Snapshot(
            life=aliases[_life(process)],
            role=capture._role(process, manifest),
            credentials=tuple(
                capture._word(words[i], manifest, group=i in (2, 4)) for i in (1, 2, 3, 4)
            ),
            audit_user=capture._word(words[0], manifest),
            audit_session="BOOT_ORIGIN"
            if words[6] == boot_origin
            else "LOGIN_ORIGIN"
            if words[6] == login_origin
            else "OTHER",
            group=by_pid(process.get("group_id")),
            session=by_pid(process.get("session_id")),
            parent=parent,
            responsible=responsible,
            responsible_token=match,
        )

    events = []
    for row in selected:
        before = snapshot(row["process"])
        if row["event_type"] == 9:
            payload = row["event"]["exec"]
            role = capture._role(payload["target"], manifest)
            events.append(
                Event(
                    kind="EXEC",
                    before=before,
                    after=snapshot(payload["target"]),
                    arguments=_argument_layout(role, payload, manifest, root),
                )
            )
        elif row["event_type"] == 11:
            child = row["event"]["fork"]["child"]
            replacements = [
                item
                for item in selected
                if item["event_type"] == 9 and _life(item["process"]) == _life(child)
            ]
            exits = [
                item
                for item in selected
                if item["event_type"] == 15 and _life(item["process"]) == _life(child)
            ]
            closed = (
                len(exits) == 1
                and not replacements
                and capture.support._matches_execution(child, exits[0]["process"])
                and _image_key(child) == _image_key(exits[0]["process"])
            )
            events.append(
                Event(
                    kind="FORK",
                    before=before,
                    after=snapshot(child),
                    fork_only_closed="PASS" if closed else "INCONCLUSIVE",
                )
            )
        else:
            outcome = capture.analyze_exits([json.dumps(row).encode()], manifest)[0].outcome
            events.append(Event(kind="EXIT", before=before, exit_outcome=outcome))
    return Report(
        provenance="PASS",
        original_collection_controls="PASS",
        core_lineage="PASS",
        events=tuple(events),
    )


def review_existing(root: Path, expected: dict[str, str]) -> Report:
    """AUTHORIZED READ ONLY: validate existing private artifacts, then return fixed labels."""
    manifest, rows = _verified(root, expected)
    return classify(rows, manifest, root)


def prepare(destination: Path | None = None) -> Path:
    """AGENT SAFE: prepare code only; never open an existing private kit."""
    root = capture.prepare(destination)
    shutil.copyfile(Path(__file__).resolve(), root / "private_ssh_review.py")
    (root / "private_ssh_review.py").chmod(0o600)
    expected = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in capture.CODE
    }
    reference._write(root / "OFFLINE-EXPECTED.json", json.dumps(expected).encode())
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
        expected = reference._decode(reference._read(own_root / "OFFLINE-EXPECTED.json"))
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
    ) as error:
        report = Report(error=capture._failure(error))
    print(report.model_dump_json(indent=2), flush=True)


if __name__ == "__main__":
    sys.excepthook = lambda _kind, _value, _traceback: print(
        Report(error="INTERNAL").model_dump_json()
    )
    main()

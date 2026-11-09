# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Offline second-host Code reference checks; return fixed findings, never rows.

This Python 3.9+ transport tool reads only the new reference kit. Admission to
production generation is a separate decision. No collector or app is launched.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType


def load(name: str, candidates: tuple[str, ...]) -> ModuleType:
    """Load one reviewed co-located tool, supporting its deployed filename."""
    root = Path(__file__).resolve().parent
    path = next(root / item for item in candidates if (root / item).is_file())
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("CODE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


capture = load(
    "_eforge_process_capture", ("process_reference.py", "macos_remote_process_reference.py")
)
shape = load(
    "_eforge_filesystem_review", ("filesystem_review.py", "macos_remote_filesystem_review.py")
)
support = capture.support
EXEC_FIELDS = frozenset(
    (
        "target",
        "script",
        "cwd",
        "args",
        "env",
        "fds",
        "last_fd",
        "image_cputype",
        "image_cpusubtype",
        "dyld_exec_path",
        "entitlements",
    )
)
EXEC_LABELS = {
    "/bin/zsh": "ZSH",
    "/bin/bash": "BASH",
    "/bin/sh": "SH",
    "/bin/ps": "PS",
    "/usr/bin/env": "ENV",
    "/usr/bin/dscl": "DSCL",
    "/usr/bin/uname": "UNAME",
    "/usr/bin/locale": "LOCALE",
    "/usr/bin/codesign": "CODESIGN",
    "/usr/bin/security": "SECURITY",
    "/usr/bin/xattr": "XATTR",
    "/usr/sbin/sysctl": "SYSCTL",
    "/usr/sbin/ioreg": "IOREG",
    "/usr/sbin/system_profiler": "SYSTEM_PROFILER",
    "/Applications/Visual Studio Code.app/Contents/Resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/darwin-arm64/rg": "BUNDLED_RG",
}
NODE_ROLES = {
    "vs/workbench/api/node/extensionHostProcess": "EXTENSION_HOST",
    "vs/code/electron-utility/sharedProcess/sharedProcessMain": "SHARED_PROCESS",
    "vs/platform/terminal/node/ptyHostMain": "PTY_HOST",
    "vs/platform/files/node/watcher/watcherMain": "FILE_WATCHER",
    "vs/platform/agentHost/node/agentHostMain": "AGENT_HOST",
}


def process_shape(row: dict, process: dict) -> bool:
    """Reuse common snapshot checks without changing the saved source record."""
    view = dict(row, process=process, event_type=15, event={"exit": {"stat": 0}})
    return shape.row_shape(view)


def row_shape(row: dict) -> bool:
    """Check v11 process-event layouts independently of graph admission."""
    if not process_shape(row, row.get("process")):
        return False
    event = row.get("event", {})
    kind = row.get("event_type")
    if kind == 15:
        return (
            set(event) == {"exit"}
            and set(event["exit"]) == {"stat"}
            and type(event["exit"]["stat"]) is int
        )
    if kind == 11:
        return (
            set(event) == {"fork"}
            and set(event["fork"]) == {"child"}
            and process_shape(row, event["fork"]["child"])
        )
    if kind != 9 or set(event) != {"exec"}:
        return False
    payload = event["exec"]
    if set(payload) != EXEC_FIELDS or not process_shape(row, payload["target"]):
        return False
    if not shape.file_shape(payload["cwd"]) or (
        payload["script"] is not None and not shape.file_shape(payload["script"])
    ):
        return False
    if any(
        type(payload[name]) is not list or any(type(item) is not str for item in payload[name])
        for name in ("args", "env")
    ):
        return False
    if any(
        type(payload[name]) is not int for name in ("last_fd", "image_cputype", "image_cpusubtype")
    ):
        return False
    if type(payload["dyld_exec_path"]) is not str or type(payload["fds"]) is not list:
        return False
    for descriptor in payload["fds"]:
        if type(descriptor) is not dict or any(
            type(descriptor.get(name)) is not int for name in ("fd", "fdtype")
        ):
            return False
        if descriptor["fdtype"] == 6:
            if set(descriptor) != {"fd", "fdtype", "pipe"} or type(descriptor["pipe"]) is not dict:
                return False
            if (
                set(descriptor["pipe"]) != {"pipe_id"}
                or type(descriptor["pipe"]["pipe_id"]) is not int
            ):
                return False
        elif set(descriptor) != {"fd", "fdtype"}:
            return False
    return payload["entitlements"] is None or type(payload["entitlements"]) is dict


def relationships(
    rows: list[dict], images: list[dict], root: str, *, matcher: object | None = None
) -> dict:
    """Independently walk retained edges and report a bounded technical census."""
    if matcher is None:
        matcher = capture.Graph(images, root)
    roots = [index for index, row in enumerate(rows) if matcher.is_main(row)]
    if not roots:
        raise ValueError("MAIN")
    first = roots[0]
    main_row = rows[first]
    main = main_row["event"]["exec"]["target"]
    before = main_row["process"]
    main_life = capture.lifetime(main)
    # Ancestry proves only these exact backwards edges. It never grants the
    # ancestor permission to contribute other children to the experiment.
    ancestors = {capture.identity(before)}
    explained = {first}
    for _ in range(3):
        for index, row in enumerate(rows[:first]):
            event = row.get("event", {})
            child = event.get("fork", {}).get("child")
            post = event.get("exec", {}).get("target")
            if capture.identity(child) in ancestors or capture.identity(post) in ancestors:
                ancestors.add(capture.identity(row["process"]))
                explained.add(index)
    known = {capture.identity(before), capture.identity(main)}
    births, exits = set(), set()
    labels, roles = {}, dict.fromkeys(capture.ROLE_NAMES, 0)
    node_roles = {}
    roles["MAIN"] = 1
    valid_edges = capture.lifetime(before) == main_life
    cpu_native = True
    for index, row in enumerate(rows):
        kind = row["event_type"]
        actor = row["process"]
        event = row["event"]
        if index < first:
            if index in explained and kind == 11:
                births.add(capture.lifetime(event["fork"]["child"]))
            continue
        if index != first and capture.identity(actor) not in known:
            valid_edges = False
            continue
        explained.add(index)
        if kind == 11:
            child = event["fork"]["child"]
            valid_edges &= capture.identity(child) is not None
            known.add(capture.identity(child))
            births.add(capture.lifetime(child))
        elif kind == 9:
            payload = event["exec"]
            target = payload["target"]
            valid_edges &= (
                capture.lifetime(target) == capture.lifetime(actor)
                and support.token_words(target["audit_token"])[7]
                != support.token_words(actor["audit_token"])[7]
            )
            known.add(capture.identity(target))
            cpu_native &= payload["image_cputype"] == 16777228
            if index != first:
                roles[capture.role(payload["args"], capture.lifetime(target) == main_life)] += 1
            image = next(
                (n for n, item in enumerate(images) if capture.image_matches(target, item)), None
            )
            label = (
                "SELECTED_CODE"
                if image is not None
                else EXEC_LABELS.get(target["executable"]["path"], "UNCLASSIFIED")
            )
            labels[label] = labels.get(label, 0) + 1
            if capture.role(payload["args"], False) == "NODE":
                entrypoints = [
                    value.partition("=")[2]
                    for value in payload["env"]
                    if value.startswith("VSCODE_ESM_ENTRYPOINT=")
                ]
                node_role = (
                    NODE_ROLES.get(entrypoints[0], "UNCLASSIFIED")
                    if len(entrypoints) == 1
                    else "ABSENT_OR_AMBIGUOUS"
                )
                node_roles[node_role] = node_roles.get(node_role, 0) + 1
        elif kind == 15:
            exits.add(capture.lifetime(actor))
        else:
            valid_edges = False
    payload = main_row["event"]["exec"]
    environment = payload["env"]
    return {
        "wire_shapes_match": bool(rows) and all(row_shape(row) for row in rows),
        "all_rows_explained": len(explained) == len(rows),
        "exact_execution_edges": bool(valid_edges),
        "ordered_source_sequences": all(
            rows[index - 1]["global_seq_num"] < rows[index]["global_seq_num"]
            for index in range(1, len(rows))
        ),
        "all_execs_arm64": bool(cpu_native),
        "main_birth_observed": main_life in births,
        "main_exit_observed": main_life in exits,
        "open_lifetimes": len((births | {main_life}) - exits),
        "role_exec_counts": roles,
        "exec_labels": labels,
        "node_role_exec_counts": node_roles,
        "shell_isolation_control": (
            "--force-disable-user-env" in payload["args"]
            and "ZDOTDIR=" + root + "/shell" in environment
            and "VSCODE_CLI=1" in environment
        ),
        "reference_admission": "NOT_EVALUATED",
    }


def review(work: Path) -> dict:
    """Check private artifacts and their hashes before consuming retained rows."""
    for directory in (work, work / "code"):
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("DIRECTORY")
    for name, limit in (
        ("manifest.json", 65536),
        ("REPORT.json", 65536),
        ("controls.json", 65536),
        ("native.ndjson", support.MAX_RETAINED_BYTES),
    ):
        shape.checked_file(work / name, limit)
    manifest = support.decode((work / "manifest.json").read_bytes())
    report = support.decode((work / "REPORT.json").read_bytes())
    if manifest["root"] != str(work) or report != manifest["report"]:
        raise ValueError("PROVENANCE")
    for name in ("native", "controls"):
        if manifest[name + "_sha256"] != support.digest(
            work / (name + ".ndjson" if name == "native" else name + ".json")
        ):
            raise ValueError("PROVENANCE")
    hashes = manifest["provenance"]["code_sha256"]
    if type(hashes) is not dict or set(hashes) != set(capture.CODE_FILES):
        raise ValueError("CODE")
    for name, expected in hashes.items():
        if Path(name).name != name:
            raise ValueError("CODE")
        shape.checked_file(work / "code" / name, support.MAX_RETAINED_BYTES)
        if support.digest(work / "code" / name) != expected:
            raise ValueError("CODE")
    if report["error"] != "NONE" or not all(
        report.get(key) is True
        for key in (
            "collector_ready",
            "app_launch_control",
            "save_control",
            "second_window_control",
            "ordinary_quit",
            "cleanup",
            "installed_code_unchanged",
        )
    ):
        raise ValueError("CONTROLS")
    controls = json.loads((work / "controls.json").read_bytes())
    if (
        type(controls) is not list
        or len(controls) > 10
        or any(type(item) is not dict for item in controls)
    ):
        raise ValueError("CONTROLS")
    launches = [item for item in controls if item.get("kind") == "launch"]
    ends = [item for item in controls if item.get("kind") == "ended"]
    if (
        len(launches) != 1
        or launches[0].get("ok") is not True
        or len(ends) != 1
        or ends[0].get("terminated") is not True
        or ends[0].get("forced") is not False
    ):
        raise ValueError("CONTROLS")
    control_paths = (
        work / "extensions/evidenceforge.native-reference-0.0.1/reference.json",
        work / "workflow-control.json",
        work / "second-window.json",
        work / "save-control.json",
        work / "workspace/example.txt",
    )
    for path in control_paths:
        shape.checked_file(path, 4096)
    reference, workflow, second, saved = [
        support.decode(path.read_bytes()) for path in control_paths[:4]
    ]
    if any(
        item.get("nonce") != reference.get("nonce") for item in (workflow, second, saved)
    ) or reference.get("root") != str(work):
        raise ValueError("CONTROLS")
    if (
        workflow.get("saved") is not True
        or workflow.get("second") is not True
        or second.get("ready") is not True
        or saved.get("saved") is not True
        or control_paths[4].read_text() != "reference save complete\n"
    ):
        raise ValueError("CONTROLS")
    rows = []
    with (work / "native.ndjson").open("rb") as source:
        for line in source:
            if len(rows) >= support.MAX_RETAINED_RECORDS:
                raise ValueError("RECORD_LIMIT")
            rows.append(support.decode(line))
    result = relationships(rows, manifest["images"], str(work))
    result["workflow_controls_match"] = True
    result["stream_complete_control"] = (
        report["stream_sequence_gaps"] == 0 and report["stream_sequence_reordered"] is False
    )
    return result


def main() -> None:
    root = Path(__file__).resolve().parent
    runs = sorted(path for path in root.glob("vscode-run-*") if (path / "code").is_dir())
    reports = []
    for work in runs[:2]:
        try:
            reports.append(review(work))
        except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError):
            reports.append(
                {"error": "REFERENCE_CHECK_FAILED", "reference_admission": "NOT_EVALUATED"}
            )
    print(
        json.dumps(
            {"schema_version": 1, "runs": reports, "run_limit_exceeded": len(runs) > 2},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

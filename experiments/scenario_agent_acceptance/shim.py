"""Standalone instrumented eforge policy shim copied into clean workspaces."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

MAX_CAPTURE_BYTES = 2_000_000


def _append_event(path: Path, event: dict[str, Any]) -> None:
    payload = (json.dumps(event, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _contained(root: Path, raw: str) -> bool:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
    except OSError:
        return False
    return resolved == root or root in resolved.parents


def _scenario_argument(args: list[str]) -> str | None:
    if not args:
        return None
    if args[0] in {"validate", "resolve"} and len(args) > 1:
        return args[1]
    return None


def _allowed(args: list[str], workspace: Path) -> tuple[bool, str | None, str | None]:
    if not args:
        return False, "missing eforge command", "unsupported"
    if args in (["--version"], ["-V"]):
        return True, None, None
    if args in (["--help"], ["-h"]):
        return True, None, None
    command = args[0]
    if command == "schema":
        allowed = len(args) >= 2 and "--json" in args
        return (
            allowed,
            None if allowed else "schema requires a selector and --json",
            (None if allowed else "unsupported"),
        )
    if command == "info":
        allowed = len(args) >= 2
        return (
            allowed,
            None if allowed else "info requires a field",
            (None if allowed else "unsupported"),
        )
    if command == "validate":
        if len(args) < 2 or "--json" not in args:
            return False, "validate requires a scenario and --json", "unsupported"
        forbidden = {"--oob-host", "--project-root"}
        if forbidden.intersection(args):
            return False, "validate OOB and project-root overrides are forbidden", "forbidden"
        contained = _contained(workspace, args[1])
        return (
            contained,
            None if contained else "scenario path escapes the clean workspace",
            (None if contained else "forbidden"),
        )
    if command == "resolve":
        required = {"--json", "--explain-composition"}
        forbidden = {"--output", "-o", "--oob-host", "--project-root"}
        if not required.issubset(args) or forbidden.intersection(args):
            return False, "resolve must be non-writing JSON composition inspection", "forbidden"
        if len(args) < 2:
            return False, "resolve requires a scenario", "unsupported"
        contained = _contained(workspace, args[1])
        return (
            contained,
            None if contained else "scenario path escapes the clean workspace",
            (None if contained else "forbidden"),
        )
    if command == "pack" and len(args) >= 2 and args[1] in {"list", "show", "validate"}:
        if "--project-root" in args:
            return False, "pack project-root overrides are forbidden", "forbidden"
        return True, None, None
    dangerous = command in {
        "generate",
        "install-skills",
        "validate-config",
    } or (command == "pack" and len(args) >= 2)
    return (
        False,
        f"eforge command is outside the read-only policy: {command}",
        "forbidden" if dangerous else "unsupported",
    )


def _snapshot(
    workspace: Path, artifact_root: Path, sequence: int, scenario: str | None
) -> str | None:
    if scenario is None:
        return None
    path = Path(scenario)
    if not path.is_absolute():
        path = workspace / path
    if not path.is_file() or path.is_symlink() or not _contained(workspace, str(path)):
        return None
    content = path.read_bytes()
    if len(content) > MAX_CAPTURE_BYTES:
        return None
    digest = hashlib.sha256(content).hexdigest()
    destination = artifact_root / "snapshots" / f"{sequence:04d}-{digest}.yaml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.write_bytes(content)
    return digest


def main() -> int:
    """Enforce policy, delegate to the packaged CLI, and capture one bounded event."""

    workspace = Path(os.environ["EFORGE_ACCEPTANCE_WORKSPACE"]).resolve()
    artifact_root = Path(os.environ["EFORGE_ACCEPTANCE_ARTIFACTS"]).resolve()
    trace_path = Path(os.environ["EFORGE_ACCEPTANCE_TRACE"]).resolve()
    real_eforge = Path(os.environ["EFORGE_ACCEPTANCE_REAL_EFORGE"]).resolve()
    sequence_path = artifact_root / "sequence"
    try:
        sequence = int(sequence_path.read_text(encoding="utf-8")) + 1
    except (FileNotFoundError, ValueError):
        sequence = 1
    sequence_path.parent.mkdir(parents=True, exist_ok=True)
    sequence_path.write_text(str(sequence), encoding="utf-8")
    args = sys.argv[1:]
    allowed, reason, policy_class = _allowed(args, workspace)
    scenario = _scenario_argument(args)
    scenario_digest = _snapshot(workspace, artifact_root, sequence, scenario)
    started = time.monotonic()
    if not allowed:
        event = {
            "event_schema_version": "1.0",
            "sequence": sequence,
            "kind": "eforge_command",
            "argv": args,
            "allowed": False,
            "policy_reason": reason,
            "policy_class": policy_class,
            "exit_code": 64,
            "duration_seconds": time.monotonic() - started,
            "scenario_digest": scenario_digest,
            "stdout": "",
            "stderr": f"eforge acceptance policy: {reason}\n",
        }
        _append_event(trace_path, event)
        sys.stderr.write(event["stderr"])
        return 64
    completed = subprocess.run(
        [str(real_eforge), *args],
        cwd=workspace,
        capture_output=True,
        check=False,
    )
    stdout = completed.stdout[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    stderr = completed.stderr[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    event = {
        "event_schema_version": "1.0",
        "sequence": sequence,
        "kind": "eforge_command",
        "argv": args,
        "allowed": True,
        "policy_reason": None,
        "policy_class": None,
        "exit_code": completed.returncode,
        "duration_seconds": time.monotonic() - started,
        "scenario_digest": scenario_digest,
        "stdout": stdout,
        "stderr": stderr,
    }
    _append_event(trace_path, event)
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())

"""Prepare real subprocess fixtures for POSIX and Windows Studio tests."""

from __future__ import annotations

import os
import re
from pathlib import Path


def prepare_script(path: Path, *, codex: bool = False) -> Path:
    """Keep POSIX shebangs; explicitly select Python scripts on Windows."""
    if os.name != "nt":
        path.chmod(0o755)
        return path
    content = path.read_text(encoding="utf-8")
    if codex:
        # These model-free servers must acknowledge the Windows-only preflight
        # before exercising the same transport/history/turn tests as POSIX.
        def readiness(match: re.Match[str]) -> str:
            indent = match[1]
            return (
                match[0]
                + "\n"
                + indent
                + "if request.get('method') == 'windowsSandbox/readiness':\n"
                + indent
                + "    print(json.dumps({'id': request['id'], 'result': {'status': 'ready'}}), flush=True)\n"
                + indent
                + "    continue"
            )

        content, count = re.subn(r"(?m)^([ \t]*)request = json.loads\(line\)$", readiness, content)
        if count != 1:
            raise AssertionError("The fake Codex server must have one JSON request ingress")
    target = path.with_suffix(".py")
    path.unlink()
    target.write_text(content, encoding="utf-8")
    return target

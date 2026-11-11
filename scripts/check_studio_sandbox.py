"""Run the native, model-free Codex permission contract on the current platform."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys


def main() -> None:
    """Require an installed Codex CLI; this dedicated gate must never silently skip."""
    command = shutil.which("codex")
    if command is None:
        raise RuntimeError("Install the pinned Codex CLI before running native permission checks")
    subprocess.run(
        [sys.executable, "-m", "pytest", "--no-cov", "tests/unit/test_studio_chat_sandbox.py"],
        check=True,
        env={**os.environ, "EFORGE_NATIVE_CODEX_BIN": command},
    )


if __name__ == "__main__":
    main()

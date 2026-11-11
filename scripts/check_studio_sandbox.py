"""Run the native, model-free Codex permission contract on the current platform."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    """Require an installed Codex CLI; this dedicated gate must never silently skip."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--studio-resources", type=Path)
    arguments = parser.parse_args()
    command = shutil.which("codex")
    if command is None:
        raise RuntimeError("Install the pinned Codex CLI before running native permission checks")
    environment = {**os.environ, "EFORGE_NATIVE_CODEX_BIN": command}
    with tempfile.TemporaryDirectory(prefix="eforge codex private 汉 ") as temporary:
        if arguments.studio_resources is not None:
            if sys.platform != "win32":
                parser.error("Installed Studio sandbox probing currently requires Windows")
            from evidenceforge.studio.windows_runtime import install_runtime

            root = install_runtime(arguments.studio_resources.resolve(), Path(temporary) / "data")
            environment["EFORGE_NATIVE_STUDIO_CLI"] = str(root / "Scripts/eforge.exe")
        subprocess.run(
            [sys.executable, "-m", "pytest", "--no-cov", "tests/unit/test_studio_chat_sandbox.py"],
            check=True,
            env=environment,
        )


if __name__ == "__main__":
    main()

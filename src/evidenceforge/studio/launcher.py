"""Source-run entry point for the Tauri desktop shell."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Launch the checked-out desktop UI with this Python environment."""
    root = Path(__file__).resolve().parents[3]
    frontend = root / "desktop-ui"
    if not (frontend / "node_modules").is_dir():
        raise SystemExit("Install frontend dependencies first: cd desktop-ui && npm install")
    try:
        result = subprocess.run(
            ["npm", "run", "tauri", "dev"],
            cwd=frontend,
            env={**os.environ, "EFORGE_STUDIO_PYTHON": sys.executable},
            check=False,
        )
    except FileNotFoundError as error:
        raise SystemExit("Node.js and npm are required to run the source desktop app") from error
    raise SystemExit(result.returncode)

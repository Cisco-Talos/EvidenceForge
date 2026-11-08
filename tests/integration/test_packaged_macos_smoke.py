"""The shared installed-CLI smoke exercises real Mac generation and evaluation."""

import os
import sys
from pathlib import Path

import pytest
from scripts.verify_studio_runtime import verify_macos_native


@pytest.mark.slow
def test_macos_native_installed_cli_smoke(tmp_path: Path) -> None:
    cli = Path(sys.executable).parent / ("eforge.exe" if sys.platform == "win32" else "eforge")
    verify_macos_native(cli, tmp_path, dict(os.environ))

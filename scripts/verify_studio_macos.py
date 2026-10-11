"""Verify a packaged macOS app's private runtime and resources in isolation."""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path

from verify_studio_runtime import verify_runtime


def main() -> None:
    """Verify the relocated packaged runtime using the common Unix acceptance checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    arguments = parser.parse_args()
    resources = arguments.app.resolve() / "Contents/Resources/runtime"
    architecture = "aarch64" if platform.machine() == "arm64" else "x86_64"
    print(json.dumps(verify_runtime(resources, architecture), indent=2))


if __name__ == "__main__":
    main()

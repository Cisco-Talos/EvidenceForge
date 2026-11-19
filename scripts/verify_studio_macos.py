"""Verify a packaged macOS app's private runtime and resources in isolation."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import tempfile
from pathlib import Path

from verify_studio_runtime import verify_runtime


def verify_signature(app: Path) -> None:
    """Require the complete bundle signature Gatekeeper checks for downloaded copies."""
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)


def verify_disk_image_app(dmg: Path) -> None:
    """Verify the app exactly as users drag it from the disk image."""
    with tempfile.TemporaryDirectory(prefix="eforge-dmg-") as mount:
        subprocess.run(
            [
                "/usr/bin/hdiutil",
                "attach",
                "-nobrowse",
                "-readonly",
                "-mountpoint",
                mount,
                str(dmg),
            ],
            check=True,
            capture_output=True,
        )
        try:
            verify_signature(Path(mount) / "EvidenceForge Studio.app")
        finally:
            subprocess.run(["/usr/bin/hdiutil", "detach", mount], check=True, capture_output=True)


def main() -> None:
    """Verify signatures, then the relocated runtime using the common Unix checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("--dmg", type=Path, help="Also verify the app inside this disk image")
    arguments = parser.parse_args()
    verify_signature(arguments.app.resolve())
    if arguments.dmg is not None:
        verify_disk_image_app(arguments.dmg.resolve())
    resources = arguments.app.resolve() / "Contents/Resources/runtime"
    architecture = "aarch64" if platform.machine() == "arm64" else "x86_64"
    print(json.dumps(verify_runtime(resources, architecture), indent=2))


if __name__ == "__main__":
    main()

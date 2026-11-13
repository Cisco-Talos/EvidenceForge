"""Run the portable Studio source gate without depending on shell glob expansion."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    """Run every Studio/desktop unit module, leaving shared recovery to its gate."""
    recovery = {
        "test_studio_runtime.py",
        "test_studio_state_durability.py",
        "test_studio_sessions.py",
        "test_studio_ownership.py",
        "test_studio_state_contracts.py",
    }
    directory = Path("tests/unit")
    tests = sorted(
        {
            *directory.glob("test_studio_*.py"),
            *directory.glob("test_desktop_*.py"),
            directory / "test_resource_prediction.py",
        }
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--no-cov",
            "--maxfail=5",
            *(str(test) for test in tests if test.name not in recovery),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()

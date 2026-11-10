"""Run the single shared native source recovery gate for CI and installer builders."""

from __future__ import annotations

import subprocess
import sys


def main() -> None:
    """Execute routine durability/helper cases and the native slow crash matrix."""
    commands = [
        [
            "tests/integration/test_studio_state_upgrade.py",
            "tests/integration/test_studio_state_edges.py",
            "tests/integration/test_studio_state_crashes.py",
            "tests/integration/test_studio_state_migrations.py",
            "tests/unit/test_studio_state_durability.py",
            "tests/unit/test_studio_state_contracts.py",
        ],
        [
            "tests/unit/test_studio_sessions.py",
            "tests/integration/test_studio_helper.py",
            "tests/unit/test_studio_runtime.py",
            "tests/unit/test_studio_ownership.py",
            "tests/integration/test_studio_ownership.py",
        ],
        [
            "-m",
            "slow",
            "tests/integration/test_studio_state_crashes.py",
            "tests/integration/test_studio_state_edges.py",
            "tests/integration/test_studio_state_migrations.py",
        ],
    ]
    for arguments in commands:
        subprocess.run([sys.executable, "-m", "pytest", "--no-cov", *arguments], check=True)


if __name__ == "__main__":
    main()

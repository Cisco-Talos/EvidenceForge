"""Capture native foreground contract cases and compare raw evidence bytes."""

from pathlib import Path

from cleanup_foreground_contract import CASES
from cleanup_native_matrix import run_matrix

if __name__ == "__main__":
    run_matrix(
        driver=Path(__file__).with_name("cleanup_foreground_contract.py"),
        cases=CASES,
        description=__doc__,
    )

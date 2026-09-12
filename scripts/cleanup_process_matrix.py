"""Capture native process contract cases and compare raw evidence bytes."""

from pathlib import Path

from cleanup_native_matrix import run_matrix
from cleanup_process_contract import CASES

if __name__ == "__main__":
    run_matrix(
        driver=Path(__file__).with_name("cleanup_process_contract.py"),
        cases=CASES,
        description=__doc__,
    )

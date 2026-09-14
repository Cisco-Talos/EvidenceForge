"""Run the frozen canonical protocol comparison matrix."""

from pathlib import Path

from cleanup_native_matrix import run_matrix
from cleanup_network_contract import CASES

if __name__ == "__main__":
    run_matrix(
        driver=Path(__file__).with_name("cleanup_network_contract.py"),
        cases=CASES,
        description=__doc__,
    )

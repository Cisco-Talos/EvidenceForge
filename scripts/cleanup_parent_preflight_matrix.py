"""Compare frozen parent selection and process preflight evidence in fresh processes."""

from pathlib import Path

from cleanup_native_matrix import run_matrix
from cleanup_parent_preflight_contract import CASES

if __name__ == "__main__":
    run_matrix(
        driver=Path(__file__).with_name("cleanup_parent_preflight_contract.py"),
        cases=CASES,
        description=__doc__,
    )

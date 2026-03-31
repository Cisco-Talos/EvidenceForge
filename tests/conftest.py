"""Shared pytest fixtures for EvidenceForge tests.

This module provides common fixtures used across unit and integration
test suites.
"""

import random
from pathlib import Path

import pytest

from evidenceforge.utils.rng import _thread_local


def pytest_addoption(parser):
    """Register custom CLI options."""
    parser.addoption(
        "--include-slow",
        action="store_true",
        default=False,
        help="Include slow tests (large dataset generation, 100+ users)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip tests marked @pytest.mark.slow unless --include-slow is passed."""
    if config.getoption("--include-slow"):
        return
    skip_slow = pytest.mark.skip(reason="slow test — pass --include-slow to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


@pytest.fixture(autouse=True)
def _reset_rng():
    """Reset all RNG state before each test for deterministic results.

    The thread-local RNG in _get_rng() accumulates state across tests.
    Deleting the attribute forces re-creation with the same seed on next call.
    """
    if hasattr(_thread_local, "rng"):
        del _thread_local.rng
    random.seed(42)


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory.

    Returns:
        Path to tests/fixtures/
    """
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def scenarios_dir(fixtures_dir: Path) -> Path:
    """Path to the test scenario fixtures directory.

    Returns:
        Path to tests/fixtures/scenarios/
    """
    return fixtures_dir / "scenarios"


@pytest.fixture
def configs_dir(fixtures_dir: Path) -> Path:
    """Path to the test config fixtures directory.

    Returns:
        Path to tests/fixtures/configs/
    """
    return fixtures_dir / "configs"


@pytest.fixture
def sample_logs_dir(fixtures_dir: Path) -> Path:
    """Path to the sample logs fixtures directory.

    Returns:
        Path to tests/fixtures/sample_logs/
    """
    return fixtures_dir / "sample_logs"


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Temporary directory for test output files.

    Args:
        tmp_path: pytest's built-in temporary directory fixture

    Returns:
        Path to a clean temporary output directory
    """
    output = tmp_path / "output"
    output.mkdir()
    return output

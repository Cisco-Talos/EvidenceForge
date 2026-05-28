# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

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
    parser.addoption(
        "--include-external-parsers",
        action="store_true",
        default=False,
        help="Include tests that run third-party parser containers",
    )


def pytest_collection_modifyitems(config, items):
    """Skip opt-in test groups unless their matching CLI flag is passed."""
    skip_slow = pytest.mark.skip(reason="slow test — pass --include-slow to run")
    skip_external_parser = pytest.mark.skip(
        reason="external parser test — pass --include-external-parsers to run"
    )
    for item in items:
        if "slow" in item.keywords and not config.getoption("--include-slow"):
            item.add_marker(skip_slow)
        if "external_parser" in item.keywords and not config.getoption(
            "--include-external-parsers"
        ):
            item.add_marker(skip_external_parser)


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

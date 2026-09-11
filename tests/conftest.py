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

import hashlib
import random
from pathlib import Path

import pytest

from evidenceforge.utils.rng import _thread_local


def pytest_addoption(parser):
    """Register custom CLI options."""
    parser.addoption(
        "--include-external-parsers",
        action="store_true",
        default=False,
        help="Include tests that run third-party parser containers",
    )
    parser.addoption(
        "--slow-shard-count",
        action="store",
        default=1,
        type=int,
        help="Split slow tests into this many deterministic shards",
    )
    parser.addoption(
        "--slow-shard-index",
        action="store",
        default=0,
        type=int,
        help="Run this zero-based deterministic slow-test shard",
    )


def _slow_shard_index(nodeid: str, shard_count: int) -> int:
    """Return the stable shard index for one collected slow test."""

    digest = hashlib.sha256(nodeid.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big") % shard_count


def _validate_slow_shard_coordinates(*, shard_count: int, shard_index: int) -> None:
    """Reject invalid slow-test shard coordinates."""

    if shard_count < 1:
        raise pytest.UsageError("--slow-shard-count must be at least 1")
    if shard_index < 0 or shard_index >= shard_count:
        raise pytest.UsageError("--slow-shard-index must be between 0 and --slow-shard-count - 1")


def _partition_slow_items(
    items: list[pytest.Item],
    *,
    shard_count: int,
    shard_index: int,
) -> tuple[list[pytest.Item], list[pytest.Item]]:
    """Partition slow items while leaving other marker selection to pytest."""

    retained: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        if (
            "slow" not in item.keywords
            or _slow_shard_index(item.nodeid, shard_count) == shard_index
        ):
            retained.append(item)
        else:
            deselected.append(item)
    return retained, deselected


def _validate_test_tiers(items: list[pytest.Item]) -> None:
    """Reject tests assigned to more than one cost tier."""

    overlapping = [
        item.nodeid for item in items if "slow" in item.keywords and "soak" in item.keywords
    ]
    if overlapping:
        rendered = "\n".join(f"  - {nodeid}" for nodeid in overlapping)
        raise pytest.UsageError("Tests must not be marked both 'slow' and 'soak':\n" + rendered)


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Enforce exclusive cost tiers and skip unrequested external parser tests."""
    _validate_test_tiers(items)
    shard_count = config.getoption("slow_shard_count")
    shard_index = config.getoption("slow_shard_index")
    _validate_slow_shard_coordinates(shard_count=shard_count, shard_index=shard_index)
    if shard_count > 1:
        retained, deselected = _partition_slow_items(
            items,
            shard_count=shard_count,
            shard_index=shard_index,
        )
        items[:] = retained
        config.hook.pytest_deselected(items=deselected)

    skip_external_parser = pytest.mark.skip(
        reason="external parser test — pass --include-external-parsers to run"
    )
    for item in items:
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

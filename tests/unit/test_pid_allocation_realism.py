# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for realistic PID allocation (P0 fix).

PID allocation should use a random distribution instead of a fixed choice
list, producing non-uniform gaps that don't create a statistical fingerprint.
"""

import statistics
from datetime import datetime

import pytest

from evidenceforge.generation.state_manager import StateManager


@pytest.fixture
def sm():
    """Fresh StateManager with current time set."""
    manager = StateManager()
    manager.set_current_time(datetime(2024, 3, 18, 12, 0, 0))
    return manager


def _allocate_n_pids(sm: StateManager, n: int, os: str = "windows") -> list[int]:
    """Allocate n PIDs on a test system."""
    if os == "linux":
        # Seed systemd as the root parent for Linux (PID 0 is the kernel)
        init_pid = sm.create_process(
            system="TEST-01",
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system",
            username="root",
            integrity_level="System",
        )
    image = r"C:\test.exe" if os == "windows" else "/usr/bin/test"
    parent_pid = 4 if os == "windows" else init_pid
    pids = []
    for i in range(n):
        pid = sm.create_process(
            system="TEST-01",
            parent_pid=parent_pid,
            image=image,
            command_line=f"test{i}",
            username="SYSTEM" if os == "windows" else "root",
            integrity_level="System",
        )
        pids.append(pid)
    return pids


class TestWindowsPidAllocation:
    """Windows PIDs must be multiples of 4, monotonically increasing, with non-uniform gaps."""

    def test_windows_pids_are_multiples_of_4(self, sm):
        """Every Windows PID must be divisible by 4."""
        pids = _allocate_n_pids(sm, 200, os="windows")
        for pid in pids:
            assert pid % 4 == 0, f"PID {pid} is not a multiple of 4"

    def test_pids_are_monotonically_increasing(self, sm):
        """PIDs must never decrease (until wrap-around)."""
        pids = _allocate_n_pids(sm, 200, os="windows")
        for i in range(1, len(pids)):
            assert pids[i] > pids[i - 1], (
                f"PID {pids[i]} at index {i} is not greater than {pids[i - 1]}"
            )

    def test_pid_gaps_are_non_uniform(self, sm):
        """PID gaps should NOT come from a small fixed set of values.

        The old implementation used choice([1,1,1,1,2,3,5,8]) * 4,
        producing gaps only from {4,8,12,20,32}. The new implementation
        should produce a wider variety of gap values.
        """
        pids = _allocate_n_pids(sm, 200, os="windows")
        gaps = [(pids[i] - pids[i - 1]) // 4 for i in range(1, len(pids))]
        unique_gaps = set(gaps)

        # Old implementation produced exactly 5 unique gap multipliers: {1,2,3,5,8}
        # New implementation should produce significantly more diversity
        assert len(unique_gaps) > 10, (
            f"Only {len(unique_gaps)} unique gap values found: {sorted(unique_gaps)[:20]}. "
            f"Expected diverse gaps from a continuous distribution, not a fixed set."
        )

    def test_pid_gap_distribution_has_heavy_tail(self, sm):
        """At least some gaps should be large (>60 PIDs) to simulate background churn."""
        pids = _allocate_n_pids(sm, 500, os="windows")
        gaps = [pids[i] - pids[i - 1] for i in range(1, len(pids))]
        max_gap = max(gaps)

        assert max_gap > 60, (
            f"Maximum PID gap was only {max_gap}. Expected at least some gaps > 60 "
            f"to simulate background process churn consuming PIDs."
        )

    def test_pid_gaps_have_reasonable_variance(self, sm):
        """Gap standard deviation should be meaningful — not all similar-sized."""
        pids = _allocate_n_pids(sm, 200, os="windows")
        gaps = [pids[i] - pids[i - 1] for i in range(1, len(pids))]
        stdev = statistics.stdev(gaps)
        mean = statistics.mean(gaps)

        # Coefficient of variation (CV) should indicate real variance
        cv = stdev / mean if mean > 0 else 0
        assert cv > 0.5, (
            f"Gap CV is only {cv:.2f} (stdev={stdev:.1f}, mean={mean:.1f}). "
            f"Expected CV > 0.5 for realistic PID gap diversity."
        )


class TestLinuxPidAllocation:
    """Linux PIDs increment by 1+, monotonically increasing."""

    def test_linux_pids_are_positive(self, sm):
        """Linux PIDs must be positive integers."""
        pids = _allocate_n_pids(sm, 100, os="linux")
        for pid in pids:
            assert pid > 0, f"Linux PID {pid} is not positive"

    def test_linux_pids_monotonically_increasing(self, sm):
        """Linux PIDs must increase monotonically."""
        pids = _allocate_n_pids(sm, 100, os="linux")
        for i in range(1, len(pids)):
            assert pids[i] > pids[i - 1]

    def test_linux_pids_have_varied_gaps(self, sm):
        """Linux PID gaps should not all be 1."""
        pids = _allocate_n_pids(sm, 100, os="linux")
        gaps = [pids[i] - pids[i - 1] for i in range(1, len(pids))]
        unique_gaps = set(gaps)
        assert len(unique_gaps) > 3, (
            f"Only {len(unique_gaps)} unique gap values: {sorted(unique_gaps)}. "
            f"Expected varied gaps."
        )


class TestPidWraparound:
    """PID wraparound should not reuse PIDs of still-running processes."""

    def test_pid_wraparound_skips_allocated(self, sm):
        """After wraparound, allocated PIDs still in running_processes are skipped."""
        # Force a high starting PID near the wrap threshold
        sm._pid_counters["TEST-01"] = 65500
        sm._pid_os["TEST-01"] = "windows"

        # Create a few processes near the boundary
        pids_near_boundary = _allocate_n_pids(sm, 20, os="windows")

        # All PIDs should be unique (no collisions with still-running processes)
        assert len(set(pids_near_boundary)) == len(pids_near_boundary), (
            "Duplicate PIDs found near wraparound boundary"
        )

        # After wrap, PIDs should still be positive and reasonable
        for pid in pids_near_boundary:
            assert pid > 0, f"PID {pid} after wrap is not positive"
            assert pid % 4 == 0, f"PID {pid} after wrap is not a multiple of 4"

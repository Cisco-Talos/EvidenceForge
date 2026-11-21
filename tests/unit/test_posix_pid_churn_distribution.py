# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""POSIX hidden process counts retain workload texture and allocation capacity."""

import random
from collections import Counter

import evidenceforge.generation.state_manager as state_module
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.utils.rng import generation_seed_scope


def test_posix_churn_schedule_is_seed_scoped_pure_and_replayable() -> None:
    before = random.getstate()
    with generation_seed_scope(41):
        first = StateManager._build_linux_pid_weekly_churn_prefix("posix-worker")
        replay = StateManager._build_linux_pid_weekly_churn_prefix("posix-worker")
        other = StateManager._build_linux_pid_weekly_churn_prefix("posix-other")
    with generation_seed_scope(43):
        changed_seed = StateManager._build_linux_pid_weekly_churn_prefix("posix-worker")
    assert first == replay
    assert first != other and first != changed_seed
    assert random.getstate() == before


def test_posix_churn_preserves_every_half_minute_reorder_lane() -> None:
    for host in ["linux-batch", "mac-workstation", "quiet-service", "busy-service"]:
        prefix = StateManager._build_linux_pid_weekly_churn_prefix(host)
        for seconds in range(0, 7 * 24 * 3600, 30):
            start = StateManager._linux_pid_hidden_churn_from_prefix(prefix, seconds)
            end = StateManager._linux_pid_hidden_churn_from_prefix(prefix, seconds + 30)
            assert end - start >= state_module._LINUX_PID_REORDER_LANE_WIDTH


def test_posix_workload_counts_do_not_censor_quiet_regimes_into_a_shared_floor() -> None:
    all_counts: list[int] = []
    all_ten_minute_deltas: Counter[int] = Counter()
    host_minimums: set[int] = set()
    for ordinal in range(16):
        prefix = StateManager._build_linux_pid_weekly_churn_prefix(f"posix-workload-{ordinal}")
        counts = [right - left for left, right in zip(prefix[:-1], prefix[1:], strict=True)]
        all_counts.extend(counts)
        deltas = [prefix[index + 10] - prefix[index] for index in range(0, len(prefix) - 10, 10)]
        all_ten_minute_deltas.update(deltas)
        host_minimums.add(min(deltas))
    capacity_count = 2 * state_module._LINUX_PID_REORDER_LANE_WIDTH
    # Integer counts may naturally equal their support boundary. They must not
    # acquire a large censored atom or expose one fleet-wide ten-minute floor.
    assert all_counts.count(capacity_count) / len(all_counts) < 0.05
    assert len(host_minimums) >= 8
    assert max(all_ten_minute_deltas.values()) / all_ten_minute_deltas.total() < 0.02

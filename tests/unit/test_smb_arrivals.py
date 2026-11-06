# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""SMB opportunity planning varies counts and gaps while preserving replay."""

import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import SmbArrivalProfile
from evidenceforge.generation.engine.baseline import _baseline_smb_arrival_offsets


def test_smb_arrivals_are_scoped_bursty_bounded_and_replayable() -> None:
    hour = datetime(2026, 11, 2, 13, tzinfo=UTC)
    first = [
        _baseline_smb_arrival_offsets(f"HOST-{i}", hour + timedelta(hours=j), 300, 900, 42)
        for i in range(12)
        for j in range(6)
    ]
    assert first == [
        _baseline_smb_arrival_offsets(f"HOST-{i}", hour + timedelta(hours=j), 300, 900, 42)
        for i in range(12)
        for j in range(6)
    ]
    assert len({len(values) for values in first}) >= 5
    assert all(
        tuple(sorted(values)) == values and all(0 <= x < 3600 for x in values) for values in first
    )
    gaps = [b - a for values in first for a, b in zip(values, values[1:], strict=False)]
    assert statistics.stdev(gaps) / statistics.mean(gaps) > 0.5
    assert first[0] != _baseline_smb_arrival_offsets("HOST-0", hour, 300, 900, 43)
    assert first[0] != first[1] and first[0] != first[6]
    sparse = [_baseline_smb_arrival_offsets(f"HOST-{i}", hour, 3000, 3600, 42) for i in range(32)]
    assert any(not values for values in sparse) and any(len(values) > 1 for values in sparse)


@pytest.mark.parametrize(
    "patch",
    [
        {"branching_ratio": 1.0},
        {"branching_ratio": -0.1},
        {"excitation_decay_seconds": 0},
        {"excitation_decay_seconds": float("inf")},
        {"candidate_ceiling_multiplier": 1},
    ],
)
def test_smb_arrival_policy_rejects_unstable_or_unbounded_profiles(patch: dict[str, float]) -> None:
    with pytest.raises(ValidationError):
        SmbArrivalProfile.model_validate(patch)


def test_windows_inline_smb_consumes_the_shared_arrival_plan(
    scenarios_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import random
    from unittest.mock import Mock

    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.generation.engine import baseline as baseline_module
    from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
    from tests.unit.test_smb_persistent_production import _forecast, _windows_read_scenario

    scenario = _windows_read_scenario(scenarios_dir)
    arrivals = Mock(return_value=(600.125678,))
    monkeypatch.setattr(baseline_module, "_baseline_smb_arrival_offsets", arrivals)
    with generation_seed_scope(scenario.generation_seed):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path, resource_forecast=_forecast(tmp_path))
        try:
            engine._initialize()
            generator = engine.activity_generator
            user, client = scenario.environment.users[0], scenario.environment.systems[0]
            generator.generate_logon(
                user, client, engine.start_time + timedelta(minutes=1), logon_type=2
            )
            prepared = Mock(wraps=generator.prepare_smb_activity)
            monkeypatch.setattr(generator, "prepare_smb_activity", prepared)
            assert not engine._uses_linux_smb_prepass()
            engine._generate_inline_windows_baseline_smb_activity(
                current_hour=engine.start_time, system=client, rng=random.Random(42), dc_ips=[]
            )
            assert arrivals.call_count == prepared.call_count == 1
            assert arrivals.call_args.args[0] == client.hostname
            assert prepared.call_args.kwargs["time"] == engine.start_time + timedelta(
                seconds=600.125678
            )
            assert generator.state_manager.get_state_summary()["smb_mutations"] > 0
        finally:
            engine._close_emitters()

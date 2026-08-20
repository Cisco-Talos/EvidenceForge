# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for the production engine timing-runtime owner."""

from __future__ import annotations

from pathlib import Path

import pytest

import evidenceforge.generation.engine.core as core_module
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.timing import (
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils.files import load_yaml

_ENGINE_TIMING_NAMESPACE = "shared-timing-v1"


def _minimal_scenario() -> Scenario:
    path = Path(__file__).parents[1] / "fixtures" / "scenarios" / "minimal.yaml"
    return Scenario(**load_yaml(path))


def _engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    generation_seed: int = 73,
    output_name: str = "timing-owner",
) -> GenerationEngine:
    engine = GenerationEngine(
        _minimal_scenario(),
        tmp_path / output_name,
        generation_seed=generation_seed,
    )
    monkeypatch.setattr(engine, "_init_emitters", lambda: None)
    monkeypatch.setattr(engine, "_seed_system_process_trees", lambda: None)
    return engine


def test_engine_constructs_one_timing_runtime_after_warmup_and_injects_exact_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """One engine runtime should own dispatcher, source, network, and activity timing."""

    engine = _engine(tmp_path, monkeypatch)
    constructed: list[dict[str, object]] = []
    runtime_type = TimingRuntime

    def construct_runtime(**kwargs: object) -> TimingRuntime:
        assert hasattr(engine, "warmup_start_time")
        constructed.append(dict(kwargs))
        return runtime_type(**kwargs)

    monkeypatch.setattr(core_module, "TimingRuntime", construct_runtime)

    engine._initialize()

    assert len(constructed) == 1
    runtime = engine.timing_runtime
    assert type(runtime) is TimingRuntime
    assert constructed == [
        {
            "reference_time": engine.warmup_start_time,
            "namespace": _ENGINE_TIMING_NAMESPACE,
            "generation_seed": 73,
        }
    ]
    assert runtime is engine.dispatcher.timing_runtime
    assert runtime is engine.source_timing_planner.timing_runtime
    assert engine.source_timing_planner is engine.dispatcher.source_timing_planner
    assert runtime is engine.dispatcher.network_observation_planner.timing_runtime
    assert engine.dispatcher.network_observation_planner._runtime_injected is True
    assert runtime is engine.activity_generator.timing_runtime
    assert engine.source_timing_planner is engine.activity_generator._source_timing_planner


def test_engine_runtime_uses_warmup_reference_and_explicit_run_seed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Direct initialization should not depend on an ambient seed scope."""

    engine = _engine(tmp_path, monkeypatch, generation_seed=91)

    engine._initialize()

    runtime = engine.timing_runtime
    assert type(runtime) is TimingRuntime
    assert runtime.clocks.reference_time == engine.warmup_start_time
    assert runtime.clocks.reference_time == engine._generation_epoch
    assert runtime.sampler.namespace == _ENGINE_TIMING_NAMESPACE
    assert runtime.sampler.generation_seed == 91


def test_engine_initialization_never_calls_timing_compatibility_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Every production timing owner should receive the explicit engine runtime."""

    def reject_compatibility_default(_cls: type[TimingRuntime]) -> TimingRuntime:
        raise AssertionError("production requested TimingRuntime.compatibility_default")

    monkeypatch.setattr(
        TimingRuntime,
        "compatibility_default",
        classmethod(reject_compatibility_default),
    )
    engine = _engine(tmp_path, monkeypatch)

    engine._initialize()

    assert type(engine.timing_runtime) is TimingRuntime


def test_engine_runtime_seed_is_deterministic_and_run_scoped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Equivalent runs should replay exactly while a different public seed diverges."""

    first = _engine(tmp_path, monkeypatch, generation_seed=123, output_name="first")
    second = _engine(tmp_path, monkeypatch, generation_seed=123, output_name="second")
    different = _engine(tmp_path, monkeypatch, generation_seed=124, output_name="different")
    first._initialize()
    second._initialize()
    different._initialize()
    distribution = TriangularDistribution(minimum=100.0, mode=500.0, maximum=900.0)

    def samples(engine: GenerationEngine) -> tuple[int, ...]:
        runtime = engine.timing_runtime
        assert type(runtime) is TimingRuntime
        return tuple(
            runtime.sampler.sample_microseconds(
                distribution,
                relationship_key="engine.owner.determinism",
                scope=TimingScope(stable_id="same-run", ordinal=ordinal),
                sample_key="gap",
            )
            for ordinal in range(8)
        )

    first_samples = samples(first)
    second_samples = samples(second)
    different_samples = samples(different)

    assert first_samples == second_samples
    assert first_samples != different_samples
    assert first.timing_runtime.audit.snapshot() == second.timing_runtime.audit.snapshot()


def test_engine_runtime_owner_failure_leaves_zero_timing_residue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A downstream construction rejection must not mutate the new timing owner."""

    engine = _engine(tmp_path, monkeypatch, generation_seed=177)

    def reject_dispatcher(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("dispatcher construction rejected")

    monkeypatch.setattr(core_module, "EventDispatcher", reject_dispatcher)

    with pytest.raises(RuntimeError, match="dispatcher construction rejected"):
        engine._initialize()

    runtime = engine.timing_runtime
    assert type(runtime) is TimingRuntime
    census = runtime.census()
    assert census.clocks.live_entries == 0
    assert census.clocks.backing_entries == 0
    assert census.clocks.lookup_count == 0
    assert census.audit.relationship_slots_live == 0
    assert census.audit.distribution_keys_live == 0
    assert census.audit.sample_count == 0
    assert census.audit.repair_count == 0
    assert census.audit.saturation_count == 0
    assert census.audit.fallback_count == 0

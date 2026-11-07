# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Launch admission rejects incomplete truth before process allocation."""

import random
import shlex
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.macos_launch_support import resolve_macos_launch_support
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_finder_generation import _finder_engine


def test_complete_preflight_rejects_unknown_app_metadata_before_any_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True, missing_app_signature=True)
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            with pytest.raises(
                StateError, match="Unsupported native Mac launch.*entitlements_unknown"
            ):
                engine._initialize()
        assert not engine.state_manager.get_processes_on_system("MAC-01")
    finally:
        engine._close_emitters()


def test_execution_boundary_rejects_lost_runtime_policy_without_allocating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True, gui_application="edge")
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time - timedelta(minutes=5))
        image = engine.deployment_registry.application_descriptor("edge", "macos").image_path
        provider = engine.macos_execution_metadata
        provider.profile = provider.profile.model_copy(
            update={
                "code_validation": tuple(
                    rule for rule in provider.profile.code_validation if rule.product_id != "edge"
                )
            }
        )
        support = resolve_macos_launch_support(
            engine.deployment_registry, provider.profile, system.hostname, user.username, image
        )
        assert support.mechanism == "finder" and support.issues == ("image_security_unknown",)
        before = engine.state_manager.materialization_digest()
        with pytest.raises(StateError, match="image_security_unknown.*No process was admitted"):
            generator.generate_process(
                user,
                system,
                engine.start_time + timedelta(minutes=2),
                logon,
                image,
                shlex.join((image,)),
            )
        assert engine.state_manager.materialization_digest() == before
    finally:
        engine._close_emitters()


def test_finder_activity_reuses_the_same_desktop_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = _finder_engine(tmp_path, monkeypatch, native=True, gui_application="macos-finder")
    try:
        with effective_config_scope(engine.compiled_scenario.effective_config):
            engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time - timedelta(minutes=5))
        image = engine.deployment_registry.application_descriptor(
            "macos-finder", "macos"
        ).image_path
        pids = [
            generator.generate_process(
                user,
                system,
                engine.start_time + timedelta(minutes=2 + n),
                logon,
                image,
                shlex.join((image,)),
            )
            for n in range(5)
        ]
        assert min(pids) > 0 and len(set(pids)) == 1
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
        assert census.expected_forks == census.published_forks == 1
        assert census.expected_execs == census.published_execs == 2
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("seed", [1, 42, 123, 349, 20261107])
def test_filesystem_sampling_cannot_resample_later_baseline_ownership(
    seed: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    draws: list[float] = []

    def sample(engine: object, system: object, hour: datetime, rng: random.Random) -> None:
        draws.extend(rng.random() for _ in range(30))

    monkeypatch.setattr(
        "evidenceforge.generation.macos_filesystem_workload.emit_macos_document_workload", sample
    )
    engine = SimpleNamespace(
        activity_generator=SimpleNamespace(
            macos_execution_metadata=SimpleNamespace(
                profile=SimpleNamespace(filesystem_workload=object())
            )
        )
    )
    rng = random.Random(seed)
    before = rng.getstate()
    at = datetime(2026, 11, 7, tzinfo=UTC)
    BaselineMixin._emit_ecar_file_churn(
        engine, SimpleNamespace(hostname="MAC-01"), at, rng, "macos", {}
    )
    assert rng.getstate() == before
    assert rng.choice(("chrome", "edge", "safari")) == random.Random(seed).choice(
        ("chrome", "edge", "safari")
    )
    BaselineMixin._emit_ecar_file_churn(
        engine, SimpleNamespace(hostname="MAC-02"), at, rng, "macos", {}
    )
    assert draws[:30] != draws[30:]

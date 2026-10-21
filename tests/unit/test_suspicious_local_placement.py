# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Local red-herring processes retain canonical mixed-fleet user placement."""

import random
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from evidenceforge.generation.activity.suspicious_benign import (
    generate_suspicious_cli,
    generate_temp_dir_execution,
    generate_unusual_powershell,
)
from evidenceforge.generation.world_model import WorldModel
from tests.unit.test_macos_installed_provisioning import _deployments, _scenario


@pytest.mark.parametrize("compiled", [False, True])
@pytest.mark.parametrize("primary", [False, True])
@pytest.mark.parametrize(
    "producer", [generate_suspicious_cli, generate_temp_dir_execution, generate_unusual_powershell]
)
def test_local_noise_never_moves_an_explicitly_placed_user_to_an_unrelated_host(
    compiled: bool, primary: bool, producer: Callable[..., dict[str, Any] | None]
) -> None:
    scenario = _scenario().model_copy(deep=True)
    if not primary:
        for user in scenario.environment.users:
            user.primary_system = None
    world = WorldModel(scenario, "example.test")
    registry = _deployments(scenario)
    observed = 0
    for seed in range(40):
        result = producer(
            random.Random(seed),
            scenario.environment.users,
            scenario.environment.systems,
            datetime(2026, 10, 21, 14, tzinfo=UTC),
            world_model=world if compiled else None,
        )
        if result is None:
            continue
        observed += 1
        user, system = result["user"], result["system"]
        assert system in world.user_for(user.username).activity_systems
        platform = world.hosts[system.hostname].os_category
        assert registry.user_profile_for(system.hostname, user.username, platform) is not None
        if producer is generate_unusual_powershell:
            assert system.hostname == "WIN-01" and user.username == "robin"
    assert observed


def test_windows_only_noise_is_absent_when_only_mac_actors_are_eligible() -> None:
    scenario = _scenario()
    world = WorldModel(scenario, "example.test")
    user = next(user for user in scenario.environment.users if user.username == "alex")
    for compiled in (False, True):
        assert (
            generate_unusual_powershell(
                random.Random(1),
                [user],
                scenario.environment.systems,
                datetime(2026, 10, 21, 14, tzinfo=UTC),
                world_model=world if compiled else None,
            )
            is None
        )

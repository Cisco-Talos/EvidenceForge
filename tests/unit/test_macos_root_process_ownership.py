# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import random
from types import SimpleNamespace
from unittest.mock import Mock

from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.models.scenario import User
from tests.unit.test_macos_foundations import _TIME, _system


def test_authored_mac_root_process_does_not_create_windows_service_authentication() -> None:
    generator, state, planner = Mock(), Mock(), Mock()
    runtime = SimpleNamespace(
        world_planner=planner,
        state_manager=state,
        activity_generator=generator,
        scenario=SimpleNamespace(environment=SimpleNamespace(service_accounts=[])),
    )
    actor = User(username="root", full_name="Invented administrator", email="root@example.test")
    assert (
        StorylineMixin._resolve_storyline_process_logon_id(
            runtime, actor, _system(), _TIME, random.Random(7)
        )
        == ""
    )
    assert not generator.mock_calls
    assert not state.mock_calls
    assert not planner.mock_calls

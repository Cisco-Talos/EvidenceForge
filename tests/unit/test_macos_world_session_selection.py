# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Default Mac workstation requests retain exact local GUI ownership."""

import random
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from tests.support.macos_ssh import macos_ssh_scenario


@pytest.mark.parametrize("other_kind, other_type", [("network", 3), ("service", 5), ("ssh", 10)])
@pytest.mark.parametrize("requested_kind", [None, "interactive"])
def test_mac_default_session_reuses_gui_before_newer_remote_or_service_session(
    scenarios_dir: Path, other_kind: str, other_type: int, requested_kind: str | None
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    system, user = scenario.environment.systems[0], scenario.environment.users[0]
    state = StateManager()
    at = scenario.time_window.start
    state.set_current_time(at)
    gui = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )
    state.set_current_time(at + timedelta(minutes=1))
    other = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=other_type,
        source_ip="192.0.2.55",
        session_kind=other_kind,
    )
    generator = Mock()
    planner = WorldPlanner(WorldModel(scenario, "example.test"), state, generator)
    close = SessionEndPlan(at + timedelta(hours=1), "storyline", "end-gui")
    result = planner.bootstrap_user_session(
        user,
        system,
        at + timedelta(minutes=2),
        random.Random(7),
        session_kind=requested_kind,
        session_end_plan=close,
        storyline_protected=True,
    )
    assert result.session.logon_id == gui
    assert result.session.end_plan == close and result.session.storyline_protected
    assert state.get_session(other).end_plan is None
    generator.generate_logon.assert_not_called()


def test_explicit_mac_network_session_remains_network(scenarios_dir: Path) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    system, user = scenario.environment.systems[0], scenario.environment.users[0]
    state = StateManager()
    at = scenario.time_window.start
    state.set_current_time(at)
    network = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=3,
        source_ip="192.0.2.55",
        session_kind="network",
    )
    generator = Mock()
    planner = WorldPlanner(WorldModel(scenario, "example.test"), state, generator)
    result = planner.bootstrap_user_session(
        user,
        system,
        at + timedelta(minutes=2),
        random.Random(7),
        session_kind="network",
    )
    assert result.session.logon_id == network
    generator.generate_logon.assert_not_called()


@pytest.mark.parametrize("expired_gui", [False, True])
def test_default_mac_request_bootstraps_gui_when_only_non_gui_sessions_are_eligible(
    scenarios_dir: Path, expired_gui: bool
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    system, user = scenario.environment.systems[0], scenario.environment.users[0]
    state = StateManager()
    at = scenario.time_window.start
    state.set_current_time(at)
    if expired_gui:
        old_gui = state.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state.plan_session_end(old_gui, SessionEndPlan(at + timedelta(minutes=1), "action_bundle"))
    network = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=3,
        source_ip="192.0.2.55",
        session_kind="network",
    )
    generator = Mock()

    def local_logon(**kwargs: object) -> str:
        assert kwargs["logon_type"] == 2
        assert kwargs["source_ip"] == system.ip
        assert kwargs["reuse_required_at"] == at + timedelta(minutes=2)
        return state.create_session(
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )

    generator.generate_logon.side_effect = local_logon
    planner = WorldPlanner(WorldModel(scenario, "example.test"), state, generator)
    result = planner.bootstrap_user_session(
        user,
        system,
        at + timedelta(minutes=2),
        random.Random(7),
    )
    assert result.session.logon_id != network
    assert result.session.session_kind == "interactive"
    generator.generate_logon.assert_called_once()

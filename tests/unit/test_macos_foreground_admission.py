# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Optional foreground work cannot consume a shell reserved by authored intent."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.checkpoints.owner_inventory import (
    GENERATION_ENGINE_CHECKPOINT_FIELDS,
    assert_owner_inventory_covers,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_terminal_applications import _engine as terminal_engine


@pytest.mark.parametrize("reserved", [False, True])
def test_baseline_editor_requires_a_known_release_before_authored_shell_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reserved: bool
) -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["output"]["logs"] = [{"format": "ecar"}]
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [{"user": "alex", "applications": ["macos-terminal", "vim"]}],
        }
    ]
    engine = GenerationEngine(Scenario.model_validate(raw), tmp_path, generation_seed=358)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        generator.ensure_macos_session_shell(user, system, logon, at + timedelta(seconds=1))
        registry = engine.deployment_registry
        profile = registry.user_profile_for(system.hostname, user.username, "macos")
        assert profile is not None
        assignment = registry.user_application_assignment_for_application(profile.profile_id, "vim")
        assert assignment is not None
        select = registry.select_user_application_assignment_for_category
        monkeypatch.setattr(
            type(registry),
            "select_user_application_assignment_for_category",
            lambda _self, profile_id, category, **kwargs: (
                assignment if category == "code" else select(profile_id, category, **kwargs)
            ),
        )
        generator.execute_baseline_activity(
            user,
            system,
            at + timedelta(seconds=10),
            "process_code",
            foreground_deadline=at + timedelta(minutes=1) if reserved else None,
        )
        editors = [
            process
            for process in engine.state_manager.get_processes_on_system(system.hostname)
            if process.image == "/opt/homebrew/bin/vim"
        ]
        assert len(editors) == int(not reserved)
        if editors:
            assert (
                generator.foreground_process_termination_time(system.hostname, editors[0].pid)
                is None
            )
    finally:
        engine._close_emitters()


def test_authored_foreground_deadlines_follow_pending_intents_and_ignore_other_hosts(
    tmp_path: Path,
) -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["output"]["logs"] = [{"format": "ecar"}]
    raw["storyline"] = [
        {
            "id": "query",
            "time": "+30m",
            "actor": "alex",
            "system": "MAC-01",
            "activity": "Use the reserved local shell",
            "events": [{"type": "process", "process_name": "/usr/bin/id"}],
        }
    ]
    raw["red_herrings"] = []
    engine = GenerationEngine(Scenario.model_validate(raw), tmp_path)
    try:
        engine._initialize()
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=10)
        assert engine._macos_authored_foreground_deadline(user, system, at) == (
            engine.start_time + timedelta(minutes=29, seconds=30)
        )
        assert_owner_inventory_covers(
            engine, GENERATION_ENGINE_CHECKPOINT_FIELDS, owner_name="GenerationEngine"
        )
        other = system.model_copy(update={"hostname": "OTHER-MAC"})
        assert engine._macos_authored_foreground_deadline(user, other, at) is None
        engine._storyline_executed.add(0)
        assert engine._macos_authored_foreground_deadline(user, system, at) is None
    finally:
        engine._close_emitters()


def test_prepared_parent_lookup_cannot_borrow_a_future_terminal_shell(tmp_path: Path) -> None:
    engine = terminal_engine(tmp_path, "macos-terminal", native=False)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        future_shell = generator.ensure_macos_session_shell(
            user, system, logon, at + timedelta(minutes=10)
        )
        assert future_shell is not None
        before = engine.state_manager.materialization_digest()
        parent = generator._resolve_existing_prepared_process_parent(
            system=system,
            user=user,
            time=at + timedelta(minutes=5),
            logon_id=logon,
            parent_pid=0,
            process_username=user.username,
        )
        assert parent == 1
        assert engine.state_manager.materialization_digest() == before
        shell = engine.state_manager.get_process(system.hostname, future_shell)
        assert shell is not None and shell.executed_at is not None
        assert shell.start_time < shell.executed_at
        assert (
            generator._resolve_existing_prepared_process_parent(
                system=system,
                user=user,
                time=shell.start_time,
                logon_id=logon,
                parent_pid=0,
                process_username=user.username,
            )
            == 1
        )
        assert (
            generator._process_parents()._macos_existing_parent(
                system, at + timedelta(minutes=5), logon, process_name="/usr/bin/id"
            )
            == future_shell
        )
    finally:
        engine._close_emitters()


def test_terminal_frontier_preserves_an_already_advanced_rdp_owner(tmp_path: Path) -> None:
    engine = terminal_engine(tmp_path, "macos-terminal", native=False)
    try:
        engine._initialize()
        generator = engine.activity_generator
        committed = engine.end_time + timedelta(seconds=5)
        generator.advance_rdp_session_lifecycle_watermark(committed)
        assert generator.terminal_lifecycle_frontier(engine.end_time) == committed
        generator.finalize_rdp_session_lifecycles(
            generator.terminal_lifecycle_frontier(engine.end_time)
        )
        assert generator._rdp_session_lifecycle_frontier() == committed
    finally:
        engine._close_emitters()

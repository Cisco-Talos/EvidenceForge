# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Profiled Mac helpers use canonical parent/session and deployment owners."""

import json
import random
import shlex
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.deployment_registry import UserApplicationAssignment
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import System, User
from tests.support.macos_ssh import macos_ssh_scenario


@dataclass
class HelperContext:
    generator: ActivityGenerator
    user: User
    system: System
    assignment: UserApplicationAssignment
    logon: str
    parent: int
    time: datetime
    emitter: EcarEmitter | None

    def spawn(self, **changes: object) -> tuple[int, ...]:
        values = dict(
            user=self.user,
            system=self.system,
            assignment=self.assignment,
            logon_id=self.logon,
            parent_pid=self.parent,
            time=self.time,
            rng=random.Random(41),
        )
        return self.generator._generate_macos_application_children(**(values | changes))


def _setup(tmp_path: Path, scenarios_dir: Path, collected: bool) -> HelperContext:
    scenario = macos_ssh_scenario(scenarios_dir)
    system, user = scenario.environment.systems[0], scenario.environment.users[0]
    start = scenario.time_window.start
    app = ApplicationEntry.model_validate(application_descriptor("chrome"))
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=(app,)
    )
    state = StateManager()
    state.set_current_time(start - timedelta(hours=1))
    plan = state.plan_process_materialization(
        system=system.hostname,
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        fixed_pid=1,
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    with state.materialization_guard(plan.expected_version):
        state.materialize_process(plan)
    emitter = EcarEmitter(load_format("ecar"), tmp_path / "ecar.json") if collected else None
    emitters = {"ecar": emitter} if emitter else {}
    dispatcher = EventDispatcher(state, emitters, deployment_registry=registry)
    generator = ActivityGenerator(
        state,
        emitters,
        dispatcher=dispatcher,
        identity_directory=IdentityDirectory.from_scenario(scenario),
    )
    generator._scenario_end_time = start + timedelta(hours=1)
    logon = generator.generate_logon(user, system, start)
    at = start + timedelta(seconds=30)
    image = app.platforms["macos"].image_path
    parent = generator.generate_process(user, system, at, logon, image, f'"{image}"', parent_pid=1)
    profile = registry.user_profile_for(system.hostname, user.username, "macos")
    assignment = registry.user_application_assignment_for_application(profile.profile_id, "chrome")
    assert assignment is not None and parent > 0
    return HelperContext(generator, user, system, assignment, logon, parent, at, emitter)


@pytest.mark.parametrize("collected", [True, False])
def test_helpers_have_real_browser_parent_and_close_with_session(
    tmp_path: Path, scenarios_dir: Path, collected: bool
) -> None:
    context = _setup(tmp_path, scenarios_dir, collected)
    generator, system = context.generator, context.system
    state = generator.state_manager
    try:
        children = context.spawn()
        assert 1 <= len(children) <= 3
        identities = [state.get_process_identity(system.hostname, pid) for pid in children]
        parent = state.get_process_identity(system.hostname, context.parent)
        for child in identities:
            assert child.parent_pid == context.parent
            assert child.logon_id == context.logon
            assert child.credentials == parent.credentials
            assert child.started_at > parent.started_at
            assert child.arguments[0] == child.image
            assert child.arguments[1].startswith("--type=")
            assert child.command_line == shlex.join(child.arguments)
            assert child.environment is None
            assert child.image.startswith("/Applications/Google Chrome.app/Contents/Frameworks/")
        from evidenceforge.generation.checkpoints.state_manager_head import (
            _capture_head,
            _restore_head,
        )

        restored = StateManager()
        _restore_head(restored, _capture_head(state))
        for child in identities:
            assert restored.get_process_identity(system.hostname, child.pid) == child
        generator.generate_logoff(
            context.user, system, context.time + timedelta(minutes=3), context.logon
        )
        assert all(state.get_process(system.hostname, pid) is None for pid in children)
    finally:
        if context.emitter:
            context.emitter.close()
    if collected:
        rows = [json.loads(line) for line in (tmp_path / "ecar.json").read_text().splitlines()]
        for child in identities:
            creates = [
                row
                for row in rows
                if row["object"] == "PROCESS"
                and row["action"] == "CREATE"
                and row["pid"] == child.pid
            ]
            assert len(creates) == 1 and creates[0]["ppid"] == context.parent
            assert creates[0]["properties"]["parent_image_path"] == parent.image
            closes = [
                row
                for row in rows
                if row["object"] == "PROCESS"
                and row["action"] == "TERMINATE"
                and row["objectID"] == creates[0]["objectID"]
            ]
            assert len(closes) == 1
            assert closes[0]["timestamp_ms"] > int(
                (context.time + timedelta(minutes=2)).timestamp() * 1000
            )
            assert any(
                row["object"] == "PROCESS"
                and row["action"] == "TERMINATE"
                and row["objectID"] == creates[0]["objectID"]
                for row in rows
            )


@pytest.mark.parametrize("reason", ["parent", "assignment", "session_deadline", "window"])
def test_unavailable_helper_owner_or_deadline_does_not_allocate_processes(
    tmp_path: Path, scenarios_dir: Path, reason: str
) -> None:
    context = _setup(tmp_path, scenarios_dir, False)
    changes: dict[str, object] = {}
    if reason == "parent":
        changes["parent_pid"] = 1
    elif reason == "assignment":
        changes["assignment"] = replace(
            context.assignment, principal="other", materialization_principal="other"
        )
    elif reason == "session_deadline":
        context.generator.state_manager.plan_session_end(
            context.logon, SessionEndPlan(context.time + timedelta(milliseconds=1), "action_bundle")
        )
    else:
        context.generator._scenario_end_time = context.time + timedelta(milliseconds=1)
    before = context.generator.state_manager.materialization_digest()
    assert context.spawn(**changes) == ()
    assert context.generator.state_manager.materialization_digest() == before


def test_baseline_uses_compiled_helpers_without_legacy_child_catalog_lookup(
    tmp_path: Path, scenarios_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.activity import application_catalog

    context = _setup(tmp_path, scenarios_dir, False)

    def reject_legacy(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Compiled Mac activity consulted the legacy child catalog")

    monkeypatch.setattr(application_catalog, "get_child_processes", reject_legacy)
    monkeypatch.setattr(context.generator, "_emit_process_network_correlation", lambda *_args: None)
    context.generator.execute_baseline_activity(
        context.user, context.system, context.time + timedelta(minutes=1), "process_user_apps"
    )
    processes = context.generator.state_manager.get_processes_on_system(context.system.hostname)
    helpers = [process for process in processes if "/Helpers/" in process.image]
    assert helpers
    for child in helpers:
        parent = context.generator.state_manager.get_process(
            context.system.hostname, child.parent_pid
        )
        assert parent.image.endswith("/MacOS/Google Chrome")
        assert parent.logon_id == child.logon_id == context.logon


@pytest.mark.parametrize("allowed, maximum, count", [(False, 1, 0), (True, 1, 1)])
def test_spawn_profile_controls_helper_admission_and_count(
    tmp_path: Path,
    scenarios_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    allowed: bool,
    maximum: int,
    count: int,
) -> None:
    from evidenceforge.generation.activity import spawn_rules

    context = _setup(tmp_path, scenarios_dir, False)
    original = spawn_rules.get_parent_config
    profile = dict(original("macos", "Google Chrome"))
    profile["max_children"] = maximum
    if not allowed:
        profile["children"] = []
    monkeypatch.setattr(
        spawn_rules,
        "get_parent_config",
        lambda os_name, name: (
            profile if name.casefold() == "google chrome" else original(os_name, name)
        ),
    )
    assert len(context.spawn()) == count


def test_config_validator_recognizes_child_binaries_but_still_reports_unknown_children() -> None:
    from evidenceforge.validation.configuration import ValidationResult, _validate_process_chains

    app = {
        "id": "example",
        "personas": [],
        "platforms": {
            "macos": {
                "image_path": "/Applications/Example.app/Contents/MacOS/Example",
                "children": ['"/Applications/Example.app/Contents/Helpers/Worker" --child'],
            }
        },
    }
    result = ValidationResult()
    _validate_process_chains(
        apps=[app],
        result=result,
        process_net_data={},
        sys_proc_data={},
        spawn_data={"macos": {"Example": {"children": ["Worker", "Unknown"]}}},
    )
    assert len(result.issues) == 1 and '"Unknown"' in result.issues[0].message


def test_generic_stale_cleanup_preserves_mac_helper_session_owner(
    tmp_path: Path, scenarios_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.engine import baseline

    context = _setup(tmp_path, scenarios_dir, False)
    children = context.spawn()
    state = context.generator.state_manager
    before = state.materialization_digest()
    engine = SimpleNamespace(
        _system_pids={},
        state_manager=state,
        activity_generator=context.generator,
        scenario=SimpleNamespace(environment=SimpleNamespace(systems=[context.system])),
    )

    def reject_windows_policy(*args: object) -> float:
        raise AssertionError("Mac cleanup must not request a Windows lifetime")

    monkeypatch.setattr(baseline, "_windows_stale_process_target_lifetime", reject_windows_policy)
    baseline.BaselineMixin._terminate_stale_processes(engine, context.time + timedelta(hours=8))
    assert state.materialization_digest() == before
    assert all(state.get_process(context.system.hostname, pid) for pid in children)


def test_baseline_logon_reuses_live_mac_gui_session(
    tmp_path: Path, scenarios_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.activity import generator as activity_module

    context = _setup(tmp_path, scenarios_dir, False)
    state = context.generator.state_manager
    sessions = tuple(state.get_sessions_on_system(context.system.hostname))
    at = context.time + timedelta(minutes=1)
    monkeypatch.setattr(activity_module, "_get_rng", lambda: random.Random(0))
    context.generator.execute_baseline_activity(context.user, context.system, at, "logon")
    assert tuple(state.get_sessions_on_system(context.system.hostname)) == sessions
    assert state.get_session(context.logon).last_activity_time == at


def test_invalid_later_helper_template_allocates_none_of_the_selected_children(
    tmp_path: Path, scenarios_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.models.exceptions import StateError

    class AllHelpersRng(random.Random):
        def randint(self, a: int, b: int) -> int:
            return b

    context = _setup(tmp_path, scenarios_dir, False)
    registry = context.generator.dispatcher.deployment_registry
    original = type(registry).materialize_application_child_command
    calls = 0

    def damage(owner: object, *args: object, **kwargs: object) -> tuple[str, str] | None:
        nonlocal calls
        result = original(owner, *args, **kwargs)
        calls += 1
        if calls == 2:
            return result[0], result[1] + " | cat"
        return result

    monkeypatch.setattr(type(registry), "materialize_application_child_command", damage)
    before = context.generator.state_manager.materialization_digest()
    with pytest.raises(StateError, match="canonical literal argv"):
        context.spawn(rng=AllHelpersRng(41))
    assert calls == 2
    assert context.generator.state_manager.materialization_digest() == before

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Compiled deployment consumers use bounded registry-owned assignment truth."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import textwrap
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation import world_model as world_model_module
from evidenceforge.generation.activity import application_catalog
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.state_manager import ActiveSession, StateManager
from evidenceforge.generation.world_model import WorldModel, WorldPlanner
from evidenceforge.models.scenario import Scenario, System, User

_ACTIVITY_TIME = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
_REPOSITORY_ROOT = Path(__file__).parents[2]
_SCENARIO_PATH = Path(__file__).parents[1] / "fixtures" / "scenarios" / "minimal.yaml"


def _assignment(
    application_id: str,
    *,
    categories: tuple[str, ...] = ("user_app",),
    ordinal: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        assignment_id=f"assignment-{application_id}",
        application_id=application_id,
        eligible_categories=categories,
        selection_ordinal=ordinal,
    )


def _descriptor(
    application_id: str,
    executable: str,
    *,
    categories: tuple[str, ...] = ("user_app",),
    ordinal: int = 0,
    singleton: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        application_id=application_id,
        executable=executable,
        categories=categories,
        selection_ordinal=ordinal,
        singleton_per_session=singleton,
    )


class _CategoryAssignmentRegistry:
    """Sentinel exposing only bounded activity-selection APIs."""

    def __init__(
        self,
        *,
        assignment: SimpleNamespace | None,
        descriptor: SimpleNamespace | None = None,
        preferred: SimpleNamespace | None = None,
        alternative: SimpleNamespace | None = None,
        browser_count: int = 0,
        profile_present: bool = True,
        platform: str = "windows",
        host_present: bool = True,
    ) -> None:
        self.host = SimpleNamespace(platform=platform) if host_present else None
        self.platform = platform
        self.profile = SimpleNamespace(profile_id="profile-exact") if profile_present else None
        self.assignment = assignment
        self.descriptor = descriptor
        self.preferred = preferred
        self.alternative = alternative
        self.browser_count = browser_count
        self.count_calls: list[tuple[str, str]] = []
        self.select_calls: list[tuple[str, str, float]] = []
        self.preferred_calls = 0
        self.alternative_calls: list[int] = []
        self.descriptor_calls: list[str] = []
        self.materialize_calls: list[tuple[str, str | None]] = []
        self.host_calls: list[str] = []
        self.profile_calls: list[tuple[str, str, str]] = []

    def host_deployment(self, hostname: str) -> SimpleNamespace | None:
        assert hostname == "WS-01"
        self.host_calls.append(hostname)
        return self.host

    def user_profile_for(
        self,
        hostname: str,
        principal: str,
        platform: str,
    ) -> SimpleNamespace | None:
        assert (hostname, principal, platform) == ("WS-01", "alice", self.platform)
        self.profile_calls.append((hostname, principal, platform))
        return self.profile

    def count_user_application_assignments_for_category(
        self,
        profile_id: str,
        category: str,
    ) -> int:
        assert profile_id == "profile-exact"
        self.count_calls.append((profile_id, category))
        if category == "browser":
            return self.browser_count
        return int(self.assignment is not None)

    def select_user_application_assignment_for_category(
        self,
        profile_id: str,
        category: str,
        *,
        unit_interval: float,
    ) -> SimpleNamespace | None:
        assert (profile_id, category) == ("profile-exact", "user_app")
        assert 0.0 <= unit_interval < 1.0
        self.select_calls.append((profile_id, category, unit_interval))
        return self.assignment

    def preferred_browser_assignment(self, profile_id: str) -> SimpleNamespace | None:
        assert profile_id == "profile-exact"
        self.preferred_calls += 1
        return self.preferred

    def browser_alternative_assignment_at(
        self,
        profile_id: str,
        preferred_assignment_id: str,
        ordinal: int,
    ) -> SimpleNamespace | None:
        assert profile_id == "profile-exact"
        assert preferred_assignment_id
        self.alternative_calls.append(ordinal)
        return self.alternative

    def application_descriptor_for_assignment(
        self,
        assignment: SimpleNamespace,
    ) -> SimpleNamespace | None:
        self.descriptor_calls.append(assignment.application_id)
        return self.descriptor

    def materialize_application_command(
        self,
        _rng: random.Random,
        assignment: SimpleNamespace,
        *,
        username: str,
        category: str | None = None,
    ) -> tuple[str, str]:
        assert username == "alice"
        self.materialize_calls.append((assignment.application_id, category))
        return (
            rf"C:\Compiled\{assignment.application_id}.exe",
            f"{assignment.application_id}.exe --compiled",
        )

    def iter_user_application_assignments_for_profile(self, *_args: object) -> object:
        raise AssertionError("activity consumer iterated a compiled profile bucket")

    def user_application_assignments_for_profile(self, *_args: object) -> object:
        raise AssertionError("activity consumer copied a compiled profile bucket")

    def iter_user_application_assignments_for_category(self, *_args: object) -> object:
        raise AssertionError("activity consumer iterated a compiled category bucket")

    def page_user_application_assignments_for_category(self, *_args: object) -> object:
        raise AssertionError("activity consumer paged a compiled category bucket")


class _ServiceAssignmentRegistry:
    """Sentinel exposing exact service/application intersections only."""

    def __init__(
        self,
        applications: dict[str, tuple[SimpleNamespace, SimpleNamespace, str, str]],
        *,
        executable_ids: dict[str, tuple[str, ...]] | None = None,
        profile_present: bool = True,
        platform: str = "windows",
        host_present: bool = True,
    ) -> None:
        self.host = SimpleNamespace(platform=platform) if host_present else None
        self.platform = platform
        self.profile = SimpleNamespace(profile_id="profile-service") if profile_present else None
        self.applications = applications
        self.executable_ids = {
            executable.casefold(): application_ids
            for executable, application_ids in (executable_ids or {}).items()
        }
        self.executable_calls: list[str] = []
        self.exact_calls: list[str] = []
        self.descriptor_calls: list[str] = []
        self.image_calls: list[str] = []
        self.select_calls: list[tuple[str, ...]] = []
        self.materialize_calls: list[str] = []
        self.host_calls: list[str] = []
        self.profile_calls: list[tuple[str, str, str]] = []

    def host_deployment(self, hostname: str) -> SimpleNamespace | None:
        assert hostname == "WS-01"
        self.host_calls.append(hostname)
        return self.host

    def user_profile_for(
        self,
        hostname: str,
        principal: str,
        platform: str,
    ) -> SimpleNamespace | None:
        assert (hostname, principal, platform) == ("WS-01", "alice", self.platform)
        self.profile_calls.append((hostname, principal, platform))
        return self.profile

    def application_ids_for_executable(
        self,
        platform: str,
        executable: str,
    ) -> tuple[str, ...]:
        assert platform == self.platform
        self.executable_calls.append(executable)
        return self.executable_ids.get(executable.casefold(), ())

    def user_application_assignment_for_application(
        self,
        profile_id: str,
        application_id: str,
    ) -> SimpleNamespace | None:
        assert profile_id == "profile-service"
        self.exact_calls.append(application_id)
        entry = self.applications.get(application_id)
        return None if entry is None else entry[0]

    def application_descriptor_for_assignment(
        self,
        assignment: SimpleNamespace,
    ) -> SimpleNamespace | None:
        self.descriptor_calls.append(assignment.application_id)
        entry = self.applications.get(assignment.application_id)
        return None if entry is None else entry[1]

    def application_executable_for_assignment(
        self,
        assignment: SimpleNamespace,
    ) -> str | None:
        self.image_calls.append(assignment.application_id)
        entry = self.applications.get(assignment.application_id)
        return None if entry is None else entry[2]

    def select_user_application_assignment_for_applications(
        self,
        profile_id: str,
        application_ids: tuple[str, ...],
        *,
        unit_interval: float,
    ) -> SimpleNamespace | None:
        assert profile_id == "profile-service"
        assert 0.0 <= unit_interval < 1.0
        self.select_calls.append(application_ids)
        if not application_ids:
            return None
        selected_index = min(len(application_ids) - 1, int(unit_interval * len(application_ids)))
        return self.applications[application_ids[selected_index]][0]

    def materialize_application_command(
        self,
        _rng: random.Random,
        assignment: SimpleNamespace,
        *,
        username: str,
        category: str | None = None,
    ) -> tuple[str, str] | None:
        assert username == "alice"
        assert category is None
        self.materialize_calls.append(assignment.application_id)
        entry = self.applications.get(assignment.application_id)
        return None if entry is None else (entry[2], entry[3])

    def iter_user_application_assignments_for_profile(self, *_args: object) -> object:
        raise AssertionError("world consumer iterated a compiled profile bucket")

    def user_application_assignments_for_profile(self, *_args: object) -> object:
        raise AssertionError("world consumer copied a compiled profile bucket")

    def page_user_application_assignments_for_profile(self, *_args: object) -> object:
        raise AssertionError("world consumer paged a compiled profile bucket")


def _user() -> User:
    return User(
        username="alice",
        full_name="Alice Example",
        email="alice@example.com",
        persona="developer",
    )


def _system(*, system_type: str = "workstation", os_name: str = "Windows 11") -> System:
    return System(
        hostname="WS-01",
        ip="10.0.0.11",
        os=os_name,
        type=system_type,
    )


def _forbid_packaged_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    def reject(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("bound deployment consumer consulted the packaged catalog")

    for name in (
        "pick_app_and_command",
        "is_singleton_application_image",
        "get_child_processes",
        "parameterize_scoped_command",
        "get_applications_for_ids",
        "load_catalog",
    ):
        monkeypatch.setattr(application_catalog, name, reject)


def _activity_harness(
    registry: _CategoryAssignmentRegistry | None,
    *,
    os_name: str = "Windows 11",
) -> tuple[ActivityGenerator, StateManager, User, System, list[tuple[str, str]]]:
    state = StateManager()
    state.set_current_time(_ACTIVITY_TIME)
    emitters = {"windows_event_security": Mock()}
    dispatcher = EventDispatcher(
        state_manager=state,
        emitters=emitters,
        deployment_registry=registry,  # type: ignore[arg-type]
    )
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    user = _user()
    system = _system(os_name=os_name)
    state.register_session(
        logon_id="0x1001",
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_ACTIVITY_TIME - timedelta(hours=1),
    )
    generated: list[tuple[str, str]] = []

    def generate_process(
        _user_value: User,
        _system_value: System,
        _time_value: datetime,
        _logon_id: str,
        process_name: str,
        command_line: str,
        **_kwargs: object,
    ) -> int:
        generated.append((process_name, command_line))
        return 4242 + len(generated)

    generator.generate_process = generate_process  # type: ignore[method-assign]
    generator._resolve_parent = lambda *_args, **_kwargs: 0  # type: ignore[method-assign]
    generator._record_user_process = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    generator._process_effect_context = (  # type: ignore[method-assign]
        lambda _system, _pid, image, command: (image, command)
    )
    generator._emit_process_network_correlation = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: None
    )
    return generator, state, user, system, generated


def _world_planner_harness(
    registry: _ServiceAssignmentRegistry | Any | None,
    *,
    system_type: str = "workstation",
    os_name: str = "Windows 11",
) -> tuple[WorldPlanner, ActiveSession, User, System, list[dict[str, Any]]]:
    state = StateManager()
    state.set_current_time(_ACTIVITY_TIME)
    user = _user()
    system = _system(system_type=system_type, os_name=os_name)
    state.register_session(
        logon_id="0x2001",
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=_ACTIVITY_TIME - timedelta(hours=1),
    )
    session = state.get_session("0x2001")
    assert session is not None
    generated: list[dict[str, Any]] = []

    def generate_process(**kwargs: Any) -> int:
        generated.append(kwargs)
        return 4242

    activity_generator = SimpleNamespace(
        dispatcher=SimpleNamespace(deployment_registry=registry),
        _last_workstation_lock_time={},
        _user_process_history={},
        _software_deployment_key="default",
        _scenario_end_time=_ACTIVITY_TIME + timedelta(hours=1),
        _parameterize_command_for_system=lambda _rng, command, **_kwargs: command,
        _singleton_application_key=lambda *_args, **_kwargs: ("singleton",),
        claim_singleton_application_interval=lambda *_args, **_kwargs: True,
        _resolve_parent=lambda *_args, **_kwargs: 0,
        generate_process=generate_process,
        _record_user_process=lambda *_args, **_kwargs: None,
        _remember_foreground_process_finalizer=lambda *_args, **_kwargs: None,
    )
    planner = object.__new__(WorldPlanner)
    planner.world_model = SimpleNamespace(
        hosts={
            system.hostname: SimpleNamespace(os_category=generator_module._get_os_category(os_name))
        }
    )
    planner.state_manager = state
    planner.activity_generator = activity_generator
    return planner, session, user, system, generated


def test_activity_uses_exact_compiled_assignment_materialization_and_singleton(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignment = _assignment("custom_app")
    descriptor = _descriptor("custom_app", "custom_app.exe", singleton=True)
    registry = _CategoryAssignmentRegistry(assignment=assignment, descriptor=descriptor)
    generator, _state, user, system, generated = _activity_harness(registry)
    singleton_claims: list[tuple[object, ...]] = []
    generator.claim_singleton_application_interval = (  # type: ignore[method-assign]
        lambda *args: singleton_claims.append(args) or True
    )
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(17))

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert registry.count_calls == [("profile-exact", "user_app")]
    assert len(registry.select_calls) == 1
    assert registry.descriptor_calls == ["custom_app"]
    assert registry.materialize_calls == [("custom_app", "user_app")]
    assert generated == [(r"C:\Compiled\custom_app.exe", "custom_app.exe --compiled")]
    assert len(singleton_claims) == 1


@pytest.mark.parametrize("profile_present, assignment_present", [(False, False), (True, False)])
def test_activity_bound_registry_never_falls_back_or_consumes_selection_rng(
    monkeypatch: pytest.MonkeyPatch,
    profile_present: bool,
    assignment_present: bool,
) -> None:
    assignment = _assignment("custom_app") if assignment_present else None
    registry = _CategoryAssignmentRegistry(
        assignment=assignment,
        descriptor=_descriptor("custom_app", "custom_app.exe"),
        profile_present=profile_present,
    )
    generator, _state, user, system, generated = _activity_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    rng = random.Random(23)
    before = rng.getstate()
    monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert rng.getstate() == before
    assert generated == []
    assert registry.select_calls == []
    assert registry.count_calls == ([("profile-exact", "user_app")] if profile_present else [])


def test_activity_bound_registry_uses_compiled_macos_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assignment = _assignment("custom_app")
    registry = _CategoryAssignmentRegistry(
        assignment=assignment,
        descriptor=_descriptor("custom_app", "custom_app"),
        platform="macos",
    )
    generator, _state, user, system, generated = _activity_harness(
        registry,
        os_name="macOS 14",
    )
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(37))

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert registry.host_calls == ["WS-01"]
    assert registry.profile_calls == [("WS-01", "alice", "macos")]
    assert registry.materialize_calls == [("custom_app", "user_app")]
    assert len(generated) == 1


def test_activity_bound_registry_unsupported_host_fails_closed_without_rng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _CategoryAssignmentRegistry(
        assignment=_assignment("custom_app"),
        descriptor=_descriptor("custom_app", "custom_app"),
        host_present=False,
    )
    generator, _state, user, system, generated = _activity_harness(
        registry,
        os_name="FreeBSD 14",
    )
    _forbid_packaged_catalog(monkeypatch)
    rng = random.Random(39)
    before = rng.getstate()
    monkeypatch.setattr(generator_module, "_get_rng", lambda: rng)

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert rng.getstate() == before
    assert registry.host_calls == ["WS-01"]
    assert registry.profile_calls == []
    assert registry.count_calls == []
    assert registry.select_calls == []
    assert generated == []


@pytest.mark.parametrize("failure", ["descriptor", "materialization"])
def test_activity_bound_registry_fails_closed_after_assignment_selection(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    assignment = _assignment("custom_app")
    registry = _CategoryAssignmentRegistry(
        assignment=assignment,
        descriptor=(None if failure == "descriptor" else _descriptor("custom_app", "custom.exe")),
    )
    if failure == "materialization":
        monkeypatch.setattr(
            registry,
            "materialize_application_command",
            lambda *_args, **_kwargs: None,
        )
    generator, _state, user, system, generated = _activity_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(41))

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert generated == []
    assert len(registry.select_calls) == 1


@pytest.mark.parametrize(
    ("seed", "expected_application", "alternative_calls"),
    [(0, "chrome", []), (2, "firefox", [0])],
)
def test_activity_compiled_browser_affinity_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    seed: int,
    expected_application: str,
    alternative_calls: list[int],
) -> None:
    selected = _assignment("edge", categories=("user_app", "browser"), ordinal=2)
    preferred = _assignment("chrome", categories=("user_app", "browser"), ordinal=0)
    alternative = _assignment("firefox", categories=("user_app", "browser"), ordinal=1)
    registry = _CategoryAssignmentRegistry(
        assignment=selected,
        descriptor=_descriptor(
            expected_application,
            f"{expected_application}.exe",
            categories=("user_app", "browser"),
        ),
        preferred=preferred,
        alternative=alternative,
        browser_count=3,
    )
    generator, _state, user, system, generated = _activity_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(seed))

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert registry.preferred_calls == 1
    assert registry.alternative_calls == alternative_calls
    assert registry.materialize_calls == [(expected_application, "user_app")]
    assert generated[0][0] == rf"C:\Compiled\{expected_application}.exe"


def test_activity_without_registry_preserves_legacy_catalog_and_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generator, _state, user, system, generated = _activity_harness(None)
    calls: list[str] = []
    monkeypatch.setattr(
        application_catalog,
        "pick_app_and_command",
        lambda *_args, **_kwargs: (r"C:\Legacy\legacy.exe", "legacy.exe"),
    )
    monkeypatch.setattr(application_catalog, "is_singleton_application_image", lambda *_args: False)
    monkeypatch.setattr(
        application_catalog,
        "get_child_processes",
        lambda *_args: calls.append("children") or [],
    )
    monkeypatch.setattr(generator_module, "_get_rng", lambda: random.Random(29))

    generator.execute_baseline_activity(user, system, _ACTIVITY_TIME, "process_user_apps")

    assert generated == [(r"C:\Legacy\legacy.exe", "legacy.exe")]
    assert calls == ["children"]


def _service_entry(
    application_id: str,
    executable: str,
    image: str,
    *,
    categories: tuple[str, ...] = ("user_app",),
    ordinal: int = 0,
    command: str | None = None,
) -> tuple[SimpleNamespace, SimpleNamespace, str, str]:
    return (
        _assignment(application_id, categories=categories, ordinal=ordinal),
        _descriptor(
            application_id,
            executable,
            categories=categories,
            ordinal=ordinal,
        ),
        image,
        command or f"{executable} --compiled",
    )


def test_world_intersects_service_executables_with_exact_assignments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {
            "postman": _service_entry(
                "postman",
                "postman.exe",
                r"C:\Users\alice\AppData\Local\Postman\Postman.exe",
            )
        },
        executable_ids={"Slack.exe": ("slack",), "Postman.exe": ("postman",)},
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": ["Slack.exe", "Postman.exe"]},
    )
    monkeypatch.setattr(
        planner.state_manager,
        "get_processes_for_session",
        lambda *_args, **_kwargs: pytest.fail("inferred service copied the session bucket"),
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(31),
    )

    assert pid == 4242
    assert registry.exact_calls == ["postman", "slack"]
    assert registry.descriptor_calls == ["postman"]
    assert registry.image_calls == ["postman"]
    assert registry.select_calls == []
    assert registry.materialize_calls == ["postman"]
    assert generated[0]["process_name"].endswith(r"Postman\Postman.exe")


@pytest.mark.parametrize("profile_present", [False, True])
def test_world_bound_registry_never_relaxes_to_legacy(
    monkeypatch: pytest.MonkeyPatch,
    profile_present: bool,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {},
        executable_ids={"Postman.exe": ("postman",)},
        profile_present=profile_present,
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": ["Postman.exe"]},
    )
    rng = random.Random(37)
    before = rng.getstate()

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        rng,
    )

    assert pid == -1
    assert rng.getstate() == before
    assert generated == []
    assert registry.materialize_calls == []


def test_world_bound_registry_uses_compiled_macos_platform(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {
            "custom_mac": _service_entry(
                "custom_mac",
                "custom-mac",
                "/Applications/Custom.app/Contents/MacOS/custom-mac",
            )
        },
        executable_ids={"custom-mac": ("custom_mac",)},
        platform="macos",
    )
    planner, session, user, system, generated = _world_planner_harness(
        registry,
        os_name="macOS 14",
    )
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": ["custom-mac"]},
    )
    monkeypatch.setattr(
        planner.state_manager,
        "get_processes_for_session",
        lambda *_args, **_kwargs: pytest.fail("inferred service copied the session bucket"),
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(43),
    )

    assert pid == 4242
    assert registry.host_calls == ["WS-01"]
    assert registry.profile_calls == [("WS-01", "alice", "macos")]
    assert registry.executable_calls == ["custom-mac"]
    assert generated[0]["process_name"] == "/Applications/Custom.app/Contents/MacOS/custom-mac"


def test_world_bound_registry_unsupported_host_fails_closed_without_rng(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry({}, host_present=False)
    planner, session, user, system, generated = _world_planner_harness(
        registry,
        os_name="Solaris 11",
    )
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: pytest.fail("unsupported compiled host reached service inference"),
    )
    rng = random.Random(47)
    before = rng.getstate()

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        rng,
    )

    assert pid == -1
    assert rng.getstate() == before
    assert registry.host_calls == ["WS-01"]
    assert registry.profile_calls == []
    assert generated == []


def test_world_destination_scoring_is_seed_and_service_order_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = {
        "chrome": _service_entry(
            "chrome",
            "chrome.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            ordinal=0,
        ),
        "outlook": _service_entry(
            "outlook",
            "outlook.exe",
            r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
            categories=("user_app", "office"),
            ordinal=1,
        ),
        "vpn": _service_entry(
            "vpn",
            "vpnui.exe",
            r"C:\Program Files\Cisco\vpnui.exe",
            ordinal=2,
        ),
    }
    executable_ids = {
        "chrome.exe": ("chrome",),
        "outlook.exe": ("outlook",),
        "vpnui.exe": ("vpn",),
    }
    observed: list[str] = []
    for service_executables in (
        ("chrome.exe", "outlook.exe", "vpnui.exe"),
        ("vpnui.exe", "outlook.exe", "chrome.exe"),
    ):
        monkeypatch.setattr(
            world_model_module,
            "get_service_to_exes",
            lambda service_executables=service_executables: {"ssl": service_executables},
        )
        for seed in (0, 19):
            registry = _ServiceAssignmentRegistry(entries, executable_ids=executable_ids)
            planner, session, user, system, generated = _world_planner_harness(registry)
            monkeypatch.setattr(
                planner.state_manager,
                "get_processes_for_session",
                lambda *_args, **_kwargs: pytest.fail("inferred service copied session state"),
            )
            pid = planner.ensure_connection_process(
                user,
                system,
                session,
                _ACTIVITY_TIME,
                "ssl",
                random.Random(seed),
                destination_hostname="outlook.office.com",
            )
            assert pid == 4242
            observed.append(Path(str(generated[0]["process_name"]).replace("\\", "/")).name)
            assert registry.materialize_calls == ["outlook"]

    assert observed == ["OUTLOOK.EXE"] * 4


def test_world_explicit_custom_application_bypasses_service_and_destination_inference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {
            "custom_slack": _service_entry(
                "custom_slack",
                "custom-slack.exe",
                r"C:\Custom\custom-slack.exe",
                command=r'"C:\Custom\custom-slack.exe" --tenant blue',
            )
        }
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: pytest.fail("explicit application inferred a service bucket"),
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        destination_hostname="outlook.office.com",
        application_ids=["custom_slack"],
    )

    assert pid == 4242
    assert registry.executable_calls == []
    assert registry.materialize_calls == ["custom_slack"]
    assert generated[0]["process_name"] == r"C:\Custom\custom-slack.exe"
    assert generated[0]["command_line"].endswith("--tenant blue")


def test_world_explicit_empty_application_ids_are_authoritative_and_rng_neutral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry({})
    planner, session, user, system, generated = _world_planner_harness(registry)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: pytest.fail("explicit empty application IDs inferred a service bucket"),
    )
    rng = random.Random(43)
    before = rng.getstate()

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        rng,
        application_ids=[],
    )

    assert pid == -1
    assert rng.getstate() == before
    assert registry.exact_calls == []
    assert generated == []


def test_world_scores_only_the_assigned_destination_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {
            "broad": _service_entry(
                "broad",
                "broad.exe",
                r"C:\Apps\broad.exe",
            )
        },
        executable_ids={"specific.exe": ("specific",), "broad.exe": ("broad",)},
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": ["specific.exe", "broad.exe"]},
    )
    from evidenceforge.generation.activity import dns_registry, process_network

    monkeypatch.setattr(dns_registry, "get_domain_tags", lambda _hostname: ["target", "web"])
    monkeypatch.setattr(
        process_network,
        "get_exe_to_service",
        lambda: {
            "specific.exe": {"dns_tags": ["target"]},
            "broad.exe": {"dns_tags": ["web"]},
        },
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(47),
        destination_hostname="target.example",
    )

    assert pid == 4242
    assert registry.exact_calls == ["broad", "specific"]
    assert registry.materialize_calls == ["broad"]
    assert generated[0]["process_name"] == r"C:\Apps\broad.exe"


def test_world_inferred_reuse_is_bounded_to_ten_recent_history_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outlook_image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
    registry = _ServiceAssignmentRegistry(
        {"outlook": _service_entry("outlook", "outlook.exe", outlook_image)},
        executable_ids={"outlook.exe": ("outlook",)},
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    outlook_pid = planner.state_manager.create_process(
        system=system.hostname,
        parent_pid=0,
        image=outlook_image,
        command_line="outlook.exe",
        username=user.username,
        integrity_level="Medium",
        logon_id=session.logon_id,
    )
    planner.activity_generator._user_process_history[(system.hostname, user.username)] = (
        [(50_000 + ordinal, r"C:\Noise\noise.exe") for ordinal in range(100_000)]
        + [(outlook_pid, outlook_image)]
        + [(160_000 + ordinal, r"C:\Noise\noise.exe") for ordinal in range(9)]
    )
    original_get_process = planner.state_manager.get_process
    lookup_count = 0

    def counted_get_process(hostname: str, pid: int) -> object:
        nonlocal lookup_count
        lookup_count += 1
        return original_get_process(hostname, pid)

    monkeypatch.setattr(planner.state_manager, "get_process", counted_get_process)
    monkeypatch.setattr(
        planner.state_manager,
        "get_processes_for_session",
        lambda *_args, **_kwargs: pytest.fail("inferred service copied session state"),
    )
    monkeypatch.setattr(world_model_module, "get_service_to_exes", lambda: {"ssl": ["outlook.exe"]})

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        destination_hostname="outlook.office.com",
    )

    assert pid == outlook_pid
    assert lookup_count == 10
    assert registry.materialize_calls == []
    assert generated == []


def test_world_explicit_assignment_reuses_active_process_outside_recent_history() -> None:
    image = r"C:\Custom\custom-slack.exe"
    registry = _ServiceAssignmentRegistry(
        {"custom_slack": _service_entry("custom_slack", "custom-slack.exe", image)}
    )
    planner, session, user, system, generated = _world_planner_harness(registry)
    pid = planner.state_manager.create_process(
        system=system.hostname,
        parent_pid=0,
        image=image,
        command_line="custom-slack.exe",
        username=user.username,
        integrity_level="Medium",
        logon_id=session.logon_id,
    )

    resolved = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        application_ids=["custom_slack"],
    )

    assert resolved == pid
    assert registry.materialize_calls == []
    assert generated == []


def test_world_server_admin_excludes_compiled_browser_office_code_and_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _ServiceAssignmentRegistry(
        {
            "vscode": _service_entry(
                "vscode",
                "code.exe",
                r"C:\Program Files\Microsoft VS Code\Code.exe",
                categories=("code",),
            )
        },
        executable_ids={"code.exe": ("vscode",)},
    )
    planner, session, user, system, generated = _world_planner_harness(
        registry,
        system_type="server",
    )
    monkeypatch.setattr(world_model_module, "get_service_to_exes", lambda: {"ssl": ["code.exe"]})

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        effective_persona="_server_admin",
    )

    assert pid == -1
    assert registry.materialize_calls == []
    assert generated == []


def test_world_multiple_candidates_select_in_compiled_ordinal_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = {
        "alpha": _service_entry(
            "alpha",
            "alpha.exe",
            r"C:\Apps\alpha.exe",
            ordinal=1,
        ),
        "zeta": _service_entry(
            "zeta",
            "zeta.exe",
            r"C:\Apps\zeta.exe",
            ordinal=0,
        ),
    }
    registry = _ServiceAssignmentRegistry(
        entries,
        executable_ids={"alpha.exe": ("alpha",), "zeta.exe": ("zeta",)},
    )
    planner, session, user, system, _generated = _world_planner_harness(registry)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": ["alpha.exe", "zeta.exe"]},
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(4),
    )

    assert pid == 4242
    assert registry.select_calls == [("zeta", "alpha")]


def test_world_without_registry_preserves_legacy_destination_scoring(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner, session, user, system, generated = _world_planner_harness(None)
    service_executables = tuple(world_model_module.get_service_to_exes()["ssl"])
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: {"ssl": tuple(reversed(service_executables))},
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(0),
        destination_hostname="outlook.office.com",
    )

    assert pid == 4242
    assert generated[0]["process_name"].endswith(r"Office16\OUTLOOK.EXE")


def _custom_application(application_id: str, image_path: str) -> ApplicationEntry:
    raw = next(
        application
        for application in application_catalog.load_catalog()["applications"]
        if application["id"] == "slack"
    )
    payload = ApplicationEntry.model_validate(raw).model_dump(mode="python")
    payload["id"] = application_id
    payload["display_name"] = "Compiled Custom Slack"
    payload["categories"] = ["user_app"]
    payload["singleton_per_session"] = True
    windows = payload["platforms"]["windows"]
    windows["image_path"] = image_path
    windows["command_templates"] = [f'"{image_path}" --tenant {{tenant}}']
    windows["command_parameter_pools"] = {"tenant": ["blue"]}
    windows["children"] = []
    windows["loaded_modules"] = []
    windows["pe_metadata"]["original_filename"] = image_path.rsplit("\\", 1)[-1]
    if application_id != "slack":
        windows["deployment"]["product_id"] = application_id
    payload["platforms"] = {"windows": windows}
    return ApplicationEntry.model_validate(payload)


def _compiled_custom_registry(application: ApplicationEntry):
    payload = yaml.safe_load(_SCENARIO_PATH.read_text(encoding="utf-8"))
    payload["environment"]["users"] = [
        {
            "username": "alice",
            "full_name": "Alice Example",
            "email": "alice@example.com",
            "primary_system": "WS-01",
            "enabled": True,
            "persona": "developer",
        }
    ]
    payload["environment"]["systems"] = [
        {
            "hostname": "WS-01",
            "ip": "10.0.0.11",
            "os": "Windows 11 Enterprise",
            "os_build": "10.0.22631.3880",
            "architecture": "x64",
            "type": "workstation",
        }
    ]
    payload["environment"]["network"]["segments"][0]["systems"] = ["WS-01"]
    scenario = Scenario.model_validate(payload)
    return compile_deployment_registry(
        scenario,
        WorldModel(scenario, "example.com"),
        application_entries=(application,),
    )


@pytest.mark.parametrize(
    ("application_id", "image_path"),
    [
        ("custom_slack", r"C:\Custom\custom-slack.exe"),
        ("slack", r"C:\Custom\overridden-slack.exe"),
    ],
)
def test_world_consumes_real_registry_custom_and_same_id_override_truth(
    monkeypatch: pytest.MonkeyPatch,
    application_id: str,
    image_path: str,
) -> None:
    registry = _compiled_custom_registry(_custom_application(application_id, image_path))
    planner, session, user, system, generated = _world_planner_harness(registry)
    _forbid_packaged_catalog(monkeypatch)
    monkeypatch.setattr(
        world_model_module,
        "get_service_to_exes",
        lambda: pytest.fail("explicit application inferred a service bucket"),
    )

    pid = planner.ensure_connection_process(
        user,
        system,
        session,
        _ACTIVITY_TIME,
        "ssl",
        random.Random(7),
        application_ids=[application_id],
    )

    assert pid == 4242
    assert generated[0]["process_name"] == image_path
    assert generated[0]["command_line"] == f'"{image_path}" --tenant blue'


def test_compiled_activity_launch_is_hash_seed_independent() -> None:
    script = textwrap.dedent(
        """
        import json
        import yaml
        from datetime import UTC, datetime, timedelta
        from pathlib import Path

        from evidenceforge.events.dispatcher import EventDispatcher
        from evidenceforge.generation.activity.generator import ActivityGenerator
        from evidenceforge.generation.deployment_compiler import compile_deployment_registry
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.generation.world_model import WorldModel
        from evidenceforge.models.scenario import Scenario
        from evidenceforge.utils.rng import reset_thread_rng

        payload = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_text())
        scenario = Scenario.model_validate(payload)
        world = WorldModel(scenario, "example.com")
        registry = compile_deployment_registry(scenario, world)
        state = StateManager()
        timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
        state.set_current_time(timestamp)
        user = scenario.environment.users[0]
        system = scenario.environment.systems[0]
        state.register_session(
            logon_id="0x3001",
            username=user.username,
            system=system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(hours=1),
        )
        dispatcher = EventDispatcher(
            state_manager=state,
            emitters={},
            deployment_registry=registry,
        )
        generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
        generator._scenario_end_time = timestamp + timedelta(hours=1)
        generator._resolve_parent = lambda *_args, **_kwargs: 0

        class Selected(Exception):
            pass

        def stop(_user, _system, _time, _logon_id, image, command, **_kwargs):
            print(json.dumps({"image": image, "command": command}, sort_keys=True))
            raise Selected

        generator.generate_process = stop
        reset_thread_rng(8417)
        try:
            generator.execute_baseline_activity(user, system, timestamp, "process_user_apps")
        except Selected:
            pass
        """
    )
    outputs: list[dict[str, str]] = []
    for hash_seed in ("1", "99991"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(_REPOSITORY_ROOT / "src")
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=_REPOSITORY_ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        output_lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
        assert len(output_lines) == 1
        outputs.append(json.loads(output_lines[0]))

    assert outputs[0] == outputs[1]

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Logical developer commands retain their actual shared native runtime."""

import json
import random
import shlex
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.activity.application_catalog import (
    application_descriptor,
    is_singleton_application_image,
)
from evidenceforge.generation.activity.process_helpers import (
    _macos_foreground_lifetime,
    _macos_process_uses_shell,
    _posix_shell_process_reserves_foreground,
)
from evidenceforge.generation.activity.process_network import ambient_network_allowed
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_installed_provisioning import _deployments, _scenario


@pytest.mark.parametrize(
    "application",
    ["vscode", "intellij", "sublimetext", "postman", "dbeaver", "macos-terminal", "macos-iterm2"],
)
def test_mac_gui_platform_override_compiles_without_changing_other_platforms(
    application: str,
) -> None:
    catalog = application_descriptor(application)
    platform = catalog["platforms"]["macos"]
    assert is_singleton_application_image(platform["image_path"], "macos")
    registry = _deployments(_scenario())
    assert registry.application_descriptor(application, "macos").singleton_per_session
    for category, other in catalog["platforms"].items():
        if category != "macos":
            assert is_singleton_application_image(other["image_path"], category) == bool(
                catalog.get("singleton_per_session")
            )


@pytest.mark.parametrize("application", ["intellij", "vscode"])
def test_repeated_gui_baseline_actions_reuse_one_main_process(
    tmp_path: Path, application: str
) -> None:
    data = _scenario().model_dump(mode="json", exclude_none=True)
    data["environment"]["deployment_overrides"] = [
        {"system": "MAC-01", "user_applications": [{"user": "alex", "applications": [application]}]}
    ]
    scenario = Scenario.model_validate(data)
    scenario.output.logs = [{"format": "ecar"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=329)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time + timedelta(minutes=1))
        for minute in (5, 7, 11, 14):
            generator.execute_baseline_activity(
                user, system, engine.start_time + timedelta(minutes=minute), "process_code"
            )
        image = application_descriptor(application)["platforms"]["macos"]["image_path"]
        processes = [
            p for p in engine.state_manager.get_processes_for_session(logon) if p.image == image
        ]
        assert len(processes) == 1
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("application", ["curl", "nano"])
def test_mac_storyline_execution_does_not_invent_its_own_file_create(
    tmp_path: Path, application: str
) -> None:
    data = _scenario().model_dump(mode="json", exclude_none=True)
    data["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [{"user": "alex", "applications": [application, "macos-zsh"]}],
        }
    ]
    scenario = Scenario.model_validate(data)
    scenario.output.logs = [{"format": "ecar"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=329)
    image = application_descriptor(application)["platforms"]["macos"]["image_path"]
    output = "/Users/alex/Downloads/manifest.json"
    command = (
        f"{image} -fsSL https://releases.example.test/manifest.json -o {output}"
        if application == "curl"
        else f"{image} /Users/alex/Projects/README.md"
    )
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time + timedelta(minutes=1))
        at = engine.start_time + timedelta(minutes=5)
        shell = generator.ensure_macos_session_shell(user, system, logon, at)
        pid = generator.generate_process(
            user,
            system,
            at,
            logon,
            image,
            command,
            parent_pid=shell,
            ensure_file_event=True,
            from_storyline=True,
        )
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    creates = [row for row in rows if row["object"] == "FILE" and row["action"] == "CREATE"]
    assert any(row["object"] == "PROCESS" and row["pid"] == pid for row in rows)
    assert all(row["properties"]["file_path"] != image for row in creates)


@pytest.mark.parametrize("future", [False, True])
@pytest.mark.parametrize("application", ["macos-terminal", "macos-iterm2"])
def test_shell_bootstrap_reuses_only_an_eligible_existing_terminal_main(
    tmp_path: Path,
    future: bool,
    application: str,
) -> None:
    scenario = _scenario()
    scenario.output.logs = [{"format": "ecar"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=330)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time + timedelta(minutes=1))
        at = engine.start_time + timedelta(minutes=6)
        image = application_descriptor(application)["platforms"]["macos"]["image_path"]
        terminal = generator.generate_process(
            user,
            system,
            at + timedelta(minutes=2 if future else -2),
            logon,
            image,
            image,
            parent_pid=1,
        )
        shell = generator.ensure_macos_session_shell(
            user, system, logon, at, terminal_application_id=application
        )
        session = engine.state_manager.get_session(logon)
        if future:
            assert shell is None and session.session_shell_pid is None
        else:
            assert shell is not None and session.process_tree_root == terminal
        terminals = [
            p for p in engine.state_manager.get_processes_for_session(logon) if p.image == image
        ]
        assert len(terminals) == 1 and terminals[0].pid == terminal
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("application", ["msbuild", "npm", "pytest", "pip", "powershell_query"])
def test_mac_runtime_catalog_uses_bounded_direct_native_invocations(application: str) -> None:
    platform = application_descriptor(application)["platforms"]["macos"]
    image = platform["image_path"]
    assert platform["executable_format"] == "mach_o"
    assert tuple(platform["deployment"]["architectures"]) == ("arm64",)
    assert not image.endswith((".js", ".py", ".cmd", ".exe"))
    assert not ambient_network_allowed(image)
    for command in platform["command_templates"]:
        assert shlex.split(command)[0] == image
        assert _macos_foreground_lifetime(image, command) is not None
        assert _macos_process_uses_shell(image)
        assert _posix_shell_process_reserves_foreground("macos", image, command)
        assert "Get-CimInstance" not in command and "Get-WmiObject" not in command
    # A known runtime is not a blanket short-lived classification.
    assert _macos_foreground_lifetime(image, image + " arbitrary-daemon") is None


def test_compiled_logical_apps_share_installed_runtime_and_preserve_old_availability() -> None:
    applications = ["msbuild", "dotnet", "npm", "nodejs", "pytest", "pip", "powershell_query"]
    data = _scenario().model_dump(mode="json", exclude_none=True)
    data["time_window"]["start"] = "2026-10-21T14:00:00Z"
    data["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [{"user": "alex", "applications": applications}],
        }
    ]
    registry = _deployments(Scenario.model_validate(data))
    profile = registry.user_profile_for("MAC-01", "alex", "macos")
    images: dict[str, str] = {}
    for application in applications:
        assignment = registry.user_application_assignment_for_application(
            profile.profile_id, application
        )
        assert assignment is not None
        descriptor = registry.application_descriptor_for_assignment(assignment)
        materialized = registry.materialize_application_command(
            random.Random(17), assignment, username="alex", category=descriptor.categories[0]
        )
        assert materialized is not None
        image, command = materialized
        assert shlex.split(command)[0] == image
        binary = registry.resolve_binary("MAC-01", image, "macos", principal="alex")
        assert binary is not None and binary.mach_o_image is not None
        images[application] = image
    assert images["msbuild"] == images["dotnet"]
    assert images["npm"] == images["nodejs"]
    assert images["pytest"] == images["pip"]
    old = _deployments(_scenario())
    old_profile = old.user_profile_for("MAC-01", "alex", "macos")
    assert old.user_application_assignment_for_application(old_profile.profile_id, "pytest") is None
    assert "macos" not in application_descriptor("zscaler_client_connector")["platforms"]


@pytest.mark.parametrize("application", ["pytest", "pip"])
def test_framework_module_baseline_uses_live_shell_and_closes_its_foreground_lease(
    tmp_path: Path, application: str
) -> None:
    data = _scenario().model_dump(mode="json", exclude_none=True)
    data["time_window"]["start"] = "2026-10-21T14:00:00Z"
    data["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [{"user": "alex", "applications": [application, "macos-zsh"]}],
        }
    ]
    scenario = Scenario.model_validate(data)
    scenario.output.logs = [{"format": "ecar"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=329)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = generator.generate_logon(user, system, engine.start_time + timedelta(minutes=1))
        session = engine.state_manager.get_session(logon)
        at = engine.start_time + timedelta(minutes=5)
        generator.execute_baseline_activity(user, system, at, "process_build")
        processes = [
            process
            for process in engine.state_manager.get_processes_for_session(
                logon, include_retained=True
            )
            if f" -m {application} " in process.command_line
        ]
        assert len(processes) == 1
        process = processes[0]
        assert process.parent_pid == session.session_shell_pid
        # Short invocations may already have published their bounded exit.
        close = process.end_time or generator.foreground_process_termination_time(
            system.hostname, process.pid
        )
        assert at < close <= at + timedelta(seconds=45)
        generator.finalize_foreground_process_lifetimes(engine.end_time)
        assert engine.state_manager.get_process(system.hostname, process.pid) is None
    finally:
        engine._close_emitters()

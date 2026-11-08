# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Standard persona admission and installed CLI execution share qualified truth."""

import json
import shlex
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import MacosCommandEnvironmentPolicy
from evidenceforge.generation.activity.macos_execution_metadata import (
    load_macos_execution_metadata_profile,
)
from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.macos_launch_support import macos_launch_issues
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml


def _scenario(persona: str, applications: list[str] | None = None) -> Scenario:
    raw = load_yaml(Path("tests/fixtures/scenarios/macos-native-smoke.yaml"))
    raw["storyline"] = []
    raw["environment"]["users"][0]["persona"] = persona
    if applications is None:
        raw["environment"].pop("deployment_overrides")
    else:
        raw["environment"]["deployment_overrides"][0]["user_applications"][0]["applications"] = [
            "macos-terminal",
            *applications,
        ]
    return Scenario.model_validate(raw)


@pytest.mark.parametrize(
    "persona",
    [path.stem for path in Path("src/evidenceforge/config/personas").glob("*.yaml")] + ["default"],
)
def test_standard_mac_personas_admit_every_selectable_installed_launch(persona: str) -> None:
    scenario = _scenario(persona)
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))
    profile = load_macos_execution_metadata_profile()
    assert macos_launch_issues(scenario, registry, profile) == ()


@pytest.mark.parametrize("application", ["powershell_query", "redis_cli", "ldapsearch"])
def test_preflight_includes_query_tool_runtime_metadata(application: str) -> None:
    scenario = _scenario("sysadmin", [application])
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))
    descriptor = registry.application_descriptor(application, "macos")
    binary = registry.resolve_binary("MAC-SMOKE", descriptor.image_path, "macos", principal="alex")
    profile = load_macos_execution_metadata_profile()
    missing = profile.model_copy(
        update={
            "code_validation": tuple(
                rule for rule in profile.code_validation if rule.product_id != binary.key.product_id
            )
        }
    )
    findings = macos_launch_issues(scenario, registry, missing)
    assert len(findings) == 1
    assert findings[0].image == descriptor.image_path
    assert findings[0].issues == ("image_security_unknown",)


_COMMANDS = {
    "7zip": ("i",),
    "git": ("--version",),
    "docker": ("--version",),
    "kubectl": ("version", "--client"),
    "make": ("--version",),
    "vim": ("--version",),
    "emacs": ("--version",),
    "gcc": ("--version",),
    "cargo": ("--version",),
    "dotnet": ("--info",),
    "msbuild": ("msbuild", "-version"),
    "nodejs": ("--version",),
    "npm": ("/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js", "--version"),
    "pip": ("-m", "pip", "--version"),
    "pytest": ("-m", "pytest", "--version"),
    "powershell_query": ("-NoProfile", "-NonInteractive", "-Command", 'Write-Output "reference"'),
    "redis_cli": ("--version",),
    "ldapsearch": ("-VV",),
}

# Independent startup csops snapshots on the installed macOS 27 reference tools.
# These are scoped observations, not a universal conversion of static flags.
_RUNTIME_FLAGS = {
    "7zip": 0x22020201,
    "git": 0x22000201,
    "docker": 0x22011311,
    "kubectl": 0x22020201,
    "make": 0x22020201,
    "vim": 0x22000201,
    "emacs": 0x22000201,
    "gcc": 0x22020201,
    "cargo": 0x22000201,
    "dotnet": 0x22000205,
    "msbuild": 0x22000205,
    "nodejs": 0x22000201,
    "npm": 0x22000201,
    "pip": 0x22000201,
    "pytest": 0x22000201,
    "powershell_query": 0x22000201,
    "redis_cli": 0x22000201,
    "ldapsearch": 0x22000201,
}


@pytest.mark.parametrize("application", _COMMANDS)
def test_installed_cli_has_shell_owned_native_exec(tmp_path: Path, application: str) -> None:
    scenario = _scenario("developer", [application])
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        user, system = scenario.environment.users[0], scenario.environment.systems[0]
        logon = engine.activity_generator.generate_logon(
            user, system, engine.start_time - timedelta(minutes=5)
        )
        image = engine.deployment_registry.application_descriptor(application, "macos").image_path
        arguments = (image, *_COMMANDS[application])
        pid = engine.activity_generator.generate_process(
            user,
            system,
            engine.start_time + timedelta(minutes=2),
            logon,
            image,
            shlex.join(arguments),
        )
        identity = engine.state_manager.get_process_identity(system.hostname, pid)
        parent = engine.state_manager.get_process_identity(system.hostname, identity.parent_pid)
        assert identity.execution_ordinal == 1 and identity.arguments == arguments
        assert identity.image_security.codesigning_flags == _RUNTIME_FLAGS[application]
        assert parent.image == "/bin/zsh"
        if application == "powershell_query":
            assert "DOTNET_ROOT=/opt/homebrew/opt/dotnet/libexec" in identity.environment
            assert "DOTNET_ROOT=/opt/homebrew/opt/dotnet/libexec" not in parent.environment
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
    finally:
        engine._close_emitters()
    targets = [
        row["event"]["exec"]
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
        if (row := json.loads(line))["event_type"] == 9
        and row["event"]["exec"]["target"]["executable"]["path"] == image
    ]
    assert len(targets) == 1 and targets[0]["args"] == list(arguments)
    assert targets[0]["target"]["codesigning_flags"] == _RUNTIME_FLAGS[application]
    if application == "powershell_query":
        assert "DOTNET_ROOT=/opt/homebrew/opt/dotnet/libexec" in targets[0]["env"]


@pytest.mark.parametrize("assignments", [("BAD",), ("X=1", "X=2"), ("X=bad\0value",)])
def test_command_environment_rejects_invalid_assignments(assignments: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        MacosCommandEnvironmentPolicy(image="/opt/example", environment=assignments)


def test_command_environment_preserves_supplied_and_unknown_values(tmp_path: Path) -> None:
    engine = GenerationEngine(_scenario("developer", ["powershell_query"]), tmp_path)
    try:
        engine._initialize()
        provider = engine.macos_execution_metadata
        image = "/opt/homebrew/opt/powershell/libexec/pwsh"
        assert provider.command_environment(image, None) is None
        inherited = ("DOTNET_ROOT=/custom/runtime", "OTHER=1", "OTHER=2")
        assert provider.command_environment(image, inherited) == inherited
        assert provider.command_environment("/unlisted/image", ("OTHER=1",)) == ("OTHER=1",)
    finally:
        engine._close_emitters()

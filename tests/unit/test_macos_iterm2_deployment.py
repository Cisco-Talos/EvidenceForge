# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Paired terminal prerequisites remain frozen installed facts, including the user cache."""

from copy import deepcopy
from pathlib import Path

import pytest

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.deployment_compiler import (
    _deployment_application_entries,
    compile_deployment_registry,
)
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_installed_provisioning import _scenario

_SERVER = "/Users/alex/Library/Application Support/iTerm2/iTermServer-3.7.6"
_SHELL = "/Applications/iTerm.app/Contents/MacOS/ShellLauncher"
_APP = "/Applications/iTerm.app/Contents/MacOS/iTerm2"


def _entries() -> list[ApplicationEntry]:
    return [
        ApplicationEntry.model_validate(application_descriptor(name))
        for name in ("macos-iterm2", "macos-iterm2-server", "macos-iterm2-shell-launcher")
    ]


@pytest.mark.parametrize("selected", [False, True])
def test_helpers_follow_owner_host_and_user_selection_without_becoming_user_apps(
    selected: bool,
) -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "applications": ["macos-iterm2"] if selected else [],
            "user_applications": [{"user": "alex", "applications": ["macos-iterm2"]}],
        }
    ]
    scenario = Scenario.model_validate(raw)
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=_entries()
    )
    images = {
        path: registry.resolve_binary("MAC-01", path, "macos", principal="alex")
        for path in (_APP, _SERVER, _SHELL)
    }
    assert all(binary is not None for binary in images.values()) == selected
    if not selected:
        assert all(binary is None for binary in images.values())
        return
    assert {binary.key.version for binary in images.values()} == {"3.7.6"}
    assert len({binary.release_id for binary in images.values()}) == 1
    assert len({binary.content_id for binary in images.values()}) == 3
    assert images[_SERVER].code_signature.signing_id == "iTermServer"
    assert images[_SERVER].code_signature.entitlements == ()
    assert images[_SHELL].code_signature.signing_id == "ShellLauncher"
    assert images[_SHELL].code_signature.entitlements == (
        ("com.apple.application-identifier", "H7V7XYVQ7D."),
    )
    assert registry.resolve_binary("MAC-01", _SERVER, "macos", principal="sam") is None
    placement = registry.installation_for_image("MAC-01", _SERVER, "macos", principal="alex")
    assert placement.scope == "user" and placement.principal == "alex"
    assert registry.application_descriptor("macos-iterm2-server", "macos").categories == (
        "terminal_helper",
    )


def test_user_exclusion_omits_the_support_cache_without_removing_the_machine_bundle() -> None:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "applications": ["macos-iterm2"],
            "user_applications": [{"user": "alex", "applications": []}],
        }
    ]
    scenario = Scenario.model_validate(raw)
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=_entries()
    )
    assert registry.resolve_binary("MAC-01", _APP, "macos", principal="alex") is not None
    assert registry.resolve_binary("MAC-01", _SHELL, "macos", principal="alex") is not None
    assert registry.resolve_binary("MAC-01", _SERVER, "macos", principal="alex") is None


@pytest.mark.parametrize("damage", ["missing", "self", "nested", "platform"])
def test_helper_dependency_rejects_ambiguous_or_recursive_placement(damage: str) -> None:
    owner, server, shell = deepcopy(_entries())
    if damage == "missing":
        server.installed_with = "missing"
    elif damage == "self":
        server.installed_with = server.id
    elif damage == "nested":
        server.installed_with = shell.id
    else:
        owner.platforms = {}
    with pytest.raises(ValueError, match="installed_with requires one independent"):
        _deployment_application_entries([owner, server, shell])


def test_installed_helpers_use_their_own_runtime_validation_policy(
    tmp_path: Path,
) -> None:
    from tests.unit.test_macos_terminal_applications import _engine

    engine = _engine(tmp_path, "macos-iterm2", native=False)
    try:
        engine._initialize()
        provider = engine.activity_generator.macos_execution_metadata
        registry = engine.dispatcher.deployment_registry
        for path, flags in ((_APP, 0x22015311), (_SERVER, 0x22011311), (_SHELL, 0x22011311)):
            binary = registry.resolve_binary("MAC-01", path, "macos", principal="alex")
            security = provider.image_security(binary)
            assert security.codesigning_flags == flags
            assert not security.is_platform_binary and security.validation_category == 6
            assert provider.image_cpu_subtype(binary) == 0
    finally:
        engine._close_emitters()

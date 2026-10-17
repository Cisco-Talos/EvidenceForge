# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit native image metadata compiles without inferring format from signing."""

from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.events.content_identity import MachOImageIdentity
from evidenceforge.generation.deployment_registry import (
    _pack_binary_release,
    _unpack_binary_release,
)
from tests.unit.test_macos_code_signature import _application, _release


@pytest.mark.parametrize("signed", [False, True])
def test_explicit_native_image_compiles_independently_of_signing(signed: bool) -> None:
    app = _application()
    platform = app.platforms["macos"]
    if not signed:
        platform.code_signature = None
    original = _release(app)
    assert original.mach_o_image is None
    platform.executable_format = "mach_o"
    binary = _release(ApplicationEntry.model_validate(app.model_dump(exclude_none=True)))
    assert binary.mach_o_image == MachOImageIdentity.derive(binary.key)
    assert binary.code_signature == original.code_signature
    assert binary.release_id == original.release_id
    assert binary.content_id == original.content_id
    assert binary.digests == original.digests
    assert _unpack_binary_release(_pack_binary_release(binary)) == binary
    moved = app.model_copy(deep=True)
    moved.platforms[
        "macos"
    ].image_path = "/Users/example/Applications/Example.app/Contents/MacOS/Example"
    assert _release(moved) == binary
    upgraded = moved.model_copy(deep=True)
    upgraded.platforms["macos"].deployment = platform.deployment.model_copy(update={"build": "2"})
    assert _release(upgraded).mach_o_image != binary.mach_o_image


def test_unknown_image_format_does_not_acquire_native_metadata_from_signing_or_path() -> None:
    app = _application()
    assert _release(app).code_signature is not None
    assert _release(app).mach_o_image is None
    app.platforms["macos"].image_path = "/usr/local/bin/example-script"
    assert _release(app).mach_o_image is None
    assert "executable_format" not in app.model_dump(exclude_none=True)["platforms"]["macos"]


def test_main_image_metadata_does_not_leak_into_helper_release() -> None:
    app = _application()
    app.platforms["macos"].executable_format = "mach_o"
    main = _release(app)
    helper = _release(app, "/Applications/Example.app/Contents/Helpers/Worker")
    assert main.mach_o_image is not None
    assert helper.mach_o_image is None and helper.code_signature is None
    assert replace(main, code_signature=None).mach_o_image == main.mach_o_image


@pytest.mark.parametrize(
    "damage", ["linux", "windows", "x64", "neutral", "mixed", "legacy_static", "unknown"]
)
def test_unsupported_native_image_profile_fails_at_catalog_boundary(damage: str) -> None:
    document = _application().model_dump()
    platform = document["platforms"]["macos"]
    platform["executable_format"] = "mach_o"
    platform["code_signature"] = None
    if damage in {"linux", "windows"}:
        document["platforms"] = {damage: platform}
    elif damage == "legacy_static":
        platform["deployment"] = {"kind": "legacy_static"}
    elif damage == "unknown":
        platform["executable_format"] = "elf"
    else:
        platform["deployment"]["architectures"] = (
            ["arm64", "x64"] if damage == "mixed" else [damage]
        )
    with pytest.raises(ValidationError, match="executable_format|architectures"):
        ApplicationEntry.model_validate(document)


@pytest.mark.parametrize(
    "image",
    [
        "/sbin/launchd",
        "/System/Library/CoreServices/logind",
        "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
    ],
)
def test_catalog_boot_image_facts_reach_compiled_host_identity(
    scenarios_dir: Path, image: str
) -> None:
    from evidenceforge.generation.deployment_compiler import compile_native_deployment_registry
    from evidenceforge.generation.world_model import WorldModel
    from tests.support.macos_ssh import macos_ssh_scenario

    scenario = macos_ssh_scenario(scenarios_dir)
    registry = compile_native_deployment_registry(scenario, WorldModel(scenario, "example.test"))
    binary = registry.resolve_binary("TEST-01", image, "macos")
    assert binary is not None and binary.mach_o_image is not None
    assert binary.mach_o_image == MachOImageIdentity.derive(binary.key)
    assert binary.code_signature is None

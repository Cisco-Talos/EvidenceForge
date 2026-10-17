# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac helper paths retain the installed browser release and platform isolation."""

import shlex
from pathlib import Path

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import (
    application_descriptor,
    get_child_processes,
)
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.world_model import WorldModel
from tests.support.macos_ssh import macos_ssh_scenario


def test_chrome_mac_helpers_have_distinct_images_and_minimal_role_arguments() -> None:
    app = ApplicationEntry.model_validate(application_descriptor("chrome"))
    platform = app.platforms["macos"]
    children = get_child_processes("macos", "Google Chrome")
    assert len(children) == 3
    assert {shlex.split(row["command_line"])[1] for row in children} == {
        "--type=renderer",
        "--type=gpu-process",
        "--type=utility",
    }
    images = {row["image"] for row in children}
    assert len(images) == 3 and platform.image_path not in images
    for row in children:
        assert shlex.split(row["command_line"])[0] == row["image"]
        assert f"/Versions/{platform.deployment.version}/Helpers/" in row["image"]
        assert row["image"].startswith("/Applications/Google Chrome.app/")
    assert not get_child_processes("linux", "Google Chrome")
    assert not get_child_processes("macos", "chrome.exe")
    assert all(
        row["image"].startswith("C:") for row in get_child_processes("windows", "chrome.exe")
    )


def test_chrome_helpers_compile_as_distinct_binaries_in_same_installed_release(
    scenarios_dir: Path,
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    app = ApplicationEntry.model_validate(application_descriptor("chrome"))
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=(app,)
    )
    main = registry.resolve_binary("TEST-01", app.platforms["macos"].image_path, "macos")
    assert main is not None
    content_ids = {main.content_id}
    for row in get_child_processes("macos", "Google Chrome"):
        helper = registry.resolve_binary("TEST-01", row["image"], "macos")
        assert helper is not None
        assert helper.key.product_id == main.key.product_id
        assert helper.key.version == main.key.version
        assert helper.key.build == main.key.build
        assert helper.key.architecture == "arm64"
        assert helper.content_id not in content_ids
        content_ids.add(helper.content_id)
        assert helper.mach_o_image is None and helper.code_signature is None
        assert registry.resolve_binary("SSH-TEST", row["image"], "linux") is None
    assert len(content_ids) == 4

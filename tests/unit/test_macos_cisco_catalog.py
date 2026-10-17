# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native Cisco GUI catalog and deployment contracts."""

import shlex

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import (
    application_descriptor,
    get_apps_for_persona,
)
from evidenceforge.generation.activity.spawn_rules import get_parent_config
from evidenceforge.generation.deployment_compiler import _release_for_application_artifact


def test_mac_cisco_gui_keeps_ui_release_distinct_from_vpn_core() -> None:
    app = ApplicationEntry.model_validate(application_descriptor("cisco_secure_client"))
    platform = app.platforms["macos"]
    image = "/Applications/Cisco/Cisco Secure Client.app/Contents/MacOS/Cisco Secure Client"
    assert platform.image_path == image
    assert shlex.split(platform.command_templates[0]) == [image]
    assert (platform.deployment.version, platform.deployment.build) == ("5.1.16", "1663")
    assert tuple(platform.deployment.architectures) == ("arm64",)
    release = _release_for_application_artifact(
        app, "macos", platform, image, None, "arm64", "26.0"
    )
    assert release.key.product_id == "cisco-secure-client-ui"
    assert release.key.artifact_name == "Cisco Secure Client"
    assert release.mach_o_image is None and release.code_signature is None
    assert app.compatibility_group == "remote_access_stack"
    assert app.compatibility_option == "cisco_secure_client"
    assert not platform.children
    assert not get_parent_config("macos", "Cisco Secure Client")["children"]
    assert "Cisco Secure Client" in get_parent_config("macos", "launchd")["children"]
    selected: set[str] = set()
    for index in range(32):
        options = {
            item["id"]
            for item in get_apps_for_persona(
                "analyst", "macos", "user_app", "workstation", deployment_key=f"mac-{index}"
            )
        } & {"cisco_secure_client", "globalprotect"}
        assert len(options) == 1
        selected.update(options)
    assert selected == {"cisco_secure_client", "globalprotect"}
    assert app.platforms["windows"].image_path.endswith("\\vpnui.exe")

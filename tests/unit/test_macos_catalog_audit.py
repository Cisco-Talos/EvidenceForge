# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ensure catalog audit decisions agree with the admitted platform variants."""

from pathlib import Path

import yaml

from evidenceforge.generation.activity.application_catalog import get_apps_for_persona
from evidenceforge.validation.configuration import ValidationResult, _validate_process_chains


def test_mac_catalog_audit_covers_original_entries_and_admitted_variants() -> None:
    root = Path(__file__).resolve().parents[2]
    catalog = yaml.safe_load(
        (root / "src/evidenceforge/config/activity/application_catalog.yaml").read_text()
    )
    audit = yaml.safe_load(
        (root / "docs/design/macos-workstation-feasibility/catalog-audit.yaml").read_text()
    )
    original = {
        app["id"]: app for app in catalog["applications"] if not app["id"].startswith("macos-")
    }
    decisions = {entry["id"]: entry for entry in audit["applications"]}
    assert len(original) == len(audit["applications"]) == 67
    assert decisions.keys() == original.keys()
    for app_id, decision in decisions.items():
        assert decision["availability"] in {"supported", "unavailable", "unresolved"}
        assert decision["reference"].startswith("https://")
        assert decision["boundary"]
        assert (decision["variant"] == "prefilled") == ("macos" in original[app_id]["platforms"])
        if decision["variant"] == "prefilled":
            assert decision["availability"] == "supported"


def test_catalog_only_native_services_do_not_become_user_apps_or_root_boot_processes() -> None:
    root = Path(__file__).resolve().parents[2]
    catalog = yaml.safe_load(
        (root / "src/evidenceforge/config/activity/application_catalog.yaml").read_text()
    )
    audit = yaml.safe_load(
        (root / "docs/design/macos-workstation-feasibility/native-catalog-audit.yaml").read_text()
    )
    apps = {entry["id"]: entry for entry in catalog["applications"]}
    assert len(audit["applications"]) == 18
    for entry in audit["applications"]:
        app = apps[entry["id"]]
        assert app["categories"] == ["macos_service"]
        assert app["personas"] == []
        assert app["platforms"]["macos"]["image_path"] == entry["image_path"]
        assert app["platforms"]["macos"]["deployment"]["architectures"] == ["arm64"]
        assert entry["behavior"] == "catalog_only"
    assert not get_apps_for_persona("default", "macos", category="macos_service")


def test_catalog_only_services_remain_known_without_requiring_baseline_spawn_rules() -> None:
    result = ValidationResult()
    service = {
        "id": "sample-service",
        "personas": [],
        "platforms": {"macos": {"image_path": "/usr/libexec/sample-service"}},
    }
    _validate_process_chains(
        apps=[service],
        process_net_data={},
        result=result,
        spawn_data={},
        sys_proc_data={},
    )
    assert result.issues == []
    # Explicit children may reference the service even without persona activation.
    _validate_process_chains(
        apps=[service],
        process_net_data={},
        result=result,
        spawn_data={"macos": {"launchd": {"children": ["sample-service"]}}},
        sys_proc_data={},
    )
    assert result.issues == []
    service["personas"] = ["default"]
    _validate_process_chains(
        apps=[service],
        process_net_data={},
        result=result,
        spawn_data={},
        sys_proc_data={},
    )
    assert len(result.issues) == 1
    assert result.issues[0].severity == "INFO"
    assert "sample-service" in result.issues[0].message


def test_mac_ssh_native_actor_is_bundle_owned_and_separate_from_homebrew() -> None:
    from evidenceforge.generation.activity.application_catalog import application_descriptor

    native = application_descriptor("macos-ssh")
    managed = application_descriptor("ssh")
    assert native["platforms"]["macos"]["image_path"] == "/usr/bin/ssh"
    assert managed["platforms"]["macos"]["image_path"] == "/opt/homebrew/bin/ssh"
    assert native["platforms"]["macos"]["deployment"]["release_policy"] == "host_build"
    assert native["personas"] == []
    assert not get_apps_for_persona("default", "macos", category="macos_transport")


def test_citrix_mac_variant_retains_quoted_native_launch_and_existing_personas() -> None:
    import shlex

    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.activity.spawn_rules import get_parent_config

    app = application_descriptor("citrix_workspace")
    platform = app["platforms"]["macos"]
    assert tuple(platform["deployment"]["architectures"]) == ("arm64",)
    assert platform["deployment"]["version"] == "26.09.0.17"
    assert shlex.split(platform["command_templates"][0]) == [platform["image_path"]]
    assert not get_parent_config("macos", "Citrix Workspace")["children"]
    assert "citrix_workspace" in {
        item["id"] for item in get_apps_for_persona("analyst", "macos", "user_app", "workstation")
    }
    assert app["platforms"]["windows"]["image_path"].endswith("SelfService.exe")


def test_acrobat_mac_launch_uses_existing_unspecified_release_semantics() -> None:
    import shlex

    from evidenceforge.config.schemas import ApplicationEntry
    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.activity.spawn_rules import get_parent_config
    from evidenceforge.generation.deployment_compiler import _release_for_application_artifact

    descriptor = application_descriptor("acrobat")
    app = ApplicationEntry.model_validate(descriptor)
    platform = app.platforms["macos"]
    assert shlex.split(platform.command_templates[0]) == [platform.image_path]
    assert tuple(platform.deployment.architectures) == ("arm64",)
    release = _release_for_application_artifact(
        app, "macos", platform, platform.image_path, None, "arm64", "26.0"
    )
    assert release.key.product_id == "acrobat"
    assert release.key.version == release.key.build == "unspecified"
    assert release.code_signature is None
    assert not get_parent_config("macos", "AdobeAcrobat")["children"]
    assert app.platforms["windows"].image_path.endswith("Acrobat.exe")

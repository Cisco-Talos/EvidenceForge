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
        (root / "src/evidenceforge/config/activity/application_catalog.yaml").read_text(
            encoding="utf-8"
        )
    )
    audit = yaml.safe_load(
        (root / "docs/design/macos-workstation-feasibility/catalog-audit.yaml").read_text(
            encoding="utf-8"
        )
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


def test_native_service_audit_distinguishes_only_the_two_qualified_residents() -> None:
    root = Path(__file__).resolve().parents[2]
    catalog = yaml.safe_load(
        (root / "src/evidenceforge/config/activity/application_catalog.yaml").read_text(
            encoding="utf-8"
        )
    )
    audit = yaml.safe_load(
        (root / "docs/design/macos-workstation-feasibility/native-catalog-audit.yaml").read_text(
            encoding="utf-8"
        )
    )
    apps = {entry["id"]: entry for entry in catalog["applications"]}
    assert len(audit["applications"]) == 18
    for entry in audit["applications"]:
        app = apps[entry["id"]]
        resident = entry["id"] in {"macos-cfprefsd", "macos-launchservicesd"}
        assert app["categories"] == (
            ["macos_service", "macos_resident"] if resident else ["macos_service"]
        )
        assert entry["behavior"] == ("preexisting_root_resident" if resident else "catalog_only")
        assert app["personas"] == []
        assert app["platforms"]["macos"]["image_path"] == entry["image_path"]
        assert app["platforms"]["macos"]["deployment"]["architectures"] == ["arm64"]
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
    assert release.code_signature is not None
    assert release.code_signature.signing_id == "com.adobe.Acrobat.Pro"
    assert release.code_signature.team_id == "JQ525L2MZD"
    assert not get_parent_config("macos", "AdobeAcrobat")["children"]
    assert app.platforms["windows"].image_path.endswith("Acrobat.exe")


def test_webex_mac_launch_uses_public_package_release_and_existing_personas() -> None:
    import shlex

    from evidenceforge.config.schemas import ApplicationEntry
    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.activity.spawn_rules import get_parent_config

    app = ApplicationEntry.model_validate(application_descriptor("webex"))
    platform = app.platforms["macos"]
    assert platform.image_path == "/Applications/Webex.app/Contents/MacOS/Webex"
    assert shlex.split(platform.command_templates[0]) == [platform.image_path]
    assert platform.deployment.version == "46.10.0.36042"
    assert platform.deployment.build == "36042"
    assert tuple(platform.deployment.architectures) == ("arm64",)
    assert platform.code_signature is not None
    assert platform.code_signature.signing_id == "Cisco-Systems.Spark"
    assert platform.code_signature.team_id == "DE8Y96K9QP"
    assert not get_parent_config("macos", "Webex")["children"]
    assert "webex" in {
        item["id"] for item in get_apps_for_persona("analyst", "macos", "user_app", "workstation")
    }
    assert app.platforms["windows"].image_path == r"C:\Program Files\Cisco Spark\Webex.exe"


def test_globalprotect_mac_launch_preserves_stack_selection_and_excludes_unmodeled_helpers() -> (
    None
):
    import shlex

    from evidenceforge.config.schemas import ApplicationEntry
    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.activity.spawn_rules import get_parent_config

    app = ApplicationEntry.model_validate(application_descriptor("globalprotect"))
    platform = app.platforms["macos"]
    assert platform.image_path == "/Applications/GlobalProtect.app/Contents/MacOS/GlobalProtect"
    assert shlex.split(platform.command_templates[0]) == [platform.image_path]
    assert (platform.deployment.version, platform.deployment.build) == ("6.3.3", "c711")
    assert tuple(platform.deployment.architectures) == ("arm64",)
    assert app.compatibility_group == "remote_access_stack"
    assert app.compatibility_option == "globalprotect"
    assert platform.code_signature is not None
    assert platform.code_signature.signing_id == "com.paloaltonetworks.GlobalProtect.client"
    assert platform.code_signature.team_id == "PXPZ95SK77"
    assert not platform.children
    assert not get_parent_config("macos", "GlobalProtect")["children"]
    assert "globalprotect" in {
        item["id"] for item in get_apps_for_persona("analyst", "macos", "user_app", "workstation")
    }
    assert (
        app.platforms["windows"].image_path
        == r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
    )


def test_mac_receiver_catalog_preserves_split_roles_without_baseline_activation() -> None:
    import shlex

    from evidenceforge.config.schemas import ApplicationEntry
    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.deployment_compiler import _release_for_application_artifact

    root = Path(__file__).resolve().parents[2]
    audit = yaml.safe_load(
        (root / "docs/design/macos-workstation-feasibility/native-catalog-audit.yaml").read_text(
            encoding="utf-8"
        )
    )
    entries = [row for row in audit["action_applications"] if row["id"] != "macos-ssh"]
    assert {entry["id"] for entry in entries} == {
        "macos-sshd-keygen-wrapper",
        "macos-sshd",
        "macos-sshd-session",
        "macos-sshd-auth",
    }
    paths = set()
    for entry in entries:
        app = ApplicationEntry.model_validate(application_descriptor(entry["id"]))
        assert set(app.platforms) == {"macos"}
        assert not app.personas
        assert app.categories == ["macos_transport"]
        platform = app.platforms["macos"]
        assert platform.image_path == entry["image_path"]
        assert tuple(platform.deployment.architectures) == ("arm64",)
        assert platform.deployment.release_policy == "host_build"
        argv = shlex.split(platform.command_templates[0])
        if entry["id"] == "macos-sshd-keygen-wrapper":
            assert argv == ["sshd-keygen-wrapper"]
        else:
            assert argv[0] == platform.image_path
        release = _release_for_application_artifact(
            app, "macos", platform, platform.image_path, None, "arm64", "26.0"
        )
        assert release.key.product_id == "apple-macos"
        assert release.code_signature.signing_id == platform.code_signature.signing_id
        assert release.code_signature.team_id is None
        assert release.mach_o_image.architecture == "arm64"
        assert entry["behavior"] == "ssh_receiver_bundle"
        assert entry["references"] and all(
            url.startswith("https://github.com/apple-oss-distributions/")
            for url in entry["references"]
        )
        paths.add(platform.image_path)
    assert len(paths) == 4
    assert not get_apps_for_persona("default", "macos", category="macos_transport")
    assert application_descriptor("macos-sshd")["platforms"]["macos"]["command_templates"] == [
        "/usr/sbin/sshd -i"
    ]


def test_readable_mac_audit_matches_every_machine_readable_decision() -> None:
    root = Path(__file__).resolve().parents[2] / "docs/design/macos-workstation-feasibility"
    readable = (root / "catalog-audit.md").read_text(encoding="utf-8")
    audit = yaml.safe_load((root / "catalog-audit.yaml").read_text(encoding="utf-8"))
    for entry in audit["applications"]:
        rows = [line for line in readable.splitlines() if line.startswith(f"| `{entry['id']}` |")]
        assert len(rows) == 1, entry["id"]
        assert rows[0].startswith(
            f"| `{entry['id']}` | {entry['availability']} | {entry['variant']} |"
        ), entry["id"]


def test_tableau_mac_launch_uses_arm64_tahoe_release_and_preserves_windows_variant() -> None:
    import shlex

    from evidenceforge.config.schemas import ApplicationEntry
    from evidenceforge.generation.activity.application_catalog import application_descriptor
    from evidenceforge.generation.activity.spawn_rules import get_parent_config
    from evidenceforge.generation.deployment_compiler import _release_for_application_artifact

    app = ApplicationEntry.model_validate(application_descriptor("tableau_desktop"))
    platform = app.platforms["macos"]
    assert platform.image_path == "/Applications/Tableau Desktop 2026.1.app/Contents/MacOS/Tableau"
    assert shlex.split(platform.command_templates[0]) == [platform.image_path]
    assert tuple(platform.deployment.architectures) == ("arm64",)
    release = _release_for_application_artifact(
        app, "macos", platform, platform.image_path, None, "arm64", "26.0"
    )
    assert (release.key.product_id, release.key.version, release.key.build) == (
        "tableau_desktop",
        "2026.1",
        "20261.26.0226.1626",
    )
    assert release.code_signature is not None
    assert release.code_signature.signing_id == "com.tableausoftware.tableaudesktop"
    assert release.code_signature.team_id == "QJ4XPRK37C"
    assert not platform.children and not platform.loaded_modules
    assert not get_parent_config("macos", "Tableau")["children"]
    assert "Tableau" in get_parent_config("macos", "launchd")["children"]
    assert "tableau_desktop" in {
        entry["id"] for entry in get_apps_for_persona("analyst", "macos", "user_app", "workstation")
    }
    assert app.platforms["windows"].image_path.endswith(r"Tableau 2024.1\bin\tableau.exe")

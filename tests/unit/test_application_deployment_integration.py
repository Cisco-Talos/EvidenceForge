# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Installed-application content identity compilation and rendering probes."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import load_catalog
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario

_SCENARIO_PATH = Path(__file__).parents[1] / "fixtures" / "scenarios" / "minimal.yaml"
_APP_PATHS = {
    "slack": r"C:\Users\{username}\AppData\Local\slack\Slack.exe",
    "zoom": r"C:\Users\{username}\AppData\Roaming\Zoom\bin\Zoom.exe",
    "postman": r"C:\Users\{username}\AppData\Local\Postman\Postman.exe",
}
_MODULE_PATHS = {
    "slack": r"C:\Users\{username}\AppData\Local\slack\app-4.38.125\slack_elf.dll",
    "zoom": r"C:\Users\{username}\AppData\Roaming\Zoom\bin\zVideoApp.dll",
    "postman": r"C:\Users\{username}\AppData\Local\Postman\app-11.2.14\Postman.dll",
}


def _user(username: str, persona: str, hostname: str) -> dict[str, object]:
    return {
        "username": username,
        "full_name": username.replace("_", " ").title(),
        "email": f"{username}@example.com",
        "primary_system": hostname,
        "enabled": True,
        "persona": persona,
    }


def _system(
    hostname: str,
    ip_suffix: int,
    *,
    system_type: str = "workstation",
    architecture: str = "x64",
) -> dict[str, object]:
    return {
        "hostname": hostname,
        "ip": f"10.0.0.{ip_suffix}",
        "os": "Windows Server 2022" if system_type != "workstation" else "Windows 11 Enterprise",
        "os_build": "10.0.22631.3880",
        "architecture": architecture,
        "type": system_type,
    }


def _scenario(
    users: list[dict[str, object]],
    systems: list[dict[str, object]],
    *,
    deployment_overrides: list[dict[str, object]] | None = None,
) -> Scenario:
    payload = yaml.safe_load(_SCENARIO_PATH.read_text(encoding="utf-8"))
    payload["environment"]["users"] = users
    payload["environment"]["systems"] = systems
    payload["environment"]["network"]["segments"][0]["systems"] = [
        system["hostname"] for system in systems
    ]
    if deployment_overrides is not None:
        payload["environment"]["deployment_overrides"] = deployment_overrides
    return Scenario.model_validate(payload)


def _compile(
    scenario: Scenario,
    *,
    applications: tuple[ApplicationEntry, ...] | None = None,
):
    return compile_deployment_registry(
        scenario,
        WorldModel(scenario, "example.com"),
        application_entries=applications,
    )


def _application(application_id: str) -> ApplicationEntry:
    raw = next(
        application
        for application in load_catalog()["applications"]
        if application["id"] == application_id
    )
    return ApplicationEntry.model_validate(raw)


def _application_variant(
    application: ApplicationEntry,
    *,
    version: str | None = None,
    build: str | None = None,
    prevalence: float | None = None,
) -> ApplicationEntry:
    payload = application.model_dump(mode="python")
    windows = payload["platforms"]["windows"]
    deployment = windows["deployment"]
    if version is not None:
        deployment["version"] = version
        windows["pe_metadata"]["file_version"] = version
        for module in windows.get("loaded_modules") or []:
            if module.get("pe_metadata") is not None:
                module["pe_metadata"]["file_version"] = version
    if build is not None:
        deployment["build"] = build
    if prevalence is not None:
        deployment["fleet_prevalence"] = prevalence
    return ApplicationEntry.model_validate(payload)


def _resolved(registry, hostname: str, username: str, application_id: str):
    return registry.resolve_binary(
        hostname,
        _APP_PATHS[application_id].format(username=username),
        "windows",
        principal=username,
    )


def test_application_release_is_shared_across_users_and_hosts_but_separated_by_architecture() -> (
    None
):
    """Placement does not perturb content, while architecture remains a release dimension."""

    scenario = _scenario(
        [
            _user("alice", "developer", "WS-A"),
            _user("alex", "developer", "WS-A"),
            _user("bob", "developer", "WS-B"),
            _user("arm_user", "developer", "WS-ARM"),
        ],
        [
            _system("WS-A", 1),
            _system("WS-B", 2),
            _system("WS-ARM", 3, architecture="arm64"),
        ],
    )
    registry = _compile(scenario)

    alice = _resolved(registry, "WS-A", "alice", "slack")
    alex = _resolved(registry, "WS-A", "alex", "slack")
    bob = _resolved(registry, "WS-B", "bob", "slack")
    arm = _resolved(registry, "WS-ARM", "arm_user", "slack")
    assert alice is not None and alex is not None and bob is not None and arm is not None
    assert alice is alex is bob
    assert alice.content_id == alex.content_id == bob.content_id
    assert alice.digests == alex.digests == bob.digests
    assert alice.content_id != arm.content_id
    assert alice.release_id != arm.release_id
    assert registry.count_installations_for_application("WS-A", "slack") == 2

    alice_module = registry.resolve_binary(
        "WS-A",
        _MODULE_PATHS["slack"].format(username="alice"),
        "windows",
        principal="alice",
    )
    bob_module = registry.resolve_binary(
        "WS-B",
        _MODULE_PATHS["slack"].format(username="bob"),
        "windows",
        principal="bob",
    )
    assert alice_module is bob_module
    assert alice_module is not None and alice_module.release_id == alice.release_id


def test_build_and_version_changes_separate_application_content() -> None:
    """Application release compilation preserves both version and build dimensions."""

    scenario = _scenario([_user("alice", "developer", "WS-A")], [_system("WS-A", 1)])
    slack = _application("slack")
    build_variant = _application_variant(slack, build="4.38.125+rev2")
    version_variant = _application_variant(
        slack,
        version="4.39.0",
        build="4.39.0",
    )

    baseline = _resolved(_compile(scenario, applications=(slack,)), "WS-A", "alice", "slack")
    changed_build = _resolved(
        _compile(scenario, applications=(build_variant,)),
        "WS-A",
        "alice",
        "slack",
    )
    changed_version = _resolved(
        _compile(scenario, applications=(version_variant,)),
        "WS-A",
        "alice",
        "slack",
    )

    assert baseline is not None and changed_build is not None and changed_version is not None
    assert len({baseline.content_id, changed_build.content_id, changed_version.content_id}) == 3
    assert len({baseline.release_id, changed_build.release_id, changed_version.release_id}) == 3


def test_placement_is_host_application_and_persona_intersection() -> None:
    """Only compatible installed applications become per-user installations and assignments."""

    scenario = _scenario(
        [
            _user("alice", "developer", "WS-A"),
            _user("bob", "accountant", "WS-A"),
            _user("server_admin", "developer", "APP-01"),
        ],
        [
            _system("WS-A", 1),
            _system("APP-01", 2, system_type="server"),
        ],
        deployment_overrides=[
            {"system": "WS-A", "applications": ["slack", "postman"]},
            {"system": "APP-01", "applications": ["slack", "postman"]},
        ],
    )
    registry = _compile(scenario)

    assert registry.count_installations_for_application("WS-A", "slack") == 2
    assert registry.count_installations_for_application("WS-A", "postman") == 1
    assert registry.count_installations_for_application("WS-A", "zoom") == 0
    assert registry.count_installations_for_application("APP-01", "slack") == 0
    assert _resolved(registry, "WS-A", "bob", "postman") is None
    assert _resolved(registry, "APP-01", "server_admin", "slack") is None
    assert (
        registry.resolve_binary(
            "WS-A",
            _MODULE_PATHS["zoom"].format(username="alice"),
            "windows",
            principal="alice",
        )
        is None
    )

    alice_postman = tuple(registry.installations_for_principal("WS-A", "alice", "windows"))
    bob_postman = tuple(registry.installations_for_principal("WS-A", "bob", "windows"))
    assert {installation.application_id for installation in alice_postman} >= {"slack", "postman"}
    assert "postman" not in {installation.application_id for installation in bob_postman}
    postman_assignments = registry.user_application_assignments_for_product("WS-A", "postman")
    assert [(assignment.principal, assignment.persona) for assignment in postman_assignments] == [
        ("alice", "developer")
    ]


def test_exact_host_user_and_module_overrides_win_over_prevalence() -> None:
    """Exact replacements can force placement, remove a user, and suppress modules."""

    slack = _application_variant(_application("slack"), prevalence=0.0)
    scenario = _scenario(
        [
            _user("alice", "developer", "WS-A"),
            _user("bob", "developer", "WS-A"),
            _user("carol", "developer", "WS-B"),
        ],
        [_system("WS-A", 1), _system("WS-B", 2)],
        deployment_overrides=[
            {
                "system": "WS-A",
                "applications": ["slack"],
                "modules": [],
                "user_applications": [
                    {"user": "alice", "applications": ["slack"]},
                    {"user": "bob", "applications": []},
                ],
            }
        ],
    )
    registry = _compile(scenario, applications=(slack,))

    assert _resolved(registry, "WS-A", "alice", "slack") is not None
    assert _resolved(registry, "WS-A", "bob", "slack") is None
    assert _resolved(registry, "WS-B", "carol", "slack") is None
    assert registry.count_installations_for_application("WS-A", "slack") == 1
    assert (
        registry.user_application_assignments_for_product("WS-A", "slack")[0].principal == "alice"
    )
    deployment = registry.host_deployment("WS-A")
    assert deployment is not None and deployment.module_handles == ()
    assert (
        registry.resolve_binary(
            "WS-A",
            _MODULE_PATHS["slack"].format(username="alice"),
            "windows",
            principal="alice",
        )
        is None
    )


def test_application_deployment_is_order_and_hash_seed_independent() -> None:
    """Application digests and assignment/deployment identities are deterministic."""

    users = [_user("alice", "developer", "WS-A"), _user("bob", "developer", "WS-B")]
    systems = [_system("WS-A", 1), _system("WS-B", 2)]
    first = _compile(_scenario(users, systems))
    second = _compile(_scenario(list(reversed(users)), list(reversed(systems))))
    for hostname, username in (("WS-A", "alice"), ("WS-B", "bob")):
        first_identity = _resolved(first, hostname, username, "slack")
        second_identity = _resolved(second, hostname, username, "slack")
        first_deployment = first.host_deployment(hostname)
        second_deployment = second.host_deployment(hostname)
        assert first_identity is not None and second_identity is not None
        assert first_identity.content_id == second_identity.content_id
        assert first_identity.digests == second_identity.digests
        assert first_deployment is not None and second_deployment is not None
        assert first_deployment.deployment_id == second_deployment.deployment_id

    script = r"""
import json
from pathlib import Path
import yaml
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import Scenario

payload = yaml.safe_load(Path("tests/fixtures/scenarios/minimal.yaml").read_text())
payload["environment"]["users"][0]["persona"] = "developer"
scenario = Scenario.model_validate(payload)
registry = compile_deployment_registry(scenario, WorldModel(scenario, "example.com"))
identity = registry.resolve_binary(
    "TEST-01",
    r"C:\Users\test_user\AppData\Local\slack\Slack.exe",
    "windows",
    principal="test_user",
)
assignment = registry.user_application_assignments_for_product("TEST-01", "slack")[0]
print(json.dumps({
    "content": identity.content_id,
    "digests": [identity.digests.md5, identity.digests.sha1, identity.digests.sha256],
    "assignment": assignment.assignment_id,
}, sort_keys=True))
"""
    outputs: list[str] = []
    for seed in ("1", "8675309"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            check=True,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]

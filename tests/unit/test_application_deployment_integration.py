# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Installed-application content identity compilation and rendering probes."""

from __future__ import annotations

import copy
import os
import random
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import load_catalog
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.deployment_registry import (
    _compiled_command_executables,
    _split_compiled_command_executable,
)
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


def _custom_slack_descriptor(
    application_id: str,
    image_path: str,
    command_template: str,
) -> ApplicationEntry:
    payload = _application("slack").model_dump(mode="python")
    payload["id"] = application_id
    payload["display_name"] = "Custom Slack"
    payload["categories"] = ["user_app"]
    payload["singleton_per_session"] = True
    windows = payload["platforms"]["windows"]
    windows["image_path"] = image_path
    windows["command_templates"] = [command_template]
    windows["command_parameter_pools"] = {"tenant": ["blue"]}
    windows["children"] = []
    windows["loaded_modules"] = []
    windows["pe_metadata"]["original_filename"] = image_path.rsplit("\\", 1)[-1]
    if application_id != "slack":
        windows["deployment"]["product_id"] = application_id
    payload["platforms"] = {"windows": windows}
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


def test_compiled_application_descriptor_owns_custom_command_and_executable_truth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public custom entries remain exact after compilation without global catalog reads."""

    application = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant {tenant} --user {username}',
    )
    payload = application.model_dump(mode="python")
    payload["platforms"]["windows"]["command_parameter_pools"] = {"tenant": ["blue-{username}"]}
    application = ApplicationEntry.model_validate(payload)
    scenario = _scenario(
        [
            _user("alice", "developer", "WS-A"),
            _user("bob", "developer", "WS-A"),
        ],
        [_system("WS-A", 1)],
    )
    import evidenceforge.generation.deployment_compiler as deployment_compiler

    monkeypatch.setattr(
        deployment_compiler,
        "load_catalog",
        lambda: pytest.fail("global application catalog was consulted"),
    )
    registry = _compile(scenario, applications=(application,))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    assert assignment is not None
    bob_profile = registry.user_profile_for("WS-A", "bob", "windows")
    assert bob_profile is not None
    bob_assignment = registry.user_application_assignment_for_application(
        bob_profile.profile_id,
        "custom_slack",
    )
    assert bob_assignment is not None

    descriptor = registry.application_descriptor("custom_slack", "windows")
    assert descriptor is not None
    assert descriptor.image_path == r"C:\Custom\custom-slack.exe"
    assert descriptor.command_templates == (
        r'"C:\Custom\custom-slack.exe" --tenant {tenant} --user {username}',
    )
    assert descriptor.command_parameter_pools == (("tenant", ("blue-{username}",)),)
    assert descriptor.categories == ("user_app",)
    assert descriptor.singleton_per_session is True
    assert assignment.selection_ordinal == descriptor.selection_ordinal
    executable_ids = registry.application_ids_for_executable(
        "windows",
        "CUSTOM-SLACK.EXE",
    )
    assert executable_ids == ("custom_slack",)
    assert executable_ids is registry.application_ids_for_executable(
        "windows",
        "custom-slack.exe",
    )
    assert copy.copy(descriptor) == descriptor
    assert copy.deepcopy(descriptor) == descriptor

    application.platforms["windows"].command_templates.append("mutated after compile")
    application.categories.append("mutated")
    assert registry.application_descriptor("custom_slack", "windows") == descriptor

    from evidenceforge.generation.activity import application_catalog

    monkeypatch.setattr(
        application_catalog,
        "materialize_application_command",
        lambda *_args, **_kwargs: pytest.fail("global application catalog was consulted"),
    )
    assert registry.materialize_application_command(
        random.Random(0),
        assignment,
        username="alice",
        category="user_app",
    ) == (
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant blue-alice --user alice',
    )
    for copied_assignment in (copy.copy(assignment), copy.deepcopy(assignment)):
        assert copied_assignment.selection_ordinal == descriptor.selection_ordinal
        assert registry.materialize_application_command(
            random.Random(0),
            copied_assignment,
            username="alice",
            category="user_app",
        ) == (
            r"C:\Custom\custom-slack.exe",
            r'"C:\Custom\custom-slack.exe" --tenant blue-alice --user alice',
        )

    invalid_cases = (
        {
            "assignment": assignment,
            "username": "mallory",
            "category": None,
        },
        {
            "assignment": assignment,
            "username": "alice",
            "category": "browser",
        },
        {
            "assignment": replace(
                assignment,
                installation_handle=bob_assignment.installation_handle,
            ),
            "username": "alice",
            "category": "user_app",
        },
        {
            "assignment": replace(
                assignment,
                materialization_principal="ALICE",
            ),
            "username": "alice",
            "category": "user_app",
        },
        {
            "assignment": replace(
                assignment,
                selection_ordinal=assignment.selection_ordinal + 1,
            ),
            "username": "alice",
            "category": "user_app",
        },
    )
    for invalid in invalid_cases:
        invalid_rng = random.Random(8675309)
        before = invalid_rng.getstate()
        assert (
            registry.materialize_application_command(
                invalid_rng,
                invalid["assignment"],
                username=invalid["username"],
                category=invalid["category"],
            )
            is None
        )
        assert invalid_rng.getstate() == before
    with pytest.raises(ValueError, match="non-negative exact int"):
        replace(assignment, selection_ordinal=True)


def test_public_assignment_mutation_cannot_retarget_owner_runtime_truth() -> None:
    """An in-place forged public assignment cannot authenticate as another installed app."""

    first = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --first',
    )
    second = _custom_slack_descriptor(
        "custom_chrome",
        r"C:\Custom\custom-chrome.exe",
        r'"C:\Custom\custom-chrome.exe" --second',
    )
    scenario = _scenario(
        [_user("alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
        deployment_overrides=[
            {
                "system": "WS-A",
                "applications": ["custom_slack", "custom_chrome"],
                "user_applications": [
                    {
                        "user": "alice",
                        "applications": ["custom_slack", "custom_chrome"],
                    }
                ],
            }
        ],
    )
    registry = _compile(scenario, applications=(first, second))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    source = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    target = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_chrome",
    )
    assert source is not None and target is not None
    assert source.assignment_id != target.assignment_id
    fresh_source = registry.user_application_assignment(source.assignment_id)
    assert fresh_source == source and fresh_source is not source
    census_before = (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    )

    for field_name in (
        "application_profile_id",
        "application_id",
        "product_id",
        "release_id",
        "installation_handle",
        "application_profile_handle",
        "selection_ordinal",
    ):
        object.__setattr__(source, field_name, getattr(target, field_name))
    rejected_rng = random.Random(8675309)
    rejected_rng_before = rejected_rng.getstate()
    assert registry.application_descriptor_for_assignment(source) is None
    assert registry.application_executable_for_assignment(source) is None
    assert (
        registry.materialize_application_command(
            rejected_rng,
            source,
            username="alice",
        )
        is None
    )
    assert rejected_rng.getstate() == rejected_rng_before
    assert registry.application_ids_for_executable("windows", "custom-slack.exe") == (
        "custom_slack",
    )
    assert registry.application_ids_for_executable("windows", "custom-chrome.exe") == (
        "custom_chrome",
    )
    assert (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    ) == census_before

    canonical = registry.user_application_assignment(fresh_source.assignment_id)
    assert canonical == fresh_source
    canonical_rng = random.Random(8675309)
    assert registry.materialize_application_command(
        canonical_rng,
        canonical,
        username="alice",
    ) == (
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --first',
    )


def test_windows_materialization_preserves_authored_principal_case() -> None:
    """Windows authentication is case-insensitive without rewriting command bytes."""

    application = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Users\{username}\AppData\Local\Custom\custom-slack.exe",
        r'"C:\Users\{username}\AppData\Local\Custom\custom-slack.exe" --user {username}',
    )
    scenario = _scenario(
        [_user("Alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    registry = _compile(scenario, applications=(application,))
    descriptor = registry.application_descriptor("custom_slack", "windows")
    assert descriptor is not None
    expected_materialization = (
        r"C:\Users\Alice\AppData\Local\Custom\custom-slack.exe",
        r'"C:\Users\Alice\AppData\Local\Custom\custom-slack.exe" --user Alice',
    )
    aliases = ("Alice", "ALICE", "aLiCe")
    assignments = []
    for lookup_alias in aliases:
        profile = registry.user_profile_for("WS-A", lookup_alias, "windows")
        assert profile is not None
        assignment = registry.user_application_assignment_for_application(
            profile.profile_id,
            "custom_slack",
        )
        assert assignment is not None
        assert assignment.principal == "alice"
        assert assignment.materialization_principal == "Alice"
        assignments.append(assignment)
    census_before = (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    )
    for assignment in assignments:
        for caller_alias in aliases:
            rng = random.Random(8675309)
            expected_rng = random.Random(8675309)
            expected_rng.choice(descriptor.command_templates)
            assert (
                registry.materialize_application_command(
                    rng,
                    assignment,
                    username=caller_alias,
                )
                == expected_materialization
            )
            assert rng.getstate() == expected_rng.getstate()
    assert (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    ) == census_before


def test_compiled_application_descriptor_overrides_packaged_same_id_truth() -> None:
    """A same-ID compiler input controls both the selected binary and command."""

    application = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --custom',
    )
    scenario = _scenario([_user("alice", "developer", "WS-A")], [_system("WS-A", 1)])
    registry = _compile(scenario, applications=(application,))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "slack",
    )
    assert assignment is not None
    installation = registry.installation_by_handle(assignment.installation_handle)
    assert installation is not None
    assert (
        registry.application_executable_for_assignment(assignment) == (installation.image_paths[0])
    )
    assert registry.materialize_application_command(
        random.Random(0),
        assignment,
        username="alice",
    ) == (
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --custom',
    )


def test_compiler_rejects_deployed_application_without_command_truth() -> None:
    """An incomplete custom descriptor fails at compilation, not consumption."""

    payload = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe"',
    ).model_dump(mode="python")
    payload["platforms"]["windows"]["command_templates"] = None
    application = ApplicationEntry.model_validate(payload)
    scenario = _scenario([_user("alice", "developer", "WS-A")], [_system("WS-A", 1)])
    valid = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --custom',
    )
    baseline = _compile(scenario, applications=(valid,))

    with pytest.raises(
        ValueError,
        match="compiled application command_templates must not be empty",
    ):
        _compile(scenario, applications=(application,))

    mismatched = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        "calc.exe --stale",
    )
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(mismatched,))

    mismatched_extension = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        "custom-slack.cmd --stale",
    )
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(mismatched_extension,))

    drive_relative = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        "C:custom-slack.exe --stale",
    )
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(drive_relative,))

    extensionless_image = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack",
        "custom-slack.exe --flag",
    )
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(extensionless_image,))

    embedded_image_payload = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --flag',
    ).model_dump(mode="python")
    embedded_image_payload["platforms"]["windows"]["image_path"] = r"C:\Custom\{tool}.exe"
    embedded_image = ApplicationEntry.model_validate(embedded_image_payload)
    with pytest.raises(ValueError, match=r"image_path may contain only \{username\}"):
        _compile(scenario, applications=(embedded_image,))

    embedded_command_payload = _custom_slack_descriptor(
        "slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\{tool}.exe" --flag',
    ).model_dump(mode="python")
    embedded_command_payload["platforms"]["windows"]["command_parameter_pools"] = {
        "tool": ["custom-slack"]
    }
    embedded_command = ApplicationEntry.model_validate(embedded_command_payload)
    with pytest.raises(ValueError, match="unsupported embedded placeholder"):
        _compile(scenario, applications=(embedded_command,))

    linux_payload = _application("curl").model_dump(mode="python")
    linux = linux_payload["platforms"]["linux"]
    linux["image_path"] = "/opt/acme/bin/tool"
    linux["command_templates"] = [r"'/opt/acme\bin/tool' --flag"]
    linux_payload["platforms"] = {"linux": linux}
    quoted_literal_backslash = ApplicationEntry.model_validate(linux_payload)
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(quoted_literal_backslash,))

    linux["command_templates"] = [r'"/opt/acme\bin/tool" --flag']
    double_quoted_literal_backslash = ApplicationEntry.model_validate(linux_payload)
    with pytest.raises(ValueError, match="not its declared image"):
        _compile(scenario, applications=(double_quoted_literal_backslash,))

    linux["image_path"] = r"/opt/acme\bin/tool"
    linux["command_templates"] = [r"'/opt/acme\bin/tool' --flag"]
    declared_literal_backslash = ApplicationEntry.model_validate(linux_payload)
    with pytest.raises(ValueError, match="image_path cannot contain backslashes"):
        _compile(scenario, applications=(declared_literal_backslash,))

    linux["image_path"] = "/opt/acme bin/tool"
    linux["command_templates"] = [r"/opt/acme\ bin/tool --flag"]
    escaped_space = ApplicationEntry.model_validate(linux_payload)
    escaped_registry = _compile(scenario, applications=(escaped_space,))
    assert escaped_registry.application_descriptor("curl", "linux") is not None

    recovered = _compile(scenario, applications=(valid,))
    assert recovered.application_descriptor("slack", "windows") == (
        baseline.application_descriptor("slack", "windows")
    )


def test_compiler_rejects_username_placeholder_in_executable_basename_neutrally() -> None:
    """An assignment-varying executable name cannot enter immutable descriptor routes."""

    valid = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant {tenant}',
    )
    invalid = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Users\{username}\AppData\Local\Custom\custom-{username}.exe",
        r'"C:\Users\{username}\AppData\Local\Custom\custom-{username}.exe" '
        r"--tenant {tenant}",
    )
    scenario = _scenario(
        [_user("alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    baseline = _compile(scenario, applications=(valid,))
    census_before = (
        baseline.census(),
        baseline.deployment_census(),
        baseline.assignment_category_index_census(),
        baseline.scale_census(),
    )
    rng = random.Random(8675309)
    rng_before = rng.getstate()

    with pytest.raises(ValueError, match="executable basename cannot contain"):
        _compile(scenario, applications=(invalid,))

    assert rng.getstate() == rng_before
    assert (
        baseline.census(),
        baseline.deployment_census(),
        baseline.assignment_category_index_census(),
        baseline.scale_census(),
    ) == census_before


@pytest.mark.parametrize(
    ("command_line", "platform", "expected_executable", "expected_remainder"),
    [
        (
            r'"C:\Program Files\Example App\example.exe" --flag',
            "windows",
            r"C:\Program Files\Example App\example.exe",
            "--flag",
        ),
        (
            r"C:\Program Files\Example App\example.exe --flag",
            "windows",
            r"C:\Program Files\Example App\example.exe",
            "--flag",
        ),
        (
            '"/opt/Example App/example" --flag',
            "linux",
            "/opt/Example App/example",
            "--flag",
        ),
        (
            r"/opt/Example\ App/example --flag",
            "linux",
            "/opt/Example App/example",
            "--flag",
        ),
        ("/usr/bin/example --flag", "linux", "/usr/bin/example", "--flag"),
        (
            r"'C:\Program Files\Example App\example.exe' --flag",
            "windows",
            r"'C:\Program",
            r"Files\Example App\example.exe' --flag",
        ),
    ],
)
def test_compiled_command_executable_parser_is_platform_and_quote_aware(
    command_line: str,
    platform: str,
    expected_executable: str,
    expected_remainder: str,
) -> None:
    """Command validation parses the launched token instead of using an image fallback."""

    assert _split_compiled_command_executable(
        command_line,
        platform,  # type: ignore[arg-type]
    ) == (expected_executable, expected_remainder)


def test_compiled_command_executable_parser_resolves_wrappers_and_scoped_pools() -> None:
    """Windows wrappers and first-token pools validate their actual child executable."""

    assert _compiled_command_executables(
        "cmd.exe /c npm run build",
        "windows",
        {},
    ) == ("npm",)
    assert _compiled_command_executables(
        "{redis_cmd}",
        "linux",
        {"redis_cmd": ("redis-cli INFO memory", "redis-cli DBSIZE")},
    ) == ("redis-cli", "redis-cli")

    with pytest.raises(ValueError, match="alternatives exceed the bounded limit"):
        _compiled_command_executables(
            "{tool}",
            "linux",
            {"tool": tuple(f"tool --variant {ordinal}" for ordinal in range(1_025))},
        )


def test_principal_dependent_output_overflow_fails_during_assignment_compilation() -> None:
    """A principal-dependent output overflow never reaches runtime materialization."""

    username = "alice_with_a_principal_longer_than_the_username_placeholder"
    prefix = '"C:\\Custom\\custom-slack.exe" --payload '
    suffix = " {username}"
    command_template = prefix + ("x" * (65_536 - len(prefix) - len(suffix))) + suffix
    application = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        command_template,
    )
    scenario = _scenario(
        [_user(username, "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    with pytest.raises(ValueError, match="assigned principal within the bounded output"):
        _compile(scenario, applications=(application,))


def test_compiler_charges_username_and_nested_pool_replacements_before_publication() -> None:
    """Literal username work composes with pool work under the 1,024 expansion cap."""

    prefix = r'"C:\Custom\custom-slack.exe"'
    scenario = _scenario(
        [_user("alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    accepted = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        prefix + (" {username}" * 1_024),
    )
    registry = _compile(scenario, applications=(accepted,))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    assert assignment is not None
    rng = random.Random(8675309)
    expected_rng = random.Random(8675309)
    expected_rng.choice((prefix + (" {username}" * 1_024),))
    assert registry.materialize_application_command(rng, assignment, username="alice") == (
        r"C:\Custom\custom-slack.exe",
        prefix + (" alice" * 1_024),
    )
    assert rng.getstate() == expected_rng.getstate()
    census_before = (registry.census(), registry.deployment_census(), registry.scale_census())

    rejected = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        prefix + (" {username}" * 1_025),
    )
    with pytest.raises(ValueError, match="bounded output contract"):
        _compile(scenario, applications=(rejected,))

    nested_payload = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        prefix + " {outer}",
    ).model_dump(mode="python")
    nested_payload["platforms"]["windows"]["command_parameter_pools"] = {
        "outer": ["{username}" * 1_023]
    }
    nested_accepted = ApplicationEntry.model_validate(nested_payload)
    _compile(scenario, applications=(nested_accepted,))
    nested_payload["platforms"]["windows"]["command_parameter_pools"] = {
        "outer": ["{username}" * 1_024]
    }
    nested_rejected = ApplicationEntry.model_validate(nested_payload)
    with pytest.raises(ValueError, match="bounded output contract"):
        _compile(scenario, applications=(nested_rejected,))

    assert (registry.census(), registry.deployment_census(), registry.scale_census()) == (
        census_before
    )


def test_assignment_command_bounds_are_cached_by_descriptor_and_principal_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Many equal-length principals reuse one descriptor-bound validation result."""

    import evidenceforge.generation.deployment_registry as deployment_registry

    application = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant {tenant} --user {username}',
    )
    original = deployment_registry._validate_application_command_expansion_bounds
    calls = 0

    def counting_validator(
        command_templates: tuple[str, ...],
        parameter_pools: tuple[tuple[str, tuple[str, ...]], ...],
        *,
        literal_replacements: tuple[tuple[str, str], ...] = (),
    ) -> None:
        nonlocal calls
        calls += 1
        original(
            command_templates,
            parameter_pools,
            literal_replacements=literal_replacements,
        )

    monkeypatch.setattr(
        deployment_registry,
        "_validate_application_command_expansion_bounds",
        counting_validator,
    )
    users = [_user(f"u{ordinal:03d}", "developer", "WS-A") for ordinal in range(64)]
    registry = _compile(
        _scenario(users, [_system("WS-A", 1)]),
        applications=(application,),
    )

    assert registry.deployment_census().user_application_assignments == 64
    # Source construction, registry-owned admission snapshot, and one principal-length
    # result stay constant across all 64 users.
    assert calls == 3
    profile = registry.user_profile_for("WS-A", "u000", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    assert assignment is not None
    for _ordinal in range(64):
        assert registry.materialize_application_command(
            random.Random(0),
            assignment,
            username="u000",
        ) == (
            r"C:\Custom\custom-slack.exe",
            r'"C:\Custom\custom-slack.exe" --tenant blue --user u000',
        )
    assert calls == 3


def test_compiler_shares_descriptor_population_bounds_with_direct_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compiler input and canonical descriptor construction use the same finite envelope."""

    import evidenceforge.generation.deployment_registry as deployment_registry

    applications = tuple(
        _custom_slack_descriptor(
            f"custom_slack_{ordinal}",
            r"C:\Custom\custom-slack.exe",
            r'"C:\Custom\custom-slack.exe" --tenant {tenant}',
        )
        for ordinal in range(2)
    )
    scenario = _scenario([_user("alice", "developer", "WS-A")], [_system("WS-A", 1)])
    baseline = _compile(scenario, applications=(applications[0],))
    census_before = (baseline.census(), baseline.deployment_census(), baseline.scale_census())
    count_limit = deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT

    monkeypatch.setattr(deployment_registry, "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT", 1)
    with pytest.raises(ValueError, match="application_entries exceeds the bounded registry count"):
        _compile(scenario, applications=applications)

    monkeypatch.setattr(
        deployment_registry,
        "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT",
        count_limit,
    )
    monkeypatch.setattr(
        deployment_registry,
        "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_TEXT_BYTES",
        1,
    )
    with pytest.raises(ValueError, match="bounded registry text budget"):
        _compile(scenario, applications=(applications[0],))

    assert (baseline.census(), baseline.deployment_census(), baseline.scale_census()) == (
        census_before
    )


@pytest.mark.parametrize(
    ("template_tail", "pool_value", "expected_tail"),
    [
        (
            " {x}}",
            ("a" * 40_000) + "{x",
            " " + ("a" * 40_000) + "{x}",
        ),
        (
            " {x}" + ("}" * 1_025),
            "{x",
            " {x" + ("}" * 1_025),
        ),
        (
            " {x}name}",
            "{user",
            " {username}",
        ),
    ],
)
def test_scoped_materialization_never_rescans_replacement_boundaries(
    template_tail: str,
    pool_value: str,
    expected_tail: str,
) -> None:
    """Replacement fragments cannot synthesize new scoped tokens or consume extra RNG."""

    prefix = r'"C:\Custom\custom-slack.exe"'
    command_template = prefix + template_tail
    payload = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        command_template,
    ).model_dump(mode="python")
    payload["platforms"]["windows"]["command_parameter_pools"] = {"x": [pool_value]}
    application = ApplicationEntry.model_validate(payload)
    scenario = _scenario(
        [_user("alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    registry = _compile(scenario, applications=(application,))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    assert assignment is not None

    rng = random.Random(8675309)
    expected_rng = random.Random(8675309)
    expected_rng.choice((command_template,))
    expected_rng.choice((pool_value,))
    assert registry.materialize_application_command(rng, assignment, username="alice") == (
        r"C:\Custom\custom-slack.exe",
        prefix + expected_tail,
    )
    assert rng.getstate() == expected_rng.getstate()


def test_scoped_materialization_expands_nested_tokens_structurally() -> None:
    """Complete nested scoped tokens still expand in deterministic depth-first order."""

    payload = _custom_slack_descriptor(
        "custom_slack",
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant {outer}',
    ).model_dump(mode="python")
    payload["platforms"]["windows"]["command_parameter_pools"] = {
        "outer": ["{inner}"],
        "inner": ["blue-{username}"],
    }
    application = ApplicationEntry.model_validate(payload)
    scenario = _scenario(
        [_user("alice", "developer", "WS-A")],
        [_system("WS-A", 1)],
    )
    registry = _compile(scenario, applications=(application,))
    profile = registry.user_profile_for("WS-A", "alice", "windows")
    assert profile is not None
    assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "custom_slack",
    )
    assert assignment is not None

    assert registry.materialize_application_command(
        random.Random(0),
        assignment,
        username="alice",
    ) == (
        r"C:\Custom\custom-slack.exe",
        r'"C:\Custom\custom-slack.exe" --tenant blue-alice',
    )


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
        first_assignment = first.user_application_assignments_for_product(hostname, "slack")[0]
        second_assignment = second.user_application_assignments_for_product(hostname, "slack")[0]
        first_descriptor = first.application_descriptor("slack", "windows")
        second_descriptor = second.application_descriptor("slack", "windows")
        assert first_descriptor is not None and second_descriptor is not None
        assert first_assignment.selection_ordinal == first_descriptor.selection_ordinal
        assert second_assignment.selection_ordinal == second_descriptor.selection_ordinal
        assert first_assignment.selection_ordinal == second_assignment.selection_ordinal

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
descriptor = registry.application_descriptor("slack", "windows")
print(json.dumps({
    "content": identity.content_id,
    "digests": [identity.digests.md5, identity.digests.sha1, identity.digests.sha256],
    "assignment": assignment.assignment_id,
    "assignment_ordinal": assignment.selection_ordinal,
    "descriptor": [
        descriptor.application_id,
        descriptor.platform,
        descriptor.image_path,
        descriptor.command_templates,
        descriptor.categories,
        descriptor.command_parameter_pools,
        descriptor.singleton_per_session,
        descriptor.selection_ordinal,
    ],
    "executable_ids": registry.application_ids_for_executable("windows", "Slack.exe"),
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

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import random
import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.world_model import WorldModel
from evidenceforge.models.scenario import System, User
from tests.support.macos_ssh import macos_ssh_scenario


def _owner(
    scenarios_dir: Path, applications: tuple[str, ...]
) -> tuple[ActivityGenerator, System, User, DeploymentContentRegistry]:
    scenario = macos_ssh_scenario(scenarios_dir)
    scenario.environment.users[0].persona = "default"
    registry = compile_deployment_registry(
        scenario,
        WorldModel(scenario, "example.test"),
        application_entries=tuple(
            ApplicationEntry.model_validate(application_descriptor(app)) for app in applications
        ),
    )
    owner = object.__new__(ActivityGenerator)
    owner.dispatcher = SimpleNamespace(deployment_registry=registry)
    return owner, scenario.environment.systems[0], scenario.environment.users[0], registry


@pytest.mark.parametrize(
    "app,agent", [("outlook", "Microsoft Outlook"), ("thunderbird", "Thunderbird")]
)
def test_mac_mail_image_uses_the_exact_assigned_release(
    scenarios_dir: Path, app: str, agent: str
) -> None:
    owner, system, user, registry = _owner(scenarios_dir, (app,))
    image = owner._email_access_process_image(
        system, "imaps", agent, random.Random(1), username=user.username
    )
    expected = application_descriptor(app)["platforms"]["macos"]["image_path"]
    assert image == expected
    assert registry.resolve_binary(system.hostname, image, "macos") is not None
    command = owner._email_access_process_command_line(
        image, protocol="imaps", server_hostname="mail.example.test"
    )
    assert shlex.split(command) == [image]
    assert (
        owner._email_access_process_image(
            system, "imaps", agent, random.Random(1), username="unassigned"
        )
        is None
    )


@pytest.mark.parametrize("agent", ["Microsoft Outlook", "Apple Mail", "Thunderbird"])
def test_missing_mac_mail_deployment_never_uses_foreign_executables(
    scenarios_dir: Path, agent: str
) -> None:
    owner, system, user, _ = _owner(scenarios_dir, ("chrome",))
    assert (
        owner._email_access_process_image(
            system, "imaps", agent, random.Random(1), username=user.username
        )
        is None
    )
    assert owner._ensure_email_client_process(
        user=user, system=system, time=None, image=None, command_line=""
    ) == (-1, None)


def test_mac_webmail_uses_preferred_browser_assignment(scenarios_dir: Path) -> None:
    owner, system, user, registry = _owner(scenarios_dir, ("chrome", "firefox"))
    profile = registry.user_profile_for(system.hostname, user.username, "macos")
    assignment = registry.preferred_browser_assignment(profile.profile_id)
    image = owner._email_access_process_image(
        system, "owa", "Microsoft Outlook", random.Random(1), username=user.username
    )
    assert image == registry.application_executable_for_assignment(assignment)
    assert shlex.split(
        owner._email_access_process_command_line(
            image, protocol="owa", server_hostname="mail.example.test"
        )
    ) == [image, "https://mail.example.test/owa/"]


def test_default_mac_mailer_version_comes_from_installed_release(scenarios_dir: Path) -> None:
    owner, system, user, registry = _owner(scenarios_dir, ("outlook",))
    assignment = owner._macos_email_assignment(system, "smtp", "", username=user.username)
    image = registry.application_executable_for_assignment(assignment)
    release = registry.resolve_binary(system.hostname, image, "macos")
    assert owner._email_user_agent(system, random.Random(1), username=user.username) == (
        f"{release.key.artifact_name} {release.key.version}"
    )
    assert owner._email_user_agent(system, random.Random(1), username="unassigned") == ""


def test_mac_sender_documents_use_modeled_user_home(scenarios_dir: Path) -> None:
    owner, system, user, _ = _owner(scenarios_dir, ("outlook",))
    assert owner._email_sender_attachment_path(user, system, "invented.txt") == (
        f"/Users/{user.username}/Documents/invented.txt"
    )


@pytest.mark.slow
def test_mac_mail_submission_owns_native_endpoint_process_and_avoids_linux_cache(
    tmp_path: Path,
) -> None:
    from datetime import UTC, datetime

    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.models.scenario import LogonEventSpec, OutputSpec, StorylineEvent
    from tests.unit.test_email_evidence import _email_scenario, _read_ndjson

    scenario = _email_scenario()
    scenario.time_window.start = datetime(2026, 10, 15, 14, tzinfo=UTC)
    for system in scenario.environment.systems[:2]:
        system.os = "macOS 26"
        system.architecture = "arm64"
    scenario.output = OutputSpec(
        logs=[{"format": "zeek"}, {"format": "ecar"}], destination="./data"
    )
    scenario.storyline.insert(
        0,
        StorylineEvent(
            id="mail-login",
            time="+1m",
            actor="alice",
            system="WS-ALICE",
            activity="Start the invented sender workstation session",
            events=[LogonEventSpec(logon_type=2)],
        ),
    )
    engine = GenerationEngine(
        scenario,
        output_dir=tmp_path / "data",
        ground_truth_dir=tmp_path,
        artifact_dir=tmp_path / "artifacts",
    )
    engine.generate()
    records = [row for path in (tmp_path / "data").rglob("ecar.json") for row in _read_ndjson(path)]
    flow = next(
        row
        for row in records
        if row.get("object") == "FLOW"
        and row.get("action") == "CONNECT"
        and row.get("properties", {}).get("src_ip") == "10.10.1.10"
        and row.get("properties", {}).get("dst_port") == "587"
        and row.get("properties", {}).get("direction") == "OUTBOUND"
    )
    assert flow["properties"]["image_path"] == (
        "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook"
    )
    assert int(flow["pid"]) > 0
    assert any(row.get("object") == "PROCESS" and row.get("pid") == flow["pid"] for row in records)
    for row in records:
        if row.get("principal") not in {"alice", "bob"}:
            continue
        properties = row.get("properties", {})
        for field in ("image_path", "file_path"):
            path = properties.get(field, "")
            assert not path.startswith(("/home/", "C:")), path
        assert ".thunderbird/" not in properties.get("file_path", "")

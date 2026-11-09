# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native administration queries retain installation, session and effect boundaries."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml

from evidenceforge.config.schemas import ApplicationEntry
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.application_catalog import (
    application_descriptor,
    get_apps_for_persona,
)
from evidenceforge.generation.activity.process_helpers import _macos_foreground_lifetime
from evidenceforge.generation.deployment_compiler import compile_deployment_registry
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.world_model import WorldModel
from tests.support.macos_ssh import macos_ssh_scenario
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user


@pytest.mark.parametrize("name", ["launchctl", "plutil"])
def test_admin_queries_compile_only_native_arm64_host_build_without_baseline_assignment(
    scenarios_dir: Path, name: str
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir)
    app = ApplicationEntry.model_validate(application_descriptor(f"macos-{name}"))
    assert set(app.platforms) == {"macos"} and app.personas == []
    platform = app.platforms["macos"]
    assert platform.deployment.architectures == ("arm64",)
    assert platform.deployment.release_policy == "host_build"
    assert not platform.children and platform.code_signature is None
    registry = compile_deployment_registry(
        scenario, WorldModel(scenario, "example.test"), application_entries=(app,)
    )
    binary = registry.resolve_binary("TEST-01", platform.image_path, "macos")
    assert binary is not None and binary.key.product_id == "apple-macos"
    assert binary.key.architecture == "arm64"
    assert binary.code_signature is None and binary.mach_o_image is None
    assert registry.resolve_binary("SSH-TEST", platform.image_path, "linux") is None
    for persona in ("developer", "sysadmin", "default"):
        assert not get_apps_for_persona(persona, "macos", "macos_administration", "workstation")
    audit = yaml.safe_load(
        (
            Path(__file__).parents[2]
            / "docs/design/macos-workstation-feasibility/native-catalog-audit.yaml"
        ).read_text()
    )
    row = next(row for row in audit["administration_applications"] if row["id"] == app.id)
    assert row["image_path"] == platform.image_path and row["references"]


@pytest.mark.parametrize(
    "image,command,bounded",
    [
        ("/bin/launchctl", "/bin/launchctl list", True),
        ("/usr/bin/plutil", "/usr/bin/plutil -help", True),
        (
            "/bin/launchctl",
            "/bin/launchctl bootstrap system /Library/LaunchDaemons/example.plist",
            False,
        ),
        ("/bin/launchctl", "/bin/launchctl bootout system/example", False),
        ("/usr/bin/plutil", "/usr/bin/plutil -replace Label -string example job.plist", False),
        ("/bin/launchctl", "/bin/launchctl list; /usr/bin/id", False),
    ],
)
def test_only_profiled_query_forms_get_short_lifetimes(
    image: str, command: str, bounded: bool
) -> None:
    assert (_macos_foreground_lifetime(image, command) is not None) is bounded


@pytest.mark.parametrize("name", ["launchctl", "plutil"])
def test_admin_query_process_closes_without_creating_persistence_or_file_evidence(
    tmp_path: Path, name: str
) -> None:
    platform = application_descriptor(f"macos-{name}")["platforms"]["macos"]
    image, command = platform["image_path"], platform["command_templates"][0]
    state = StateManager()
    _seed_launchd(state)
    path = tmp_path / "ecar.json"
    emitter = EcarEmitter(load_format("ecar"), path)
    emitters = {"ecar": emitter}
    generator = ActivityGenerator(state, emitters, dispatcher=EventDispatcher(state, emitters))
    user, system = _user(), _system()
    try:
        logon = generator.generate_logon(user, system, _TIME)
        at = _TIME + timedelta(seconds=30)
        shell = generator.ensure_macos_session_shell(user, system, logon, at)
        assert shell is not None
        pid = generator.generate_process(user, system, at, logon, image, command, parent_pid=shell)
        identity = state.get_process_identity(system.hostname, pid)
        assert identity is not None and identity.parent_pid == shell
        close = generator.foreground_process_termination_time(system.hostname, pid)
        assert close is not None and at < close < at + timedelta(seconds=50)
        generator._finalize_due_process_lifetimes(at + timedelta(minutes=2), exhaust=True)
        generator.generate_logoff(user, system, at + timedelta(minutes=3), logon)
    finally:
        emitter.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    own = [row for row in rows if row["objectID"] == identity.object_id]
    assert [row["action"] for row in own] == ["CREATE", "TERMINATE"]
    assert own[0]["properties"]["logon_id"] == logon
    assert all(row["object"] in {"PROCESS", "USER_SESSION"} for row in rows)

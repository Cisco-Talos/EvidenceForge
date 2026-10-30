# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Both terminal applications use one session and command publication contract."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.activity.spawn_rules import get_parent_config
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from tests.unit.test_macos_installed_provisioning import _scenario


def _engine(tmp_path: Path, terminal_id: str, *, native: bool = True) -> GenerationEngine:
    raw = _scenario().model_dump(mode="json", exclude_none=True)
    raw["environment"]["deployment_overrides"] = [
        {
            "system": "MAC-01",
            "user_applications": [{"user": "alex", "applications": [terminal_id]}],
        }
    ]
    raw["output"]["logs"] = [{"format": "ecar"}]
    if native:
        raw["output"]["logs"].append({"format": "macos_endpoint_security"})
        raw["macos_process_coverage"] = "complete"
    engine = GenerationEngine(Scenario.model_validate(raw), tmp_path, generation_seed=358)
    engine._chronological_es_delivery = True
    return engine


@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
@pytest.mark.parametrize("native", [False, True], ids=["filtered", "native"])
@pytest.mark.parametrize("preexisting", [False, True], ids=["in-window", "preexisting"])
def test_assigned_terminal_owns_commands_and_preserves_complete_coverage_boundary(
    tmp_path: Path, terminal_id: str, native: bool, preexisting: bool
) -> None:
    engine = _engine(tmp_path, terminal_id, native=native)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=-10 if preexisting else 1)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell_pid = generator.ensure_macos_session_shell(
            user, system, logon, at + timedelta(minutes=1)
        )
        assert shell_pid is not None
        state = engine.state_manager
        shell = state.get_process_identity(system.hostname, shell_pid)
        login = state.get_process_identity(system.hostname, shell.parent_pid)
        terminal = state.get_process_identity(system.hostname, login.parent_pid)
        catalog = application_descriptor(terminal_id)
        assert terminal.image == catalog["platforms"]["macos"]["image_path"]
        assert shell.image == "/bin/zsh" and login.image == "/usr/bin/login"
        assert (
            shell.credentials.audit_uid
            == login.credentials.audit_uid
            == terminal.credentials.audit_uid
        )
        assert shell.credentials.audit_session_id == terminal.credentials.audit_session_id
        assert shell.responsibility.responsible.object_id == terminal.object_id
        assert shell.job_control.session == login.job_control.session
        assert state.known_macos_terminal(shell.job_control.session, shell.started_at).native_path
        session = state.get_session(logon)
        assert session.process_tree_root == terminal.pid
        assert (
            generator.ensure_macos_session_shell(
                user, system, logon, engine.start_time + timedelta(minutes=5)
            )
            == shell_pid
        )
        command_pid = generator.generate_process(
            user,
            system,
            engine.start_time + timedelta(minutes=10),
            logon,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=shell_pid,
            require_exact_parent=True,
        )
        command = state.get_process_identity(system.hostname, command_pid)
        assert command.execution_ordinal == 1
        assert command.parent_pid == shell_pid
        assert command.responsibility == shell.responsibility
        if native and not preexisting:
            with pytest.raises(StateError, match="Incomplete native macOS process coverage"):
                engine._finalize_macos_process_coverage()
        else:
            engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    records = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    if native:
        execs = [row for row in records if row.event_type == 9]
        assert len(execs) == 1
        target = execs[0].event.exec.target
        assert target.audit_token.pid == command.pid
        assert target.audit_token.pidversion == command.audit_pid_version
        assert target.responsible_audit_token.pid == terminal.pid
        assert target.responsible_audit_token.pidversion == terminal.audit_pid_version
    else:
        assert not records


@pytest.mark.parametrize("terminal_id", ["macos-terminal", "macos-iterm2"])
def test_terminal_role_has_distinct_catalog_identity_and_matching_spawn_policy(
    terminal_id: str,
) -> None:
    entry = application_descriptor(terminal_id)
    assert "macos_terminal" in entry["categories"]
    assert set(entry["platforms"]) == {"macos"}
    platform = entry["platforms"]["macos"]
    assert platform["singleton_per_session"]
    name = platform["image_path"].rsplit("/", 1)[-1]
    assert get_parent_config("macos", name)["children"] == ["login"]
    if terminal_id == "macos-iterm2":
        assert platform["deployment"]["product_id"] == "iterm2"
        assert "code_signature" not in platform


def test_nonterminal_selection_rejects_before_allocating_and_cannot_replace_live_shell(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path, "macos-iterm2", native=False)
    try:
        engine._initialize()
        generator = engine.activity_generator
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        at = engine.start_time + timedelta(minutes=1)
        logon = generator.generate_logon(user, system, at)
        before = engine.state_manager.materialization_digest()
        with pytest.raises(StateError, match="macos_terminal catalog entry"):
            generator.ensure_macos_session_shell(
                user,
                system,
                logon,
                at + timedelta(minutes=1),
                terminal_application_id="macos-safari",
            )
        assert engine.state_manager.materialization_digest() == before
        shell = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(minutes=1))
        assert shell is not None
        before = engine.state_manager.materialization_digest()
        assert (
            generator.ensure_macos_session_shell(
                user,
                system,
                logon,
                at + timedelta(minutes=2),
                terminal_application_id="macos-terminal",
            )
            is None
        )
        assert engine.state_manager.materialization_digest() == before
    finally:
        engine._close_emitters()

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Actual boot/SSH producers supply complete fork metadata without native defaults."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_metadata_producers import _Fixture, _terminal
from tests.unit.test_macos_metadata_producers import modeled as modeled


@pytest.mark.parametrize("native", [False, True])
def test_real_ssh_metadata_inheritance_authentication_native_forks_and_close(
    tmp_path: Path, native: bool
) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].services = ["ssh"]
    scenario.output.logs = [{"format": "ecar"}]
    if native:
        scenario.output.logs.append({"format": "macos_endpoint_security"})
    engine = GenerationEngine(scenario, tmp_path, generation_seed=328)
    try:
        engine._initialize()
        state = engine.state_manager
        generator = engine.activity_generator
        root = state.get_process_identity("MAC-01", 1)
        assert root.credentials.audit_session_id > 0
        assert replace(root.credentials, audit_session_id=0) == PosixProcessCredentials(
            0, 0, 0, 0, 2**32 - 1, 0
        )
        assert root.responsibility.responsible is None
        generator.generate_ssh_session(
            scenario.environment.users[0],
            scenario.environment.systems[0],
            engine.start_time + timedelta(minutes=10),
            source_ip="192.0.2.200",
            duration=120,
            emit_session_close=True,
            defer_session_close=True,
        )
        continuation = generator._pending_ssh_session_closures[0]
        session = state.get_session(continuation.plan.logon_id)
        shell = state.get_process_identity("MAC-01", session.session_shell_pid)
        assert shell.credentials.audit_uid == 501
        assert shell.credentials.audit_session_id >= 100_000
        assert "HOME=/Users/alex" in shell.environment
        assert "USER=alex" in shell.environment and "USER=root" not in shell.environment
        assert shell.execution_directory.native_path == "/Users/alex"
        assert shell.exec_image.dyld_exec_path == "/bin/zsh"
        # A complete fork source does not invent a complete native exec FD table.
        assert state.process_descriptors_at(shell, event_time=shell.execution_started_at) is None
        restored = StateManager()
        _restore_head(restored, _capture_head(state))
        assert restored.get_process_identity("MAC-01", shell.pid) == shell
        generator.finalize_ssh_session_lifecycles(engine.end_time)
        assert state.get_session(session.logon_id) is None
        assert state.get_process("MAC-01", shell.pid) is None
    finally:
        engine._close_emitters()
    paths = list(tmp_path.rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(native)
    if native:
        records = [json.loads(line) for line in paths[0].read_text().splitlines()]
        assert len(records) == 3
        for record in records:
            decode_endpoint_security_record(json.dumps(record))
            assert record["event_type"] == 11 and record["version"] == 11
        assert records[0]["process"]["audit_token"]["auid"] == 2**32 - 1
        assert records[0]["process"]["audit_token"]["asid"] == root.credentials.audit_session_id
        assert records[1]["process"]["audit_token"]["auid"] == 501
        assert records[2]["event"]["fork"]["child"]["audit_token"]["auid"] == 501


def test_old_execution_policy_preserves_unknown_audit_and_responsibility(modeled: _Fixture) -> None:
    profile = modeled.producer.profile.model_copy(
        update={"system_audit_origin": None, "system_responsibility": None}
    )
    producer = MacosExecutionMetadataProducer(
        modeled.producer._filesystem,
        IdentityDirectory.from_scenario(_scenario()),
        profile,
        window_start=modeled.start,
        window_end=modeled.end,
    )
    metadata = producer.deployed_launch(
        "MAC-01", "root", at=modeled.start, path="/sbin/launchd", kind="system"
    )
    assert metadata.credentials == PosixProcessCredentials(0, 0, 0, 0)
    assert metadata.responsibility is None


def test_fork_producer_observes_current_directory_and_retains_unknown_on_missing_state(
    modeled: _Fixture,
) -> None:
    state = modeled.state
    parent = _terminal(modeled)
    state.materialize_process(parent)
    at = modeled.start + timedelta(seconds=2)
    builder = state.begin_action_cohort_materialization()
    child = modeled.producer.plan_fork(builder, state, parent.identity, at=at)
    assert child.identity.execution_directory.observed_at == at
    assert child.identity.execution_directory.native_path == "/Users/alex"
    state.materialize_action_cohort(builder.seal())
    unknown = state.plan_process_materialization(
        system="MAC-01",
        parent_pid=1,
        image="/bin/zsh",
        command_line="/bin/zsh",
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        start_time=at,
    )
    state.materialize_process(unknown)
    builder = state.begin_action_cohort_materialization()
    with pytest.raises(StateError, match="directory"):
        modeled.producer.plan_fork(builder, state, unknown.identity, at=at)

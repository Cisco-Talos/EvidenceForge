# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""An explicit retained shebang fact is distinct from guessing a script from argv."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.engine import GenerationEngine
from tests.unit.test_macos_exec_script import _script
from tests.unit.test_macos_installed_provisioning import _scenario
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _manager


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("explicit_script", [False, True])
def test_explicit_retained_script_uses_shared_fork_exec_and_completeness(
    tmp_path: Path, native: bool, explicit_script: bool
) -> None:
    scenario = _scenario()
    scenario.output.logs = [{"format": "ecar"}] + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    engine = GenerationEngine(scenario, tmp_path)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator = engine.activity_generator
        system, user = scenario.environment.systems[0], scenario.environment.users[0]
        at = engine.start_time - timedelta(minutes=5)
        logon = generator.generate_logon(user, system, at, allow_local_session_reuse=False)
        shell = generator.ensure_macos_session_shell(user, system, logon, at + timedelta(minutes=1))
        assert shell is not None
        content = _manager()
        generator._runtime_content_manager = content
        engine.dispatcher.bind_local_artifact_registry(content.registry)
        descriptor, record = _script(content, system.hostname)
        _publish(content, descriptor, engine.start_time - timedelta(seconds=1))
        reference = MacosExecScript.from_runtime_record(record)
        pid = generator.generate_process(
            user,
            system,
            engine.start_time + timedelta(minutes=1),
            logon,
            "/bin/zsh",
            "/bin/zsh " + descriptor.native_path,
            arguments=("/bin/zsh", descriptor.native_path),
            parent_pid=shell,
            require_exact_parent=True,
            exec_script=reference if explicit_script else None,
            suppress_command_file_effect=True,
        )
        identity = engine.state_manager.get_process_identity(system.hostname, pid)
        assert identity.execution_ordinal == 1
        assert identity.exec_script == (reference if explicit_script else MacosExecScript())
        assert identity.executable_version.identity_kind == "installed_release"
        engine._finalize_macos_process_coverage()
        summary = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert summary.expected_forks == summary.expected_execs == 1
        assert summary.aggregate_births == 0
        assert summary.complete is native
        from evidenceforge.generation.checkpoints.state_manager_head import (
            _capture_head,
            _restore_head,
        )
        from evidenceforge.generation.state_manager import StateManager

        restored = StateManager()
        _restore_head(restored, _capture_head(engine.state_manager))
        assert restored.get_process_identity(system.hostname, pid) == identity
        assert (
            restored.macos_process_census_snapshot()
            == engine.state_manager.macos_process_census_snapshot()
        )
    finally:
        engine._close_emitters()
    rows = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    executions = [row for row in rows if row.event_type == 9]
    assert len(executions) == int(native)
    if native:
        if explicit_script:
            assert executions[0].event.exec.script.path == descriptor.native_path
        else:
            assert executions[0].event.exec.script is None
        assert executions[0].event.exec.target.executable.path == "/bin/zsh"

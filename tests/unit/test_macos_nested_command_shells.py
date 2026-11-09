# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented SSH command trees retain native facts through a nested shell."""

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.config.schemas import MacosCommandShellPolicy
from tests.unit.test_macos_command_exit_outcomes import _engine, _native_exits


@pytest.mark.parametrize("shell", ["/bin/zsh", "/bin/bash"])
@pytest.mark.parametrize("qualified", [True, False])
def test_nested_command_shell_reuses_canonical_fork_exec_and_known_exit(
    tmp_path: Path, scenarios_dir: Path, shell: str, qualified: bool
) -> None:
    with _engine(tmp_path, scenarios_dir) as (engine, target, user, session):
        generator = engine.activity_generator
        at = engine.start_time + timedelta(minutes=11)
        nested_pid = generator.generate_process(
            user,
            target,
            at,
            session.logon_id,
            shell,
            shell,
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
        )
        nested = engine.state_manager.get_process_identity(target.hostname, nested_pid)
        assert nested.execution_ordinal == 1
        if not qualified:
            provider = engine.macos_execution_metadata
            provider.profile = provider.profile.model_copy(update={"nested_command_shells": ()})
        child_pid = generator.generate_process(
            user,
            target,
            at + timedelta(seconds=1),
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=nested_pid,
            require_exact_parent=True,
        )
        child = engine.state_manager.get_process_identity(target.hostname, child_pid)
        assert child.parent_pid == nested.pid
        assert child.execution_ordinal == int(qualified)
        close = generator.foreground_process_termination_time(target.hostname, child_pid)
        assert close is not None
        generator.generate_process_termination(
            user,
            target,
            close,
            child_pid,
            child.image,
            session.logon_id,
            macos_command_completed=True,
        )
        assert engine.state_manager.get_process_identity(target.hostname, nested_pid) == nested
    exits = _native_exits(tmp_path, child_pid)
    assert len(exits) == int(qualified)
    if exits:
        assert exits[0].event.exit.stat == 0
        assert exits[0].process.ppid == nested_pid


@pytest.mark.parametrize("arguments", [["/bin/zsh", "-c", "id"], ["/bin/bash", "-l"], ["-zsh"]])
def test_nested_shell_policy_rejects_command_strings_and_flags(arguments: list[str]) -> None:
    with pytest.raises(ValidationError):
        MacosCommandShellPolicy(image="/bin/zsh", arguments=tuple(arguments))

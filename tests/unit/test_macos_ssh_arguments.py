# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverStartup,
    macos_ssh_command_arguments,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _descriptor, _request


@pytest.mark.parametrize(
    "application,arguments",
    [
        ("macos-sshd-keygen-wrapper", ("sshd-keygen-wrapper",)),
        ("macos-sshd", ("/usr/sbin/sshd", "-i")),
        ("macos-sshd-session", ("/usr/libexec/sshd-session", "-i", "-R")),
        ("macos-sshd-auth", ("/usr/libexec/sshd-auth", "-i", "-R")),
    ],
)
def test_direct_ssh_role_vectors_follow_catalog_templates(
    application: str, arguments: tuple[str, ...]
) -> None:
    assert macos_ssh_command_arguments(_descriptor(application)) == arguments


def test_direct_profile_preserves_literal_quoted_argument_without_expansion() -> None:
    descriptor = replace(
        _descriptor("macos-sshd"), command_templates=("/usr/sbin/sshd 'literal $HOME' ''",)
    )
    assert macos_ssh_command_arguments(descriptor) == ("/usr/sbin/sshd", "literal $HOME", "")


@pytest.mark.parametrize(
    "command",
    [
        "/usr/sbin/sshd -i > /tmp/example",
        "/usr/sbin/sshd | /bin/cat",
        "/usr/sbin/sshd $HOME",
        "/usr/sbin/sshd $(id)",
        "MODE=x /usr/sbin/sshd",
        "sshd -i",
        "/usr/sbin/sshd '",
        "/usr/sbin/sshd\0",
    ],
)
def test_direct_profile_rejects_shell_semantics_or_an_unbound_executable(command: str) -> None:
    with pytest.raises((StateError, ValueError)):
        macos_ssh_command_arguments(
            replace(_descriptor("macos-sshd"), command_templates=(command,))
        )


def test_direct_argv_parser_is_not_a_general_catalog_command_parser() -> None:
    with pytest.raises(StateError, match="bounded direct-exec"):
        macos_ssh_command_arguments(_descriptor("macos-zsh"))


@pytest.mark.parametrize("shell", ["macos-zsh", "macos-bash"])
@pytest.mark.parametrize("collected", [False, True])
def test_startup_exec_and_fork_keep_the_owned_vector_through_checkpoint(
    tmp_path: Path, shell: str, collected: bool
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    request = _request(receiver, shell)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    for index in range(11):
        startup.advance()
        if index == 0:
            daemon = state.get_process_identity(host.hostname, receiver.pid)
            assert daemon.arguments == ("/usr/sbin/sshd", "-i")
        if index == 1:
            worker = state.get_process_identity(host.hostname, receiver.pid)
            assert worker.arguments == ("/usr/libexec/sshd-session", "-i", "-R")
        if index == 2:
            child = startup._preauth
            assert child.arguments == worker.arguments
        if index == 3:
            assert startup._preauth.arguments == ("/usr/libexec/sshd-auth", "-i", "-R")
    result = startup.result
    assert result.shell.arguments == ("-bash" if shell == "macos-bash" else "-zsh",)
    assert result.shell.environment is None
    assert (
        result.authenticated_child.arguments
        == result.privileged_receiver.arguments
        == worker.arguments
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for process in (result.shell, result.privileged_receiver, result.authenticated_child):
        assert restored.get_process_identity(host.hostname, process.pid) == process
    emitter.close()


def test_bad_direct_profile_is_rejected_before_startup_mutates_state(tmp_path: Path) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    before = state.materialization_digest()
    request = _request(receiver)
    with pytest.raises(StateError, match="canonical literal"):
        replace(
            request, daemon=replace(request.daemon, command_templates=("/usr/sbin/sshd $HOME",))
        )
    assert state.materialization_digest() == before
    emitter.close()

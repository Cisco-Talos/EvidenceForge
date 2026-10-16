# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ordered receiver startup retains exact recovery before exposing shell readiness."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverStartup,
    MacosSshReceiverStartupRequest,
)
from evidenceforge.generation.activity.application_catalog import application_descriptor
from evidenceforge.generation.deployment_registry import CompiledApplicationDescriptor
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_audit_sessions import _START
from tests.unit.test_macos_service_drop import _account
from tests.unit.test_macos_ssh_process_graph import _bootstrap


def _descriptor(application_id: str) -> CompiledApplicationDescriptor:
    application = application_descriptor(application_id)
    platform = application["platforms"]["macos"]
    return CompiledApplicationDescriptor(
        application_id=application_id,
        platform="macos",
        image_path=platform["image_path"],
        command_templates=tuple(platform["command_templates"]),
        categories=tuple(application["categories"]),
    )


def _request(receiver: ProcessIdentity, shell: str = "macos-zsh") -> MacosSshReceiverStartupRequest:
    return MacosSshReceiverStartupRequest(
        receiver=receiver,
        service_account=_account(),
        wrapper=_descriptor("macos-sshd-keygen-wrapper"),
        daemon=_descriptor("macos-sshd"),
        session_worker=_descriptor("macos-sshd-session"),
        authentication_worker=_descriptor("macos-sshd-auth"),
        shell=_descriptor(shell),
        phase_times=tuple(_START + timedelta(seconds=second) for second in range(1, 12)),
    )


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("shell", ["macos-zsh", "macos-bash"])
def test_startup_exposes_ready_roles_only_after_every_ordered_phase(
    tmp_path: Path, collected: bool, shell: str
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    startup = MacosSshReceiverStartup(
        _request(receiver, shell), state=state, dispatcher=dispatcher, host=host
    )
    host.hostname = "changed-by-caller"
    for phase in range(11):
        assert startup.completed_phases == phase and startup.result is None
        result = startup.advance()
        assert (result is not None) == (phase == 10)
    assert startup.completed_phases == 11
    assert result == startup.result == startup.advance()
    assert result.privileged_receiver.principal == "root"
    assert result.authenticated_child.principal == result.shell.principal == "casey"
    assert result.privileged_receiver.pid == receiver.pid
    assert result.shell.command_line == ("-zsh" if shell == "macos-zsh" else "-bash")
    assert result.shell.parent_pid == result.authenticated_child.pid
    assert len(state._running_processes) == 4  # launchd, privileged receiver, user child, shell
    emitter.close()
    lines = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(lines) == (11 if collected else 0)


@pytest.mark.parametrize("failed_phase", range(11))
def test_startup_recovers_each_phase_lost_return_before_advancing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_phase: int
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_return(
        writer: ExternalSortedLineWriter, key: tuple[str, int, int], digest: str, frozen: object
    ) -> None:
        nonlocal attempts
        original(writer, key, digest, frozen)
        attempts += 1
        if attempts == failed_phase + 1:
            raise RuntimeError("injected startup phase lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    for _ in range(failed_phase):
        startup.advance()
    with pytest.raises(RuntimeError, match="startup phase lost return"):
        startup.advance()
    assert startup.completed_phases == failed_phase and startup.result is None
    version = state.materialization_version
    startup.advance()
    assert state.materialization_version == version
    while startup.result is None:
        startup.advance()
    dispatcher.assert_exact_projection_recoveries_drained()
    assert startup.completed_phases == 11
    emitter.close()
    lines = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(lines) == 11 and attempts == 12


@pytest.mark.parametrize(
    "damage", ["count", "order", "naive", "before_wrapper", "wrapper", "role", "shell", "service"]
)
def test_startup_request_rejects_invalid_phase_or_role_ownership(
    tmp_path: Path, damage: str
) -> None:
    _, _, emitter, _, receiver = _bootstrap(tmp_path)
    request = _request(receiver)
    fields = {}
    if damage == "count":
        fields["phase_times"] = request.phase_times[:-1]
    elif damage == "order":
        fields["phase_times"] = request.phase_times[::-1]
    elif damage == "naive":
        fields["phase_times"] = tuple(at.replace(tzinfo=None) for at in request.phase_times)
    elif damage == "before_wrapper":
        fields["phase_times"] = (_START,) + request.phase_times[1:]
    elif damage == "wrapper":
        fields["receiver"] = replace(receiver, image="/usr/bin/false")
    elif damage == "role":
        fields["daemon"] = request.authentication_worker
    elif damage == "shell":
        fields["shell"] = request.daemon
    else:
        fields["service_account"] = replace(request.service_account, host="MAC-B")
    with pytest.raises(StateError):
        replace(request, **fields)
    emitter.close()


@pytest.mark.parametrize("damage", ["host", "platform", "authentication", "readiness", "close"])
def test_startup_rejects_changed_session_or_host_before_mutation(
    tmp_path: Path, damage: str
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    request = _request(receiver)
    if damage == "host":
        host.hostname = "MAC-B"
    elif damage == "platform":
        host.os_category = "linux"
    elif damage == "authentication":
        request = replace(
            request,
            phase_times=request.phase_times[:6]
            + (_START + timedelta(seconds=7.5),)
            + request.phase_times[7:],
        )
    elif damage == "readiness":
        state.get_session(receiver.logon_id).source_ready_time = _START + timedelta(seconds=9)
    else:
        state.get_session(receiver.logon_id).network_close_time = _START + timedelta(seconds=9)
    version = state.materialization_version
    with pytest.raises(StateError):
        MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    assert state.materialization_version == version
    emitter.close()


@pytest.mark.parametrize("failed_phase", [0, 2, 4, 5, 6, 7, 9, 10])
def test_startup_precommit_failure_replans_without_advancing_or_changing_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_phase: int
) -> None:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability

    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(failed_phase):
        startup.advance()
    before = state.get_process_identity(receiver.hostname, receiver.pid)
    original = PreparedActionCohortCapability.commit_no_fail

    def fail_before_commit(capability: PreparedActionCohortCapability) -> None:
        raise RuntimeError("injected startup precommit failure")

    monkeypatch.setattr(PreparedActionCohortCapability, "commit_no_fail", fail_before_commit)
    version = state.materialization_version
    with pytest.raises(RuntimeError, match="startup precommit failure"):
        startup.advance()
    assert startup.completed_phases == failed_phase
    assert state.materialization_version == version
    assert state.get_process_identity(receiver.hostname, receiver.pid) == before
    monkeypatch.setattr(PreparedActionCohortCapability, "commit_no_fail", original)
    while startup.result is None:
        startup.advance()
    emitter.close()
    lines = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(lines) == 11


def test_startup_cannot_overwrite_an_intervening_receiver_execution(tmp_path: Path) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    builder = state.begin_action_cohort_materialization()
    changed = builder.execute_process(
        receiver,
        image="/usr/bin/false",
        command_line="/usr/bin/false",
        executed_at=_START + timedelta(milliseconds=100),
    )
    state.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError):
        startup.advance()
    assert state.get_process_identity(receiver.hostname, receiver.pid) == changed
    assert startup.completed_phases == 0
    emitter.close()

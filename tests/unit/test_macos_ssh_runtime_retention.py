# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _START, _request


@pytest.mark.parametrize("collected", [False, True])
def test_ssh_exec_retains_runtime_image_through_generation_and_history(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = _START + timedelta(days=6)
    request = _request(receiver)
    descriptor = replace(_executable(), native_path=request.daemon.image_path)
    _publish(content, descriptor, _START)
    first = content.build_record(descriptor)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    startup.advance()
    loaded = state.get_process_identity(host.hostname, receiver.pid)
    assert loaded.executable_version.artifact_version_id == first.artifact.artifact_version_id
    replacement = replace(descriptor, artifact_version=2, content_version=2)
    _publish(content, replacement, _START + timedelta(seconds=2))
    while startup.result is None:
        startup.advance()
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(first.artifact.artifact_version_id) == first
    head = LocalArtifactVersionRegistryParticipant(content.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        head.head.payload, ()
    )
    assert restored.registry.resolve_version(first.artifact.artifact_version_id) == first
    restored.registry.advance_watermark(_START + timedelta(days=8, seconds=1))
    assert restored.registry.resolve_version(first.artifact.artifact_version_id) is None
    emitter.close()


def test_ssh_retention_failure_preserves_phase_and_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = _START + timedelta(days=6)
    request = _request(receiver)
    descriptor = replace(_executable(), native_path=request.daemon.image_path)
    _publish(content, descriptor, _START)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> None:
        original(registry, *args)
        raise StateError("injected SSH retention failure")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    with pytest.raises(StateError, match="SSH retention"):
        startup.advance()
    assert startup.completed_phases == 0
    assert state.get_process_identity(host.hostname, receiver.pid) == receiver
    assert content.registry.census().prepared_publications == 0
    monkeypatch.undo()
    while startup.result is None:
        startup.advance()
    emitter.close()


def test_ssh_source_recovery_keeps_retention_and_does_not_execute_twice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path)
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = _START + timedelta(days=6)
    request = _request(receiver)
    descriptor = replace(_executable(), native_path=request.daemon.image_path)
    _publish(content, descriptor, _START)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal attempts
        original(writer, *args)
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected SSH image source return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    with pytest.raises(RuntimeError, match="SSH image source"):
        startup.advance()
    version = state.materialization_version
    startup.advance()
    assert state.materialization_version == version
    while startup.result is None:
        startup.advance()
    emitter.close()
    assert sum(len(path.read_text().splitlines()) for path in tmp_path.rglob("ecar.json")) == 11


@pytest.mark.parametrize("finite", [False, True])
def test_ssh_without_future_finite_horizon_does_not_invent_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, finite: bool
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, False)
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = _START if finite else datetime.max.replace(tzinfo=_START.tzinfo)
    request = _request(receiver)
    _publish(content, replace(_executable(), native_path=request.daemon.image_path), _START)

    def reject(*args: object, **kwargs: object) -> None:
        raise AssertionError("unexpected retention without a future finite horizon")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "prepare_version_retention", reject)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    startup.advance()
    emitter.close()


@pytest.mark.parametrize("collected", [False, True])
def test_first_exec_retains_the_old_runtime_wrapper_even_without_known_target_content(
    tmp_path: Path, collected: bool
) -> None:
    from evidenceforge.events.process_executable import ProcessExecutableVersion
    from tests.unit.test_macos_ssh_startup import _descriptor

    content = _manager()
    descriptor = replace(
        _executable(), native_path=_descriptor("macos-sshd-keygen-wrapper").image_path
    )
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    state, dispatcher, emitter, host, receiver = _bootstrap(
        tmp_path, collected, executable_version=ProcessExecutableVersion.from_binary(record.binary)
    )
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = _START + timedelta(days=6)
    startup = MacosSshReceiverStartup(
        _request(receiver), state=state, dispatcher=dispatcher, host=host
    )
    startup.advance()
    assert state.get_process_identity(host.hostname, receiver.pid).executable_version is None
    while startup.result is None:
        startup.advance()
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    emitter.close()


@pytest.mark.parametrize("collected", [False, True])
def test_ssh_fork_acquires_loaded_image_retention_without_requiring_an_exec_lease(
    tmp_path: Path,
    collected: bool,
) -> None:
    state, dispatcher, emitter, host, receiver = _bootstrap(tmp_path, collected)
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    dispatcher.output_end_time = None
    request = _request(receiver)
    descriptor = replace(_executable(), native_path=request.daemon.image_path)
    _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    startup.advance()
    assert startup.completed_phases == 1
    assert content.registry.census().active_leases == 0
    dispatcher.output_end_time = _START + timedelta(days=6)
    startup.advance()
    assert startup.completed_phases == 2
    assert content.registry.census().active_leases == 1
    _publish(
        content,
        replace(descriptor, artifact_version=2, content_version=2),
        _START + timedelta(seconds=3),
    )
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    assert content.resolve_record(host.hostname, "root", descriptor.native_path, "macos") is None
    emitter.close()

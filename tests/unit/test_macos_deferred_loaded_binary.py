# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatch
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_deferred_transport_binary_owner import _clone_prepared
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager
from tests.unit.test_ssh_deferred_production import _START, _fixture


def test_deferred_ssh_transport_authenticates_loaded_binary_after_path_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _fixture(tmp_path, production_timing_runtime=True)
    fixture.source.os = "macOS 26"
    content = _manager()
    descriptor = replace(
        _executable(), hostname=fixture.source.hostname, principal=fixture.user.username
    )
    _publish(content, descriptor, _START - timedelta(minutes=2))
    original_binary = content.build_record(descriptor).binary
    dispatcher = fixture.generator.dispatcher
    dispatcher.bind_local_artifact_registry(content.registry)
    launchd = fixture.state.plan_process_materialization(
        system=fixture.source.hostname,
        fixed_pid=1,
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START - timedelta(minutes=1),
        credentials=PosixProcessCredentials(0, 0, 0, 0),
    )
    fixture.state.materialize_process(launchd)
    fixture.generator._lifecycle_authority.ensure_process(fixture.source.hostname, 1)
    logon = fixture.generator.generate_logon(fixture.user, fixture.source, _START)
    pid = fixture.generator.generate_process(
        fixture.user,
        fixture.source,
        _START + timedelta(seconds=10),
        logon,
        descriptor.native_path,
        descriptor.native_path,
        parent_pid=1,
        suppress_command_file_effect=True,
        require_exact_parent=True,
    )
    assert pid > 0
    loaded = fixture.state.get_process_identity(fixture.source.hostname, pid)
    assert loaded.executable_version.content_id == original_binary.content_id
    _publish(
        content,
        replace(descriptor, artifact_version=2, content_version=2),
        _START + timedelta(seconds=11),
    )
    current = content.resolve_record(
        fixture.source.hostname, fixture.user.username, descriptor.native_path, "macos"
    )
    assert current.binary != original_binary
    original = EventDispatcher._validate_deferred_session_transport_binary_owner
    observed: list[str] = []

    def inspect(owner: EventDispatcher, prepared: PreparedDispatch, root: object) -> None:
        original(owner, prepared, root)
        if prepared._occurrence.src_host.hostname == fixture.source.hostname:
            assert prepared._occurrence.process.binary_identity == original_binary
            damaged = replace(
                original_binary, digests=replace(original_binary.digests, sha256="0" * 64)
            )
            for invalid in (current.binary, damaged):
                occurrence = replace(
                    prepared._occurrence,
                    process=replace(prepared._occurrence.process, binary_identity=invalid),
                )
                with pytest.raises(EventContractError, match="exact live root-owned"):
                    original(owner, _clone_prepared(prepared, occurrence), root)
            resolve = content.registry.resolve_version
            with monkeypatch.context() as missing:
                missing.setattr(
                    type(content.registry),
                    "resolve_version",
                    lambda _registry, key: (
                        None
                        if key == loaded.executable_version.artifact_version_id
                        else resolve(key)
                    ),
                )
                with pytest.raises(EventContractError, match="exact retained content"):
                    original(owner, prepared, root)
            observed.append(prepared.occurrence_id)

    monkeypatch.setattr(
        EventDispatcher, "_validate_deferred_session_transport_binary_owner", inspect
    )
    try:
        request = replace(
            fixture.request(),
            time=_START + timedelta(seconds=30),
            source_pid=pid,
            source_process_image=descriptor.native_path,
            emit_session_close=True,
            defer_session_close=True,
        )
        SshSessionActionBundle(request, fixture.generator).execute()
        fixture.generator.finalize_ssh_session_lifecycles(_START + timedelta(minutes=5))
        assert observed
    finally:
        fixture.close_and_read()

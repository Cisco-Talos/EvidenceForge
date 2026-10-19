# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented provisioning allocates installed file facts without host inspection."""

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from evidenceforge.events.content_identity import SoftwareInstallationIdentity
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_file import MacosFileTime
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_es_exit import MacosExitRecordInput
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.macos_endpoint_security import (
    prepare_installed_es_process_snapshot,
    prepare_planned_installed_es_process_snapshot,
)
from evidenceforge.generation.macos_installed_filesystem import (
    MacosInstalledFileSpec,
    MacosInstalledFilesystem,
    MacosInstalledVolumeSpec,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_exec_preparation import _fixture as _exec_fixture
from tests.unit.test_macos_es_exec_preparation import _prepare as _prepare_exec
from tests.unit.test_macos_es_exit_preparation import _fixture as _exit_fixture
from tests.unit.test_macos_es_exit_preparation import _prepare as _prepare_exit
from tests.unit.test_macos_es_fork_preparation import _fixture as _fork_fixture
from tests.unit.test_macos_es_fork_preparation import _prepare as _prepare_fork
from tests.unit.test_macos_installed_es_preparation import _setup
from tests.unit.test_macos_planned_installed_preparation import _plan
from tests.unit.test_macos_runtime_file_metadata import _metadata


def _volume(host: str, **changes: object) -> MacosInstalledVolumeSpec:
    return MacosInstalledVolumeSpec.model_validate(
        dict(
            hostname=host,
            volume_id="invented-system-volume",
            device=29,
            first_inode=730,
            preferred_block_size=4096,
        )
        | changes
    )


def _spec(
    deployments: DeploymentContentRegistry, process: ProcessIdentity, **changes: object
) -> MacosInstalledFileSpec:
    installation = deployments.installation_for_image(process.hostname, process.image, "macos")
    assert installation is not None
    stat = _metadata()
    return MacosInstalledFileSpec.model_validate(
        dict(
            installation_id=installation.installation_id,
            native_path=process.image,
            volume_id="invented-system-volume",
            valid_from=process.execution_started_at,
            valid_until=process.execution_started_at + timedelta(hours=2),
            permissions=0o755,
            uid=0,
            gid=0,
            accessed=stat.accessed,
            modified=stat.modified,
            changed=stat.changed,
            born=stat.born,
            size_bytes=8192,
            allocated_blocks=8,
            flags=0,
            generation=1,
        )
        | changes
    )


def _provider(
    deployments: DeploymentContentRegistry, process: ProcessIdentity
) -> MacosInstalledFilesystem:
    return MacosInstalledFilesystem(
        deployments,
        volumes=(_volume(process.hostname),),
        files=(_spec(deployments, process),),
    )


@pytest.mark.parametrize("version", [6, 9, 10])
def test_provider_drives_native_preparation_and_reconstruction_without_host_stat(
    monkeypatch: pytest.MonkeyPatch, version: int
) -> None:
    state, deployments, process, collection = _setup()

    def forbidden_stat(*args: object, **kwargs: object) -> None:
        pytest.fail("Modeled metadata must not inspect the generator filesystem")

    monkeypatch.setattr(Path, "stat", forbidden_stat)
    provider = _provider(deployments, process)
    before = state.materialization_digest()
    result = prepare_installed_es_process_snapshot(
        state,
        deployments,
        process=process,
        collection=collection,
        filesystem=provider,
        version=version,
    )
    assert state.materialization_digest() == before
    stat = result.executable.stat
    assert (stat.st_dev, stat.st_ino, stat.st_mode) == (29, 730, 0o100755)
    assert (stat.st_size, stat.st_blocks, stat.st_blksize) == (8192, 8, 4096)
    assert stat.st_birthtimespec != stat.st_mtimespec
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert (
        prepare_installed_es_process_snapshot(
            restored,
            deployments,
            process=process,
            collection=collection,
            filesystem=_provider(deployments, process),
            version=version,
        )
        == result
    )


@pytest.mark.parametrize("phase", ["birth", "exec", "terminal"])
def test_planned_preparation_uses_the_same_allocated_object(
    phase: Literal["birth", "exec", "terminal"],
) -> None:
    state, deployments, process, _ = _setup()
    provider = _provider(deployments, process)
    plan, collection = _plan(state, process, phase)
    before = state.materialization_digest()
    result = prepare_planned_installed_es_process_snapshot(
        state,
        deployments,
        cohort=plan,
        collection=collection,
        filesystem=provider,
        phase=phase,
        version=9,
    )
    assert result.executable.stat.st_ino == 730
    assert state.materialization_digest() == before
    if phase != "terminal":
        state.materialize_action_cohort(plan)
    assert (
        prepare_installed_es_process_snapshot(
            state,
            deployments,
            process=collection.process,
            collection=collection,
            filesystem=provider,
            version=9,
        )
        == result
    )


def test_allocation_order_scope_and_content_size_are_independent_of_paths_and_queries() -> None:
    _, source, process, _ = _setup()
    binary = source.resolve_binary(process.hostname, process.image, "macos")
    assert binary is not None
    first = SoftwareInstallationIdentity(
        process.hostname,
        "invented-worker",
        binary.release_id,
        "macos",
        "machine",
        image_paths=(process.image, "/opt/invented/invented-worker"),
    )
    second = replace(first, hostname="another-mac")
    deployments = DeploymentContentRegistry(
        binary_releases=(binary,), installations=(first, second)
    )
    spec = _spec(deployments, process)
    alternate = spec.model_copy(update={"native_path": "/opt/invented/invented-worker"})
    elsewhere = spec.model_copy(update={"installation_id": second.installation_id})
    volumes = (_volume(process.hostname), _volume("another-mac"))
    specs = (spec, alternate, elsewhere)
    provider = MacosInstalledFilesystem(deployments, volumes=volumes, files=specs)
    reordered = MacosInstalledFilesystem(
        deployments, volumes=reversed(volumes), files=reversed(specs)
    )
    alternate_process = replace(process, image=alternate.native_path)
    other_process = replace(
        process,
        hostname="another-mac",
        responsibility=None,
        parentage=None,
        job_control=None,
        primary_thread=None,
    )
    for subject in (other_process, alternate_process, process, alternate_process):
        assert provider.observe(
            deployments, subject, observed_at=spec.valid_from
        ) == reordered.observe(deployments, subject, observed_at=spec.valid_from)
    original = provider.observe(deployments, process, observed_at=spec.valid_from)
    other_path = provider.observe(deployments, alternate_process, observed_at=spec.valid_from)
    other_host = provider.observe(deployments, other_process, observed_at=spec.valid_from)
    assert original.binary == other_path.binary == other_host.binary
    assert original.metadata.inode != other_path.metadata.inode
    assert original.metadata.file_object_id != other_host.metadata.file_object_id
    with pytest.raises(StateError, match="conflicting sizes"):
        MacosInstalledFilesystem(
            deployments,
            volumes=volumes,
            files=(spec, alternate.model_copy(update={"size_bytes": 9000})),
        )


@pytest.mark.parametrize(
    "damage", ["missing", "wrong_deployment", "wrong_release", "before", "end", "naive"]
)
def test_observation_rejects_unknown_or_foreign_facts(damage: str) -> None:
    _, deployments, process, _ = _setup()
    provider = _provider(deployments, process)
    at = process.execution_started_at
    if damage == "missing":
        provider = MacosInstalledFilesystem(deployments, volumes=(), files=())
    elif damage == "wrong_deployment":
        deployments = DeploymentContentRegistry()
    elif damage == "wrong_release":
        process = replace(
            process, executable_version=replace(process.executable_version, content_id="wrong")
        )
    elif damage == "before":
        at -= timedelta(microseconds=1)
    elif damage == "end":
        at += timedelta(hours=2)
    else:
        at = at.replace(tzinfo=None)
    with pytest.raises(StateError, match="exact|provisioned"):
        provider.observe(deployments, process, observed_at=at)


def test_specs_and_returned_observations_cannot_mutate_allocated_metadata() -> None:
    _, deployments, process, _ = _setup()
    spec = _spec(deployments, process)
    provider = MacosInstalledFilesystem(
        deployments, volumes=(_volume(process.hostname),), files=(spec,)
    )
    before = provider.observe(deployments, process, observed_at=process.execution_started_at)
    object.__setattr__(spec.modified, "seconds", 1)
    object.__setattr__(before.metadata, "inode", 999)
    after = provider.observe(deployments, process, observed_at=process.execution_started_at)
    assert after.metadata.inode == 730 and after.metadata.modified.seconds != 1


@pytest.mark.parametrize(
    "damage", ["volume", "device", "placement", "installation", "path", "exhaustion"]
)
def test_compilation_rejects_ambiguous_or_incomplete_provisioning(damage: str) -> None:
    _, deployments, process, _ = _setup()
    volume = _volume(process.hostname)
    spec = _spec(deployments, process)
    volumes = (volume,)
    files = (spec,)
    if damage == "volume":
        volumes = ()
    elif damage == "device":
        volumes += (_volume(process.hostname, volume_id="duplicate-device"),)
    elif damage == "placement":
        files += (spec,)
    elif damage == "installation":
        files = (spec.model_copy(update={"installation_id": "missing"}),)
    elif damage == "path":
        files = (spec.model_copy(update={"native_path": "/tmp/not-installed"}),)
    else:
        # A second exact installed path would need inode 2**64 and must fail atomically.
        original = deployments.installation_by_id(spec.installation_id)
        binary = deployments.resolve_binary(process.hostname, process.image, "macos")
        original = replace(original, image_paths=(process.image, "/opt/invented/invented-worker"))
        deployments = DeploymentContentRegistry(
            binary_releases=(binary,), installations=(original,)
        )
        volumes = (_volume(process.hostname, first_inode=2**64 - 1),)
        files += (spec.model_copy(update={"native_path": "/opt/invented/invented-worker"}),)
    with pytest.raises(StateError):
        MacosInstalledFilesystem(deployments, volumes=volumes, files=files)


@pytest.mark.parametrize(
    "change",
    [
        {"valid_until": datetime(2020, 1, 1)},
        {"native_path": "/opt/../worker"},
        {"native_path": "//opt/worker"},
        {"native_path": "/opt//worker"},
        {"permissions": 0o100755},
        {"modified": MacosFileTime(seconds=2_000_000_000, nanoseconds=1)},
    ],
)
def test_provisioning_requires_explicit_valid_facts(change: dict[str, object]) -> None:
    _, deployments, process, _ = _setup()
    with pytest.raises(ValidationError):
        _spec(deployments, process, **change)


def test_native_preparation_rejects_two_competing_stat_owners() -> None:
    state, deployments, process, collection = _setup()
    with pytest.raises(StateError, match="one exact filesystem"):
        prepare_installed_es_process_snapshot(
            state,
            deployments,
            process=process,
            collection=collection,
            metadata=_metadata(),
            filesystem=_provider(deployments, process),
            version=9,
        )


@pytest.mark.parametrize("status", ["visible", "filtered", "delayed"])
def test_fork_prepares_one_allocated_file_for_both_executions(status: str) -> None:
    fixture = _fork_fixture(status, installed=True)
    provider = _provider(fixture.executables, fixture.parent.process)
    before = fixture.owner.state.materialization_digest()
    with _prepare_fork(fixture, installed_file=None, installed_filesystem=provider) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        assert record.process.executable == record.event.fork.child.executable
        assert record.process.executable.stat.st_ino == 730
        assert fixture.owner.state.materialization_digest() == before


@pytest.mark.parametrize("providers", ["ii", "ir", "ri"])
@pytest.mark.parametrize("version", [6, 9])
def test_exec_resolves_each_installed_image_from_its_own_provider(
    providers: str,
    version: int,
) -> None:
    fixture = _exec_fixture(providers=providers)
    process = fixture.before.process if providers[0] == "i" else fixture.after.process
    provider = _provider(fixture.deployments, process)
    before = fixture.owner.state.materialization_digest()
    with _prepare_exec(
        fixture,
        before_installed_file=None,
        after_installed_file=None,
        installed_filesystem=provider,
        version=version,
    ) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        if providers[0] == "i":
            assert record.process.executable.stat.st_ino == 730
        if providers[1] == "i":
            assert record.event.exec.target.executable.stat.st_ino == 730
        assert fixture.owner.state.materialization_digest() == before


def test_exit_and_batch_input_freeze_allocated_terminal_file_without_closing_state() -> None:
    fixture = _exit_fixture(installed=True)
    provider = _provider(fixture.executables, fixture.process.process)
    before = fixture.owner.state.materialization_digest()
    with _prepare_exit(fixture, installed_file=None, installed_filesystem=provider) as prepared:
        record = decode_endpoint_security_record(prepared.ndjson)
        batch_input = MacosExitRecordInput(
            fixture.executables,
            fixture.process,
            fixture.process.process.primary_thread,
            record.action,
            installed_filesystem=provider,
        )
        assert batch_input.installed_file.inode == record.process.executable.stat.st_ino == 730
        # A batch retains detached facts, not a mutable allocator or a query to repeat on retry.
        assert batch_input.installed_filesystem is None
        assert replace(batch_input) == batch_input
        assert fixture.owner.state.materialization_digest() == before


@pytest.mark.parametrize("family", ["fork", "exec", "exit"])
def test_native_record_preparation_rejects_borrowed_or_competing_providers(family: str) -> None:
    if family == "fork":
        fixture = _fork_fixture(installed=True)
        preparation = _prepare_fork(
            fixture, installed_filesystem=_provider(fixture.executables, fixture.parent.process)
        )
    elif family == "exec":
        fixture = _exec_fixture(providers="ii")
        preparation = _prepare_exec(
            fixture, installed_filesystem=_provider(fixture.deployments, fixture.before.process)
        )
    else:
        fixture = _exit_fixture(installed=True)
        preparation = _prepare_exit(
            fixture, installed_filesystem=_provider(fixture.executables, fixture.process.process)
        )
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError, match="one exact filesystem"):
        with preparation:
            pytest.fail("Competing file owners must not prepare native bytes")
    assert fixture.owner.state.materialization_digest() == before


@pytest.mark.parametrize("collected", [False, True])
def test_provisioned_native_bytes_join_exact_canonical_publication(
    tmp_path: Path,
    collected: bool,
) -> None:
    from tests.unit.test_macos_es_dispatch_publication import _bind
    from tests.unit.test_macos_es_dispatch_publication import _setup as dispatch_setup

    native, dispatcher, emitter, batch, frozen = dispatch_setup(
        tmp_path,
        installed=True,
        installed_filesystem=True,
        collected=collected,
    )
    try:
        _bind(native, dispatcher, batch)
        result = dispatcher.publish_prepared_action_cohort_batch(batch)
        assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
        assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
        assert decode_endpoint_security_record(frozen).process.executable.stat.st_ino == 730
        assert (
            native.owner.state.get_process(
                native.process.process.hostname, native.process.process.pid
            )
            is None
        )
        dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        emitter.close()


@pytest.mark.parametrize("after_write", [False, True])
def test_provisioned_file_observation_is_frozen_through_source_failure_and_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    after_write: bool,
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
    from tests.unit.test_macos_es_dispatch_publication import _bind
    from tests.unit.test_macos_es_dispatch_publication import _setup as dispatch_setup

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail_once(
        writer: ExternalSortedLineWriter,
        key: tuple[str, int, int],
        digest: str,
        row: object,
    ) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected provisioned-file source failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_once)
    native, dispatcher, emitter, batch, frozen = dispatch_setup(
        tmp_path,
        installed=True,
        installed_filesystem=True,
        threaded=False,
    )
    try:
        _bind(native, dispatcher, batch)
        with pytest.raises(RuntimeError, match="provisioned-file source failure") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
        assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
        state_version = native.owner.state.materialization_version
        collector = native.owner.collectors.connection(native.delivery.observation.source_instance)
        dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
        assert native.owner.state.materialization_version == state_version
        assert native.owner.collectors.connection(collector.source_instance) == collector
        assert attempts == 2
        dispatcher.assert_exact_projection_recoveries_drained()
    finally:
        emitter.close()

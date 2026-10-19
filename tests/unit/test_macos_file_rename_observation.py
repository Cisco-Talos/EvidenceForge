# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepared file observations freeze canonical truth without acting as authority."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_file_operation import MacosFileRenameObservation
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_file_replace import _destination
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable


@pytest.mark.parametrize("replacing", [False, True])
def test_observation_uses_exact_prepared_versions_without_changing_placements(
    replacing: bool,
) -> None:
    manager, source = _setup()
    destination = _destination(manager) if replacing else None
    with _rename(manager, source, replacement=destination) as rename:
        before = manager.census()
        observed = rename.observe()
        assert type(observed) is MacosFileRenameObservation
        assert observed.source == source
        assert observed.target.artifact.native_path == "/usr/local/libexec/renamed-worker"
        assert observed.target.content == source.content
        assert observed.replacement == destination
        assert observed.observed_at == _START + timedelta(seconds=1)
        assert observed.canonical_token == rename.expected_receipt.group_token
        assert rename.observe() == observed
        assert manager.census() == before
        assert _at(manager, source.artifact.native_path) == source
        assert _at(manager, observed.target.artifact.native_path) == destination
        receipt = rename.commit()
    assert receipt.group_token == observed.canonical_token
    assert _at(manager, observed.target.artifact.native_path) == observed.target
    assert observed.source == source


@pytest.mark.parametrize("field", ["source", "target", "replacement"])
def test_mutating_returned_stat_cannot_change_prepared_truth_or_the_retained_file(
    field: str,
) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with _rename(manager, source, replacement=destination) as rename:
        observed = rename.observe()
        expected = rename.observe()
        object.__setattr__(getattr(observed, field).macos_file, "inode", 9999)
        assert rename.observe() == expected
        assert _at(manager, source.artifact.native_path) == source
        assert _at(manager, destination.artifact.native_path) == destination
        rename.commit()
    assert _at(manager, destination.artifact.native_path) == expected.target
    assert manager.registry.resolve_version(source.artifact.artifact_version_id) == source
    assert manager.registry.resolve_version(destination.artifact.artifact_version_id) == destination


@pytest.mark.parametrize("committed", [False, True])
def test_expired_preparation_cannot_reobserve_even_though_detached_facts_survive(
    committed: bool,
) -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        observed = rename.observe()
        if committed:
            rename.commit()
    with pytest.raises(StateError):
        rename.observe()
    assert observed.source == source
    assert observed.target.artifact.artifact_id == source.artifact.artifact_id


@pytest.mark.parametrize("changed", ["source", "destination"])
def test_observation_rechecks_placements_instead_of_reusing_a_stale_preparation(
    changed: str,
) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with _rename(manager, source, replacement=destination) as rename:
        frozen = rename.observe()
        if changed == "source":
            descriptor = replace(_executable(), artifact_version=10, content_version=2)
        else:
            descriptor = replace(
                _executable(),
                artifact_version=10,
                content_version=2,
                native_path=destination.artifact.native_path,
            )
        token = manager.prepare_publication(descriptor, _START + timedelta(seconds=1))
        with manager.registry.prepared_publication(token) as publication:
            publication.commit()
        with pytest.raises(StateError, match="source|destination"):
            rename.observe()
        with pytest.raises(StateError, match="source|destination"):
            rename.commit()
        assert frozen.source == source and frozen.replacement == destination
    assert manager.census().prepared_publications == 0


def test_observation_value_does_not_authorize_publication_or_registry_operations() -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        observed = rename.observe()
        for value in (observed, replace(observed), rename.expected_receipt):
            with pytest.raises((StateError, TypeError)):
                manager.registry.observe_macos_file_rename(value)
            with pytest.raises((StateError, TypeError)):
                manager.registry.commit_macos_file_rename(value)
    assert _at(manager, source.artifact.native_path) == source


@pytest.mark.parametrize("damage", ["token", "time", "content", "signing", "mode", "destination"])
def test_observation_value_rejects_contradictory_file_facts(damage: str) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with _rename(manager, source, replacement=destination) as rename:
        observed = rename.observe()
        changes: dict[str, object] = {}
        if damage == "token":
            changes["canonical_token"] = "unbound"
        elif damage == "time":
            changes["observed_at"] = observed.observed_at.replace(tzinfo=None)
        elif damage == "content":
            changes["target"] = destination
        elif damage == "signing":
            changes["target"] = replace(
                observed.target, binary=replace(observed.target.binary, code_signature=None)
            )
        elif damage == "mode":
            changes["target"] = replace(
                observed.target,
                macos_file=observed.target.macos_file.model_copy(update={"mode": 0o100700}),
            )
        else:
            changes["replacement"] = source
        with pytest.raises(ValueError):
            replace(observed, **changes)
    assert _at(manager, source.artifact.native_path) == source


def test_observation_requires_same_thread_and_registry_claim() -> None:
    from concurrent.futures import ThreadPoolExecutor

    manager, source = _setup()
    other, _ = _setup()
    with _rename(manager, source) as rename:
        with pytest.raises(StateError):
            other.registry.observe_macos_file_rename(rename._publication)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(StateError):
                pool.submit(rename.observe).result(timeout=5)
        assert rename.observe().source == source
    assert _at(manager, source.artifact.native_path) == source

# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Nested admitted work must finish before a queued watermark can advance."""

from concurrent.futures import Future, ThreadPoolExecutor
from datetime import timedelta
from threading import Event, local

import pytest

from evidenceforge.events.content_identity import LocalArtifactIdentity
from evidenceforge.events.macos_file_operation import MacosFileRenameObservation
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPreparedGroupCommit,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.synchronization import MutationWatermarkGate
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_launch_registration import _START


def test_nested_mutation_finishes_but_waiting_writer_still_precedes_new_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = MutationWatermarkGate()
    writer_waiting, reader_waiting = Event(), Event()
    role = local()
    wait = gate._condition.wait
    order: list[str] = []

    def observed_wait(timeout: float | None = None) -> bool:
        (writer_waiting if role.name == "writer" else reader_waiting).set()
        return wait(timeout)

    monkeypatch.setattr(gate._condition, "wait", observed_wait)

    def writer() -> None:
        role.name = "writer"
        with gate.watermark():
            order.append("writer")

    def reader() -> None:
        role.name = "reader"
        with gate.mutation():
            order.append("reader")

    with ThreadPoolExecutor(max_workers=2) as pool:
        with gate.mutation():
            pending_writer = pool.submit(writer)
            assert writer_waiting.wait(3)
            pending_reader = pool.submit(reader)
            assert reader_waiting.wait(3)
            with pytest.raises(RuntimeError, match="injected"):
                with gate.mutation():
                    assert gate._readers == 2
                    order.append("nested")
                    raise RuntimeError("injected inner rollback")
            assert gate._readers == 1
            assert order == ["nested"]
        pending_writer.result(timeout=3)
        pending_reader.result(timeout=3)
    assert order == ["nested", "writer", "reader"]
    assert not gate._reader_depths
    assert (gate._readers, gate._waiting_writers, gate._writer) == (0, 0, False)


def test_actual_rename_completes_when_watermark_queues_between_validation_and_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    registry = manager.registry
    waiting = Event()
    wait = registry._gate._condition.wait
    original = LocalArtifactVersionRegistry._observe_macos_file_rename_locked
    pending: Future[tuple[LocalArtifactIdentity, ...]] | None = None

    def observed_wait(timeout: float | None = None) -> bool:
        waiting.set()
        return wait(timeout)

    monkeypatch.setattr(registry._gate._condition, "wait", observed_wait)
    with ThreadPoolExecutor(max_workers=1) as pool:

        def queue_watermark(
            owner: LocalArtifactVersionRegistry, transaction: LocalArtifactPreparedGroupCommit
        ) -> MacosFileRenameObservation:
            nonlocal pending
            observation = original(owner, transaction)
            if pending is None:
                pending = pool.submit(owner.advance_watermark, _START + timedelta(days=2))
                assert waiting.wait(3)
            return observation

        monkeypatch.setattr(
            LocalArtifactVersionRegistry, "_observe_macos_file_rename_locked", queue_watermark
        )
        with _rename(manager, source) as rename:
            rename.commit()
        assert pending is not None
        pending.result(timeout=3)
    assert _at(manager, source.artifact.native_path) is None
    assert _at(manager, "/usr/local/libexec/renamed-worker") is not None
    assert not registry._gate._reader_depths
    assert not registry._gate._readers

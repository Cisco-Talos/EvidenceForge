"""Discard-only cleanup must follow registered ownership and preserve failures."""

import os
import sqlite3
from pathlib import Path
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from evidenceforge.generation.emitters.verification_resources import (
    VerificationDisposal,
    VerificationResources,
)


def test_disposal_closes_shared_registered_descriptors_once(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY)
    child = SimpleNamespace(descriptor=descriptor)
    child._verification_resources = VerificationResources(child)
    child._verification_resources.register("descriptor", "descriptor")
    owner = SimpleNamespace(descriptor=descriptor, children={"a": child, "b": child})
    resources = VerificationResources(owner)
    resources.register("descriptor", "descriptor")
    resources.register("children", "children")
    VerificationDisposal(pending=[resources]).run()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    assert owner.descriptor is None
    assert child.descriptor is None
    VerificationDisposal(pending=[resources]).run()


def test_disposal_handles_partial_initialization_and_ignores_unowned_handles(
    tmp_path: Path,
) -> None:
    with (tmp_path / "external").open("w") as external:
        owner = SimpleNamespace(external_descriptor=external.fileno())
        resources = VerificationResources(owner)
        resources.register("connection", "not_initialized")
        resources.register("child", "not_initialized_child")
        VerificationDisposal(pending=[resources]).run()
        external.write("still externally owned")


def test_disposal_continues_after_sqlite_failure_and_retains_primary(tmp_path: Path) -> None:
    failure = sqlite3.OperationalError("injected close failure")

    class FailingConnection(sqlite3.Connection):
        def close(self) -> None:
            raise failure

    connection = sqlite3.connect(":memory:", factory=FailingConnection)
    descriptor = os.open(tmp_path, os.O_RDONLY)
    owner = SimpleNamespace(connection=connection, descriptor=descriptor)
    resources = VerificationResources(owner)
    resources.register("connection", "connection")
    resources.register("descriptor", "descriptor")
    try:
        with pytest.raises(sqlite3.OperationalError) as raised:
            VerificationDisposal(pending=[resources]).run()
        assert raised.value is failure
        assert owner.connection is connection
        assert owner.descriptor is None
    finally:
        sqlite3.Connection.close(connection)


def test_disposal_stops_worker_without_calling_source_finalization() -> None:
    stop = Event()
    worker = Thread(target=stop.wait)
    owner = SimpleNamespace(_stop_event=stop, _thread=worker, _verification_discard=False)
    resources = VerificationResources(owner, worker=True)
    worker.start()
    try:
        VerificationDisposal(pending=[resources]).run()
        assert not worker.is_alive()
        assert owner._verification_discard
        VerificationDisposal(pending=[resources]).run()
    finally:
        stop.set()
        worker.join()

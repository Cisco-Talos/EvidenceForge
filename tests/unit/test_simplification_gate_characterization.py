"""Freeze shared registry admission and caller-owned stable lock ordering."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event, local
from typing import Any

import pytest

from evidenceforge.generation.application_channels import _acquire_stable_locks as application_locks
from evidenceforge.generation.application_channels import _MutationGate as ApplicationGate
from evidenceforge.generation.deployment_registry import _ArtifactRegistryGate as ArtifactGate
from evidenceforge.generation.http_channels import _HttpMutationGate as HttpGate
from evidenceforge.generation.lifecycle_registry import _MutationGate as LifecycleGate
from evidenceforge.generation.proxy_channels import _SidecarMutationGate as ProxyGate
from evidenceforge.generation.rdp_sessions import _acquire_stable_locks as rdp_locks
from evidenceforge.generation.rdp_sessions import _MutationGate as RdpGate
from evidenceforge.generation.smb_channels import _SmbMutationGate as SmbGate
from evidenceforge.generation.ssh_channels import _MutationGate as SshGate
from evidenceforge.generation.ssh_channels import _stable_locks as ssh_locks


@pytest.mark.parametrize(
    "gate_type",
    [ApplicationGate, ArtifactGate, HttpGate, LifecycleGate, ProxyGate, RdpGate, SmbGate, SshGate],
)
def test_gate_admits_disjoint_work_but_waiting_writer_precedes_late_reader(
    gate_type: Any, monkeypatch: Any
) -> None:
    gate = gate_type()
    writer_waiting = Event()
    late_waiting = Event()
    role = local()
    order: list[str] = []
    wait = gate._condition.wait

    def observed_wait(timeout: float | None = None) -> bool:
        if role.name == "writer":
            writer_waiting.set()
        else:
            late_waiting.set()
        return wait(timeout)

    monkeypatch.setattr(gate._condition, "wait", observed_wait)

    def mutate(name: str) -> None:
        role.name = name
        with gate.mutation():
            order.append(name)

    def watermark() -> None:
        role.name = "writer"
        with gate.watermark():
            assert gate._readers == 0
            order.append("writer")

    with ThreadPoolExecutor(max_workers=3) as pool:
        with gate.mutation():
            pool.submit(mutate, "overlap").result(timeout=10)
            writer = pool.submit(watermark)
            assert writer_waiting.wait(timeout=10)
            late = pool.submit(mutate, "late")
            assert late_waiting.wait(timeout=10)
            assert order == ["overlap"]
            with gate_type().watermark():
                assert gate._readers == 1
        writer.result(timeout=10)
        late.result(timeout=10)
    assert order == ["overlap", "writer", "late"]
    assert (gate._readers, gate._waiting_writers, gate._writer) == (0, 0, False)


@pytest.mark.parametrize("acquire", [application_locks, rdp_locks, ssh_locks])
def test_stable_locks_deduplicate_identity_keep_first_key_and_release_reverse(acquire: Any) -> None:
    operations: list[tuple[str, str]] = []

    class RecordingLock:
        def __init__(self, name: str) -> None:
            self.name = name

        def acquire(self) -> bool:
            operations.append(("acquire", self.name))
            return True

        def release(self) -> None:
            operations.append(("release", self.name))

    first = RecordingLock("first")
    second = RecordingLock("second")
    entries = [((2, 0), first), ((1, 0), second), ((0, 0), first)]
    with pytest.raises(ValueError, match="primary"):
        with acquire(entries):
            assert operations == [("acquire", "second"), ("acquire", "first")]
            raise ValueError("primary")
    assert operations == [
        ("acquire", "second"),
        ("acquire", "first"),
        ("release", "first"),
        ("release", "second"),
    ]

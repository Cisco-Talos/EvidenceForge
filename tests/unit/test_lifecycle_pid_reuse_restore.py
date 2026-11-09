# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Hydrate distinct retained PID intervals before replaying authenticated closure."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleMembership,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry

_START = datetime(2026, 10, 15, tzinfo=UTC)


def _tree(
    image: str, new_start: int = 5
) -> tuple[LifecycleRegistry, tuple[ProcessLifecycleIdentity, ...]]:
    registry = LifecycleRegistry(shard_count=4)
    identities: list[ProcessLifecycleIdentity] = []

    def start(name: str, pid: int, seconds: int, parent: str = "") -> ProcessLifecycleIdentity:
        identity = ProcessLifecycleIdentity(
            "modeled-host",
            name,
            pid,
            _START + timedelta(seconds=seconds),
            image,
            parent_object_id=parent,
        )
        registry.register_process(
            identity,
            token=ProcessTokenIdentity("root", ""),
            membership=LifecycleMembership("boot", "modeled-boot", ""),
            action_id=name,
            transition_id=f"{name}:start",
        )
        identities.append(identity)
        return identity

    def close(identity: ProcessLifecycleIdentity, seconds: int) -> None:
        ticket = registry.request_close(
            LifecycleCloseBarrier(
                f"{identity.object_id}:barrier",
                identity.ref,
                _START + timedelta(seconds=seconds),
                "generated",
                f"{identity.object_id}:close",
            ),
            ticket_id=f"{identity.object_id}:ticket",
        )
        registry.close(ticket.ticket_id)

    root = start("root", 1, 0)
    old = start("z-old-parent", 42, 1, root.object_id)
    child = start("z-old-child", 43, 2, old.object_id)
    close(child, 3)
    close(old, 4)
    new = start("a-new-parent", 42, new_start, root.object_id)
    start("a-new-child", 43, new_start + 1, new.object_id)
    return registry, tuple(identities)


@pytest.mark.parametrize("image", ["/sbin/launchd", "/usr/bin/bash", r"C:\Windows\cmd.exe"])
@pytest.mark.parametrize("new_start", [4, 5])
def test_restore_preserves_closed_parent_tree_and_reused_live_pids(
    image: str, new_start: int
) -> None:
    registry, identities = _tree(image, new_start)
    restored = LifecycleRegistry(shard_count=4)
    _restore(restored, _capture(registry))
    for identity in identities:
        assert restored.get_process(identity.object_id) == registry.get_process(identity.object_id)
    assert restored.live_child_process_page("z-old-parent", limit=4)[0] == ()
    children, cursor = restored.live_child_process_page("a-new-parent", limit=4)
    assert tuple(child.identity.object_id for child in children) == ("a-new-child",)
    assert cursor is None
    twice = LifecycleRegistry(shard_count=4)
    _restore(twice, _capture(restored))
    assert twice.get_process("z-old-parent") == restored.get_process("z-old-parent")


def test_overlapping_checkpoint_pid_intervals_cannot_replace_the_live_registry() -> None:
    registry, _ = _tree("/sbin/launchd")
    document = loads(_capture(registry))
    row = next(
        row
        for partition in document["partitions"]
        for row in partition[0]
        if row[0][1] == "z-old-parent"
    )
    row[3][4] = (_START + timedelta(seconds=7)).isoformat()
    fresh = LifecycleRegistry(shard_count=4)
    before = _capture(fresh)
    with pytest.raises(CheckpointCorruptionError, match="overlapping PID"):
        _restore(fresh, dumps(document))
    assert _capture(fresh) == before


def test_restore_preserves_reused_logon_ids_and_their_exact_process_members() -> None:
    registry = LifecycleRegistry(shard_count=4)
    sessions = []
    processes = []
    for index in range(2):
        session = SessionLifecycleIdentity(
            hostname="modeled-host",
            object_id=f"session-{index}",
            logon_id="0x123",
            principal="synthetic-user",
            session_kind="interactive",
            started_at=_START + timedelta(seconds=index * 4),
        )
        registry.register_session(
            session, action_id=session.object_id, transition_id=f"{session.object_id}:start"
        )
        process = ProcessLifecycleIdentity(
            hostname=session.hostname,
            object_id=f"process-{index}",
            pid=42,
            started_at=session.started_at + timedelta(seconds=1),
            image="/bin/zsh",
        )
        registry.register_process(
            process,
            token=ProcessTokenIdentity(session.principal, session.logon_id),
            membership=LifecycleMembership("session", session.object_id, session.object_id),
            action_id=process.object_id,
            transition_id=f"{process.object_id}:start",
        )
        if index == 0:
            for identity, seconds in ((process, 2), (session, 3)):
                ticket = registry.request_close(
                    LifecycleCloseBarrier(
                        f"{identity.object_id}:barrier",
                        identity.ref,
                        _START + timedelta(seconds=seconds),
                        "generated",
                        f"{identity.object_id}:close",
                    ),
                    ticket_id=f"{identity.object_id}:ticket",
                )
                registry.close(ticket.ticket_id)
        sessions.append(session)
        processes.append(process)
    restored = LifecycleRegistry(shard_count=4)
    _restore(restored, _capture(registry))
    for session in sessions:
        assert restored.get_session(session.object_id) == registry.get_session(session.object_id)
    for process in processes:
        assert restored.get_process(process.object_id) == registry.get_process(process.object_id)


@pytest.mark.parametrize("kind", ["process", "session"])
def test_zero_duration_predecessor_at_equal_start_restores_before_live_reuse(kind: str) -> None:
    registry = LifecycleRegistry(shard_count=4)
    for index, name in enumerate(("z-ended", "a-live")):
        if kind == "process":
            identity = ProcessLifecycleIdentity("modeled-host", name, 42, _START, "/bin/true")
            registry.register_process(
                identity,
                token=ProcessTokenIdentity("root", ""),
                membership=LifecycleMembership("boot", "boot", ""),
                action_id=name,
                transition_id=f"{name}:start",
            )
        else:
            identity = SessionLifecycleIdentity(
                "modeled-host", name, "0x123", "synthetic-user", "interactive", _START
            )
            registry.register_session(identity, action_id=name, transition_id=f"{name}:start")
        if index == 0:
            ticket = registry.request_close(
                LifecycleCloseBarrier(
                    f"{name}:barrier", identity.ref, _START, "generated", f"{name}:close"
                ),
                ticket_id=f"{name}:ticket",
            )
            registry.close(ticket.ticket_id)
    restored = LifecycleRegistry(shard_count=4)
    _restore(restored, _capture(registry))
    read = restored.get_process if kind == "process" else restored.get_session
    original = registry.get_process if kind == "process" else registry.get_session
    assert read("z-ended") == original("z-ended")
    assert read("a-live") == original("a-live")

"""Cooperative generation-interrupt contracts."""

from __future__ import annotations

import os
import signal

import pytest

from evidenceforge.cli.generation_interrupt import GenerationInterruptController


@pytest.mark.parametrize(
    ("checkpoint_enabled", "expected"),
    [
        (True, b"after creating a recovery checkpoint"),
        (False, b"Checkpoint creation is disabled"),
    ],
)
def test_first_sigint_latches_graceful_stop_and_explains_behavior(
    checkpoint_enabled: bool,
    expected: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first interrupt should acknowledge a deferred end-of-hour stop."""

    writes: list[tuple[int, bytes]] = []
    monkeypatch.setattr(
        os,
        "write",
        lambda descriptor, payload: writes.append((descriptor, payload)) or len(payload),
    )
    controller = GenerationInterruptController(checkpoint_enabled=checkpoint_enabled)

    controller._handle_sigint(signal.SIGINT, None)

    assert controller.requested
    assert writes[0][0] == 2
    assert expected in writes[0][1]
    assert b"Press Ctrl+C again to force exit" in writes[0][1]


def test_second_sigint_forces_immediate_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    """A repeated interrupt should bypass cooperative cleanup with status 130."""

    writes: list[bytes] = []
    monkeypatch.setattr(
        os,
        "write",
        lambda _descriptor, payload: writes.append(payload) or len(payload),
    )
    monkeypatch.setattr(os, "_exit", lambda status: (_ for _ in ()).throw(SystemExit(status)))
    controller = GenerationInterruptController(checkpoint_enabled=True)
    controller._handle_sigint(signal.SIGINT, None)

    with pytest.raises(SystemExit, match="130"):
        controller._handle_sigint(signal.SIGINT, None)

    assert b"forcing immediate exit" in writes[-1]
    assert b"Any previously published recovery checkpoint" in writes[-1]

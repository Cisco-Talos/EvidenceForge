"""Contracts for the bounded ActivityGenerator checkpoint head."""

from datetime import UTC, datetime
from types import SimpleNamespace

from evidenceforge.generation.checkpoints.activity_head import _restore_foreground
from evidenceforge.generation.checkpoints.state_values import encode_state_value
from evidenceforge.generation.indexes import ExpiringIndex
from evidenceforge.models.scenario import System


def test_foreground_checkpoint_accepts_system_process_without_logon_id() -> None:
    """A valid system-owned process may have no interactive logon identifier."""
    system = System(
        hostname="LINUX-01",
        ip="10.0.0.20",
        os="Ubuntu 22.04",
        type="server",
    )
    started_at = datetime(2024, 1, 15, 10, 13, 41, tzinfo=UTC)
    finalizer_at = datetime(2024, 1, 15, 10, 13, 49, tzinfo=UTC)
    index: ExpiringIndex[tuple[object, ...], object] = ExpiringIndex()
    generator = SimpleNamespace(
        _scenario_environment=SimpleNamespace(systems=[system]),
        _foreground_process_finalizers=index,
    )
    rows = [
        [
            encode_state_value((system.hostname, 2042906, started_at)),
            system.hostname,
            "root",
            "/usr/bin/systemctl",
            "",
            encode_state_value(finalizer_at),
            finalizer_at.timestamp(),
            0,
            False,
        ]
    ]

    _restore_foreground(generator, rows)

    restored = index.checkpoint_records()
    assert len(restored) == 1
    assert restored[0][1][3] == ""

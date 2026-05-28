"""Tests for Windows source-native EventRecordID sequence modeling."""

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from evidenceforge.generation.emitters.windows_record_ids import WindowsRecordIdSequence


def _sample_gaps(channel: str, host_key: str, count: int = 640) -> list[int]:
    sequence = WindowsRecordIdSequence(channel, host_key)
    base = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    record_ids = [
        sequence.next(base + timedelta(seconds=index * 11), 5156 if channel == "security" else 3)
        for index in range(count)
    ]
    return [right - left for left, right in pairwise(record_ids)]


def test_security_record_id_gaps_include_midrange_and_large_hidden_activity() -> None:
    """Security exports should not expose small fixed renderer gap buckets."""
    gaps = _sample_gaps("security", "DC-01")

    assert all(gap > 0 for gap in gaps)
    assert any(9 <= gap <= 40 for gap in gaps)
    assert any(41 <= gap <= 400 for gap in gaps)
    assert max(gaps) > 900


def test_sysmon_record_id_gaps_are_not_capped_at_fifty() -> None:
    """Sysmon EventRecordID gaps should vary beyond the old fixed 50 cap."""
    gaps = _sample_gaps("sysmon", "WS-AJOHNSON-01")

    assert all(gap > 0 for gap in gaps)
    assert any(9 <= gap <= 40 for gap in gaps)
    assert max(gaps) > 120


def test_record_id_sequence_is_deterministic_per_host_channel() -> None:
    """Repeated generation for the same host/channel should be reproducible."""
    first = _sample_gaps("security", "FILE-SRV-01", count=128)
    second = _sample_gaps("security", "FILE-SRV-01", count=128)

    assert first == second

"""Tests for Windows source-native EventRecordID sequence modeling."""

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from evidenceforge.generation.emitters.windows_record_ids import (
    WindowsRecordIdSequence,
    coerce_windows_event_id,
    normalize_windows_event_id_value,
)


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


def test_security_clear_starts_a_new_native_channel_epoch() -> None:
    """Event 1102 should become the first record in the newly cleared Security channel."""
    sequence = WindowsRecordIdSequence("security", "DC-01")
    base = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

    before_clear = sequence.next(base, 4688)
    clear = sequence.next(base + timedelta(seconds=1), 1102)
    after_clear = sequence.next(base + timedelta(seconds=2), 5156)

    assert before_clear > 1
    assert clear == 1
    assert after_clear > clear


def test_multiple_security_clears_each_start_a_new_epoch() -> None:
    """Every visible clear should reset only its Security-channel sequence."""
    sequence = WindowsRecordIdSequence("security", "DC-01")
    base = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

    assert sequence.next(base, 1102) == 1
    assert sequence.next(base + timedelta(seconds=1), 4624) > 1
    assert sequence.next(base + timedelta(seconds=2), 1102) == 1


def test_sysmon_sequence_does_not_reset_for_numeric_1102() -> None:
    """The clear event ID is meaningful only inside the Security channel."""
    sequence = WindowsRecordIdSequence("sysmon", "DC-01")
    base = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

    first = sequence.next(base, 1)
    second = sequence.next(base + timedelta(seconds=1), 1102)

    assert second > first


def test_coerce_windows_event_id_ignores_malformed_raw_values() -> None:
    """Malformed raw EventID values should not abort record-ID sequencing."""
    assert coerce_windows_event_id("4624") == 4624
    assert coerce_windows_event_id(1.0) == 1
    assert coerce_windows_event_id("not-an-int") is None
    assert coerce_windows_event_id([]) is None
    assert coerce_windows_event_id({"EventID": 4624}) is None


def test_normalize_windows_event_id_value_stringifies_unhashable_raw_values() -> None:
    """Raw EventID containers should be safe for template metadata lookups."""
    assert normalize_windows_event_id_value([1]) == "[1]"
    assert normalize_windows_event_id_value({"EventID": 4624}) == "{'EventID': 4624}"
    assert normalize_windows_event_id_value("not-an-int") == "not-an-int"
    assert normalize_windows_event_id_value(4624) == 4624

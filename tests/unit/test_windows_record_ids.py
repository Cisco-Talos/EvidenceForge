"""Tests for Windows source-native EventRecordID sequence modeling."""

from datetime import UTC, datetime, timedelta
from itertools import pairwise

from evidenceforge.generation.emitters.windows_record_ids import (
    WindowsRecordIdSequence,
    coerce_windows_event_id,
    normalize_windows_event_id_value,
)


def _sample_gaps(
    channel: str,
    host_key: str,
    count: int = 640,
    interval: timedelta = timedelta(seconds=11),
) -> list[int]:
    sequence = WindowsRecordIdSequence(channel, host_key)
    base = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    record_ids = [
        sequence.next(base + (interval * index), 5156 if channel == "security" else 3)
        for index in range(count)
    ]
    return [right - left for left, right in pairwise(record_ids)]


def test_subsecond_security_gaps_are_bounded_by_elapsed_time() -> None:
    """A workstation cannot accumulate a large hidden channel burst in milliseconds."""
    gaps = _sample_gaps(
        "security",
        "WS-AJOHNSON-01",
        count=1_000,
        interval=timedelta(milliseconds=9),
    )

    assert all(gap > 0 for gap in gaps)
    assert max(gaps) <= 2


def test_subsecond_sysmon_gaps_are_bounded_by_elapsed_time() -> None:
    """Sysmon gaps should not imply hundreds of records between adjacent rows."""
    gaps = _sample_gaps(
        "sysmon",
        "WS-AJOHNSON-01",
        count=1_000,
        interval=timedelta(milliseconds=9),
    )

    assert all(gap > 0 for gap in gaps)
    assert max(gaps) <= 2


def test_security_hidden_activity_accumulates_over_long_intervals() -> None:
    """Long DC quiet periods should retain varied gaps from omitted channel activity."""
    gaps = _sample_gaps(
        "security",
        "DC-01",
        count=128,
        interval=timedelta(minutes=10),
    )

    assert len(set(gaps)) > 10
    assert max(gaps) > 40


def test_sysmon_hidden_activity_accumulates_over_long_intervals() -> None:
    """Long endpoint quiet periods should permit modest, non-uniform Sysmon gaps."""
    gaps = _sample_gaps(
        "sysmon",
        "WS-AJOHNSON-01",
        count=128,
        interval=timedelta(minutes=30),
    )

    assert len(set(gaps)) > 5
    assert max(gaps) > 10


def test_hidden_gap_volume_scales_with_elapsed_time() -> None:
    """Omitted record volume should follow elapsed time, not visible row count."""
    short_gaps = _sample_gaps(
        "security",
        "FILE-SRV-01",
        count=128,
        interval=timedelta(seconds=1),
    )
    long_gaps = _sample_gaps(
        "security",
        "FILE-SRV-01",
        count=128,
        interval=timedelta(minutes=10),
    )

    assert sum(gap - 1 for gap in long_gaps) > 50 * sum(gap - 1 for gap in short_gaps)


def test_multi_day_interval_is_sampled_without_per_record_iteration() -> None:
    """A 30-day interval should remain bounded and produce a plausible aggregate gap."""
    sequence = WindowsRecordIdSequence("security", "DC-01")
    base = datetime(2024, 3, 1, tzinfo=UTC)

    first = sequence.next(base, 4624)
    second = sequence.next(base + timedelta(days=30), 4624)

    assert second > first + 10_000
    assert second - first <= 1 + (240 * 30 * 24 * 60 * 60)


def test_record_id_sequence_is_deterministic_per_host_channel() -> None:
    """Repeated generation for the same host/channel should be reproducible."""
    first = _sample_gaps("security", "FILE-SRV-01", count=128)
    second = _sample_gaps("security", "FILE-SRV-01", count=128)

    assert first == second


def test_typed_host_capability_precedes_hostname_compatibility_fallback() -> None:
    """Canonical host type should own rate class even when a name is misleading."""
    workstation = WindowsRecordIdSequence("security", "DC-LAPTOP-01", "workstation")
    domain_controller = WindowsRecordIdSequence("security", "WS-IDENTITY-01", "domain_controller")

    assert 25_000 <= workstation.current <= 950_000
    assert 6_000_000 <= domain_controller.current <= 35_000_000


def test_security_and_sysmon_keep_independent_channel_epochs() -> None:
    """One host's Security and Sysmon streams should not share a record counter."""
    security = WindowsRecordIdSequence("security", "WS-AJOHNSON-01", "workstation")
    sysmon = WindowsRecordIdSequence("sysmon", "WS-AJOHNSON-01", "workstation")

    assert security.current != sysmon.current


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

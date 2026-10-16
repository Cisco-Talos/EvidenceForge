# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored native export structure contracts; no captured records."""

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from evidenceforge.formats.macos_unified_log import (
    UnifiedLogCompletion,
    UnifiedLogRecord,
    decode_unified_log_record,
)


def _log_record() -> dict[str, object]:
    return {
        "eventType": "logEvent",
        "messageType": "Default",
        "timezoneName": "",
        "timestamp": "2026-10-19 14:00:00.123456+0000",
        "machTimestamp": 24000000,
        "bootUUID": "11111111-2222-3333-4444-555555555555",
        "processID": 702,
        "userID": 501,
        "threadID": 4107,
        "processImagePath": "/Applications/Example.app/Contents/MacOS/Example",
        "processImageUUID": "22222222-3333-4444-5555-666666666666",
        "senderImagePath": "/Applications/Example.app/Contents/MacOS/Example",
        "senderImageUUID": "22222222-3333-4444-5555-666666666666",
        "senderProgramCounter": 1024,
        "activityIdentifier": 0,
        "parentActivityIdentifier": 0,
        "traceID": 123456789,
        "subsystem": "org.example.synthetic",
        "category": "contract-test",
        "formatString": "Example value: %{private}s",
        "eventMessage": "Example value: <private>",
        "backtrace": {
            "frames": [{"imageOffset": 1024, "imageUUID": "22222222-3333-4444-5555-666666666666"}]
        },
    }


@pytest.mark.parametrize("explicit_null", [False, True])
def test_unified_log_roundtrip_preserves_native_types_redaction_and_optional_presence(
    explicit_null: bool,
) -> None:
    fields = _log_record()
    if explicit_null:
        fields["source"] = None
    record = decode_unified_log_record(json.dumps(fields))
    assert isinstance(record, UnifiedLogRecord)
    assert record.event_time == datetime(2026, 10, 19, 14, 0, 0, 123456, tzinfo=UTC)
    assert json.loads(record.to_ndjson()) == fields
    assert record.event_message == "Example value: <private>"
    assert record.backtrace is not None and len(record.backtrace.frames) == 1
    with pytest.raises(ValidationError):
        record.process_id = 703


def test_unified_log_completion_is_not_an_event() -> None:
    record = decode_unified_log_record('{"count":2,"finished":1}')
    assert type(record) is UnifiedLogCompletion
    assert json.loads(record.to_ndjson()) == {"count": 2, "finished": 1}
    assert not hasattr(record, "event_time")


@pytest.mark.parametrize(
    "record",
    [
        '{"count":2,"finished":true}',
        '{"count":2,"finished":0}',
        '{"count":-1,"finished":1}',
        '{"count":"2","finished":1}',
        '{"count":2,"finished":1,"eventMessage":"not an event"}',
        "[]",
        "null",
    ],
)
def test_unified_log_rejects_invalid_completion_objects(record: str) -> None:
    with pytest.raises(ValidationError):
        decode_unified_log_record(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eventType", "activityCreateEvent"),
        ("eventType", "signpostEvent"),
        ("eventType", "timesyncEvent"),
        ("messageType", "Notice"),
        ("timestamp", "2026-02-30 14:00:00.123456+0000"),
        ("timestamp", "2026-10-19T14:00:00.123456Z"),
        ("timestamp", "2026-10-19 14:00:00.123456+9999"),
        ("processID", "702"),
        ("processID", True),
        ("userID", -1),
        ("traceID", 1 << 64),
        ("machTimestamp", 0.5),
        ("processImageUUID", "not-a-uuid"),
        ("source", {"unsupported": "metadata"}),
        ("backtrace", {"frames": [{"imageOffset": -1, "imageUUID": ""}]}),
        ("futureField", 42),
    ],
)
def test_unified_log_rejects_unimplemented_kinds_and_invalid_fields(
    field: str, value: object
) -> None:
    fields = _log_record()
    fields[field] = value
    with pytest.raises(ValidationError):
        decode_unified_log_record(json.dumps(fields))


def test_unified_log_preserves_offset_and_escapes_message_newlines() -> None:
    fields = _log_record()
    fields["timestamp"] = "2026-10-19 10:00:00.123456-0400"
    fields["eventMessage"] = "Synthetic first line\nSynthetic second line"
    record = decode_unified_log_record(json.dumps(fields))
    assert isinstance(record, UnifiedLogRecord)
    assert record.event_time.astimezone(UTC).hour == 14
    assert len(record.to_ndjson().splitlines()) == 1
    assert json.loads(record.to_ndjson()) == fields

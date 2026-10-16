# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded native Unified Log NDJSON contracts, independent of event generation.

This is the public-reference logEvent export profile. It deliberately does not
accept signposts, activity creation, timesync records, native archives or future
fields. Serialization preserves missing versus explicit null fields. These wire
contracts establish structure, not the fidelity of a generated native message.
"""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

type NativeUInt64 = Annotated[int, Field(ge=0, le=(1 << 64) - 1)]
type NativeUInt32 = Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
type NativeImageUUID = Annotated[
    str,
    Field(pattern=r"^(?:[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})?$"),
]


class _NativeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    def to_ndjson(self) -> str:
        """Render one native object without expanding absent optional fields."""
        return self.model_dump_json(exclude_unset=True, by_alias=True) + "\n"


class UnifiedLogFrame(_NativeRecord):
    """One image-relative native backtrace frame."""

    image_offset: NativeUInt64 = Field(
        alias="imageOffset", description="Image-relative program counter"
    )
    image_uuid: NativeImageUUID = Field(
        alias="imageUUID", description="Mach-O image UUID, not a content digest"
    )


class UnifiedLogBacktrace(_NativeRecord):
    """Native export wrapper for a sequence of image-relative frames."""

    frames: tuple[UnifiedLogFrame, ...] = Field(description="Ordered native backtrace frames")


class UnifiedLogRecord(_NativeRecord):
    """Selected logEvent representation from Apple's NDJSON export interface."""

    event_type: Literal["logEvent"] = Field(
        alias="eventType", description="Only the implemented export event kind"
    )
    message_type: Literal["Default", "Info", "Debug", "Error", "Fault"] = Field(
        alias="messageType", description="Source-native log level"
    )
    timezone_name: str = Field(
        alias="timezoneName", description="Export timezone label; may be empty"
    )
    timestamp: str = Field(
        pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}[+-][0-9]{4}$",
        description="Native wall-clock timestamp with explicit UTC offset",
    )
    mach_timestamp: NativeUInt64 = Field(alias="machTimestamp", description="Host Mach clock value")
    boot_uuid: NativeImageUUID = Field(alias="bootUUID", description="Host boot identity")
    process_id: NativeUInt32 = Field(alias="processID", description="Observed host-local PID")
    user_id: NativeUInt32 = Field(alias="userID", description="Observed effective user ID")
    thread_id: NativeUInt64 = Field(alias="threadID", description="Observed native thread ID")
    process_image_path: str = Field(alias="processImagePath", description="Process executable path")
    process_image_uuid: NativeImageUUID = Field(
        alias="processImageUUID", description="Process Mach-O image UUID"
    )
    sender_image_path: str = Field(
        alias="senderImagePath", description="Image with the logging call"
    )
    sender_image_uuid: NativeImageUUID = Field(
        alias="senderImageUUID", description="Sender Mach-O image UUID"
    )
    sender_program_counter: NativeUInt64 = Field(
        alias="senderProgramCounter", description="Sender image-relative program counter"
    )
    activity_identifier: NativeUInt64 = Field(
        alias="activityIdentifier", description="Native activity identity"
    )
    parent_activity_identifier: NativeUInt64 = Field(
        alias="parentActivityIdentifier", description="Parent activity identity"
    )
    trace_id: NativeUInt64 = Field(alias="traceID", description="Native trace identifier")
    subsystem: str = Field(description="Logging subsystem; may be empty")
    category: str = Field(description="Logging category; may be empty")
    format_string: str = Field(
        alias="formatString", description="Native format string with privacy annotations retained"
    )
    event_message: str = Field(
        alias="eventMessage", description="Rendered source message, including any redaction"
    )
    source: None = Field(default=None, description="Only absent/null source metadata is supported")
    backtrace: UnifiedLogBacktrace | None = Field(
        default=None, description="Optional native backtrace; explicit null remains distinct"
    )

    @field_validator("timestamp")
    @classmethod
    def valid_timestamp(cls, value: str) -> str:
        """Reject invalid calendar dates and offsets without changing native spelling."""
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f%z")
        return value

    @property
    def event_time(self) -> datetime:
        """Return the timezone-aware event time for evaluation."""
        return datetime.strptime(self.timestamp, "%Y-%m-%d %H:%M:%S.%f%z")


class UnifiedLogCompletion(_NativeRecord):
    """Export bookkeeping, explicitly not an evidence-producing event."""

    count: NativeUInt64 = Field(description="Exported event count")
    finished: Literal[1] = Field(description="Native export completion marker")

    @field_validator("finished", mode="before")
    @classmethod
    def integer_marker(cls, value: object) -> object:
        """Keep JSON booleans distinct from the numeric native marker."""
        if type(value) is not int:
            raise ValueError("Unified Log completion requires an integer marker")
        return value


def decode_unified_log_record(raw: str) -> UnifiedLogRecord | UnifiedLogCompletion:
    """Decode one bounded-profile object without treating completion as an event.

    File readers own byte limits. Validation errors are left for the caller's
    normal parse-diagnostic path; unsupported native event families fail closed.
    """
    import json

    # Inspect only the discriminant. Each branch validates the original JSON,
    # retaining strict JSON types and tuple-from-array handling in Pydantic.
    value = json.loads(raw)
    if isinstance(value, dict) and "eventType" not in value and "finished" in value:
        return UnifiedLogCompletion.model_validate_json(raw)
    return UnifiedLogRecord.model_validate_json(raw)

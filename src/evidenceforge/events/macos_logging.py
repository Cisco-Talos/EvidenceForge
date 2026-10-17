# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Immutable writer facts for bounded native Unified Log projections.

These facts describe the process doing the logging, not the user or session that
its message concerns. Producers supply modeled image locations and clock facts;
renderers never inspect the host, allocate identities, or infer a Mach-O image
from a path. This first profile uses a main-image callsite without an activity,
private arguments, oversize data, or a backtrace.
"""

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal
from uuid import UUID

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.identity import ProcessIdentity, ThreadIdentity

type UnifiedLogLevel = Literal["Default", "Info", "Debug", "Error", "Fault"]

# Native protocol discriminants, not activity pools. Apple's public XNU
# firehose_types_private.h and tracepoint_private.h define this little-endian
# namespace/type/flags/code layout. The offsets below are producer-owned facts,
# not values taken from an observed Apple executable.
_LOG_TYPES: dict[str, int] = {"Default": 0, "Info": 1, "Debug": 2, "Error": 16, "Fault": 17}


def _unsigned(value: int, bits: int, name: str, *, positive: bool = False) -> None:
    if type(value) is not int or not int(positive) <= value < 2**bits:
        raise ValueError(f"{name} requires an unsigned {bits}-bit integer")


def _aware(value: datetime, name: str) -> None:
    if type(value) is not datetime or value.utcoffset() is None:
        raise ValueError(f"{name} requires an aware timestamp")


@dataclass(frozen=True, slots=True)
class UnifiedLogCallsite:
    """One explicit main-executable logging point in a modeled build.

    Format and program-counter offsets are distinct. A tracepoint is not an
    occurrence ID: repeated calls at this point retain the same native trace ID.
    Synthetic build profiles may supply modeled offsets; doing so does not claim
    that those offsets were measured in a publisher's binary.
    """

    message_type: UnifiedLogLevel
    subsystem: str
    category: str
    format_string: str
    format_string_offset: int
    program_counter: int
    has_rules: bool = False

    def __post_init__(self) -> None:
        """Reject unsupported wire shapes before a renderer receives them."""
        if type(self.message_type) is not str or self.message_type not in _LOG_TYPES:
            raise ValueError("Unified Log callsite requires a supported message type")
        for value in (self.subsystem, self.category, self.format_string):
            if type(value) is not str or "\x00" in value:
                raise ValueError("Unified Log callsite text requires NUL-free strings")
        if not self.format_string or (self.category and not self.subsystem):
            raise ValueError("Unified Log callsite requires a format and consistent subsystem")
        # The top bit denotes a dynamic format, which this static profile excludes.
        _unsigned(self.format_string_offset, 31, "Static format offset", positive=True)
        _unsigned(self.program_counter, 32, "Main-image program counter", positive=True)
        if self.program_counter % 4:
            raise ValueError("Native arm64 program counter must be instruction-aligned")
        if type(self.has_rules) is not bool:
            raise ValueError("Unified Log callsite rules flag requires a boolean")

    @property
    def trace_id(self) -> int:
        """Encode the supported native tracepoint header without occurrence entropy."""
        flags = 0x0002  # Main executable program-counter style.
        if self.subsystem:
            flags |= 0x0200
        if self.has_rules:
            flags |= 0x0400
        return (
            (self.format_string_offset << 32)
            | (flags << 16)
            | (_LOG_TYPES[self.message_type] << 8)
            | 0x04
        )


@dataclass(frozen=True, slots=True)
class MacosUnifiedLogObservation:
    """A logging occurrence with already-owned native identity and uptime.

    Canonical action/session ownership lives outside this source view. The
    effective UID is the writer's credential, even when a root service logs a
    request concerning a nonroot user. Collection delay does not change uptime.
    """

    canonical_time: datetime
    writer: ProcessIdentity
    thread: ThreadIdentity
    binary: BinaryReleaseIdentity
    boot_uuid: str
    mach_timestamp: int
    callsite: UnifiedLogCallsite
    message: str

    def __post_init__(self) -> None:
        """Bind writer, thread, image and clock facts without filling unknowns."""
        _aware(self.canonical_time, "Unified Log occurrence")
        if type(self.writer) is not ProcessIdentity or type(self.thread) is not ThreadIdentity:
            raise ValueError("Unified Log requires exact canonical writer and thread identities")
        if type(self.binary) is not BinaryReleaseIdentity or self.binary.mach_o_image is None:
            raise ValueError("Unified Log writer requires explicit native Mach-O image metadata")
        if self.binary.key.platform != "macos" or self.binary.key.architecture != "arm64":
            raise ValueError("Unified Log writer requires the native macOS arm64 profile")
        if type(self.callsite) is not UnifiedLogCallsite:
            raise ValueError("Unified Log requires an exact immutable callsite")
        if self.writer.credentials is None:
            raise ValueError("Unified Log writer requires explicit effective credentials")
        if (
            self.thread.hostname != self.writer.hostname
            or self.thread.process_object_id != self.writer.object_id
            or self.thread.pid != self.writer.pid
        ):
            raise ValueError("Unified Log thread must belong to the exact writer lifetime")
        _aware(self.writer.execution_started_at, "Unified Log writer execution")
        _aware(self.thread.started_at, "Unified Log writer thread")
        if not self.writer.execution_started_at <= self.thread.started_at <= self.canonical_time:
            raise ValueError("Unified Log thread must exist in the current writer execution")
        path = PurePosixPath(self.writer.image)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or path.name != self.binary.key.artifact_name
        ):
            raise ValueError("Unified Log image path must name its exact native artifact")
        _unsigned(self.writer.pid, 32, "Unified Log PID", positive=True)
        _unsigned(self.thread.tid, 64, "Unified Log TID", positive=True)
        _unsigned(self.mach_timestamp, 64, "Unified Log Mach timestamp")
        if type(self.boot_uuid) is not str:
            raise ValueError("Unified Log requires a canonical nonnil boot UUID")
        try:
            boot_uuid = UUID(self.boot_uuid)
        except ValueError as error:
            raise ValueError("Unified Log requires a canonical nonnil boot UUID") from error
        if boot_uuid.int == 0 or str(boot_uuid) != self.boot_uuid.lower():
            raise ValueError("Unified Log requires a canonical nonnil boot UUID")
        object.__setattr__(self, "boot_uuid", str(boot_uuid).upper())
        if type(self.message) is not str or "\x00" in self.message:
            raise ValueError("Unified Log message requires a NUL-free string")

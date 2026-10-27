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
from uuid import NAMESPACE_URL, UUID, uuid5

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.identity import (
    EntityIdentity,
    ProcessIdentity,
    SessionIdentity,
    ThreadIdentity,
)
from evidenceforge.events.macos_policy import MacosPolicyRefusalTarget

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


@dataclass(frozen=True, slots=True)
class MacosWorkspaceRequest:
    """Workspace method entry, distinct from authentication or desktop completion.

    The canonical request can occur without native source reachability. An
    unavailable projection retains its reason instead of manufacturing a writer.
    """

    session: SessionIdentity
    requested_at: datetime
    writer: ProcessIdentity | None
    native: MacosUnifiedLogObservation | None
    unavailable_reason: Literal[
        "", "writer_unavailable", "native_image_unavailable", "profile_unavailable"
    ] = ""

    def __post_init__(self) -> None:
        """Keep the request's subject separate from its reporting process."""
        if type(self.session) is not SessionIdentity or self.session.session_kind != "interactive":
            raise ValueError("Mac workspace request requires a local interactive session")
        _aware(self.requested_at, "Mac workspace request")
        if self.requested_at < self.session.started_at:
            raise ValueError("Mac workspace request cannot precede its session")
        if self.writer is not None and (
            type(self.writer) is not ProcessIdentity
            or self.writer.hostname != self.session.hostname
        ):
            raise ValueError("Mac workspace writer must belong to the subject host")
        if self.native is None:
            expected = "writer_unavailable" if self.writer is None else "native_image_unavailable"
            if self.unavailable_reason not in {expected, "profile_unavailable"}:
                raise ValueError("Unavailable native workspace observation requires its reason")
        elif (
            type(self.native) is not MacosUnifiedLogObservation
            or self.native.writer != self.writer
            or self.native.canonical_time != self.requested_at
            or self.unavailable_reason != ""
        ):
            raise ValueError("Native workspace observation must match the exact request and writer")


@dataclass(frozen=True, slots=True)
class KernelLogCallsite:
    """Explicit modeled kernel callsite using the reviewed absolute PC style.

    Offsets are synthetic build-profile facts, never sampled native addresses.
    Activities, private/oversize/context payloads and non-log namespaces are excluded.
    """

    format_string: str
    format_string_offset: int
    program_counter: int

    def __post_init__(self) -> None:
        if (
            type(self.format_string) is not str
            or not self.format_string
            or "\0" in self.format_string
        ):
            raise ValueError("Kernel callsite requires a static NUL-free format")
        _unsigned(self.format_string_offset, 31, "Kernel static format offset", positive=True)
        _unsigned(self.program_counter, 64, "Kernel sender program counter", positive=True)
        if self.program_counter % 4:
            raise ValueError("Kernel sender program counter requires arm64 alignment")

    @property
    def trace_id(self) -> int:
        """Encode Default/log namespace with only the absolute-PC style bits."""
        return (self.format_string_offset << 32) | (0x0008 << 16) | 0x04


@dataclass(frozen=True, slots=True)
class MacosKernelLogObservation:
    """Boot-owned kernel writer and independent sender image at one observation.

    A kernel logging TID is reserved in the host namespace without inventing an
    ordinary process or a thread-creation event. Its lifetime is unspecified.
    """

    canonical_time: datetime
    writer: EntityIdentity
    boot_time: datetime
    boot_uuid: str
    kernel_path: str
    kernel_binary: BinaryReleaseIdentity
    sender_path: str
    sender_binary: BinaryReleaseIdentity
    thread_id: int
    mach_timestamp: int
    callsite: KernelLogCallsite
    message: str

    def __post_init__(self) -> None:
        _aware(self.canonical_time, "Kernel log observation")
        _aware(self.boot_time, "Kernel writer boot")
        if self.canonical_time < self.boot_time:
            raise ValueError("Kernel observation cannot precede its boot")
        if type(self.writer) is not EntityIdentity or self.writer.kind != "kernel_writer":
            raise ValueError("Kernel observation requires a boot-owned kernel resource")
        if not self.writer.hostname:
            raise ValueError("Kernel writer requires its host")
        for path, binary in (
            (self.kernel_path, self.kernel_binary),
            (self.sender_path, self.sender_binary),
        ):
            if (
                type(path) is not str
                or any(char in path for char in ("\0", "\n", "\r"))
                or type(binary) is not BinaryReleaseIdentity
                or binary.mach_o_image is None
                or binary.key.platform != "macos"
                or binary.key.architecture != "arm64"
                or not PurePosixPath(path).is_absolute()
                or ".." in PurePosixPath(path).parts
                or PurePosixPath(path).name != binary.key.artifact_name
            ):
                raise ValueError("Kernel writer and sender require exact deployed native artifacts")
        if self.kernel_path == self.sender_path or self.kernel_binary == self.sender_binary:
            raise ValueError("Kernel writer and policy sender must retain distinct artifacts")
        if type(self.callsite) is not KernelLogCallsite:
            raise ValueError("Kernel log requires its exact absolute-style callsite")
        _unsigned(self.thread_id, 64, "Kernel logging TID", positive=True)
        _unsigned(self.mach_timestamp, 64, "Kernel Mach timestamp")
        try:
            boot = UUID(self.boot_uuid)
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError("Kernel log requires a canonical nonnil boot UUID") from error
        if not boot.int or str(boot) != self.boot_uuid.lower():
            raise ValueError("Kernel log requires a canonical nonnil boot UUID")
        object.__setattr__(self, "boot_uuid", str(boot).upper())
        if self.writer != kernel_writer_identity(
            self.writer.hostname, self.boot_uuid, self.kernel_path
        ):
            raise ValueError("Kernel writer must belong to the exact host boot and kernel image")
        if type(self.message) is not str or "\0" in self.message:
            raise ValueError("Kernel log requires a NUL-free message")


@dataclass(frozen=True, slots=True)
class MacosPolicyRefusal:
    """A bounded app-policy refusal with no claimed cause or execution stage."""

    target: MacosPolicyRefusalTarget
    initiator: ProcessIdentity
    native: MacosKernelLogObservation | None
    unavailable_reason: Literal["", "profile_unavailable", "native_image_unavailable"] = ""

    def __post_init__(self) -> None:
        if (
            type(self.target) is not MacosPolicyRefusalTarget
            or type(self.initiator) is not ProcessIdentity
        ):
            raise ValueError("Policy refusal requires its exact attempt and initiating process")
        if (
            self.initiator.hostname != self.target.hostname
            or self.initiator.execution_started_at > self.target.refused_at
            or self.initiator.pid == self.target.pid
        ):
            raise ValueError("Policy refusal target must be distinct from its existing initiator")
        if self.native is None:
            if self.unavailable_reason not in {"profile_unavailable", "native_image_unavailable"}:
                raise ValueError("Unavailable native policy refusal requires its reason")
        elif (
            type(self.native) is not MacosKernelLogObservation
            or self.native.writer.hostname != self.target.hostname
            or self.native.canonical_time != self.target.refused_at
            or self.unavailable_reason
        ):
            raise ValueError("Policy refusal observation must preserve its exact host and time")
        if self.native is not None and (
            self.native.callsite.format_string
            != "ASP: Security policy would not allow process: %d, %s\n"
            or self.native.message
            != self.native.callsite.format_string % (self.target.pid, self.target.image)
        ):
            raise ValueError("Policy refusal must retain the bounded template and exact target")


def kernel_writer_identity(hostname: str, boot_uuid: str, kernel_path: str) -> EntityIdentity:
    """Name a boot-owned kernel resource independently of process PID identities."""
    return EntityIdentity(
        str(uuid5(NAMESPACE_URL, f"kernel-writer:{hostname}:{boot_uuid.upper()}")),
        "kernel_writer",
        hostname,
        kernel_path,
    )

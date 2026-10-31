# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Version-bounded eslogger notification contracts from reviewed references.

These are wire records, not canonical process or file state. Version 6 and 9
profiles describe historical references; version 10 covers fork. The privately
reviewed macOS 27/message-11 profile covers fork, exec with null or bounded Boolean/string-array
entitlements, and exit. Decoder admission does not enable generator sources or establish
macOS 26 fidelity. Unsupported combinations fail closed. A notification result
is not an authorization callback or a synthetic policy decision.
"""

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_entitlements import (
    FrozenEntitlements,
    freeze_entitlements,
    native_entitlements,
)
from evidenceforge.events.process_outcome import PosixProcessExit

type UInt32 = Annotated[int, Field(ge=0, le=(1 << 32) - 1)]
type UInt64 = Annotated[int, Field(ge=0, le=(1 << 64) - 1)]
type Int32 = Annotated[int, Field(ge=-(1 << 31), le=(1 << 31) - 1)]
type NativeTime = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$")
]
type ProcessStartTime = Annotated[
    str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$")
]
type AuditTokenArray = tuple[UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32]


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @field_validator(
        "version",
        "schema_version",
        "event_type",
        "action_type",
        "result_type",
        "auth",
        "destination_type",
        mode="before",
        check_fields=False,
    )
    @classmethod
    def reject_boolean_discriminants(cls, value: object) -> object:
        """Literal integers must not admit JSON booleans or numeric strings."""
        if type(value) is not int:
            raise ValueError("Native discriminants require an integer")
        return value


class ESAuditToken(_Record):
    """Historical named audit token; no username substitution or PID-only identity."""

    auid: UInt32 = Field(description="Audit user identity, including the unset sentinel")
    euid: UInt32 = Field(description="Effective UID")
    egid: UInt32 = Field(description="Effective GID")
    ruid: UInt32 = Field(description="Real UID")
    rgid: UInt32 = Field(description="Real GID")
    pid: UInt32 = Field(description="Host-local process ID")
    asid: UInt32 = Field(description="Audit session ID")
    pidversion: UInt32 = Field(description="Native audit PID version, distinct from PID/lifetime")

    @classmethod
    def from_process_identity(cls, identity: ProcessIdentity) -> Self:
        """Project a complete canonical snapshot; never substitute inferred audit IDs."""

        credentials = identity.credentials
        if (
            credentials is None
            or credentials.audit_uid is None
            or credentials.audit_session_id is None
            or identity.audit_pid_version is None
        ):
            raise ValueError(
                "ES audit-token projection requires explicit credentials and PID version"
            )
        return cls(
            auid=credentials.audit_uid,
            euid=credentials.effective_uid,
            egid=credentials.effective_gid,
            ruid=credentials.real_uid,
            rgid=credentials.real_gid,
            pid=identity.pid,
            asid=credentials.audit_session_id,
            pidversion=identity.audit_pid_version,
        )

    def as_native_array(self) -> AuditTokenArray:
        """Project the native eight-word ordering used by the version-10 profile."""

        return (
            self.auid,
            self.euid,
            self.egid,
            self.ruid,
            self.rgid,
            self.pid,
            self.asid,
            self.pidversion,
        )


class ESFileStat(_Record):
    """Native stat metadata, independent of the content digest and rendered path."""

    st_dev: Int32
    st_mode: Annotated[int, Field(ge=0, le=65535)]
    st_nlink: Annotated[int, Field(ge=0, le=65535)]
    st_ino: UInt64
    st_uid: UInt32
    st_gid: UInt32
    st_rdev: Int32
    st_atimespec: NativeTime
    st_mtimespec: NativeTime
    st_ctimespec: NativeTime
    st_birthtimespec: NativeTime
    st_size: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
    st_blocks: Annotated[int, Field(ge=0, le=(1 << 63) - 1)]
    st_blksize: Int32
    st_flags: UInt32
    st_gen: UInt32

    @field_validator("st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec")
    @classmethod
    def valid_calendar_time(cls, value: str) -> str:
        """Validate the calendar while retaining all native nanosecond digits."""
        datetime.fromisoformat(value)
        return value


class ESFile(_Record):
    """Observed file identity/path with source-native truncation information."""

    path: str
    path_truncated: bool
    stat: ESFileStat


class ESProcess(_Record):
    """One source-native process snapshot; parent/responsible identities stay distinct."""

    audit_token: ESAuditToken | AuditTokenArray
    parent_audit_token: ESAuditToken | AuditTokenArray
    responsible_audit_token: ESAuditToken | AuditTokenArray
    ppid: UInt32
    original_ppid: UInt32
    group_id: UInt32
    session_id: UInt32
    codesigning_flags: UInt32
    is_platform_binary: bool
    is_es_client: bool
    executable: ESFile
    tty: ESFile | None
    start_time: ProcessStartTime
    signing_id: str | None
    team_id: str | None
    cdhash: Annotated[str, Field(pattern=r"^[0-9a-fA-F]{40}$")]
    cs_validation_category: UInt32 | None = None

    @field_validator("start_time")
    @classmethod
    def valid_start_time(cls, value: str) -> str:
        """Validate the six-digit native process-start timestamp."""
        datetime.fromisoformat(value)
        return value


class ESAuthorizationResult(_Record):
    auth: Literal[0, 1]


class ESNotificationResult(_Record):
    result_type: Literal[0]
    result: ESAuthorizationResult


class ESAction(_Record):
    result: ESNotificationResult


class ESThread(_Record):
    thread_id: UInt64


class ESFork(_Record):
    child: ESProcess


class ESForkEvent(_Record):
    fork: ESFork


class ESPipe(_Record):
    pipe_id: UInt64 = Field(description="Source-native pipe identity, not a filesystem inode")


class ESFileDescriptor(_Record):
    fd: Int32
    fdtype: UInt32
    pipe: ESPipe | None = None

    @model_validator(mode="after")
    def pipe_variant(self) -> Self:
        """Preserve the tagged pipe payload instead of treating every FD as a file."""
        if self.fdtype == 6:
            if self.pipe is None:
                raise ValueError("Native pipe descriptor requires pipe_id")
        elif "pipe" in self.model_fields_set:
            raise ValueError("Only a pipe descriptor may carry pipe metadata")
        return self


class ESExec(_Record):
    target: ESProcess
    script: ESFile | None
    cwd: ESFile
    args: tuple[str, ...]
    env: tuple[str, ...]
    fds: tuple[ESFileDescriptor, ...]
    last_fd: Int32
    image_cputype: Int32
    image_cpusubtype: Int32
    dyld_exec_path: str | None = None


class ESExecV11(ESExec):
    """Reviewed v11 null, Boolean and string-array entitlement exports."""

    dyld_exec_path: str = Field(description="Required native execution path")
    entitlements: Annotated[FrozenEntitlements, Field(min_length=1, max_length=128)] | None = Field(
        description="Required null or a nonempty bounded Boolean/string-array object"
    )

    @field_validator("entitlements", mode="before")
    @classmethod
    def bounded_entitlements(cls, value: object) -> object:
        """Admit only the reviewed value types, with exact types and shared bounds."""
        return freeze_entitlements(value) if value is not None else None

    @field_serializer("entitlements")
    def native_entitlements(
        self, value: FrozenEntitlements | None
    ) -> dict[str, bool | list[str]] | None:
        """Keep the validated model immutable while preserving the native JSON object."""
        return native_entitlements(value) if value is not None else None


class ESExecEvent(_Record):
    exec: ESExecV11 | ESExec


class ESExit(_Record):
    stat: Int32 = Field(description="Raw wait status, not an already-decoded exit code")

    @classmethod
    def from_process_exit(cls, outcome: PosixProcessExit) -> Self:
        """Encode an explicit terminal result using Darwin's wait-status ABI."""
        if type(outcome) is not PosixProcessExit:
            raise ValueError("ES exit requires an explicit POSIX terminal result")
        outcome.__post_init__()
        if outcome.exit_code is not None:
            return cls(stat=outcome.exit_code << 8)
        if outcome.signal is None or outcome.signal >= 32:
            raise ValueError("ES exit signal is outside the Darwin signal range")
        return cls(stat=outcome.signal | (128 if outcome.core_dumped else 0))

    def process_exit(self) -> PosixProcessExit:
        """Decode the bounded terminal subset without altering the original record.

        Stopped/continued, reserved bits and unsupported values remain readable
        as raw native integers but cannot become canonical terminal outcomes.
        """
        status = self.stat
        if status < 0 or status > 65535:
            raise ValueError("ES wait status is outside the supported terminal subset")
        signal = status & 127
        if signal == 0 and status & 128 == 0:
            return PosixProcessExit(exit_code=status >> 8)
        if 1 <= signal < 32 and status < 256:
            return PosixProcessExit(signal=signal, core_dumped=bool(status & 128))
        raise ValueError("ES wait status does not describe a supported terminal outcome")


class ESExitEvent(_Record):
    exit: ESExit


class ESExistingDestination(_Record):
    existing_file: ESFile


class ESNewPath(_Record):
    dir: ESFile
    filename: str


class ESNewDestination(_Record):
    new_path: ESNewPath


class ESCreate(_Record):
    destination_type: Literal[0]
    destination: ESExistingDestination
    acl: None = Field(description="Only the observed null ACL representation is admitted")


class ESCreateEvent(_Record):
    create: ESCreate


class ESRenameExisting(_Record):
    source: ESFile
    destination_type: Literal[0]
    destination: ESExistingDestination


class ESRenameNew(_Record):
    source: ESFile
    destination_type: Literal[1]
    destination: ESNewDestination


class ESRenameEvent(_Record):
    rename: ESRenameExisting | ESRenameNew


class EndpointSecurityRecord(_Record):
    """Only reviewed message/event combinations, with exact wire optionality."""

    schema_version: Literal[1]
    version: Literal[6, 9, 10, 11]
    event_type: Literal[9, 11, 13, 15, 25]
    action_type: Literal[1]
    action: ESAction
    time: NativeTime
    mach_time: UInt64
    seq_num: UInt64
    global_seq_num: UInt64
    thread: ESThread
    process: ESProcess
    event: ESExecEvent | ESForkEvent | ESCreateEvent | ESExitEvent | ESRenameEvent

    @field_validator("time")
    @classmethod
    def valid_event_time(cls, value: str) -> str:
        """Keep the native time spelling after validating its calendar."""
        datetime.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def supported_profile(self) -> Self:
        """Do not silently promote a historical reference to a current-build family."""
        allowed = {6: {9, 11, 13, 25}, 9: {9, 15}, 10: {11}, 11: {9, 11, 15}}
        if self.event_type not in allowed[self.version]:
            raise ValueError("Unsupported Endpoint Security message-version/event-family pair")
        expected = {
            9: ESExecEvent,
            11: ESForkEvent,
            13: ESCreateEvent,
            15: ESExitEvent,
            25: ESRenameEvent,
        }
        if type(self.event) is not expected[self.event_type]:
            raise ValueError("Endpoint Security event tag disagrees with its payload")
        processes = [self.process]
        if isinstance(self.event, ESForkEvent):
            processes.append(self.event.fork.child)
        elif isinstance(self.event, ESExecEvent):
            processes.append(self.event.exec.target)
            if (self.version == 11) != (type(self.event.exec) is ESExecV11):
                raise ValueError("Exec entitlements presence disagrees with the selected profile")
            has_dyld = "dyld_exec_path" in self.event.exec.model_fields_set
            if (self.version == 6 and has_dyld) or (self.version in {9, 11} and not has_dyld):
                raise ValueError("Exec dyld path presence disagrees with the selected profile")
            if has_dyld and self.event.exec.dyld_exec_path is None:
                raise ValueError("The selected exec profile requires a string dyld path")
        for process in processes:
            for token in (
                process.audit_token,
                process.parent_audit_token,
                process.responsible_audit_token,
            ):
                if (self.version == 10) != isinstance(token, tuple):
                    raise ValueError("Audit-token representation disagrees with message version")
            has_category = "cs_validation_category" in process.model_fields_set
            if (self.version in {10, 11}) != has_category:
                raise ValueError("Code-signing category presence disagrees with message version")
            if has_category and process.cs_validation_category is None:
                raise ValueError("The selected process profile requires a numeric signing category")
        return self

    def to_ndjson(self) -> str:
        """Serialize only the observed fields; never synthesize identities or defaults."""
        return self.model_dump_json(exclude_unset=True) + "\n"


def decode_endpoint_security_record(raw: str) -> EndpointSecurityRecord:
    """Decode one bounded notification profile; unknown families remain unavailable."""
    return EndpointSecurityRecord.model_validate_json(raw)

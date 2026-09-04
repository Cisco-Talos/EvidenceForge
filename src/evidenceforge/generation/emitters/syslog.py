# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Syslog emitter for Linux system logs.

Most rows render an authored :class:`SyslogContext`. Protocol-owned Samba
occurrences are projected here so their messages stay source-native while the
canonical SMB/auth contexts retain shared correlation truth.
"""

import hashlib
import heapq
import json
import os
import re
import stat
import tempfile
from bisect import bisect_right
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock, get_ident
from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.contexts import HostContext
from evidenceforge.formats.format_def import FormatDefinition
from evidenceforge.generation.activity.smb_profiles import (
    get_samba_audit_operation,
    samba_audit_enabled,
)
from evidenceforge.generation.emitters.base import (
    ExactPublicationError,
    ExactPublicationKey,
    ExactPublicationParticipantKey,
    exact_publication_attempt_active,
    stage_exact_publication_row,
)
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.generation.emitters.syslog_family import (
    bounded_syslog_int,
    coerce_syslog_datetime,
    make_syslog_family_route_key,
    render_rfc3164_syslog,
    render_rfc5424_syslog,
    rfc3164_sort_key,
    sanitize_syslog_family_route_key,
    syslog_family_writer_path,
    syslog_priority,
    syslog_route_source,
    syslog_route_year,
)
from evidenceforge.generation.identity import default_linux_uid_for_user
from evidenceforge.output_targets import OutputTarget, normalize_output_target
from evidenceforge.utils.rng import _stable_seed

_LOGIND_NEW_SESSION_RE = re.compile(
    r"(?P<prefix>\bsystemd-logind(?:\[(?P<pid_bracket>\d+)\]:|"
    r"\s+(?P<pid_token>\d+)\s+\S+\s+\S+)\s+New session )"
    r"(?P<session>\d+)(?P<suffix> of user .*)"
)
_LOGIND_REMOVED_SESSION_RE = re.compile(
    r"(?P<prefix>\bsystemd-logind(?:\[(?P<pid_bracket>\d+)\]:|"
    r"\s+(?P<pid_token>\d+)\s+\S+\s+\S+)\s+Removed session )"
    r"(?P<session>\d+)(?P<suffix>\.)"
)
_RFC5424_LOGIND_NEW_SESSION_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"systemd-logind\s+"
    r"(?P<pid>\S+)\s+-\s+-\s+"
    r"New session (?P<session>\d+) of user (?P<user>[A-Za-z0-9_.-]+)\.$"
)
_RFC5424_PAM_OPEN_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<pid>\S+)\s+-\s+-\s+"
    r"pam_unix\((?P<service>[^:]+):session\): session opened for user "
    r"(?P<user>[A-Za-z0-9_.-]+)\(uid=(?P<uid>\d+)\)"
)
_KERNEL_UPTIME_RE = re.compile(
    r"(?P<prefix>\bkernel(?:\[\d+\])?(?::|\s+-\s+-\s+-)\s+\[)"
    r"(?P<uptime>\d+\.\d{6})"
    r"(?P<suffix>\])"
)
_MAX_LOGIND_SESSION_ID_DIGITS = 18
_PAM_OPEN_VISIBLE_WINDOW = timedelta(seconds=20)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_IO_CHUNK_BYTES = 1024 * 1024
_DEFAULT_SPOOL_RECORD_BYTE_CAPACITY = 16 * 1024 * 1024
_DEFAULT_SPOOL_ROUTE_BYTE_CAPACITY = 16 * 1024 * 1024 * 1024
_DEFAULT_SPOOL_ROUTE_ROW_CAPACITY = 10_000_000
_DEFAULT_TERMINAL_HOST_ROW_CAPACITY = 1_000_000
_DEFAULT_TERMINAL_HOST_BYTE_CAPACITY = 4 * 1024 * 1024 * 1024
_DEFAULT_TERMINAL_HOST_CAPACITY = 1_000_000
_DEFAULT_TERMINAL_MERGE_FAN_IN = 16
_SPOOL_EXTENT_HEADER_BYTE_CAPACITY = 16 * 1024


def _parse_rfc5424_timestamp(value: str) -> Any:
    """Parse an RFC5424 timestamp string into a datetime-like object."""
    return coerce_syslog_datetime(value.replace("Z", "+00:00"))


def _format_rfc5424_timestamp(value: Any) -> str:
    """Format a datetime-like value as the project's RFC5424 UTC timestamp."""
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _fallback_linux_uid(user: str) -> int:
    """Return a source-native fallback UID for a syslog-only PAM backfill."""
    return default_linux_uid_for_user(user)


def _fallback_linux_uid_for_host(host_key: str, user: str) -> int:
    """Return a stable UID for a syslog-only PAM row on one host."""
    return default_linux_uid_for_user(user, host=host_key)


def _linux_uid_collision_repaired(lines: list[str], host_key: str) -> list[str]:
    """Repair fallback PAM UIDs so default and named users do not collide."""
    seen_users_by_uid: dict[int, set[str]] = {}
    parsed: list[re.Match[str] | None] = []
    for line in lines:
        match = _RFC5424_PAM_OPEN_RE.match(line)
        parsed.append(match)
        if match is None:
            continue
        uid = int(match.group("uid"))
        seen_users_by_uid.setdefault(uid, set()).add(match.group("user"))

    collision_uids = {
        uid
        for uid, users in seen_users_by_uid.items()
        if len(users) > 1 and any(user not in {"root", "ubuntu", "ec2-user"} for user in users)
    }
    if not collision_uids:
        return lines

    normalized: list[str] = []
    for line, match in zip(lines, parsed, strict=True):
        if match is None:
            normalized.append(line)
            continue
        user = match.group("user")
        uid = int(match.group("uid"))
        if uid not in collision_uids or user in {"root", "ubuntu", "ec2-user"}:
            normalized.append(line)
            continue
        repaired_uid = _fallback_linux_uid_for_host(host_key, user)
        normalized.append(line[: match.start("uid")] + str(repaired_uid) + line[match.end("uid") :])
    return normalized


def _parse_logind_session_id(value: str) -> int | None:
    """Parse bounded systemd-logind session IDs without triggering huge-int failures."""
    if len(value) > _MAX_LOGIND_SESSION_ID_DIGITS:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _ssh_lifecycle_priority(line: str) -> int:
    """Order same-second SSH lifecycle messages after timestamp precision is lost."""
    if " sshd " not in line and " sshd[" not in line:
        return 50
    if "Connection from " in line:
        return 10
    if "Accepted " in line or "Failed " in line:
        return 20
    if "pam_unix(sshd:session): session opened" in line:
        return 30
    return 50


def _systemd_lifecycle_priority(line: str) -> int:
    """Order same-second systemd unit lifecycle messages after second-precision render."""
    if (" systemd " not in line and " systemd[" not in line) or ".service" not in line:
        return 50
    if " Starting " in line:
        return 10
    if " Started " in line:
        return 20
    if " Stopping " in line:
        return 30
    if " Stopped " in line or " Finished " in line:
        return 40
    return 50


def _dhclient_lifecycle_priority(line: str) -> int:
    """Order same-second DHCP client messages after timestamp precision is lost."""
    if " dhclient " not in line and " dhclient[" not in line:
        return 50
    if " DHCPDISCOVER " in line:
        return 10
    if " DHCPOFFER " in line:
        return 20
    if " DHCPREQUEST " in line:
        return 30
    if " DHCPACK " in line:
        return 40
    if " bound to " in line:
        return 50
    return 60


def _logind_pid(match: re.Match[str]) -> str:
    """Return a logind PID from either RFC3164 or legacy RFC5424-ish rendering."""
    return match.group("pid_bracket") or match.group("pid_token")


def _syslog_sort_key(line: str) -> tuple[int, int, int, int, int, int, str]:
    """Sort RFC3164 syslog lines by timestamp plus same-time lifecycle order."""
    lifecycle_priority = min(
        _ssh_lifecycle_priority(line),
        _systemd_lifecycle_priority(line),
        _dhclient_lifecycle_priority(line),
    )
    return rfc3164_sort_key(line, lifecycle_priority)


_RFC5424_TS_RE = re.compile(r"^<\d{1,3}>1\s+(?P<timestamp>\S+)")
_RFC5424_LINE_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app_name>\S+)\s+"
    r"(?P<pid>\S+)\s+-\s+-\s+"
    r"(?P<message>.*)$"
)


def _rfc5424_syslog_sort_key(line: str) -> tuple[Any, int, str]:
    """Sort RFC5424 syslog lines by full timestamp plus lifecycle order."""
    lifecycle_priority = min(
        _ssh_lifecycle_priority(line),
        _systemd_lifecycle_priority(line),
        _dhclient_lifecycle_priority(line),
    )
    match = _RFC5424_TS_RE.match(line)
    timestamp = (
        _parse_rfc5424_timestamp(match.group("timestamp"))
        if match is not None
        else coerce_syslog_datetime(datetime.min)
    )
    return (timestamp, lifecycle_priority, line)


def _replace_rfc5424_timestamp(line: str, timestamp: Any) -> str:
    """Return ``line`` with its RFC5424 timestamp replaced."""
    parts = line.split(maxsplit=2)
    if len(parts) != 3:
        return line
    return f"{parts[0]} {_format_rfc5424_timestamp(timestamp)} {parts[2]}"


class _RoutedSyslogLine(str):
    """One logical record retaining source ownership behind a physical writer."""

    _logical_route_key: str

    def __new__(cls, value: str, logical_route_key: str) -> "_RoutedSyslogLine":
        instance = super().__new__(cls, value)
        instance._logical_route_key = logical_route_key
        return instance


class _ExactSyslogLine(_RoutedSyslogLine):
    """One immutable exact candidate retained in a legacy record buffer."""

    _exact_key: ExactPublicationKey

    def __new__(
        cls,
        value: str,
        logical_route_key: str,
        key: ExactPublicationKey,
    ) -> "_ExactSyslogLine":
        instance = super().__new__(cls, value, logical_route_key)
        instance._exact_key = key
        return instance


@dataclass(slots=True)
class _ExactSyslogReservation:
    """Capacity reserved during exact rendering before canonical mutation."""

    digest: str
    retained_bytes: int
    capacity_bytes: int


@dataclass(slots=True)
class _ExactSyslogCandidate:
    """One admitted source record retained until terminal normalization."""

    digest: str
    frozen: str
    writer_route_key: str
    logical_route_key: str
    marker: _ExactSyslogLine
    capacity_bytes: int
    installed: bool = False
    released: bool = False


@dataclass(slots=True)
class _SyslogFinalCandidate:
    """One anonymous normalized route payload retained across close retries."""

    route_key: str
    writer: object
    output_path: Path
    stream: Any
    candidate_identity: tuple[int, int]
    digest: str
    payload_bytes: int
    close_started: bool = False


@dataclass(frozen=True, slots=True)
class _SyslogPublicProof:
    """Authenticated public bytes retained after private-candidate retirement."""

    writer: object
    output_path: Path
    parent_identity: tuple[int, int]
    file_identity: tuple[int, int] | None
    digest: str
    payload_bytes: int


@dataclass(slots=True)
class _SyslogDescriptorOwner:
    """Slotted primary/guard state; registry helpers are its only access path."""

    descriptor: int | None = None
    guard_descriptor: int | None = None
    identity: tuple[int, int] | None = None
    closed: bool = False
    retirement_started: bool = False
    lease_descriptors: dict[str, int] = field(default_factory=dict, repr=False)
    lock: Any = field(default_factory=Lock, repr=False)


@dataclass(frozen=True, slots=True)
class _SyslogSecurityRegistry:
    """Closed registry of every live capability used by exact Syslog storage."""

    os_module: Any
    path_module: Any
    stat_module: Any
    tempfile_module: Any
    hashlib_module: Any
    json_module: Any
    temporary_file: Callable[..., Any]
    temporary_file_code: object
    temporary_mkstemp_inner: object
    stream_type: type[Any]
    stream_namespace: tuple[tuple[str, object], ...]
    stream_fileno: Callable[[Any], int]
    stream_close: Callable[[Any], None]
    stream_flush: Callable[[Any], None]
    stream_closed: object
    os_open: Callable[..., int]
    os_dup: Callable[[int], int]
    os_close: Callable[[int], None]
    os_fstat: Callable[[int], os.stat_result]
    os_stat: Callable[..., os.stat_result]
    os_mkdir: Callable[..., None]
    os_pread: Callable[[int, int, int], bytes] | None
    os_read: Callable[[int, int], bytes]
    os_write: Callable[[int, bytes | memoryview], int]
    os_lseek: Callable[[int, int, int], int]
    os_fsync: Callable[[int], None]
    os_get_inheritable: Callable[[int], bool]
    os_get_blocking: Callable[[int], bool]
    os_set_blocking: Callable[[int, bool], None]
    os_geteuid: Callable[[], int] | None
    os_abspath: Callable[[Any], str]
    supports_dir_fd: object
    supports_dir_fd_values: frozenset[object]
    supports_fd: object
    supports_fd_values: frozenset[object]
    supports_follow_symlinks: object
    supports_follow_symlinks_values: frozenset[object]
    nofollow: int
    directory: int
    o_rdonly: int
    o_rdwr: int
    o_creat: int
    o_excl: int
    seek_set: int
    seek_cur: int
    path_separator: str
    private_directory_mode: int
    private_file_mode: int
    stat_isreg: Callable[[int], bool]
    stat_isdir: Callable[[int], bool]
    stat_islnk: Callable[[int], bool]
    stat_imode: Callable[[int], int]
    sha256: Callable[..., Any]
    json_loads: Callable[..., Any]
    json_dumps: Callable[..., str]
    owner_type: type[_SyslogDescriptorOwner]
    owner_namespace: tuple[tuple[str, object], ...]
    owner_descriptor_slot: object
    owner_guard_descriptor_slot: object
    owner_identity_slot: object
    owner_closed_slot: object
    owner_retirement_started_slot: object
    owner_lease_descriptors_slot: object
    owner_lock_slot: object
    lock_type: type[Any]
    lock_namespace: tuple[tuple[str, object], ...]
    lock_acquire: Callable[..., bool]
    lock_release: Callable[..., None]


def _make_security_registry() -> tuple[
    _SyslogSecurityRegistry,
    Callable[[_SyslogSecurityRegistry], _SyslogSecurityRegistry],
]:
    """Capture one independently attested exact-storage capability registry."""

    trusted_os = os
    trusted_path = os.path
    trusted_stat = stat
    trusted_tempfile = tempfile
    trusted_hashlib = hashlib
    trusted_json = json
    module_namespace = globals()
    trusted_factory = tempfile.TemporaryFile
    trusted_factory_code = trusted_factory.__code__
    trusted_mkstemp_inner = tempfile._mkstemp_inner
    prototype = trusted_factory(mode="w+b")
    stream_type = type(prototype)
    stream_fileno = stream_type.fileno
    stream_close = stream_type.close
    stream_flush = stream_type.flush
    stream_closed = stream_type.closed
    stream_namespace = tuple(vars(stream_type).items())
    stream_close(prototype)

    owner_type = _SyslogDescriptorOwner
    owner_namespace = tuple(vars(owner_type).items())
    owner_descriptor_slot = vars(owner_type)["descriptor"]
    owner_guard_descriptor_slot = vars(owner_type)["guard_descriptor"]
    owner_identity_slot = vars(owner_type)["identity"]
    owner_closed_slot = vars(owner_type)["closed"]
    owner_retirement_started_slot = vars(owner_type)["retirement_started"]
    owner_lease_descriptors_slot = vars(owner_type)["lease_descriptors"]
    owner_lock_slot = vars(owner_type)["lock"]
    owner_prototype = owner_type()
    lock = owner_lock_slot.__get__(owner_prototype, owner_type)
    lock_type = type(lock)
    lock_namespace = tuple(vars(lock_type).items())
    lock_acquire = lock_type.acquire
    lock_release = lock_type.release

    registry = _SyslogSecurityRegistry(
        os_module=trusted_os,
        path_module=trusted_path,
        stat_module=trusted_stat,
        tempfile_module=trusted_tempfile,
        hashlib_module=trusted_hashlib,
        json_module=trusted_json,
        temporary_file=trusted_factory,
        temporary_file_code=trusted_factory_code,
        temporary_mkstemp_inner=trusted_mkstemp_inner,
        stream_type=stream_type,
        stream_namespace=stream_namespace,
        stream_fileno=stream_fileno,
        stream_close=stream_close,
        stream_flush=stream_flush,
        stream_closed=stream_closed,
        os_open=trusted_os.open,
        os_dup=trusted_os.dup,
        os_close=trusted_os.close,
        os_fstat=trusted_os.fstat,
        os_stat=trusted_os.stat,
        os_mkdir=trusted_os.mkdir,
        os_pread=getattr(trusted_os, "pread", None),
        os_read=trusted_os.read,
        os_write=trusted_os.write,
        os_lseek=trusted_os.lseek,
        os_fsync=trusted_os.fsync,
        os_get_inheritable=trusted_os.get_inheritable,
        os_get_blocking=trusted_os.get_blocking,
        os_set_blocking=trusted_os.set_blocking,
        os_geteuid=getattr(trusted_os, "geteuid", None),
        os_abspath=trusted_path.abspath,
        supports_dir_fd=trusted_os.supports_dir_fd,
        supports_dir_fd_values=frozenset(trusted_os.supports_dir_fd),
        supports_fd=trusted_os.supports_fd,
        supports_fd_values=frozenset(trusted_os.supports_fd),
        supports_follow_symlinks=trusted_os.supports_follow_symlinks,
        supports_follow_symlinks_values=frozenset(trusted_os.supports_follow_symlinks),
        nofollow=_NOFOLLOW,
        directory=_DIRECTORY,
        o_rdonly=trusted_os.O_RDONLY,
        o_rdwr=trusted_os.O_RDWR,
        o_creat=trusted_os.O_CREAT,
        o_excl=trusted_os.O_EXCL,
        seek_set=trusted_os.SEEK_SET,
        seek_cur=trusted_os.SEEK_CUR,
        path_separator=trusted_os.sep,
        private_directory_mode=_PRIVATE_DIRECTORY_MODE,
        private_file_mode=_PRIVATE_FILE_MODE,
        stat_isreg=trusted_stat.S_ISREG,
        stat_isdir=trusted_stat.S_ISDIR,
        stat_islnk=trusted_stat.S_ISLNK,
        stat_imode=trusted_stat.S_IMODE,
        sha256=trusted_hashlib.sha256,
        json_loads=trusted_json.loads,
        json_dumps=trusted_json.dumps,
        owner_type=owner_type,
        owner_namespace=owner_namespace,
        owner_descriptor_slot=owner_descriptor_slot,
        owner_guard_descriptor_slot=owner_guard_descriptor_slot,
        owner_identity_slot=owner_identity_slot,
        owner_closed_slot=owner_closed_slot,
        owner_retirement_started_slot=owner_retirement_started_slot,
        owner_lease_descriptors_slot=owner_lease_descriptors_slot,
        owner_lock_slot=owner_lock_slot,
        lock_type=lock_type,
        lock_namespace=lock_namespace,
        lock_acquire=lock_acquire,
        lock_release=lock_release,
    )
    registry_type = type(registry)
    registry_namespace = tuple(vars(registry_type).items())

    def namespace_is_exact(subject: type[Any], expected: tuple[tuple[str, object], ...]) -> bool:
        current = vars(subject)
        return len(current) == len(expected) and all(
            current.get(name) is value for name, value in expected
        )

    def attest(candidate: _SyslogSecurityRegistry) -> _SyslogSecurityRegistry:
        if candidate is not registry:
            raise ExactPublicationError("Syslog registry belongs to another emitter authority")
        return candidate

        try:
            current_dir_fd_values = (
                frozenset(trusted_os.supports_dir_fd)
                if trusted_os.supports_dir_fd is registry.supports_dir_fd
                else None
            )
            current_fd_values = (
                frozenset(trusted_os.supports_fd)
                if trusted_os.supports_fd is registry.supports_fd
                else None
            )
            current_follow_values = (
                frozenset(trusted_os.supports_follow_symlinks)
                if trusted_os.supports_follow_symlinks is registry.supports_follow_symlinks
                else None
            )
        except (RuntimeError, TypeError, ValueError) as error:
            raise ExactPublicationError("Syslog security boundary changed") from error
        if (
            candidate is not registry
            or type(candidate) is not registry_type
            or not namespace_is_exact(registry_type, registry_namespace)
            or module_namespace.get("_SyslogSecurityRegistry") is not registry_type
            or module_namespace.get("_SYSLOG_SECURITY_REGISTRY") is not registry
            or module_namespace.get("_SYSLOG_SECURITY_ATTESTATION") is not attest
            or registry.os_module is not trusted_os
            or registry.path_module is not trusted_path
            or registry.stat_module is not trusted_stat
            or registry.tempfile_module is not trusted_tempfile
            or registry.hashlib_module is not trusted_hashlib
            or registry.json_module is not trusted_json
            or os is not trusted_os
            or os.path is not trusted_path
            or stat is not trusted_stat
            or tempfile is not trusted_tempfile
            or hashlib is not trusted_hashlib
            or json is not trusted_json
            or trusted_tempfile.TemporaryFile is not registry.temporary_file
            or getattr(trusted_tempfile.TemporaryFile, "__code__", None)
            is not registry.temporary_file_code
            or getattr(trusted_tempfile, "_mkstemp_inner", None)
            is not registry.temporary_mkstemp_inner
            or trusted_os.open is not registry.os_open
            or trusted_os.dup is not registry.os_dup
            or trusted_os.close is not registry.os_close
            or trusted_os.fstat is not registry.os_fstat
            or trusted_os.stat is not registry.os_stat
            or trusted_os.mkdir is not registry.os_mkdir
            or getattr(trusted_os, "pread", None) is not registry.os_pread
            or trusted_os.read is not registry.os_read
            or trusted_os.write is not registry.os_write
            or trusted_os.lseek is not registry.os_lseek
            or trusted_os.fsync is not registry.os_fsync
            or trusted_os.get_inheritable is not registry.os_get_inheritable
            or trusted_os.get_blocking is not registry.os_get_blocking
            or trusted_os.set_blocking is not registry.os_set_blocking
            or getattr(trusted_os, "geteuid", None) is not registry.os_geteuid
            or trusted_path.abspath is not registry.os_abspath
            or trusted_os.supports_dir_fd is not registry.supports_dir_fd
            or type(registry.supports_dir_fd_values) is not frozenset
            or current_dir_fd_values != registry.supports_dir_fd_values
            or trusted_os.supports_fd is not registry.supports_fd
            or type(registry.supports_fd_values) is not frozenset
            or current_fd_values != registry.supports_fd_values
            or trusted_os.supports_follow_symlinks is not registry.supports_follow_symlinks
            or type(registry.supports_follow_symlinks_values) is not frozenset
            or current_follow_values != registry.supports_follow_symlinks_values
            or type(_NOFOLLOW) is not int
            or type(registry.nofollow) is not int
            or _NOFOLLOW != registry.nofollow
            or type(_DIRECTORY) is not int
            or type(registry.directory) is not int
            or _DIRECTORY != registry.directory
            or type(getattr(trusted_os, "O_NOFOLLOW", 0)) is not int
            or getattr(trusted_os, "O_NOFOLLOW", 0) != registry.nofollow
            or type(getattr(trusted_os, "O_DIRECTORY", 0)) is not int
            or getattr(trusted_os, "O_DIRECTORY", 0) != registry.directory
            or type(trusted_os.O_RDONLY) is not int
            or type(registry.o_rdonly) is not int
            or trusted_os.O_RDONLY != registry.o_rdonly
            or type(trusted_os.O_RDWR) is not int
            or type(registry.o_rdwr) is not int
            or trusted_os.O_RDWR != registry.o_rdwr
            or type(trusted_os.O_CREAT) is not int
            or type(registry.o_creat) is not int
            or trusted_os.O_CREAT != registry.o_creat
            or type(trusted_os.O_EXCL) is not int
            or type(registry.o_excl) is not int
            or trusted_os.O_EXCL != registry.o_excl
            or type(trusted_os.SEEK_SET) is not int
            or type(registry.seek_set) is not int
            or trusted_os.SEEK_SET != registry.seek_set
            or type(trusted_os.SEEK_CUR) is not int
            or type(registry.seek_cur) is not int
            or trusted_os.SEEK_CUR != registry.seek_cur
            or type(trusted_os.sep) is not str
            or type(registry.path_separator) is not str
            or trusted_os.sep != registry.path_separator
            or type(_PRIVATE_DIRECTORY_MODE) is not int
            or type(registry.private_directory_mode) is not int
            or _PRIVATE_DIRECTORY_MODE != registry.private_directory_mode
            or type(_PRIVATE_FILE_MODE) is not int
            or type(registry.private_file_mode) is not int
            or _PRIVATE_FILE_MODE != registry.private_file_mode
            or trusted_stat.S_ISREG is not registry.stat_isreg
            or trusted_stat.S_ISDIR is not registry.stat_isdir
            or trusted_stat.S_ISLNK is not registry.stat_islnk
            or trusted_stat.S_IMODE is not registry.stat_imode
            or trusted_hashlib.sha256 is not registry.sha256
            or trusted_json.loads is not registry.json_loads
            or trusted_json.dumps is not registry.json_dumps
            or not namespace_is_exact(stream_type, registry.stream_namespace)
            or stream_type.fileno is not registry.stream_fileno
            or stream_type.close is not registry.stream_close
            or stream_type.flush is not registry.stream_flush
            or stream_type.closed is not registry.stream_closed
            or registry.stream_type is not stream_type
            or registry.owner_type is not owner_type
            or _SyslogDescriptorOwner is not owner_type
            or not namespace_is_exact(owner_type, registry.owner_namespace)
            or vars(owner_type).get("descriptor") is not registry.owner_descriptor_slot
            or vars(owner_type).get("guard_descriptor") is not registry.owner_guard_descriptor_slot
            or vars(owner_type).get("identity") is not registry.owner_identity_slot
            or vars(owner_type).get("closed") is not registry.owner_closed_slot
            or vars(owner_type).get("retirement_started")
            is not registry.owner_retirement_started_slot
            or vars(owner_type).get("lease_descriptors")
            is not registry.owner_lease_descriptors_slot
            or vars(owner_type).get("lock") is not registry.owner_lock_slot
            or registry.lock_type is not lock_type
            or not namespace_is_exact(lock_type, registry.lock_namespace)
            or lock_type.acquire is not registry.lock_acquire
            or lock_type.release is not registry.lock_release
        ):
            raise ExactPublicationError("Syslog security boundary changed")
        return registry

    return registry, attest


_SYSLOG_SECURITY_REGISTRY, _SYSLOG_SECURITY_ATTESTATION = _make_security_registry()


def _security_boundary(
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
) -> _SyslogSecurityRegistry:
    """Return the trusted process-local filesystem operation registry."""

    del _attest
    return _registry


def _stream_descriptor(
    stream: Any,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _stream_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.stream_type,
    _fileno: Callable[[Any], int] = _SYSLOG_SECURITY_REGISTRY.stream_fileno,
) -> int:
    descriptor = _fileno(stream)
    if type(descriptor) is not int or descriptor < 0:
        raise ExactPublicationError("Syslog stream returned an invalid descriptor")
    return descriptor


def _stream_is_closed(
    stream: Any,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _stream_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.stream_type,
    _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.stream_closed,
) -> bool:
    return bool(_closed_slot.__get__(stream, _stream_type))


def _stream_flush(
    stream: Any,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _stream_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.stream_type,
    _flush: Callable[[Any], None] = _SYSLOG_SECURITY_REGISTRY.stream_flush,
) -> None:
    _flush(stream)


def _stream_close(
    stream: Any,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _stream_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.stream_type,
    _close: Callable[[Any], None] = _SYSLOG_SECURITY_REGISTRY.stream_close,
) -> None:
    _close(stream)


def _secure_open(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., int] = _SYSLOG_SECURITY_REGISTRY.os_open,
    **kwargs: Any,
) -> int:
    return _operation(*args, **kwargs)


def _secure_dup(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], int] = _SYSLOG_SECURITY_REGISTRY.os_dup,
) -> int:
    return _operation(descriptor)


def _secure_close(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], None] = _SYSLOG_SECURITY_REGISTRY.os_close,
) -> None:
    _operation(descriptor)


def _secure_fstat(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_fstat,
) -> os.stat_result:
    return _operation(descriptor)


def _secure_stat(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_stat,
    **kwargs: Any,
) -> os.stat_result:
    return _operation(*args, **kwargs)


def _secure_mkdir(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.os_mkdir,
    **kwargs: Any,
) -> None:
    _operation(*args, **kwargs)


def _secure_pread(
    descriptor: int,
    count: int,
    offset: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int, int, int], bytes] | None = _SYSLOG_SECURITY_REGISTRY.os_pread,
) -> bytes:
    if _operation is None:
        raise ExactPublicationError("Syslog exact publication requires descriptor pread")
    return _operation(descriptor, count, offset)


def _secure_read(
    descriptor: int,
    count: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int, int], bytes] = _SYSLOG_SECURITY_REGISTRY.os_read,
) -> bytes:
    return _operation(descriptor, count)


def _secure_write(
    descriptor: int,
    payload: bytes | memoryview,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int, bytes], int] = _SYSLOG_SECURITY_REGISTRY.os_write,
) -> int:
    return _operation(descriptor, payload)


def _secure_lseek(
    descriptor: int,
    offset: int,
    whence: int = _SYSLOG_SECURITY_REGISTRY.seek_set,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int, int, int], int] = _SYSLOG_SECURITY_REGISTRY.os_lseek,
) -> int:
    return _operation(descriptor, offset, whence)


def _secure_fsync(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], None] = _SYSLOG_SECURITY_REGISTRY.os_fsync,
) -> None:
    _operation(descriptor)


def _secure_get_inheritable(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.os_get_inheritable,
) -> bool:
    return _operation(descriptor)


def _secure_get_blocking(
    descriptor: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.os_get_blocking,
) -> bool:
    return _operation(descriptor)


def _secure_set_blocking(
    descriptor: int,
    blocking: bool,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int, bool], None] = _SYSLOG_SECURITY_REGISTRY.os_set_blocking,
) -> None:
    _operation(descriptor, blocking)


def _same_open_description(
    first: int,
    second: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _get_blocking: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.os_get_blocking,
    _set_blocking: Callable[[int, bool], None] = _SYSLOG_SECURITY_REGISTRY.os_set_blocking,
) -> bool:
    """Check whether two descriptors share one open description."""

    original = _get_blocking(first)
    if _get_blocking(second) is not original:
        return False
    _set_blocking(first, not original)
    try:
        return _get_blocking(second) is not original
    finally:
        _set_blocking(first, original)


def _secure_geteuid(
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[], int] | None = _SYSLOG_SECURITY_REGISTRY.os_geteuid,
) -> int | None:
    return None if _operation is None else _operation()


def _secure_abspath(
    path: Any,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[Any], str] = _SYSLOG_SECURITY_REGISTRY.os_abspath,
) -> str:
    return _operation(path)


def _secure_isreg(
    mode: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.stat_isreg,
) -> bool:
    return _operation(mode)


def _secure_isdir(
    mode: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.stat_isdir,
) -> bool:
    return _operation(mode)


def _secure_islnk(
    mode: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.stat_islnk,
) -> bool:
    return _operation(mode)


def _secure_imode(
    mode: int,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[[int], int] = _SYSLOG_SECURITY_REGISTRY.stat_imode,
) -> int:
    return _operation(mode)


def _secure_sha256(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., Any] = _SYSLOG_SECURITY_REGISTRY.sha256,
    **kwargs: Any,
) -> Any:
    return _operation(*args, **kwargs)


def _secure_json_loads(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., Any] = _SYSLOG_SECURITY_REGISTRY.json_loads,
    **kwargs: Any,
) -> Any:
    return _operation(*args, **kwargs)


def _secure_json_dumps(
    *args: Any,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _operation: Callable[..., str] = _SYSLOG_SECURITY_REGISTRY.json_dumps,
    **kwargs: Any,
) -> str:
    return _operation(*args, **kwargs)


def _new_temporary_stream(
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _factory: Callable[..., Any] = _SYSLOG_SECURITY_REGISTRY.temporary_file,
    _stream_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.stream_type,
    _close: Callable[[Any], None] = _SYSLOG_SECURITY_REGISTRY.stream_close,
) -> Any:
    """Create the trusted process-local temporary stream."""

    return _factory(mode="w+b")


def _descriptor_owner_snapshot(
    owner: object,
    *,
    label: str,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
    _descriptor_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_descriptor_slot,
    _guard_descriptor_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_guard_descriptor_slot),
    _identity_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_identity_slot,
    _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_closed_slot,
    _retirement_started_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_retirement_started_slot),
    _lease_descriptors_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_lease_descriptors_slot),
    _lock_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_lock_slot,
    _lock_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.lock_type,
    _acquire: Callable[..., bool] = _SYSLOG_SECURITY_REGISTRY.lock_acquire,
    _release: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.lock_release,
    _fstat: Callable[[int], os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_fstat,
    _get_blocking: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.os_get_blocking,
    _set_blocking: Callable[[int, bool], None] = (_SYSLOG_SECURITY_REGISTRY.os_set_blocking),
) -> tuple[int, tuple[int, int]]:
    """Lease one authenticated primary while its private guard proves the open description."""

    if type(owner) is not _owner_type:
        raise ExactPublicationError(f"Syslog {label} owner type changed")
    lock = _lock_slot.__get__(owner, _owner_type)
    if type(lock) is not _lock_type:
        raise ExactPublicationError(f"Syslog {label} owner lock changed")
    _acquire(lock)
    try:
        descriptor = _descriptor_slot.__get__(owner, _owner_type)
        guard_descriptor = _guard_descriptor_slot.__get__(owner, _owner_type)
        identity = _identity_slot.__get__(owner, _owner_type)
        closed = _closed_slot.__get__(owner, _owner_type)
        retirement_started = _retirement_started_slot.__get__(owner, _owner_type)
        lease_descriptors = _lease_descriptors_slot.__get__(owner, _owner_type)
        if (
            type(closed) is not bool
            or closed
            or type(retirement_started) is not bool
            or retirement_started
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor owner is not open")
        if (
            type(descriptor) is not int
            or descriptor < 0
            or type(guard_descriptor) is not int
            or guard_descriptor < 0
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        if descriptor == guard_descriptor:
            raise ExactPublicationError(f"Syslog {label} has a duplicate descriptor lease")
        if (
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(part) is not int for part in identity)
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        if type(lease_descriptors) is not dict or lease_descriptors != {
            "primary": descriptor,
            "guard": guard_descriptor,
        }:
            raise ExactPublicationError(f"Syslog {label} descriptor lease map changed")
        try:
            metadata = _fstat(descriptor)
            guard_metadata = _fstat(guard_descriptor)
        except OSError as error:
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed") from error
        if (int(metadata.st_dev), int(metadata.st_ino)) != identity or (
            int(guard_metadata.st_dev),
            int(guard_metadata.st_ino),
        ) != identity:
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        blocking = _get_blocking(descriptor)
        if type(blocking) is not bool or _get_blocking(guard_descriptor) is not blocking:
            raise ExactPublicationError(f"Syslog {label} open-description ownership changed")
        _set_blocking(descriptor, not blocking)
        try:
            if _get_blocking(guard_descriptor) is blocking:
                raise ExactPublicationError(f"Syslog {label} open-description ownership changed")
        finally:
            _set_blocking(descriptor, blocking)
            if (
                _get_blocking(descriptor) is not blocking
                or _get_blocking(guard_descriptor) is not blocking
            ):
                raise ExactPublicationError(
                    f"Syslog {label} open-description flags were not restored"
                )
    finally:
        _release(lock)
    return descriptor, identity


def _new_descriptor_owner(
    descriptor: int | None = None,
    identity: tuple[int, int] | None = None,
    *,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
) -> _SyslogDescriptorOwner:
    """Construct one bounded primary/guard owner from a freshly opened descriptor."""

    if (descriptor is None) != (identity is None):
        raise ExactPublicationError("Syslog descriptor owner state is incomplete")
    if descriptor is None:
        return _owner_type()
    if type(descriptor) is not int or descriptor < 0:
        raise ExactPublicationError("Syslog descriptor owner state is invalid")
    if (
        type(identity) is not tuple
        or len(identity) != 2
        or any(type(part) is not int for part in identity)
    ):
        raise ExactPublicationError("Syslog descriptor owner state is invalid")
    metadata = _secure_fstat(descriptor)
    if (int(metadata.st_dev), int(metadata.st_ino)) != identity:
        raise ExactPublicationError("Syslog descriptor owner identity changed")
    if _secure_get_inheritable(descriptor):
        raise ExactPublicationError("Syslog descriptor owner is inheritable")
    guard_descriptor = _secure_dup(descriptor)
    try:
        if (
            type(guard_descriptor) is not int
            or guard_descriptor < 0
            or guard_descriptor == descriptor
        ):
            raise ExactPublicationError("Syslog descriptor owner guard is invalid")
        guard_metadata = _secure_fstat(guard_descriptor)
        if (
            (int(guard_metadata.st_dev), int(guard_metadata.st_ino)) != identity
            or _secure_get_inheritable(guard_descriptor)
            or not _same_open_description(descriptor, guard_descriptor)
        ):
            raise ExactPublicationError("Syslog descriptor owner guard changed")
        return _owner_type(
            descriptor=descriptor,
            guard_descriptor=guard_descriptor,
            identity=identity,
            lease_descriptors={"primary": descriptor, "guard": guard_descriptor},
        )
    except BaseException:
        _secure_close(guard_descriptor)
        raise


def _descriptor_owner_is_closed(
    owner: object,
    *,
    label: str,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
    _descriptor_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_descriptor_slot,
    _guard_descriptor_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_guard_descriptor_slot),
    _identity_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_identity_slot,
    _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_closed_slot,
    _retirement_started_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_retirement_started_slot),
    _lease_descriptors_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_lease_descriptors_slot),
    _lock_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_lock_slot,
    _lock_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.lock_type,
    _acquire: Callable[..., bool] = _SYSLOG_SECURITY_REGISTRY.lock_acquire,
    _release: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.lock_release,
) -> bool:
    """Return whether the trusted descriptor owner is retired."""

    if not isinstance(owner, _SyslogDescriptorOwner):
        raise ExactPublicationError(f"Syslog {label} owner is invalid")
    with owner.lock:
        return owner.closed


def _descriptor_owner_is_empty(
    owner: object,
    *,
    label: str,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
    _descriptor_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_descriptor_slot,
    _guard_descriptor_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_guard_descriptor_slot),
    _identity_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_identity_slot,
    _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_closed_slot,
    _retirement_started_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_retirement_started_slot),
    _lease_descriptors_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_lease_descriptors_slot),
    _lock_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_lock_slot,
    _lock_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.lock_type,
    _acquire: Callable[..., bool] = _SYSLOG_SECURITY_REGISTRY.lock_acquire,
    _release: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.lock_release,
) -> bool:
    """Return whether the trusted owner has not acquired a descriptor."""

    if not isinstance(owner, _SyslogDescriptorOwner):
        raise ExactPublicationError(f"Syslog {label} owner is invalid")
    with owner.lock:
        return bool(
            not owner.closed
            and not owner.retirement_started
            and owner.descriptor is None
            and owner.guard_descriptor is None
            and owner.identity is None
            and not owner.lease_descriptors
        )


def _retire_descriptor_owner(
    owner: object,
    *,
    label: str,
    _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
    _attest: Callable[
        [_SyslogSecurityRegistry], _SyslogSecurityRegistry
    ] = _SYSLOG_SECURITY_ATTESTATION,
    _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
    _descriptor_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_descriptor_slot,
    _guard_descriptor_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_guard_descriptor_slot),
    _identity_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_identity_slot,
    _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_closed_slot,
    _retirement_started_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_retirement_started_slot),
    _lease_descriptors_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_lease_descriptors_slot),
    _lock_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_lock_slot,
    _lock_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.lock_type,
    _acquire: Callable[..., bool] = _SYSLOG_SECURITY_REGISTRY.lock_acquire,
    _release: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.lock_release,
    _fstat: Callable[[int], os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_fstat,
    _close: Callable[[int], None] = _SYSLOG_SECURITY_REGISTRY.os_close,
    _get_blocking: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.os_get_blocking,
    _set_blocking: Callable[[int, bool], None] = (_SYSLOG_SECURITY_REGISTRY.os_set_blocking),
) -> None:
    """Retire one exact two-lease owner without touching a reused primary fd."""

    if type(owner) is not _owner_type:
        raise ExactPublicationError(f"Syslog {label} owner type changed")
    lock = _lock_slot.__get__(owner, _owner_type)
    if type(lock) is not _lock_type:
        raise ExactPublicationError(f"Syslog {label} owner lock changed")
    _acquire(lock)
    pending_error: BaseException | None = None
    try:
        descriptor = _descriptor_slot.__get__(owner, _owner_type)
        guard_descriptor = _guard_descriptor_slot.__get__(owner, _owner_type)
        identity = _identity_slot.__get__(owner, _owner_type)
        closed = _closed_slot.__get__(owner, _owner_type)
        retirement_started = _retirement_started_slot.__get__(owner, _owner_type)
        lease_descriptors = _lease_descriptors_slot.__get__(owner, _owner_type)
        if (
            type(closed) is not bool
            or type(retirement_started) is not bool
            or type(lease_descriptors) is not dict
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        if closed:
            if (
                descriptor is not None
                or guard_descriptor is not None
                or identity is not None
                or lease_descriptors
                or not retirement_started
            ):
                raise ExactPublicationError(f"Syslog {label} retirement state changed")
            return
        if descriptor is not None and descriptor == guard_descriptor:
            raise ExactPublicationError(f"Syslog {label} has a duplicate descriptor lease")
        if descriptor is not None and (type(descriptor) is not int or descriptor < 0):
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        if type(guard_descriptor) is not int or guard_descriptor < 0:
            raise ExactPublicationError(f"Syslog {label} descriptor guard changed")
        if (
            type(identity) is not tuple
            or len(identity) != 2
            or any(type(part) is not int for part in identity)
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor ownership changed")
        expected_leases = {"guard": guard_descriptor}
        if descriptor is not None:
            expected_leases["primary"] = descriptor
        if lease_descriptors != expected_leases:
            raise ExactPublicationError(f"Syslog {label} descriptor lease map changed")
        _retirement_started_slot.__set__(owner, True)
        try:
            guard_metadata = _fstat(guard_descriptor)
        except OSError as error:
            raise ExactPublicationError(f"Syslog {label} descriptor guard disappeared") from error
        if (int(guard_metadata.st_dev), int(guard_metadata.st_ino)) != identity:
            raise ExactPublicationError(f"Syslog {label} descriptor guard changed")

        if descriptor is not None:
            primary_is_owned = False
            try:
                metadata = _fstat(descriptor)
            except OSError:
                pending_error = ExactPublicationError(
                    f"Syslog {label} descriptor disappeared before retirement"
                )
            else:
                if (int(metadata.st_dev), int(metadata.st_ino)) == identity:
                    blocking = _get_blocking(descriptor)
                    if type(blocking) is bool and _get_blocking(guard_descriptor) is blocking:
                        _set_blocking(descriptor, not blocking)
                        try:
                            primary_is_owned = _get_blocking(guard_descriptor) is not blocking
                        finally:
                            _set_blocking(descriptor, blocking)
                            if (
                                _get_blocking(descriptor) is not blocking
                                or _get_blocking(guard_descriptor) is not blocking
                            ):
                                raise ExactPublicationError(
                                    f"Syslog {label} open-description flags were not restored"
                                )
                if not primary_is_owned:
                    pending_error = ExactPublicationError(
                        f"Syslog {label} open-description ownership changed"
                    )
            if primary_is_owned:
                try:
                    _close(descriptor)
                except OSError as error:
                    try:
                        metadata = _fstat(descriptor)
                    except OSError:
                        pending_error = error
                    else:
                        if (int(metadata.st_dev), int(metadata.st_ino)) == identity:
                            raise
                        pending_error = ExactPublicationError(
                            f"Syslog {label} descriptor ownership changed"
                        )
            lease_descriptors.pop("primary", None)
            _descriptor_slot.__set__(owner, None)

        try:
            _close(guard_descriptor)
        except OSError as error:
            try:
                guard_metadata = _fstat(guard_descriptor)
            except OSError:
                if pending_error is None:
                    pending_error = error
            else:
                if (int(guard_metadata.st_dev), int(guard_metadata.st_ino)) == identity:
                    if pending_error is not None:
                        raise pending_error
                    raise
                if pending_error is None:
                    pending_error = ExactPublicationError(
                        f"Syslog {label} descriptor guard changed"
                    )
        lease_descriptors.pop("guard", None)
        _guard_descriptor_slot.__set__(owner, None)
        _identity_slot.__set__(owner, None)
        _closed_slot.__set__(owner, True)
    finally:
        _release(lock)
    if pending_error is not None:
        raise pending_error


@dataclass(slots=True)
class _SyslogPublicAppend:
    """One descriptor-owned public append retained until its route is proven."""

    writer: object
    output_path: Path
    candidate: _SyslogFinalCandidate
    parent_owner: _SyslogDescriptorOwner | None
    parent_identity: tuple[int, int]
    descriptor_owner: _SyslogDescriptorOwner
    file_identity: tuple[int, int] | None
    digest: str
    payload_bytes: int
    descriptor_close_started: bool = False
    parent_close_started: bool = False


@dataclass(frozen=True, slots=True)
class _SyslogRoutePlan:
    """All-render and parent-identity preflight truth for one physical route."""

    writer: object
    output_path: Path
    parent_identity: tuple[int, int]
    digest: str
    payload_bytes: int


@dataclass(slots=True)
class _SyslogMergeRun:
    """One descriptor-pinned, record-framed transient terminal merge run."""

    stream: Any
    run_identity: tuple[int, int]
    digest: str
    payload_bytes: int
    record_count: int
    record_byte_capacity: int
    row_capacity: int
    byte_capacity: int
    close_started: bool = False


@dataclass(slots=True)
class _SyslogSpoolAppend:
    """One retryable anonymous-journal extent retained until buffer release."""

    writer: object
    records: tuple[str, ...]
    offset: int
    header: bytes
    payload_bytes: int
    record_count: int
    previous_head: int
    prior_route_bytes: int
    prior_record_count: int
    prior_extent_count: int
    prior_global_record_count: int
    prior_global_extent_count: int
    prior_digest: str
    expected_digest: str
    expected_bytes: int
    expected_hash_state: Any
    payload_digest: str


@dataclass(frozen=True, slots=True)
class _SyslogSpoolReceipt:
    """One authenticated extent-chain head for a physical route."""

    head_offset: int
    payload_bytes: int
    record_count: int
    extent_count: int


@dataclass(frozen=True, slots=True)
class SyslogExactCandidateCensus:
    """Bounded exact-candidate admission and terminal-retention counts."""

    admitted_rows: int
    admitted_bytes: int
    reserved_rows: int
    reserved_bytes: int
    released_rows: int
    row_capacity: int
    byte_capacity: int
    high_water_rows: int
    high_water_bytes: int
    final_candidates: int
    final_candidate_high_water: int
    terminal_high_water_rows: int
    terminal_high_water_bytes: int
    publication_complete: bool


class SyslogEmitter(HostMultiplexEmitter):
    """Emitter for Linux syslog format.

    Default target writes flat per-host RFC5424 files. SOF-ELK target writes
    per-host/year RFC3164 files.
    Renders context-authored Linux messages plus source-native Samba projections.
    """

    _log_filename = "syslog.log"
    _flat_filename = "syslog.log"
    _sort_flat_file = True
    _sort_key = staticmethod(_rfc5424_syslog_sort_key)
    _defer_sorted_flush_until_close = True
    _checkpoint_external_sorting = False
    _EXACT_CANDIDATE_METADATA_BYTES = 1_024

    # Context-driven: handles any event type that carries SyslogContext
    _supported_types: set[str] = set()

    def __init__(
        self,
        format_def: FormatDefinition,
        output_path: Path,
        buffer_size: int = 10000,
        threaded: bool = False,
        *,
        exact_candidate_row_capacity: int = 1_000_000,
        exact_candidate_byte_capacity: int = 4 * 1024 * 1024 * 1024,
        spool_record_byte_capacity: int = _DEFAULT_SPOOL_RECORD_BYTE_CAPACITY,
        spool_route_byte_capacity: int = _DEFAULT_SPOOL_ROUTE_BYTE_CAPACITY,
        spool_route_row_capacity: int = _DEFAULT_SPOOL_ROUTE_ROW_CAPACITY,
        terminal_host_row_capacity: int = _DEFAULT_TERMINAL_HOST_ROW_CAPACITY,
        terminal_host_byte_capacity: int = _DEFAULT_TERMINAL_HOST_BYTE_CAPACITY,
        terminal_host_capacity: int = _DEFAULT_TERMINAL_HOST_CAPACITY,
        terminal_merge_fan_in: int = _DEFAULT_TERMINAL_MERGE_FAN_IN,
    ) -> None:
        if type(exact_candidate_row_capacity) is not int or exact_candidate_row_capacity <= 0:
            raise ValueError("exact_candidate_row_capacity must be a positive exact int")
        if type(exact_candidate_byte_capacity) is not int or exact_candidate_byte_capacity <= 0:
            raise ValueError("exact_candidate_byte_capacity must be a positive exact int")
        capacities = {
            "spool_record_byte_capacity": spool_record_byte_capacity,
            "spool_route_byte_capacity": spool_route_byte_capacity,
            "spool_route_row_capacity": spool_route_row_capacity,
            "terminal_host_row_capacity": terminal_host_row_capacity,
            "terminal_host_byte_capacity": terminal_host_byte_capacity,
            "terminal_host_capacity": terminal_host_capacity,
        }
        for name, value in capacities.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive exact int")
        if type(terminal_merge_fan_in) is not int or terminal_merge_fan_in < 2:
            raise ValueError("terminal_merge_fan_in must be an exact int of at least 2")
        super().__init__(format_def, output_path, buffer_size, threaded)
        self._exact_syslog_reservations: dict[ExactPublicationKey, _ExactSyslogReservation] = {}
        self._exact_syslog_candidates: dict[ExactPublicationKey, _ExactSyslogCandidate] = {}
        self._exact_candidate_row_capacity = exact_candidate_row_capacity
        self._exact_candidate_byte_capacity = exact_candidate_byte_capacity
        self._exact_reserved_rows = 0
        self._exact_reserved_bytes = 0
        self._exact_admitted_rows = 0
        self._exact_admitted_bytes = 0
        self._exact_released_rows = 0
        self._exact_high_water_rows = 0
        self._exact_high_water_bytes = 0
        self._spool_record_byte_capacity = spool_record_byte_capacity
        self._spool_route_byte_capacity = spool_route_byte_capacity
        self._spool_route_row_capacity = spool_route_row_capacity
        self._terminal_host_row_capacity = terminal_host_row_capacity
        self._terminal_host_byte_capacity = terminal_host_byte_capacity
        self._terminal_host_capacity = terminal_host_capacity
        self._terminal_merge_fan_in = terminal_merge_fan_in
        self._terminal_high_water_rows = 0
        self._terminal_high_water_bytes = 0
        self._final_candidates: dict[str, _SyslogFinalCandidate] = {}
        self._final_candidate_count = 0
        self._final_candidate_high_water = 0
        self._public_proofs: dict[str, _SyslogPublicProof] = {}
        self._public_appends: dict[str, _SyslogPublicAppend] = {}
        self._route_plans: dict[str, _SyslogRoutePlan] = {}
        self._spool_stream: _SyslogDescriptorOwner | None = None
        self._spool_snapshot: Any | None = None
        self._spool_identity: tuple[int, int] | None = None
        self._spool_snapshot_identity: tuple[int, int] | None = None
        self._spool_close_started = False
        self._spool_snapshot_close_started = False
        self._spool_hash_state = _secure_sha256()
        self._spool_digest = self._spool_hash_state.hexdigest()
        self._spool_bytes = 0
        self._spool_record_count = 0
        self._spool_extent_count = 0
        self._spool_total_row_capacity = (
            self._spool_route_row_capacity * self._terminal_host_capacity
        )
        self._spool_total_byte_capacity = (
            self._spool_route_byte_capacity * self._terminal_host_capacity
        )
        self._spool_appends: dict[str, _SyslogSpoolAppend] = {}
        self._spool_receipts: dict[str, _SyslogSpoolReceipt] = {}
        self._syslog_publication_complete = False
        self._syslog_cleanup_ready = False
        self._terminal_retry_required = False
        self._output_contract_frozen = False

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Return whether record-framed exact candidate publication is active."""

        return True

    def configure_output_target(self, target: str | OutputTarget | None) -> None:
        """Configure target-specific syslog rendering and sort order."""
        normalized = normalize_output_target(target)
        with self._close_condition:
            if self._output_contract_frozen and normalized != self.output_target:
                raise RuntimeError("Syslog output target is frozen after event admission")
            if self._close_state != "open":
                raise RuntimeError("Syslog output target cannot change during terminal close")
            super().configure_output_target(normalized)
            if self.output_target == OutputTarget.SOF_ELK:
                self._sort_key = _syslog_sort_key
            else:
                self._sort_key = _rfc5424_syslog_sort_key

    def _safe_writer_key(self, host_fqdn: str) -> str:
        if self._direct_file_mode:
            return ""
        return sanitize_syslog_family_route_key(host_fqdn)

    def _require_accepting_events_locked(self) -> None:
        super()._require_accepting_events_locked()
        if self._terminal_retry_required:
            raise RuntimeError("Syslog emitter requires terminal close retry")

    def emit_event(self, event_data: dict[str, Any]) -> None:
        """Freeze the target/layout contract before ordinary or exact admission."""

        with self._close_condition:
            self._require_accepting_events_locked()
            self._output_contract_frozen = True
        super().emit_event(event_data)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        return syslog_family_writer_path(
            base_dir=self._base_dir,
            safe_route_key=safe_writer_key,
            log_filename=self._log_filename,
            direct_file_path=self._direct_file_path,
            flat_filename=self._flat_filename,
        )

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Return whether this occurrence has a Linux-native syslog projection."""
        if self._is_samba_lifecycle_event(event):
            return True
        if self._is_samba_audit_event(event):
            return self._samba_audit_enabled(event)
        return event.syslog is not None and self._linux_host(event) is not None

    @staticmethod
    def _is_samba_server(event: CanonicalOccurrence) -> bool:
        """Return whether the occurrence belongs to a modeled Samba server."""
        host = event.dst_host
        if host is None or host.os_category != "linux":
            return False
        auth = event.auth
        smb = event.smb
        return bool(
            (auth is not None and auth.session_kind == "smb")
            or (smb is not None and (smb.provider == "samba" or smb.server_platform == "linux"))
        )

    @classmethod
    def _is_samba_lifecycle_event(cls, event: CanonicalOccurrence) -> bool:
        """Return whether one occurrence renders Samba auth/connect lifecycle."""
        return cls._is_samba_server(event) and event.event_type in {
            "logon",
            "smb_tree_connect",
            "logoff",
        }

    @classmethod
    def _is_samba_audit_event(cls, event: CanonicalOccurrence) -> bool:
        """Return whether one occurrence is eligible for a Samba VFS audit row."""
        return (
            cls._is_samba_server(event) and get_samba_audit_operation(event.event_type) is not None
        )

    @staticmethod
    def _samba_audit_enabled(event: CanonicalOccurrence) -> bool:
        """Apply the share's minimal/standard/high source-observation profile."""
        smb = event.smb
        return bool(
            smb is not None and samba_audit_enabled(event.event_type, smb.audit, smb.result)
        )

    @staticmethod
    def _linux_host(event: CanonicalOccurrence) -> "HostContext | None":
        """Return whichever host has os_category == 'linux'."""
        if (
            (
                SyslogEmitter._is_samba_server(event)
                or (
                    event.syslog is not None
                    and event.syslog.app_name in {"sshd", "smbd", "smbd_audit"}
                )
            )
            and event.dst_host
            and event.dst_host.os_category == "linux"
        ):
            return event.dst_host
        if event.src_host and event.src_host.os_category == "linux":
            return event.src_host
        if event.dst_host and event.dst_host.os_category == "linux":
            return event.dst_host
        return None

    def emit(self, event: CanonicalOccurrence) -> None:
        """Render syslog entry from SyslogContext."""
        if self._is_samba_lifecycle_event(event) or self._is_samba_audit_event(event):
            self._emit_samba(event)
            return
        if event.syslog is None:
            raise NotImplementedError(
                f"SyslogEmitter: event has no SyslogContext (event_type={event.event_type})"
            )
        host = self._linux_host(event)
        ctx = event.syslog
        event_data = {
            "timestamp": event.timestamp,
            "hostname": host.hostname if host else "",
            "app_name": ctx.app_name,
            "pid": ctx.pid,
            "facility": ctx.facility,
            "severity": ctx.severity,
            "message": ctx.message,
            "_host_fqdn": (host.fqdn or host.hostname) if host else "",
        }
        self.emit_event(event_data)

    @staticmethod
    def _samba_field(value: Any) -> str:
        """Return one safe, single-line field for a Samba text record."""
        return str(value or "-").replace("\r", " ").replace("\n", " ").replace("|", "_")

    @classmethod
    def _samba_principal(cls, event: CanonicalOccurrence) -> str:
        """Return the SMB credential principal rather than the client process owner."""
        auth = event.auth
        if auth is None:
            return "-"
        return cls._samba_field(auth.smb_principal or auth.username)

    @staticmethod
    def _samba_pid(event: CanonicalOccurrence) -> int | None:
        """Return a source-owned smbd PID when the canonical transport provides one."""
        network = event.network
        if network is None or network.responding_pid <= 0:
            return None
        return network.responding_pid

    @staticmethod
    def _samba_session_key(event: CanonicalOccurrence) -> str:
        """Return a durable key shared by Samba auth, tree, and disconnect phases."""
        auth = event.auth
        smb = event.smb
        lifecycle = event.lifecycle
        return (
            (auth.auth_session_ref if auth is not None else "")
            or (smb.session_id if smb is not None else "")
            or (lifecycle.group_id if lifecycle is not None else "")
            or (auth.logon_id if auth is not None else "")
        )

    def _samba_session_state(self) -> dict[str, tuple[str, int | None]]:
        """Return lazily allocated renderer-local share/PID correlation state."""
        state = getattr(self, "_samba_sessions", None)
        if state is None:
            state = {}
            self._samba_sessions = state
        return state

    def _emit_samba_row(
        self,
        event: CanonicalOccurrence,
        *,
        app_name: str,
        message: str,
        pid: int | None,
        severity: int = 6,
    ) -> None:
        """Render one destination-host-local Samba row through the syslog family."""
        host = event.dst_host
        self.emit_event(
            {
                "timestamp": event.timestamp,
                "hostname": host.hostname if host else "",
                "app_name": app_name,
                "pid": pid,
                "facility": 3,
                "severity": severity,
                "message": message,
                "_host_fqdn": (host.fqdn or host.hostname) if host else "",
            }
        )

    def _emit_samba(self, event: CanonicalOccurrence) -> None:
        """Project canonical SMB lifecycle and VFS operations as Samba text logs."""
        auth = event.auth
        smb = event.smb
        principal = self._samba_principal(event)
        source_ip = self._samba_field(auth.source_ip if auth is not None else "")
        session_key = self._samba_session_key(event)
        exact_attempt = exact_publication_attempt_active()

        if event.event_type == "logon":
            outcome = "succeeded" if auth is not None and auth.result == "success" else "failed"
            protocol = self._samba_field(auth.auth_protocol) if auth is not None else "-"
            protocol_suffix = f" using {protocol}" if protocol != "-" else ""
            self._emit_samba_row(
                event,
                app_name="smbd",
                pid=None,
                message=(
                    f"Authentication for user [{principal}] from [{source_ip}] "
                    f"{outcome}{protocol_suffix}"
                ),
                severity=6 if outcome == "succeeded" else 4,
            )
            return

        if event.event_type == "smb_tree_connect" and smb is not None:
            pid = self._samba_pid(event)
            if session_key and not exact_attempt:
                sessions = self._samba_session_state()
                sessions[session_key] = (smb.share_name, pid)
            unix_identity = ""
            if auth is not None and auth.effective_uid is not None:
                unix_identity = f" (uid={auth.effective_uid}"
                if auth.effective_gid is not None:
                    unix_identity += f", gid={auth.effective_gid}"
                unix_identity += ")"
            result_suffix = "" if smb.result == "success" else f" failed: {smb.result}"
            self._emit_samba_row(
                event,
                app_name="smbd",
                pid=pid,
                message=(
                    f"connect to service {self._samba_field(smb.share_name)} as user "
                    f"{principal}{unix_identity}{result_suffix}"
                ),
                severity=6 if smb.result == "success" else 4,
            )
            return

        if event.event_type == "logoff":
            if exact_attempt:
                if smb is None:
                    raise ExactPublicationError(
                        "Exact Samba logoff requires its immutable SMB source context"
                    )
                share_name = smb.share_name
                pid = self._samba_pid(event)
            else:
                share_name = "-"
                pid = None
                sessions = self._samba_session_state()
                if session_key and session_key in sessions:
                    share_name, pid = sessions.pop(session_key)
            self._emit_samba_row(
                event,
                app_name="smbd",
                pid=pid,
                message=f"closed connection to service {self._samba_field(share_name)}",
            )
            return

        if smb is None or not self._samba_audit_enabled(event):
            return
        audit_operation = get_samba_audit_operation(event.event_type)
        if audit_operation is None:
            return
        message = "|".join(
            (
                principal,
                source_ip,
                self._samba_field(smb.share_name),
                audit_operation.label,
                self._samba_field(smb.result),
                self._samba_field(smb.server_path or smb.share_local_path),
            )
        )
        self._emit_samba_row(
            event,
            app_name="smbd_audit",
            pid=self._samba_pid(event),
            message=f"smbd_audit: {message}",
            severity=6 if smb.result == "success" else 4,
        )

    @staticmethod
    def _exact_candidate_payload(
        writer_route_key: str,
        logical_route_key: str,
        rendered: str,
    ) -> str:
        """Encode one logical source record without exposing newline framing."""

        return _secure_json_dumps(
            {
                "line": rendered,
                "logical_route": logical_route_key,
                "route": writer_route_key,
                "version": 2,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _decode_exact_candidate(frozen: object) -> tuple[str, str, str]:
        """Decode one canonical exact candidate using strict JSON field types."""

        if type(frozen) is not str:
            raise ExactPublicationError("Exact Syslog candidate must retain one exact str")
        try:
            payload = _secure_json_loads(frozen)
        except (TypeError, ValueError) as exc:
            raise ExactPublicationError("Exact Syslog candidate encoding is invalid") from exc
        if type(payload) is not dict or set(payload) != {
            "line",
            "logical_route",
            "route",
            "version",
        }:
            raise ExactPublicationError("Exact Syslog candidate fields are invalid")
        if payload["version"] != 2 or type(payload["version"]) is not int:
            raise ExactPublicationError("Exact Syslog candidate version is invalid")
        writer_route_key = payload["route"]
        logical_route_key = payload["logical_route"]
        rendered = payload["line"]
        if (
            type(writer_route_key) is not str
            or type(logical_route_key) is not str
            or type(rendered) is not str
        ):
            raise ExactPublicationError("Exact Syslog route and line must be exact strings")
        if (
            len(writer_route_key.encode("utf-8")) > 4_096
            or len(logical_route_key.encode("utf-8")) > 4_096
        ):
            raise ExactPublicationError("Exact Syslog route exceeds the bounded key size")
        if (
            sanitize_syslog_family_route_key(writer_route_key) != writer_route_key
            or sanitize_syslog_family_route_key(logical_route_key) != logical_route_key
        ):
            raise ExactPublicationError("Exact Syslog route is not canonical")
        if (
            SyslogEmitter._exact_candidate_payload(
                writer_route_key,
                logical_route_key,
                rendered,
            )
            != frozen
        ):
            raise ExactPublicationError("Exact Syslog candidate encoding is not canonical")
        return writer_route_key, logical_route_key, rendered

    def _exact_candidate_capacity_bytes(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> int:
        namespace, _ordinal, _cursor = key
        return (
            (2 * retained_bytes)
            + len(namespace.encode("utf-8"))
            + len(digest.encode("ascii"))
            + self._EXACT_CANDIDATE_METADATA_BYTES
        )

    def _update_exact_high_water_unlocked(self) -> None:
        rows = self._exact_reserved_rows + self._exact_admitted_rows
        retained_bytes = self._exact_reserved_bytes + self._exact_admitted_bytes
        self._exact_high_water_rows = max(self._exact_high_water_rows, rows)
        self._exact_high_water_bytes = max(self._exact_high_water_bytes, retained_bytes)

    def _reserve_exact_publication_row(
        self,
        key: ExactPublicationKey,
        digest: str,
        retained_bytes: int,
    ) -> None:
        """Reserve bounded candidate storage before canonical owner mutation."""

        participant_key = key[:2]
        capacity_bytes = self._exact_candidate_capacity_bytes(key, digest, retained_bytes)
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact Syslog reservation lost its emitter fence")
            with self._file_lock:
                retained = self._exact_syslog_reservations.get(key)
                if retained is not None:
                    if (
                        retained.digest != digest
                        or retained.retained_bytes != retained_bytes
                        or retained.capacity_bytes != capacity_bytes
                    ):
                        raise ExactPublicationError(
                            "Exact Syslog reservation changed before admission"
                        )
                    return
                if (
                    self._exact_reserved_rows + self._exact_admitted_rows + 1
                    > self._exact_candidate_row_capacity
                ):
                    raise ExactPublicationError("Exact Syslog candidate row capacity is exhausted")
                if (
                    self._exact_reserved_bytes + self._exact_admitted_bytes + capacity_bytes
                    > self._exact_candidate_byte_capacity
                ):
                    raise ExactPublicationError("Exact Syslog candidate byte capacity is exhausted")
                self._exact_reserved_rows += 1
                self._exact_reserved_bytes += capacity_bytes
                self._update_exact_high_water_unlocked()
                try:
                    self._exact_syslog_reservations[key] = _ExactSyslogReservation(
                        digest=digest,
                        retained_bytes=retained_bytes,
                        capacity_bytes=capacity_bytes,
                    )
                except BaseException:
                    self._exact_reserved_rows -= 1
                    self._exact_reserved_bytes -= capacity_bytes
                    raise

    def _commit_exact_candidate(
        self,
        key: ExactPublicationKey,
        digest: str,
        frozen: object,
    ) -> None:
        """Admit one immutable record marker with lost-return reconciliation."""

        writer_route_key, logical_route_key, rendered = self._decode_exact_candidate(frozen)
        participant_key = key[:2]
        with self._exact_publication_condition:
            if participant_key not in self._active_exact_publication_keys:
                raise ExactPublicationError("Exact Syslog candidate lost its emitter fence")
            with self._file_lock:
                retained = self._exact_syslog_candidates.get(key)
                if retained is not None:
                    if retained.digest != digest or retained.frozen != frozen:
                        raise ExactPublicationError("Exact Syslog candidate changed on retry")
                else:
                    reservation = self._exact_syslog_reservations.get(key)
                    if reservation is None or reservation.digest != digest:
                        raise ExactPublicationError(
                            "Exact Syslog candidate lost its capacity reservation"
                        )
                    marker = _ExactSyslogLine(rendered, logical_route_key, key)
                    retained = _ExactSyslogCandidate(
                        digest=digest,
                        frozen=frozen,
                        writer_route_key=writer_route_key,
                        logical_route_key=logical_route_key,
                        marker=marker,
                        capacity_bytes=reservation.capacity_bytes,
                    )
                    self._exact_syslog_candidates[key] = retained
                    self._exact_syslog_reservations.pop(key)
                    self._exact_reserved_rows -= 1
                    self._exact_reserved_bytes -= reservation.capacity_bytes
                    self._exact_admitted_rows += 1
                    self._exact_admitted_bytes += reservation.capacity_bytes
                    self._update_exact_high_water_unlocked()

        if not retained.installed:
            writer = self._get_writer(writer_route_key)
            with writer._lock:
                if not any(line is retained.marker for line in writer.buffer):
                    writer.buffer.append(retained.marker)
                    writer.event_count += 1
            with self._file_lock:
                current = self._exact_syslog_candidates.get(key)
                if current is not retained:
                    raise ExactPublicationError("Exact Syslog candidate ownership changed")
                retained.installed = True

    def _release_exact_candidate(self, key: ExactPublicationKey) -> None:
        """Retain source truth while marking its batch receipt terminal."""

        with self._file_lock:
            retained = self._exact_syslog_candidates.get(key)
            if retained is None:
                raise ExactPublicationError("Exact Syslog candidate receipt is missing")
            if not retained.released:
                retained.released = True
                self._exact_released_rows += 1

    def _abort_exact_publication_batch(
        self,
        key: ExactPublicationParticipantKey,
    ) -> None:
        with self._file_lock:
            reservations = [
                row_key for row_key in self._exact_syslog_reservations if row_key[:2] == key
            ]
            for row_key in reservations:
                retained = self._exact_syslog_reservations.pop(row_key)
                self._exact_reserved_rows -= 1
                self._exact_reserved_bytes -= retained.capacity_bytes
        super()._abort_exact_publication_batch(key)

    def exact_candidate_census(self) -> SyslogExactCandidateCensus:
        """Return O(1) bounded candidate and terminal-finalization counts."""

        with self._file_lock:
            return SyslogExactCandidateCensus(
                admitted_rows=self._exact_admitted_rows,
                admitted_bytes=self._exact_admitted_bytes,
                reserved_rows=self._exact_reserved_rows,
                reserved_bytes=self._exact_reserved_bytes,
                released_rows=self._exact_released_rows,
                row_capacity=self._exact_candidate_row_capacity,
                byte_capacity=self._exact_candidate_byte_capacity,
                high_water_rows=self._exact_high_water_rows,
                high_water_bytes=self._exact_high_water_bytes,
                final_candidates=self._final_candidate_count,
                final_candidate_high_water=self._final_candidate_high_water,
                terminal_high_water_rows=self._terminal_high_water_rows,
                terminal_high_water_bytes=self._terminal_high_water_bytes,
                publication_complete=self._syslog_publication_complete,
            )

    @staticmethod
    def _filesystem_identity(metadata: os.stat_result) -> tuple[int, int]:
        return int(metadata.st_dev), int(metadata.st_ino)

    @classmethod
    def _require_descriptor_primitives(
        cls,
        *,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _open: Callable[..., int] = _SYSLOG_SECURITY_REGISTRY.os_open,
        _mkdir: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.os_mkdir,
        _stat: Callable[..., os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_stat,
        _pread: Callable[[int, int, int], bytes] | None = (_SYSLOG_SECURITY_REGISTRY.os_pread),
        _supports_dir_fd: object = _SYSLOG_SECURITY_REGISTRY.supports_dir_fd,
        _supports_dir_fd_values: frozenset[object] = (
            _SYSLOG_SECURITY_REGISTRY.supports_dir_fd_values
        ),
        _supports_follow: object = _SYSLOG_SECURITY_REGISTRY.supports_follow_symlinks,
        _supports_follow_values: frozenset[object] = (
            _SYSLOG_SECURITY_REGISTRY.supports_follow_symlinks_values
        ),
        _nofollow: int = _SYSLOG_SECURITY_REGISTRY.nofollow,
        _directory: int = _SYSLOG_SECURITY_REGISTRY.directory,
    ) -> None:
        """Fail closed when portable descriptor-relative safety is unavailable."""

        required_dir_fd = (_open, _mkdir, _stat)
        if (
            _nofollow == 0
            or _directory == 0
            or any(function not in _supports_dir_fd_values for function in required_dir_fd)
            or _stat not in _supports_follow_values
            or _pread is None
        ):
            raise ExactPublicationError(
                "Syslog exact publication requires trusted no-follow descriptor-relative "
                "filesystem primitives"
            )

    @classmethod
    def _new_anonymous_stream(cls, *, label: str) -> tuple[Any, tuple[int, int]]:
        """Create owner-private storage with no directory entry to clean up."""

        stream = _new_temporary_stream()
        try:
            descriptor = _stream_descriptor(stream)
            metadata = _secure_fstat(descriptor)
            effective_uid = _secure_geteuid()
            if (
                not _secure_isreg(metadata.st_mode)
                or int(metadata.st_nlink) != 0
                or _secure_imode(metadata.st_mode) & 0o077
                or (effective_uid is not None and int(metadata.st_uid) != int(effective_uid))
                or _secure_get_inheritable(descriptor)
            ):
                raise ExactPublicationError(f"Syslog {label} is not anonymous owner storage")
            return stream, cls._filesystem_identity(metadata)
        except BaseException:
            _stream_close(stream)
            raise

    @classmethod
    def _new_anonymous_descriptor_owner(
        cls,
        *,
        label: str,
    ) -> tuple[_SyslogDescriptorOwner, tuple[int, int]]:
        """Detach anonymous storage from Python finalizers into one exact raw owner."""

        stream, identity = cls._new_anonymous_stream(label=label)
        source_descriptor = _stream_descriptor(stream)
        descriptor = _secure_dup(source_descriptor)
        try:
            _stream_close(stream)
            owner = _new_descriptor_owner(descriptor, identity)
        except BaseException:
            try:
                _secure_close(descriptor)
            except OSError:
                pass
            if not _stream_is_closed(stream):
                _stream_close(stream)
            raise
        return owner, identity

    @classmethod
    def _verify_anonymous_stream(
        cls,
        stream: Any,
        expected_identity: tuple[int, int],
        *,
        label: str,
        expected_bytes: int | None = None,
    ) -> int:
        """Authenticate a retained anonymous descriptor without using a pathname."""

        try:
            if type(stream) is _SYSLOG_SECURITY_REGISTRY.owner_type:
                descriptor, owner_identity = _descriptor_owner_snapshot(stream, label=label)
                if owner_identity != expected_identity:
                    raise ExactPublicationError(f"Syslog {label} descriptor identity changed")
            else:
                descriptor = _stream_descriptor(stream)
            metadata = _secure_fstat(descriptor)
        except (OSError, ValueError) as error:
            raise ExactPublicationError(f"Syslog {label} descriptor disappeared") from error
        if (
            cls._filesystem_identity(metadata) != expected_identity
            or not _secure_isreg(metadata.st_mode)
            or int(metadata.st_nlink) != 0
            or (expected_bytes is not None and int(metadata.st_size) != expected_bytes)
        ):
            raise ExactPublicationError(f"Syslog {label} descriptor identity or size changed")
        return descriptor

    @staticmethod
    def _close_retained_stream(stream: Any, *, close_started: bool, label: str) -> None:
        """Close a retained stream while reconciling a prior close lost return."""

        if type(stream) is _SYSLOG_SECURITY_REGISTRY.owner_type:
            if _descriptor_owner_is_closed(stream, label=label):
                if not close_started:
                    raise ExactPublicationError(
                        f"Syslog {label} closed without retirement ownership"
                    )
                return
            _retire_descriptor_owner(stream, label=label)
            return
        if _stream_is_closed(stream):
            if not close_started:
                raise ExactPublicationError(f"Syslog {label} closed without retirement ownership")
            return
        _stream_close(stream)

    @classmethod
    def _close_public_owner(
        cls,
        owner: object,
        *,
        label: str,
    ) -> None:
        """Authenticate and retire the exact slotted owner without dynamic methods."""

        _retire_descriptor_owner(owner, label=label)

    @staticmethod
    def _write_descriptor(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = _secure_write(descriptor, view[written:])
            if count <= 0:
                raise ExactPublicationError("Syslog descriptor write made no progress")
            written += count

    @staticmethod
    def _read_descriptor(descriptor: int, payload_bytes: int) -> bytes:
        payload = bytearray()
        while len(payload) < payload_bytes:
            chunk = _secure_read(descriptor, payload_bytes - len(payload))
            if not chunk:
                raise ExactPublicationError("Syslog descriptor prefix disappeared")
            payload.extend(chunk)
        return bytes(payload)

    @staticmethod
    def _descriptor_digest(descriptor: int) -> tuple[str, int]:
        digest = _secure_sha256()
        payload_bytes = 0
        _secure_lseek(descriptor, 0)
        while chunk := _secure_read(descriptor, _IO_CHUNK_BYTES):
            digest.update(chunk)
            payload_bytes += len(chunk)
        _secure_lseek(descriptor, 0)
        return digest.hexdigest(), payload_bytes

    @classmethod
    def _walk_output_directory(
        cls,
        path: Path,
        *,
        create: bool,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _separator: str = _SYSLOG_SECURITY_REGISTRY.path_separator,
        _read_only: int = _SYSLOG_SECURITY_REGISTRY.o_rdonly,
        _directory: int = _SYSLOG_SECURITY_REGISTRY.directory,
        _nofollow: int = _SYSLOG_SECURITY_REGISTRY.nofollow,
    ) -> tuple[int, tuple[int, int]]:
        """Open one absolute directory through no-follow descriptor-relative steps."""

        cls._require_descriptor_primitives()
        absolute = Path(_secure_abspath(path))
        if absolute.anchor != _separator:
            raise ExactPublicationError("Syslog final output directory must be absolute")
        descriptor = _secure_open(_separator, _read_only | _directory | _nofollow)
        try:
            for component in absolute.parts[1:]:
                if component in {"", ".", ".."} or _separator in component:
                    raise ExactPublicationError("Syslog final output directory is invalid")
                if create:
                    try:
                        _secure_mkdir(component, 0o755, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                lexical = _secure_stat(component, dir_fd=descriptor, follow_symlinks=False)
                if _secure_islnk(lexical.st_mode) or not _secure_isdir(lexical.st_mode):
                    raise ExactPublicationError(
                        "Syslog final output directory contains an unsafe component"
                    )
                opened = _secure_open(
                    component,
                    _read_only | _directory | _nofollow,
                    dir_fd=descriptor,
                )
                metadata = _secure_fstat(opened)
                if not _secure_isdir(metadata.st_mode) or cls._filesystem_identity(
                    lexical
                ) != cls._filesystem_identity(metadata):
                    _secure_close(opened)
                    raise ExactPublicationError("Syslog final output directory identity changed")
                _secure_close(descriptor)
                descriptor = opened
            metadata = _secure_fstat(descriptor)
            if not _secure_isdir(metadata.st_mode):
                raise ExactPublicationError("Syslog final output parent is not a directory")
            return descriptor, cls._filesystem_identity(metadata)
        except BaseException:
            _secure_close(descriptor)
            raise

    @classmethod
    def _open_output_parent(
        cls,
        output_path: Path,
        *,
        create: bool,
        expected_identity: tuple[int, int] | None = None,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _separator: str = _SYSLOG_SECURITY_REGISTRY.path_separator,
    ) -> tuple[int, tuple[int, int]]:
        if output_path.name in {"", ".", ".."} or _separator in output_path.name:
            raise ExactPublicationError("Syslog final output filename is invalid")
        descriptor, identity = cls._walk_output_directory(output_path.parent, create=create)
        if expected_identity is not None and identity != expected_identity:
            _secure_close(descriptor)
            raise ExactPublicationError("Syslog final output directory identity changed")
        return descriptor, identity

    @classmethod
    def _authenticate_output_parent(
        cls,
        output_path: Path,
        descriptor: int,
        expected_identity: tuple[int, int],
    ) -> None:
        metadata = _secure_fstat(descriptor)
        if (
            not _secure_isdir(metadata.st_mode)
            or cls._filesystem_identity(metadata) != expected_identity
        ):
            raise ExactPublicationError("Syslog final output directory identity changed")
        verifier, identity = cls._open_output_parent(output_path, create=False)
        _secure_close(verifier)
        if identity != expected_identity:
            raise ExactPublicationError("Syslog final output directory identity changed")

    @classmethod
    def _authenticate_public_descriptor(
        cls,
        descriptor: int,
        expected_identity: tuple[int, int] | None,
    ) -> tuple[int, int]:
        metadata = _secure_fstat(descriptor)
        identity = cls._filesystem_identity(metadata)
        if (
            not _secure_isreg(metadata.st_mode)
            or int(metadata.st_nlink) != 1
            or (expected_identity is not None and identity != expected_identity)
        ):
            raise ExactPublicationError("Syslog final output descriptor identity changed")
        return identity

    @classmethod
    def _authenticate_public_entry(
        cls,
        output_path: Path,
        parent_descriptor: int,
        parent_identity: tuple[int, int],
        descriptor: int,
        file_identity: tuple[int, int],
    ) -> None:
        cls._authenticate_output_parent(output_path, parent_descriptor, parent_identity)
        metadata = _secure_stat(
            output_path.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            _secure_islnk(metadata.st_mode)
            or not _secure_isreg(metadata.st_mode)
            or cls._filesystem_identity(metadata) != file_identity
            or cls._authenticate_public_descriptor(descriptor, file_identity) != file_identity
        ):
            raise ExactPublicationError("Syslog final output directory entry changed")

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route syslog event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        if self.output_target == OutputTarget.SOF_ELK:
            route_key = make_syslog_family_route_key(
                host_fqdn,
                event_data["timestamp"],
                direct_file_mode=self._direct_file_mode,
            )
        else:
            route_key = host_fqdn
        if not route_key and not self._direct_file_path:
            return
        logical_route_key = sanitize_syslog_family_route_key(str(route_key))
        writer_route_key = self._safe_writer_key(str(route_key))
        frozen = self._exact_candidate_payload(writer_route_key, logical_route_key, rendered)
        if stage_exact_publication_row(
            self,
            frozen,
            publish=self._commit_exact_candidate,
            release=self._release_exact_candidate,
        ):
            return
        self.emit_to_host(_RoutedSyslogLine(rendered, logical_route_key), str(route_key))

    def _render_event(self, event_data: dict[str, Any]) -> str:
        ts = event_data.get("timestamp")
        ts = coerce_syslog_datetime(ts)

        facility = bounded_syslog_int(event_data.get("facility"), default=3, minimum=0, maximum=23)
        severity = bounded_syslog_int(event_data.get("severity"), default=6, minimum=0, maximum=7)
        pid = event_data.get("pid")
        if self.output_target != OutputTarget.SOF_ELK:
            return render_rfc5424_syslog(
                pri=syslog_priority(facility, severity),
                timestamp=ts,
                hostname=event_data.get("hostname") or "",
                app_name=event_data.get("app_name") or "-",
                pid=pid,
                message=event_data.get("message") or "",
            )
        return render_rfc3164_syslog(
            pri=syslog_priority(facility, severity),
            timestamp=ts,
            hostname=event_data.get("hostname") or "",
            app_name=event_data.get("app_name") or "-",
            pid=pid,
            message=event_data.get("message") or "",
        )

    def close(self) -> None:
        """Close emitter after normalizing source-native syslog presentation state."""
        if not self._begin_close():
            return
        try:
            if self.threaded:
                self.stop_thread()
            self._finalize_spooled_hosts()
        except BaseException:
            self._terminal_retry_required = True
            self._fail_close()
            raise
        try:
            self._finish_close()
        except BaseException:
            self._terminal_retry_required = True
            self._fail_close()
            raise
        with self._file_lock:
            self._final_candidates.clear()
            self._final_candidate_count = 0
            self._public_proofs.clear()
            self._public_appends.clear()
            self._route_plans.clear()
        self._terminal_retry_required = False

    def flush(self, force: bool = False) -> None:
        """Spool buffered rows at barriers while deferring final normalization.

        Syslog requires a final host-wide sort because generation can render
        events out of timestamp order. Hourly barriers still spill sorted runs
        to disk so long scenarios do not retain every rendered row in memory.
        ``close()`` restores those runs once for final normalization.
        """
        worker_final_flush = bool(
            self.threaded
            and self._thread is not None
            and self._thread.ident == get_ident()
            and self._stop_event is not None
            and self._stop_event.is_set()
        )
        if not worker_final_flush:
            self._begin_queue_admission()
        try:
            self._wait_for_exact_publication_turn(None)
            with self._writers_lock:
                for route_key, writer in self._writers.items():
                    with writer._lock:
                        self._spool_writer_records(route_key, writer)
        finally:
            if not worker_final_flush:
                self._finish_queue_admission()

    def checkpoint_spool_export(self, committed_bytes: int) -> tuple[bytes, dict[str, object]]:
        """Export only the new anonymous-journal suffix and its bounded live head."""

        if type(committed_bytes) is not int or committed_bytes < 0:
            raise ExactPublicationError("Syslog checkpoint byte watermark is invalid")
        with self._writers_lock:
            route_writers = tuple(self._writers.items())
            if any(writer.buffer for _route, writer in route_writers):
                raise ExactPublicationError("Syslog checkpoint retains an unsealed writer buffer")
        with self._file_lock:
            if self._exact_syslog_reservations or self._spool_appends:
                raise ExactPublicationError("Syslog checkpoint retains a prepared append")
            if any(
                not candidate.installed or not candidate.released
                for candidate in self._exact_syslog_candidates.values()
            ):
                raise ExactPublicationError("Syslog checkpoint retains an active exact candidate")
            if (
                self._final_candidates
                or self._public_appends
                or self._public_proofs
                or self._route_plans
                or self._syslog_publication_complete
                or self._syslog_cleanup_ready
                or self._terminal_retry_required
            ):
                raise ExactPublicationError("Syslog checkpoint crossed terminal publication")
            exact_rows = len(self._exact_syslog_candidates)
            exact_bytes = sum(
                candidate.capacity_bytes for candidate in self._exact_syslog_candidates.values()
            )
        if committed_bytes > self._spool_bytes:
            raise ExactPublicationError("Syslog checkpoint journal was truncated")
        if self._spool_bytes == 0:
            if self._spool_receipts or route_writers or exact_rows:
                raise ExactPublicationError("Syslog empty checkpoint journal has retained state")
            return b"", {
                "digest": self._spool_digest,
                "extent_count": 0,
                "record_count": 0,
                "receipts": [],
            }
        descriptor = self._verify_anonymous_stream(
            self._spool_stream,
            self._spool_identity or (-1, -1),
            label="private spool",
            expected_bytes=self._spool_bytes,
        )
        suffix = bytearray()
        offset = committed_bytes
        while offset < self._spool_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, self._spool_bytes - offset),
                offset,
            )
            if not chunk:
                raise ExactPublicationError("Syslog checkpoint journal suffix disappeared")
            suffix.extend(chunk)
            offset += len(chunk)
        if int(_secure_fstat(descriptor).st_size) != self._spool_bytes:
            raise ExactPublicationError("Syslog checkpoint journal changed during export")
        receipts = [
            [
                route,
                receipt.head_offset,
                receipt.payload_bytes,
                receipt.record_count,
                receipt.extent_count,
            ]
            for route, receipt in sorted(self._spool_receipts.items())
        ]
        if (
            {route for route, _writer in route_writers} != set(self._spool_receipts)
            or sum(receipt.record_count for receipt in self._spool_receipts.values())
            != self._spool_record_count
            or sum(receipt.extent_count for receipt in self._spool_receipts.values())
            != self._spool_extent_count
            or exact_rows > self._spool_record_count
            or exact_bytes != self._exact_admitted_bytes
            or self._exact_released_rows != exact_rows
        ):
            raise ExactPublicationError("Syslog checkpoint journal census diverged")
        return bytes(suffix), {
            "digest": self._spool_digest,
            "extent_count": self._spool_extent_count,
            "record_count": self._spool_record_count,
            "receipts": receipts,
        }

    def _checkpoint_restore_exact_candidates(self, descriptor: int) -> set[ExactPublicationKey]:
        """Rebuild exact candidate authentication from restored journal records."""

        keys: set[ExactPublicationKey] = set()
        cursor = 0
        extents = 0
        records = 0
        while cursor < self._spool_bytes:
            header_frame, payload_offset = self._read_frame_at(
                descriptor,
                cursor,
                capacity=_SPOOL_EXTENT_HEADER_BYTE_CAPACITY,
                journal_bytes=self._spool_bytes,
            )
            try:
                header = _secure_json_loads(header_frame)
            except (UnicodeDecodeError, ValueError) as error:
                raise ExactPublicationError(
                    "Syslog checkpoint journal extent header is invalid"
                ) from error
            if (
                type(header) is not dict
                or set(header)
                != {
                    "payload_bytes",
                    "payload_digest",
                    "previous",
                    "record_count",
                    "route",
                    "version",
                }
                or type(header["payload_bytes"]) is not int
                or type(header["record_count"]) is not int
                or type(header["route"]) is not str
                or type(header["version"]) is not int
                or header["version"] != 1
                or header["payload_bytes"] < 0
                or header["record_count"] <= 0
                or payload_offset + header["payload_bytes"] > self._spool_bytes
            ):
                raise ExactPublicationError("Syslog checkpoint journal extent header changed")
            route = header["route"]
            if route not in self._spool_receipts:
                raise ExactPublicationError("Syslog checkpoint journal has an unknown route")
            extent_records = 0
            for encoded_bytes in self._iter_extent_payload_frames(
                descriptor,
                offset=payload_offset,
                payload_bytes=header["payload_bytes"],
            ):
                extent_records += 1
                try:
                    encoded = encoded_bytes.decode("utf-8")
                    value = _secure_json_loads(encoded)
                except (UnicodeDecodeError, ValueError) as error:
                    raise ExactPublicationError(
                        "Syslog checkpoint journal record is invalid"
                    ) from error
                if type(value) is not dict or set(value) != {
                    "digest",
                    "key",
                    "line",
                    "logical_route",
                    "version",
                }:
                    continue
                raw_key = value["key"]
                if (
                    value["version"] != 2
                    or type(value["version"]) is not int
                    or type(raw_key) is not list
                    or len(raw_key) != 3
                    or type(raw_key[0]) is not str
                    or type(raw_key[1]) is not int
                    or type(raw_key[2]) is not int
                    or type(value["digest"]) is not str
                    or type(value["line"]) is not str
                    or type(value["logical_route"]) is not str
                ):
                    raise ExactPublicationError("Syslog checkpoint exact journal record changed")
                key: ExactPublicationKey = (raw_key[0], raw_key[1], raw_key[2])
                frozen = self._exact_candidate_payload(
                    route,
                    value["logical_route"],
                    value["line"],
                )
                digest = _secure_sha256(frozen.encode()).hexdigest()
                if key in keys or digest != value["digest"]:
                    raise ExactPublicationError("Syslog checkpoint exact journal identity changed")
                capacity_bytes = self._exact_candidate_capacity_bytes(
                    key,
                    digest,
                    len(frozen.encode()),
                )
                marker = _ExactSyslogLine(value["line"], value["logical_route"], key)
                self._exact_syslog_candidates[key] = _ExactSyslogCandidate(
                    digest=digest,
                    frozen=frozen,
                    writer_route_key=route,
                    logical_route_key=value["logical_route"],
                    marker=marker,
                    capacity_bytes=capacity_bytes,
                    installed=True,
                    released=True,
                )
                keys.add(key)
            if extent_records != header["record_count"]:
                raise ExactPublicationError("Syslog checkpoint journal record count changed")
            records += extent_records
            extents += 1
            cursor = payload_offset + header["payload_bytes"]
        if cursor != self._spool_bytes or (
            records,
            extents,
        ) != (
            self._spool_record_count,
            self._spool_extent_count,
        ):
            raise ExactPublicationError("Syslog checkpoint journal framing changed")
        return keys

    def checkpoint_spool_restore(self, payload: bytes, state: object) -> None:
        """Restore an authenticated anonymous journal into a fresh emitter."""

        if (
            type(state) is not dict
            or set(state) != {"digest", "extent_count", "record_count", "receipts"}
            or type(state["digest"]) is not str
            or type(state["extent_count"]) is not int
            or state["extent_count"] < 0
            or type(state["record_count"]) is not int
            or state["record_count"] < 0
            or type(state["receipts"]) is not list
            or len(payload) > self._spool_total_byte_capacity
            or _secure_sha256(payload).hexdigest() != state["digest"]
        ):
            raise ExactPublicationError("Syslog checkpoint spool head is invalid")
        if (
            self._writers
            or self._spool_stream is not None
            or self._spool_bytes
            or self._spool_receipts
            or self._exact_syslog_candidates
        ):
            raise ExactPublicationError("Syslog checkpoint restore requires a fresh emitter")
        receipts: dict[str, _SyslogSpoolReceipt] = {}
        for row in state["receipts"]:
            if (
                type(row) is not list
                or len(row) != 5
                or type(row[0]) is not str
                or sanitize_syslog_family_route_key(row[0]) != row[0]
                or type(row[1]) is not int
                or row[1] < 0
                or type(row[2]) is not int
                or row[2] <= 0
                or type(row[3]) is not int
                or row[3] <= 0
                or type(row[4]) is not int
                or row[4] <= 0
                or row[0] in receipts
            ):
                raise ExactPublicationError("Syslog checkpoint route receipt is invalid")
            receipts[row[0]] = _SyslogSpoolReceipt(
                head_offset=row[1],
                payload_bytes=row[2],
                record_count=row[3],
                extent_count=row[4],
            )
        if (
            (not payload) != (not receipts)
            or sum(receipt.record_count for receipt in receipts.values()) != state["record_count"]
            or sum(receipt.extent_count for receipt in receipts.values()) != state["extent_count"]
        ):
            raise ExactPublicationError("Syslog checkpoint route census changed")
        descriptor = self._ensure_spool_stream(allow_zero_recovery=True) if payload else None
        self._spool_receipts = receipts
        self._spool_bytes = len(payload)
        self._spool_record_count = state["record_count"]
        self._spool_extent_count = state["extent_count"]
        self._spool_digest = state["digest"]
        self._spool_hash_state = _secure_sha256()
        self._spool_hash_state.update(payload)
        if payload:
            assert descriptor is not None
            self._write_descriptor(descriptor, payload)
            _secure_fsync(descriptor)
            for route, receipt in sorted(receipts.items()):
                writer = self._get_writer(route)
                writer.event_count = receipt.record_count
            keys = self._checkpoint_restore_exact_candidates(descriptor)
            self._exact_admitted_rows = len(keys)
            self._exact_released_rows = len(keys)
            self._exact_admitted_bytes = sum(
                candidate.capacity_bytes for candidate in self._exact_syslog_candidates.values()
            )
            if (
                self._exact_admitted_rows > self._exact_candidate_row_capacity
                or self._exact_admitted_bytes > self._exact_candidate_byte_capacity
            ):
                raise ExactPublicationError("Syslog checkpoint exact candidate capacity changed")
            self._exact_high_water_rows = self._exact_admitted_rows
            self._exact_high_water_bytes = self._exact_admitted_bytes
            self._authenticate_spool_journal()
            matched: set[ExactPublicationKey] = set()
            for route, receipt in sorted(receipts.items()):
                tuple(self._iter_spooled_route_lines(route, receipt, matched))
            self._invalidate_spool_snapshot()
            if matched != keys:
                raise ExactPublicationError("Syslog checkpoint exact candidate set changed")

    @staticmethod
    def _spool_records_match_prefix(buffer: list[str], records: tuple[str, ...]) -> bool:
        if len(buffer) < len(records):
            return False
        for current, retained in zip(buffer, records, strict=False):
            if type(retained) is _ExactSyslogLine:
                if current is not retained:
                    return False
            elif type(retained) is _RoutedSyslogLine:
                if current is not retained:
                    return False
            elif type(current) is not str or current != retained:
                return False
        return True

    def _encoded_spool_frames(self, records: tuple[str, ...]) -> Iterator[bytes]:
        """Yield bounded canonical record frames without retaining a payload copy."""

        for rendered in records:
            frame = self._encode_spool_record(rendered).encode("utf-8") + b"\n"
            if len(frame) > self._spool_record_byte_capacity:
                raise ExactPublicationError("Syslog private spool record capacity is exhausted")
            yield frame

    @staticmethod
    def _descriptor_prefix_digest(descriptor: int, payload_bytes: int) -> str:
        digest = _secure_sha256()
        retained = 0
        while retained < payload_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, payload_bytes - retained),
                retained,
            )
            if not chunk:
                raise ExactPublicationError("Syslog anonymous journal prefix disappeared")
            digest.update(chunk)
            retained += len(chunk)
        return digest.hexdigest()

    def _pending_extent_frames(self, pending: _SyslogSpoolAppend) -> Iterator[bytes]:
        yield pending.header
        yield from self._encoded_spool_frames(pending.records)

    def _descriptor_suffix_matches_pending(
        self,
        descriptor: int,
        *,
        offset: int,
        retained_bytes: int,
        pending: _SyslogSpoolAppend,
    ) -> bool:
        compared = 0
        for frame in self._pending_extent_frames(pending):
            if compared == retained_bytes:
                break
            retained = min(len(frame), retained_bytes - compared)
            current = _secure_pread(descriptor, retained, offset + compared)
            if current != frame[:retained]:
                return False
            compared += retained
            if retained != len(frame):
                break
        return compared == retained_bytes

    def _write_pending_suffix(
        self,
        descriptor: int,
        pending: _SyslogSpoolAppend,
        retained_bytes: int,
    ) -> None:
        _secure_lseek(descriptor, pending.offset + retained_bytes)
        skip = retained_bytes
        for frame in self._pending_extent_frames(pending):
            if skip >= len(frame):
                skip -= len(frame)
                continue
            self._write_descriptor(descriptor, frame[skip:])
            skip = 0
        if skip:
            raise ExactPublicationError("Syslog anonymous journal suffix metadata changed")

    def _authenticate_spool_journal(
        self,
        *,
        expected_digest: str | None = None,
        expected_bytes: int | None = None,
        maximum_bytes: int | None = None,
    ) -> int:
        """Authenticate the anonymous journal or one completed prefix."""

        stream = self._spool_stream
        identity = self._spool_identity
        if stream is None or identity is None:
            if (expected_bytes or self._spool_bytes) == 0:
                return 0
            raise ExactPublicationError("Syslog anonymous journal descriptor is missing")
        descriptor = self._verify_anonymous_stream(stream, identity, label="private spool")
        current_size = int(_secure_fstat(descriptor).st_size)
        retained_bytes = self._spool_bytes if expected_bytes is None else expected_bytes
        retained_digest = self._spool_digest if expected_digest is None else expected_digest
        limit = retained_bytes if maximum_bytes is None else maximum_bytes
        if (
            retained_bytes < 0
            or retained_bytes > self._spool_total_byte_capacity
            or limit < retained_bytes
            or limit > self._spool_total_byte_capacity
            or current_size < retained_bytes
            or current_size > limit
        ):
            raise ExactPublicationError("Syslog anonymous journal size metadata changed")
        if self._descriptor_prefix_digest(descriptor, retained_bytes) != retained_digest:
            raise ExactPublicationError("Syslog anonymous journal prefix changed")
        after = _secure_fstat(descriptor)
        if (
            self._filesystem_identity(after) != identity
            or int(after.st_size) != current_size
            or int(after.st_nlink) != 0
        ):
            raise ExactPublicationError("Syslog anonymous journal identity or size changed")
        return current_size

    def _ensure_spool_stream(self, *, allow_zero_recovery: bool) -> int:
        if self._spool_stream is not None:
            try:
                return self._verify_anonymous_stream(
                    self._spool_stream,
                    self._spool_identity or (-1, -1),
                    label="private spool",
                )
            except ExactPublicationError:
                if not allow_zero_recovery or self._spool_bytes or self._spool_receipts:
                    raise
                try:
                    _retire_descriptor_owner(self._spool_stream, label="private spool")
                except ExactPublicationError:
                    if not _descriptor_owner_is_closed(
                        self._spool_stream,
                        label="private spool",
                    ):
                        raise
                self._spool_stream = None
                self._spool_identity = None
        if self._spool_bytes or self._spool_receipts:
            raise ExactPublicationError("Syslog anonymous journal descriptor disappeared")
        stream, identity = self._new_anonymous_descriptor_owner(label="private spool")
        self._spool_stream = stream
        self._spool_identity = identity
        return _descriptor_owner_snapshot(stream, label="private spool")[0]

    def _invalidate_spool_snapshot(self) -> None:
        if self._spool_snapshot is not None:
            if _stream_is_closed(self._spool_snapshot) and not self._spool_snapshot_close_started:
                raise ExactPublicationError(
                    "Syslog private spool snapshot closed without retirement ownership"
                )
            self._spool_snapshot_close_started = True
            self._close_retained_stream(
                self._spool_snapshot,
                close_started=self._spool_snapshot_close_started,
                label="private spool snapshot",
            )
        self._spool_snapshot = None
        self._spool_snapshot_identity = None
        self._spool_snapshot_close_started = False

    def _ensure_spool_snapshot(self) -> int | None:
        """Freeze authenticated journal bytes in a second anonymous descriptor."""

        if self._spool_bytes == 0:
            if self._spool_receipts:
                raise ExactPublicationError("Syslog anonymous journal receipt is invalid")
            return None
        self._authenticate_spool_journal()
        source = self._verify_anonymous_stream(
            self._spool_stream,
            self._spool_identity or (-1, -1),
            label="private spool",
            expected_bytes=self._spool_bytes,
        )
        if self._spool_snapshot is not None:
            snapshot = self._verify_anonymous_stream(
                self._spool_snapshot,
                self._spool_snapshot_identity or (-1, -1),
                label="private spool snapshot",
                expected_bytes=self._spool_bytes,
            )
            digest, payload_bytes = self._descriptor_digest(snapshot)
            if digest != self._spool_digest or payload_bytes != self._spool_bytes:
                raise ExactPublicationError("Syslog anonymous journal snapshot changed")
            return snapshot

        stream, identity = self._new_anonymous_stream(label="private spool snapshot")
        descriptor = _stream_descriptor(stream)
        try:
            retained = 0
            while retained < self._spool_bytes:
                chunk = _secure_pread(
                    source,
                    min(_IO_CHUNK_BYTES, self._spool_bytes - retained),
                    retained,
                )
                if not chunk:
                    raise ExactPublicationError("Syslog anonymous journal changed while copying")
                self._write_descriptor(descriptor, chunk)
                retained += len(chunk)
            _stream_flush(stream)
            _secure_fsync(descriptor)
            digest, payload_bytes = self._descriptor_digest(descriptor)
            if digest != self._spool_digest or payload_bytes != self._spool_bytes:
                raise ExactPublicationError("Syslog anonymous journal snapshot changed")
            self._authenticate_spool_journal()
        except BaseException:
            _stream_close(stream)
            raise
        self._spool_snapshot = stream
        self._spool_snapshot_identity = identity
        return descriptor

    def _new_spool_append(
        self,
        route_key: str,
        writer: Any,
    ) -> _SyslogSpoolAppend:
        records = tuple(writer.buffer)
        if not records:
            raise ExactPublicationError("Syslog anonymous journal append has no records")
        if self._spool_appends and route_key not in self._spool_appends:
            raise ExactPublicationError("Syslog anonymous journal has a foreign pending append")
        self._ensure_spool_stream(allow_zero_recovery=True)
        self._authenticate_spool_journal()
        receipt = self._spool_receipts.get(route_key)
        previous_head = -1 if receipt is None else receipt.head_offset
        prior_route_bytes = 0 if receipt is None else receipt.payload_bytes
        prior_record_count = 0 if receipt is None else receipt.record_count
        prior_extent_count = 0 if receipt is None else receipt.extent_count
        if prior_record_count + len(records) > self._spool_route_row_capacity:
            raise ExactPublicationError("Syslog private spool row capacity is exhausted")
        payload_digest_state = _secure_sha256()
        payload_bytes = 0
        for frame in self._encoded_spool_frames(records):
            payload_digest_state.update(frame)
            payload_bytes += len(frame)
            if prior_route_bytes + payload_bytes > self._spool_route_byte_capacity:
                raise ExactPublicationError("Syslog private spool byte capacity is exhausted")
        if self._spool_record_count + len(records) > self._spool_total_row_capacity:
            raise ExactPublicationError("Syslog total private spool row capacity is exhausted")
        payload_digest = payload_digest_state.hexdigest()
        header_payload = {
            "payload_bytes": payload_bytes,
            "payload_digest": payload_digest,
            "previous": previous_head,
            "record_count": len(records),
            "route": route_key,
            "version": 1,
        }
        header = (
            _secure_json_dumps(
                header_payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        if len(header) > _SPOOL_EXTENT_HEADER_BYTE_CAPACITY:
            raise ExactPublicationError("Syslog private spool extent header is too large")
        expected_bytes = self._spool_bytes + len(header) + payload_bytes
        if expected_bytes > self._spool_total_byte_capacity:
            raise ExactPublicationError("Syslog total private spool byte capacity is exhausted")
        if self._spool_hash_state.hexdigest() != self._spool_digest:
            raise ExactPublicationError("Syslog anonymous journal digest state changed")
        expected_state = self._spool_hash_state.copy()
        expected_state.update(header)
        for frame in self._encoded_spool_frames(records):
            expected_state.update(frame)
        pending = _SyslogSpoolAppend(
            writer=writer,
            records=records,
            offset=self._spool_bytes,
            header=header,
            payload_bytes=payload_bytes,
            record_count=len(records),
            previous_head=previous_head,
            prior_route_bytes=prior_route_bytes,
            prior_record_count=prior_record_count,
            prior_extent_count=prior_extent_count,
            prior_global_record_count=self._spool_record_count,
            prior_global_extent_count=self._spool_extent_count,
            prior_digest=self._spool_digest,
            expected_digest=expected_state.hexdigest(),
            expected_bytes=expected_bytes,
            expected_hash_state=expected_state,
            payload_digest=payload_digest,
        )
        self._spool_appends[route_key] = pending
        return pending

    def _complete_spool_append(
        self,
        route_key: str,
        writer: Any,
        pending: _SyslogSpoolAppend,
    ) -> None:
        if pending.writer is not writer:
            raise ExactPublicationError("Syslog anonymous journal writer changed during retry")
        payload_digest = _secure_sha256()
        payload_bytes = 0
        for frame in self._encoded_spool_frames(pending.records):
            payload_digest.update(frame)
            payload_bytes += len(frame)
        if (
            payload_bytes != pending.payload_bytes
            or payload_digest.hexdigest() != pending.payload_digest
        ):
            raise ExactPublicationError("Syslog anonymous journal payload changed during retry")
        receipt = self._spool_receipts.get(route_key)
        expected_receipt = _SyslogSpoolReceipt(
            head_offset=pending.offset,
            payload_bytes=pending.prior_route_bytes + pending.payload_bytes,
            record_count=pending.prior_record_count + pending.record_count,
            extent_count=pending.prior_extent_count + 1,
        )
        receipt_is_expected = bool(
            receipt == expected_receipt
            and self._spool_digest == pending.expected_digest
            and self._spool_bytes == pending.expected_bytes
            and self._spool_record_count == pending.prior_global_record_count + pending.record_count
            and self._spool_extent_count == pending.prior_global_extent_count + 1
        )
        if receipt_is_expected:
            if self._spool_hash_state.hexdigest() != pending.expected_digest:
                raise ExactPublicationError("Syslog anonymous journal receipt state changed")
        else:
            prior_receipt = None
            if pending.prior_extent_count:
                prior_receipt = _SyslogSpoolReceipt(
                    head_offset=pending.previous_head,
                    payload_bytes=pending.prior_route_bytes,
                    record_count=pending.prior_record_count,
                    extent_count=pending.prior_extent_count,
                )
            if (
                receipt != prior_receipt
                or self._spool_digest != pending.prior_digest
                or self._spool_bytes != pending.offset
                or self._spool_record_count != pending.prior_global_record_count
                or self._spool_extent_count != pending.prior_global_extent_count
                or self._spool_hash_state.hexdigest() != pending.prior_digest
            ):
                raise ExactPublicationError("Syslog anonymous journal prior receipt changed")

        descriptor = self._ensure_spool_stream(allow_zero_recovery=pending.offset == 0)
        if receipt_is_expected:
            current_size = self._authenticate_spool_journal()
        else:
            current_size = self._authenticate_spool_journal(
                expected_digest=pending.prior_digest,
                expected_bytes=pending.offset,
                maximum_bytes=pending.expected_bytes,
            )
            suffix_bytes = current_size - pending.offset
            if not self._descriptor_suffix_matches_pending(
                descriptor,
                offset=pending.offset,
                retained_bytes=suffix_bytes,
                pending=pending,
            ):
                raise ExactPublicationError(
                    "Syslog anonymous journal append found conflicting bytes"
                )
            if current_size != pending.expected_bytes:
                self._write_pending_suffix(descriptor, pending, suffix_bytes)
        _secure_fsync(descriptor)
        digest, retained_bytes = self._descriptor_digest(descriptor)
        if digest != pending.expected_digest or retained_bytes != pending.expected_bytes:
            raise ExactPublicationError("Syslog anonymous journal append changed")
        self._verify_anonymous_stream(
            self._spool_stream,
            self._spool_identity or (-1, -1),
            label="private spool",
            expected_bytes=pending.expected_bytes,
        )

        self._spool_hash_state = pending.expected_hash_state.copy()
        self._spool_digest = pending.expected_digest
        self._spool_bytes = pending.expected_bytes
        self._spool_record_count = pending.prior_global_record_count + pending.record_count
        self._spool_extent_count = pending.prior_global_extent_count + 1
        self._spool_receipts[route_key] = expected_receipt
        self._invalidate_spool_snapshot()

        if not self._spool_records_match_prefix(writer.buffer, pending.records):
            raise ExactPublicationError(
                "Syslog anonymous journal source buffer changed during retry"
            )
        if self._spool_appends.get(route_key) is not pending:
            raise ExactPublicationError("Syslog anonymous journal append ownership changed")
        del writer.buffer[: len(pending.records)]
        self._spool_appends.pop(route_key)

    def _spool_writer_records(self, route_key: str, writer: Any) -> None:
        pending = self._spool_appends.get(route_key)
        if pending is not None:
            self._complete_spool_append(route_key, writer, pending)
        if writer.buffer:
            pending = self._new_spool_append(route_key, writer)
            self._complete_spool_append(route_key, writer, pending)

    def _encode_spool_record(self, rendered: str) -> str:
        """Frame one logical record, preserving exact ownership and embedded CRLF."""

        if type(rendered) is not _ExactSyslogLine:
            if type(rendered) is _RoutedSyslogLine:
                payload = {
                    "line": str(rendered),
                    "logical_route": rendered._logical_route_key,
                    "version": 2,
                }
                return _secure_json_dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            if type(rendered) is not str:
                raise ExactPublicationError("Syslog spool record must be one exact string")
            return _secure_json_dumps(rendered, ensure_ascii=False)
        key = rendered._exact_key
        with self._file_lock:
            retained = self._exact_syslog_candidates.get(key)
            if retained is None:
                raise ExactPublicationError("Exact Syslog spool marker is foreign or stale")
            self._validate_retained_candidate_unlocked(key, retained)
            if retained.marker is not rendered or not retained.installed:
                raise ExactPublicationError("Exact Syslog spool marker is foreign or stale")
            payload = {
                "digest": retained.digest,
                "key": [key[0], key[1], key[2]],
                "line": str(rendered),
                "logical_route": retained.logical_route_key,
                "version": 2,
            }
        return _secure_json_dumps(
            payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )

    @classmethod
    def _validate_retained_candidate_unlocked(
        cls,
        key: ExactPublicationKey,
        retained: _ExactSyslogCandidate,
    ) -> None:
        """Recompute immutable candidate truth before any terminal publication."""

        writer_route_key, logical_route_key, rendered = cls._decode_exact_candidate(retained.frozen)
        digest = _secure_sha256(retained.frozen.encode()).hexdigest()
        if (
            retained.digest != digest
            or retained.writer_route_key != writer_route_key
            or retained.logical_route_key != logical_route_key
            or type(retained.marker) is not _ExactSyslogLine
            or retained.marker._exact_key != key
            or retained.marker._logical_route_key != logical_route_key
            or str(retained.marker) != rendered
        ):
            raise ExactPublicationError("Exact Syslog retained candidate changed")

    @staticmethod
    def _validate_logical_route_key(logical_route_key: str, *, label: str) -> None:
        """Reject unbounded or non-canonical logical source route keys."""

        if (
            len(logical_route_key.encode("utf-8")) > 4_096
            or sanitize_syslog_family_route_key(logical_route_key) != logical_route_key
        ):
            raise ExactPublicationError(f"Syslog {label} logical route is invalid")

    def _decode_spool_record(
        self,
        encoded: str,
        route_key: str,
        matched: set[ExactPublicationKey] | None,
    ) -> _RoutedSyslogLine:
        """Decode and authenticate one record-framed private spool entry."""

        try:
            payload = _secure_json_loads(encoded)
        except (TypeError, ValueError) as exc:
            raise ExactPublicationError("Syslog private spool record is invalid") from exc
        if type(payload) is str:
            return _RoutedSyslogLine(payload, route_key)
        if type(payload) is dict and set(payload) == {"line", "logical_route", "version"}:
            if (
                payload["version"] != 2
                or type(payload["version"]) is not int
                or type(payload["line"]) is not str
                or type(payload["logical_route"]) is not str
            ):
                raise ExactPublicationError("Ordinary Syslog private spool types are invalid")
            self._validate_logical_route_key(
                payload["logical_route"],
                label="private spool",
            )
            return _RoutedSyslogLine(payload["line"], payload["logical_route"])
        if type(payload) is not dict or set(payload) != {
            "digest",
            "key",
            "line",
            "logical_route",
            "version",
        }:
            raise ExactPublicationError("Exact Syslog private spool fields are invalid")
        raw_key = payload["key"]
        if (
            payload["version"] != 2
            or type(payload["version"]) is not int
            or type(raw_key) is not list
            or len(raw_key) != 3
            or type(raw_key[0]) is not str
            or type(raw_key[1]) is not int
            or type(raw_key[2]) is not int
            or type(payload["digest"]) is not str
            or type(payload["line"]) is not str
            or type(payload["logical_route"]) is not str
        ):
            raise ExactPublicationError("Exact Syslog private spool types are invalid")
        self._validate_logical_route_key(
            payload["logical_route"],
            label="private spool",
        )
        key: ExactPublicationKey = (raw_key[0], raw_key[1], raw_key[2])
        with self._file_lock:
            retained = self._exact_syslog_candidates.get(key)
            if retained is None:
                raise ExactPublicationError("Exact Syslog private spool record changed")
            self._validate_retained_candidate_unlocked(key, retained)
            if (
                not retained.installed
                or not retained.released
                or retained.writer_route_key != route_key
                or retained.logical_route_key != payload["logical_route"]
                or retained.digest != payload["digest"]
                or str(retained.marker) != payload["line"]
            ):
                raise ExactPublicationError("Exact Syslog private spool record changed")
        if matched is not None:
            if key in matched:
                raise ExactPublicationError("Exact Syslog candidate appears more than once")
            matched.add(key)
        return _RoutedSyslogLine(payload["line"], payload["logical_route"])

    def _decode_buffer_record(
        self,
        rendered: str,
        route_key: str,
        matched: set[ExactPublicationKey] | None,
    ) -> _RoutedSyslogLine:
        """Authenticate an in-memory exact marker or return one ordinary record."""

        if type(rendered) is not _ExactSyslogLine:
            if type(rendered) is _RoutedSyslogLine:
                return rendered
            if type(rendered) is not str:
                raise ExactPublicationError("Syslog buffer record must be one exact string")
            return _RoutedSyslogLine(rendered, route_key)
        key = rendered._exact_key
        with self._file_lock:
            retained = self._exact_syslog_candidates.get(key)
            if retained is None:
                raise ExactPublicationError("Exact Syslog buffer marker changed")
            self._validate_retained_candidate_unlocked(key, retained)
            if (
                retained.marker is not rendered
                or not retained.installed
                or not retained.released
                or retained.writer_route_key != route_key
                or retained.logical_route_key != rendered._logical_route_key
            ):
                raise ExactPublicationError("Exact Syslog buffer marker changed")
        if matched is not None:
            if key in matched:
                raise ExactPublicationError("Exact Syslog candidate appears more than once")
            matched.add(key)
        return _RoutedSyslogLine(str(rendered), retained.logical_route_key)

    @staticmethod
    def _read_frame_at(
        descriptor: int,
        offset: int,
        *,
        capacity: int,
        journal_bytes: int,
    ) -> tuple[bytes, int]:
        """Read one bounded newline frame with positional descriptor reads."""

        if offset < 0 or offset >= journal_bytes:
            raise ExactPublicationError("Syslog anonymous journal extent offset is invalid")
        frame = bytearray()
        position = offset
        while position < journal_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, journal_bytes - position),
                position,
            )
            if not chunk:
                raise ExactPublicationError("Syslog anonymous journal extent disappeared")
            newline = chunk.find(b"\n")
            retained = chunk if newline < 0 else chunk[:newline]
            if len(frame) + len(retained) + 1 > capacity:
                raise ExactPublicationError("Syslog anonymous journal frame capacity is exhausted")
            frame.extend(retained)
            if newline >= 0:
                return bytes(frame), position + newline + 1
            position += len(chunk)
        raise ExactPublicationError("Syslog anonymous journal frame is not newline framed")

    def _scan_extent_payload(
        self,
        descriptor: int,
        *,
        offset: int,
        payload_bytes: int,
        expected_records: int,
        expected_digest: str,
    ) -> None:
        """Authenticate one entire extent before any of its JSON records decode."""

        digest = _secure_sha256()
        record_count = 0
        pending_record_bytes = 0
        retained = 0
        while retained < payload_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, payload_bytes - retained),
                offset + retained,
            )
            if not chunk:
                raise ExactPublicationError("Syslog anonymous journal extent payload disappeared")
            digest.update(chunk)
            retained += len(chunk)
            parts = chunk.split(b"\n")
            for part in parts[:-1]:
                pending_record_bytes += len(part) + 1
                if pending_record_bytes > self._spool_record_byte_capacity:
                    raise ExactPublicationError("Syslog private spool record capacity is exhausted")
                record_count += 1
                pending_record_bytes = 0
            pending_record_bytes += len(parts[-1])
            if pending_record_bytes > self._spool_record_byte_capacity:
                raise ExactPublicationError("Syslog private spool record capacity is exhausted")
        if (
            pending_record_bytes
            or record_count != expected_records
            or digest.hexdigest() != expected_digest
        ):
            raise ExactPublicationError("Syslog anonymous journal extent content changed")

    def _iter_extent_payload_frames(
        self,
        descriptor: int,
        *,
        offset: int,
        payload_bytes: int,
    ) -> Iterator[bytes]:
        """Yield already-authenticated payload frames with bounded resident memory."""

        pending = bytearray()
        retained = 0
        while retained < payload_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, payload_bytes - retained),
                offset + retained,
            )
            if not chunk:
                raise ExactPublicationError("Syslog anonymous journal extent payload disappeared")
            retained += len(chunk)
            parts = chunk.split(b"\n")
            pending.extend(parts[0])
            for part in parts[1:]:
                if len(pending) + 1 > self._spool_record_byte_capacity:
                    raise ExactPublicationError("Syslog private spool record capacity is exhausted")
                yield bytes(pending)
                pending = bytearray(part)
            if len(pending) > self._spool_record_byte_capacity:
                raise ExactPublicationError("Syslog private spool record capacity is exhausted")
        if pending:
            raise ExactPublicationError("Syslog anonymous journal record is not newline framed")

    def _iter_spooled_route_lines(
        self,
        route_key: str,
        receipt: _SyslogSpoolReceipt,
        matched: set[ExactPublicationKey] | None,
    ) -> Iterator[_RoutedSyslogLine]:
        if (
            receipt.head_offset < 0
            or receipt.head_offset >= self._spool_bytes
            or receipt.payload_bytes <= 0
            or receipt.payload_bytes > self._spool_route_byte_capacity
            or receipt.record_count <= 0
            or receipt.record_count > self._spool_route_row_capacity
            or receipt.extent_count <= 0
            or receipt.extent_count > self._spool_extent_count
        ):
            raise ExactPublicationError("Syslog anonymous journal route receipt changed")
        descriptor = self._ensure_spool_snapshot()
        if descriptor is None:
            raise ExactPublicationError("Syslog anonymous journal receipt has no payload")
        offset = receipt.head_offset
        extent_count = 0
        record_count = 0
        payload_bytes = 0
        while offset != -1:
            header_frame, payload_offset = self._read_frame_at(
                descriptor,
                offset,
                capacity=_SPOOL_EXTENT_HEADER_BYTE_CAPACITY,
                journal_bytes=self._spool_bytes,
            )
            try:
                header = _secure_json_loads(header_frame)
            except (UnicodeDecodeError, ValueError) as error:
                raise ExactPublicationError(
                    "Syslog anonymous journal extent header is invalid"
                ) from error
            if type(header) is not dict or set(header) != {
                "payload_bytes",
                "payload_digest",
                "previous",
                "record_count",
                "route",
                "version",
            }:
                raise ExactPublicationError("Syslog anonymous journal extent header changed")
            if (
                type(header["payload_bytes"]) is not int
                or type(header["payload_digest"]) is not str
                or type(header["previous"]) is not int
                or type(header["record_count"]) is not int
                or type(header["route"]) is not str
                or type(header["version"]) is not int
                or header["version"] != 1
                or header["route"] != route_key
                or not re.fullmatch(r"[0-9a-f]{64}", header["payload_digest"])
            ):
                raise ExactPublicationError("Syslog anonymous journal extent header changed")
            extent_bytes = header["payload_bytes"]
            extent_records = header["record_count"]
            previous = header["previous"]
            if (
                extent_bytes < 0
                or extent_records <= 0
                or extent_bytes > self._spool_route_byte_capacity
                or extent_records > self._spool_route_row_capacity
                or payload_offset + extent_bytes > self._spool_bytes
                or (previous != -1 and (previous < 0 or previous >= offset))
            ):
                raise ExactPublicationError("Syslog anonymous journal extent bounds changed")
            next_bytes = payload_bytes + extent_bytes
            next_records = record_count + extent_records
            next_extents = extent_count + 1
            if (
                next_bytes > self._spool_route_byte_capacity
                or next_records > self._spool_route_row_capacity
                or next_extents > self._spool_extent_count
            ):
                raise ExactPublicationError("Syslog anonymous journal route capacity changed")
            self._scan_extent_payload(
                descriptor,
                offset=payload_offset,
                payload_bytes=extent_bytes,
                expected_records=extent_records,
                expected_digest=header["payload_digest"],
            )
            decoded_records = 0
            for encoded_bytes in self._iter_extent_payload_frames(
                descriptor,
                offset=payload_offset,
                payload_bytes=extent_bytes,
            ):
                try:
                    encoded = encoded_bytes.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise ExactPublicationError(
                        "Syslog private spool record is not valid UTF-8"
                    ) from error
                decoded_records += 1
                yield self._decode_spool_record(encoded, route_key, matched)
            if decoded_records != extent_records:
                raise ExactPublicationError("Syslog anonymous journal extent row count changed")
            payload_bytes = next_bytes
            record_count = next_records
            extent_count = next_extents
            offset = previous
        if (
            payload_bytes != receipt.payload_bytes
            or record_count != receipt.record_count
            or extent_count != receipt.extent_count
        ):
            raise ExactPublicationError("Syslog anonymous journal route receipt changed")

    def _iter_route_lines(
        self,
        route_key: str,
        writer: Any,
        matched: set[ExactPublicationKey] | None,
    ) -> Iterator[_RoutedSyslogLine]:
        """Stream logical records without consuming their retryable private truth."""

        with writer._lock:
            pending = self._spool_appends.get(route_key)
            if pending is not None:
                self._complete_spool_append(route_key, writer, pending)
            receipt = self._spool_receipts.get(route_key)
            if receipt is not None:
                yield from self._iter_spooled_route_lines(route_key, receipt, matched)
            for rendered in writer.buffer:
                yield self._decode_buffer_record(rendered, route_key, matched)

    def _load_route_lines(
        self,
        route_key: str,
        writer: Any,
        matched: set[ExactPublicationKey] | None,
    ) -> list[_RoutedSyslogLine]:
        """Compatibility wrapper returning one authenticated route as a list."""

        return list(self._iter_route_lines(route_key, writer, matched))

    def _write_terminal_run(
        self,
        lines: Iterator[str],
        *,
        record_byte_capacity: int,
        row_capacity: int,
        byte_capacity: int,
    ) -> _SyslogMergeRun:
        """Write one descriptor-pinned JSON-framed run under explicit bounds."""

        stream, run_identity = self._new_anonymous_stream(label="terminal merge run")
        digest = _secure_sha256()
        payload_bytes = 0
        record_count = 0
        try:
            descriptor = _stream_descriptor(stream)
            for line in lines:
                frame = self._terminal_run_frame(line, capacity=record_byte_capacity)
                if record_count + 1 > row_capacity:
                    raise ExactPublicationError("Syslog terminal merge row capacity is exhausted")
                if payload_bytes + len(frame) > byte_capacity:
                    raise ExactPublicationError("Syslog terminal merge byte capacity is exhausted")
                self._write_descriptor(descriptor, frame)
                digest.update(frame)
                payload_bytes += len(frame)
                record_count += 1
            _stream_flush(stream)
            _secure_fsync(descriptor)
            retained_digest, retained_bytes = self._descriptor_digest(descriptor)
            if retained_digest != digest.hexdigest() or retained_bytes != payload_bytes:
                raise ExactPublicationError("Syslog terminal merge run changed while writing")
            return _SyslogMergeRun(
                stream=stream,
                run_identity=run_identity,
                digest=digest.hexdigest(),
                payload_bytes=payload_bytes,
                record_count=record_count,
                record_byte_capacity=record_byte_capacity,
                row_capacity=row_capacity,
                byte_capacity=byte_capacity,
            )
        except BaseException:
            _stream_close(stream)
            raise

    def _new_terminal_run(self, lines: Iterator[str]) -> _SyslogMergeRun:
        """Write one descriptor-pinned final-record merge run."""

        return self._write_terminal_run(
            lines,
            record_byte_capacity=self._spool_record_byte_capacity,
            row_capacity=self._spool_route_row_capacity,
            byte_capacity=self._spool_route_byte_capacity,
        )

    def _direct_partition_capacities(self) -> tuple[int, int, int]:
        metadata_bytes = 8_704
        return (
            (3 * self._spool_record_byte_capacity) + metadata_bytes,
            self._spool_route_row_capacity,
            (3 * self._spool_route_byte_capacity)
            + (self._spool_route_row_capacity * metadata_bytes),
        )

    def _new_direct_partition_run(self, lines: Iterator[str]) -> _SyslogMergeRun:
        """Write bounded logical-host partition records with framing overhead."""

        record_byte_capacity, row_capacity, byte_capacity = self._direct_partition_capacities()
        return self._write_terminal_run(
            lines,
            record_byte_capacity=record_byte_capacity,
            row_capacity=row_capacity,
            byte_capacity=byte_capacity,
        )

    def _terminal_run_frame(self, line: str, *, capacity: int | None = None) -> bytes:
        """Return one bounded terminal-run frame exactly as the merge writer emits it."""

        frame = _secure_json_dumps(line, ensure_ascii=False).encode("utf-8") + b"\n"
        limit = self._spool_record_byte_capacity if capacity is None else capacity
        if len(frame) > limit:
            raise ExactPublicationError("Syslog terminal merge record capacity is exhausted")
        return frame

    def _authenticate_terminal_run(self, retained: _SyslogMergeRun) -> None:
        """Authenticate an entire transient run before any record decode."""

        capacities = (
            retained.record_byte_capacity,
            retained.row_capacity,
            retained.byte_capacity,
        )
        expected_final = (
            self._spool_record_byte_capacity,
            self._spool_route_row_capacity,
            self._spool_route_byte_capacity,
        )
        if (
            capacities not in {expected_final, self._direct_partition_capacities()}
            or type(retained.record_count) is not int
            or retained.record_count < 0
            or retained.record_count > retained.row_capacity
            or type(retained.payload_bytes) is not int
            or retained.payload_bytes < 0
            or retained.payload_bytes > retained.byte_capacity
            or type(retained.digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", retained.digest) is None
        ):
            raise ExactPublicationError("Syslog terminal merge run capacities changed")
        descriptor = self._verify_anonymous_stream(
            retained.stream,
            retained.run_identity,
            label="terminal merge run",
            expected_bytes=retained.payload_bytes,
        )
        digest, payload_bytes = self._descriptor_digest(descriptor)
        if digest != retained.digest or payload_bytes != retained.payload_bytes:
            raise ExactPublicationError("Syslog terminal merge run content changed")

    @staticmethod
    def _iter_terminal_run_frames(
        descriptor: int,
        *,
        payload_bytes: int,
        record_byte_capacity: int,
    ) -> Iterator[bytes]:
        """Read every run byte once while yielding bounded newline frames."""

        pending = bytearray()
        retained = 0
        while retained < payload_bytes:
            chunk = _secure_pread(
                descriptor,
                min(_IO_CHUNK_BYTES, payload_bytes - retained),
                retained,
            )
            if not chunk:
                raise ExactPublicationError("Syslog terminal merge run disappeared")
            retained += len(chunk)
            parts = chunk.split(b"\n")
            pending.extend(parts[0])
            for part in parts[1:]:
                if len(pending) + 1 > record_byte_capacity:
                    raise ExactPublicationError(
                        "Syslog terminal merge record capacity is exhausted"
                    )
                yield bytes(pending)
                pending = bytearray(part)
            if len(pending) + 1 > record_byte_capacity:
                raise ExactPublicationError("Syslog terminal merge record capacity is exhausted")
        if pending:
            raise ExactPublicationError("Syslog terminal merge run is not framed")

    def _iter_terminal_run(self, retained: _SyslogMergeRun) -> Iterator[str]:
        """Yield one authenticated transient run without splitting embedded CRLF."""

        self._authenticate_terminal_run(retained)
        descriptor = _stream_descriptor(retained.stream)
        record_count = 0
        for frame in self._iter_terminal_run_frames(
            descriptor,
            payload_bytes=retained.payload_bytes,
            record_byte_capacity=retained.record_byte_capacity,
        ):
            try:
                line = _secure_json_loads(frame)
            except (UnicodeDecodeError, ValueError) as error:
                raise ExactPublicationError(
                    "Syslog terminal merge run record is invalid"
                ) from error
            if type(line) is not str:
                raise ExactPublicationError("Syslog terminal merge run record is invalid")
            record_count += 1
            if record_count > retained.row_capacity:
                raise ExactPublicationError("Syslog terminal merge row capacity is exhausted")
            yield line
        if record_count != retained.record_count:
            raise ExactPublicationError("Syslog terminal merge run row count changed")
        self._authenticate_terminal_run(retained)

    def _merge_terminal_runs(
        self,
        runs: tuple[_SyslogMergeRun, ...],
        *,
        sort_key: Callable[[str], Any] | None = None,
    ) -> _SyslogMergeRun:
        """Merge one configured-width group with bounded descriptors and heap state."""

        if len(runs) < 2 or len(runs) > self._terminal_merge_fan_in:
            raise ExactPublicationError("Syslog terminal merge fan-in changed")
        capacities = {
            (run.record_byte_capacity, run.row_capacity, run.byte_capacity) for run in runs
        }
        if len(capacities) != 1:
            raise ExactPublicationError("Syslog terminal merge run capacities changed")
        record_byte_capacity, row_capacity, byte_capacity = next(iter(capacities))
        iterators = tuple(self._iter_terminal_run(retained) for retained in runs)
        try:
            merged = heapq.merge(*iterators, key=self._sort_key if sort_key is None else sort_key)
            return self._write_terminal_run(
                merged,
                record_byte_capacity=record_byte_capacity,
                row_capacity=row_capacity,
                byte_capacity=byte_capacity,
            )
        finally:
            for lines in iterators:
                lines.close()

    @staticmethod
    def _close_terminal_run(retained: _SyslogMergeRun) -> None:
        """Retire one anonymous run through an idempotent owned close phase."""

        if _stream_is_closed(retained.stream) and not retained.close_started:
            raise ExactPublicationError(
                "Syslog terminal merge run closed without retirement ownership"
            )
        retained.close_started = True
        SyslogEmitter._close_retained_stream(
            retained.stream,
            close_started=retained.close_started,
            label="terminal merge run",
        )

    @staticmethod
    def _close_terminal_runs(runs: Iterator[_SyslogMergeRun]) -> None:
        """Close every run supplied to one ownership cleanup boundary."""

        first_error: BaseException | None = None
        for retained in runs:
            try:
                SyslogEmitter._close_terminal_run(retained)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def _merge_and_retire_terminal_runs(
        self,
        runs: tuple[_SyslogMergeRun, ...],
        *,
        sort_key: Callable[[str], Any] | None,
    ) -> _SyslogMergeRun:
        """Create one retained merge before retiring all of its authenticated inputs."""

        merged = self._merge_terminal_runs(runs, sort_key=sort_key)
        try:
            self._close_terminal_runs(iter(runs))
        except BaseException:
            self._close_terminal_run(merged)
            raise
        return merged

    def _add_tiered_terminal_run(
        self,
        tiers: list[list[_SyslogMergeRun]],
        retained: _SyslogMergeRun,
        *,
        sort_key: Callable[[str], Any] | None = None,
    ) -> None:
        """Insert one run into a balanced base-fan-in carry tree."""

        carry = retained
        level = 0
        while True:
            if level == len(tiers):
                tiers.append([])
            bucket = tiers[level]
            bucket.append(carry)
            if len(bucket) < self._terminal_merge_fan_in:
                return
            inputs = tuple(bucket)
            merged = self._merge_and_retire_terminal_runs(inputs, sort_key=sort_key)
            bucket.clear()
            carry = merged
            level += 1

    def _finish_tiered_terminal_runs(
        self,
        tiers: list[list[_SyslogMergeRun]],
        *,
        sort_key: Callable[[str], Any] | None = None,
    ) -> _SyslogMergeRun | None:
        """Drain a carry tree with at most one merge per remaining tier."""

        carry: _SyslogMergeRun | None = None
        try:
            for bucket in tiers:
                if not bucket:
                    continue
                if carry is None and len(bucket) == 1:
                    carry = bucket.pop()
                    continue
                inputs = tuple(bucket) + (() if carry is None else (carry,))
                if len(inputs) == 1:
                    carry = inputs[0]
                    bucket.clear()
                    continue
                merged = self._merge_and_retire_terminal_runs(inputs, sort_key=sort_key)
                bucket.clear()
                carry = merged
            return carry
        except BaseException:
            if carry is not None:
                self._close_terminal_run(carry)
            raise

    def _cleanup_tiered_terminal_runs(
        self,
        tiers: list[list[_SyslogMergeRun]],
    ) -> None:
        """Retire every run that remains owned by a failed carry tree."""

        self._close_terminal_runs(run for bucket in tiers for run in bucket)

    @staticmethod
    def _line_payload(line: str) -> bytes:
        payload = line.encode("utf-8")
        if not line.endswith("\n"):
            payload += b"\n"
        return payload

    @classmethod
    def _candidate_payload_identity(
        cls,
        line_factory: Callable[[], Iterator[str]],
    ) -> tuple[str, int]:
        digest = _secure_sha256()
        payload_bytes = 0
        for line in line_factory():
            payload = cls._line_payload(line)
            digest.update(payload)
            payload_bytes += len(payload)
        return digest.hexdigest(), payload_bytes

    def _prepare_final_candidate(
        self,
        route_key: str,
        writer: Any,
        line_factory: Callable[[], Iterator[str]],
    ) -> _SyslogFinalCandidate:
        """Freeze one normalized route payload in anonymous owner storage."""

        with self._file_lock:
            retained = self._final_candidates.get(route_key)
            if retained is not None:
                expected_digest, expected_bytes = self._candidate_payload_identity(line_factory)
                if (
                    retained.route_key != route_key
                    or retained.writer is not writer
                    or retained.output_path != writer.output_path
                    or retained.digest != expected_digest
                    or retained.payload_bytes != expected_bytes
                ):
                    raise ExactPublicationError("Syslog final route changed during retry")
                self._verify_final_candidate(retained)
                return retained
            for foreign_route, foreign in self._final_candidates.items():
                if foreign.output_path == writer.output_path:
                    raise ExactPublicationError(
                        f"Syslog routes share one physical output target: {foreign_route!r}"
                    )
        stream, candidate_identity = self._new_anonymous_stream(label="final candidate")
        descriptor = _stream_descriptor(stream)
        digest_state = _secure_sha256()
        payload_bytes = 0
        try:
            for line in line_factory():
                payload = self._line_payload(line)
                next_bytes = payload_bytes + len(payload)
                if next_bytes > self._spool_route_byte_capacity:
                    raise ExactPublicationError("Syslog final route byte capacity is exhausted")
                self._write_descriptor(descriptor, payload)
                digest_state.update(payload)
                payload_bytes = next_bytes
            _stream_flush(stream)
            _secure_fsync(descriptor)
            retained_digest, retained_bytes = self._descriptor_digest(descriptor)
            if retained_digest != digest_state.hexdigest() or retained_bytes != payload_bytes:
                raise ExactPublicationError("Syslog final candidate changed while writing")
            self._verify_anonymous_stream(
                stream,
                candidate_identity,
                label="final candidate",
                expected_bytes=payload_bytes,
            )
        except BaseException:
            _stream_close(stream)
            raise
        with self._file_lock:
            retained = self._final_candidates.get(route_key)
            if retained is not None:
                _stream_close(stream)
                raise ExactPublicationError("Syslog final route ownership changed")
            retained = _SyslogFinalCandidate(
                route_key=route_key,
                writer=writer,
                output_path=writer.output_path,
                stream=stream,
                candidate_identity=candidate_identity,
                digest=digest_state.hexdigest(),
                payload_bytes=payload_bytes,
            )
            self._final_candidates[route_key] = retained
            self._final_candidate_count += 1
            self._final_candidate_high_water = max(
                self._final_candidate_high_water,
                self._final_candidate_count,
            )
            return retained

    @classmethod
    def _verify_final_candidate(cls, retained: _SyslogFinalCandidate) -> None:
        descriptor = cls._verify_anonymous_stream(
            retained.stream,
            retained.candidate_identity,
            label="final candidate",
            expected_bytes=retained.payload_bytes,
        )
        digest, payload_bytes = cls._descriptor_digest(descriptor)
        if digest != retained.digest or payload_bytes != retained.payload_bytes:
            raise ExactPublicationError("Syslog final candidate content changed")

    @classmethod
    def _public_file_digest(
        cls,
        path: Path,
        *,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _read_only: int = _SYSLOG_SECURITY_REGISTRY.o_rdonly,
        _nofollow: int = _SYSLOG_SECURITY_REGISTRY.nofollow,
    ) -> tuple[str, int]:
        parent_descriptor, parent_identity = cls._open_output_parent(path, create=False)
        try:
            descriptor = _secure_open(
                path.name,
                _read_only | _nofollow,
                dir_fd=parent_descriptor,
            )
        except OSError as error:
            _secure_close(parent_descriptor)
            raise ExactPublicationError("Syslog final output cannot be opened safely") from error
        try:
            identity = cls._authenticate_public_descriptor(descriptor, None)
            cls._authenticate_public_entry(
                path,
                parent_descriptor,
                parent_identity,
                descriptor,
                identity,
            )
            digest, payload_bytes = cls._descriptor_digest(descriptor)
            return digest, payload_bytes
        finally:
            _secure_close(descriptor)
            _secure_close(parent_descriptor)

    @classmethod
    def _verify_public_candidate(
        cls,
        retained: _SyslogPublicProof,
        *,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _read_only: int = _SYSLOG_SECURITY_REGISTRY.o_rdonly,
        _nofollow: int = _SYSLOG_SECURITY_REGISTRY.nofollow,
    ) -> None:
        parent_descriptor, parent_identity = cls._open_output_parent(
            retained.output_path,
            create=False,
            expected_identity=retained.parent_identity,
        )
        try:
            if retained.payload_bytes == 0:
                if retained.file_identity is not None:
                    raise ExactPublicationError("Empty Syslog route has a public file identity")
                try:
                    _secure_stat(
                        retained.output_path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    return
                raise ExactPublicationError("Empty Syslog route retained unexpected public bytes")
            if retained.file_identity is None:
                raise ExactPublicationError("Syslog public proof lost its file identity")
            try:
                descriptor = _secure_open(
                    retained.output_path.name,
                    _read_only | _nofollow,
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                raise ExactPublicationError(
                    "Syslog final output disappeared after publication"
                ) from error
            try:
                cls._authenticate_public_entry(
                    retained.output_path,
                    parent_descriptor,
                    parent_identity,
                    descriptor,
                    retained.file_identity,
                )
                digest, payload_bytes = cls._descriptor_digest(descriptor)
                if digest != retained.digest or payload_bytes != retained.payload_bytes:
                    raise ExactPublicationError("Syslog final output changed after publication")
            finally:
                _secure_close(descriptor)
        finally:
            _secure_close(parent_descriptor)

    @classmethod
    def _public_prefix_size(
        cls,
        retained: _SyslogFinalCandidate,
        append: _SyslogPublicAppend,
    ) -> int:
        """Authenticate the exact public prefix against the retained candidate."""

        cls._verify_final_candidate(retained)
        if append.parent_owner is None:
            raise ExactPublicationError("Syslog public append acquisition is incomplete")
        parent_descriptor, parent_identity = _descriptor_owner_snapshot(
            append.parent_owner,
            label="public parent",
        )
        descriptor, file_identity = _descriptor_owner_snapshot(
            append.descriptor_owner,
            label="public file",
        )
        if parent_identity != append.parent_identity:
            raise ExactPublicationError("Syslog public parent ownership changed")
        if append.file_identity is None or file_identity != append.file_identity:
            raise ExactPublicationError("Syslog public file ownership changed")
        cls._authenticate_public_entry(
            append.output_path,
            parent_descriptor,
            append.parent_identity,
            descriptor,
            append.file_identity,
        )
        current_size = int(_secure_fstat(descriptor).st_size)
        if current_size > retained.payload_bytes:
            raise ExactPublicationError("Syslog final output contains conflicting bytes")
        candidate_descriptor = _stream_descriptor(retained.stream)
        compared = 0
        while compared < current_size:
            count = min(_IO_CHUNK_BYTES, current_size - compared)
            public_chunk = _secure_pread(descriptor, count, compared)
            candidate_chunk = _secure_pread(candidate_descriptor, count, compared)
            if public_chunk != candidate_chunk or len(public_chunk) != count:
                raise ExactPublicationError("Syslog final output prefix changed during retry")
            compared += count
        return current_size

    def _acquire_public_parent(self, append: _SyslogPublicAppend) -> None:
        """Retain the pinned parent inside the acquisition phase before returning."""

        if append.parent_owner is not None:
            parent_descriptor, parent_identity = _descriptor_owner_snapshot(
                append.parent_owner,
                label="public parent",
            )
            if parent_identity != append.parent_identity:
                raise ExactPublicationError("Syslog public parent acquisition changed")
            self._authenticate_output_parent(
                append.output_path,
                parent_descriptor,
                append.parent_identity,
            )
            return
        parent_descriptor, parent_identity = self._open_output_parent(
            append.output_path,
            create=False,
            expected_identity=append.parent_identity,
        )
        try:
            parent_owner = _new_descriptor_owner(parent_descriptor, parent_identity)
        except BaseException:
            _secure_close(parent_descriptor)
            raise
        append.parent_owner = parent_owner
        if parent_identity != append.parent_identity:
            raise ExactPublicationError("Syslog public parent acquisition changed")

    @classmethod
    def _acquire_public_descriptor(
        cls,
        append: _SyslogPublicAppend,
        *,
        _registry: _SyslogSecurityRegistry = _SYSLOG_SECURITY_REGISTRY,
        _attest: Callable[
            [_SyslogSecurityRegistry], _SyslogSecurityRegistry
        ] = _SYSLOG_SECURITY_ATTESTATION,
        _owner_type: type[_SyslogDescriptorOwner] = _SYSLOG_SECURITY_REGISTRY.owner_type,
        _descriptor_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_descriptor_slot,
        _guard_descriptor_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_guard_descriptor_slot),
        _identity_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_identity_slot,
        _closed_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_closed_slot,
        _retirement_started_slot: object = (
            _SYSLOG_SECURITY_REGISTRY.owner_retirement_started_slot
        ),
        _lease_descriptors_slot: object = (_SYSLOG_SECURITY_REGISTRY.owner_lease_descriptors_slot),
        _lock_slot: object = _SYSLOG_SECURITY_REGISTRY.owner_lock_slot,
        _lock_type: type[Any] = _SYSLOG_SECURITY_REGISTRY.lock_type,
        _acquire: Callable[..., bool] = _SYSLOG_SECURITY_REGISTRY.lock_acquire,
        _release: Callable[..., None] = _SYSLOG_SECURITY_REGISTRY.lock_release,
        _open: Callable[..., int] = _SYSLOG_SECURITY_REGISTRY.os_open,
        _dup: Callable[[int], int] = _SYSLOG_SECURITY_REGISTRY.os_dup,
        _fstat: Callable[[int], os.stat_result] = _SYSLOG_SECURITY_REGISTRY.os_fstat,
        _get_inheritable: Callable[[int], bool] = (_SYSLOG_SECURITY_REGISTRY.os_get_inheritable),
        _get_blocking: Callable[[int], bool] = (_SYSLOG_SECURITY_REGISTRY.os_get_blocking),
        _set_blocking: Callable[[int, bool], None] = (_SYSLOG_SECURITY_REGISTRY.os_set_blocking),
        _isreg: Callable[[int], bool] = _SYSLOG_SECURITY_REGISTRY.stat_isreg,
        _read_write: int = _SYSLOG_SECURITY_REGISTRY.o_rdwr,
        _create: int = _SYSLOG_SECURITY_REGISTRY.o_creat,
        _exclusive: int = _SYSLOG_SECURITY_REGISTRY.o_excl,
        _nofollow: int = _SYSLOG_SECURITY_REGISTRY.nofollow,
        _private_mode: int = _SYSLOG_SECURITY_REGISTRY.private_file_mode,
    ) -> None:
        """Create and retain the no-replace public fd as one internal phase."""

        owner = append.descriptor_owner
        if type(owner) is not _owner_type:
            raise ExactPublicationError("Syslog public file owner type changed")
        if append.parent_owner is None:
            raise ExactPublicationError("Syslog public parent acquisition is incomplete")
        parent_descriptor, parent_identity = _descriptor_owner_snapshot(
            append.parent_owner,
            label="public parent",
        )
        if parent_identity != append.parent_identity:
            raise ExactPublicationError("Syslog public parent acquisition changed")
        lock = _lock_slot.__get__(owner, _owner_type)
        if type(lock) is not _lock_type:
            raise ExactPublicationError("Syslog public file owner lock changed")
        _acquire(lock)
        try:
            descriptor = _descriptor_slot.__get__(owner, _owner_type)
            guard_descriptor = _guard_descriptor_slot.__get__(owner, _owner_type)
            identity = _identity_slot.__get__(owner, _owner_type)
            closed = _closed_slot.__get__(owner, _owner_type)
            retirement_started = _retirement_started_slot.__get__(owner, _owner_type)
            lease_descriptors = _lease_descriptors_slot.__get__(owner, _owner_type)
            if (
                type(closed) is not bool
                or closed
                or type(retirement_started) is not bool
                or retirement_started
                or type(lease_descriptors) is not dict
            ):
                raise ExactPublicationError("Syslog public file owner retired before publication")
            if descriptor is None:
                if guard_descriptor is not None or identity is not None or lease_descriptors:
                    raise ExactPublicationError("Syslog public acquisition state changed")
                descriptor = _open(
                    append.output_path.name,
                    _read_write | _create | _exclusive | _nofollow,
                    _private_mode,
                    dir_fd=parent_descriptor,
                )
                if type(descriptor) is not int or descriptor < 0:
                    raise ExactPublicationError("Syslog public acquisition returned an invalid fd")
                _descriptor_slot.__set__(owner, descriptor)
                lease_descriptors["primary"] = descriptor
            elif type(descriptor) is not int or descriptor < 0:
                raise ExactPublicationError("Syslog public acquisition state changed")
            elif lease_descriptors.get("primary") != descriptor:
                raise ExactPublicationError("Syslog public acquisition lease map changed")
            try:
                metadata = _fstat(descriptor)
            except OSError as error:
                raise ExactPublicationError(
                    "Syslog final output descriptor identity changed"
                ) from error
            acquired_identity = (int(metadata.st_dev), int(metadata.st_ino))
            if (
                not _isreg(metadata.st_mode)
                or int(metadata.st_nlink) != 1
                or (identity is not None and identity != acquired_identity)
            ):
                raise ExactPublicationError("Syslog final output descriptor identity changed")
            _identity_slot.__set__(owner, acquired_identity)
            if _get_inheritable(descriptor):
                raise ExactPublicationError("Syslog final output descriptor is inheritable")
            if guard_descriptor is None:
                if set(lease_descriptors) != {"primary"}:
                    raise ExactPublicationError("Syslog public acquisition lease map changed")
                guard_descriptor = _dup(descriptor)
                if (
                    type(guard_descriptor) is not int
                    or guard_descriptor < 0
                    or guard_descriptor == descriptor
                ):
                    raise ExactPublicationError("Syslog public guard descriptor is invalid")
                _guard_descriptor_slot.__set__(owner, guard_descriptor)
                lease_descriptors["guard"] = guard_descriptor
            elif (
                type(guard_descriptor) is not int
                or guard_descriptor < 0
                or guard_descriptor == descriptor
            ):
                raise ExactPublicationError("Syslog public guard descriptor changed")
            if lease_descriptors != {
                "primary": descriptor,
                "guard": guard_descriptor,
            }:
                raise ExactPublicationError("Syslog public acquisition lease map changed")
            try:
                guard_metadata = _fstat(guard_descriptor)
            except OSError as error:
                raise ExactPublicationError("Syslog public guard descriptor changed") from error
            if (
                int(guard_metadata.st_dev),
                int(guard_metadata.st_ino),
            ) != acquired_identity or _get_inheritable(guard_descriptor):
                raise ExactPublicationError("Syslog public guard descriptor changed")
            blocking = _get_blocking(descriptor)
            if type(blocking) is not bool or _get_blocking(guard_descriptor) is not blocking:
                raise ExactPublicationError("Syslog public open-description ownership changed")
            _set_blocking(descriptor, not blocking)
            try:
                if _get_blocking(guard_descriptor) is blocking:
                    raise ExactPublicationError("Syslog public open-description ownership changed")
            finally:
                _set_blocking(descriptor, blocking)
                if (
                    _get_blocking(descriptor) is not blocking
                    or _get_blocking(guard_descriptor) is not blocking
                ):
                    raise ExactPublicationError(
                        "Syslog public open-description flags were not restored"
                    )
            append.file_identity = acquired_identity
        finally:
            _release(lock)

    def _publish_final_candidate(self, retained: _SyslogFinalCandidate) -> None:
        """Create once and resume only an authenticated descriptor-bound public prefix."""

        self._verify_final_candidate(retained)
        plan = self._route_plans.get(retained.route_key)
        if plan is None or (
            plan.writer is not retained.writer
            or plan.output_path != retained.output_path
            or plan.digest != retained.digest
            or plan.payload_bytes != retained.payload_bytes
        ):
            raise ExactPublicationError("Syslog final route has no matching preflight plan")
        if retained.payload_bytes == 0:
            return
        append = self._public_appends.get(retained.route_key)
        if append is None:
            append = _SyslogPublicAppend(
                writer=retained.writer,
                output_path=retained.output_path,
                candidate=retained,
                parent_owner=None,
                parent_identity=plan.parent_identity,
                descriptor_owner=_new_descriptor_owner(),
                file_identity=None,
                digest=retained.digest,
                payload_bytes=retained.payload_bytes,
            )
            self._public_appends[retained.route_key] = append
        elif (
            append.writer is not retained.writer
            or append.output_path != retained.output_path
            or append.candidate is not retained
            or append.digest != retained.digest
            or append.payload_bytes != retained.payload_bytes
            or append.parent_identity != plan.parent_identity
        ):
            raise ExactPublicationError("Syslog public append ownership changed during retry")

        self._acquire_public_parent(append)
        try:
            self._acquire_public_descriptor(append)
        except FileExistsError as error:
            raise ExactPublicationError("Syslog final output already exists") from error
        if append.parent_owner is None:
            raise ExactPublicationError("Syslog public append acquisition is incomplete")
        parent_descriptor, parent_identity = _descriptor_owner_snapshot(
            append.parent_owner,
            label="public parent",
        )
        descriptor, file_identity = _descriptor_owner_snapshot(
            append.descriptor_owner,
            label="public file",
        )
        if parent_identity != append.parent_identity:
            raise ExactPublicationError("Syslog public parent ownership changed")
        if append.file_identity is None or append.file_identity != file_identity:
            raise ExactPublicationError("Syslog public file ownership changed")
        self._authenticate_public_entry(
            retained.output_path,
            parent_descriptor,
            append.parent_identity,
            descriptor,
            append.file_identity,
        )
        _secure_fsync(parent_descriptor)

        current_size = self._public_prefix_size(retained, append)
        candidate_descriptor = _stream_descriptor(retained.stream)
        _secure_lseek(descriptor, current_size)
        retained_bytes = current_size
        while retained_bytes < retained.payload_bytes:
            chunk = _secure_pread(
                candidate_descriptor,
                min(_IO_CHUNK_BYTES, retained.payload_bytes - retained_bytes),
                retained_bytes,
            )
            if not chunk:
                raise ExactPublicationError("Syslog final candidate changed during publication")
            self._write_descriptor(descriptor, chunk)
            retained_bytes += len(chunk)
        _secure_fsync(descriptor)
        digest, payload_bytes = self._descriptor_digest(descriptor)
        if digest != retained.digest or payload_bytes != retained.payload_bytes:
            raise ExactPublicationError("Syslog final output changed during publication")
        self._verify_final_candidate(retained)
        _secure_fsync(parent_descriptor)
        if append.file_identity is None:
            raise ExactPublicationError("Syslog public append lost its file identity")
        self._authenticate_public_entry(
            retained.output_path,
            parent_descriptor,
            append.parent_identity,
            descriptor,
            append.file_identity,
        )

    def _retire_public_append(self, route_key: str, append: _SyslogPublicAppend) -> None:
        """Retire both public fds without forgetting a close lost return."""

        if append.file_identity is None or append.parent_owner is None:
            raise ExactPublicationError("Syslog public append acquisition is incomplete")
        descriptor_owner = append.descriptor_owner
        parent_owner = append.parent_owner
        descriptor_closed = _descriptor_owner_is_closed(descriptor_owner, label="public file")
        if not append.descriptor_close_started:
            if descriptor_closed:
                raise ExactPublicationError(
                    "Syslog public file closed without retirement ownership"
                )
            append.descriptor_close_started = True
        self._close_public_owner(descriptor_owner, label="public file")
        parent_closed = _descriptor_owner_is_closed(parent_owner, label="public parent")
        if not append.parent_close_started:
            if parent_closed:
                raise ExactPublicationError(
                    "Syslog public parent closed without retirement ownership"
                )
            append.parent_close_started = True
        self._close_public_owner(parent_owner, label="public parent")
        if self._public_appends.get(route_key) is not append:
            raise ExactPublicationError("Syslog public append retirement ownership changed")
        self._public_appends.pop(route_key)

    def _record_public_proof(
        self,
        route_key: str,
        retained: _SyslogFinalCandidate,
    ) -> _SyslogPublicProof:
        """Retain a path-independent proof before releasing publication descriptors."""

        plan = self._route_plans.get(route_key)
        if plan is None:
            raise ExactPublicationError("Syslog public proof has no route preflight")
        existing = self._public_proofs.get(route_key)
        if existing is not None:
            if (
                existing.writer is not retained.writer
                or existing.output_path != retained.output_path
                or existing.digest != retained.digest
                or existing.payload_bytes != retained.payload_bytes
                or existing.parent_identity != plan.parent_identity
            ):
                raise ExactPublicationError("Syslog public proof changed during retry")
            self._verify_public_candidate(existing)
            append = self._public_appends.get(route_key)
            if append is not None:
                self._retire_public_append(route_key, append)
            return existing

        append = self._public_appends.get(route_key)
        if retained.payload_bytes == 0:
            parent_descriptor, parent_identity = self._open_output_parent(
                retained.output_path,
                create=False,
                expected_identity=plan.parent_identity,
            )
            try:
                try:
                    _secure_stat(
                        retained.output_path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    raise ExactPublicationError(
                        "Empty Syslog route retained unexpected public bytes"
                    )
            finally:
                _secure_close(parent_descriptor)
            file_identity = None
        else:
            if append is None or append.candidate is not retained:
                raise ExactPublicationError("Syslog public append proof is missing")
            if self._public_prefix_size(retained, append) != retained.payload_bytes:
                raise ExactPublicationError("Syslog public append is incomplete")
            if append.parent_owner is None:
                raise ExactPublicationError("Syslog public append acquisition is incomplete")
            descriptor, descriptor_identity = _descriptor_owner_snapshot(
                append.descriptor_owner,
                label="public file",
            )
            digest, payload_bytes = self._descriptor_digest(descriptor)
            if digest != retained.digest or payload_bytes != retained.payload_bytes:
                raise ExactPublicationError("Syslog public append changed before proof")
            parent_identity = append.parent_identity
            file_identity = append.file_identity
            if file_identity is None or descriptor_identity != file_identity:
                raise ExactPublicationError("Syslog public append lost its file identity")

        proof = _SyslogPublicProof(
            writer=retained.writer,
            output_path=retained.output_path,
            parent_identity=parent_identity,
            file_identity=file_identity,
            digest=retained.digest,
            payload_bytes=retained.payload_bytes,
        )
        self._public_proofs[route_key] = proof
        if append is not None:
            self._retire_public_append(route_key, append)
        return proof

    def _retire_final_candidate(
        self,
        route_key: str,
        retained: _SyslogFinalCandidate,
    ) -> None:
        """Close one anonymous candidate only after its public proof authenticates."""

        proof = self._public_proofs.get(route_key)
        if proof is None or (
            proof.writer is not retained.writer
            or proof.output_path != retained.output_path
            or proof.digest != retained.digest
            or proof.payload_bytes != retained.payload_bytes
        ):
            raise ExactPublicationError("Syslog final candidate has no matching public proof")
        self._verify_public_candidate(proof)
        if _stream_is_closed(retained.stream):
            if not retained.close_started:
                raise ExactPublicationError(
                    "Syslog final candidate closed without retirement ownership"
                )
        else:
            self._verify_final_candidate(retained)
        if self._final_candidates.get(route_key) is not retained:
            raise ExactPublicationError("Syslog final candidate ownership changed during cleanup")
        retained.close_started = True
        self._close_retained_stream(
            retained.stream,
            close_started=retained.close_started,
            label="final candidate",
        )
        self._final_candidates.pop(route_key)
        self._final_candidate_count -= 1

    def _cleanup_terminal_sources(self) -> None:
        """Close anonymous raw truth only after every final route has a proof."""

        if self._spool_appends:
            raise ExactPublicationError("Syslog cleanup found an unfinished journal append")
        if self._public_appends:
            raise ExactPublicationError("Syslog cleanup found an unfinished public append")
        with self._writers_lock:
            route_writers = tuple(self._writers.items())
        if set(self._public_proofs) != {route_key for route_key, _writer in route_writers}:
            raise ExactPublicationError("Syslog cleanup public proof census changed")
        for proof in self._public_proofs.values():
            self._verify_public_candidate(proof)
        if self._spool_snapshot is not None:
            if _stream_is_closed(self._spool_snapshot) and not self._spool_snapshot_close_started:
                raise ExactPublicationError(
                    "Syslog private spool snapshot closed without retirement ownership"
                )
            if not _stream_is_closed(self._spool_snapshot):
                descriptor = self._verify_anonymous_stream(
                    self._spool_snapshot,
                    self._spool_snapshot_identity or (-1, -1),
                    label="private spool snapshot",
                    expected_bytes=self._spool_bytes,
                )
                digest, payload_bytes = self._descriptor_digest(descriptor)
                if digest != self._spool_digest or payload_bytes != self._spool_bytes:
                    raise ExactPublicationError("Syslog anonymous journal snapshot changed")
            self._spool_snapshot_close_started = True
            self._close_retained_stream(
                self._spool_snapshot,
                close_started=self._spool_snapshot_close_started,
                label="private spool snapshot",
            )
            self._spool_snapshot = None
            self._spool_snapshot_identity = None
            self._spool_snapshot_close_started = False
        if self._spool_stream is not None:
            spool_closed = _descriptor_owner_is_closed(
                self._spool_stream,
                label="private spool",
            )
            if spool_closed and not self._spool_close_started:
                raise ExactPublicationError(
                    "Syslog private spool closed without retirement ownership"
                )
            if not spool_closed:
                self._authenticate_spool_journal()
            self._spool_close_started = True
            self._close_retained_stream(
                self._spool_stream,
                close_started=self._spool_close_started,
                label="private spool",
            )
            self._spool_stream = None
            self._spool_identity = None
            self._spool_close_started = False
        for _route_key, writer in route_writers:
            with writer._lock:
                writer.buffer.clear()
        self._spool_appends.clear()
        self._spool_receipts.clear()
        with self._file_lock:
            self._exact_syslog_reservations.clear()
            self._exact_syslog_candidates.clear()
            self._exact_reserved_rows = 0
            self._exact_reserved_bytes = 0
            self._exact_admitted_rows = 0
            self._exact_admitted_bytes = 0
            self._exact_released_rows = 0
        self._syslog_cleanup_ready = True

    def _cleanup_final_candidates(self) -> None:
        for route_key, retained in tuple(self._final_candidates.items()):
            self._retire_final_candidate(route_key, retained)

    def _normalize_terminal_host_lines(self, host_key: str, lines: list[str]) -> list[str]:
        """Normalize one bounded logical host without inspecting any foreign host."""

        normalized = self._normalize_logind_session_ids_for_lines(lines, host_key)
        if self.output_target != OutputTarget.SOF_ELK:
            normalized = self._backfill_missing_logind_pam_openers_for_lines(
                normalized,
                host_key,
            )
            normalized = _linux_uid_collision_repaired(normalized, host_key)
        normalized = self._normalize_sudo_session_lifecycles_for_lines(normalized)
        normalized = self._normalize_kernel_uptime_stamps_for_lines(normalized)

        normalized_bytes = sum(len(self._line_payload(line)) for line in normalized)
        if len(normalized) > self._terminal_host_row_capacity:
            raise ExactPublicationError("Syslog terminal host row capacity is exhausted")
        if normalized_bytes > self._terminal_host_byte_capacity:
            raise ExactPublicationError("Syslog terminal host byte capacity is exhausted")
        self._terminal_high_water_rows = max(
            self._terminal_high_water_rows,
            len(normalized),
        )
        self._terminal_high_water_bytes = max(
            self._terminal_high_water_bytes,
            normalized_bytes,
        )
        return normalized

    def _terminal_host_rows(
        self,
        host_key: str,
        route_keys: tuple[str, ...],
        writers: dict[str, Any],
    ) -> list[tuple[str, str]]:
        """Load and normalize exactly one logical host across its physical routes."""

        rows: list[tuple[int, tuple[Any, ...], str, str]] = []
        payload_bytes = 0
        for route_key in route_keys:
            writer = writers[route_key]
            year = 0
            for line in self._iter_route_lines(route_key, writer, None):
                logical_route_key = line._logical_route_key
                self._validate_logical_route_key(logical_route_key, label="record")
                if syslog_route_source(logical_route_key) != host_key:
                    continue
                next_rows = len(rows) + 1
                next_bytes = payload_bytes + len(self._line_payload(str(line)))
                if next_rows > self._terminal_host_row_capacity:
                    raise ExactPublicationError("Syslog terminal host row capacity is exhausted")
                if next_bytes > self._terminal_host_byte_capacity:
                    raise ExactPublicationError("Syslog terminal host byte capacity is exhausted")
                year = int(syslog_route_year(logical_route_key) or 0)
                rows.append((year, self._sort_key(line), route_key, str(line)))
                payload_bytes = next_bytes
                self._terminal_high_water_rows = max(
                    self._terminal_high_water_rows,
                    next_rows,
                )
                self._terminal_high_water_bytes = max(
                    self._terminal_high_water_bytes,
                    next_bytes,
                )

        rows.sort(key=lambda row: (row[0], row[1]))
        normalized = self._normalize_terminal_host_lines(
            host_key,
            [line for _year, _sort_key, _route_key, line in rows],
        )

        if len(normalized) != len(rows):
            physical_routes = {row[2] for row in rows}
            if len(physical_routes) != 1:
                raise ExactPublicationError(
                    "Syslog inserted rows cannot cross physical output routes"
                )
            only_route = next(iter(physical_routes))
            return [(only_route, line) for line in normalized]
        return [(row[2], line) for row, line in zip(rows, normalized, strict=True)]

    def _encode_direct_partition_record(self, line: _RoutedSyslogLine) -> str:
        self._validate_logical_route_key(line._logical_route_key, label="direct partition")
        return _secure_json_dumps(
            {
                "line": str(line),
                "logical_route": line._logical_route_key,
                "version": 1,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def _decode_direct_partition_record(self, encoded: str) -> tuple[str, str]:
        try:
            payload = _secure_json_loads(encoded)
        except (TypeError, ValueError) as error:
            raise ExactPublicationError("Syslog direct partition record is invalid") from error
        if (
            type(payload) is not dict
            or set(payload) != {"line", "logical_route", "version"}
            or type(payload["line"]) is not str
            or type(payload["logical_route"]) is not str
            or type(payload["version"]) is not int
            or payload["version"] != 1
        ):
            raise ExactPublicationError("Syslog direct partition record is invalid")
        logical_route = payload["logical_route"]
        self._validate_logical_route_key(logical_route, label="direct partition")
        return syslog_route_source(logical_route), payload["line"]

    def _direct_partition_sort_key(self, encoded: str) -> tuple[Any, ...]:
        host_key, line = self._decode_direct_partition_record(encoded)
        return host_key, self._sort_key(line), line

    def _direct_partition_run(
        self,
        route_key: str,
        writer: Any,
        expected_exact: set[ExactPublicationKey],
    ) -> _SyslogMergeRun:
        """Decode one shared physical route once into bounded host-sorted runs."""

        run_tiers: list[list[_SyslogMergeRun]] = []
        buffered: list[str] = []
        buffered_rows = 0
        buffered_bytes = 0
        matched: set[ExactPublicationKey] = set()
        host_rows: dict[str, int] = {}
        host_bytes: dict[str, int] = {}

        def spill_buffer() -> None:
            nonlocal buffered_rows, buffered_bytes
            if not buffered:
                return
            buffered.sort(key=self._direct_partition_sort_key)
            self._add_tiered_terminal_run(
                run_tiers,
                self._new_direct_partition_run(iter(buffered)),
                sort_key=self._direct_partition_sort_key,
            )
            buffered.clear()
            buffered_rows = 0
            buffered_bytes = 0

        try:
            for line in self._iter_route_lines(route_key, writer, matched):
                logical_route_key = line._logical_route_key
                self._validate_logical_route_key(logical_route_key, label="record")
                host_key = syslog_route_source(logical_route_key)
                if host_key not in host_rows:
                    if len(host_rows) + 1 > self._terminal_host_capacity:
                        raise ExactPublicationError(
                            "Syslog terminal logical host capacity is exhausted"
                        )
                    host_rows[host_key] = 0
                    host_bytes[host_key] = 0
                line_bytes = len(self._line_payload(str(line)))
                next_host_rows = host_rows[host_key] + 1
                next_host_bytes = host_bytes[host_key] + line_bytes
                if next_host_rows > self._terminal_host_row_capacity:
                    raise ExactPublicationError("Syslog terminal host row capacity is exhausted")
                if next_host_bytes > self._terminal_host_byte_capacity:
                    raise ExactPublicationError("Syslog terminal host byte capacity is exhausted")
                host_rows[host_key] = next_host_rows
                host_bytes[host_key] = next_host_bytes
                self._terminal_high_water_rows = max(
                    self._terminal_high_water_rows,
                    next_host_rows,
                )
                self._terminal_high_water_bytes = max(
                    self._terminal_high_water_bytes,
                    next_host_bytes,
                )
                if buffered and (
                    buffered_rows + 1 > self._terminal_host_row_capacity
                    or buffered_bytes + line_bytes > self._terminal_host_byte_capacity
                ):
                    spill_buffer()
                buffered.append(self._encode_direct_partition_record(line))
                buffered_rows += 1
                buffered_bytes += line_bytes

            if matched != expected_exact:
                missing = len(expected_exact - matched)
                extra = len(matched - expected_exact)
                raise ExactPublicationError(
                    f"Syslog exact candidate census changed (missing={missing}, extra={extra})"
                )
            spill_buffer()
            retained = self._finish_tiered_terminal_runs(
                run_tiers,
                sort_key=self._direct_partition_sort_key,
            )
            if retained is None:
                return self._new_direct_partition_run(iter(()))
            return retained
        except BaseException:
            self._cleanup_tiered_terminal_runs(run_tiers)
            raise

    def _direct_normalized_route_run(
        self,
        partition: _SyslogMergeRun,
    ) -> _SyslogMergeRun:
        """Normalize one partitioned host at a time into one sorted physical route."""

        run_tiers: list[list[_SyslogMergeRun]] = []
        current_host: str | None = None
        host_lines: list[str] = []
        route_rows = 0
        route_bytes = 0

        def spill_host() -> None:
            nonlocal route_rows, route_bytes
            if current_host is None:
                return
            normalized = self._normalize_terminal_host_lines(current_host, host_lines)
            normalized.sort(key=self._sort_key)
            for line in normalized:
                frame = self._terminal_run_frame(line)
                route_rows += 1
                route_bytes += len(frame)
                if route_rows > self._spool_route_row_capacity:
                    raise ExactPublicationError("Syslog terminal merge row capacity is exhausted")
                if route_bytes > self._spool_route_byte_capacity:
                    raise ExactPublicationError("Syslog terminal merge byte capacity is exhausted")
            if normalized:
                self._add_tiered_terminal_run(
                    run_tiers,
                    self._new_terminal_run(iter(normalized)),
                )

        try:
            for encoded in self._iter_terminal_run(partition):
                host_key, line = self._decode_direct_partition_record(encoded)
                if current_host is None:
                    current_host = host_key
                elif host_key != current_host:
                    if host_key <= current_host:
                        raise ExactPublicationError("Syslog direct partition order changed")
                    spill_host()
                    host_lines.clear()
                    current_host = host_key
                host_lines.append(line)
            spill_host()
            retained = self._finish_tiered_terminal_runs(run_tiers)
            if retained is None:
                return self._new_terminal_run(iter(()))
            return retained
        except BaseException:
            self._cleanup_tiered_terminal_runs(run_tiers)
            raise

    def _terminal_route_run(
        self,
        route_key: str,
        host_keys: tuple[str, ...],
        host_routes: dict[str, tuple[str, ...]],
        writers: dict[str, Any],
    ) -> _SyslogMergeRun:
        """Build one physical route with configured bounded multiway merge groups."""

        run_tiers: list[list[_SyslogMergeRun]] = []

        try:
            for host_key in host_keys:
                normalized = [
                    line
                    for physical_route, line in self._terminal_host_rows(
                        host_key,
                        host_routes[host_key],
                        writers,
                    )
                    if physical_route == route_key
                ]
                if not normalized:
                    continue
                normalized.sort(key=self._sort_key)
                self._add_tiered_terminal_run(
                    run_tiers,
                    self._new_terminal_run(iter(normalized)),
                )
            retained = self._finish_tiered_terminal_runs(run_tiers)
            if retained is None:
                return self._new_terminal_run(iter(()))
            return retained
        except BaseException:
            self._cleanup_tiered_terminal_runs(run_tiers)
            raise

    def _preflight_terminal_routes(
        self,
        route_writers: tuple[tuple[str, Any], ...],
        expected_exact: set[ExactPublicationKey],
    ) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
        """Authenticate all raw rows and retain only bounded host/route metadata."""

        matched: set[ExactPublicationKey] = set()
        host_routes_mutable: dict[str, list[str]] = {}
        route_hosts_mutable: dict[str, list[str]] = {
            route_key: [] for route_key, _writer in route_writers
        }
        host_rows: dict[str, int] = {}
        host_bytes: dict[str, int] = {}
        paths: dict[Path, str] = {}
        for route_key, writer in route_writers:
            foreign_route = paths.setdefault(writer.output_path, route_key)
            if foreign_route != route_key:
                raise ExactPublicationError(
                    f"Syslog routes share one physical output target: {foreign_route!r}"
                )
            for line in self._iter_route_lines(route_key, writer, matched):
                logical_route_key = line._logical_route_key
                self._validate_logical_route_key(logical_route_key, label="record")
                host_key = syslog_route_source(logical_route_key)
                routes = host_routes_mutable.get(host_key)
                if routes is None:
                    if len(host_routes_mutable) + 1 > self._terminal_host_capacity:
                        raise ExactPublicationError(
                            "Syslog terminal logical host capacity is exhausted"
                        )
                    routes = []
                    host_routes_mutable[host_key] = routes
                if route_key not in routes:
                    routes.append(route_key)
                    route_hosts_mutable[route_key].append(host_key)
                next_rows = host_rows.get(host_key, 0) + 1
                next_bytes = host_bytes.get(host_key, 0) + len(self._line_payload(str(line)))
                if next_rows > self._terminal_host_row_capacity:
                    raise ExactPublicationError("Syslog terminal host row capacity is exhausted")
                if next_bytes > self._terminal_host_byte_capacity:
                    raise ExactPublicationError("Syslog terminal host byte capacity is exhausted")
                host_rows[host_key] = next_rows
                host_bytes[host_key] = next_bytes
                self._terminal_high_water_rows = max(
                    self._terminal_high_water_rows,
                    next_rows,
                )
                self._terminal_high_water_bytes = max(
                    self._terminal_high_water_bytes,
                    next_bytes,
                )

        if matched != expected_exact:
            missing = len(expected_exact - matched)
            extra = len(matched - expected_exact)
            raise ExactPublicationError(
                f"Syslog exact candidate census changed (missing={missing}, extra={extra})"
            )
        host_routes = {
            host_key: tuple(route_keys) for host_key, route_keys in host_routes_mutable.items()
        }
        route_hosts = {
            route_key: tuple(host_keys) for route_key, host_keys in route_hosts_mutable.items()
        }
        return host_routes, route_hosts

    def _preflight_normalized_route_capacities(
        self,
        host_routes: dict[str, tuple[str, ...]],
        route_writers: tuple[tuple[str, Any], ...],
    ) -> None:
        """Validate every normalized physical route before the first public write."""

        writers = dict(route_writers)
        route_rows = {route_key: 0 for route_key, _writer in route_writers}
        route_bytes = {route_key: 0 for route_key, _writer in route_writers}
        for host_key, route_keys in host_routes.items():
            for physical_route, line in self._terminal_host_rows(
                host_key,
                route_keys,
                writers,
            ):
                if physical_route not in route_rows:
                    raise ExactPublicationError("Syslog normalized physical route changed")
                frame = self._terminal_run_frame(line)
                next_rows = route_rows[physical_route] + 1
                next_bytes = route_bytes[physical_route] + len(frame)
                if next_rows > self._spool_route_row_capacity:
                    raise ExactPublicationError("Syslog terminal merge row capacity is exhausted")
                if next_bytes > self._spool_route_byte_capacity:
                    raise ExactPublicationError("Syslog terminal merge byte capacity is exhausted")
                route_rows[physical_route] = next_rows
                route_bytes[physical_route] = next_bytes

    def _preflight_public_route_identity(
        self,
        route_key: str,
        writer: Any,
        digest: str,
        payload_bytes: int,
    ) -> None:
        """Authenticate one fully rendered route and its lexical parent identity."""

        parent_descriptor, parent_identity = self._open_output_parent(
            writer.output_path,
            create=True,
        )
        try:
            _secure_fsync(parent_descriptor)
            existing = self._route_plans.get(route_key)
            plan = _SyslogRoutePlan(
                writer=writer,
                output_path=writer.output_path,
                parent_identity=parent_identity,
                digest=digest,
                payload_bytes=payload_bytes,
            )
            if existing is not None and existing != plan:
                raise ExactPublicationError("Syslog route preflight changed during retry")
            proof = self._public_proofs.get(route_key)
            append = self._public_appends.get(route_key)
            if proof is not None:
                if (
                    proof.writer is not writer
                    or proof.output_path != writer.output_path
                    or proof.parent_identity != parent_identity
                    or proof.digest != digest
                    or proof.payload_bytes != payload_bytes
                ):
                    raise ExactPublicationError("Syslog public route changed during retry")
                self._verify_public_candidate(proof)
            elif append is not None:
                if (
                    append.writer is not writer
                    or append.output_path != writer.output_path
                    or append.parent_identity != parent_identity
                    or append.digest != digest
                    or append.payload_bytes != payload_bytes
                ):
                    raise ExactPublicationError("Syslog public append changed during retry")
                if append.parent_owner is not None:
                    append_parent_descriptor, append_parent_identity = _descriptor_owner_snapshot(
                        append.parent_owner,
                        label="public parent",
                    )
                    if append_parent_identity != append.parent_identity:
                        raise ExactPublicationError("Syslog public parent acquisition changed")
                    self._authenticate_output_parent(
                        append.output_path,
                        append_parent_descriptor,
                        append.parent_identity,
                    )
                if _descriptor_owner_is_empty(
                    append.descriptor_owner,
                    label="public file",
                ):
                    try:
                        _secure_stat(
                            writer.output_path.name,
                            dir_fd=parent_descriptor,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        pass
                    else:
                        raise ExactPublicationError("Syslog final output already exists")
                else:
                    self._acquire_public_descriptor(append)
                    self._public_prefix_size(append.candidate, append)
            else:
                try:
                    _secure_stat(
                        writer.output_path.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    raise ExactPublicationError("Syslog final output already exists")
            self._route_plans[route_key] = plan
        finally:
            _secure_close(parent_descriptor)

    def _preflight_public_route_plans(
        self,
        route_writers: tuple[tuple[str, Any], ...],
        host_routes: dict[str, tuple[str, ...]],
        route_hosts: dict[str, tuple[str, ...]],
    ) -> None:
        """Render and authenticate every route and parent before public creation."""

        writers = dict(route_writers)
        for route_key, writer in route_writers:
            retained_run = self._terminal_route_run(
                route_key,
                route_hosts[route_key],
                host_routes,
                writers,
            )

            def line_factory(retained: _SyslogMergeRun = retained_run) -> Iterator[str]:
                return self._iter_terminal_run(retained)

            try:
                digest, payload_bytes = self._candidate_payload_identity(line_factory)
            finally:
                self._close_terminal_run(retained_run)
            self._preflight_public_route_identity(
                route_key,
                writer,
                digest,
                payload_bytes,
            )

        expected_routes = {route_key for route_key, _writer in route_writers}
        if set(self._route_plans) != expected_routes:
            raise ExactPublicationError("Syslog route preflight census changed")

    def _publish_preflighted_route_run(
        self,
        route_key: str,
        writer: Any,
        retained_run: _SyslogMergeRun,
    ) -> None:
        """Publish or reconcile one route from its already preflighted final run."""

        for completed in self._public_proofs.values():
            self._verify_public_candidate(completed)
        plan = self._route_plans[route_key]
        proof = self._public_proofs.get(route_key)
        if proof is not None:
            if (
                proof.writer is not writer
                or proof.output_path != writer.output_path
                or proof.parent_identity != plan.parent_identity
                or proof.digest != plan.digest
                or proof.payload_bytes != plan.payload_bytes
            ):
                raise ExactPublicationError("Syslog public route changed during retry")
            retained = self._final_candidates.get(route_key)
            if retained is not None:
                self._record_public_proof(route_key, retained)
                self._retire_final_candidate(route_key, retained)
            elif route_key in self._public_appends:
                raise ExactPublicationError("Syslog public append lost its candidate owner")
            return

        def line_factory() -> Iterator[str]:
            return self._iter_terminal_run(retained_run)

        retained = self._prepare_final_candidate(route_key, writer, line_factory)
        if retained.digest != plan.digest or retained.payload_bytes != plan.payload_bytes:
            raise ExactPublicationError("Syslog final route changed after preflight")
        self._publish_final_candidate(retained)
        self._record_public_proof(route_key, retained)
        self._retire_final_candidate(route_key, retained)
        for completed in self._public_proofs.values():
            self._verify_public_candidate(completed)

    def _finalize_direct_spooled_route(
        self,
        route_writers: tuple[tuple[str, Any], ...],
        expected_exact: set[ExactPublicationKey],
    ) -> None:
        """Partition and normalize one direct physical route with one raw decode pass."""

        if len(route_writers) != 1:
            raise ExactPublicationError("Syslog direct output lost its single physical writer")
        route_key, writer = route_writers[0]
        partition = self._direct_partition_run(route_key, writer, expected_exact)
        try:
            retained_run = self._direct_normalized_route_run(partition)
        finally:
            self._close_terminal_run(partition)

        def line_factory() -> Iterator[str]:
            return self._iter_terminal_run(retained_run)

        try:
            digest, payload_bytes = self._candidate_payload_identity(line_factory)
            self._preflight_public_route_identity(
                route_key,
                writer,
                digest,
                payload_bytes,
            )
            if set(self._route_plans) != {route_key}:
                raise ExactPublicationError("Syslog route preflight census changed")
            self._ensure_spool_snapshot()
            self._publish_preflighted_route_run(route_key, writer, retained_run)
        finally:
            self._close_terminal_run(retained_run)

        if set(self._public_proofs) != {route_key}:
            raise ExactPublicationError("Syslog public route proof census changed")
        self._syslog_publication_complete = True
        self._cleanup_terminal_sources()
        self._cleanup_final_candidates()

    def _finalize_spooled_hosts(self) -> None:
        """Preflight every route, then publish each authenticated physical sink."""

        with self._writers_lock:
            route_writers = tuple(self._writers.items())
        route_keys = {route_key for route_key, _writer in route_writers}
        if self._syslog_publication_complete:
            if set(self._public_proofs) != route_keys:
                raise ExactPublicationError("Syslog public route proof census changed")
            for route_key, proof in self._public_proofs.items():
                if route_key not in dict(route_writers):
                    raise ExactPublicationError("Syslog public route owner disappeared")
                self._verify_public_candidate(proof)
            if not self._syslog_cleanup_ready:
                self._cleanup_terminal_sources()
            self._cleanup_final_candidates()
            return

        with self._file_lock:
            expected_exact = set(self._exact_syslog_candidates)
            if self._exact_syslog_reservations:
                raise ExactPublicationError("Syslog cannot close with reserved exact candidates")
            for key, retained in self._exact_syslog_candidates.items():
                self._validate_retained_candidate_unlocked(key, retained)
                if not retained.installed or not retained.released:
                    raise ExactPublicationError("Syslog cannot close with live exact candidates")
        for route_key, writer in route_writers:
            with writer._lock:
                self._spool_writer_records(route_key, writer)
        self._ensure_spool_snapshot()
        if self._direct_file_mode and route_writers:
            self._finalize_direct_spooled_route(route_writers, expected_exact)
            return
        host_routes, route_hosts = self._preflight_terminal_routes(
            route_writers,
            expected_exact,
        )
        self._preflight_normalized_route_capacities(host_routes, route_writers)
        self._preflight_public_route_plans(route_writers, host_routes, route_hosts)
        self._ensure_spool_snapshot()
        writers = dict(route_writers)

        for route_key, writer in route_writers:
            retained_run = self._terminal_route_run(
                route_key,
                route_hosts[route_key],
                host_routes,
                writers,
            )

            try:
                self._publish_preflighted_route_run(route_key, writer, retained_run)
            finally:
                self._close_terminal_run(retained_run)

        if set(self._public_proofs) != route_keys:
            raise ExactPublicationError("Syslog public route proof census changed")
        self._syslog_publication_complete = True
        self._cleanup_terminal_sources()
        self._cleanup_final_candidates()

    def _normalize_sof_elk_buffers(self) -> None:
        """Normalize SOF-ELK RFC3164 syslog rows with one final sort pass."""
        with self._writers_lock:
            for host_key, rows in self._sorted_lines_by_host().items():
                if not rows:
                    continue
                normalized = [line for _year, _sort_key, _route_key, line in rows]
                normalized = self._normalize_logind_session_ids_for_lines(normalized, host_key)
                normalized = self._normalize_sudo_session_lifecycles_for_lines(normalized)
                normalized = self._normalize_kernel_uptime_stamps_for_lines(normalized)
                self._replace_buffers_by_sorted_rows(rows, normalized)

    def _sorted_lines_by_host(self) -> dict[str, list[tuple[int, tuple[Any, ...], str, str]]]:
        """Return buffered rows grouped by host and sorted in final render order."""
        grouped: dict[str, list[tuple[str, Any]]] = {}
        for route_key, writer in self._writers.items():
            grouped.setdefault(syslog_route_source(route_key), []).append((route_key, writer))

        sorted_by_host: dict[str, list[tuple[int, tuple[Any, ...], str, str]]] = {}
        for host_key, route_writers in grouped.items():
            rows: list[tuple[int, tuple[Any, ...], str, str]] = []
            for route_key, writer in route_writers:
                year = int(syslog_route_year(route_key) or 0)
                with writer._lock:
                    for line in writer.buffer:
                        sort_key = (
                            _syslog_sort_key(line)
                            if self.output_target == OutputTarget.SOF_ELK
                            else _rfc5424_syslog_sort_key(line)
                        )
                        rows.append((year, sort_key, route_key, line))
            rows.sort(key=lambda row: (row[0], row[1]))
            sorted_by_host[host_key] = rows
        return sorted_by_host

    def _replace_buffers_by_sorted_rows(
        self,
        rows: list[tuple[int, tuple[Any, ...], str, str]],
        normalized: list[str],
    ) -> None:
        """Replace writer buffers with normalized lines while preserving route splits."""
        buffers_by_route: dict[str, list[str]] = {}
        for row, line in zip(rows, normalized, strict=True):
            buffers_by_route.setdefault(row[2], []).append(line)
        for route_key, writer in self._writers.items():
            if route_key in buffers_by_route:
                with writer._lock:
                    writer.buffer = buffers_by_route[route_key]

    def _replace_host_buffers_with_lines(
        self,
        rows: list[tuple[int, tuple[Any, ...], str, str]],
        normalized: list[str],
    ) -> None:
        """Replace one default-target host buffer when normalization inserts rows."""
        route_keys = list(dict.fromkeys(row[2] for row in rows))
        if not route_keys:
            return
        for route_key in route_keys:
            writer = self._writers.get(route_key)
            if writer is not None:
                with writer._lock:
                    writer.buffer = []
        primary_writer = self._writers.get(route_keys[0])
        if primary_writer is not None:
            with primary_writer._lock:
                primary_writer.buffer = normalized

    def _normalize_logind_session_ids(self) -> None:
        """Rewrite visible logind New-session IDs in final rendered order.

        systemd-logind session IDs are source-local syslog presentation state.
        The generator can emit events out of final sorted order, so the final
        syslog renderer owns the last mile: preserve the original relative
        regime, make New-session rows monotonic per host/logind PID, and carry
        the rewritten ID into matching Removed-session rows when both are
        visible in the collection window.
        """
        with self._writers_lock:
            for host_key, rows in self._sorted_lines_by_host().items():
                if not rows:
                    continue
                normalized = self._normalize_logind_session_ids_for_lines(
                    [line for _year, _sort_key, _route_key, line in rows],
                    host_key,
                )
                self._replace_buffers_by_sorted_rows(rows, normalized)

    def _backfill_missing_logind_pam_openers(self) -> None:
        """Insert a native PAM opener for orphaned visible logind New-session rows."""
        if self.output_target == OutputTarget.SOF_ELK:
            return
        with self._writers_lock:
            for host_key, rows in self._sorted_lines_by_host().items():
                if not rows:
                    continue
                lines = [line for _year, _sort_key, _route_key, line in rows]
                normalized = self._backfill_missing_logind_pam_openers_for_lines(
                    lines,
                    host_key,
                )
                if len(normalized) != len(lines):
                    self._replace_host_buffers_with_lines(rows, normalized)

    def _normalize_sudo_session_lifecycles(self) -> None:
        """Keep same-PID sudo PAM session rows around COMMAND rows."""
        for rows in self._sorted_lines_by_host().values():
            lines = [row[3] for row in rows]
            normalized = self._normalize_sudo_session_lifecycles_for_lines(lines)
            self._replace_buffers_by_sorted_rows(rows, normalized)

    def _normalize_pam_uid_collisions(self) -> None:
        """Keep syslog-only PAM UID ownership coherent on each host."""
        if self.output_target == OutputTarget.SOF_ELK:
            return
        with self._writers_lock:
            for host_key, rows in self._sorted_lines_by_host().items():
                if not rows:
                    continue
                normalized = _linux_uid_collision_repaired(
                    [line for _year, _sort_key, _route_key, line in rows],
                    host_key,
                )
                self._replace_buffers_by_sorted_rows(rows, normalized)

    def _normalize_kernel_uptime_stamps(self) -> None:
        """Clamp visible kernel bracket uptime values to final syslog order."""
        with self._writers_lock:
            for rows in self._sorted_lines_by_host().values():
                if not rows:
                    continue
                normalized = self._normalize_kernel_uptime_stamps_for_lines(
                    [line for _year, _sort_key, _route_key, line in rows]
                )
                self._replace_buffers_by_sorted_rows(rows, normalized)

    @staticmethod
    def _normalize_logind_session_ids_for_lines(lines: list[str], host_key: str) -> list[str]:
        """Return lines with monotonic logind New-session IDs for one host.

        Canonical SSH sessions can expose the same logind session ID in eCAR.
        Preserve already-monotonic syslog IDs so renderer finalization does not
        split that cross-source identity; only repair invalid, duplicate, or
        backward-moving rows.
        """
        first_by_pid: dict[str, int] = {}
        for line in lines:
            match = _LOGIND_NEW_SESSION_RE.search(line)
            if match is None:
                continue
            pid = _logind_pid(match)
            session = _parse_logind_session_id(match.group("session"))
            if session is None:
                continue
            first_by_pid[pid] = min(session, first_by_pid.get(pid, session))

        if not first_by_pid:
            return lines

        latest_new_by_pid: dict[str, int] = {}
        prewindow_next_by_pid = {pid: max(2, start) - 1 for pid, start in first_by_pid.items()}
        rewritten_by_original: dict[tuple[str, str], int] = {}
        prewindow_seen_by_original: set[tuple[str, str]] = set()
        normalized: list[str] = []
        for index, line in enumerate(lines):
            new_match = _LOGIND_NEW_SESSION_RE.search(line)
            if new_match is not None:
                pid = _logind_pid(new_match)
                original_session = new_match.group("session")
                parsed_session = _parse_logind_session_id(original_session)
                if parsed_session is None:
                    normalized.append(line)
                    continue
                latest_session = latest_new_by_pid.get(pid)
                if latest_session is None or parsed_session > latest_session:
                    rewritten = parsed_session
                else:
                    step_seed = _stable_seed(
                        f"syslog_logind_session_step:{host_key}:{pid}:{original_session}:{index}"
                    )
                    rewritten = latest_session + 1 + (step_seed % 3)
                    line = (
                        f"{line[: new_match.start('session')]}"
                        f"{rewritten}"
                        f"{line[new_match.end('session') :]}"
                    )
                latest_new_by_pid[pid] = rewritten
                rewritten_by_original[(pid, original_session)] = rewritten
                normalized.append(line)
                continue

            removed_match = _LOGIND_REMOVED_SESSION_RE.search(line)
            if removed_match is not None:
                key = (_logind_pid(removed_match), removed_match.group("session"))
                rewritten = rewritten_by_original.get(key)
                if rewritten is None:
                    pid = _logind_pid(removed_match)
                    original_session_id = _parse_logind_session_id(removed_match.group("session"))
                    if original_session_id is None:
                        normalized.append(line)
                        continue
                    first_visible = max(2, first_by_pid.get(pid, original_session_id + 1))
                    needs_prewindow_rewrite = (
                        original_session_id >= first_visible or key in prewindow_seen_by_original
                    )
                    prewindow_seen_by_original.add(key)
                    if needs_prewindow_rewrite:
                        step_seed = _stable_seed(
                            "syslog_logind_prewindow_session_step:"
                            f"{host_key}:{pid}:{removed_match.group('session')}:{index}"
                        )
                        prewindow_next_by_pid[pid] = (
                            prewindow_next_by_pid.get(pid, first_visible - 1) - 1 - (step_seed % 3)
                        )
                        rewritten = prewindow_next_by_pid[pid]
                if rewritten is not None:
                    line = (
                        f"{line[: removed_match.start('session')]}"
                        f"{rewritten}"
                        f"{line[removed_match.end('session') :]}"
                    )
            normalized.append(line)
        return normalized

    @staticmethod
    def _backfill_missing_logind_pam_openers_for_lines(
        lines: list[str],
        host_key: str,
    ) -> list[str]:
        """Return RFC5424 syslog lines with orphaned logind rows given PAM openers."""
        uid_by_user: dict[str, int] = {}
        open_times_by_user: dict[str, list[Any]] = {}
        for line in lines:
            pam_match = _RFC5424_PAM_OPEN_RE.match(line)
            if pam_match is None:
                continue
            user = pam_match.group("user")
            uid_by_user[user] = int(pam_match.group("uid"))
            open_times_by_user.setdefault(user, []).append(
                _parse_rfc5424_timestamp(pam_match.group("timestamp"))
            )

        for open_times in open_times_by_user.values():
            open_times.sort()

        normalized: list[str] = []
        for index, line in enumerate(lines):
            new_match = _RFC5424_LOGIND_NEW_SESSION_RE.match(line)
            if new_match is None:
                normalized.append(line)
                continue
            if _parse_logind_session_id(new_match.group("session")) is None:
                normalized.append(line)
                continue

            user = new_match.group("user")
            new_time = _parse_rfc5424_timestamp(new_match.group("timestamp"))
            open_times = open_times_by_user.get(user, [])
            newest_index = bisect_right(open_times, new_time) - 1
            has_recent_open = (
                newest_index >= 0
                and new_time - open_times[newest_index] <= _PAM_OPEN_VISIBLE_WINDOW
            )
            if not has_recent_open:
                normalized.append(
                    SyslogEmitter._render_pam_open_backfill(
                        host_key=host_key,
                        hostname=new_match.group("hostname"),
                        user=user,
                        uid=uid_by_user.get(user, _fallback_linux_uid(user)),
                        new_time=new_time,
                        index=index,
                    )
                )
            normalized.append(line)
        return sorted(normalized, key=_rfc5424_syslog_sort_key)

    @staticmethod
    def _render_pam_open_backfill(
        *,
        host_key: str,
        hostname: str,
        user: str,
        uid: int,
        new_time: Any,
        index: int,
    ) -> str:
        """Render a source-native PAM open row for a visible orphaned logind row."""
        seed = _stable_seed(f"syslog_logind_pam_backfill:{host_key}:{user}:{index}")
        if user == "root":
            service = ("login", "su")[seed % 2]
        else:
            service = "login"
        app_name = service
        pid = 1200 + (seed % 8300)
        lead = timedelta(milliseconds=1800 + (seed % 2200))
        opener = "LOGIN(uid=0)" if service == "login" else "(uid=0)"
        message = (
            f"pam_unix({service}:session): session opened for user {user}(uid={uid}) by {opener}"
        )
        return render_rfc5424_syslog(
            pri=86,
            timestamp=_format_rfc5424_timestamp(new_time - lead),
            hostname=hostname,
            app_name=app_name,
            pid=pid,
            message=message,
        )

    @staticmethod
    def _normalize_sudo_session_lifecycles_for_lines(lines: list[str]) -> list[str]:
        """Return RFC5424 lines with sudo command/open/close order repaired."""
        parsed: dict[int, dict[str, Any]] = {}
        rows_by_pid: dict[str, dict[str, list[int]]] = {}
        for index, line in enumerate(lines):
            match = _RFC5424_LINE_RE.match(line)
            if match is None or match.group("app_name") != "sudo":
                continue
            timestamp = _parse_rfc5424_timestamp(match.group("timestamp"))
            message = match.group("message")
            pid = match.group("pid")
            parsed[index] = {
                "timestamp": timestamp,
                "pid": pid,
                "message": message,
            }
            bucket = rows_by_pid.setdefault(pid, {"open": [], "command": [], "close": []})
            if "pam_unix(sudo:session): session opened" in message:
                bucket["open"].append(index)
            elif "COMMAND=" in message and "command not allowed" not in message:
                bucket["command"].append(index)
            elif "pam_unix(sudo:session): session closed" in message:
                bucket["close"].append(index)

        normalized = list(lines)
        if not parsed:
            return normalized
        min_gap = timedelta(milliseconds=1)
        max_repair_gap = timedelta(seconds=2)
        for bucket in rows_by_pid.values():
            open_indices = bucket["open"]
            close_indices = bucket["close"]
            for command_index in bucket["command"]:
                command_time = parsed[command_index]["timestamp"]
                has_open_after = any(
                    command_time < parsed[open_index]["timestamp"] for open_index in open_indices
                )
                if not has_open_after:
                    prior_opens = [
                        open_index
                        for open_index in open_indices
                        if command_time - max_repair_gap
                        <= parsed[open_index]["timestamp"]
                        <= command_time
                    ]
                    if prior_opens:
                        open_index = min(
                            prior_opens,
                            key=lambda index: abs(
                                (parsed[index]["timestamp"] - command_time).total_seconds()
                            ),
                        )
                        repaired_time = command_time + min_gap
                        parsed[open_index]["timestamp"] = repaired_time
                        normalized[open_index] = _replace_rfc5424_timestamp(
                            normalized[open_index],
                            repaired_time,
                        )

                matching_open_times = [
                    parsed[open_index]["timestamp"]
                    for open_index in open_indices
                    if command_time < parsed[open_index]["timestamp"]
                ]
                lifecycle_floor = min(matching_open_times) if matching_open_times else command_time
                has_close_after = any(
                    parsed[close_index]["timestamp"] > lifecycle_floor
                    for close_index in close_indices
                )
                if not has_close_after:
                    prior_closes = [
                        close_index
                        for close_index in close_indices
                        if lifecycle_floor - max_repair_gap
                        <= parsed[close_index]["timestamp"]
                        <= lifecycle_floor
                    ]
                    if prior_closes:
                        close_index = max(
                            prior_closes,
                            key=lambda index: parsed[index]["timestamp"],
                        )
                        repaired_time = lifecycle_floor + min_gap
                        parsed[close_index]["timestamp"] = repaired_time
                        normalized[close_index] = _replace_rfc5424_timestamp(
                            normalized[close_index],
                            repaired_time,
                        )
        return sorted(normalized, key=_rfc5424_syslog_sort_key)

    @staticmethod
    def _normalize_kernel_uptime_stamps_for_lines(lines: list[str]) -> list[str]:
        """Return lines with nondecreasing kernel bracket uptime values."""
        last_uptime: float | None = None
        normalized: list[str] = []
        for line in lines:
            match = _KERNEL_UPTIME_RE.search(line)
            if match is None:
                normalized.append(line)
                continue
            uptime = float(match.group("uptime"))
            if last_uptime is not None and uptime <= last_uptime:
                uptime = last_uptime + 0.000001
                line = line[: match.start("uptime")] + f"{uptime:.6f}" + line[match.end("uptime") :]
            last_uptime = uptime
            normalized.append(line)
        return normalized

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

Renders syslog-format entries from SyslogContext on SecurityEvent.
All syslog message construction is done by ActivityGenerator — the emitter
just formats the context fields into the syslog template.
"""

import re
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed

_SYSLOG_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}
_SYSLOG_TS_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d\d:\d\d:\d\d)")
_LOGIND_NEW_SESSION_RE = re.compile(
    r"(?P<prefix>\bsystemd-logind\[(?P<pid>\d+)\]: New session )"
    r"(?P<session>\d+)(?P<suffix> of user .*)"
)
_LOGIND_REMOVED_SESSION_RE = re.compile(
    r"(?P<prefix>\bsystemd-logind\[(?P<pid>\d+)\]: Removed session )"
    r"(?P<session>\d+)(?P<suffix>\.)"
)


def _ssh_lifecycle_priority(line: str) -> int:
    """Order same-second SSH lifecycle messages after timestamp precision is lost."""
    if " sshd[" not in line:
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
    if " systemd[" not in line or ".service" not in line:
        return 50
    if ": Starting " in line:
        return 10
    if ": Started " in line:
        return 20
    if ": Stopping " in line:
        return 30
    if ": Stopped " in line or ": Finished " in line:
        return 40
    return 50


def _dhclient_lifecycle_priority(line: str) -> int:
    """Order same-second DHCP client messages after timestamp precision is lost."""
    if " dhclient[" not in line:
        return 50
    if ": DHCPDISCOVER " in line:
        return 10
    if ": DHCPOFFER " in line:
        return 20
    if ": DHCPREQUEST " in line:
        return 30
    if ": DHCPACK " in line:
        return 40
    if ": bound to " in line:
        return 50
    return 60


def _syslog_sort_key(line: str) -> tuple[int, int, str, int, str]:
    """Sort traditional syslog lines by their rendered month/day/time prefix."""
    match = _SYSLOG_TS_RE.match(line)
    if match is None:
        return (13, 32, "99:99:99", 99, line)
    return (
        _SYSLOG_MONTHS.get(match.group("mon"), 13),
        int(match.group("day")),
        match.group("hms"),
        min(
            _ssh_lifecycle_priority(line),
            _systemd_lifecycle_priority(line),
            _dhclient_lifecycle_priority(line),
        ),
        line,
    )


class SyslogEmitter(HostMultiplexEmitter):
    """Emitter for Linux syslog format.

    Per-host FQDN directory routing: each Linux host gets its own syslog.log.
    Renders any SecurityEvent that carries a SyslogContext on a Linux host.
    """

    _log_filename = "syslog.log"
    _flat_filename = "syslog.log"
    _sort_flat_file = True
    _sort_key = staticmethod(_syslog_sort_key)
    _defer_sorted_flush_until_close = True

    # Context-driven: handles any event type that carries SyslogContext
    _supported_types: set[str] = set()

    def can_handle(self, event: SecurityEvent) -> bool:
        """Syslog emitter handles any event with SyslogContext on a Linux host."""
        return event.syslog is not None and self._linux_host(event) is not None

    @staticmethod
    def _linux_host(event: SecurityEvent) -> "HostContext | None":
        """Return whichever host has os_category == 'linux'."""
        if (
            event.syslog is not None
            and event.syslog.app_name == "sshd"
            and event.dst_host
            and event.dst_host.os_category == "linux"
        ):
            return event.dst_host
        if event.src_host and event.src_host.os_category == "linux":
            return event.src_host
        if event.dst_host and event.dst_host.os_category == "linux":
            return event.dst_host
        return None

    def emit(self, event: SecurityEvent) -> None:
        """Render syslog entry from SyslogContext."""
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

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route syslog event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        ts = event_data.get("timestamp")
        if isinstance(ts, str):
            from evidenceforge.utils.time import parse_iso8601

            ts = parse_iso8601(ts)
        context = {
            "timestamp": ts,
            "hostname": event_data.get("hostname") or "",
            "facility": event_data.get("facility"),
            "severity": event_data.get("severity"),
            "app_name": event_data.get("app_name"),
            "pid": event_data.get("pid"),
            "message": event_data.get("message"),
        }
        rendered = self._template.render(**context)
        return rendered.strip()

    def close(self) -> None:
        """Close emitter after normalizing source-native logind session order."""
        if self.threaded:
            self.stop_thread()
        self._normalize_logind_session_ids()
        self.flush(force=True)

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
            for host_key, writer in self._writers.items():
                with writer._lock:
                    if not writer.buffer:
                        continue
                    lines = sorted(writer.buffer, key=_syslog_sort_key)
                    writer.buffer = self._normalize_logind_session_ids_for_lines(
                        lines,
                        host_key,
                    )

    @staticmethod
    def _normalize_logind_session_ids_for_lines(lines: list[str], host_key: str) -> list[str]:
        """Return lines with monotonic logind New-session IDs for one host."""
        first_by_pid: dict[str, int] = {}
        for line in lines:
            match = _LOGIND_NEW_SESSION_RE.search(line)
            if match is None:
                continue
            pid = match.group("pid")
            session = int(match.group("session"))
            first_by_pid[pid] = min(session, first_by_pid.get(pid, session))

        if not first_by_pid:
            return lines

        next_by_pid = {pid: start - 1 for pid, start in first_by_pid.items()}
        rewritten_by_original: dict[tuple[str, str], int] = {}
        normalized: list[str] = []
        for index, line in enumerate(lines):
            new_match = _LOGIND_NEW_SESSION_RE.search(line)
            if new_match is not None:
                pid = new_match.group("pid")
                original_session = new_match.group("session")
                step_seed = _stable_seed(
                    f"syslog_logind_session_step:{host_key}:{pid}:{original_session}:{index}"
                )
                next_by_pid[pid] = next_by_pid.get(pid, first_by_pid[pid] - 1) + 1 + (step_seed % 3)
                rewritten = next_by_pid[pid]
                rewritten_by_original[(pid, original_session)] = rewritten
                line = (
                    f"{line[: new_match.start('session')]}"
                    f"{rewritten}"
                    f"{line[new_match.end('session') :]}"
                )
                normalized.append(line)
                continue

            removed_match = _LOGIND_REMOVED_SESSION_RE.search(line)
            if removed_match is not None:
                key = (removed_match.group("pid"), removed_match.group("session"))
                rewritten = rewritten_by_original.get(key)
                if rewritten is not None:
                    line = (
                        f"{line[: removed_match.start('session')]}"
                        f"{rewritten}"
                        f"{line[removed_match.end('session') :]}"
                    )
            normalized.append(line)
        return normalized

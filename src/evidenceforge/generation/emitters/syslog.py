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
from pathlib import Path
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
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
from evidenceforge.output_targets import OutputTarget
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
_KERNEL_UPTIME_RE = re.compile(
    r"(?P<prefix>\bkernel(?:\[\d+\])?(?::|\s+-\s+-\s+-)\s+\[)"
    r"(?P<uptime>\d+\.\d{6})"
    r"(?P<suffix>\])"
)
_SSHD_PID_RFC3164_RE = re.compile(r"(?P<prefix>\bsshd\[)(?P<pid>\d+)(?P<suffix>\]:)")
_SSHD_PID_RFC5424_RE = re.compile(
    r"(?P<prefix>^<\d{1,3}>1\s+\S+\s+\S+\s+sshd\s+)"
    r"(?P<pid>\d+)"
    r"(?P<suffix>\s+-\s+-\s+)"
)
_MAX_LOGIND_SESSION_ID_DIGITS = 18


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


def _rfc5424_syslog_sort_key(line: str) -> tuple[str, int, str]:
    """Sort RFC5424 syslog lines by full timestamp plus lifecycle order."""
    lifecycle_priority = min(
        _ssh_lifecycle_priority(line),
        _systemd_lifecycle_priority(line),
        _dhclient_lifecycle_priority(line),
    )
    match = _RFC5424_TS_RE.match(line)
    timestamp = match.group("timestamp") if match is not None else ""
    return (timestamp, lifecycle_priority, line)


class SyslogEmitter(HostMultiplexEmitter):
    """Emitter for Linux syslog format.

    Default target writes flat per-host RFC5424 files. SOF-ELK target writes
    per-host/year RFC3164 files.
    Renders any SecurityEvent that carries a SyslogContext on a Linux host.
    """

    _log_filename = "syslog.log"
    _flat_filename = "syslog.log"
    _sort_flat_file = True
    _sort_key = staticmethod(_rfc5424_syslog_sort_key)
    _defer_sorted_flush_until_close = True

    # Context-driven: handles any event type that carries SyslogContext
    _supported_types: set[str] = set()

    def configure_output_target(self, target: str | OutputTarget | None) -> None:
        """Configure target-specific syslog rendering and sort order."""
        super().configure_output_target(target)
        if self.output_target == OutputTarget.SOF_ELK:
            self._sort_key = _syslog_sort_key
        else:
            self._sort_key = _rfc5424_syslog_sort_key

    def _safe_writer_key(self, host_fqdn: str) -> str:
        return sanitize_syslog_family_route_key(host_fqdn)

    def _writer_path_for_key(self, safe_writer_key: str) -> Path:
        return syslog_family_writer_path(
            base_dir=self._base_dir,
            safe_route_key=safe_writer_key,
            log_filename=self._log_filename,
            direct_file_path=self._direct_file_path,
            flat_filename=self._flat_filename,
        )

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
        if self.output_target == OutputTarget.SOF_ELK:
            route_key = make_syslog_family_route_key(
                host_fqdn,
                event_data["timestamp"],
                direct_file_mode=self._direct_file_mode,
            )
            self.emit_to_host(rendered, route_key)
            return
        self.emit_to_host(rendered, host_fqdn)

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
        if self.threaded:
            self.stop_thread()
        self._normalize_logind_session_ids()
        self._normalize_kernel_uptime_stamps()
        self._normalize_sshd_child_pids()
        self.flush(force=True)

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

    def _normalize_sshd_child_pids(self) -> None:
        """Keep visible sshd child PIDs monotonic in final syslog order."""
        with self._writers_lock:
            for host_key, rows in self._sorted_lines_by_host().items():
                if not rows:
                    continue
                normalized = self._normalize_sshd_child_pids_for_lines(
                    [line for _year, _sort_key, _route_key, line in rows],
                    host_key,
                )
                self._replace_buffers_by_sorted_rows(rows, normalized)

    @staticmethod
    def _sshd_pid_match(line: str) -> re.Match[str] | None:
        """Return the sshd PID match for RFC5424 or RFC3164 syslog."""
        return _SSHD_PID_RFC5424_RE.search(line) or _SSHD_PID_RFC3164_RE.search(line)

    @classmethod
    def _normalize_sshd_child_pids_for_lines(cls, lines: list[str], host_key: str) -> list[str]:
        """Return lines with per-session sshd child PIDs increasing by source time."""
        pid_map: dict[str, int] = {}
        latest_pid = 0
        normalized: list[str] = []
        for line in lines:
            match = cls._sshd_pid_match(line)
            if match is None:
                normalized.append(line)
                continue
            old_pid = match.group("pid")
            new_pid = pid_map.get(old_pid)
            if new_pid is None:
                parsed_old_pid = int(old_pid)
                if parsed_old_pid > latest_pid:
                    new_pid = parsed_old_pid
                else:
                    bump = 1 + (
                        _stable_seed(f"syslog_sshd_pid:{host_key}:{old_pid}:{len(pid_map)}") % 17
                    )
                    new_pid = latest_pid + bump
                latest_pid = new_pid
                pid_map[old_pid] = new_pid
            normalized.append(
                f"{line[: match.start()]}{match.group('prefix')}{new_pid}{match.group('suffix')}"
                f"{line[match.end() :]}"
            )
        return normalized

    @staticmethod
    def _normalize_logind_session_ids_for_lines(lines: list[str], host_key: str) -> list[str]:
        """Return lines with monotonic logind New-session IDs for one host."""
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

        next_by_pid = {pid: max(2, start) - 1 for pid, start in first_by_pid.items()}
        prewindow_next_by_pid = {pid: max(2, start) - 1 for pid, start in first_by_pid.items()}
        rewritten_by_original: dict[tuple[str, str], int] = {}
        prewindow_seen_by_original: set[tuple[str, str]] = set()
        normalized: list[str] = []
        for index, line in enumerate(lines):
            new_match = _LOGIND_NEW_SESSION_RE.search(line)
            if new_match is not None:
                pid = _logind_pid(new_match)
                original_session = new_match.group("session")
                if _parse_logind_session_id(original_session) is None:
                    normalized.append(line)
                    continue
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

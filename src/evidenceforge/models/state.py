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

"""Runtime state models for EvidenceForge.

This module defines dataclass containers for tracking runtime state during log generation.
Unlike the Pydantic models in config.py and scenario.py, these use standard Python
dataclasses since they are runtime containers, not input validation models.

No validation is performed in these dataclasses - they are mutable containers for
runtime state tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ActiveSession:
    """Active logon session (Windows Security Event Log concept).

    Tracks an active user session on a system. Used to maintain consistency
    across logon/logoff events in Windows Security Event Logs.

    Attributes:
        logon_id: Unique logon session identifier (hex string like "0x3e7")
        username: Username for this session
        system: System hostname where session is active
        logon_type: Windows logon type (2=interactive, 3=network, 10=remote, etc.)
        start_time: When the session started
        source_ip: Source IP address for the logon
        explorer_pid: PID of explorer.exe instance for this interactive session
        process_tree_root: Root PID for this session's process tree
        last_activity_time: Last baseline activity timestamp (for login cooldown)
        network_close_time: Close time for a transport connection backing the session
    """

    logon_id: str
    username: str
    system: str
    logon_type: int
    start_time: datetime
    source_ip: str
    explorer_pid: int | None = None
    session_shell_pid: int | None = None  # Linux: per-session bash login shell
    session_winlogon_pid: int | None = None  # Windows: per-RDP-session winlogon
    process_tree_root: int | None = None
    last_activity_time: datetime | None = None
    network_close_time: datetime | None = None
    source_port: int = 0
    session_kind: str = "logon"
    transport_pid: int | None = None
    ecar_object_id: str = ""
    storyline_protected: bool = False


@dataclass
class RunningProcess:
    """Running process state.

    Tracks a running process on a system. Used to maintain consistency
    across process creation/termination events.

    Attributes:
        pid: Process ID
        parent_pid: Parent process ID
        image: Process image path/name (e.g., "C:\\Windows\\System32\\cmd.exe")
        command_line: Full command line with arguments
        username: User running this process
        system: System hostname where process is running
        start_time: When the process started
        integrity_level: Windows integrity level (System, High, Medium, Low)
    """

    pid: int
    parent_pid: int
    image: str
    command_line: str
    username: str
    system: str
    start_time: datetime
    integrity_level: str
    logon_id: str = ""
    ecar_object_id: str = ""
    story_created: bool = False


@dataclass
class OpenConnection:
    """Open network connection.

    Tracks an open network connection between two endpoints. Used for
    consistency in network logs (Zeek, firewall logs, etc.).

    Attributes:
        conn_id: Unique connection identifier
        zeek_uid: Zeek UID for cross-log correlation (shared across conn/dns/http/etc.)
        src_ip: Source IP address
        src_port: Source port number
        dst_ip: Destination IP address
        dst_port: Destination port number
        protocol: Network protocol ("tcp", "udp", etc.)
    state: Connection state ("established", "closed", "time_wait", etc.)
    start_time: When the connection opened
    close_time: When the connection closed (if known)
    bytes_sent: Bytes sent (cumulative)
    bytes_received: Bytes received (cumulative)
    """

    conn_id: str
    zeek_uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    state: str
    start_time: datetime
    source_system: str = ""
    source_hostname: str = ""
    hostname: str = ""
    initiating_pid: int = -1
    close_time: datetime | None = None
    bytes_sent: int = 0
    bytes_received: int = 0


@dataclass
class GeneratorState:
    """Complete runtime state for log generation.

    Central state container that tracks all active sessions, processes,
    connections, and other runtime information during log generation.

    This is the "world state" that the generation engine maintains to
    ensure cross-log consistency.

    Attributes:
        active_sessions: Map of logon_id -> ActiveSession
        running_processes: Map of (system, pid) -> RunningProcess
        open_connections: Map of conn_id -> OpenConnection
        dns_cache: Map of hostname -> IP address (simulated DNS resolution)
        current_time: Current simulation time (advances during generation)
    """

    active_sessions: dict[str, ActiveSession] = field(default_factory=dict)
    running_processes: dict[tuple[str, int], RunningProcess] = field(default_factory=dict)
    open_connections: dict[str, OpenConnection] = field(default_factory=dict)
    dns_cache: dict[str, str] = field(default_factory=dict)
    current_time: datetime | None = None

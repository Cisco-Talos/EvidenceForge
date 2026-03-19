"""Composable context dataclasses for the canonical event model.

Each context represents a domain-specific facet of a security event.
ActivityGenerator populates contexts; emitters and StateManager read from them.
All use @dataclass(slots=True) for memory efficiency.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class HostContext:
    """The system where this event occurs."""

    hostname: str
    ip: str
    os: str  # e.g., "Windows Server 2019", "Ubuntu 22.04"
    os_category: str  # "windows" | "linux"
    system_type: str  # "workstation" | "server" | "domain_controller"
    domain: str = ""


@dataclass(slots=True)
class AuthContext:
    """Authentication/session details."""

    username: str
    full_name: str = ""
    user_sid: str = ""
    logon_id: str = ""  # Allocated by StateManager.create_session()
    logon_type: int = 2
    auth_package: str = "Negotiate"
    result: str = "success"  # "success" | "failure"
    failure_reason: str = ""
    source_ip: str = ""
    source_port: int = 0
    elevated: bool = False


@dataclass(slots=True)
class ProcessContext:
    """Process creation/termination details."""

    pid: int  # Allocated by StateManager.create_process()
    parent_pid: int
    image: str  # Full path
    command_line: str
    username: str
    integrity_level: str = "Medium"


@dataclass(slots=True)
class NetworkContext:
    """Network connection details -- shared across Zeek, eCAR, Snort."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp"
    service: str = ""
    zeek_uid: str = ""  # From StateManager.open_connection()
    conn_id: str = ""  # From StateManager.open_connection()
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    conn_state: str = ""
    history: str = ""
    local_orig: bool = True
    local_resp: bool = False


@dataclass(slots=True)
class DnsContext:
    """DNS query/response details."""

    query: str
    query_type: str = "A"
    response_ip: str = ""
    rcode: str = "NOERROR"


@dataclass(slots=True)
class FileContext:
    """File operation details."""

    path: str
    action: str  # "create" | "modify" | "delete" | "read"
    pid: int = 0


@dataclass(slots=True)
class RegistryContext:
    """Windows registry operation details."""

    key: str
    value: str = ""
    action: str = ""  # "create" | "modify" | "delete"
    pid: int = 0


@dataclass(slots=True)
class IdsContext:
    """IDS/IPS alert details for Snort."""

    sid: int
    message: str
    classification: str
    priority: int = 2

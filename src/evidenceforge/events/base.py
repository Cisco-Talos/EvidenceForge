"""Core event model types for the canonical event system.

SecurityEvent is the intermediate representation between ActivityGenerator
and emitters. RawLogEntry is the escape hatch for single-format entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from evidenceforge.events.contexts import (
    AccountManagementContext,
    AuthContext,
    DhcpContext,
    DnsContext,
    FileContext,
    FileTransferContext,
    GroupMembershipContext,
    HostContext,
    HttpContext,
    IdsContext,
    KerberosContext,
    NetworkContext,
    NtpContext,
    OcspContext,
    PeContext,
    ProcessContext,
    ProxyContext,
    RawContext,
    RegistryContext,
    ScheduledTaskContext,
    ServiceContext,
    ShellContext,
    SslContext,
    SyslogContext,
    X509Context,
)


@dataclass(slots=True)
class SecurityEvent:
    """Canonical event carrying all shared metadata for a single logical event.

    Composable contexts are populated as needed by ActivityGenerator.
    Emitters render their format-specific view from these contexts.
    """

    timestamp: datetime
    event_type: str

    host: HostContext | None = None
    auth: AuthContext | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None
    dns: DnsContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    ids: IdsContext | None = None
    syslog: SyslogContext | None = None
    kerberos: KerberosContext | None = None
    shell: ShellContext | None = None
    service: ServiceContext | None = None
    scheduled_task: ScheduledTaskContext | None = None
    group_membership: GroupMembershipContext | None = None
    account_management: AccountManagementContext | None = None

    # Zeek protocol-layer contexts (Phase: Zeek expansion)
    ssl: SslContext | None = None
    http: HttpContext | None = None
    file_transfer: FileTransferContext | None = None
    x509: X509Context | None = None
    dhcp: DhcpContext | None = None
    ntp: NtpContext | None = None
    ocsp: OcspContext | None = None
    pe: PeContext | None = None
    proxy: ProxyContext | None = None

    # Raw event: carries arbitrary fields for a single target emitter.
    # Goes through pipeline (state mgmt, visibility, local_only) unlike dispatch_raw().
    raw: RawContext | None = None

    # Host-local event: skip network-sensor formats (Zeek/Snort) but still
    # emit to host-based formats (eCAR, Windows, Sysmon).  Set when src_ip == dst_ip.
    local_only: bool = False

    # Sensor routing metadata (not a context — set by dispatcher)
    # Maps format_name → list of sensor hostnames that produce that format
    _sensor_hostnames_by_format: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class RawLogEntry:
    """Escape hatch -- bypass the event model for simple, single-format entries.

    Use for: background noise that only appears in one format, simple heartbeats,
    or events that don't yet fit the context model.
    """

    timestamp: datetime
    target_emitter: str  # Emitter dict key (e.g., "syslog", "zeek_conn")
    data: dict[str, Any]

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
    EdrContext,
    FileContext,
    FileTransferContext,
    FirewallContext,
    GroupMembershipContext,
    HostContext,
    HttpContext,
    IdsContext,
    ImageLoadContext,
    KerberosContext,
    NatContext,
    NetworkContext,
    NtpContext,
    OcspContext,
    PeContext,
    ProcessAccessContext,
    ProcessContext,
    ProxyContext,
    RawContext,
    RegistryContext,
    RemoteThreadContext,
    ScheduledTaskContext,
    ServiceContext,
    ShellContext,
    SslContext,
    SyslogContext,
    WeirdContext,
    X509Context,
)


@dataclass
class SecurityEvent:
    """Canonical event carrying all shared metadata for a single logical event.

    Composable contexts are populated as needed by ActivityGenerator.
    Emitters render their format-specific view from these contexts.

    Host context uses a dual src/dst model:
    - src_host: the system that originates or performs the action
    - dst_host: the system that is the target or receiver of the action
    For single-host events, only one is set (src_host for local events like
    process_create; dst_host for target events like logon).  For network events,
    both may be set when both endpoints are internal/known.
    """

    timestamp: datetime
    event_type: str

    src_host: HostContext | None = None
    dst_host: HostContext | None = None
    auth: AuthContext | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None
    dns: DnsContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    remote_thread: RemoteThreadContext | None = None
    process_access: ProcessAccessContext | None = None
    ids: IdsContext | None = None
    image_load: ImageLoadContext | None = None
    syslog: SyslogContext | None = None
    weird: WeirdContext | None = None
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
    x509_chain: list[X509Context] = field(default_factory=list)
    dhcp: DhcpContext | None = None
    ntp: NtpContext | None = None
    ocsp: OcspContext | None = None
    pe: PeContext | None = None
    proxy: ProxyContext | None = None

    # EDR entity tracking (eCAR object/actor graph)
    edr: EdrContext | None = None

    # Firewall decision context (Cisco ASA)
    firewall: FirewallContext | None = None

    # NAT translation context (Cisco ASA)
    nat: NatContext | None = None

    # Raw event: carries arbitrary fields for a single target emitter.
    # Goes through pipeline (state mgmt, visibility, local_only) unlike dispatch_raw().
    raw: RawContext | None = None

    # Host-local event: skip network-sensor formats (Zeek/Snort) but still
    # emit to host-based formats (eCAR, Windows, Sysmon).  Set when src_ip == dst_ip.
    local_only: bool = False

    # Sensor routing metadata (not a context — set by dispatcher)
    # Maps format_name → list of sensor hostnames that produce that format
    _sensor_hostnames_by_format: dict[str, list[str]] = field(default_factory=dict)
    # NAT swap metadata: maps sensor hostname → dict of IP/port swaps for post-NAT sensors
    _nat_swaps_by_sensor: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(slots=True)
class RawLogEntry:
    """Escape hatch -- bypass the event model for simple, single-format entries.

    Use for: background noise that only appears in one format, simple heartbeats,
    or events that don't yet fit the context model.
    """

    timestamp: datetime
    target_emitter: str  # Emitter dict key (e.g., "syslog", "zeek_conn")
    data: dict[str, Any]
